// The dev host, running in a console of its own, so pty channels work under `dotnet test`.
//
// WHY THIS IS NEEDED
//
// ConPTY cannot be driven from a process whose stdout is redirected, and `dotnet test` redirects it.
// That is not a pwssh defect: ConPtySession calls CreateProcess with inherit = false and never sets
// STARTF_USESTDHANDLES (src/agent/ConPty.cs:280-281), exactly as the ConPTY contract requires. The
// consequence is that the shell takes its std handles from its parent's PEB defaults, so when those
// are pipes it writes into a pipe instead of into the pseudoconsole. Measured 3/3 each way.
//
// WHY NOT A PSEUDOCONSOLE OF OUR OWN, which was the first thing tried
//
// Creating a pseudoconsole here and launching the host into it with
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE does not work, and the reason is the same mechanism one level
// up: the attribute sets the child's *console*, not its *std handles*. Those still come from this
// process, which under `dotnet test` means pipes. Observed directly -- the dev host's banner appeared
// on the test runner's own stdout while the pseudoconsole capture stayed empty. There is no documented
// way for a creating process to obtain handles to the client side of a pseudoconsole it made, so the
// child cannot be handed them either.
//
// CREATE_NO_WINDOW is what actually works: the child gets a real console with no window, and all
// three of its std handles point at that console. This is the same arrangement as launching the dev
// host with `Start-Process -WindowStyle Hidden`, which was measured passing 3/3 where a redirected
// host failed 3/3.
//
// THE COST, stated plainly: nothing may be redirected, so the dev host's own diagnostics are not
// readable from here. Not being redirected is precisely why it works, so this is a genuine trade
// rather than an oversight. It also means readiness has to be detected by polling the port instead of
// by reading the host's "listening" banner. When a pty test fails and the reason is not obvious, run
// the dev host by hand in a terminal and drive it with the stock client.

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Pwssh.Tests
{
    // Public because xUnit constructs it as an IClassFixture. Shared across the pty tests on purpose:
    // starting pwsh and compiling the engine per test is slow, and two hosts starting and being killed
    // back to back turned out to be enough for the second one to come up reporting conpty=0.
    public sealed class ConsoleHostFixture : IDisposable
    {
        private readonly Process host;

        public int Port { get; private set; }

        // A cold start pays for pwsh plus a Roslyn compile of the engine; a warm one hits the
        // client's on-disk assembly cache and is far quicker.
        private const int StartupTimeoutMs = 120000;

        // Exactly one public constructor, taking nothing: xUnit resolves class-fixture constructors
        // by parameter, rejects a second public overload outright, and does not treat a default
        // argument as satisfying a parameter.
        public ConsoleHostFixture()
        {
            int startupTimeoutMs = StartupTimeoutMs;
            string repo = FindRepoRoot();
            string script = Path.Combine(repo, "tools", "Start-PwsshTcpHost.ps1");
            if (!File.Exists(script)) throw new FileNotFoundException("dev host script not found", script);

            // The dev host prints the port it was ASKED for, never the one it got, so an ephemeral
            // bind is unobservable there and the port has to be chosen here. Same approach as the
            // PowerShell suite's Get-FreePort: bind 0, read it back, release.
            Port = FreePort();

            ProcessStartInfo psi = new ProcessStartInfo("pwsh");
            psi.ArgumentList.Add("-NoProfile");
            psi.ArgumentList.Add("-NoLogo");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(script);
            psi.ArgumentList.Add("-Port");
            psi.ArgumentList.Add(Port.ToString());
            psi.WorkingDirectory = repo;
            psi.UseShellExecute = false;
            // Nothing redirected, deliberately. .NET sets STARTF_USESTDHANDLES as soon as ANY stream
            // is redirected, and passes this process's own handles for the others -- so redirecting
            // even stderr alone would hand the child our piped stdout and break ConPTY again.
            psi.RedirectStandardOutput = false;
            psi.RedirectStandardError = false;
            psi.RedirectStandardInput = false;
            // A console, but no window: CREATE_NO_WINDOW rather than DETACHED_PROCESS.
            psi.CreateNoWindow = true;

            host = Process.Start(psi);
            if (host == null) throw new InvalidOperationException("could not start the dev host");

            if (!WaitForPort(Port, startupTimeoutMs))
            {
                string extra = host.HasExited ? " (the host exited with " + host.ExitCode + ")" : "";
                Dispose();
                throw new TimeoutException(
                    "the dev host did not start listening on 127.0.0.1:" + Port + " within "
                    + startupTimeoutMs + " ms" + extra
                    + ". Its console is not redirected, so there is no captured log; run"
                    + " tools/Start-PwsshTcpHost.ps1 by hand to see why.");
            }
        }

        private static bool WaitForPort(int port, int timeoutMs)
        {
            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (unchecked(Environment.TickCount - deadline) < 0)
            {
                try
                {
                    using (TcpClient c = new TcpClient())
                    {
                        if (c.ConnectAsync(IPAddress.Loopback, port).Wait(500) && c.Connected) return true;
                    }
                }
                catch (Exception) { }
                Thread.Sleep(200);
            }
            return false;
        }

        private static int FreePort()
        {
            TcpListener l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int p = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return p;
        }

        /// <summary>
        /// Walks up from the test assembly until a directory holding pwssh-connect.ps1 turns up, so
        /// the fixture does not depend on the working directory the test runner happens to use.
        /// </summary>
        private static string FindRepoRoot()
        {
            string dir = AppContext.BaseDirectory;
            for (int i = 0; i < 12 && dir != null; i++)
            {
                if (File.Exists(Path.Combine(dir, "pwssh-connect.ps1"))) return dir;
                DirectoryInfo parent = Directory.GetParent(dir);
                dir = parent == null ? null : parent.FullName;
            }
            throw new DirectoryNotFoundException(
                "could not locate the repo root above " + AppContext.BaseDirectory);
        }

        public void Dispose()
        {
            // A leaked dev host holds a listening socket and would collide with the next run's port
            // pick, so this is not merely tidiness. Bounded, and killed rather than asked politely:
            // the dev host has no shutdown path of its own.
            try
            {
                if (!host.HasExited)
                {
                    host.Kill(true);
                    host.WaitForExit(5000);
                }
            }
            catch (Exception) { }
            try { host.Dispose(); } catch (Exception) { }
        }
    }
}
