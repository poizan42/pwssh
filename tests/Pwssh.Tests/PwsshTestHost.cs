// An in-process pwssh engine on a loopback socket, for tests to point a real SSH client at.
//
// This is a near-copy of Pwssh.Dev.TcpHost.Serve, and deliberately so: that method is the contract
// for an engine's lifecycle (config, agent, writer thread, reader loop, teardown) and diverging from
// it would mean testing something other than what the dev host and the ProxyCommand do. Four things
// differ, all of them because a test needs what a developer at a console does not:
//
//   1. Port 0, with the assigned port read back. TcpHost.Run accepts 0 but prints the requested
//      value and never exposes LocalEndpoint, so the real port is unobservable there.
//   2. It can be stopped. TcpHost.Run is an unstoppable while(true) accept loop whose TcpListener is
//      a local variable nothing else can reach.
//   3. Engine log lines are captured rather than written to Console.Error. This matters more than it
//      sounds: a failed algorithm negotiation closes the transport with no SSH_MSG_DISCONNECT, so
//      PwsshEngine.LastError and DrainLog() are the ONLY places the reason exists.
//   4. Every wait in teardown is bounded, per the rule the PowerShell suite already holds itself to.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Pwssh;

namespace Pwssh.Tests
{
    internal sealed class PwsshTestHost : IDisposable
    {
        private readonly TcpListener listener;
        private readonly string hostKey;
        private readonly Action<PwsshConfig> tweak;
        private readonly int latencyMs;
        private readonly ConcurrentQueue<string> log = new ConcurrentQueue<string>();
        private readonly List<PwsshEngine> engines = new List<PwsshEngine>();
        private readonly List<Thread> threads = new List<Thread>();
        private readonly object gate = new object();
        private volatile bool stopping;
        private volatile string lastError;

        public int Port { get; private set; }

        /// <param name="tweak">
        /// Applied to each connection's config after the defaults, so a test can vary
        /// SftpReadAheadChunks or SftpFaultAfterKiB without a constructor parameter per knob.
        /// </param>
        /// <param name="latencyMs">
        /// One-way delay on the client-to-agent link, the same knob the dev host exposes as
        /// -LatencyMs and for the same reason. A bare loopback has no round trip at all, which does
        /// not merely hide costs: it changes behaviour. With no latency the SFTP prefetch reaches EOF
        /// in one burst before the client has consumed anything, Refill finishes the prefetch, and
        /// the read-ahead drops out of the picture entirely -- so any test that needs a LIVE prefetch
        /// (a mid-transfer seek, say) is testing nothing without this.
        /// </param>
        public PwsshTestHost(Action<PwsshConfig> tweak = null, int latencyMs = 0)
        {
            this.tweak = tweak;
            this.latencyMs = latencyMs;
            // One key for the host rather than one per connection: 2048-bit RSA keygen is ~40 ms,
            // and a client reconnecting to the same host should see the same key anyway.
            hostKey = PwsshKey.Generate(2048);

            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;

            Thread accept = new Thread(AcceptLoop);
            accept.IsBackground = true;
            accept.Name = "pwssh-test-accept";
            accept.Start();
            Track(accept);
        }

        /// <summary>Engine log lines captured so far. Print these when a test fails.</summary>
        public string[] Log { get { return log.ToArray(); } }

        /// <summary>The last fatal engine error, or null. A negotiation failure only shows up here.</summary>
        public string LastError { get { return lastError; } }

        private void Track(Thread t)
        {
            lock (gate) threads.Add(t);
        }

        private void AcceptLoop()
        {
            try
            {
                while (!stopping)
                {
                    TcpClient c = listener.AcceptTcpClient();
                    // The ThreadStart cast is required: a parameterless anonymous delegate is
                    // ambiguous between ThreadStart and ParameterizedThreadStart.
                    Thread t = new Thread((ThreadStart)delegate { Serve(c); });
                    t.IsBackground = true;
                    t.Name = "pwssh-test-serve";
                    t.Start();
                    Track(t);
                }
            }
            catch (Exception)
            {
                // Disposing the listener is how this loop is stopped; the throw is expected.
            }
        }

        private void Serve(TcpClient c)
        {
            PwsshEngine eng = null;
            try
            {
                NetworkStream ns = c.GetStream();

                PwsshConfig cfg = new PwsshConfig();
                cfg.HostKey = hostKey;
                // Set explicitly rather than left to the agent's HELLO: the resolution path blocks
                // for up to 30 s and the dev host exercises it already. A test wants determinism.
                cfg.ExpectedUser = Environment.UserName;
                // 0 disables both the idle shutdown and the keepalive it feeds (PwsshEngine's
                // watchdog guards both on limitMs > 0), so a debugger sitting on a breakpoint
                // cannot have the connection pulled out from under it.
                cfg.InactivityTimeoutSeconds = 0;
                cfg.Agent = latencyMs > 0 ? DelayedLoopback.Start(latencyMs) : PwsshLoopback.Start();
                if (tweak != null) tweak(cfg);

                eng = new PwsshEngine(cfg);
                lock (gate) engines.Add(eng);
                eng.Start();

                PwsshEngine engRef = eng;
                Thread writer = new Thread((ThreadStart)delegate
                {
                    try
                    {
                        while (true)
                        {
                            byte[] b = engRef.TakeOutbound(200);
                            Drain(engRef);
                            if (b != null && b.Length > 0)
                            {
                                ns.Write(b, 0, b.Length);
                                ns.Flush();
                            }
                            else if (engRef.Finished)
                            {
                                break;
                            }
                        }
                        try { c.Client.Shutdown(SocketShutdown.Send); } catch { }
                    }
                    catch (Exception ex)
                    {
                        log.Enqueue("writer: " + ex.Message);
                    }
                });
                writer.IsBackground = true;
                writer.Name = "pwssh-test-writer";
                writer.Start();
                Track(writer);

                byte[] buf = new byte[32768];
                while (true)
                {
                    int n = ns.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    byte[] chunk = new byte[n];
                    Array.Copy(buf, 0, chunk, 0, n);
                    eng.PushInbound(chunk);
                }
            }
            catch (Exception ex)
            {
                log.Enqueue("connection: " + ex.Message);
            }
            finally
            {
                if (eng != null)
                {
                    Drain(eng);
                    if (eng.LastError != null)
                    {
                        lastError = eng.LastError;
                        log.Enqueue("ERROR: " + eng.LastError);
                    }
                    eng.Stop();
                }
                try { c.Close(); } catch { }
            }
        }

        private void Drain(PwsshEngine eng)
        {
            string[] lines = eng.DrainLog();
            for (int i = 0; i < lines.Length; i++) log.Enqueue(lines[i]);
        }

        /// <summary>
        /// Waits for a log line containing <paramref name="needle"/>. The engine logs asynchronously
        /// to whatever the client observes, so a test that asserts on the log immediately after an
        /// operation completes is racing it.
        /// </summary>
        public bool WaitForLog(string needle, int timeoutMs = 10000)
        {
            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (unchecked(Environment.TickCount - deadline) < 0)
            {
                foreach (string line in log)
                    if (line != null && line.IndexOf(needle, StringComparison.Ordinal) >= 0) return true;
                Thread.Sleep(25);
            }
            return false;
        }

        /// <summary>The first log line containing <paramref name="needle"/>, or null.</summary>
        public string FindLog(string needle)
        {
            foreach (string line in log)
                if (line != null && line.IndexOf(needle, StringComparison.Ordinal) >= 0) return line;
            return null;
        }

        public void Dispose()
        {
            stopping = true;
            try { listener.Stop(); } catch { }

            PwsshEngine[] all;
            Thread[] ts;
            lock (gate)
            {
                all = engines.ToArray();
                ts = threads.ToArray();
            }
            foreach (PwsshEngine e in all)
            {
                try { e.Stop(); } catch { }
            }
            // Bounded, and only a diagnostic if it expires: these are background threads, so a
            // straggler cannot hold the test process open. An unbounded Join here would turn one
            // stuck engine into a run that produces no output at all, which is the failure shape
            // the PowerShell suite already learned to avoid.
            foreach (Thread t in ts)
            {
                try { t.Join(2000); } catch { }
            }
        }
    }
}
