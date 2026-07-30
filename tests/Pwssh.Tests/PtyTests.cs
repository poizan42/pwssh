// The first automated pty coverage.
//
// The PowerShell suite already has pty cases, but they need a real console: ConPTY cannot attach in
// a process whose stdout is redirected, and both `dotnet test` and a CI runner redirect it. So those
// cases have never run anywhere but a developer's terminal. ConsoleHostFixture fixes that by giving
// the dev host a console of its own (CREATE_NO_WINDOW), leaving this process's console untouched. See
// that file for why a pseudoconsole of our own cannot work.
//
// The fixture is shared across the class rather than built per test. Starting pwsh and compiling the
// engine is slow, and two hosts started and killed back to back proved to be enough for the second to
// come up reporting conpty=0 -- which failed the test for a reason that had nothing to do with pwssh.
//
// `window-change` is covered here too, which it could not be until SSH.NET 2025.1.0: before that the
// request was only reachable through the non-public ChannelSession, and CLAUDE.md recorded the resize
// path as verifiable by hand only ("None can be asserted from a script"). ShellStream.ChangeWindowSize
// is the public route, and the assertion is made on the REMOTE's view of its console rather than on
// anything local, so it proves the request travelled and ResizePseudoConsole acted on it.

using System;
using System.Text;
using System.Threading;
using Renci.SshNet;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class PtyTests : IClassFixture<ConsoleHostFixture>
    {
        private readonly ConsoleHostFixture host;
        private readonly ITestOutputHelper output;

        public PtyTests(ConsoleHostFixture host, ITestOutputHelper output)
        {
            this.host = host;
            this.output = output;
        }

        [Fact]
        public void A_pty_session_produces_output()
        {
            using (SshClient ssh = SshNetClient.Ssh(host.Port))
            {
                ssh.Connect();
                using (ShellStream shell = ssh.CreateShellStream("xterm", 120, 40, 800, 600, 8192))
                {
                    string seen = ShellDriver.Run(shell, "echo hello-from-pty", "hello-from-pty",
                                                  ShellDriver.PtyNewline, 30000);
                    output.WriteLine(seen.Replace("", "<ESC>"));
                    Assert.Contains("hello-from-pty", seen);
                }
            }
        }

        [Fact]
        public void Window_change_resizes_the_remote_console()
        {
            // Asked of the remote's own console rather than inferred from the VT stream, so this
            // proves the whole path: window-change over the wire, SessionChannel.Resize, a RESIZE
            // frame, and ResizePseudoConsole actually taking effect in the child's console.
            //
            // The width is read with PowerShell rather than `mode con` because `mode` labels its
            // output ("Columns:") and those labels are localised, whereas RawUI.WindowSize.Width is
            // just a number.
            using (SshClient ssh = SshNetClient.Ssh(host.Port))
            {
                ssh.Connect();
                using (ShellStream shell = ssh.CreateShellStream("xterm", 120, 40, 800, 600, 8192))
                {
                    Assert.Equal(120, ReadRemoteWidth(shell));

                    shell.ChangeWindowSize(100, 30, 800, 600);
                    // The resize is asynchronous with respect to the shell, so retry rather than
                    // assume the next command already sees it. Bounded, like every other wait here.
                    int width = 0;
                    for (int attempt = 0; attempt < 5; attempt++)
                    {
                        width = ReadRemoteWidth(shell);
                        if (width == 100) break;
                    }
                    Assert.Equal(100, width);
                }
            }
        }

        /// <summary>
        /// The remote console's width, as the remote sees it. The marker is assembled at runtime
        /// ('WI'+'D=') so that the shell's echo of the command line cannot itself match it -- with a
        /// literal marker the read would satisfy itself on the echo and never see the answer.
        /// </summary>
        private int ReadRemoteWidth(ShellStream shell)
        {
            string command = "powershell -NoProfile -Command \"'WI'+'D='+(Get-Host).UI.RawUI.WindowSize.Width\"";
            string seen = ShellDriver.Run(shell, command, "WID=", ShellDriver.PtyNewline, 60000);
            System.Text.RegularExpressions.Match m =
                System.Text.RegularExpressions.Regex.Match(seen, @"WID=(\d+)");
            Assert.True(m.Success, "no width reported by the remote. Saw: " + seen.Replace("", "<ESC>"));
            output.WriteLine("remote console width: " + m.Groups[1].Value);
            return int.Parse(m.Groups[1].Value);
        }

        [Fact]
        public void A_pty_session_emits_vt_sequences()
        {
            // A pty is not merely "output arrived": ConPTY drives a real console, so the stream
            // carries escape sequences. Over pipes it would not, which is what separates the two.
            using (SshClient ssh = SshNetClient.Ssh(host.Port))
            {
                ssh.Connect();
                using (ShellStream shell = ssh.CreateShellStream("xterm", 120, 40, 800, 600, 8192))
                {
                    string seen = ShellDriver.Run(shell, "echo vt-probe", "vt-probe",
                                                  ShellDriver.PtyNewline, 30000);
                    Assert.Contains("[", seen);
                }
            }
        }
    }
}
