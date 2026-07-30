// The two shell paths that need no console of their own, so they run against the fast in-process host.

using System;
using Renci.SshNet;
using Renci.SshNet.Common;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class ShellNegotiationTests
    {
        private readonly ITestOutputHelper output;

        public ShellNegotiationTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void A_shell_without_a_pty_runs_over_pipes()
        {
            // What `echo cmd | ssh host` does: no pty-req, so the shell gets pipes. Note the pipe
            // newline -- with no console in the path nothing translates a bare CR into a line.
            using (PwsshTestHost host = new PwsshTestHost())
            {
                try
                {
                    using (SshClient ssh = SshNetClient.Ssh(host))
                    {
                        ssh.Connect();
                        using (ShellStream shell = ssh.CreateShellStreamNoTerminal(8192))
                        {
                            string seen = ShellDriver.Run(shell, "echo hello-over-pipes", "hello-over-pipes",
                                                          ShellDriver.PipeNewline, 30000);
                            Assert.Contains("hello-over-pipes", seen);
                            // And no VT, because there is no console: this is what makes it the
                            // counterpart to the pty case rather than a duplicate of it.
                            Assert.DoesNotContain("[?25l", seen);
                        }
                    }
                }
                catch
                {
                    foreach (string line in host.Log) output.WriteLine(line);
                    throw;
                }
            }
        }

        [Fact]
        public void Pty_allocation_is_refused_when_the_remote_has_no_conpty()
        {
            // The graceful-degradation path: the agent reports conpty=0 in HELLO and the engine answers
            // pty-req with CHANNEL_FAILURE. `ssh -tt` treats that as fatal, which is correct, and so
            // does SSH.NET's CreateShellStream.
            //
            // Driven by the existing DisableConPty hook rather than by withholding a console, and the
            // difference matters: IsAvailable() only checks that the export resolves and that a 1x1
            // pseudoconsole can be created, both of which succeed even with a redirected stdout. Without
            // the hook, pty-req is ACCEPTED and the shell's output silently goes to the wrong handle --
            // a different failure, and not the one this asserts.
            //
            // A process-wide static, hence the reset, and hence this assembly running serialized.
            bool previous = Pwssh.PwsshAgentHost.DisableConPty;
            Pwssh.PwsshAgentHost.DisableConPty = true;
            try
            {
                using (PwsshTestHost host = new PwsshTestHost())
                using (SshClient ssh = SshNetClient.Ssh(host))
                {
                    ssh.Connect();
                    SshException ex = Assert.Throws<SshException>(delegate
                    {
                        ssh.CreateShellStream("xterm", 120, 40, 800, 600, 8192).Dispose();
                    });
                    Assert.Contains("pseudo-terminal", ex.Message);

                    // And the session survives the refusal rather than dying with it, which is what
                    // makes `ssh` able to print "PTY allocation request failed" and carry on.
                    using (SshCommand cmd = ssh.CreateCommand("echo still-alive"))
                    {
                        Assert.Contains("still-alive", cmd.Execute());
                    }
                }
            }
            finally
            {
                Pwssh.PwsshAgentHost.DisableConPty = previous;
            }
        }
    }
}
