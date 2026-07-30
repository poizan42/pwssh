// The gate for everything else in this project: can a library SSH client negotiate with pwssh at
// all? pwssh offers one algorithm per category and no fallback, and a failure to agree closes the
// transport with no SSH_MSG_DISCONNECT, so without these tests every later failure would look like
// a bug in whatever it was testing.

using System;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class ConnectSmokeTests
    {
        private readonly ITestOutputHelper output;

        public ConnectSmokeTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        private void Dump(PwsshTestHost host)
        {
            foreach (string line in host.Log) output.WriteLine(line);
            if (host.LastError != null) output.WriteLine("LastError: " + host.LastError);
        }

        [Fact]
        public void A_library_client_can_negotiate_and_run_a_command()
        {
            using (PwsshTestHost host = new PwsshTestHost())
            using (SshClient ssh = SshNetClient.Ssh(host))
            {
                try
                {
                    ssh.Connect();
                    using (SshCommand cmd = ssh.CreateCommand("echo hello-from-sshnet"))
                    {
                        string result = cmd.Execute();
                        Assert.Contains("hello-from-sshnet", result);
                        Assert.Equal(0, cmd.ExitStatus);
                    }
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void The_negotiated_algorithms_are_the_only_ones_pwssh_offers()
        {
            using (PwsshTestHost host = new PwsshTestHost())
            using (SshClient ssh = SshNetClient.Ssh(host))
            {
                try
                {
                    ssh.Connect();
                    // Asserted from the client's side so this is a real negotiation result rather
                    // than a restatement of the server's constants.
                    Assert.Equal("aes256-ctr", ssh.ConnectionInfo.CurrentServerEncryption);
                    Assert.Equal("aes256-ctr", ssh.ConnectionInfo.CurrentClientEncryption);
                    Assert.Equal("hmac-sha2-256-etm@openssh.com", ssh.ConnectionInfo.CurrentServerHmacAlgorithm);
                    Assert.Equal("hmac-sha2-256-etm@openssh.com", ssh.ConnectionInfo.CurrentClientHmacAlgorithm);
                    Assert.Equal("diffie-hellman-group14-sha256", ssh.ConnectionInfo.CurrentKeyExchangeAlgorithm);
                    Assert.Equal("rsa-sha2-256", ssh.ConnectionInfo.CurrentHostKeyAlgorithm);
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void A_username_that_does_not_match_the_account_is_rejected()
        {
            using (PwsshTestHost host = new PwsshTestHost())
            using (SshClient ssh = SshNetClient.Ssh(host, "definitely-not-this-user"))
            {
                Assert.ThrowsAny<Exception>(() => ssh.Connect());
            }
        }

        [Fact]
        public void An_exit_status_reaches_the_client()
        {
            using (PwsshTestHost host = new PwsshTestHost())
            using (SshClient ssh = SshNetClient.Ssh(host))
            {
                try
                {
                    ssh.Connect();
                    using (SshCommand cmd = ssh.CreateCommand("exit 42"))
                    {
                        cmd.Execute();
                        Assert.Equal(42, cmd.ExitStatus);
                    }
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void Sftp_connects_and_realpath_answers_in_the_documented_shape()
        {
            using (PwsshTestHost host = new PwsshTestHost())
            using (SftpClient sftp = SshNetClient.Sftp(host))
            {
                try
                {
                    sftp.Connect();
                    string cwd = sftp.WorkingDirectory;
                    // /C:/Users/... is the convention established from the reference server.
                    Assert.Matches(new Regex(@"^/[A-Za-z]:/"), cwd);
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }
    }
}
