// SSH.NET client construction against a PwsshTestHost.
//
// Two notes on what is deliberately NOT done here.
//
// The algorithm lists are left at SSH.NET's defaults. pwssh advertises exactly one name per category
// and PwsshEngine.Require only checks that its choice appears in the client's list, so narrowing the
// client to one each would test a less realistic path than the one OpenSSH exercises. Verified
// against SSH.NET 2024.2.0: all four of diffie-hellman-group14-sha256, rsa-sha2-256, aes256-ctr and
// hmac-sha2-256-etm@openssh.com are in its defaults. The ETM MAC is the load-bearing one, since the
// packet layer implements no other framing.
//
// The host key is accepted unconditionally. It authenticates the proxy rather than any remote
// machine, and PwsshTestHost generates a fresh one per instance, so there is nothing to pin.

using System;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace Pwssh.Tests
{
    internal static class SshNetClient
    {
        /// <summary>
        /// A ConnectionInfo for the given host. The username must match the engine's ExpectedUser,
        /// which PwsshTestHost sets to Environment.UserName; the auth method is irrelevant because
        /// PwsshEngine never inspects it, but `none` is what the design actually intends.
        /// </summary>
        public static ConnectionInfo Info(int port, string user = null)
        {
            string u = user ?? Environment.UserName;
            ConnectionInfo ci = new ConnectionInfo(
                "127.0.0.1", port, u, new NoneAuthenticationMethod(u));
            ci.Timeout = TimeSpan.FromSeconds(30);
            return ci;
        }

        public static ConnectionInfo Info(PwsshTestHost host, string user = null)
        {
            return Info(host.Port, user);
        }

        public static SshClient Ssh(int port, string user = null)
        {
            SshClient c = new SshClient(Info(port, user));
            c.HostKeyReceived += Accept;
            return c;
        }

        public static SshClient Ssh(PwsshTestHost host, string user = null)
        {
            return Ssh(host.Port, user);
        }

        /// <param name="bufferSize">
        /// SftpFileStream buffers reads internally, so a seek can be satisfied without any READ
        /// reaching the server. A small buffer is what makes a seek observable on the wire.
        /// </param>
        public static SftpClient Sftp(PwsshTestHost host, string user = null, uint? bufferSize = null)
        {
            SftpClient c = new SftpClient(Info(host, user));
            c.HostKeyReceived += Accept;
            if (bufferSize.HasValue) c.BufferSize = bufferSize.Value;
            return c;
        }

        private static void Accept(object sender, HostKeyEventArgs e)
        {
            e.CanTrust = true;
        }
    }
}
