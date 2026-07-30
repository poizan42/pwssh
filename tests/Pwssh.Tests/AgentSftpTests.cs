// Request/reply tests against the SFTP server, with no SSH in the loop.
//
// Everything here is unreachable from the stock `sftp` client and from SSH.NET's SftpClient alike:
// there is no CLI command and no library method that sends a forged handle, an unknown extension name
// or an INIT claiming a version the server does not speak. Several of these code paths had never
// executed once.

using System;
using System.Collections.Generic;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class AgentSftpTests
    {
        private readonly ITestOutputHelper output;

        public AgentSftpTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void The_version_reply_advertises_exactly_the_documented_extensions()
        {
            // Asserted as a set, because the client's behaviour depends on it: advertising
            // limits@openssh.com is what makes sftp raise its transfer buffer 8x, and an extension
            // silently disappearing would show up only as a throughput regression.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(3));
                byte[] reply = d.Receive();

                uint version;
                Dictionary<string, string> ext;
                AgentSftpDriver.ParseVersion(reply, out version, out ext);
                output.WriteLine("version " + version + ", extensions: " + string.Join(", ", ext.Keys));

                Assert.Equal(3u, version);
                Assert.Equal(
                    new[]
                    {
                        "fsync@openssh.com",
                        "hardlink@openssh.com",
                        "limits@openssh.com",
                        "lsetstat@openssh.com",
                        "posix-rename@openssh.com",
                    },
                    Sorted(ext.Keys));
            }
        }

        [Fact]
        public void An_init_claiming_a_newer_version_still_gets_version_3()
        {
            // A v6 client is not something either available client will send. The server speaks v3
            // only, and the protocol says the server answers with the lowest of the two; answering
            // with the client's number would be a promise it cannot keep.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(6));
                byte[] reply = d.Receive();

                uint version;
                Dictionary<string, string> ext;
                AgentSftpDriver.ParseVersion(reply, out version, out ext);
                Assert.Equal(3u, version);
            }
        }

        [Fact]
        public void Readlink_and_symlink_are_refused_as_unsupported()
        {
            // Refused on purpose rather than merely absent: symlink creation needs
            // SeCreateSymbolicLinkPrivilege, and resolution needs DeviceIoControl plus a reverse path
            // mapping. The status matters -- OP_UNSUPPORTED tells a client to stop asking, where
            // FAILURE invites a retry.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(3));
                d.Receive();

                uint id = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, id, "/C:/Windows"));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.OpUnsupported, s.Code);

                id = d.NextId();
                d.Send(AgentSftpDriver.TwoStrings(AgentSftpDriver.SftpTypeByte.Symlink, id,
                                                  "/C:/Windows/Temp/link", "/C:/Windows"));
                s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.OpUnsupported, s.Code);
            }
        }

        [Fact]
        public void An_unknown_extension_is_refused_rather_than_ignored()
        {
            // statvfs@openssh.com is the concrete case: `sftp`'s own `df` sends it, we do not
            // implement it, and it lands on the unknown-extension fallthrough. A dropped reply here
            // would hang the client until its own timeout, which on this transport is
            // indistinguishable from ordinary slowness.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(3));
                d.Receive();

                uint id = d.NextId();
                d.Send(AgentSftpDriver.Extended(id, "statvfs@openssh.com"));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.OpUnsupported, s.Code);
                Assert.Contains("statvfs", s.Message);
            }
        }

        [Fact]
        public void A_forged_handle_fails_instead_of_addressing_some_other_file()
        {
            // Handle ids are never reused, so a stale or invented handle must be rejected rather than
            // resolving to whatever now sits at that slot. This is the assertion behind that claim,
            // and there is no way to make a client send it.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(3));
                d.Receive();

                uint id = d.NextId();
                d.Send(AgentSftpDriver.Read(id, "not-a-handle", 0, 1024));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.Failure, s.Code);
            }
        }

        [Fact]
        public void Every_request_gets_exactly_one_reply()
        {
            // The invariant a catch-all in Dispatch exists to keep. Worth asserting directly because
            // the failure mode is silence: a dropped reply is not an error a client can see, it just
            // waits. Three requests in, three replies out, ids matching and in order.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(3));
                d.Receive();

                uint a = d.NextId();
                uint b = d.NextId();
                uint c = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, a, "/C:/one"));
                d.Send(AgentSftpDriver.Extended(b, "nonsense@example.invalid"));
                d.Send(AgentSftpDriver.Read(c, "also-not-a-handle", 0, 16));

                Assert.Equal(a, AgentSftpDriver.ParseStatus(d.Receive()).Id);
                Assert.Equal(b, AgentSftpDriver.ParseStatus(d.Receive()).Id);
                Assert.Equal(c, AgentSftpDriver.ParseStatus(d.Receive()).Id);

                // And nothing extra follows.
                Assert.Throws<TimeoutException>(delegate { d.Receive(1500); });
            }
        }

        [Fact]
        public void Realpath_answers_for_a_path_that_does_not_exist()
        {
            // Established from the reference server, which does not require the path to exist. A
            // client uses realpath to canonicalise before creating something, so refusing a missing
            // path would break `put` to a new name.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(3));
                d.Receive();

                uint id = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.Realpath, id,
                                                 "/C:/definitely/not/here-" + Guid.NewGuid().ToString("N")));
                byte[] reply = d.Receive();
                Assert.Equal(AgentSftpDriver.SftpTypeByte.Name, AgentSftpDriver.TypeOf(reply));
            }
        }

        private static string[] Sorted(IEnumerable<string> items)
        {
            List<string> l = new List<string>(items);
            l.Sort(StringComparer.Ordinal);
            return l.ToArray();
        }
    }
}
