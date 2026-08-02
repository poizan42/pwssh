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
                        "fstatvfs@openssh.com",
                        "fsync@openssh.com",
                        "hardlink@openssh.com",
                        "limits@openssh.com",
                        "lsetstat@openssh.com",
                        "posix-rename@openssh.com",
                        "statvfs@openssh.com",
                    },
                    Sorted(ext.Keys));

                // The two statvfs entries must advertise "2" and not "1". The client compares the
                // value against "2" exactly before it will use either, so "1" reads to it as no
                // support at all -- and the symptom is `df` printing "Server does not support
                // statvfs@openssh.com extension" against a server that implements it perfectly.
                Assert.Equal("2", ext["statvfs@openssh.com"]);
                Assert.Equal("2", ext["fstatvfs@openssh.com"]);
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
        public void An_unknown_extension_is_refused_rather_than_ignored()
        {
            // users-groups-by-id@openssh.com is the concrete case: the client sends it to put owner
            // names on `ls -l`, we do not implement it, and it lands on the unknown-extension
            // fallthrough. A dropped reply here would hang the client until its own timeout, which
            // on this transport is indistinguishable from ordinary slowness.
            //
            // This case used to use statvfs@openssh.com, which is now implemented. The replacement
            // is picked to stay valid: Windows has no uid or gid, every file here reports 0 for
            // both, and mapping that to a single name for the whole filesystem would be worse than
            // the numeral -- so this one is not coming. expand-path@openssh.com is the other name
            // the client knows and we do not answer, and it deliberately is NOT used here, because
            // tilde expansion is something we might reasonably want one day.
            using (AgentSftpDriver d = new AgentSftpDriver())
            {
                d.Send(AgentSftpDriver.Init(3));
                d.Receive();

                uint id = d.NextId();
                d.Send(AgentSftpDriver.Extended(id, "users-groups-by-id@openssh.com"));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.OpUnsupported, s.Code);
                Assert.Contains("users-groups-by-id", s.Message);
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
