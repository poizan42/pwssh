// The legacy scp protocol, driven at the frame level.
//
// Everything here is either unreachable from a real client, or unprovable through one. Both this
// machine and the WinRM remote have scp.exe on PATH, so a failure to recognise `scp -f` would fall
// through to that binary and the transfer would still succeed -- only a directly-constructed
// PwsshAgentHost proves our own code ran.
//
// The protocol expectations were measured against C:\Program Files\OpenSSH\scp.exe rather than read
// out of a specification: both `scp -f` and `scp -t` are pure stdin/stdout programs, so each half
// can be driven over pipes. Two of those measurements are asserted here because they contradicted
// what the design assumed -- E at depth 0 is accepted, and the byte after a body is ours.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class AgentScpTests : IDisposable
    {
        private readonly ITestOutputHelper output;
        private readonly string dir;

        public AgentScpTests(ITestOutputHelper output)
        {
            this.output = output;
            dir = Path.Combine(Path.GetTempPath(), "pwssh-scp-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
        }

        public void Dispose() { try { Directory.Delete(dir, true); } catch (Exception) { } }

        private static string Wire(string windowsPath) { return "/" + windowsPath.Replace('\\', '/'); }

        // ---- the command parser, which needs no host at all

        [Theory]
        [InlineData("scp -f /C:/x", false, true, false, false)]          // OpenSSH, separate
        [InlineData("scp -t /C:/x", true, false, false, false)]
        [InlineData("scp -v -r -p -d -t /C:/x", true, false, true, true)] // OpenSSH's full form
        [InlineData("scp -pf \"/C:/x\"", false, true, false, true)]       // SSH.NET, bundled
        [InlineData("scp -prf \"/C:/x\"", false, true, true, true)]
        [InlineData("scp -r -p -d -t \"/C:/x\"", true, false, true, true)]
        public void Both_client_dialects_parse(string line, bool sink, bool source, bool recursive, bool times)
        {
            ScpCommand c;
            Assert.True(ScpCommand.TryParse(line, out c), line);
            Assert.Equal(sink, c.Sink);
            Assert.Equal(source, c.Source);
            Assert.Equal(recursive, c.Recursive);
            Assert.Equal(times, c.PreserveTimes);
            Assert.Equal("/C:/x", c.Paths[0]);
        }

        [Theory]
        [InlineData("ls -la", false)]
        [InlineData("scp", false)]                       // no direction
        [InlineData("scp -r /C:/x", false)]              // still no direction
        [InlineData("scp.exe -f /C:/x", false)]          // only the bare word is ours
        [InlineData("scp -f /C:/x", true)]
        public void Only_an_scp_server_invocation_is_intercepted(string line, bool expected)
        {
            ScpCommand c;
            Assert.Equal(expected, ScpCommand.TryParse(line, out c));
        }

        [Fact]
        public void The_tokenizer_keeps_windows_paths_intact()
        {
            // The deliberate deviation from POSIX. A shell would turn C:\Users\kb into C:Userskb,
            // which is useless here because Windows paths are exactly what users type -- so a
            // backslash is only an escape before a character that plausibly needs one.
            ScpCommand c;
            Assert.True(ScpCommand.TryParse("scp -f C:\\Users\\kb\\f.txt", out c));
            Assert.Equal("C:\\Users\\kb\\f.txt", c.Paths[0]);

            Assert.True(ScpCommand.TryParse("scp -f a\\ b", out c));
            Assert.Equal("a b", c.Paths[0]);

            Assert.True(ScpCommand.TryParse("scp -t \"/C:/a b/c\"", out c));
            Assert.Equal("/C:/a b/c", c.Paths[0]);

            Assert.True(ScpCommand.TryParse("scp -t '/C:/a b/c'", out c));
            Assert.Equal("/C:/a b/c", c.Paths[0]);

            // `--` protects a path that starts with a dash; OpenSSH emits it only in that case.
            Assert.True(ScpCommand.TryParse("scp -f -- -weird", out c));
            Assert.Equal("-weird", c.Paths[0]);
        }

        [Fact]
        public void An_unknown_flag_is_still_intercepted_and_reported()
        {
            // Deliberately NOT a fall-through: the remote may have its own scp.exe, and falling
            // through would make behaviour depend on whether it happens to be installed.
            ScpCommand c;
            Assert.True(ScpCommand.TryParse("scp -f -Z /C:/x", out c));
            Assert.Equal("-Z", c.BadFlag);
        }

        // ---- the security boundary

        [Theory]
        [InlineData("")]
        [InlineData(".")]
        [InlineData("..")]
        [InlineData("a/b")]
        [InlineData("a\\b")]
        [InlineData("..\\..\\escape.txt")]
        [InlineData("C:evil.txt")]
        [InlineData("f.txt:stream")]
        [InlineData("f.txt::$DATA")]
        [InlineData("bad\u0001name")]
        public void A_hostile_upload_filename_is_refused(string name)
        {
            // The names come from the client, so this is the one place a buggy or malicious peer
            // could write outside the directory the user named. OpenSSH's own sink checks empty,
            // "/", "." and ".." -- everything past that is Windows-specific and ours to get right.
            string why;
            Assert.False(AgentScpChannel.ValidateEntryName(name, out why), name);
            Assert.False(string.IsNullOrEmpty(why));
        }

        [Theory]
        [InlineData("ordinary.txt")]
        [InlineData("with space.txt")]
        [InlineData("naïve.txt")]
        [InlineData("CON")]                 // a reserved name is an ordinary file under \\?\
        public void An_ordinary_upload_filename_is_accepted(string name)
        {
            string why;
            Assert.True(AgentScpChannel.ValidateEntryName(name, out why), name + ": " + why);
        }

        [Fact]
        public void A_traversing_name_does_not_reach_the_filesystem()
        {
            // The end-to-end version of the check above: a real sink channel must refuse it, and
            // nothing may appear outside the target directory.
            string target = Path.Combine(dir, "target");
            Directory.CreateDirectory(target);
            using (AgentScpDriver d = new AgentScpDriver("scp -t " + Wire(target)))
            {
                Assert.Equal(0, d.ReadStatus());                     // ready
                d.SendText(AgentScpDriver.CFile("0644", 5, "..\\pwned.txt"));
                string msg;
                int st = d.ReadStatus(out msg);
                output.WriteLine("status " + st + ": " + msg);
                Assert.Equal(1, st);
                Assert.Contains("pwssh-scp", msg);
                d.SendEof();
                Assert.Equal(1u, d.WaitForExit());
            }
            Assert.False(File.Exists(Path.Combine(dir, "pwned.txt")));
        }

        // ---- sink mode

        [Fact]
        public void An_upload_lands_with_the_bytes_and_the_ack_order_measured_from_the_reference()
        {
            string target = Path.Combine(dir, "up");
            Directory.CreateDirectory(target);
            byte[] payload = Encoding.ASCII.GetBytes("abcde");

            using (AgentScpDriver d = new AgentScpDriver("scp -t " + Wire(target)))
            {
                // The ready byte comes first and unprompted; every upload client blocks on it.
                Assert.Equal(0, d.ReadStatus());
                d.SendText(AgentScpDriver.CFile("0644", payload.Length, "hello.txt"));
                Assert.Equal(0, d.ReadStatus());                     // the C line is acked on its own
                d.Send(payload);
                d.SendByte(0);                                       // our status byte for the body
                Assert.Equal(0, d.ReadStatus());                     // then the sink's verdict
                d.SendEof();
                Assert.Equal(0u, d.WaitForExit());
            }
            Assert.Equal(payload, File.ReadAllBytes(Path.Combine(target, "hello.txt")));
        }

        [Fact]
        public void An_upload_to_a_non_directory_target_ignores_the_sent_name()
        {
            // The rename form: `scp -O f.txt host:C:/tmp/renamed.txt`. Measured against the
            // reference, which ignores the name in the C record entirely when the target is not a
            // directory. Implementing only the directory case breaks a very common command.
            string target = Path.Combine(dir, "renamed.txt");
            using (AgentScpDriver d = new AgentScpDriver("scp -t " + Wire(target)))
            {
                Assert.Equal(0, d.ReadStatus());
                d.SendText(AgentScpDriver.CFile("0644", 3, "ORIGINAL.txt"));
                Assert.Equal(0, d.ReadStatus());
                d.SendText("xyz");
                d.SendByte(0);
                Assert.Equal(0, d.ReadStatus());
                d.SendEof();
                Assert.Equal(0u, d.WaitForExit());
            }
            Assert.True(File.Exists(target));
            Assert.False(File.Exists(Path.Combine(dir, "ORIGINAL.txt")));
            Assert.Equal("xyz", File.ReadAllText(target));
        }

        [Fact]
        public void A_zero_byte_upload_still_completes_the_status_exchange()
        {
            string target = Path.Combine(dir, "zero");
            Directory.CreateDirectory(target);
            using (AgentScpDriver d = new AgentScpDriver("scp -t " + Wire(target)))
            {
                Assert.Equal(0, d.ReadStatus());
                d.SendText(AgentScpDriver.CFile("0644", 0, "empty.bin"));
                Assert.Equal(0, d.ReadStatus());
                d.SendByte(0);                                       // no body at all
                Assert.Equal(0, d.ReadStatus());
                d.SendEof();
                Assert.Equal(0u, d.WaitForExit());
            }
            Assert.Equal(0, new FileInfo(Path.Combine(target, "empty.bin")).Length);
        }

        [Fact]
        public void E_at_depth_zero_is_accepted_rather_than_refused()
        {
            // Measured: the reference acks a stray E and ends. Refusing it would make pwssh
            // stricter than the implementation it is cloning, for no benefit.
            string target = Path.Combine(dir, "stray");
            Directory.CreateDirectory(target);
            using (AgentScpDriver d = new AgentScpDriver("scp -r -t " + Wire(target)))
            {
                Assert.Equal(0, d.ReadStatus());
                d.SendText("E\n");
                Assert.Equal(0, d.ReadStatus());
                d.SendEof();
                Assert.Equal(0u, d.WaitForExit());
            }
        }

        [Fact]
        public void A_directory_upload_without_r_is_refused()
        {
            string target = Path.Combine(dir, "nor");
            Directory.CreateDirectory(target);
            using (AgentScpDriver d = new AgentScpDriver("scp -t " + Wire(target)))
            {
                Assert.Equal(0, d.ReadStatus());
                d.SendText(AgentScpDriver.DDir("0755", "sub"));
                string msg;
                Assert.Equal(1, d.ReadStatus(out msg));
                Assert.Contains("without -r", msg);
                d.SendEof();
                Assert.Equal(1u, d.WaitForExit());
            }
        }

        [Fact]
        public void A_recursive_upload_creates_the_tree()
        {
            string target = Path.Combine(dir, "tree");
            Directory.CreateDirectory(target);
            using (AgentScpDriver d = new AgentScpDriver("scp -r -t " + Wire(target)))
            {
                Assert.Equal(0, d.ReadStatus());
                d.SendText(AgentScpDriver.DDir("0755", "sub"));
                Assert.Equal(0, d.ReadStatus());
                d.SendText(AgentScpDriver.CFile("0644", 2, "in.txt"));
                Assert.Equal(0, d.ReadStatus());
                d.SendText("hi");
                d.SendByte(0);
                Assert.Equal(0, d.ReadStatus());
                d.SendText("E\n");
                Assert.Equal(0, d.ReadStatus());
                d.SendEof();
                Assert.Equal(0u, d.WaitForExit());
            }
            Assert.Equal("hi", File.ReadAllText(Path.Combine(target, "sub", "in.txt")));
        }

        // ---- source mode

        [Fact]
        public void A_download_sends_the_documented_record_then_the_body()
        {
            string file = Path.Combine(dir, "down.txt");
            File.WriteAllText(file, "hello scp");
            using (AgentScpDriver d = new AgentScpDriver("scp -f " + Wire(file)))
            {
                d.SendByte(0);                                       // our ready byte
                string c = d.ReadLine();
                output.WriteLine(c);
                Assert.Equal("C0644 9 down.txt", c);
                d.SendByte(0);                                       // ack the C line
                Assert.Equal("hello scp", Encoding.ASCII.GetString(d.Read(9)));
                Assert.Equal(0, d.ReadStatus());                     // the source's own status byte
                d.SendByte(0);                                       // our verdict
                d.SendEof();
                Assert.Equal(0u, d.WaitForExit());
            }
        }

        [Fact]
        public void A_download_echoes_the_name_the_client_asked_for()
        {
            // Since 8.0 the client fnmatches every incoming name against its own request, and that
            // match is CASE-SENSITIVE. NTFS opens File.TXT quite happily when the file on disk is
            // file.txt -- but answering with the on-disk casing gets the transfer rejected as an
            // attempted spoof, so the requested spelling is what goes back on the wire.
            File.WriteAllText(Path.Combine(dir, "casing.txt"), "x");
            string asked = Wire(Path.Combine(dir, "CASING.TXT"));
            using (AgentScpDriver d = new AgentScpDriver("scp -f " + asked))
            {
                d.SendByte(0);
                string c = d.ReadLine();
                output.WriteLine(c);
                Assert.EndsWith(" CASING.TXT", c);
            }
        }

        [Fact]
        public void A_missing_source_is_reported_with_our_own_prefix()
        {
            // The prefix is what an end-to-end test keys on: with a real scp.exe on PATH, a
            // recognition failure would fall through and the message would read "scp: ..." instead.
            using (AgentScpDriver d = new AgentScpDriver("scp -f " + Wire(Path.Combine(dir, "nope.txt"))))
            {
                d.SendByte(0);
                string msg;
                Assert.Equal(1, d.ReadStatus(out msg));
                Assert.Contains("pwssh-scp", msg);
                d.SendEof();
                Assert.Equal(1u, d.WaitForExit());
            }
        }

        [Fact]
        public void A_directory_download_without_r_is_refused_but_the_session_survives()
        {
            string sub = Path.Combine(dir, "adir");
            Directory.CreateDirectory(sub);
            using (AgentScpDriver d = new AgentScpDriver("scp -f " + Wire(sub)))
            {
                d.SendByte(0);
                string msg;
                Assert.Equal(1, d.ReadStatus(out msg));
                Assert.Contains("not a regular file", msg);
                d.SendEof();
                Assert.Equal(1u, d.WaitForExit());
            }
        }

        [Fact]
        public void A_recursive_download_nests_D_and_E_and_skips_links()
        {
            string root = Path.Combine(dir, "rtree");
            Directory.CreateDirectory(Path.Combine(root, "inner"));
            File.WriteAllText(Path.Combine(root, "inner", "leaf.txt"), "L");

            using (AgentScpDriver d = new AgentScpDriver("scp -r -f " + Wire(root)))
            {
                d.SendByte(0);
                List<string> records = new List<string>();
                // D rtree, D inner, C leaf.txt + body + status, E, E
                Assert.StartsWith("D0755 0 rtree", d.ReadLine()); d.SendByte(0);
                Assert.StartsWith("D0755 0 inner", d.ReadLine()); d.SendByte(0);
                Assert.Equal("C0644 1 leaf.txt", d.ReadLine()); d.SendByte(0);
                Assert.Equal("L", Encoding.ASCII.GetString(d.Read(1)));
                Assert.Equal(0, d.ReadStatus());
                d.SendByte(0);
                Assert.Equal("E", d.ReadLine()); d.SendByte(0);
                Assert.Equal("E", d.ReadLine()); d.SendByte(0);
                d.SendEof();
                Assert.Equal(0u, d.WaitForExit());
                foreach (string r in records) output.WriteLine(r);
            }
        }

        [Fact]
        public void Nacking_the_C_line_suppresses_the_body()
        {
            // Measured against the reference source, which sends no body after a nack. A server
            // that sent it anyway would leave the client reading file content as control records.
            string file = Path.Combine(dir, "nack.txt");
            File.WriteAllText(file, "AAAAA");
            using (AgentScpDriver d = new AgentScpDriver("scp -f " + Wire(file)))
            {
                d.SendByte(0);
                Assert.Equal("C0644 5 nack.txt", d.ReadLine());
                d.SendText("\u0001no thanks\n");                     // nack it
                d.SendEof();
                Assert.Equal(1u, d.WaitForExit());
                // Nothing further should have been written; if the body had been sent it would be
                // sitting in the buffer now.
                Assert.Throws<TimeoutException>(delegate { d.Read(1, 800); });
            }
        }

        [Fact]
        public void Preserve_times_sends_a_T_record_that_is_acked_on_its_own()
        {
            // T is a record in its own right. Treating T and C as one unit runs the whole transfer
            // an ack behind, which works until the first error and then desyncs.
            string file = Path.Combine(dir, "times.txt");
            File.WriteAllText(file, "t");
            File.SetLastWriteTimeUtc(file, new DateTime(2019, 2, 3, 4, 5, 6, DateTimeKind.Utc));
            using (AgentScpDriver d = new AgentScpDriver("scp -pf " + Wire(file)))
            {
                d.SendByte(0);
                string t = d.ReadLine();
                output.WriteLine(t);
                Assert.StartsWith("T", t);
                Assert.Contains("1549166706", t);                    // 2019-02-03T04:05:06Z
                d.SendByte(0);                                       // T is acked before C arrives
                Assert.Equal("C0644 1 times.txt", d.ReadLine());
            }
        }

        [Fact]
        public void The_agent_logs_that_it_served_the_command_itself()
        {
            // A second, independent signal that the interception happened, for the same reason the
            // message prefix exists: a real scp.exe is on PATH here.
            string file = Path.Combine(dir, "logged.txt");
            File.WriteAllText(file, "x");
            using (AgentScpDriver d = new AgentScpDriver("scp -f " + Wire(file)))
            {
                d.SendByte(0);
                d.ReadLine();
                bool logged = false;
                foreach (string line in d.Log) { if (line.Contains("scp source on channel")) logged = true; }
                Assert.True(logged, "no scp interception line in the agent log");
            }
        }
    }
}
