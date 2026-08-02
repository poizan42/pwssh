// SYMLINK and READLINK at the frame level, where the stock client cannot reach: `sftp` has `ln -s`
// but no `readlink` command at all, so resolution is only testable from here.
//
// The suite is split along one line: **resolution is always deterministic, creation may legitimately
// fail.** Reading a link needs no privilege and Windows ships reparse points of both tags, so those
// cases assert unconditionally. Creating one depends on the token, so those cases probe capability
// and then assert whichever branch they are in — never skip. Measured on the two machines this runs
// on: the WinRM remote has a full token with SeCreateSymbolicLinkPrivilege enabled, and this client
// machine has a filtered token with the privilege absent but Developer Mode on, where
// CreateSymbolicLinkW succeeds with SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE and fails 1314
// without it. So the two suites genuinely exercise the two different routes.

using System;
using System.IO;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class AgentSymlinkTests : IDisposable
    {
        private readonly ITestOutputHelper output;
        private readonly string dir;

        public AgentSymlinkTests(ITestOutputHelper output)
        {
            this.output = output;
            dir = Path.Combine(Path.GetTempPath(), "pwssh-link-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
        }

        public void Dispose()
        {
            // Directory.Delete does not follow reparse points, so a link inside here cannot take its
            // target's contents with it.
            try { Directory.Delete(dir, true); } catch { }
        }

        private static string Wire(string windowsPath)
        {
            return "/" + windowsPath.Replace('\\', '/');
        }

        /// <summary>Sends INIT and swallows the VERSION, which every case needs first.</summary>
        private static AgentSftpDriver Started()
        {
            AgentSftpDriver d = new AgentSftpDriver();
            d.Send(AgentSftpDriver.Init(3));
            d.Receive();
            return d;
        }

        // ---------------------------------------------------------------- resolution

        [Theory]
        [InlineData(@"Users\All Users")]        // tag 0xA000000C, a directory SYMLINK to C:\ProgramData
        [InlineData(@"Users\Default User")]     // tag 0xA0000003, a JUNCTION to C:\Users\Default
        [InlineData(@"Documents and Settings")] // tag 0xA0000003
        public void Readlink_resolves_a_stock_reparse_point(string relative)
        {
            // Both tags, on links every Windows install carries and any user can read, so this needs
            // no privilege and creates nothing. The two tags have DIFFERENT reparse buffer shapes --
            // a symlink has a Flags field and its path starts at offset 20, a junction has no Flags
            // and starts at 16 -- so covering only one would leave the other parser branch unrun.
            string path = Path.Combine(Path.GetPathRoot(Environment.GetFolderPath(
                Environment.SpecialFolder.Windows)), relative);
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                output.WriteLine("not present on this machine, nothing to assert: " + path);
                return;
            }

            // The platform's own answer, used as an oracle so the parser is checked against Windows
            // rather than against its own arithmetic.
            string expected = new DirectoryInfo(path).LinkTarget;
            Assert.False(string.IsNullOrEmpty(expected), "no LinkTarget from .NET for " + path);

            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, id, Wire(path)));
                byte[] reply = d.Receive();
                Assert.Equal(AgentSftpDriver.SftpTypeByte.Name, AgentSftpDriver.TypeOf(reply));

                string got = AgentSftpDriver.ParseName(reply);
                output.WriteLine(path + "  ->  " + got + "   (.NET says " + expected + ")");
                Assert.Equal("/" + expected.Replace('\\', '/'), got);
            }
        }

        [Fact]
        public void Readlink_on_a_plain_file_fails_rather_than_reporting_nothing()
        {
            // POSIX readlink on a non-link is EINVAL, which OpenSSH maps to FAILURE -- deliberately
            // not NO_SUCH_FILE, which would tell the client the path is absent when it is not.
            string file = Path.Combine(dir, "ordinary.txt");
            File.WriteAllText(file, "x");
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, id, Wire(file)));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(AgentSftpDriver.StatusCode.Failure, s.Code);
                Assert.Contains("not a link", s.Message);
            }
        }

        [Fact]
        public void Readlink_on_an_absent_path_reports_no_such_file()
        {
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, id,
                                                 Wire(Path.Combine(dir, "nothing-here.txt"))));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(AgentSftpDriver.StatusCode.NoSuchFile, s.Code);
            }
        }

        // ---------------------------------------------------------------- argument order

        [Fact]
        public void Symlink_takes_the_target_first_and_the_link_second()
        {
            // The highest-value assertion in this file, and it needs no privilege and creates nothing.
            //
            // OpenSSH sends the two paths in the reverse of the draft's order, and a swapped
            // implementation is SILENT -- it creates the link under the other name and reports
            // success. Here the link path names a directory that does not exist, so the error message
            // must name THAT path; a reversed implementation would report the target instead, which
            // exists and would fail differently or not at all.
            //
            // This holds whichever error the machine produces -- ERROR_PATH_NOT_FOUND where creation
            // is permitted, ERROR_PRIVILEGE_NOT_HELD where it is not -- because Win32Fs.Error appends
            // the link path either way.
            string marker = "pwssh-no-such-dir-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.Symlink(id, "/C:/Windows", "/C:/" + marker + "/lnk"));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                output.WriteLine("status " + s.Code + ": " + s.Message);

                Assert.NotEqual(AgentSftpDriver.StatusCode.Ok, s.Code);
                Assert.Contains(marker, s.Message);
                Assert.DoesNotContain("Windows", s.Message);
            }
        }

        [Fact]
        public void An_empty_target_or_link_is_refused_rather_than_pointing_at_the_home_directory()
        {
            // ToWindows("") returns the home directory, so an unchecked empty target would silently
            // create a link to the user's profile and an empty link path would try to create one
            // named it. SshLikeReader.Text() returns "" on a truncated read rather than throwing, so
            // this is reachable from a malformed request as well as a daft one.
            using (AgentSftpDriver d = Started())
            {
                uint a = d.NextId();
                d.Send(AgentSftpDriver.Symlink(a, "", Wire(Path.Combine(dir, "x"))));
                Assert.Equal(AgentSftpDriver.StatusCode.BadMessage, AgentSftpDriver.ParseStatus(d.Receive()).Code);

                uint b = d.NextId();
                d.Send(AgentSftpDriver.Symlink(b, "/C:/Windows", ""));
                Assert.Equal(AgentSftpDriver.StatusCode.BadMessage, AgentSftpDriver.ParseStatus(d.Receive()).Code);
            }
        }

        // ---------------------------------------------------------------- creation

        /// <summary>
        /// Whether this machine can create a symbolic link at all, decided by trying rather than by
        /// inspecting the token — Developer Mode, the privilege and the token's filtering interact,
        /// and the only question that matters is whether the call succeeds.
        /// </summary>
        private bool CanCreateLinks()
        {
            string probe = Path.Combine(dir, "capability-probe");
            try
            {
                Pwssh.Win32Fs.CreateSymbolicLink(probe, Path.Combine(dir, "nowhere"), false);
                File.Delete(probe);
                return true;
            }
            catch (Exception) { return false; }
        }

        private void AssertRefusedWithAnActionableMessage(AgentSftpDriver.Status s)
        {
            // The incapable branch is not a consolation prize: it is the only test that the message
            // a user actually reads tells them what to do about it.
            Assert.Equal(AgentSftpDriver.StatusCode.PermissionDenied, s.Code);
            Assert.Contains("SeCreateSymbolicLinkPrivilege", s.Message);
            Assert.Contains("Developer Mode", s.Message);
            Assert.DoesNotContain("elevation", s.Message);
        }

        [Fact]
        public void An_absolute_target_round_trips_through_readlink()
        {
            string target = Path.Combine(dir, "target.txt");
            File.WriteAllText(target, "x");
            string link = Path.Combine(dir, "abs-link");

            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.Symlink(id, Wire(target), Wire(link)));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());

                if (!CanCreateLinks()) { AssertRefusedWithAnActionableMessage(s); return; }
                Assert.Equal(AgentSftpDriver.StatusCode.Ok, s.Code);

                uint rid = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, rid, Wire(link)));
                Assert.Equal(Wire(target), AgentSftpDriver.ParseName(d.Receive()));
            }
        }

        [Fact]
        public void A_relative_target_is_stored_verbatim_and_comes_back_relative()
        {
            // The case ToWindows would silently mangle: it resolves a relative path against
            // USERPROFILE rather than against the link's own directory, and Normalize then
            // upper-cases the drive and trims trailing dots. The stored string must be untouched.
            File.WriteAllText(Path.Combine(dir, "sibling.txt"), "x");
            string link = Path.Combine(dir, "rel-link");

            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.Symlink(id, "sibling.txt", Wire(link)));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());

                if (!CanCreateLinks()) { AssertRefusedWithAnActionableMessage(s); return; }
                Assert.Equal(AgentSftpDriver.StatusCode.Ok, s.Code);

                uint rid = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, rid, Wire(link)));
                string got = AgentSftpDriver.ParseName(d.Receive());
                output.WriteLine("stored target: " + got);
                Assert.Equal("sibling.txt", got);          // relative, and with no leading slash added
            }
        }

        [Fact]
        public void A_relative_target_pointing_at_a_directory_yields_a_directory_link()
        {
            // MANDATORY, and it exists because the obvious relative case above would pass while this
            // is broken. Windows types a link at creation, and the type is probed by resolving the
            // relative target against the link's parent -- but TryGetInfo prefixes with \\?\, under
            // which a ".." is looked up as a directory literally named "..". Without running the
            // combined path through Normalize first, the probe always reports "absent", every
            // relative target falls back to the file guess, and a link to a directory is created
            // file-typed and does not traverse. A `..` in the target is what exposes it.
            string sub = Path.Combine(dir, "subdir");
            Directory.CreateDirectory(sub);
            Directory.CreateDirectory(Path.Combine(dir, "nested"));
            string link = Path.Combine(dir, "nested", "up-and-over");

            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.Symlink(id, "../subdir", Wire(link)));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());

                if (!CanCreateLinks()) { AssertRefusedWithAnActionableMessage(s); return; }
                Assert.Equal(AgentSftpDriver.StatusCode.Ok, s.Code);

                // The link must be DIRECTORY-typed, or Windows will not traverse it.
                FileAttributes attrs = new DirectoryInfo(link).Attributes;
                output.WriteLine("attributes: " + attrs);
                Assert.True((attrs & FileAttributes.Directory) != 0,
                    "the link was created file-typed, so it cannot be traversed: " + attrs);
                Assert.True((attrs & FileAttributes.ReparsePoint) != 0);

                // And the stored target is still the relative string the client sent.
                uint rid = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.ReadLink, rid, Wire(link)));
                Assert.Equal("../subdir", AgentSftpDriver.ParseName(d.Receive()));
            }
        }

        [Fact]
        public void A_dangling_target_is_allowed_and_lstat_reports_a_link()
        {
            // POSIX permits a link to something that does not exist, and clients rely on it.
            string link = Path.Combine(dir, "dangling");
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.Symlink(id, "nowhere-at-all.txt", Wire(link)));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());

                if (!CanCreateLinks()) { AssertRefusedWithAnActionableMessage(s); return; }
                Assert.Equal(AgentSftpDriver.StatusCode.Ok, s.Code);

                uint lid = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.Lstat, lid, Wire(link)));
                byte[] reply = d.Receive();
                Assert.Equal(AgentSftpDriver.SftpTypeByte.Attrs, AgentSftpDriver.TypeOf(reply));
                Assert.True(AgentSftpDriver.IsSymlinkMode(reply), "LSTAT did not report S_IFLNK");
            }
        }

        [Fact]
        public void Creating_a_link_over_an_existing_name_fails()
        {
            string link = Path.Combine(dir, "taken");
            File.WriteAllText(link, "already here");
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.Symlink(id, "whatever.txt", Wire(link)));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.NotEqual(AgentSftpDriver.StatusCode.Ok, s.Code);
                // Still a file, not replaced by a link.
                Assert.Equal("already here", File.ReadAllText(link));
            }
        }
    }
}
