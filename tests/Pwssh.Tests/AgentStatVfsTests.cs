// statvfs@openssh.com and fstatvfs@openssh.com — what `sftp`'s `df` asks for.
//
// Almost all of it is at the frame level, because the stock client cannot express the interesting
// cases: it has no way to send fstatvfs at all, it renders a status through its own fx2txt rather
// than showing the server's message, and it prints a formatted table rather than the eleven raw
// fields. One SSH.NET case is here as well, for the one thing the frame driver cannot reach — see
// the comment on it.
//
// There is no reference server to compare against. Windows ships no sftp-server.exe here, and the
// Microsoft port compiles statvfs support under HAVE_STATVFS, which Windows does not have — so
// unlike every other SFTP decision in this project, the conventions could not be settled by
// probing a real implementation. The format comes from OpenSSH's PROTOCOL; the numbers are checked
// against DriveInfo, with the caveat recorded on that test.

using System;
using System.IO;
using Renci.SshNet;
using Renci.SshNet.Sftp;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class AgentStatVfsTests : IDisposable
    {
        private const string StatVfs = "statvfs@openssh.com";
        private const string FStatVfs = "fstatvfs@openssh.com";

        private readonly ITestOutputHelper output;
        private readonly string dir;

        public AgentStatVfsTests(ITestOutputHelper output)
        {
            this.output = output;
            dir = Path.Combine(Path.GetTempPath(),
                               "pwssh-vfs-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
        }

        public void Dispose()
        {
            try { Directory.Delete(dir, true); } catch (Exception) { }
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

        private AgentSftpDriver.StatVfs Ask(AgentSftpDriver d, string path)
        {
            uint id = d.NextId();
            d.Send(AgentSftpDriver.ExtendedOneString(id, StatVfs, path));
            AgentSftpDriver.StatVfs s = AgentSftpDriver.ParseStatVfs(d.Receive());
            Assert.Equal(id, s.Id);
            return s;
        }

        // ---- the shape of a reply

        [Fact]
        public void Statvfs_on_a_directory_reports_a_consistent_filesystem()
        {
            using (AgentSftpDriver d = Started())
            {
                AgentSftpDriver.StatVfs s = Ask(d, Wire(dir));
                output.WriteLine("frsize={0} blocks={1} bfree={2} bavail={3} fsid={4} flag=0x{5:x} namemax={6}",
                                 s.FrSize, s.Blocks, s.BFree, s.BAvail, s.Fsid, s.Flag, s.NameMax);

                // ParseStatVfs already insisted on exactly eleven fields and no trailing bytes.
                // That is the assertion with teeth: OpenSSH's client calls fatal_fr() on a field it
                // cannot read, so a reply one field short kills the user's sftp process rather than
                // reporting an error, while anything trailing is silently ignored.
                Assert.Equal(s.FrSize, s.BSize);
                Assert.True(s.FrSize > 0, "block size must never be zero");
                Assert.True((s.FrSize & (s.FrSize - 1)) == 0, "block size should be a power of two, got " + s.FrSize);
                Assert.True(s.Blocks > 0, "a real volume has blocks");

                // Holds on an unquota'd volume, which is what both test machines are. Under an NTFS
                // quota the two figures come from different scopes -- see the clamp in SendStatVfs
                // -- and this is the invariant that clamp exists to preserve.
                Assert.True(s.BAvail <= s.BFree, "bavail " + s.BAvail + " > bfree " + s.BFree);
                Assert.True(s.BFree <= s.Blocks, "bfree " + s.BFree + " > blocks " + s.Blocks);

                Assert.Equal(255u, (uint)s.NameMax);
                Assert.Equal(0u, (uint)s.Files);          // Windows has no inode count; df -i prints ERR
                Assert.Equal(0u, (uint)s.FFree);
                Assert.Equal(0u, (uint)s.FAvail);
                Assert.Equal(0x2u, (uint)(s.Flag & 0x2)); // ST_NOSUID: true, and unconditional
                Assert.Equal(0u, (uint)(s.Flag & 0x1));   // the temp volume is not read-only
            }
        }

        [Fact]
        public void The_capacity_figures_agree_with_the_platform()
        {
            // DriveInfo is the closest thing to an oracle available, and it is worth being precise
            // about what it does and does not prove. .NET implements TotalSize, TotalFreeSpace and
            // AvailableFreeSpace on GetDiskFreeSpaceEx -- the same call the agent uses -- so this
            // checks the division by the cluster size and the resolution of the path to its mount
            // root. It does NOT check that GetDiskFreeSpaceEx was the right API to choose: a
            // systematically wrong source would agree with itself here.
            DriveInfo drive = new DriveInfo(Path.GetPathRoot(dir));
            using (AgentSftpDriver d = Started())
            {
                AgentSftpDriver.StatVfs s = Ask(d, Wire(dir));

                ulong total = s.FrSize * s.Blocks;
                ulong free = s.FrSize * s.BFree;
                output.WriteLine("statvfs total={0} free={1}; DriveInfo total={2} free={3}",
                                 total, free, drive.TotalSize, drive.TotalFreeSpace);

                // Truncating division loses less than one cluster.
                Assert.True(Diff(total, (ulong)drive.TotalSize) <= s.FrSize,
                            "total " + total + " vs DriveInfo " + drive.TotalSize);
                // Free space moves on a live machine between the two calls, so this is a sanity
                // band rather than an equality: 64 MiB is far tighter than any plausible bug and
                // far looser than ordinary background writes.
                Assert.True(Diff(free, (ulong)drive.TotalFreeSpace) <= 64UL * 1024 * 1024,
                            "free " + free + " vs DriveInfo " + drive.TotalFreeSpace);
            }
        }

        private static ulong Diff(ulong a, ulong b)
        {
            return a > b ? a - b : b - a;
        }

        [Fact]
        public void Statvfs_takes_a_file_as_well_as_a_directory()
        {
            // POSIX statvfs accepts any existing path and describes the filesystem holding it. An
            // implementation that quietly required a directory -- which is what GetDiskFreeSpaceEx
            // alone would suggest -- passes every other case here and fails only this one.
            string file = Path.Combine(dir, "probe.txt");
            File.WriteAllText(file, "x");
            using (AgentSftpDriver d = Started())
            {
                AgentSftpDriver.StatVfs viaFile = Ask(d, Wire(file));
                AgentSftpDriver.StatVfs viaDir = Ask(d, Wire(dir));
                Assert.Equal(viaDir.Fsid, viaFile.Fsid);
                Assert.Equal(viaDir.Blocks, viaFile.Blocks);
            }
        }

        // ---- refusals

        [Fact]
        public void Statvfs_on_an_absent_path_reports_no_such_file()
        {
            // The existence check is the whole point of this case. GetVolumePathNameW succeeds on a
            // path that is not there and hands back the volume root, so without an explicit stat a
            // `df` on a typo would confidently describe the volume instead of failing.
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.ExtendedOneString(
                           id, StatVfs, Wire(Path.Combine(dir, "no-such-thing-" + Guid.NewGuid().ToString("N")))));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.NoSuchFile, s.Code);
            }
        }

        [Fact]
        public void Statvfs_on_the_virtual_root_is_refused_with_a_reason()
        {
            // "/" is a listing of drive letters this server invents, not a filesystem, so there is
            // no honest set of numbers for it. Refusing is a choice rather than a necessity -- the
            // client guards its own division, so zeroes would print ERR rather than crash -- and
            // the message is what makes it a refusal instead of a malfunction.
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.ExtendedOneString(id, StatVfs, "/"));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.Failure, s.Code);
                Assert.Contains("not a filesystem", s.Message);
            }
        }

        // ---- the handle form

        [Fact]
        public void Fstatvfs_on_a_file_handle_matches_the_path_form()
        {
            string file = Path.Combine(dir, "handle.txt");
            File.WriteAllText(file, "x");
            using (AgentSftpDriver d = Started())
            {
                uint openId = d.NextId();
                d.Send(AgentSftpDriver.Open(openId, Wire(file), 0x1));       // SSH_FXF_READ
                string handle = AgentSftpDriver.ParseHandle(d.Receive());

                uint id = d.NextId();
                d.Send(AgentSftpDriver.ExtendedOneString(id, FStatVfs, handle));
                AgentSftpDriver.StatVfs viaHandle = AgentSftpDriver.ParseStatVfs(d.Receive());
                Assert.Equal(id, viaHandle.Id);

                AgentSftpDriver.StatVfs viaPath = Ask(d, Wire(file));
                Assert.Equal(viaPath.Fsid, viaHandle.Fsid);
                Assert.Equal(viaPath.Blocks, viaHandle.Blocks);
            }
        }

        [Fact]
        public void Fstatvfs_works_on_a_directory_handle()
        {
            // Every other handle-taking request in the server rejects a directory handle, because
            // they all read or write bytes. This one must not: a directory is a perfectly ordinary
            // thing to ask which filesystem it is on, and the bug this catches is inheriting the
            // "h.File == null" guard by copying the request next door.
            using (AgentSftpDriver d = Started())
            {
                uint openId = d.NextId();
                d.Send(AgentSftpDriver.OneString(AgentSftpDriver.SftpTypeByte.Opendir, openId, Wire(dir)));
                string handle = AgentSftpDriver.ParseHandle(d.Receive());

                uint id = d.NextId();
                d.Send(AgentSftpDriver.ExtendedOneString(id, FStatVfs, handle));
                AgentSftpDriver.StatVfs s = AgentSftpDriver.ParseStatVfs(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.True(s.Blocks > 0);
            }
        }

        [Fact]
        public void Fstatvfs_on_a_forged_handle_fails()
        {
            using (AgentSftpDriver d = Started())
            {
                uint id = d.NextId();
                d.Send(AgentSftpDriver.ExtendedOneString(id, FStatVfs, "not-a-handle"));
                AgentSftpDriver.Status s = AgentSftpDriver.ParseStatus(d.Receive());
                Assert.Equal(id, s.Id);
                Assert.Equal(AgentSftpDriver.StatusCode.Failure, s.Code);
            }
        }

        // ---- through the engine

        [Fact]
        public void A_library_client_can_read_the_status_through_the_read_ahead_proxy()
        {
            // The only case here that goes through PwsshSftpReadAhead. Everything above talks
            // straight to PwsshAgentHost, so an EXTENDED_REPLY crossing the read-ahead proxy is
            // otherwise untested by anything but the PowerShell suite -- and the request direction
            // lands in that proxy's default arm, which invalidates speculative metadata.
            //
            // It doubles as a second, independent parser of the reply: SSH.NET reads the eleven
            // fields itself, so a field order this project's own driver agrees with by construction
            // still has to satisfy someone else's implementation.
            string file = Path.Combine(dir, "through-engine.txt");
            File.WriteAllText(file, "x");
            using (PwsshTestHost host = new PwsshTestHost())
            {
                using (SftpClient sftp = SshNetClient.Sftp(host))
                {
                    sftp.OperationTimeout = TimeSpan.FromSeconds(45);
                    sftp.Connect();
                    SftpFileSystemInformation info = sftp.GetStatus(Wire(file));
                    // MaxNameLenght is spelt that way in SSH.NET's public API, not here. Leave it.
                    output.WriteLine("blocksize={0} blocks={1} free={2} avail={3} maxname={4} setuid={5}",
                                     info.BlockSize, info.TotalBlocks, info.FreeBlocks,
                                     info.AvailableBlocks, info.MaxNameLenght, info.SupportsSetUid);
                    Assert.True(info.TotalBlocks > 0);
                    Assert.True(info.AvailableBlocks <= info.FreeBlocks);
                    Assert.Equal(255u, (uint)info.MaxNameLenght);
                    // Decoded from the f_flag word by someone else's parser, which is what makes it
                    // worth asserting: ST_NOSUID is set unconditionally because Windows has no
                    // setuid, and this is the only place that claim is read back rather than
                    // written. A field-order slip would show up here as much as in the numbers.
                    Assert.False(info.SupportsSetUid);
                    Assert.False(info.IsReadOnly);
                }
            }
        }
    }
}
