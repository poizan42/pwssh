// SSH.NET's ScpClient against the legacy scp protocol, through the whole engine.
//
// Two things make this worth having on top of the frame-level driver.
//
// It is the only client here that sends the BUNDLED flag form and a double-quoted path -- SSH.NET
// emits `scp -pf "..."` and `scp -prf "..."` where OpenSSH emits `scp -v -r -p -d -t ...` with
// separate flags and no quoting. A parser that handled only one dialect would pass everything else
// and fail exactly here.
//
// And it is an independent implementation of the other half of the protocol. The frame driver is
// code I wrote to match what I measured; ScpClient was written by someone else against a real
// server, so it agreeing is a genuinely separate signal.

using System;
using System.IO;
using System.Text;
using Renci.SshNet;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class ScpClientTests : IDisposable
    {
        private readonly ITestOutputHelper output;
        private readonly string dir;

        public ScpClientTests(ITestOutputHelper output)
        {
            this.output = output;
            dir = Path.Combine(Path.GetTempPath(), "pwssh-scpc-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
        }

        public void Dispose() { try { Directory.Delete(dir, true); } catch (Exception) { } }

        private static string Wire(string windowsPath) { return "/" + windowsPath.Replace('\\', '/'); }

        [Fact]
        public void A_library_client_downloads_a_file_bit_exactly()
        {
            byte[] payload = new byte[200 * 1024];
            new Random(4321).NextBytes(payload);
            string remote = Path.Combine(dir, "download.bin");
            File.WriteAllBytes(remote, payload);

            using (PwsshTestHost host = new PwsshTestHost())
            using (ScpClient scp = SshNetClient.Scp(host))
            {
                scp.Connect();
                using (MemoryStream got = new MemoryStream())
                {
                    scp.Download(Wire(remote), got);
                    Assert.Equal(payload, got.ToArray());
                }
            }
        }

        [Fact]
        public void A_library_client_uploads_a_file_bit_exactly()
        {
            byte[] payload = new byte[128 * 1024];
            new Random(8765).NextBytes(payload);
            string target = Path.Combine(dir, "uploaded.bin");

            using (PwsshTestHost host = new PwsshTestHost())
            using (ScpClient scp = SshNetClient.Scp(host))
            {
                scp.Connect();
                using (MemoryStream src = new MemoryStream(payload))
                {
                    scp.Upload(src, Wire(target));
                }
            }
            Assert.Equal(payload, File.ReadAllBytes(target));
        }

        [Fact]
        public void A_library_client_downloads_a_directory_recursively()
        {
            // This is the `scp -prf "..."` path -- bundled flags, quoted path, and the D/E nesting
            // with T records interleaved, all at once.
            string tree = Path.Combine(dir, "tree");
            Directory.CreateDirectory(Path.Combine(tree, "inner"));
            File.WriteAllText(Path.Combine(tree, "top.txt"), "top");
            File.WriteAllText(Path.Combine(tree, "inner", "leaf.txt"), "leaf");

            string into = Path.Combine(dir, "into");
            Directory.CreateDirectory(into);

            using (PwsshTestHost host = new PwsshTestHost())
            using (ScpClient scp = SshNetClient.Scp(host))
            {
                scp.Connect();
                scp.Download(Wire(tree), new DirectoryInfo(into));
            }

            foreach (string f in Directory.GetFiles(into, "*", SearchOption.AllDirectories))
                output.WriteLine(f.Substring(into.Length));

            // Note the layout: the contents land directly in the DirectoryInfo, NOT under a
            // "tree" subdirectory. SSH.NET consumes the outermost D record as "the directory you
            // asked for" and unpacks into the destination, where OpenSSH's `scp -r host:tree local`
            // would create local/tree. That is a client convention, not something the server
            // controls -- we send the same D/E nesting either way -- but it is worth pinning,
            // because the obvious expectation is the OpenSSH one and it is wrong here.
            Assert.Equal("top", File.ReadAllText(Path.Combine(into, "top.txt")));
            Assert.Equal("leaf", File.ReadAllText(Path.Combine(into, "inner", "leaf.txt")));
        }

        [Fact]
        public void A_library_client_uploads_a_directory_recursively()
        {
            string tree = Path.Combine(dir, "srctree");
            Directory.CreateDirectory(Path.Combine(tree, "sub"));
            File.WriteAllText(Path.Combine(tree, "one.txt"), "1");
            File.WriteAllText(Path.Combine(tree, "sub", "two.txt"), "2");

            string target = Path.Combine(dir, "dsttree");
            Directory.CreateDirectory(target);

            using (PwsshTestHost host = new PwsshTestHost())
            using (ScpClient scp = SshNetClient.Scp(host))
            {
                scp.Connect();
                scp.Upload(new DirectoryInfo(tree), Wire(target));
            }

            foreach (string f in Directory.GetFiles(target, "*", SearchOption.AllDirectories))
                output.WriteLine(f.Substring(target.Length));

            Assert.Equal("1", File.ReadAllText(Path.Combine(target, "one.txt")));
            Assert.Equal("2", File.ReadAllText(Path.Combine(target, "sub", "two.txt")));
        }

        [Fact]
        public void A_missing_remote_file_raises_rather_than_producing_an_empty_one()
        {
            using (PwsshTestHost host = new PwsshTestHost())
            using (ScpClient scp = SshNetClient.Scp(host))
            {
                scp.Connect();
                using (MemoryStream got = new MemoryStream())
                {
                    Exception ex = Record.Exception(delegate
                    {
                        scp.Download(Wire(Path.Combine(dir, "absent.bin")), got);
                    });
                    Assert.NotNull(ex);
                    output.WriteLine(ex.GetType().Name + ": " + ex.Message);
                    // Our own prefix, which is what proves the agent served this rather than some
                    // scp.exe on PATH.
                    Assert.Contains("pwssh-scp", ex.Message);
                }
            }
        }
    }
}
