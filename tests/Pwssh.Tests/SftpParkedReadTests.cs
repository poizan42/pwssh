// A parked read must always be resolved, even by the reply that ends the transfer.
//
// THE BUG THIS IS RED FOR
//
// `HandlePrefetchReply` retires the prefetch at its tail: `if ((p.Eof || p.Failed) && p.Outstanding
// <= 0) FinishPrefetch(p);`. FinishPrefetch nulls `active` -- and it is called from inside
// OnPrefetchData's per-message loop, which then breaks on `active != p` and skips the DrainWaiting
// that follows it. FinishPrefetch never calls ReplayParked (only AbandonPrefetch does), and
// CheckParkDeadline reads `active`, so the 30 s backstop cannot see the orphaned prefetch either.
//
// So any read parked at that instant is never answered and never replayed. SFTP has no timeout of
// its own: the client waits for ever.
//
// WHY DEPTH ONE, AND WHY THIS FILE SIZE
//
// At depth >= 2 the reply that sets Eof leaves Outstanding > 0, so retirement waits for a later
// STATUS by which time DrainWaiting has already emptied the queue -- which is why this has stayed
// invisible. At depth 1 the short DATA that proves EOF also drops Outstanding to 0, so retirement
// happens in the same call, before the drain. The file size is deliberately not a multiple of CHUNK
// (261120), so the last reply really is a short DATA rather than a full one followed by a STATUS.
//
// The dominant trigger in the field is not EOF but `p.Failed` -- a mid-transfer permission or I/O
// error stops Refill, Outstanding drains to zero, and the last reply retires with reads still parked,
// at any depth. That entry point needs a fault hook the agent does not have, so it is covered by
// inspection; the replay code it depends on is the code this test exercises.
//
// OperationTimeout is set explicitly because SSH.NET defaults it to infinite, which would turn this
// from a failing test into a hanging one -- a strictly worse outcome.

using System;
using System.IO;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Sftp;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class SftpParkedReadTests : IDisposable
    {
        // 1 MiB is 4 whole 261120-byte chunks plus 4096, so reply five is short.
        private const int FileSize = 1024 * 1024;
        private const int Depth = 1;
        private const uint ClientBuffer = 128 * 1024;
        private const int LatencyMs = 30;

        private readonly ITestOutputHelper output;
        private readonly string dir;
        private readonly string file;
        private readonly byte[] expected;

        public SftpParkedReadTests(ITestOutputHelper output)
        {
            this.output = output;
            dir = Path.Combine(Path.GetTempPath(), "pwssh-park-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);
            expected = new byte[FileSize];
            for (int i = 0; i < expected.Length; i++) expected[i] = (byte)(i * 11 + (i >> 12));
            file = Path.Combine(dir, "payload.bin");
            File.WriteAllBytes(file, expected);
        }

        public void Dispose()
        {
            try { Directory.Delete(dir, true); } catch { }
        }

        private static string Wire(string windowsPath)
        {
            return "/" + windowsPath.Replace('\\', '/');
        }

        private static void ReadExactly(Stream s, byte[] into, int count)
        {
            int got = 0;
            while (got < count)
            {
                int n = s.Read(into, got, count - got);
                if (n <= 0) throw new EndOfStreamException("stream ended after " + got + " of " + count);
                got += n;
            }
        }

        private static long Counter(string summary, string name)
        {
            Match m = Regex.Match(summary, @"\b" + Regex.Escape(name) + @"=(-?\d+)");
            Assert.True(m.Success, "no '" + name + "=' in summary: " + summary);
            return long.Parse(m.Groups[1].Value);
        }

        [Fact]
        public void A_depth_one_download_answers_every_parked_read()
        {
            using (PwsshTestHost host = new PwsshTestHost(
                       delegate(Pwssh.PwsshConfig cfg) { cfg.SftpReadAheadChunks = Depth; },
                       latencyMs: LatencyMs))
            {
                try
                {
                    byte[] whole = new byte[FileSize];
                    using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
                    {
                        // Without this the bug hangs the run instead of failing it.
                        sftp.OperationTimeout = TimeSpan.FromSeconds(45);
                        sftp.Connect();
                        using (SftpFileStream s = sftp.Open(Wire(file), FileMode.Open, FileAccess.Read))
                        {
                            ReadExactly(s, whole, whole.Length);
                        }
                    }
                    Assert.Equal(expected, whole);

                    Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
                    string summary = host.FindLog("sftp read-ahead: ");
                    output.WriteLine(summary);

                    // The shape that proves the scenario was actually reached rather than sidestepped:
                    // at depth 1 the client outruns the fetch, so reads must have parked.
                    Assert.True(Counter(summary, "parked") >= 1,
                        "no read ever parked, so this did not exercise the retiring-reply path: " + summary);
                    Assert.Equal(0, Counter(summary, "valveTrips"));
                    Assert.True(Counter(summary, "creditGranted") <= Counter(summary, "creditRecv"),
                        "granted more credit than was received: " + summary);
                }
                catch
                {
                    foreach (string line in host.Log) output.WriteLine(line);
                    throw;
                }
            }
        }
    }
}
