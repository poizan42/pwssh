// The gap CLAUDE.md names first: a mid-transfer backwards seek.
//
// `reget` covers starting at a non-zero offset, but nothing in the stock client seeks backwards
// mid-file, so until now the read-ahead's non-sequential path was reasoned about rather than run.
// SftpFileStream.Seek is what makes it reachable.
//
// The behaviour these pin down (src/PwsshSftpReadAhead.cs:809-818) is narrower than CLAUDE.md used
// to claim. A read below BufStart increments nonSequential and calls AbandonPrefetch ONCE, which
// closes the private channel, replays anything parked and sets active = null. It does not flip the
// channel to passthrough, and there is no restart counter or thrash limit anywhere in the code, so a
// later file in the same session still gets a fresh prefetch. Tests 2 and 4 hold that distinction.
//
// WHY THESE TESTS USE A SHALLOW DEPTH AND INJECTED LATENCY
//
// A prefetch retires when it has fetched through EOF, and depth does not prevent that -- it bounds
// outstanding requests, not buffered bytes, so the prefetch keeps issuing until the file runs out. On
// a link fast relative to the client it therefore finishes almost immediately.
//
// That used to mean a seek arriving afterwards reached nothing at all, because retiring dropped the
// buffer and nulled `active`. It no longer does: a finished prefetch keeps serving from what it
// already holds, so the non-sequential path is reachable whether or not the fetch is still running --
// which `A_backwards_seek_after_the_prefetch_retired_stays_bit_exact` covers deliberately.
//
// The shallow depth and latency are kept for the tests that want the seek to land while the fetch is
// genuinely still in flight, which is a different state from serving a finished buffer and worth
// exercising on its own. Latency is also what the real transport has.
//
// Every assertion is on the engine's own log rather than on what the client observed, because
// SftpFileStream buffers internally: a seek can be satisfied without any READ reaching the server, so
// a test checking only the returned bytes could pass while exercising nothing.

using System;
using System.IO;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Sftp;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class SftpBackwardsSeekTests : IDisposable
    {
        private const int FileSize = 8 * 1024 * 1024;

        // Only a megabyte in flight, so the prefetch is still working when the seek lands.
        private const int Depth = 4;

        // 128 KiB, deliberately under CHUNK (261120). A request larger than CHUNK is refused by
        // TryServeRead outright ("let the agent's own clamp decide"), so a 256 KiB client buffer
        // would forward everything and look like a read-ahead failure.
        private const uint ClientBuffer = 128 * 1024;

        // One-way, so a round trip costs twice this. See DelayedLoopback for why zero is wrong.
        private const int LatencyMs = 30;

        // How far in to read before seeking back. Small on purpose: it has to be inside the window
        // where the prefetch is still fetching, and it still puts BufStart well above zero.
        private const int ReadBeforeSeek = 256 * 1024;

        // How much to re-read after the seek. Enough to cross back over what was already buffered
        // and into the forwarded region, without paying for the whole file at a round trip per read.
        private const int ReadAfterSeek = 2 * 1024 * 1024;

        private readonly ITestOutputHelper output;
        private readonly string dir;
        private readonly string fileA;
        private readonly string fileB;
        private readonly byte[] expected;

        public SftpBackwardsSeekTests(ITestOutputHelper output)
        {
            this.output = output;
            // Outside the repo on purpose: .gitignore's `tmp/` pattern has no leading slash and so
            // matches a directory of that name at any depth, which would silently hide a fixture.
            dir = Path.Combine(Path.GetTempPath(), "pwssh-tests-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(dir);

            expected = new byte[FileSize];
            // A pattern rather than random, so a mismatch says where it went wrong rather than just
            // that it did. Every byte value appears.
            for (int i = 0; i < expected.Length; i++) expected[i] = (byte)(i * 7 + (i >> 13));

            fileA = Path.Combine(dir, "payload-a.bin");
            fileB = Path.Combine(dir, "payload-b.bin");
            File.WriteAllBytes(fileA, expected);
            File.WriteAllBytes(fileB, expected);
        }

        public void Dispose()
        {
            try { Directory.Delete(dir, true); } catch { }
        }

        /// <summary>C:\x\y becomes /C:/x/y, the wire form established from the reference server.</summary>
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

        private static byte[] Slice(byte[] src, int offset, int count)
        {
            byte[] b = new byte[count];
            Array.Copy(src, offset, b, 0, count);
            return b;
        }

        /// <summary>Pulls a counter out of a Summary() line, e.g. Counter(line, "nonSeq").</summary>
        private static long Counter(string summary, string name)
        {
            Match m = Regex.Match(summary, @"\b" + Regex.Escape(name) + @"=(-?\d+)");
            Assert.True(m.Success, "no '" + name + "=' in summary: " + summary);
            return long.Parse(m.Groups[1].Value);
        }

        private void Dump(PwsshTestHost host)
        {
            foreach (string line in host.Log) output.WriteLine(line);
        }

        /// <summary>
        /// A host whose prefetch cannot outrun the client. Both halves matter: a shallow depth keeps
        /// only a megabyte in flight, and the latency keeps its replies slow enough that the prefetch
        /// is still running when the seek arrives.
        /// </summary>
        private static PwsshTestHost NewHost()
        {
            return new PwsshTestHost(
                delegate(PwsshConfig cfg) { cfg.SftpReadAheadChunks = Depth; },
                latencyMs: LatencyMs);
        }

        /// <summary>
        /// Reads a little, seeks back to the start, reads again. Returns the read-ahead's summary,
        /// which is logged when the client closes the handle.
        /// </summary>
        private string SeekBackwards(PwsshTestHost host, string path)
        {
            using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
            {
                sftp.Connect();
                byte[] before = new byte[ReadBeforeSeek];
                byte[] after = new byte[ReadAfterSeek];
                using (SftpFileStream s = sftp.Open(path, FileMode.Open, FileAccess.Read))
                {
                    ReadExactly(s, before, before.Length);
                    // Back to the very start, which is unambiguously below BufStart by now and far
                    // too distant for SftpFileStream's own buffer to satisfy.
                    s.Seek(0, SeekOrigin.Begin);
                    ReadExactly(s, after, after.Length);
                }
                Assert.Equal(Slice(expected, 0, before.Length), before);
                Assert.Equal(Slice(expected, 0, after.Length), after);
            }

            Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
            return host.FindLog("sftp read-ahead: ");
        }

        [Fact]
        public void A_backwards_seek_abandons_read_ahead_for_that_file_and_is_bit_exact()
        {
            using (PwsshTestHost host = NewHost())
            {
                try
                {
                    string summary = SeekBackwards(host, Wire(fileA));
                    output.WriteLine(summary);

                    Assert.True(host.WaitForLog("sftp prefetch abandoned: client read backwards"),
                        "the backwards read did not abandon the prefetch");
                    Assert.True(Counter(summary, "nonSeq") >= 1, "nonSeq did not move: " + summary);
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void A_backwards_seek_is_not_a_valve_trip()
        {
            using (PwsshTestHost host = NewHost())
            {
                try
                {
                    string summary = SeekBackwards(host, Wire(fileA));

                    // Abandoning one file's prefetch and degrading the whole channel to passthrough
                    // are different things, and conflating them is the mistake a later change is
                    // most likely to make.
                    Assert.Equal(0, Counter(summary, "valveTrips"));
                    Assert.Null(host.FindLog("sftp read-ahead valve tripped"));
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void Reads_before_the_seek_are_served_and_reads_after_it_are_forwarded()
        {
            using (PwsshTestHost host = NewHost())
            {
                try
                {
                    string summary = SeekBackwards(host, Wire(fileA));

                    // Both counters non-zero is the shape that proves a switchover: read-ahead was
                    // genuinely engaged first, and genuinely out of the picture afterwards. Either
                    // one alone would be consistent with it never having worked at all.
                    Assert.True(Counter(summary, "served") > 0, "nothing was served locally: " + summary);
                    Assert.True(Counter(summary, "forwarded") > 0, "nothing was forwarded after the seek: " + summary);
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void A_later_file_in_the_same_session_still_gets_a_fresh_prefetch()
        {
            using (PwsshTestHost host = NewHost())
            {
                try
                {
                    using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
                    {
                        sftp.Connect();

                        byte[] before = new byte[ReadBeforeSeek];
                        using (SftpFileStream s = sftp.Open(Wire(fileA), FileMode.Open, FileAccess.Read))
                        {
                            ReadExactly(s, before, before.Length);
                            s.Seek(0, SeekOrigin.Begin);
                            ReadExactly(s, before, before.Length);
                        }

                        // A second file. If the abandon had disabled read-ahead for the channel
                        // rather than for the file, this would never open a prefetch of its own.
                        byte[] second = new byte[ReadBeforeSeek];
                        using (SftpFileStream s = sftp.Open(Wire(fileB), FileMode.Open, FileAccess.Read))
                        {
                            ReadExactly(s, second, second.Length);
                        }
                        Assert.Equal(Slice(expected, 0, second.Length), second);
                    }

                    Assert.True(host.WaitForLog("sftp prefetch abandoned: client read backwards"),
                        "the first file's backwards read did not abandon its prefetch");

                    int opened = 0;
                    foreach (string line in host.Log)
                        if (line != null && line.Contains("sftp prefetch opening on channel")) opened++;
                    Assert.True(opened >= 2,
                        "expected a prefetch for each file, saw " + opened + " opening(s)");
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void A_forwards_seek_within_the_buffer_is_still_served_locally()
        {
            // The control case. Without it, the backwards-seek tests could be passing because
            // seeking breaks read-ahead in general rather than because backwards is special.
            using (PwsshTestHost host = NewHost())
            {
                try
                {
                    using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
                    {
                        sftp.Connect();
                        byte[] chunk = new byte[ClientBuffer];
                        using (SftpFileStream s = sftp.Open(Wire(fileA), FileMode.Open, FileAccess.Read))
                        {
                            ReadExactly(s, chunk, chunk.Length);
                            // Forwards, and still inside what the prefetch has buffered, so
                            // Satisfiable() covers it once TakeRange discards the skipped bytes.
                            s.Seek(512 * 1024, SeekOrigin.Begin);
                            ReadExactly(s, chunk, chunk.Length);
                            Assert.Equal(Slice(expected, 512 * 1024, chunk.Length), chunk);
                        }
                    }

                    Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
                    string summary = host.FindLog("sftp read-ahead: ");
                    output.WriteLine(summary);
                    Assert.Equal(0, Counter(summary, "nonSeq"));
                    Assert.True(Counter(summary, "served") > 0, "a forwards seek should stay local: " + summary);
                    Assert.Null(host.FindLog("sftp prefetch abandoned: client read backwards"));
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void A_prefetch_that_finishes_first_keeps_serving_from_its_buffer()
        {
            // The inverse of a test that used to pin the opposite, and the measurement that motivated
            // the fix turned green. At the default depth on a bare loopback the prefetch reaches EOF
            // long before the client has consumed anything; it now keeps serving from what it holds
            // instead of retiring and letting the rest be fetched a second time.
            //
            // Before: served=18 forwarded=111 prefetchKiB=8192 -- the whole file fetched, six sevenths
            // of it fetched again. The assertion is forwarded == 0, because "mostly served" would pass
            // just as well on the old behaviour with a slower client.
            using (PwsshTestHost host = new PwsshTestHost())   // default depth, no latency
            {
                try
                {
                    byte[] whole = new byte[FileSize];
                    using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
                    {
                        sftp.Connect();
                        using (SftpFileStream s = sftp.Open(Wire(fileA), FileMode.Open, FileAccess.Read))
                        {
                            ReadExactly(s, whole, whole.Length);
                        }
                    }
                    Assert.Equal(expected, whole);

                    Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
                    string summary = host.FindLog("sftp read-ahead: ");
                    output.WriteLine(summary);

                    Assert.Equal(FileSize / 1024, Counter(summary, "prefetchKiB"));
                    Assert.Equal(0, Counter(summary, "forwarded"));
                    Assert.Equal(Counter(summary, "clientReads"), Counter(summary, "served"));
                    Assert.Equal(FileSize / 1024, Counter(summary, "servedKiB"));
                    Assert.Equal(0, Counter(summary, "nonSeq"));
                    Assert.Equal(0, Counter(summary, "valveTrips"));
                    // Nothing was fetched that the client did not read.
                    Assert.Equal(0, Counter(summary, "unreadKiB"));
                    AssertCreditSane(summary);
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void A_backwards_seek_after_the_prefetch_retired_stays_bit_exact()
        {
            // A path that did not exist before: with no latency the prefetch retires almost at once, so
            // the seek lands on a buffer that is serving rather than fetching. It must take the same
            // non-sequential route -- abandon the buffer, forward the read -- rather than quietly doing
            // nothing, which is what used to happen when retiring nulled `active`.
            using (PwsshTestHost host = new PwsshTestHost())   // default depth, no latency
            {
                try
                {
                    byte[] before = new byte[ReadBeforeSeek];
                    byte[] after = new byte[ReadAfterSeek];
                    using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
                    {
                        sftp.Connect();
                        using (SftpFileStream s = sftp.Open(Wire(fileA), FileMode.Open, FileAccess.Read))
                        {
                            ReadExactly(s, before, before.Length);
                            s.Seek(0, SeekOrigin.Begin);
                            ReadExactly(s, after, after.Length);
                        }
                    }
                    Assert.Equal(Slice(expected, 0, before.Length), before);
                    Assert.Equal(Slice(expected, 0, after.Length), after);

                    Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
                    string summary = host.FindLog("sftp read-ahead: ");
                    output.WriteLine(summary);
                    Assert.True(Counter(summary, "nonSeq") >= 1,
                        "a backwards seek onto a retired buffer went unnoticed: " + summary);
                    Assert.Equal(0, Counter(summary, "valveTrips"));
                    AssertCreditSane(summary);
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void A_retired_buffer_is_dropped_when_a_second_file_is_opened_without_closing_the_first()
        {
            // The only cover for OnClientOpen's drop. A finished buffer must not block the next file's
            // prefetch -- that would cost the many-small-files case its read-ahead entirely, which is
            // the case that needs it most. Two handles open at once does not arise from `sftp` or
            // `scp -r`, which close before opening, but SSH.NET can do it.
            using (PwsshTestHost host = new PwsshTestHost())   // default depth, no latency
            {
                try
                {
                    // Nearly all of A, deliberately: A's prefetch must have REACHED EOF and retired
                    // before B is opened, or the early return in OnClientOpen is the correct answer and
                    // this tests nothing. An earlier version read 256 KiB of 8 MiB and failed for that
                    // reason -- the prefetch was still legitimately in flight. Leaving half a megabyte
                    // unread also exercises the unread accounting rather than only the drop path.
                    const int LeaveUnread = 512 * 1024;
                    byte[] fromA = new byte[FileSize - LeaveUnread];
                    byte[] fromB = new byte[ReadBeforeSeek];
                    byte[] restOfA = new byte[ReadBeforeSeek];
                    using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
                    {
                        sftp.Connect();
                        using (SftpFileStream a = sftp.Open(Wire(fileA), FileMode.Open, FileAccess.Read))
                        {
                            ReadExactly(a, fromA, fromA.Length);

                            using (SftpFileStream b = sftp.Open(Wire(fileB), FileMode.Open, FileAccess.Read))
                            {
                                ReadExactly(b, fromB, fromB.Length);
                            }

                            // A is still open and must still read correctly, from the remote now that
                            // its buffer has been dropped in B's favour.
                            ReadExactly(a, restOfA, restOfA.Length);
                        }
                    }
                    Assert.Equal(Slice(expected, 0, fromA.Length), fromA);
                    Assert.Equal(Slice(expected, 0, fromB.Length), fromB);
                    Assert.Equal(Slice(expected, fromA.Length, restOfA.Length), restOfA);

                    int opened = 0;
                    foreach (string line in host.Log)
                        if (line != null && line.Contains("sftp prefetch opening on channel")) opened++;
                    Assert.True(opened >= 2,
                        "the second file did not get a prefetch of its own, saw " + opened + " opening(s)");

                    Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
                    AssertCreditSane(host.FindLog("sftp read-ahead: "));
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        [Fact]
        public void Many_small_files_each_get_their_own_prefetch()
        {
            // The guard for the property the eager release existed to protect, asserted on counters
            // rather than wall-clock because this transport has twice inverted a conclusion drawn from
            // a single timing. It is also where the fix should GAIN: a small file's prefetch completes
            // before the client reads anything, so every one of these used to be served from the remote.
            const int Files = 20;
            string smallDir = Path.Combine(dir, "small");
            Directory.CreateDirectory(smallDir);
            byte[] body = new byte[900];
            for (int i = 0; i < body.Length; i++) body[i] = (byte)(i * 3);
            string[] paths = new string[Files];
            for (int i = 0; i < Files; i++)
            {
                paths[i] = Path.Combine(smallDir, "f" + i.ToString("00") + ".bin");
                File.WriteAllBytes(paths[i], body);
            }

            using (PwsshTestHost host = new PwsshTestHost())
            {
                try
                {
                    using (SftpClient sftp = SshNetClient.Sftp(host, bufferSize: ClientBuffer))
                    {
                        sftp.Connect();
                        for (int i = 0; i < Files; i++)
                        {
                            byte[] got = new byte[body.Length];
                            using (SftpFileStream s = sftp.Open(Wire(paths[i]), FileMode.Open, FileAccess.Read))
                            {
                                ReadExactly(s, got, got.Length);
                            }
                            Assert.Equal(body, got);
                        }
                    }

                    int opened = 0;
                    foreach (string line in host.Log)
                        if (line != null && line.Contains("sftp prefetch opening on channel")) opened++;
                    Assert.True(opened >= Files,
                        "expected a prefetch per file, saw " + opened + " opening(s) for " + Files + " files");

                    // One summary per file; the last one carries the session totals.
                    Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
                    string summary = null;
                    foreach (string line in host.Log)
                        if (line != null && line.Contains("sftp read-ahead: ")) summary = line;
                    output.WriteLine(summary);
                    Assert.Equal(0, Counter(summary, "forwarded"));
                    AssertCreditSane(summary);
                }
                catch
                {
                    Dump(host);
                    throw;
                }
            }
        }

        /// <summary>
        /// Granting more credit than arrived is the one direction the agent's window exists to prevent,
        /// and it is what a stale prefetch reference would cause. The unambiguous detector is agent-side
        /// (AgentSftpChannel.AddCredit logs it), but PwsshAgentHost's log is not reachable from
        /// PwsshTestHost, so the summary is the only proxy available here.
        /// </summary>
        private static void AssertCreditSane(string summary)
        {
            Assert.True(Counter(summary, "creditGranted") <= Counter(summary, "creditRecv"),
                "granted more credit than was received: " + summary);
        }
    }
}
