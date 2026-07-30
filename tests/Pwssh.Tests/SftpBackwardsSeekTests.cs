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
// WHAT "MID-TRANSFER" HAS TO MEAN HERE, learned the hard way.
//
// The non-sequential path is only reachable while a prefetch is ACTIVE, and a prefetch ends as soon
// as it has fetched through EOF: Refill calls FinishPrefetch on `p.Eof && p.Outstanding <= 0`, which
// nulls `active`. Depth does not prevent that -- it bounds outstanding requests, not buffered bytes,
// so the prefetch keeps issuing until the file runs out. On any link fast relative to the client it
// therefore finishes almost immediately, and a seek arriving later reaches nothing at all: measured
// at the default depth on a bare loopback, an 8 MiB read gave served=45 forwarded=212 nonSeq=0, with
// no park or abandon recorded because none of those paths ran. That is how these tests first failed,
// and it is a real behaviour rather than a harness artifact -- see the last test in this file.
//
// So the seek is done EARLY, after a few hundred KiB, while the prefetch demonstrably still has
// requests in flight. Injected latency widens that window and is what the real transport has anyway.
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
        public void A_prefetch_that_finishes_before_the_client_drains_it_stops_serving()
        {
            // Not an aspiration, a record of what the code does today, found while writing the tests
            // above and pinned here so it cannot change unnoticed.
            //
            // Refill calls FinishPrefetch as soon as `p.Eof && p.Outstanding <= 0`, and FinishPrefetch
            // sets `active = null`. Nothing checks whether the buffer still holds bytes the client has
            // not read, so on a link fast relative to the client the prefetch fetches the whole file,
            // retires, and every remaining read is forwarded to the remote -- fetching those bytes a
            // second time. Nothing in the counters flags it: no park, no abandon, no valve trip.
            //
            // Over WinRM the client can usually keep pace, which is why CLAUDE.md's served=34
            // forwarded=0 figure came from a latency-injected host rather than a bare loopback one.
            // It is still reachable there by any client that reads in small increments.
            //
            // If this test starts failing because served went up and forwarded went to zero, that is
            // an improvement: delete the test and record the change.
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
                    // Whatever the read-ahead does or does not do, the bytes are right.
                    Assert.Equal(expected, whole);

                    Assert.True(host.WaitForLog("sftp read-ahead: "), "no read-ahead summary was logged");
                    string summary = host.FindLog("sftp read-ahead: ");
                    output.WriteLine(summary);

                    // The whole file was fetched by the prefetch...
                    Assert.Equal(FileSize / 1024, Counter(summary, "prefetchKiB"));
                    // ...some of it was served from the buffer...
                    Assert.True(Counter(summary, "served") > 0, "read-ahead never engaged: " + summary);
                    // ...and the rest was fetched again, from the remote, after the prefetch retired.
                    Assert.True(Counter(summary, "forwarded") > 0,
                        "the prefetch no longer retires early, which is an improvement: " + summary);
                    // Silently, which is the part worth knowing.
                    Assert.Equal(0, Counter(summary, "nonSeq"));
                    Assert.Equal(0, Counter(summary, "valveTrips"));
                    Assert.Null(host.FindLog("sftp prefetch abandoned"));
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
