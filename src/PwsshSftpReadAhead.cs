// SFTP read-ahead. Runs on the CLIENT only, alongside the engine, and is never pushed to the
// remote -- which is why it lives here and not under src/agent/.
//
// Must compile as C# 5, matching PwsshEngine.cs: no string interpolation, no ?., no out-var,
// no tuples, no expression-bodied members.
//
// WHY THIS EXISTS
//
// SFTP downloads over this transport are round-trip-bound, not bandwidth-bound. The OpenSSH
// client raises its outstanding-request count by one per reply, starting from one, so moving C
// chunks costs roughly sqrt(2C) round trips before the pipe is ever full. Measured on the same
// payload in one session: 8 MiB at 0.49 MiB/s against exec's 1.55, and 32 MiB at 2.22 against
// 6.76. The pacing is inside the client, so nothing the remote does can fix it.
//
// So the engine reads ahead. It watches the SFTP conversation, and when the client opens a file
// for reading it fetches that file eagerly on a channel of its own, then answers the client's
// reads out of the buffer with no round trip at all.
//
// WHAT IT DELIBERATELY DOES NOT DO
//
// It does not inject its own requests into the client's SFTP stream. That looks cheaper and is
// considerably worse: the client's CHANNEL_DATA payloads are not aligned to SFTP message
// boundaries, so injected bytes land inside a client message; injection would have to be
// serialised against the SSH protocol thread; a private request-id range cannot be guaranteed
// disjoint from a non-OpenSSH client's ids; and -- decisively -- once a request has been
// injected there is no way back to passthrough, because a reply the client never asked for is
// fatal to it ("Can't find request for ID", present in sftp.exe). A separate channel makes the
// id space disjoint by construction and lets the read-ahead be abandoned at any instant.
//
// It also never interprets a path. The client's path string is copied byte-for-byte into our
// own OPEN and the remote resolves it, exactly as it does for the client. A client-side path
// resolution would resolve against THIS machine's drives and working directory, and the
// loopback dev host could not catch it -- there both sides are the same machine, so it would
// pass locally and fail only over WinRM.

using System;
using System.Collections.Generic;

namespace Pwssh
{
    // ------------------------------------------------------------------ SFTP framing
    //
    // Splits a byte stream into SFTP messages: uint32 big-endian length, then that many bytes.
    //
    // Unlike the agent's reassembler this SCANS rather than peels -- it yields ranges into the
    // caller's buffer instead of copying each message out. The inbound direction carries every
    // upload's WRITE bodies, and copying all of them to read a type byte and an id would be
    // pure waste. Only a message straddling two Feed calls is ever copied, which is at most one
    // per frame boundary.
    internal sealed class SftpFramer
    {
        // Matches AgentSftpChannel.MAX_MSG. A length outside [1, this] is not something to
        // tolerate: it means the stream is not what we think it is.
        public const int MAX_MSG = 256 * 1024;

        private byte[] residue = new byte[0];
        private int residueLen;

        public string Error;                 // non-null once the stream stopped making sense

        // True while part of a message is held over, waiting for the rest.
        public bool HasResidue { get { return residueLen > 0; } }

        // One message, as a range. Buffer/Offset/Count cover the message body (type byte first),
        // excluding the 4-byte length prefix.
        internal struct Msg
        {
            public byte[] Buffer;
            public int Offset;
            public int Count;
        }

        // Returns the messages completed by this buffer, in order. Bytes left over are held for
        // the next call. Sets Error and returns what it had if the framing stops adding up.
        public List<Msg> Feed(byte[] data, int offset, int count)
        {
            List<Msg> done = new List<Msg>();
            if (Error != null) return done;

            int p = offset;
            int end = offset + count;

            // Finish whatever was left dangling first, then work in place.
            while (residueLen > 0 && p < end)
            {
                int need = NeededForResidue();
                if (need < 0) { Error = "bad SFTP length in residue"; return done; }
                if (need == 0)
                {
                    Msg m = new Msg();
                    m.Buffer = residue; m.Offset = 4; m.Count = residueLen - 4;
                    done.Add(m);
                    residueLen = 0;
                    break;
                }
                int take = Math.Min(need, end - p);
                Append(data, p, take);
                p += take;
                if (NeededForResidue() == 0)
                {
                    Msg m = new Msg();
                    m.Buffer = residue; m.Offset = 4; m.Count = residueLen - 4;
                    done.Add(m);
                    residueLen = 0;
                    // The residue array is handed out by reference, so start the next one fresh
                    // rather than overwriting a message the caller may still be reading.
                    residue = new byte[0];
                }
            }

            while (end - p >= 4)
            {
                long n = ((long)data[p] << 24) | ((long)data[p + 1] << 16)
                       | ((long)data[p + 2] << 8) | data[p + 3];
                if (n < 1 || n > MAX_MSG) { Error = "implausible SFTP length " + n; return done; }
                if (end - p - 4 < n) break;                  // incomplete; hold it below
                Msg m = new Msg();
                m.Buffer = data; m.Offset = p + 4; m.Count = (int)n;
                done.Add(m);
                p += 4 + (int)n;
            }

            if (p < end) Append(data, p, end - p);
            return done;
        }

        // How many more bytes the held partial message needs: 0 when complete, -1 if its length
        // field is implausible, otherwise the shortfall.
        private int NeededForResidue()
        {
            if (residueLen < 4) return 4 - residueLen;
            long n = ((long)residue[0] << 24) | ((long)residue[1] << 16)
                   | ((long)residue[2] << 8) | residue[3];
            if (n < 1 || n > MAX_MSG) return -1;
            long total = 4 + n;
            if (residueLen > total) return -1;                // cannot happen; caught if it does
            return (int)(total - residueLen);
        }

        private void Append(byte[] data, int offset, int count)
        {
            if (residueLen + count > residue.Length)
            {
                int want = residue.Length == 0 ? 8192 : residue.Length;
                while (want < residueLen + count) want *= 2;
                byte[] bigger = new byte[want];
                Array.Copy(residue, 0, bigger, 0, residueLen);
                residue = bigger;
            }
            Array.Copy(data, offset, residue, residueLen, count);
            residueLen += count;
        }
    }

    // ------------------------------------------------------------- SFTP message types
    //
    // Only what the read-ahead has to recognise. Everything else is opaque payload it forwards
    // without looking, which is what bounds how much of the protocol this code can get wrong.
    internal static class SftpMsg
    {
        public const byte INIT = 1;
        public const byte VERSION = 2;
        public const byte OPEN = 3;
        public const byte CLOSE = 4;
        public const byte READ = 5;
        public const byte STATUS = 101;
        public const byte HANDLE = 102;
        public const byte DATA = 103;

        public const uint STATUS_OK = 0;
        public const uint STATUS_EOF = 1;

        public const uint PFLAG_READ = 0x1;
        public const uint PFLAG_WRITE = 0x2;
    }

    // ------------------------------------------------------------------ the proxy
    //
    // One per SFTP subsystem channel. Sits in both directions of that channel and, for now,
    // forwards everything unchanged while counting what it sees. The read-ahead policy is layered
    // on top of this; keeping the transparent case as its own reviewable state is what makes the
    // valve trustworthy, because Passthrough is then demonstrably the same code path as before
    // this class existed.
    internal sealed class SftpReadAhead
    {
        // Matches the agent's MAX_READ, which is also what the client adopts through
        // limits@openssh.com. Fetching at the same grain means our buffer boundaries line up
        // with the client's request offsets, so the common case is a whole-chunk hit.
        private const int CHUNK = 261120;

        // Passthrough is not an error state: it is the guarantee. Anything this class does not
        // completely understand puts the channel here, and a channel here behaves exactly as it
        // did before read-ahead existed.
        private enum Mode { Proxy, Passthrough }

        private Mode mode = Mode.Proxy;
        private readonly SftpFramer fromClient = new SftpFramer();
        private readonly SftpFramer fromAgent = new SftpFramer();
        private readonly SftpFramer fromPrefetch = new SftpFramer();
        private readonly object gate = new object();

        private readonly PwsshEngine engine;
        private readonly IPwsshAgent agent;
        private readonly SessionChannel owner;
        private readonly int depth;              // how many chunks may be outstanding

        // Counters. The tests assert on these rather than on wall-clock, because the transport's
        // run-to-run spread is wide enough to invert a conclusion and has twice done so.
        private int clientReads;
        private int forwardedReads;
        private int servedFromBuffer;
        private long servedBytes;
        private int parked;
        private int nonSequential;
        private int prefetchIssued;
        private long prefetchBytes;
        private int valveTrips;
        private string valveReason;

        // The client handle of the file most recently prefetched, so its CLOSE can report the
        // counters. Cleared once reported, so a second CLOSE of the same handle stays quiet.
        private string lastPrefetchHandle;
        private bool reported;                   // keeps Kill() from repeating what CLOSE said
        private readonly long faultAfterBytes;   // test hook; 0 is off

        // A depth beyond the agent's credit cannot be in flight however many requests are issued:
        // the far side blocks on its window instead of reading, which is measurable -- depth 128
        // is slower than 64 for exactly that reason. The requests are still sent, and the batch
        // that opens a file is a single frame, so an absurd depth builds an absurd frame. Found
        // the hard way: a misparsed 326,496 produced a 10.6 MB object and WinRM refused it
        // outright ("deserialized object size ... exceeded the allowed maximum"), killing the
        // pipeline mid-download. 128 is the default credit (32 MiB) divided by CHUNK, i.e. the
        // most that can ever be outstanding; it is a ceiling on nonsense, not a tuning value.
        internal const int MAX_DEPTH = 128;

        public SftpReadAhead(PwsshEngine e, IPwsshAgent a, SessionChannel o, int depthChunks)
        {
            engine = e;
            agent = a;
            owner = o;
            depth = depthChunks > MAX_DEPTH ? MAX_DEPTH : depthChunks;
            if (depthChunks > MAX_DEPTH)
                e.LogInternal("sftp read-ahead depth " + depthChunks + " clamped to " + MAX_DEPTH);
            faultAfterBytes = (long)e.SftpFaultAfterKiB * 1024;
        }

        public bool IsPassthrough { get { return mode == Mode.Passthrough; } }

        // True when the counters have something to say that no CLOSE has reported yet.
        public bool ShouldReport { get { lock (gate) { return !reported && prefetchIssued > 0; } } }

        // Reported once at teardown rather than per event: a per-read log line on a 32 MiB
        // transfer would be 128 lines of noise, and the ratio is the only interesting part.
        public string Summary()
        {
            lock (gate)
            {
                string s = "sftp read-ahead: clientReads=" + clientReads
                         + " served=" + servedFromBuffer
                         + " forwarded=" + forwardedReads
                         + " parked=" + parked
                         + " servedKiB=" + (servedBytes / 1024)
                         + " prefetched=" + prefetchIssued
                         + " prefetchKiB=" + (prefetchBytes / 1024)
                         + " nonSeq=" + nonSequential
                         + " valveTrips=" + valveTrips;
                if (valveReason != null) s += " (" + valveReason + ")";
                return s;
            }
        }

        // A parked read is waiting for bytes already in flight, which normally costs a fraction of
        // a round trip. If that reply never comes, though, nothing else rescues the client: SFTP
        // has no timeout of its own, so the session would hang for good and look like the link
        // being slow. Past the deadline the read goes to the remote after all -- always safe,
        // since a parked read was never forwarded and the remote has not seen it.
        //
        // Driven by the engine's watchdog tick rather than a thread of its own: it needs exactly
        // the "notice while nothing is happening" shape that thread already has.
        internal const int PARK_DEADLINE_MS = 30000;

        public void CheckParkDeadline()
        {
            lock (gate)
            {
                // Deliberately NOT skipped in passthrough. Trip() abandons the prefetch and replays
                // what was parked, so there should be nothing left -- but this is the backstop for
                // a client that would otherwise wait for ever, and a backstop that trusts the thing
                // it is backing up is not one.
                Prefetch p = active;
                if (p == null || p.Waiting.Count == 0) return;
                if (unchecked(Environment.TickCount - p.Waiting.Peek().Tick) < PARK_DEADLINE_MS) return;
                AbandonPrefetch("park deadline exceeded; the reply never arrived");
            }
        }

        // Gives up on read-ahead for this channel, permanently. Safe at any instant, because
        // nothing of ours has ever entered the client's stream -- prefetch traffic lives on a
        // separate channel the client cannot see, so there is nothing to unwind.
        private void Trip(string reason)
        {
            if (mode == Mode.Passthrough) return;
            mode = Mode.Passthrough;
            valveTrips++;
            if (valveReason == null) valveReason = reason;
            engine.LogInternal("sftp read-ahead valve tripped: " + reason);

            // Abandoning is not optional here, and this was a hang waiting to happen. A read parked
            // at the moment of the trip is waiting on data the prefetch would have delivered; going
            // to passthrough means nothing ever will, and SFTP has no timeout to rescue the client.
            // AbandonPrefetch replays those reads to the remote, which has never seen them and will
            // answer each exactly once. Ordering is safe: the framer never forwards a partial
            // message, so the agent's stream is at a message boundary whenever this runs.
            AbandonPrefetch("valve tripped: " + reason);
        }

        // ---- client -> agent ----
        //
        // Returns what the caller should forward to the agent: the original array when nothing has
        // to change, a rebuilt one when a READ was answered locally, or null when there is nothing
        // to send at all.
        //
        // Whole messages, not raw bytes. A CHANNEL_DATA payload is not aligned to SFTP message
        // boundaries, so a message can span two of them -- and whether to suppress it cannot be
        // decided until it is complete. Forwarding eagerly would mean the first half had already
        // gone by the time we knew. So incomplete messages are held, and only complete ones are
        // passed on.
        //
        // The rebuild copies, which is fine: it only happens when a read was served, and the
        // messages left to forward at that point are small. Upload traffic, which is the bulk of
        // this direction, hits the no-change path.
        public byte[] FromClient(byte[] data, int offset, int count, out int outOffset, out int outCount)
        {
            outOffset = offset;
            outCount = count;
            lock (gate)
            {
                if (mode == Mode.Passthrough) return data;
                try
                {
                    List<SftpFramer.Msg> msgs = fromClient.Feed(data, offset, count);
                    if (fromClient.Error != null)
                    {
                        Trip("client stream: " + fromClient.Error);
                        // Anything already held back has to go now, or the agent is left waiting
                        // for the rest of a message it half received.
                        return FlushHeld(msgs, out outOffset, out outCount);
                    }

                    bool anySuppressed = false;
                    List<SftpFramer.Msg> keep = new List<SftpFramer.Msg>();
                    for (int i = 0; i < msgs.Count; i++)
                    {
                        if (Inspect(msgs[i])) keep.Add(msgs[i]);
                        else anySuppressed = true;
                    }

                    // The fast path: every message complete within this buffer, none suppressed,
                    // nothing held over. Then the buffer is exactly what should go, unchanged.
                    if (!anySuppressed && !fromClient.HasResidue && msgs.Count > 0
                        && msgs[0].Buffer == data && msgs[0].Offset == offset + 4)
                    {
                        return data;
                    }

                    return Rebuild(keep, out outOffset, out outCount);
                }
                catch (Exception ex)
                {
                    Trip("client parse: " + ex.Message);
                    return data;
                }
            }
        }

        private byte[] FlushHeld(List<SftpFramer.Msg> msgs, out int outOffset, out int outCount)
        {
            return Rebuild(msgs, out outOffset, out outCount);
        }

        private static byte[] Rebuild(List<SftpFramer.Msg> msgs, out int outOffset, out int outCount)
        {
            outOffset = 0;
            outCount = 0;
            if (msgs.Count == 0) return null;

            int total = 0;
            for (int i = 0; i < msgs.Count; i++) total += 4 + msgs[i].Count;
            byte[] buf = new byte[total];
            int p = 0;
            for (int i = 0; i < msgs.Count; i++)
            {
                // The 4-byte length prefix sits immediately before the body, in whichever buffer
                // the framer produced the message from.
                Array.Copy(msgs[i].Buffer, msgs[i].Offset - 4, buf, p, 4 + msgs[i].Count);
                p += 4 + msgs[i].Count;
            }
            outCount = total;
            return buf;
        }

        // ---- agent -> client ----
        //
        // Only observes for now. Replies on the client's own channel always belong to the client
        // and are always forwarded; the read-ahead's own replies arrive on its private channel
        // and never pass through here at all.
        public bool FromAgent(byte[] data, int offset, int count)
        {
            lock (gate)
            {
                if (mode == Mode.Passthrough) return true;
                try
                {
                    List<SftpFramer.Msg> msgs = fromAgent.Feed(data, offset, count);
                    if (fromAgent.Error != null) { Trip("agent stream: " + fromAgent.Error); return true; }
                    for (int i = 0; i < msgs.Count; i++) InspectReply(msgs[i]);
                }
                catch (Exception ex)
                {
                    Trip("agent parse: " + ex.Message);
                }
                return true;
            }
        }

        // Classifies one client message. An unrecognised type is not an anomaly -- the client
        // legitimately sends STAT, WRITE, READDIR and a dozen others that are simply none of our
        // business, and all of them forward correctly without being understood. What DOES trip
        // the valve is a message we think we recognise but cannot parse, which is why the cases
        // that read fields do so defensively.
        // Returns whether this message should be forwarded to the remote. Only a READ answered
        // from the buffer is ever held back.
        private bool Inspect(SftpFramer.Msg m)
        {
            if (m.Count < 1) { Trip("empty SFTP message"); return true; }
            byte type = m.Buffer[m.Offset];

            switch (type)
            {
                case SftpMsg.READ:
                    clientReads++;
                    if (TryServeRead(m)) return false;    // answered locally; do not forward
                    forwardedReads++;
                    break;

                case SftpMsg.OPEN:
                    OnClientOpen(m);
                    break;

                case SftpMsg.CLOSE:
                    OnClientClose(m);
                    break;

                // Listed only because it is the one message with no request id, so it must never
                // be read as though it had one.
                case SftpMsg.INIT:
                    break;

                default:
                    break;
            }
            return true;
        }

        // Watches the replies going back to the client for one thing only: the HANDLE that answers
        // the OPEN we started a prefetch from. Until that arrives a client READ cannot be matched
        // to the prefetch, because the client's handle string is not ours and the two are unrelated
        // strings chosen independently by the remote.
        private void InspectReply(SftpFramer.Msg m)
        {
            Prefetch p = active;
            if (p == null || !p.AwaitingClientHandle) return;
            if (m.Count < 1) return;
            byte type = m.Buffer[m.Offset];

            if (type == SftpMsg.HANDLE)
            {
                SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                uint id = r.UInt32();
                if (id != p.ClientOpenId) return;
                p.ClientHandle = r.Text();
                lastPrefetchHandle = p.ClientHandle;
                p.AwaitingClientHandle = false;
                if (p.ClientHandle.Length == 0) AbandonPrefetch("empty client handle");
            }
            else if (type == SftpMsg.STATUS)
            {
                SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                uint id = r.UInt32();
                if (id != p.ClientOpenId) return;
                // The client's own open failed, so there is nothing to serve it from.
                p.AwaitingClientHandle = false;
                AbandonPrefetch("client open failed");
            }
        }

        // ---- serving a client READ ----
        //
        // Returns true if the read was answered from the buffer or parked for it, in which case
        // the caller must NOT forward it. The guarantee that matters: a synthesised reply carries
        // either exactly the requested length, or a short read at an offset the remote has already
        // proven to be the end of the file. Nothing else is ever answered locally. A short reply
        // anywhere else makes the client permanently shrink its request size, which measured a
        // ~2.5x loss for the rest of the session.
        private bool TryServeRead(SftpFramer.Msg m)
        {
            Prefetch p = active;
            if (p == null || p.Failed || p.ClientHandle == null) return false;

            // READ is: byte type, uint32 id, string handle, uint64 offset, uint32 length.
            SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
            uint id = r.UInt32();
            string handle = r.Text();
            long offset = (long)r.UInt64();
            int want = (int)r.UInt32();

            if (handle != p.ClientHandle) return false;          // a different file; not ours
            if (want <= 0 || want > CHUNK) return false;          // let the agent's own clamp decide

            // Past a proven end of file: the same STATUS the remote would send, one round trip
            // sooner. Only ever when the remote actually proved it.
            if (offset >= p.EofOffset)
            {
                SendStatusEof(id);
                servedFromBuffer++;
                return true;
            }

            // Before the buffer means the client seeked backwards. Forward it and give up on
            // read-ahead for this file rather than trying to guess the new pattern -- which is
            // what keeps a random-access client at today's behaviour instead of worse.
            if (offset < p.BufStart)
            {
                nonSequential++;
                AbandonPrefetch("client read backwards");
                return false;
            }

            // Test hook, checked here because this is the one place that is reliably part way
            // through a transfer with a prefetch running and reads possibly parked -- the worst
            // instant to degrade, which is exactly the instant worth testing.
            if (faultAfterBytes > 0 && servedBytes >= faultAfterBytes)
            {
                Trip("fault injection after " + (servedBytes / 1024) + " KiB");
                return false;                                    // forward this read as-is
            }

            // Either satisfiable now, or in flight and worth waiting for. Waiting costs a
            // fraction of a round trip; forwarding costs a whole one and fetches the bytes twice.
            if (Satisfiable(p, offset, want))
            {
                ServeFromBuffer(p, id, offset, want);
                return true;
            }

            if (offset < p.NextOffset || !p.Eof)
            {
                Parked w = new Parked();
                w.Id = id; w.Offset = offset; w.Length = want;
                w.Tick = Environment.TickCount;
                p.Waiting.Enqueue(w);
                parked++;
                return true;
            }

            return false;                                        // beyond anything we will fetch
        }

        private static bool Satisfiable(Prefetch p, long offset, int want)
        {
            if (offset < p.BufStart) return false;
            if (offset + want <= p.BufEnd) return true;
            // A request running past the end of the file is satisfiable with what exists, which
            // is the one legitimate short reply.
            return p.EofOffset != long.MaxValue && p.BufEnd >= p.EofOffset && offset < p.EofOffset;
        }

        // Builds the reply as a header chunk plus the buffered segments it covers, enqueued in one
        // go. The segments carry the agent's credit; the header we invented carries none.
        private void ServeFromBuffer(Prefetch p, uint id, long offset, int want)
        {
            int available = (int)Math.Min((long)want, p.BufEnd - offset);
            if (p.EofOffset != long.MaxValue)
            {
                available = (int)Math.Min((long)available, p.EofOffset - offset);
            }
            if (available <= 0) { SendStatusEof(id); servedFromBuffer++; return; }

            List<Segment> parts = TakeRange(p, offset, available);

            // uint32 length, byte type, uint32 id, uint32 data length
            SshLikeWriter head = new SshLikeWriter();
            head.UInt32((uint)(1 + 4 + 4 + available));
            head.Byte(SftpMsg.DATA);
            head.UInt32(id);
            head.UInt32((uint)available);

            owner.SendSynthetic(head.ToArray(), parts);
            servedFromBuffer++;
            servedBytes += available;
            Refill(p);
        }

        private void SendStatusEof(uint id)
        {
            SshLikeWriter w = new SshLikeWriter();
            SshLikeWriter body = new SshLikeWriter();
            body.Byte(SftpMsg.STATUS);
            body.UInt32(id);
            body.UInt32(SftpMsg.STATUS_EOF);
            body.Text("end of file");
            body.Text("");
            AppendFramed(w, body);
            owner.SendSynthetic(w.ToArray(), null);
        }

        // Consumes exactly 'count' bytes from the front of the buffer. Anything the client did not
        // ask for stays where it is, split if necessary, so nothing is dropped or double-counted.
        private List<Segment> TakeRange(Prefetch p, long offset, int count)
        {
            List<Segment> parts = new List<Segment>();

            // Discard anything before the requested offset: the client has moved past it and will
            // not ask again while the read-ahead is still sequential.
            while (p.Segs.Count > 0)
            {
                Segment s = p.Segs.Peek();
                if (s.FileOffset + s.Count <= offset)
                {
                    p.Segs.Dequeue();
                    p.BufStart = s.FileOffset + s.Count;
                    ReleasePrefetchCredit(s.Count);
                    continue;
                }
                break;
            }

            int need = count;
            while (need > 0 && p.Segs.Count > 0)
            {
                Segment s = p.Segs.Peek();
                int skip = (int)(offset - s.FileOffset);
                if (skip < 0) break;                             // a gap; should not happen
                int avail = s.Count - skip;
                if (avail <= 0) { p.Segs.Dequeue(); continue; }

                int take = Math.Min(avail, need);
                Segment part = new Segment();
                part.Data = s.Data; part.Offset = s.Offset + skip; part.Count = take;
                part.FileOffset = offset;
                parts.Add(part);

                offset += take;
                need -= take;

                if (skip + take >= s.Count)
                {
                    p.Segs.Dequeue();
                    p.BufStart = s.FileOffset + s.Count;
                    // The whole segment has been handed over, so its credit goes back now.
                    ReleasePrefetchCredit(s.Count);
                }
                else
                {
                    // Partly consumed: keep the remainder, and account only what left.
                    s.Offset += skip + take;
                    s.Count -= skip + take;
                    s.FileOffset = offset;
                    p.BufStart = offset;
                    ReleasePrefetchCredit(skip + take);
                }
            }
            return parts;
        }

        // Answers whatever parked reads the newly-arrived data has made satisfiable, oldest
        // first. Strict arrival order is deliberate and free: the buffer fills forwards, so the
        // oldest parked read is always the first to become answerable. It also means the client
        // never observes a reordering -- which matters because its resume path detects a server
        // that reorders and fails the transfer outright.
        private void DrainWaiting(Prefetch p)
        {
            while (p.Waiting.Count > 0)
            {
                Parked w = p.Waiting.Peek();
                if (w.Offset >= p.EofOffset)
                {
                    p.Waiting.Dequeue();
                    SendStatusEof(w.Id);
                    continue;
                }
                if (!Satisfiable(p, w.Offset, w.Length)) break;
                p.Waiting.Dequeue();
                ServeFromBuffer(p, w.Id, w.Offset, w.Length);
            }
        }

        private void OnClientClose(SftpFramer.Msg m)
        {
            SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
            r.UInt32();
            string handle = r.Text();

            Prefetch p = active;
            if (p != null && p.ClientHandle != null && handle == p.ClientHandle)
            {
                // The client is finished with this file, so anything still buffered or in flight is
                // waste. Its own CLOSE is forwarded untouched and answered by the remote as usual.
                AbandonPrefetch("client closed the file");
            }

            // Reported here, and not only from Kill(), because Kill() does not run: ssh
            // TerminateProcesses its ProxyCommand on exit (ssh_kill_proxy_command), so for an
            // ordinary sftp session the teardown summary is never reached and the counters were
            // unobservable over WinRM -- which is precisely where they are wanted. A CLOSE always
            // arrives first, and per-file is more informative than one cumulative line anyway.
            if (handle != null && handle == lastPrefetchHandle)
            {
                lastPrefetchHandle = null;
                reported = true;
                engine.LogInternal(Summary());
            }
        }

        // ---------------------------------------------------------------- prefetching
        //
        // Started from the client's OPEN rather than from the HANDLE reply that answers it: the
        // request carries the path, so the prefetch can begin a full round trip earlier than a
        // design keyed on the reply could manage.

        private Prefetch active;

        private sealed class Prefetch
        {
            public uint Channel;                 // the private agent channel carrying it
            public string Path;                  // the client's path string, never interpreted
            public string Handle;                // the remote's handle for OUR open, once known
            public uint NextId = 1;              // request ids on our own channel start at 1
            public uint OpenId;                  // the id of our OPEN, to match its HANDLE reply
            public long NextOffset;              // where the next prefetch request starts
            public long DataOffset;              // where the next reply's bytes belong in the file
            public int Outstanding;              // requests issued and not yet answered
            public bool Eof;                     // the remote reported the end of the file
            public bool Failed;                  // the remote refused; stop and stay out of the way

            // The client's handle for the same file, learned from the HANDLE reply to ITS open.
            // Until that is known a client READ cannot be matched to this prefetch at all.
            public string ClientHandle;
            public uint ClientOpenId;
            public bool AwaitingClientHandle;

            // Buffered data, in arrival order, which is also offset order: the agent's worker is
            // serial and frames arrive in order, so the buffer always fills forwards.
            public readonly Queue<Segment> Segs = new Queue<Segment>();
            public long BufStart;                // offset of the first buffered byte
            public long BufEnd;                  // offset just past the last buffered byte
            public long EofOffset = long.MaxValue;   // the end of the file, once the remote proves it

            // Client reads waiting on data still in flight, answered strictly in arrival order.
            public readonly Queue<Parked> Waiting = new Queue<Parked>();
        }

        // One run of buffered bytes. Holds the frame buffer by reference rather than copying:
        // OnData hands the frame through as a range and nothing else will touch it.
        internal sealed class Segment
        {
            public byte[] Data;
            public int Offset;
            public int Count;
            public long FileOffset;              // where these bytes sit in the file
        }

        private sealed class Parked
        {
            public uint Id;                      // the client's request id, echoed back verbatim
            public long Offset;
            public int Length;
            public int Tick;                     // when it was parked, for the deadline below
        }

        private void OnClientOpen(SftpFramer.Msg m)
        {
            // Only one prefetch at a time: sftp and scp read one file after another, so a second
            // would be speculative work competing with the first for the same link.
            if (active != null) return;

            // OPEN is: byte type, uint32 id, string path, uint32 pflags, ATTRS.
            SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
            uint clientOpenId = r.UInt32();
            string path = r.Text();
            uint pflags = r.UInt32();

            if (path.Length == 0) return;                 // nothing useful to open
            // Read-only opens only. A file the client is writing is held FileShare.None by the
            // agent, so a second open would fail anyway -- but not asking is clearer than
            // relying on that.
            if ((pflags & SftpMsg.PFLAG_READ) == 0) return;
            if ((pflags & SftpMsg.PFLAG_WRITE) != 0) return;

            uint ch;
            if (!engine.TryRegisterPrefetchChannel(this, out ch)) return;

            Prefetch p = new Prefetch();
            p.Channel = ch;
            p.Path = path;
            p.ClientOpenId = clientOpenId;
            p.AwaitingClientHandle = true;
            active = p;

            // One frame carrying INIT and OPEN back to back. The agent's worker is serial, so it
            // answers VERSION then HANDLE without a round trip between them, and the prefetch is
            // under way while the client is still waiting for its own OPEN to be answered.
            agent.Subsystem(ch, "sftp");

            SshLikeWriter w = new SshLikeWriter();
            AppendInit(w);
            p.OpenId = p.NextId++;
            AppendOpenRead(w, p.OpenId, path);
            byte[] bytes = w.ToArray();
            agent.SendStdin(ch, bytes);

            engine.LogInternal("sftp prefetch opening on channel " + ch);
        }

        private static void AppendInit(SshLikeWriter w)
        {
            SshLikeWriter body = new SshLikeWriter();
            body.Byte(SftpMsg.INIT);
            body.UInt32(3);
            AppendFramed(w, body);
        }

        // The path is copied through byte-for-byte. Interpreting it here would resolve it against
        // THIS machine's drives and working directory -- and the loopback dev host could not catch
        // that, because there both sides are the same machine.
        private static void AppendOpenRead(SshLikeWriter w, uint id, string path)
        {
            SshLikeWriter body = new SshLikeWriter();
            body.Byte(SftpMsg.OPEN);
            body.UInt32(id);
            body.Text(path);
            body.UInt32(SftpMsg.PFLAG_READ);
            body.UInt32(0);                               // ATTRS: no flags set
            AppendFramed(w, body);
        }

        private static void AppendRead(SshLikeWriter w, uint id, string handle, long offset, int length)
        {
            SshLikeWriter body = new SshLikeWriter();
            body.Byte(SftpMsg.READ);
            body.UInt32(id);
            body.Text(handle);
            body.UInt64((ulong)offset);
            body.UInt32((uint)length);
            AppendFramed(w, body);
        }

        private static void AppendClose(SshLikeWriter w, uint id, string handle)
        {
            SshLikeWriter body = new SshLikeWriter();
            body.Byte(SftpMsg.CLOSE);
            body.UInt32(id);
            body.Text(handle);
            AppendFramed(w, body);
        }

        private static void AppendFramed(SshLikeWriter w, SshLikeWriter body)
        {
            byte[] b = body.ToArray();
            w.UInt32((uint)b.Length);
            w.Raw(b, 0, b.Length);
        }

        // Tops the pipeline back up to depth. Everything queued goes out as one frame, so a
        // refill costs one upstream frame rather than one per request.
        private void Refill(Prefetch p)
        {
            if (p.Handle == null || p.Eof || p.Failed) return;
            SshLikeWriter w = new SshLikeWriter();
            int issued = 0;
            while (p.Outstanding < depth)
            {
                AppendRead(w, p.NextId++, p.Handle, p.NextOffset, CHUNK);
                p.NextOffset += CHUNK;
                p.Outstanding++;
                issued++;
            }
            if (issued == 0) return;
            agent.SendStdin(p.Channel, w.ToArray());
            prefetchIssued += issued;
        }

        // ---- replies on our private channel ----

        public void OnPrefetchData(uint ch, byte[] buffer, int offset, int count, bool stderr)
        {
            lock (gate)
            {
                if (stderr) return;                       // the agent's diagnostics, not protocol
                Prefetch p = active;
                if (p == null || p.Channel != ch)
                {
                    // A late reply for a prefetch that has already been abandoned. Its credit
                    // still has to be returned or the agent's channel would stall on the way to
                    // being torn down.
                    agent.GrantWindow(ch, (uint)count);
                    return;
                }
                retainedThisFeed = 0;
                try
                {
                    List<SftpFramer.Msg> msgs = fromPrefetch.Feed(buffer, offset, count);
                    if (fromPrefetch.Error != null)
                    {
                        // Our own channel desynced. Nothing of the client's is at risk, so this
                        // is simply the end of read-ahead for this file.
                        AbandonPrefetch("prefetch stream: " + fromPrefetch.Error);
                        agent.GrantWindow(ch, (uint)count);
                        return;
                    }
                    for (int i = 0; i < msgs.Count; i++) HandlePrefetchReply(p, msgs[i]);
                    DrainWaiting(p);
                }
                catch (Exception ex)
                {
                    AbandonPrefetch("prefetch parse: " + ex.Message);
                }

                // Every byte received has exactly one fate and is accounted once. Framing and
                // anything not retained is released now; bytes held for the client are released
                // when they are handed over, or when they are discarded. Getting this wrong in
                // the obvious way -- releasing nothing for retained bytes -- would let the
                // outstanding total climb until credit was withheld permanently and the agent's
                // channel stalled with no timeout to break it.
                int releaseNow = count - retainedThisFeed;
                if (releaseNow > 0) agent.GrantWindow(ch, (uint)releaseNow);
                prefetchOwed += retainedThisFeed;
            }
        }

        // Bytes sitting in the buffer whose credit has not yet gone back, and the channel they
        // belong to. Tracked so that a discard can return exactly what it holds.
        private int retainedThisFeed;
        private long prefetchOwed;

        // Called as buffered bytes leave, whether to the client or to the bin.
        internal void ReleasePrefetchCredit(int bytes)
        {
            if (bytes <= 0) return;
            Prefetch p = active;
            prefetchOwed -= bytes;
            if (p != null)
            {
                try { agent.GrantWindow(p.Channel, (uint)bytes); } catch (Exception) { }
            }
        }

        private void HandlePrefetchReply(Prefetch p, SftpFramer.Msg m)
        {
            if (m.Count < 1) return;
            byte type = m.Buffer[m.Offset];
            SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);

            switch (type)
            {
                case SftpMsg.VERSION:
                    break;                                // expected, and of no further interest

                case SftpMsg.HANDLE:
                    {
                        uint id = r.UInt32();
                        if (id != p.OpenId) return;
                        p.Handle = r.Text();
                        if (p.Handle.Length == 0) { AbandonPrefetch("empty prefetch handle"); return; }
                        Refill(p);
                        break;
                    }

                case SftpMsg.DATA:
                    {
                        r.UInt32();                       // request id
                        int off, len;
                        if (!r.Blob(out off, out len)) { AbandonPrefetch("truncated prefetch DATA"); return; }
                        p.Outstanding--;
                        prefetchBytes += len;

                        // The buffer must stay contiguous, because that is what lets a client read
                        // be answered by simple arithmetic. Replies arrive in request order on a
                        // serial worker, so this holds -- but if it ever did not, serving from a
                        // gapped buffer would hand the client the wrong bytes, so check rather
                        // than assume.
                        if (p.Segs.Count == 0 && p.BufEnd == 0 && p.BufStart == 0)
                        {
                            p.BufStart = p.DataOffset;
                            p.BufEnd = p.DataOffset;
                        }
                        if (p.DataOffset != p.BufEnd)
                        {
                            AbandonPrefetch("prefetch arrived out of order");
                            return;
                        }

                        Segment s = new Segment();
                        s.Data = m.Buffer; s.Offset = off; s.Count = len; s.FileOffset = p.DataOffset;
                        p.Segs.Enqueue(s);
                        p.BufEnd += len;
                        p.DataOffset += len;
                        retainedThisFeed += len;

                        // A reply shorter than asked for is how the end of the file announces
                        // itself, and the agent only ever answers short when the file truly ended.
                        if (len < CHUNK) { p.Eof = true; p.EofOffset = p.BufEnd; }
                        Refill(p);
                        break;
                    }

                case SftpMsg.STATUS:
                    {
                        r.UInt32();                       // request id
                        uint code = r.UInt32();
                        p.Outstanding--;
                        if (code == SftpMsg.STATUS_EOF)
                        {
                            p.Eof = true;
                            // Where the file ends: the buffer holds everything up to here, so a
                            // client read at or past it can be answered EOF without asking.
                            if (p.EofOffset == long.MaxValue) p.EofOffset = p.BufEnd;
                        }
                        else if (code != SftpMsg.STATUS_OK)
                        {
                            // The remote refused something. It is authoritative about the file,
                            // so stop -- and never synthesise this error towards the client,
                            // which will get the real one when it asks for itself.
                            p.Failed = true;
                        }
                        if (!p.Eof && !p.Failed) Refill(p);
                        break;
                    }

                default:
                    // Our own requests only ever draw the four replies above.
                    AbandonPrefetch("unexpected prefetch reply type " + type);
                    break;
            }

            // Only once the pipeline has drained. Closing the handle with reads still in flight
            // would answer every one of them with "unknown handle" -- harmless, but a burst of
            // alarming-looking failures in the log for no reason.
            //
            // Reads issued past the end of the file are the normal way EOF is discovered, and
            // they cost a few bytes each rather than a chunk: the measured prefetchKiB for a
            // 2 MiB file was exactly 2048, so nothing beyond the file is ever transferred.
            if ((p.Eof || p.Failed) && p.Outstanding <= 0) FinishPrefetch(p);
        }

        // Closes our handle and channel once the file has been read through. The client's own
        // handle is untouched: it has its own, and closes it when it chooses.
        private void FinishPrefetch(Prefetch p)
        {
            if (p.Handle != null)
            {
                SshLikeWriter w = new SshLikeWriter();
                AppendClose(w, p.NextId++, p.Handle);
                try { agent.SendStdin(p.Channel, w.ToArray()); } catch (Exception) { }
                p.Handle = null;
            }
            try { agent.CloseStdin(p.Channel); } catch (Exception) { }

            // Released as the active prefetch immediately rather than when the remote's DONE
            // eventually arrives. Waiting for that would be a round trip during which the next
            // file's OPEN would find a prefetch still apparently running and skip its own --
            // which is exactly the many-small-files case that needs the help most. Late replies
            // for this channel are recognised and discarded by OnPrefetchData.
            if (active == p) active = null;
        }

        // Gives up on the current prefetch without touching the client's stream. Safe at any
        // instant, which is the whole reason the fetching happens on a channel of its own.
        private void AbandonPrefetch(string reason)
        {
            Prefetch p = active;
            if (p == null) return;
            engine.LogInternal("sftp prefetch abandoned: " + reason);
            p.Failed = true;

            // Anything still parked must be let through rather than dropped, or the client waits
            // for a reply that will never come -- and SFTP has no timeout to rescue it.
            ReplayParked(p);
            DiscardBuffer(p);

            try { agent.CloseChannel(p.Channel); } catch (Exception) { }
            engine.ForgetPrefetchChannel(p.Channel);
            active = null;
        }

        // Returns the buffer's credit before letting go of it. Skipping this would leak the
        // agent's window a chunk at a time until it stalled.
        private void DiscardBuffer(Prefetch p)
        {
            while (p.Segs.Count > 0)
            {
                Segment s = p.Segs.Dequeue();
                ReleasePrefetchCredit(s.Count);
            }
            p.BufStart = p.BufEnd;
        }

        // Parked reads cannot be answered any more, so they go to the remote after all. They were
        // never forwarded, so the remote has not seen them and will answer each exactly once.
        private void ReplayParked(Prefetch p)
        {
            if (p.Waiting.Count == 0 || p.ClientHandle == null) return;
            SshLikeWriter w = new SshLikeWriter();
            int n = 0;
            while (p.Waiting.Count > 0)
            {
                Parked k = p.Waiting.Dequeue();
                AppendRead(w, k.Id, p.ClientHandle, k.Offset, k.Length);
                n++;
            }
            if (n == 0) return;
            // Onto the CLIENT's channel, with the client's own ids and handle: from the remote's
            // point of view these are simply the client's reads arriving a little late.
            owner.SendToAgentRaw(w.ToArray());
            forwardedReads += n;
            engine.LogInternal("sftp read-ahead replayed " + n + " parked read(s) to the remote");
        }

        public void OnPrefetchClosed(uint ch)
        {
            lock (gate)
            {
                engine.ForgetPrefetchChannel(ch);
                if (active != null && active.Channel == ch) active = null;
            }
        }

        // Channel teardown: drop any prefetch still running so its remote channel does not
        // outlive the session it was serving.
        public void Dispose()
        {
            lock (gate)
            {
                Prefetch p = active;
                if (p == null) return;
                try { agent.CloseChannel(p.Channel); } catch (Exception) { }
                engine.ForgetPrefetchChannel(p.Channel);
                active = null;
            }
        }
    }
}
