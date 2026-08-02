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
using System.Globalization;

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
        public int ResidueLength { get { return residueLen; } }

        // Hands back the bytes held for an incomplete message and forgets them.
        //
        // These bytes have already been consumed from the caller's stream and never forwarded, so
        // whoever stops parsing OWES them to the far side. Dropping them shifts every byte that
        // follows, which is how a held 4-byte length prefix once turned into the agent reading a
        // READ's type byte as a length: "bad SFTP packet length 83886080" (0x05000000). When the
        // bogus length happens to be plausible instead, the far side simply waits for bytes that
        // will never come and the transfer hangs.
        public byte[] TakeResidue()
        {
            if (residueLen == 0) return null;
            byte[] held = new byte[residueLen];
            Array.Copy(residue, 0, held, 0, residueLen);
            residue = new byte[0];
            residueLen = 0;
            return held;
        }

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
                    // Same reason as the sibling below: the array has just been handed out by
                    // reference. This branch cannot currently be reached -- Feed only ever holds
                    // strictly incomplete remainders, so NeededForResidue is never 0 on entry --
                    // but the omission was a silent-corruption trap if that ever changed.
                    residue = new byte[0];
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
        // The two metadata requests the client makes for every file. Verified with sftp -vvv
        // rather than assumed: per file it sends LSTAT (T:7), then STAT (T:17), then OPEN, then
        // the reads, then CLOSE -- and it does so for a single-file get as well as a globbed one.
        public const byte LSTAT = 7;
        public const byte FSTAT = 8;
        public const byte OPENDIR = 11;
        public const byte READDIR = 12;
        public const byte REALPATH = 16;
        public const byte STAT = 17;
        public const byte STATUS = 101;
        public const byte HANDLE = 102;
        public const byte DATA = 103;
        public const byte ATTRS = 105;

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

        // Bytes fetched that the client never asked for, summed over every buffer dropped with data
        // still in it. This is the counter that keeps the fix honest: letting a finished prefetch go on
        // serving removed the old "forwarded" signal that made re-fetching visible, and replaced it
        // with a quieter waste -- fetching up to the whole credit and throwing it away. Same reason
        // creditRecv and creditGranted are in the summary: a cost with no counter is a cost nobody
        // finds. Small values are normal (the prefetch reads in 255 KiB chunks and the file rarely
        // ends on one); a figure approaching the file size means the client stopped early.
        private long unreadBytes;

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
        public bool ShouldReport
        {
            get { lock (gate) { return !reported && (prefetchIssued > 0 || metaSpeculated > 0); } }
        }

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
                         + " metaAnswered=" + metaAnswered
                         + " metaForwarded=" + metaForwarded
                         + " metaSpeculated=" + metaSpeculated
                         + " closesEarly=" + closesAnsweredEarly
                         + " creditRecv=" + creditReceived
                         + " creditGranted=" + creditGranted
                         + " unreadKiB=" + (unreadBytes / 1024)
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
            engine.LogInternal("sftp read-ahead valve tripped: " + reason
                               + (fromClient.HasResidue
                                  ? "; client framer holds " + fromClient.ResidueLength + " byte(s)"
                                  : "")
                               + (fromAgent.HasResidue
                                  ? "; agent framer holds " + fromAgent.ResidueLength + " byte(s)"
                                  : ""));

            // Held bytes are not dropped here, they are flushed by the next call in that direction
            // (PrependHeld). Logging them is kept permanently as a tripwire: a trip with residue is
            // exactly the condition that used to corrupt the stream, and it is otherwise invisible.

            // Nothing will consume held metadata answers again, and the speculation channel has no
            // further use, so let go of both rather than carrying them to teardown.
            InvalidateSpeculation();

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
                if (mode == Mode.Passthrough)
                {
                    return PrependHeld(fromClient, data, offset, count, out outOffset, out outCount);
                }
                try
                {
                    List<SftpFramer.Msg> msgs = fromClient.Feed(data, offset, count);
                    if (fromClient.Error != null)
                    {
                        Trip("client stream: " + fromClient.Error);
                        // Anything already held back has to go now, or the agent is left waiting
                        // for the rest of a message it half received.
                        return FlushHeld(fromClient, msgs, out outOffset, out outCount);
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

        // The first passthrough feed after a trip has to carry whatever the framer was still holding.
        //
        // This is the whole fix for a corruption that took a long time to pin down. Trip() flips the
        // mode from anywhere -- including the agent pump thread -- and the old code then returned the
        // caller's buffer verbatim for ever after, so bytes consumed for a half-received message
        // simply vanished and everything behind them arrived shifted. Draining here rather than
        // inside Trip() is deliberate: it runs on the thread that owns this direction's stream, so
        // it cannot race the caller's own send, and it covers a trip raised from either direction as
        // well as from the error paths.
        private static byte[] PrependHeld(SftpFramer framer, byte[] data, int offset, int count,
                                         out int outOffset, out int outCount)
        {
            outOffset = offset;
            outCount = count;
            byte[] held = framer.TakeResidue();
            if (held == null) return data;

            byte[] joined = new byte[held.Length + count];
            Array.Copy(held, 0, joined, 0, held.Length);
            Array.Copy(data, offset, joined, held.Length, count);
            outOffset = 0;
            outCount = joined.Length;
            return joined;
        }

        // Named for what it does now: the completed messages, and then whatever is still held. The
        // held bytes are owed to the far side exactly as in PrependHeld, and this path used to drop
        // them too -- its comment claimed otherwise, which is how it escaped notice.
        //
        // A framer error can still lose the tail of the feed that errored, from the bad length
        // onwards, because Feed stops there. That is accepted: at that point the stream is provably
        // not what we think it is, and the valve exists to stop interpreting it, not to repair it.
        private byte[] FlushHeld(SftpFramer framer, List<SftpFramer.Msg> msgs,
                                 out int outOffset, out int outCount)
        {
            byte[] rebuilt = Rebuild(msgs, out outOffset, out outCount);
            byte[] held = framer.TakeResidue();
            if (held == null) return rebuilt;

            int haveLen = rebuilt == null ? 0 : outCount;
            byte[] joined = new byte[haveLen + held.Length];
            if (haveLen > 0) Array.Copy(rebuilt, outOffset, joined, 0, haveLen);
            Array.Copy(held, 0, joined, haveLen, held.Length);
            outOffset = 0;
            outCount = joined.Length;
            return joined;
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
        // Mostly observes. The one thing it removes is the remote's reply to a CLOSE we already
        // answered ourselves: two replies for one request id is fatal to the client, which says so
        // in as many words ("Can't find request for ID %u", in sftp.exe).
        //
        // Structured so the bulk download path keeps its zero-copy fast path. A feed is normally
        // exactly one SFTP message, because the agent sends one frame per reply, so the common case
        // returns the caller's own buffer untouched.
        public byte[] FromAgent(byte[] data, int offset, int count, out int outOffset, out int outCount)
        {
            outOffset = offset;
            outCount = count;
            lock (gate)
            {
                // Passthrough still has to finish what it started. A CLOSE we already answered
                // ourselves leaves the remote's own reply to that id owed a suppression, and letting
                // it through gives the client two replies for one request -- fatal to it. So the
                // shortcut is taken only once nothing is outstanding, and the held bytes go first
                // either way.
                if (mode == Mode.Passthrough && closeAnswered.Count == 0)
                {
                    return PrependHeld(fromAgent, data, offset, count, out outOffset, out outCount);
                }
                try
                {
                    // Once anything is owed a suppression we stay in rebuild mode until it is done,
                    // and we only ever ENTER that mode on a message boundary (see OnClientClose).
                    // Mixing raw forwarding with rebuilt forwarding across a half-received message
                    // would either duplicate or lose the bytes it straddles.
                    bool owed = closeAnswered.Count > 0;

                    List<SftpFramer.Msg> msgs = fromAgent.Feed(data, offset, count);
                    if (fromAgent.Error != null)
                    {
                        Trip("agent stream: " + fromAgent.Error);
                        return FlushHeld(fromAgent, msgs, out outOffset, out outCount);
                    }

                    bool dropped = false;
                    List<SftpFramer.Msg> keep = new List<SftpFramer.Msg>();
                    for (int i = 0; i < msgs.Count; i++)
                    {
                        InspectReply(msgs[i]);
                        if (IsAnsweredClose(msgs[i])) { dropped = true; continue; }
                        keep.Add(msgs[i]);
                    }

                    if (!dropped && !owed && !fromAgent.HasResidue && msgs.Count > 0
                        && msgs[0].Buffer == data && msgs[0].Offset == offset + 4)
                    {
                        return data;
                    }
                    if (!dropped && !owed && msgs.Count == 0 && !fromAgent.HasResidue) return data;

                    return Rebuild(keep, out outOffset, out outCount);
                }
                catch (Exception ex)
                {
                    Trip("agent parse: " + ex.Message);
                    return data;
                }
            }
        }

        // The remote's answer to a CLOSE the client has already been told succeeded. Consumed here
        // so a lost reply cannot leave the set growing.
        private bool IsAnsweredClose(SftpFramer.Msg m)
        {
            if (closeAnswered.Count == 0 || m.Count < 5) return false;
            if (m.Buffer[m.Offset] != SftpMsg.STATUS) return false;
            try
            {
                SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                uint id = r.UInt32();
                if (!closeAnswered.ContainsKey(id)) return false;
                closeAnswered.Remove(id);
                closesAnsweredEarly++;
                return true;
            }
            catch (Exception) { return false; }
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

            // Held metadata is invalidated here, and how coarsely matters. A request that names one
            // path drops only that path, because a globbed get's own per-file OPEN and CLOSE would
            // otherwise wipe the answers prepared for every file after it -- which is the whole
            // benefit. Anything else drops everything.
            switch (type)
            {
                // Read-only requests, enumerated explicitly. A glob uses OPENDIR/READDIR and a
                // session starts with REALPATH, and none of them can change a file's attributes,
                // so wiping on them would throw away the answers the glob phase just prepared.
                case SftpMsg.LSTAT:
                case SftpMsg.STAT:
                case SftpMsg.FSTAT:
                case SftpMsg.READ:
                case SftpMsg.OPENDIR:
                case SftpMsg.READDIR:
                case SftpMsg.REALPATH:
                    break;

                case SftpMsg.OPEN:
                    InvalidatePath(PeekPath(m));         // may truncate or create
                    NoteClientOpen(m);
                    break;

                case SftpMsg.CLOSE:
                    {
                        // Only this file: a globbed get closes each file in turn, and wiping
                        // everything here would undo the preparation for all the later ones.
                        string h = PeekHandle(m);
                        string hp = PathForHandle(h);
                        if (hp != null) InvalidatePath(hp);   // a write handle finalises size and mtime
                        TryAnswerCloseEarly(m, h);
                        if (h != null) { handlePath.Remove(h); readHandles.Remove(h); }
                    }
                    break;

                // Everything else, known or not: assume it changed something.
                //
                // That includes EXTENDED, so a `df` mid-session throws away held metadata even
                // though statvfs changes nothing. Left alone deliberately: EXTENDED also carries
                // posix-rename and fsync, which genuinely do change things, so the type cannot be
                // exempted wholesale -- it would have to be exempted by NAME, which means parsing
                // the name here, in the path every bulk transfer goes through, to save a couple of
                // round trips on a command a user types once.
                default:
                    InvalidateSpeculation();
                    break;
            }

            switch (type)
            {
                case SftpMsg.LSTAT:
                case SftpMsg.STAT:
                    if (OnClientStat(m, type)) return false;   // answered locally; do not forward
                    break;

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
            if (m.Count < 1) return;
            NoteHandleReply(m);

            Prefetch p = active;
            if (p == null || !p.AwaitingClientHandle) return;
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

        // Answers a read handle's CLOSE at once, while still forwarding it so the remote frees the
        // FileStream -- a leaked one holds an NTFS lock until wsmprovhost exits, which is worse than
        // a leaked port because the user's next attempt fails on their own file.
        //
        // Nothing meaningful can fail when closing a read handle: a failure would mean the handle
        // was already gone, and the bytes the client received were still correct. A WRITE handle is
        // a different matter entirely -- its close is where an upload commits -- which is why only
        // handles seen to be opened read-only qualify.
        //
        // Ordering against a later write-open of the same path is safe on this channel, because the
        // agent's worker is FIFO per channel and so processes the forwarded CLOSE first.
        private void TryAnswerCloseEarly(SftpFramer.Msg m, string handle)
        {
            // Never arm a new suppression once the valve has tripped. Inspect does not itself check
            // the mode, so a trip part way through a feed would otherwise let a later message in the
            // same feed take on an obligation the reply direction has already stopped honouring.
            if (mode != Mode.Proxy) return;
            if (handle == null || !readHandles.ContainsKey(handle)) return;
            // Only ever entered on a message boundary in the reply direction: FromAgent switches
            // to rebuilding while anything is owed, and that switch must not happen part way
            // through a message it would then either duplicate or drop.
            if (fromAgent.HasResidue) return;
            if (closeAnswered.Count >= 64) return;         // bounded; the honest round trip still works

            uint id;
            try
            {
                SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                id = r.UInt32();
            }
            catch (Exception) { return; }

            SshLikeWriter w = new SshLikeWriter();
            SshLikeWriter body = new SshLikeWriter();
            body.Byte(SftpMsg.STATUS);
            body.UInt32(id);
            body.UInt32(SftpMsg.STATUS_OK);
            body.Text("");
            body.Text("");
            AppendFramed(w, body);
            closeAnswered[id] = true;
            owner.SendSynthetic(w.ToArray(), null);
        }

        // Ties a HANDLE reply back to the path its OPEN named, so a CLOSE can later invalidate just
        // that file. Runs for every reply, independently of whether a prefetch is in progress.
        private void NoteHandleReply(SftpFramer.Msg m)
        {
            try
            {
                byte type = m.Buffer[m.Offset];
                if (type != SftpMsg.HANDLE && type != SftpMsg.STATUS) return;
                SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                uint id = r.UInt32();
                string path;
                if (!openIdPath.TryGetValue(id, out path)) return;
                bool readOnly;
                openIdReadOnly.TryGetValue(id, out readOnly);
                openIdPath.Remove(id);
                openIdReadOnly.Remove(id);
                if (type != SftpMsg.HANDLE) return;      // the open failed; nothing to remember
                string handle = r.Text();
                if (handle.Length == 0) return;
                if (handlePath.Count >= 256) { handlePath.Clear(); readHandles.Clear(); }
                handlePath[handle] = path;
                if (readOnly) readHandles[handle] = true;
            }
            catch (Exception) { }
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
            //
            // This used to be close to dead code -- the prefetch was retired almost the instant
            // EofOffset became known, so `active` was null by the time a read could reach here. Now
            // that a finished buffer keeps serving, it is live for as long as the client holds the
            // handle, which freezes the client's view of where the file ends at the moment our
            // prefetch proved it. A file being appended to therefore reads short. That is deliberate:
            // the alternative is a forwarded round trip per file, which is the very cost the metadata
            // speculation was built to remove, and a real SFTP server racing a concurrent writer gives
            // no better guarantee.
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
                    ReleasePrefetchCredit(p, s.Count);
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
                    ReleasePrefetchCredit(p, s.Count);
                }
                else
                {
                    // Partly consumed: keep the remainder, and account only what left.
                    s.Offset += skip + take;
                    s.Count -= skip + take;
                    s.FileOffset = offset;
                    p.BufStart = offset;
                    ReleasePrefetchCredit(p, skip + take);
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
                //
                // The wording matters. A prefetch that merely finished and kept serving now reaches
                // here on EVERY ordinary download, and "abandoned" once per file would read as a fault
                // in every session log. Only say something when there is something to say -- bytes
                // fetched that the client never read -- and say it neutrally.
                AbandonPrefetch(p.ChannelClosed ? null : "client closed the file");
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

            // The fetch is over and the private channel is gone, but the buffer is still serving the
            // client. This is the one state in which a non-null `active` means "a buffer" rather than
            // "a fetch", and every place that reads `active` has to know which of the two it wants.
            public bool ChannelClosed;

            // Its OWN framer, not one shared across prefetches. A shared framer carries residue and
            // a sticky Error from one file's channel to the next: Feed returns immediately once
            // Error is set, so a single desync would silently disable read-ahead for the rest of the
            // session, and an abandon part way through a split reply would leave a partial DATA that
            // the NEXT file's bytes append to. Same class of mistake as the valve dropping held
            // bytes -- framer state outliving the thing it belonged to.
            public readonly SftpFramer Framer = new SftpFramer();

            // Credit accounting for this channel, as an absolute balance rather than a per-feed sum.
            // The invariant is Received == Granted + Retained + Framer.ResidueLength: every byte
            // that arrived has been handed back, is sitting in Segs waiting for the client, or is
            // part of a message the framer has not finished reading. Carried here rather than on the
            // proxy so it resets per prefetch for free.
            //
            // The balance FREEZES at ChannelClosed, so afterwards Retained also covers "was retained
            // at the moment the channel closed". Releasing credit past that point would be correct in
            // the arithmetic and pointless on the wire: the grants would be upstream WINDOW frames for
            // a channel the agent has already killed, and upstream is the scarce direction -- about
            // 130 of them for a full 32 MiB buffer, which is exactly the waste the batching in
            // GRANT_THRESHOLD exists to avoid.
            public long Received;
            public long Granted;
            public long Retained;

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
            //
            // A RETIRED buffer is different, and must not block the next file. Its fetch is over and
            // its channel is gone; only unread bytes remain, and the client is evidently done with
            // them or it would not be opening something else. Dropping it here is what keeps the
            // many-small-files case working -- that case is the one that needs read-ahead most (40
            // files of 900 bytes went 150 s to 94 s on earlier work), and it would lose its prefetch
            // entirely if a finished one still counted as active.
            //
            // In practice this is the rare path: sftp, scp -r and SSH.NET all CLOSE a file before
            // opening the next, so OnClientClose has usually dropped the buffer already. When it does
            // fire -- a client holding two handles at once -- the second file simply gets today's
            // behaviour rather than none.
            if (active != null)
            {
                if (!active.ChannelClosed) return;
                AbandonPrefetch("a new file was opened while a finished buffer was still held");
            }

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

        // ------------------------------------------------------ speculative metadata
        //
        // The client asks LSTAT then STAT for every file, serially, so two of the ~5 round trips
        // per file are spent learning the same file's attributes twice. On seeing the first of
        // them we forward it untouched AND ask the remote the OTHER question on a channel of our
        // own, so that by the time the client asks it we already hold the answer.
        //
        // This is a PARALLEL FETCH, NOT A CACHE, and the distinction is the whole safety argument:
        // the speculative request goes out at essentially the same moment the client's own would
        // have, so the answer is at most one round trip staler than what the client would have got.
        // Nothing is ever held across an operation that could change it.
        //
        // And metadata is never synthesised. What the client receives is the remote's own answer
        // to a byte-identical request, with only the 4-byte request id patched. Re-encoding the
        // ATTRS payload could corrupt it; patching four bytes cannot.
        //
        // LSTAT and STAT are NOT interchangeable -- STAT follows a reparse point and LSTAT does
        // not (AgentSftpChannel.DoStat's followLinks) -- so an LSTAT reply must never answer a
        // STAT. That is precisely why this issues a real second request instead of reusing the
        // first reply, and why a junction has its own test.
        //
        // A channel of its own rather than the prefetch channel: the agent's worker is serial per
        // channel, which is the whole reason the prefetch channel exists, so a speculative STAT
        // must not queue behind a 255 KiB READ.

        private bool metaStarted;
        private uint metaChannel;
        private readonly SftpFramer fromMeta = new SftpFramer();
        private uint metaNextId = 1;

        // A MAP, not a single slot, and the reason is measured rather than assumed. A globbed
        // `get dir/*` does not interleave one file's requests with the next: it LSTATs every match
        // up front to expand the glob, and only then walks the files doing STAT, OPEN, reads,
        // CLOSE one at a time. With one slot each LSTAT overwrote the last speculation, so by the
        // time STAT(first) arrived we were holding STAT(last) and the hit rate was exactly zero --
        // observed, 80 speculations and 0 answers. Holding them all turns the glob phase, which
        // the client pays for anyway, into preparation that makes every per-file STAT free.
        private readonly Dictionary<string, byte[]> metaHeld = new Dictionary<string, byte[]>();
        private readonly Dictionary<uint, string> metaPending = new Dictionary<uint, string>();

        // Bounded so a client that stats thousands of paths without opening them cannot grow this
        // without limit. Past the cap we simply stop speculating; the honest round trip is always
        // available and is what the unoptimised path does anyway.
        private const int META_MAX_HELD = 512;

        private int metaAnswered;             // client metadata requests answered from a speculation
        private int metaForwarded;
        private int metaSpeculated;

        private static string MetaKey(byte type, string path)
        {
            return type.ToString(CultureInfo.InvariantCulture) + "|" + path;
        }

        // The first string after the request id, which for OPEN is the path and for CLOSE is the
        // handle. Defensive because a truncated payload must invalidate rather than throw.
        private static string PeekFirstString(SftpFramer.Msg m)
        {
            try
            {
                SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                r.UInt32();
                return r.Text();
            }
            catch (Exception) { return null; }
        }

        private static string PeekPath(SftpFramer.Msg m) { return PeekFirstString(m); }
        private static string PeekHandle(SftpFramer.Msg m) { return PeekFirstString(m); }

        // Which path a client handle refers to, learned from its OPEN and the HANDLE that answered
        // it. Needed so a CLOSE can invalidate just that file rather than everything.
        private readonly Dictionary<uint, string> openIdPath = new Dictionary<uint, string>();
        private readonly Dictionary<string, string> handlePath = new Dictionary<string, string>();

        // Handles the client opened read-only, which are the only ones whose CLOSE may be answered
        // before the remote confirms it. A write handle's close is where an upload's data is
        // finally committed, so reporting success early there could tell the client a transfer
        // worked when it did not.
        private readonly Dictionary<uint, bool> openIdReadOnly = new Dictionary<uint, bool>();
        private readonly Dictionary<string, bool> readHandles = new Dictionary<string, bool>();

        // Client request ids for CLOSEs we answered ourselves, so the remote's own reply to each
        // can be dropped on the way back.
        private readonly Dictionary<uint, bool> closeAnswered = new Dictionary<uint, bool>();
        private int closesAnsweredEarly;

        private string PathForHandle(string handle)
        {
            if (handle == null) return null;
            string path;
            if (handlePath.TryGetValue(handle, out path)) return path;
            return null;
        }

        // Called for every client OPEN, so a later HANDLE reply can be tied back to a path. The
        // agent caps itself at 256 handles, but an OPEN that fails never produces one, so this is
        // bounded here too rather than trusting the far side to bound it for us.
        private void NoteClientOpen(SftpFramer.Msg m)
        {
            try
            {
                SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                uint id = r.UInt32();
                string path = r.Text();
                uint pflags = r.UInt32();
                if (path.Length == 0) return;
                if (openIdPath.Count >= 256) { openIdPath.Clear(); openIdReadOnly.Clear(); }
                openIdPath[id] = path;
                openIdReadOnly[id] = (pflags & SftpMsg.PFLAG_WRITE) == 0
                                     && (pflags & SftpMsg.PFLAG_READ) != 0;
            }
            catch (Exception) { }
        }

        // Returns true if the client's request was answered locally and must not be forwarded.
        private bool OnClientStat(SftpFramer.Msg m, byte type)
        {
            SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
            uint id = r.UInt32();
            string path = r.Text();
            if (path.Length == 0) return false;

            string key = MetaKey(type, path);
            byte[] held;
            if (metaHeld.TryGetValue(key, out held))
            {
                metaHeld.Remove(key);                     // single use, always
                if (AnswerFromSpeculation(held, id)) { metaAnswered++; return true; }
            }

            if (engine.SftpMetaTrace)
            {
                engine.LogInternal("meta miss: t=" + type + " '" + path + "' held=" + metaHeld.Count
                                   + " pending=" + metaPending.Count);
            }
            metaForwarded++;

            // Speculate the other question about this same path. Deliberately not conditioned on
            // which of the two arrived first: the observed order is LSTAT then STAT, and nothing
            // here depends on that continuing to hold.
            Speculate(path, type == SftpMsg.LSTAT ? SftpMsg.STAT : SftpMsg.LSTAT);
            return false;
        }

        // Wipes every held answer. Used for requests that could change a file we know nothing
        // else about -- a blacklist of things known to be safe rather than a whitelist of things
        // known to be dangerous, so a SETSTAT, RENAME, REMOVE or vendor extension nobody here
        // enumerated discards rather than being quietly trusted.
        private void InvalidateSpeculation()
        {
            if (metaHeld.Count > 0) metaHeld.Clear();
            if (metaPending.Count > 0) metaPending.Clear();
        }

        // Drops what we hold about one path, for a request that names its target. Keeping the rest
        // is what makes a globbed get fast: its per-file OPEN and CLOSE would otherwise wipe the
        // answers prepared for every file after this one.
        private void InvalidatePath(string path)
        {
            if (path == null) { InvalidateSpeculation(); return; }   // unknown target: assume the worst
            metaHeld.Remove(MetaKey(SftpMsg.LSTAT, path));
            metaHeld.Remove(MetaKey(SftpMsg.STAT, path));
        }

        private void Speculate(string path, byte type)
        {
            string key = MetaKey(type, path);
            if (metaHeld.ContainsKey(key)) return;
            if (metaHeld.Count + metaPending.Count >= META_MAX_HELD) return;
            if (metaPending.ContainsValue(key)) return;

            SshLikeWriter w = new SshLikeWriter();
            if (!metaStarted)
            {
                uint ch;
                if (!engine.TryRegisterPrefetchChannel(this, out ch)) return;
                metaChannel = ch;
                metaStarted = true;
                agent.Subsystem(ch, "sftp");
                AppendInit(w);                            // same frame as the request below
                engine.LogInternal("sftp metadata channel " + ch);
            }

            uint reqId = metaNextId++;
            SshLikeWriter body = new SshLikeWriter();
            body.Byte(type);
            body.UInt32(reqId);
            body.Text(path);                              // copied through; never interpreted here
            AppendFramed(w, body);
            try { agent.SendStdin(metaChannel, w.ToArray()); }
            catch (Exception) { return; }
            metaPending[reqId] = key;
            metaSpeculated++;
        }

        // Patches the request id and sends the reply on verbatim. Layout is
        // [4 length][1 type][4 id][payload], so the id is bytes 5..8 of the framed message.
        private bool AnswerFromSpeculation(byte[] framed, uint clientId)
        {
            if (framed.Length < 9) return false;
            byte[] copy = new byte[framed.Length];
            Array.Copy(framed, copy, framed.Length);
            copy[5] = (byte)(clientId >> 24);
            copy[6] = (byte)(clientId >> 16);
            copy[7] = (byte)(clientId >> 8);
            copy[8] = (byte)clientId;
            owner.SendSynthetic(copy, null);
            return true;
        }

        // Replies on the metadata channel. A desync here is NOT a valve trip: this channel is ours
        // alone and the client has never seen a byte of it, so the worst case is that speculation
        // stops working. Credit is granted in full on receipt because the reply is copied out --
        // nothing of the agent's window is retained.
        private void OnMetaData(uint ch, byte[] buffer, int offset, int count)
        {
            creditReceived += count;
            try
            {
                List<SftpFramer.Msg> msgs = fromMeta.Feed(buffer, offset, count);
                if (fromMeta.Error == null)
                {
                    for (int i = 0; i < msgs.Count; i++)
                    {
                        SftpFramer.Msg m = msgs[i];
                        if (m.Count < 5) continue;
                        byte type = m.Buffer[m.Offset];
                        if (type != SftpMsg.ATTRS && type != SftpMsg.STATUS) continue;
                        SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
                        // Matched strictly on id, which is what makes a reply for a speculation
                        // that has since been invalidated harmless rather than something to track.
                        uint replyId = r.UInt32();
                        string key;
                        if (!metaPending.TryGetValue(replyId, out key)) continue;
                        metaPending.Remove(replyId);
                        byte[] framed = new byte[4 + m.Count];
                        Array.Copy(m.Buffer, m.Offset - 4, framed, 0, 4 + m.Count);
                        metaHeld[key] = framed;
                    }
                }
                else
                {
                    InvalidateSpeculation();
                }
            }
            catch (Exception)
            {
                InvalidateSpeculation();
            }
            // The full count, and correct: every reply is copied out of the frame buffer, so this
            // channel retains nothing of the agent's window.
            Grant(ch, count);
        }

        // ---- replies on our private channel ----

        public void OnPrefetchData(uint ch, byte[] buffer, int offset, int count, bool stderr)
        {
            lock (gate)
            {
                if (stderr)
                {
                    // Granted before returning. No SFTP channel emits stderr today -- only a
                    // process channel does -- but returning without granting would withhold that
                    // many bytes for ever, which is the direction that stalls with no timeout.
                    creditReceived += count;
                    Grant(ch, count);
                    return;
                }
                if (metaStarted && ch == metaChannel) { OnMetaData(ch, buffer, offset, count); return; }
                creditReceived += count;
                Prefetch p = active;
                if (p != null && p.Channel == ch && p.ChannelClosed)
                {
                    // A late reply on a retired prefetch's channel, which in practice means the STATUS
                    // answering the CLOSE that retiring sent. Nothing is owed on it -- retiring
                    // requires Outstanding <= 0, so every READ has been answered -- and feeding it to
                    // the framer would be actively harmful: a DATA would push BufEnd past EofOffset and
                    // a STATUS would drive Outstanding negative, then retire a second time.
                    //
                    // No grant: the channel is closed, so a WINDOW frame would be upstream traffic the
                    // agent discards. That leaves creditGranted below creditReceived, the harmless
                    // direction, and the freeze note on Retained explains why.
                    //
                    // This is a RACE GUARD, not the normal path: ForgetPrefetchChannel means
                    // PwsshEngine.OnData's FindPrefetch usually drops such a reply a level up. It is
                    // reachable only when OnData resolved the channel under chanGate and then blocked
                    // on `gate` while the client thread retired the prefetch. Do not delete it as dead.
                    return;
                }
                if (p == null || p.Channel != ch)
                {
                    // A late reply for a prefetch that has already been abandoned. Its credit
                    // still has to be returned or the agent's channel would stall on the way to
                    // being torn down. Deliberately outside the balance below: that prefetch is
                    // gone, and its channel is closed.
                    Grant(ch, count);
                    return;
                }
                p.Received += count;
                try
                {
                    List<SftpFramer.Msg> msgs = p.Framer.Feed(buffer, offset, count);
                    if (p.Framer.Error != null)
                    {
                        // Our own channel desynced. Nothing of the client's is at risk, so this
                        // is simply the end of read-ahead for this file.
                        AbandonPrefetch("prefetch stream: " + p.Framer.Error);
                        Grant(ch, count);
                        return;
                    }
                    for (int i = 0; i < msgs.Count; i++)
                    {
                        HandlePrefetchReply(p, msgs[i]);
                        // A reply can abandon the prefetch part way through the feed. Carrying on
                        // would enqueue into a buffer nothing will ever read from.
                        //
                        // ChannelClosed has to be checked as well as `active`, because retiring no
                        // longer changes `active` -- so without it this loop would keep feeding a
                        // prefetch whose channel is gone: a DATA past EofOffset, a STATUS driving
                        // Outstanding negative, and a second retirement.
                        if (active != p || p.ChannelClosed) break;
                    }
                    // Retiring already drained; doing it again would be harmless but the condition
                    // has to agree with the loop's, or the two disagree about what `active` means.
                    if (active == p && !p.ChannelClosed) DrainWaiting(p);
                }
                catch (Exception ex)
                {
                    AbandonPrefetch("prefetch parse: " + ex.Message);
                }

                GrantOwed(p, ch);
            }
        }

        // Grants back whatever this channel is owed, as an absolute balance rather than a per-feed
        // subtraction. That single change is the fix: the old code computed `count - retained` per
        // feed and threw away the result when it went negative, so a fragment that completed
        // nothing had its whole length granted and the completing fragment's retained blob was then
        // granted again on consumption. The surplus was permanent because nothing remembered it.
        //
        // Here it is not permanent. A feed that overshoots computes owe <= 0 and grants nothing,
        // and because Granted is remembered the following feeds grant correspondingly less until
        // the books balance. No per-feed carry to get wrong.
        //
        // WHAT IS DELIBERATELY *NOT* SUBTRACTED, learned by breaking it: the framer's residue.
        // Withholding credit for a half-received message deadlocks outright whenever the window is
        // smaller than one message -- the client waits for the message to complete, the agent
        // cannot send the rest of it without credit, and neither side can move. A 64 KiB window
        // against 255 KiB replies hangs immediately. So residue counts as progress; the cost is
        // that the balance may run ahead of what has arrived by at most one message (MAX_MSG,
        // 256 KiB), which is bounded and self-correcting, where the buffered segments it does
        // withhold are the part that would otherwise grow without limit.
        private void GrantOwed(Prefetch p, uint ch)
        {
            long owe = p.Received - p.Granted - p.Retained;
            if (owe <= 0) return;
            p.Granted += owe;
            Grant(ch, owe);
        }

        // Every grant this class makes goes through here, so the session totals in Summary() are a
        // complete picture. creditGranted exceeding creditReceived is proof of an over-grant, which
        // is otherwise invisible from the client side.
        private long creditReceived;
        private long creditGranted;

        private void Grant(uint ch, long n)
        {
            if (n <= 0) return;
            creditGranted += n;
            try { agent.GrantWindow(ch, (uint)n); } catch (Exception) { }
        }

        // Called as buffered bytes leave, whether to the client or to the bin. Every retained byte
        // passes through here exactly once, which is what keeps the balance honest -- releasing one
        // twice would turn a harmless over-grant into the under-grant that stalls for good.
        // The prefetch is a parameter rather than read from `active`, and that is load-bearing rather
        // than tidiness. A retired buffer can now be dropped while a NEW prefetch is being installed
        // (OnClientOpen), and a stale read of `active` here would decrement the new prefetch's
        // Retained -- after which GrantOwed computes owe = Received - Granted - Retained against an
        // understated Retained and over-grants on a LIVE channel. That is the one direction the window
        // exists to prevent, and it is what AgentSftpChannel.AddCredit logs as "the client granted
        // more than it received". Passing p makes it unrepresentable.
        private void ReleasePrefetchCredit(Prefetch p, int bytes)
        {
            if (bytes <= 0 || p == null) return;
            if (p.ChannelClosed) return;           // the channel is gone; see the freeze note on Retained
            p.Retained -= bytes;
            p.Granted += bytes;
            Grant(p.Channel, bytes);
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
                        p.Retained += len;

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
            if ((p.Eof || p.Failed) && p.Outstanding <= 0) RetirePrefetch(p);
        }

        // Closes our handle and channel once the file has been read through, and KEEPS THE BUFFER.
        // The client's own handle is untouched: it has its own, and closes it when it chooses.
        //
        // The buffer outliving the fetch is the whole point. It used to be dropped here -- `active`
        // was nulled, TryServeRead then refused, and every remaining client read was forwarded to the
        // remote, fetching bytes we already held a second time. Measured on 8 MiB read in 128 KiB
        // increments at the default depth: served=18, forwarded=111, the whole file prefetched and six
        // sevenths of it fetched twice, with no counter showing it.
        //
        // Steps 1-3 are also the fix for a hang, which is the more serious half. This runs from inside
        // OnPrefetchData's per-message loop; nulling `active` there made the loop break and skipped the
        // DrainWaiting after it, and nothing else ever looked at p.Waiting again -- FinishPrefetch
        // never replayed, and CheckParkDeadline reads `active`, so the backstop could not see the
        // orphaned prefetch either. Any read parked at that instant was never answered and never
        // forwarded, and SFTP has no timeout: the client waited for ever. Reachable at depth 1 on the
        // EOF path, and at ANY depth once p.Failed stops Refill and the last in-flight reply retires.
        private void RetirePrefetch(Prefetch p)
        {
            // The loop can now reach this twice, because `active` no longer changes to stop it.
            if (p.ChannelClosed) return;

            // Everything the now-complete buffer can answer. Safe before the handle is released only
            // because Refill returns on p.Eof || p.Failed, which retiring guarantees -- so the Refill
            // at the tail of ServeFromBuffer cannot issue on a channel that is about to close.
            DrainWaiting(p);

            // Whatever the buffer could not answer goes to the remote after all. Only reachable on the
            // Failed path: once Eof is proven, EofOffset is set and BufEnd has reached it, so every
            // read is either satisfiable or answered EOF and nothing can still be parked. Always safe
            // regardless -- a parked read was never forwarded, so the remote answers it exactly once.
            if (p.Waiting.Count > 0) ReplayParked(p);

            // A failed prefetch keeps nothing: TryServeRead refuses on Failed, so its buffer would
            // serve nobody and only hold memory. Discarded here, before the close, so its credit still
            // has a live channel to go back to.
            if (p.Failed) DiscardBuffer(p);

            if (p.Handle != null)
            {
                SshLikeWriter w = new SshLikeWriter();
                AppendClose(w, p.NextId++, p.Handle);
                try { agent.SendStdin(p.Channel, w.ToArray()); } catch (Exception) { }
                p.Handle = null;
            }
            // CloseChannel, not CloseStdin, and the difference is an ordering guarantee rather than
            // tidiness. The agent frees a channel's handles inside Kill(), which runs on its SERIAL
            // inbound frame loop, so by the time any later frame is dispatched our read handle is
            // provably gone. An EOF frame instead leaves the release to this channel's own worker
            // thread, which is asynchronous with the client channel's worker -- so a client that
            // downloads a file and immediately uploads over it (write opens are FileShare.None)
            // would be racing our teardown.
            //
            // That race was never observed: 200 get-then-put pairs on a 900-byte file, where the
            // two are as close together as this design can put them, came back clean. It could not
            // easily be otherwise, because at least one full round trip -- the put's own STAT --
            // separates the two, while the worker needs microseconds to wake and dispose. But
            // "the scheduler would have to starve a runnable thread for a round trip" is a weaker
            // thing to rely on than "the frame loop already did it", for two lines.
            try { agent.CloseChannel(p.Channel); } catch (Exception) { }
            engine.ForgetPrefetchChannel(p.Channel);      // no DONE is coming now, so do it here
            p.ChannelClosed = true;

            // A failed prefetch is released as `active` outright; one that finished normally stays
            // installed so its buffer can go on serving. Either way the NEXT file's OPEN is not
            // blocked: OnClientOpen drops a retired buffer rather than returning early, which is what
            // preserves the many-small-files case that needs the help most. Late replies on this
            // channel -- the STATUS answering the CLOSE just sent -- are discarded by OnPrefetchData.
            if (p.Failed && active == p) active = null;
        }

        // Gives up on the current prefetch without touching the client's stream. Safe at any
        // instant, which is the whole reason the fetching happens on a channel of its own.
        //
        // A null reason means "nothing went wrong": a finished prefetch whose buffer the client is
        // simply done with. That case reaches here on every ordinary download, and "abandoned" once per
        // file would read as a fault in every session log.
        private void AbandonPrefetch(string reason)
        {
            Prefetch p = active;
            if (p == null) return;
            if (reason != null) engine.LogInternal("sftp prefetch abandoned: " + reason);

            // Bytes fetched that the client never asked for. Counted here rather than at the call
            // sites because this is the single funnel through which a buffer is dropped, whichever
            // path got here -- a CLOSE, a second OPEN, a backwards seek, a valve trip.
            if (p.ChannelClosed)
            {
                long unread = p.BufEnd - p.BufStart;
                if (unread > 0)
                {
                    unreadBytes += unread;
                    engine.LogInternal("sftp prefetch buffer released with " + (unread / 1024)
                        + " KiB the client never read");
                }
            }

            p.Failed = true;

            // Anything still parked must be let through rather than dropped, or the client waits
            // for a reply that will never come -- and SFTP has no timeout to rescue it.
            ReplayParked(p);
            DiscardBuffer(p);

            // A retired prefetch has already released these. Closing a forgotten channel twice is
            // harmless agent-side -- FindStream returns null and the frame is ignored -- but saying so
            // once is better than relying on it at four call sites.
            if (!p.ChannelClosed)
            {
                try { agent.CloseChannel(p.Channel); } catch (Exception) { }
                engine.ForgetPrefetchChannel(p.Channel);
            }
            // Always cleared, whether the prefetch was fetching or merely serving: every caller of
            // this -- the backwards seek, Trip, OnClientClose, the park deadline, a second OPEN --
            // means "this buffer is finished with".
            active = null;
        }

        // Returns the buffer's credit before letting go of it. Skipping this would leak the
        // agent's window a chunk at a time until it stalled.
        private void DiscardBuffer(Prefetch p)
        {
            while (p.Segs.Count > 0)
            {
                Segment s = p.Segs.Dequeue();
                ReleasePrefetchCredit(p, s.Count);
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
                // NOT for a retired prefetch: this fires for a channel we closed deliberately, and
                // nulling `active` here would silently throw away a buffer that is still serving the
                // client. It is the one place that must leave `active` alone. Before the buffer
                // outlived the fetch this could not run at all for a finished prefetch, because
                // ForgetPrefetchChannel had already made the engine's lookup fail; now it can.
                if (active != null && active.Channel == ch && !active.ChannelClosed) active = null;
                if (metaStarted && ch == metaChannel)
                {
                    // Speculation stops rather than being retried on a fresh channel: if the
                    // remote dropped this one, the honest round trip is the right answer.
                    metaStarted = false;
                    InvalidateSpeculation();
                }
            }
        }

        // Channel teardown: drop any prefetch still running so its remote channel does not
        // outlive the session it was serving.
        public void Dispose()
        {
            lock (gate)
            {
                // The metadata channel lives for the whole session rather than per file, so it is
                // this method's job to take it down. Leaking it would leave an idle sftp worker on
                // the remote until its own watchdog noticed.
                if (metaStarted)
                {
                    try { agent.CloseChannel(metaChannel); } catch (Exception) { }
                    engine.ForgetPrefetchChannel(metaChannel);
                    metaStarted = false;
                    InvalidateSpeculation();
                }

                Prefetch p = active;
                if (p == null) return;
                // The guard is cosmetic rather than load-bearing: a retired prefetch has already
                // released both, and closing a forgotten channel again is a no-op agent-side. It is
                // here so the code says which state it is in rather than relying on that.
                if (!p.ChannelClosed)
                {
                    try { agent.CloseChannel(p.Channel); } catch (Exception) { }
                    engine.ForgetPrefetchChannel(p.Channel);
                }
                active = null;
            }
        }
    }
}
