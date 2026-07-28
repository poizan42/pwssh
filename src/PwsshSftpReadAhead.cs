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
        private readonly int depth;              // how many chunks may be outstanding

        // Counters. The tests assert on these rather than on wall-clock, because the transport's
        // run-to-run spread is wide enough to invert a conclusion and has twice done so.
        private int clientReads;
        private int forwardedReads;
        private int prefetchIssued;
        private int prefetchBytes;
        private int valveTrips;
        private string valveReason;

        public SftpReadAhead(PwsshEngine e, IPwsshAgent a, int depthChunks)
        {
            engine = e;
            agent = a;
            depth = depthChunks;
        }

        public bool IsPassthrough { get { return mode == Mode.Passthrough; } }

        // Reported once at teardown rather than per event: a per-read log line on a 32 MiB
        // transfer would be 128 lines of noise, and the ratio is the only interesting part.
        public string Summary()
        {
            lock (gate)
            {
                string s = "sftp read-ahead: clientReads=" + clientReads
                         + " forwarded=" + forwardedReads
                         + " prefetched=" + prefetchIssued
                         + " prefetchKiB=" + (prefetchBytes / 1024)
                         + " valveTrips=" + valveTrips;
                if (valveReason != null) s += " (" + valveReason + ")";
                return s;
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
        }

        // ---- client -> agent ----
        //
        // Returns true if the caller should forward these bytes to the agent unchanged, which is
        // every case until the serving logic lands. Once it can answer a READ locally it will
        // return false for that message alone and forward the rest.
        public bool FromClient(byte[] data, int offset, int count)
        {
            lock (gate)
            {
                if (mode == Mode.Passthrough) return true;
                try
                {
                    List<SftpFramer.Msg> msgs = fromClient.Feed(data, offset, count);
                    if (fromClient.Error != null) { Trip("client stream: " + fromClient.Error); return true; }
                    for (int i = 0; i < msgs.Count; i++) Inspect(msgs[i]);
                }
                catch (Exception ex)
                {
                    Trip("client parse: " + ex.Message);
                }
                return true;
            }
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
                    // The messages are not needed yet -- this direction is framed only so that a
                    // desync is detected here rather than after the policy starts depending on it.
                    fromAgent.Feed(data, offset, count);
                    if (fromAgent.Error != null) { Trip("agent stream: " + fromAgent.Error); return true; }
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
        private void Inspect(SftpFramer.Msg m)
        {
            if (m.Count < 1) { Trip("empty SFTP message"); return; }
            byte type = m.Buffer[m.Offset];

            switch (type)
            {
                case SftpMsg.READ:
                    clientReads++;
                    forwardedReads++;
                    break;

                case SftpMsg.OPEN:
                    OnClientOpen(m);
                    break;

                case SftpMsg.CLOSE:
                    // The client is done with a handle. Ours is separate and is dropped when its
                    // own file has been read to the end, so there is nothing to do here yet.
                    break;

                // Listed only because it is the one message with no request id, so it must never
                // be read as though it had one.
                case SftpMsg.INIT:
                    break;

                default:
                    break;
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
            public int Outstanding;              // requests issued and not yet answered
            public bool Eof;                     // the remote reported the end of the file
            public bool Failed;                  // the remote refused; stop and stay out of the way
        }

        private void OnClientOpen(SftpFramer.Msg m)
        {
            // Only one prefetch at a time: sftp and scp read one file after another, so a second
            // would be speculative work competing with the first for the same link.
            if (active != null) return;

            // OPEN is: byte type, uint32 id, string path, uint32 pflags, ATTRS.
            SshLikeReader r = new SshLikeReader(m.Buffer, m.Offset + 1);
            r.UInt32();                                   // request id -- the client's, not ours
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
                }
                catch (Exception ex)
                {
                    AbandonPrefetch("prefetch parse: " + ex.Message);
                }

                // Credit is returned for every byte received. Phase 3 will hold some of these
                // bytes back for the client and release their credit as they are handed over;
                // until then nothing is retained, so everything is released immediately.
                agent.GrantWindow(ch, (uint)count);
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
                        // Phase 3 buffers this. For now the fetch is proven and the bytes are
                        // dropped, which is why this phase is expected to make transfers no
                        // faster -- only to show that prefetching works and cleans up.
                        if (len < CHUNK) p.Eof = true;    // a short read means the file ended
                        Refill(p);
                        break;
                    }

                case SftpMsg.STATUS:
                    {
                        r.UInt32();                       // request id
                        uint code = r.UInt32();
                        p.Outstanding--;
                        if (code == SftpMsg.STATUS_EOF) p.Eof = true;
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
            try { agent.CloseChannel(p.Channel); } catch (Exception) { }
            engine.ForgetPrefetchChannel(p.Channel);
            active = null;
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
