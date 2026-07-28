// pwssh agent: everything the remote needs, plus the wire plumbing shared with the engine.
//
// This file must be SELF-CONTAINED. The remote can only compile one source string -- an
// in-memory Add-Type assembly has no Location to reference from a second compilation -- so
// ByteChannel, the inbound pump and the frame helpers live here rather than in
// PwsshEngine.cs. The client compiles both files together via Add-Type -Path.
//
// Must compile as C# 5 (the .NET Framework 4.8 CodeDOM compiler used by Add-Type on
// Windows PowerShell 5.1): no string interpolation, no ?., no out-var, no tuples.
//
// No cryptography here. SSH terminates in the client, so what crosses the WinRM link is
// plaintext -- which lets WinRM's own compression work (measured ~29x on compressible
// output versus an encrypted stream).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace Pwssh
{
    public interface IByteReceiver
    {
        void PushInbound(byte[] data);
        void CloseInbound();
    }

    // ---------------------------------------------------------------------- frames
    //
    // One transport item is exactly one frame: items cross the remoting channel intact and
    // in order, so no length prefixing between frames is needed -- only this header.
    //
    //   [1 byte type][4 bytes big-endian channel id][payload...]
    //
    // The high bit of the type marks direction, which makes a misrouted frame obvious.

    public static class FrameType
    {
        // client -> agent
        public const byte EXEC = 0x01;    // payload: UTF-8 command
        public const byte DATA = 0x02;    // payload: stdin bytes
        public const byte EOF = 0x03;     // no payload: close child stdin
        public const byte CLOSE = 0x04;   // no payload: tear the channel down
        public const byte WINDOW = 0x05;  // payload: uint32 credit
        public const byte SHELL = 0x06;   // no payload: start the login shell
        public const byte PTY = 0x07;     // payload: uint32 cols, uint32 rows, UTF-8 term
        public const byte RESIZE = 0x08;  // payload: uint32 cols, uint32 rows
        public const byte SIGNAL = 0x09;  // payload: UTF-8 signal name
        public const byte CONNECT = 0x0A; // payload: UTF-8 host, uint32 port (direct-tcpip)
        // Remote forwarding (-R). The channel field carries a forward id for LISTEN/UNLISTEN,
        // and an accepted-channel id for ACCEPT_OK.
        public const byte LISTEN = 0x0B;    // payload: UTF-8 bind address, uint32 port
        public const byte UNLISTEN = 0x0C;  // no payload
        public const byte ACCEPT_OK = 0x0D; // no payload: the client confirmed, start pumping
        // Keepalive. Carries nothing and is discarded on arrival; its only purpose is to prove
        // the client is still there, so the agent's watchdog can tell an idle session from a
        // dead one. See PwsshAgentHost.Watchdog for why that distinction has to be made.
        public const byte PING = 0x0E;
        // A subsystem channel. Only "sftp" exists, and the engine refuses anything else
        // locally, so this never arrives with another name.
        public const byte SUBSYSTEM = 0x0F; // payload: UTF-8 subsystem name

        // agent -> client
        public const byte OUT = 0x81;     // payload: stdout bytes
        public const byte ERR = 0x82;     // payload: stderr bytes
        public const byte EXIT = 0x83;    // payload: uint32 exit status
        public const byte DONE = 0x84;    // no payload: channel finished
        public const byte HELLO = 0x85;   // payload: UTF-8 remote account name
        public const byte FAIL = 0x86;    // payload: UTF-8 message
        public const byte CONNECT_OK = 0x87;   // no payload: the outbound socket is up
        public const byte CONNECT_FAIL = 0x88; // payload: UTF-8 reason
        public const byte LISTEN_OK = 0x89;    // payload: uint32 actually bound port
        public const byte LISTEN_FAIL = 0x8A;  // payload: UTF-8 reason
        // payload: uint32 forward id, uint32 bound port, UTF-8 origin address, uint32 origin port.
        // The channel field is the accepted channel's id. The bound *address* is deliberately
        // not sent: the client has to quote back the address string it asked for, not the one
        // we actually bound, or ssh will not match the channel to its forward.
        public const byte ACCEPTED = 0x8B;

        // Flag bit: the payload is raw-deflate compressed. None of the types above use
        // 0x40, so it composes with any of them.
        //
        // Why compress when WinRM already does: WinRM decompresses below the PowerShell
        // layer, so the client's WSMan receive thread still parses full-size CLIXML and
        // base64. Profiling showed that single thread saturated at 89% of a core and it is
        // the throughput ceiling, so what matters is fewer bytes reaching *it*, not fewer
        // bytes on the wire.
        public const byte COMPRESSED = 0x40;
    }

    // Compressed payloads carry their uncompressed length in the first four bytes, so the
    // receiver allocates the output exactly once instead of growing a MemoryStream and then
    // copying it out with ToArray.
    internal static class Zip
    {
        public static byte[] Deflate(byte[] data, int offset, int count)
        {
            MemoryStream ms = new MemoryStream();
            ms.WriteByte((byte)(count >> 24)); ms.WriteByte((byte)(count >> 16));
            ms.WriteByte((byte)(count >> 8)); ms.WriteByte((byte)count);
            using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Compress, true))
            {
                ds.Write(data, offset, count);
            }
            return ms.ToArray();
        }

        public static byte[] Inflate(byte[] data, int offset, int count)
        {
            if (count < 4) throw new InvalidDataException("compressed payload too short");
            int outLen = ((int)data[offset] << 24) | ((int)data[offset + 1] << 16)
                       | ((int)data[offset + 2] << 8) | data[offset + 3];
            if (outLen < 0 || outLen > (64 << 20)) throw new InvalidDataException("implausible inflated length " + outLen);

            byte[] result = new byte[outLen];
            MemoryStream src = new MemoryStream(data, offset + 4, count - 4, false);
            using (DeflateStream ds = new DeflateStream(src, CompressionMode.Decompress))
            {
                int got = 0;
                while (got < outLen)
                {
                    int n = ds.Read(result, got, outLen - got);
                    if (n <= 0) break;
                    got += n;
                }
                if (got != outLen) throw new InvalidDataException("short inflate: " + got + " of " + outLen);
            }
            return result;
        }
    }

    public static class Frame
    {
        // [type:1][channel:4][seq:4]. The sequence number exists so downstream frames can be
        // striped across several PSSessions and reassembled: each session has its own WSMan
        // receive thread, and that thread is the throughput ceiling.
        public const int HEADER = 9;

        private static void PutHeader(byte[] f, byte type, uint channel)
        {
            f[0] = type;
            f[1] = (byte)(channel >> 24); f[2] = (byte)(channel >> 16);
            f[3] = (byte)(channel >> 8); f[4] = (byte)channel;
            // seq is stamped later, by whoever routes the frame
        }

        public static byte[] Make(byte type, uint channel, byte[] payload)
        {
            int n = (payload == null) ? 0 : payload.Length;
            byte[] f = new byte[HEADER + n];
            PutHeader(f, type, channel);
            if (n > 0) Array.Copy(payload, 0, f, HEADER, n);
            return f;
        }

        public static byte[] Make(byte type, uint channel, byte[] payload, int offset, int count)
        {
            byte[] f = new byte[HEADER + count];
            PutHeader(f, type, channel);
            if (count > 0) Array.Copy(payload, offset, f, HEADER, count);
            return f;
        }

        public static void SetSeq(byte[] f, uint seq)
        {
            f[5] = (byte)(seq >> 24); f[6] = (byte)(seq >> 16);
            f[7] = (byte)(seq >> 8); f[8] = (byte)seq;
        }

        public static uint Seq(byte[] f)
        {
            return ((uint)f[5] << 24) | ((uint)f[6] << 16) | ((uint)f[7] << 8) | f[8];
        }

        public static byte[] MakeText(byte type, uint channel, string text)
        {
            return Make(type, channel, Encoding.UTF8.GetBytes(text == null ? "" : text));
        }

        public static byte[] MakeUInt32(byte type, uint channel, uint value)
        {
            byte[] p = new byte[4];
            p[0] = (byte)(value >> 24); p[1] = (byte)(value >> 16);
            p[2] = (byte)(value >> 8); p[3] = (byte)value;
            return Make(type, channel, p);
        }

        public static bool IsValid(byte[] f) { return f != null && f.Length >= HEADER; }
        public static byte Type(byte[] f) { return f[0]; }

        public static uint Channel(byte[] f)
        {
            return ((uint)f[1] << 24) | ((uint)f[2] << 16) | ((uint)f[3] << 8) | f[4];
        }

        public static int PayloadLength(byte[] f) { return f.Length - HEADER; }

        public static byte[] Payload(byte[] f)
        {
            byte[] p = new byte[f.Length - HEADER];
            Array.Copy(f, HEADER, p, 0, p.Length);
            return p;
        }

        public static string PayloadText(byte[] f)
        {
            return Encoding.UTF8.GetString(f, HEADER, f.Length - HEADER);
        }

        public static uint PayloadUInt32(byte[] f)
        {
            if (f.Length < HEADER + 4) return 0;
            return ((uint)f[HEADER] << 24) | ((uint)f[HEADER + 1] << 16)
                 | ((uint)f[HEADER + 2] << 8) | f[HEADER + 3];
        }
    }

    // Minimal reader/writer for structured frame payloads (pty, resize). Same big-endian
    // uint32 and length-prefixed string conventions as SSH, kept here so the agent stays
    // self-contained rather than depending on the engine's SshWriter/SshReader.
    internal sealed class SshLikeWriter
    {
        private readonly MemoryStream ms = new MemoryStream();

        public void UInt32(uint v)
        {
            ms.WriteByte((byte)(v >> 24)); ms.WriteByte((byte)(v >> 16));
            ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v);
        }

        // SFTP carries file sizes and offsets as 64-bit.
        public void UInt64(ulong v)
        {
            UInt32((uint)(v >> 32));
            UInt32((uint)v);
        }

        public void Byte(byte v) { ms.WriteByte(v); }

        public void Text(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s == null ? "" : s);
            UInt32((uint)b.Length);
            ms.Write(b, 0, b.Length);
        }

        // Length-prefixed binary, for SFTP's DATA payloads. Separate from Text because file
        // contents are not text and must not go through a UTF-8 round trip.
        public void Blob(byte[] b, int offset, int count)
        {
            UInt32((uint)count);
            if (count > 0) ms.Write(b, offset, count);
        }

        public void Raw(byte[] b, int offset, int count)
        {
            if (count > 0) ms.Write(b, offset, count);
        }

        public int Length { get { return (int)ms.Length; } }

        public byte[] ToArray() { return ms.ToArray(); }
    }

    internal sealed class SshLikeReader
    {
        private readonly byte[] b;
        private int p;

        public SshLikeReader(byte[] data, int offset) { b = data; p = offset; }

        public uint UInt32()
        {
            if (p + 4 > b.Length) return 0;
            uint v = ((uint)b[p] << 24) | ((uint)b[p + 1] << 16) | ((uint)b[p + 2] << 8) | b[p + 3];
            p += 4;
            return v;
        }

        public ulong UInt64()
        {
            ulong hi = UInt32();
            ulong lo = UInt32();
            return (hi << 32) | lo;
        }

        public byte Byte()
        {
            if (p >= b.Length) return 0;
            return b[p++];
        }

        public string Text()
        {
            int n = (int)UInt32();
            if (n < 0 || p + n > b.Length) return "";
            string s = Encoding.UTF8.GetString(b, p, n);
            p += n;
            return s;
        }

        // A length-prefixed blob left in place: returns its offset and advances past it, so an
        // SFTP WRITE payload can be handed to FileStream.Write without being copied out first.
        public bool Blob(out int offset, out int count)
        {
            offset = 0; count = 0;
            int n = (int)UInt32();
            if (n < 0 || p + n > b.Length) return false;
            offset = p; count = n;
            p += n;
            return true;
        }

        public int Position { get { return p; } }
        public bool Exhausted { get { return p >= b.Length; } }
        // Exposed so a Blob's range can be used in place, without copying it out.
        public byte[] Buffer { get { return b; } }
    }

    // ------------------------------------------------- producer/consumer byte stream
    //
    // Moved here from PwsshEngine.cs so this file can stand alone; the engine uses it for
    // the SSH byte stream, which genuinely is a stream rather than discrete messages.

    internal sealed class ByteChannel
    {
        private readonly Queue<byte[]> q = new Queue<byte[]>();
        private readonly object gate = new object();
        private byte[] cur;
        private int curPos;
        private bool closed;

        public void Write(byte[] data, int off, int count)
        {
            if (count <= 0) return;
            byte[] copy = new byte[count];
            Array.Copy(data, off, copy, 0, count);
            lock (gate)
            {
                if (closed) return;
                q.Enqueue(copy);
                Monitor.PulseAll(gate);
            }
        }

        public void Write(byte[] data) { Write(data, 0, data.Length); }

        // Hand over a buffer without copying it. The caller must never touch it again.
        // Used by the packet layer, which builds each frame fresh and immediately releases it.
        public void WriteOwned(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            lock (gate)
            {
                if (closed) return;
                q.Enqueue(data);
                Monitor.PulseAll(gate);
            }
        }

        public void Close() { lock (gate) { closed = true; Monitor.PulseAll(gate); } }
        public bool IsClosed { get { lock (gate) { return closed; } } }

        private bool HasBufferedNoLock()
        {
            return (cur != null && curPos < cur.Length) || q.Count > 0;
        }

        public void ReadExact(byte[] dst, int off, int n)
        {
            int got = 0;
            lock (gate)
            {
                while (got < n)
                {
                    if (cur == null || curPos >= cur.Length)
                    {
                        while (q.Count == 0 && !closed) Monitor.Wait(gate);
                        if (q.Count == 0 && closed) throw new EndOfStreamException("transport closed");
                        cur = q.Dequeue();
                        curPos = 0;
                    }
                    int take = Math.Min(n - got, cur.Length - curPos);
                    Array.Copy(cur, curPos, dst, off + got, take);
                    curPos += take;
                    got += take;
                }
            }
        }

        public byte ReadByte1()
        {
            byte[] one = new byte[1];
            ReadExact(one, 0, 1);
            return one[0];
        }

        // All currently buffered bytes. null if nothing arrived within the timeout.
        public byte[] TakeAll(int timeoutMs)
        {
            lock (gate)
            {
                if (!HasBufferedNoLock())
                {
                    if (closed) return null;
                    Monitor.Wait(gate, timeoutMs);
                    if (!HasBufferedNoLock()) return null;
                }
                // Fast path: one whole buffer pending, so hand it straight over. This is the
                // common case when the consumer keeps up, and it avoids copying every byte
                // through a MemoryStream on the way out.
                if ((cur == null || curPos >= cur.Length) && q.Count == 1)
                {
                    cur = null; curPos = 0;
                    return q.Dequeue();
                }
                MemoryStream ms = new MemoryStream();
                if (cur != null && curPos < cur.Length)
                {
                    ms.Write(cur, curPos, cur.Length - curPos);
                    cur = null; curPos = 0;
                }
                while (q.Count > 0)
                {
                    byte[] x = q.Dequeue();
                    ms.Write(x, 0, x.Length);
                }
                return ms.ToArray();
            }
        }
    }

    // ---------------------------------------------------------------- frame queue
    //
    // Distinct from ByteChannel: frames must stay discrete, so this never concatenates.

    internal sealed class FrameQueue
    {
        private readonly Queue<byte[]> q = new Queue<byte[]>();
        private readonly object gate = new object();
        private bool closed;

        public void Enqueue(byte[] frame)
        {
            lock (gate)
            {
                if (closed) return;
                q.Enqueue(frame);
                Monitor.PulseAll(gate);
            }
        }

        public void Close() { lock (gate) { closed = true; Monitor.PulseAll(gate); } }
        public bool IsClosed { get { lock (gate) { return closed; } } }

        public byte[] Take(int timeoutMs)
        {
            lock (gate)
            {
                if (q.Count == 0)
                {
                    if (closed) return null;
                    Monitor.Wait(gate, timeoutMs);
                    if (q.Count == 0) return null;
                }
                return q.Dequeue();
            }
        }
    }

    // ------------------------------------------------------------- inbound pump
    //
    // The remote must read pipeline input and write pipeline output at the same time, but
    // PowerShell is single-threaded and enumerating $input blocks. So input is drained on a
    // background thread here while the pipeline thread emits output.
    //
    // Typed as object/IEnumerator rather than PSObject deliberately: keeping
    // System.Management.Automation out of these references means the identical source
    // compiles for the client and the dev host too. Items are unwrapped reflectively.

    public static class PwsshPump
    {
        private static System.Reflection.PropertyInfo baseObjectProp;

        public static Thread StartInbound(object enumerator, IByteReceiver target)
        {
            System.Collections.IEnumerator e = (System.Collections.IEnumerator)enumerator;
            Thread t = new Thread(new ThreadStart(delegate
            {
                try
                {
                    while (e.MoveNext())
                    {
                        byte[] b = Unwrap(e.Current);
                        if (b != null && b.Length > 0) target.PushInbound(b);
                    }
                }
                catch (Exception)
                {
                    // Transport went away; treated as EOF below.
                }
                finally
                {
                    target.CloseInbound();
                }
            }));
            t.IsBackground = true;
            t.Name = "pwssh-inbound";
            t.Start();
            return t;
        }

        private static byte[] Unwrap(object o)
        {
            if (o == null) return null;
            byte[] direct = o as byte[];
            if (direct != null) return direct;
            if (baseObjectProp == null || baseObjectProp.DeclaringType != o.GetType())
            {
                baseObjectProp = o.GetType().GetProperty("BaseObject");
            }
            if (baseObjectProp == null) return null;
            return baseObjectProp.GetValue(o, null) as byte[];
        }
    }

    // -------------------------------------------------------------------- stripes
    //
    // Extra PSSessions ("mules") exist only to carry downstream frames. Each session has its
    // own WSMan receive thread on the client, and that thread -- not bandwidth, and not our
    // code -- is the throughput ceiling. Measured downstream on incompressible data:
    // 1 session 0.43 MiB/s, 2 sessions 1.18, 4 sessions 1.40.
    //
    // A mule runs in a different wsmprovhost process from the agent that owns the child, so
    // frames reach it over a local named pipe. Mules are receive-only: everything the client
    // sends still goes to the primary session, which keeps ordering simple.

    internal sealed class PipeSink
    {
        private readonly FrameQueue q = new FrameQueue();
        private readonly PwsshAgentHost host;
        private readonly string pipeName;
        private volatile bool connected;

        public PipeSink(PwsshAgentHost h, string name) { host = h; pipeName = name; }
        public bool Connected { get { return connected; } }
        public void Enqueue(byte[] frame) { q.Enqueue(frame); }
        public void Close() { q.Close(); }

        public void Start()
        {
            Thread t = new Thread(new ThreadStart(delegate
            {
                try
                {
                    using (NamedPipeServerStream srv = new NamedPipeServerStream(
                        pipeName, PipeDirection.Out, 1, PipeTransmissionMode.Byte,
                        PipeOptions.None, 1 << 16, 1 << 16))
                    {
                        srv.WaitForConnection();
                        connected = true;
                        host.Log("stripe connected: " + pipeName);

                        byte[] len = new byte[4];
                        while (true)
                        {
                            byte[] f = q.Take(200);
                            if (f == null)
                            {
                                if (host.Finished || q.IsClosed) break;
                                continue;
                            }
                            len[0] = (byte)(f.Length >> 24); len[1] = (byte)(f.Length >> 16);
                            len[2] = (byte)(f.Length >> 8); len[3] = (byte)f.Length;
                            srv.Write(len, 0, 4);
                            srv.Write(f, 0, f.Length);
                        }
                        srv.Flush();
                    }
                }
                catch (Exception ex)
                {
                    host.Log("stripe " + pipeName + " ended: " + ex.Message);
                }
                finally { connected = false; }
            }));
            t.IsBackground = true;
            t.Name = "pwssh-stripe";
            t.Start();
        }
    }

    // Frames arrive from several sessions, each FIFO but interleaved. Delivery must follow
    // the sequence numbers, or SSH channel data would be reordered.
    public sealed class FrameResequencer
    {
        private readonly Dictionary<uint, byte[]> pending = new Dictionary<uint, byte[]>();
        private readonly object gate = new object();
        private uint next;

        public int Pending { get { lock (gate) { return pending.Count; } } }

        // Returns the frames that are now deliverable, in order. Usually one; occasionally
        // several, when a gap fills in.
        public List<byte[]> Accept(byte[] frame)
        {
            List<byte[]> ready = new List<byte[]>();
            lock (gate)
            {
                uint s = Frame.Seq(frame);
                if (s == next)
                {
                    ready.Add(frame);
                    next++;
                    while (pending.ContainsKey(next))
                    {
                        ready.Add(pending[next]);
                        pending.Remove(next);
                        next++;
                    }
                }
                else if (s > next)
                {
                    pending[s] = frame;
                }
                // s < next would be a duplicate; drop it.
            }
            return ready;
        }
    }

    // -------------------------------------------------------------- client contracts

    public interface IPwsshAgent
    {
        void Attach(IPwsshChannelSink sink);
        void Exec(uint channel, string command);
        void Shell(uint channel);
        // A subsystem channel. No round trip is available to ask whether the remote supports
        // one, so the engine decides locally -- see SessionChannel.StartSubsystem.
        void Subsystem(uint channel, string name);
        // direct-tcpip: the result arrives asynchronously via IPwsshChannelSink, because
        // blocking the protocol loop on a remote connect would stall every other channel.
        void Connect(uint channel, string host, int port);
        // Remote forwarding. Results arrive asynchronously via IPwsshChannelSink.
        void Listen(uint forwardId, string bindAddress, int port);
        void Unlisten(uint forwardId);
        void AcceptOk(uint channel);
        void RequestPty(uint channel, uint cols, uint rows, string term);
        void Resize(uint channel, uint cols, uint rows);
        void Signal(uint channel, string name);
        void SendStdin(uint channel, byte[] data);
        void CloseStdin(uint channel);
        void CloseChannel(uint channel);
        void GrantWindow(uint channel, uint bytes);
        // Whether the remote can provide a real terminal. Reported in HELLO, so pty-req can
        // be answered without an extra round trip.
        bool RemoteSupportsPty { get; }
        // Blocks for the agent's HELLO. The local SSH handshake is instant now, so userauth
        // can arrive before HELLO has made the round trip; blocking here lets session setup
        // and the handshake overlap instead of serialising.
        string WaitForRemoteUser(int timeoutMs);
    }

    public interface IPwsshChannelSink
    {
        // Takes a range rather than an array so the frame buffer can be passed straight
        // through: the client owns it exclusively, so copying the payload out is waste.
        void OnData(uint channel, byte[] buffer, int offset, int count, bool stderr);
        void OnExit(uint channel, uint status);
        void OnClose(uint channel);
        void OnConnectResult(uint channel, bool ok, string message);
        void OnListenResult(uint forwardId, bool ok, int boundPort, string message);
        void OnAccepted(uint channel, uint forwardId, int boundPort, string originAddress, int originPort);
        // Carries the channel the failure belongs to, so the engine can close it. Without that
        // the client keeps a channel open waiting for output that will never come, which looks
        // exactly like slowness on a link where seconds are normal.
        void OnAgentError(uint channel, string message);
    }

    // ---------------------------------------------------------- agent-side channel kinds
    //
    // What every channel kind on the remote has in common: bytes go in, credit is returned,
    // and it can be shut down. The kinds differ entirely in what they do with the bytes -- a
    // child process's stdin, a socket, or SFTP requests -- so this is all they share.
    //
    // Having it lets PwsshAgentHost keep one map instead of one per kind, which matters
    // because DATA/EOF/CLOSE/WINDOW apply to all of them: without it, adding a kind means
    // remembering to extend four separate lookups.
    internal interface IAgentStream
    {
        // The frame buffer is passed as a range, not copied. Runs on the frame dispatch
        // thread, so an implementation must not block: doing so stalls every other channel.
        void Write(byte[] frame, int offset, int count);
        void CloseWrite();
        void AddCredit(uint add);
        void Kill();
    }

    // ------------------------------------------------------------------ client proxy

    public sealed class PwsshAgentProxy : IPwsshAgent, IByteReceiver
    {
        private readonly FrameQueue outbound = new FrameQueue();
        private readonly object helloGate = new object();
        private IPwsshChannelSink sink;
        private string remoteUser;
        private volatile bool remotePty;
        private volatile bool inboundClosed;

        public bool RemoteSupportsPty { get { return remotePty; } }

        public void Attach(IPwsshChannelSink s)
        {
            sink = s;
            StartKeepAlive();
        }

        public bool InboundClosed { get { return inboundClosed; } }

        // Keepalive interval. The agent times out at four times this, so a couple of lost or
        // delayed pings are harmless.
        public static int KeepAliveMs = 30000;
        private int keepAliveStarted;

        // ssh TerminateProcesses its ProxyCommand on exit, so this process usually dies without
        // a chance to tell the remote anything. The agent therefore cannot distinguish an idle
        // client from a dead one by silence alone -- hence a ping while we are alive, and the
        // absence of one being what lets the agent give up and release its resources.
        private void StartKeepAlive()
        {
            if (KeepAliveMs <= 0) return;
            if (Interlocked.CompareExchange(ref keepAliveStarted, 1, 0) != 0) return;
            Thread t = new Thread(new ThreadStart(delegate
            {
                while (!inboundClosed)
                {
                    Thread.Sleep(KeepAliveMs);
                    if (inboundClosed) return;
                    try { outbound.Enqueue(Frame.Make(FrameType.PING, 0, null)); }
                    catch (Exception) { return; }
                }
            }));
            t.IsBackground = true;
            t.Name = "pwssh-keepalive";
            t.Start();
        }

        // Transport side: drain frames to send to the remote.
        public byte[] TakeOutboundFrame(int timeoutMs) { return outbound.Take(timeoutMs); }

        public void PushInbound(byte[] frame)
        {
            if (!Frame.IsValid(frame)) return;
            byte raw = Frame.Type(frame);
            bool compressed = (raw & FrameType.COMPRESSED) != 0;
            byte type = (byte)(raw & ~FrameType.COMPRESSED);
            uint ch = Frame.Channel(frame);

            switch (type)
            {
                case FrameType.OUT:
                case FrameType.ERR:
                    if (sink != null)
                    {
                        bool isErr = (type == FrameType.ERR);
                        if (compressed)
                        {
                            byte[] u = Zip.Inflate(frame, Frame.HEADER, Frame.PayloadLength(frame));
                            sink.OnData(ch, u, 0, u.Length, isErr);
                        }
                        else
                        {
                            // No copy: hand the frame buffer through as a range.
                            sink.OnData(ch, frame, Frame.HEADER, Frame.PayloadLength(frame), isErr);
                        }
                    }
                    break;
                case FrameType.EXIT:
                    if (sink != null) sink.OnExit(ch, Frame.PayloadUInt32(frame));
                    break;
                case FrameType.DONE:
                    if (sink != null) sink.OnClose(ch);
                    break;
                case FrameType.HELLO:
                    lock (helloGate)
                    {
                        // "user=kb;conpty=1"
                        string[] parts = Frame.PayloadText(frame).Split(';');
                        for (int i = 0; i < parts.Length; i++)
                        {
                            int eq = parts[i].IndexOf('=');
                            if (eq <= 0) continue;
                            string k = parts[i].Substring(0, eq);
                            string v = parts[i].Substring(eq + 1);
                            if (k == "user") remoteUser = v;
                            else if (k == "conpty") remotePty = (v == "1");
                        }
                        Monitor.PulseAll(helloGate);
                    }
                    break;
                case FrameType.CONNECT_OK:
                    if (sink != null) sink.OnConnectResult(ch, true, null);
                    break;
                case FrameType.CONNECT_FAIL:
                    if (sink != null) sink.OnConnectResult(ch, false, Frame.PayloadText(frame));
                    break;
                case FrameType.LISTEN_OK:
                    if (sink != null) sink.OnListenResult(ch, true, (int)Frame.PayloadUInt32(frame), null);
                    break;
                case FrameType.LISTEN_FAIL:
                    if (sink != null) sink.OnListenResult(ch, false, 0, Frame.PayloadText(frame));
                    break;
                case FrameType.ACCEPTED:
                    if (sink != null)
                    {
                        SshLikeReader ar = new SshLikeReader(frame, Frame.HEADER);
                        uint fwd = ar.UInt32();
                        int bPort = (int)ar.UInt32();
                        string oAddr = ar.Text();
                        int oPort = (int)ar.UInt32();
                        sink.OnAccepted(ch, fwd, bPort, oAddr, oPort);
                    }
                    break;
                case FrameType.FAIL:
                    if (sink != null) sink.OnAgentError(ch, Frame.PayloadText(frame));
                    break;
            }
        }

        public void CloseInbound()
        {
            inboundClosed = true;
            outbound.Close();
            lock (helloGate) { Monitor.PulseAll(helloGate); }
        }

        public string WaitForRemoteUser(int timeoutMs)
        {
            lock (helloGate)
            {
                if (remoteUser != null) return remoteUser;
                int waited = 0;
                while (remoteUser == null && !inboundClosed && waited < timeoutMs)
                {
                    Monitor.Wait(helloGate, 100);
                    waited += 100;
                }
                return remoteUser;
            }
        }

        public void Exec(uint channel, string command)
        {
            outbound.Enqueue(Frame.MakeText(FrameType.EXEC, channel, command));
        }

        public void Shell(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.SHELL, channel, null));
        }

        public void Subsystem(uint channel, string name)
        {
            outbound.Enqueue(Frame.MakeText(FrameType.SUBSYSTEM, channel, name));
        }

        public void Connect(uint channel, string host, int port)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.Text(host); w.UInt32((uint)port);
            outbound.Enqueue(Frame.Make(FrameType.CONNECT, channel, w.ToArray()));
        }

        public void Listen(uint forwardId, string bindAddress, int port)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.Text(bindAddress); w.UInt32((uint)port);
            outbound.Enqueue(Frame.Make(FrameType.LISTEN, forwardId, w.ToArray()));
        }

        public void Unlisten(uint forwardId)
        {
            outbound.Enqueue(Frame.Make(FrameType.UNLISTEN, forwardId, null));
        }

        public void AcceptOk(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.ACCEPT_OK, channel, null));
        }

        public void RequestPty(uint channel, uint cols, uint rows, string term)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.UInt32(cols); w.UInt32(rows); w.Text(term);
            outbound.Enqueue(Frame.Make(FrameType.PTY, channel, w.ToArray()));
        }

        public void Resize(uint channel, uint cols, uint rows)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.UInt32(cols); w.UInt32(rows);
            outbound.Enqueue(Frame.Make(FrameType.RESIZE, channel, w.ToArray()));
        }

        public void Signal(uint channel, string name)
        {
            outbound.Enqueue(Frame.MakeText(FrameType.SIGNAL, channel, name));
        }

        public void SendStdin(uint channel, byte[] data)
        {
            outbound.Enqueue(Frame.Make(FrameType.DATA, channel, data));
        }

        public void CloseStdin(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.EOF, channel, null));
        }

        public void CloseChannel(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.CLOSE, channel, null));
        }

        public void GrantWindow(uint channel, uint bytes)
        {
            outbound.Enqueue(Frame.MakeUInt32(FrameType.WINDOW, channel, bytes));
        }
    }

    // -------------------------------------------------------------------- agent host

    public sealed class PwsshAgentHost : IByteReceiver
    {
        // Granted at EXEC and topped up by WINDOW frames. Each WINDOW frame costs a full
        // WinRM turnaround, so a small window stalls bulk output once per round trip -- but
        // the credit is also what bounds how much the agent can push into the client's memory
        // before it must wait. Tunable so the trade-off can be measured rather than guessed.
        public static uint InitialCredit = 32 * 1024 * 1024;

        private readonly FrameQueue outbound = new FrameQueue();
        // One map for every channel kind. The four frames that apply to all of them -- DATA,
        // EOF, CLOSE, WINDOW -- would otherwise each need a lookup per kind, which is four
        // places to forget one every time a kind is added.
        private readonly Dictionary<uint, IAgentStream> streams = new Dictionary<uint, IAgentStream>();
        private readonly object chanGate = new object();
        private readonly Queue<string> logQ = new Queue<string>();

        private volatile bool finished;
        private int lastInboundTick = Environment.TickCount;

        // How long silence from the client is tolerated before giving up and releasing
        // everything; 0 disables. This is the only thing that ends an orphaned agent: ssh
        // TerminateProcesses its ProxyCommand, so the client normally dies without completing
        // the pipeline, and the remote would otherwise hold its child processes and any -R
        // listener until WinRM reclaimed the shell.
        //
        // It can be this short only because the client sends PING frames (see
        // PwsshAgentProxy.StartKeepAlive): before that, silence could equally mean an idle
        // interactive session, and a timeout of 120 s would have killed one after two minutes
        // of the user not typing.
        public int InactivityTimeoutSeconds = 120;

        // Testing hook: forces the no-ConPTY path on a remote that does have it, so the
        // graceful-degradation behaviour can be exercised rather than assumed.
        public static bool DisableConPty;

        // Testing hook: turns off read coalescing in the output pumps, so its effect can be
        // measured by interleaved A/B rather than asserted.
        public static bool DisableCoalescing;

        // The shell, matching what Windows OpenSSH runs by default.
        public static string ShellPath()
        {
            string s = Environment.GetEnvironmentVariable("ComSpec");
            if (string.IsNullOrEmpty(s)) s = "cmd.exe";
            return s;
        }

        // pty-req arrives before shell/exec, so the parameters wait here for the channel.
        private readonly Dictionary<uint, PtyRequest> pendingPty = new Dictionary<uint, PtyRequest>();

        // Forwarded connections get their own, much smaller window: a SOCKS client can have
        // dozens open at once, and the session default (32 MiB) each would be absurd. At a
        // ~0.5 s round trip 2 MiB still sustains several MiB/s per channel.
        public static uint InitialTcpCredit = 2 * 1024 * 1024;

        // Listeners are not channels -- nothing writes bytes to one -- so they keep their own map.
        private readonly Dictionary<uint, AgentListener> listeners = new Dictionary<uint, AgentListener>();

        // Channel ids for connections WE accept come from the top of the space; the engine
        // allocates upward from 0. Two allocators sharing one space would eventually collide,
        // and the symptom would be data surfacing on the wrong channel.
        private const uint ACCEPTED_ID_BASE = 0x80000000;
        private uint nextAccepted = ACCEPTED_ID_BASE;

        private AgentTcpChannel FindTcp(uint ch) { return FindStream(ch) as AgentTcpChannel; }

        public bool Finished { get { return finished; } }

        public void Start()
        {
            string user;
            try { user = CurrentAccountName(); }
            catch (Exception ex) { user = ""; Log("cannot resolve current user: " + ex.Message); }

            // Capabilities travel with HELLO so the client can answer pty-req immediately.
            // Asking later would cost a round trip on every interactive connection, and the
            // answer has to be known before the reply is sent.
            bool conpty = !DisableConPty && ConPtySession.IsAvailable();
            string hello = "user=" + user + ";conpty=" + (conpty ? "1" : "0");

            // Must go through Send: every frame needs a sequence number, or it collides with
            // the first sequenced frame and the client's resequencer drops one as a duplicate.
            Send(Frame.MakeText(FrameType.HELLO, 0, hello));
            Log("agent ready as '" + user + "', conpty=" + conpty);

            if (InactivityTimeoutSeconds > 0)
            {
                Thread wd = new Thread(new ThreadStart(Watchdog));
                wd.IsBackground = true;
                wd.Name = "pwssh-agent-watchdog";
                wd.Start();
            }
        }

        public static string CurrentAccountName()
        {
            string full = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            int bs = full.LastIndexOf('\\');
            if (bs >= 0) return full.Substring(bs + 1);
            return full;
        }

        private void Watchdog()
        {
            int limitMs = InactivityTimeoutSeconds * 1000;
            while (!finished)
            {
                Thread.Sleep(5000);
                if (finished) return;
                if (unchecked(Environment.TickCount - lastInboundTick) > limitMs)
                {
                    Log("no inbound frames for " + InactivityTimeoutSeconds + "s; shutting down");
                    Stop();
                    return;
                }
            }
        }

        public byte[] TakeOutboundFrame(int timeoutMs) { return outbound.Take(timeoutMs); }

        private readonly List<PipeSink> stripes = new List<PipeSink>();
        private int seqCounter = -1;
        private int roundRobin = -1;

        // Called before Start(). Creates one named pipe per mule session; the client starts
        // the mules, which connect and forward whatever arrives to their own pipeline output.
        public void SetStripes(string pipePrefix, int count)
        {
            for (int i = 0; i < count; i++)
            {
                PipeSink p = new PipeSink(this, pipePrefix + "-" + i);
                stripes.Add(p);
                p.Start();
            }
            if (count > 0) Log("striping downstream across " + (count + 1) + " sessions");
        }

        internal void Send(byte[] frame)
        {
            // Stamp the order here, where it is serialised across all producing threads.
            Frame.SetSeq(frame, (uint)Interlocked.Increment(ref seqCounter));

            if (stripes.Count == 0) { outbound.Enqueue(frame); return; }

            int slot = Interlocked.Increment(ref roundRobin) % (stripes.Count + 1);
            if (slot == 0) { outbound.Enqueue(frame); return; }

            PipeSink sink = stripes[slot - 1];
            // Not connected yet (or gone): fall back to the primary session. Sequence numbers
            // mean the client reassembles correctly either way.
            if (sink.Connected) sink.Enqueue(frame); else outbound.Enqueue(frame);
        }

        public string[] DrainLog()
        {
            lock (logQ)
            {
                string[] a = logQ.ToArray();
                logQ.Clear();
                return a;
            }
        }

        internal void Log(string m)
        {
            lock (logQ)
            {
                if (logQ.Count > 500) logQ.Dequeue();
                logQ.Enqueue(m);
            }
        }

        public void PushInbound(byte[] frame)
        {
            lastInboundTick = Environment.TickCount;
            if (!Frame.IsValid(frame))
            {
                Log("discarding runt frame");
                return;
            }

            byte type = Frame.Type(frame);
            uint ch = Frame.Channel(frame);

            try
            {
                switch (type)
                {
                    case FrameType.EXEC:
                        StartChannel(ch, ShellPath() + " /c " + Frame.PayloadText(frame));
                        break;

                    case FrameType.SHELL:
                        StartChannel(ch, ShellPath());
                        break;

                    case FrameType.PTY:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            PtyRequest req = new PtyRequest();
                            // A client with no local terminal of its own sends 0x0 -- ssh -tt
                            // with redirected stdin does exactly that -- and a pseudoconsole
                            // with no cells has nothing to render. ConPtySession substitutes a
                            // default of its own, but do it here too so the size the agent
                            // reports and the size it uses cannot disagree.
                            req.Cols = PtyRequest.Clamp(r.UInt32(), 80);
                            req.Rows = PtyRequest.Clamp(r.UInt32(), 24);
                            req.Term = r.Text();
                            lock (chanGate) { pendingPty[ch] = req; }
                            Log("pty requested on channel " + ch + ": " + req.Cols + "x" + req.Rows + " " + req.Term);
                        }
                        break;

                    case FrameType.RESIZE:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            uint cols = PtyRequest.Clamp(r.UInt32(), 80);
                            uint rows = PtyRequest.Clamp(r.UInt32(), 24);
                            AgentChannel c = Find(ch);
                            if (c != null) c.Resize(cols, rows);
                        }
                        break;

                    case FrameType.SIGNAL:
                        {
                            AgentChannel c = Find(ch);
                            Log("signal " + Frame.PayloadText(frame) + " on channel " + ch);
                            if (c != null) c.Kill();
                        }
                        break;

                    // Nothing to do: arriving at all is the whole message, and the inbound
                    // timestamp that keeps the watchdog quiet has already been refreshed.
                    case FrameType.PING:
                        break;

                    case FrameType.SUBSYSTEM:
                        {
                            // The engine has already refused anything but "sftp", so the else
                            // is belt and braces rather than a real branch.
                            string name = Frame.PayloadText(frame);
                            if (name == "sftp") StartSftp(ch);
                            else
                            {
                                Log("unknown subsystem on channel " + ch + ": " + name);
                                Send(Frame.MakeText(FrameType.FAIL, ch, "unknown subsystem: " + name));
                            }
                        }
                        break;

                    case FrameType.CONNECT:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            string target = r.Text();
                            int port = (int)r.UInt32();
                            AgentTcpChannel c = new AgentTcpChannel(this, ch);
                            lock (chanGate) { streams[ch] = c; }
                            c.BeginConnect(target, port);
                        }
                        break;

                    case FrameType.LISTEN:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            string addr = r.Text();
                            int port = (int)r.UInt32();
                            AgentListener l = new AgentListener(this, ch);
                            string err = l.Bind(addr, port);
                            if (err == null)
                            {
                                lock (chanGate) { listeners[ch] = l; }
                                Log("listening on " + addr + ":" + l.BoundPort + " (forward " + ch + ")");
                                Send(Frame.MakeUInt32(FrameType.LISTEN_OK, ch, (uint)l.BoundPort));
                            }
                            else
                            {
                                Log("bind " + addr + ":" + port + " failed: " + err);
                                Send(Frame.MakeText(FrameType.LISTEN_FAIL, ch, err));
                            }
                        }
                        break;

                    case FrameType.UNLISTEN:
                        {
                            AgentListener l = null;
                            lock (chanGate)
                            {
                                if (listeners.TryGetValue(ch, out l)) listeners.Remove(ch);
                            }
                            if (l != null) { l.Stop(); Log("forward " + ch + " cancelled"); }
                        }
                        break;

                    case FrameType.ACCEPT_OK:
                        {
                            AgentTcpChannel t = FindTcp(ch);
                            if (t != null) t.StartPumping();
                        }
                        break;

                    // The remaining channel frames apply to every kind, which is what the
                    // IAgentStream map is for.
                    case FrameType.DATA:
                        {
                            IAgentStream s = FindStream(ch);
                            if (s != null) s.Write(frame, Frame.HEADER, Frame.PayloadLength(frame));
                        }
                        break;

                    case FrameType.EOF:
                        {
                            IAgentStream s = FindStream(ch);
                            if (s != null) s.CloseWrite();
                        }
                        break;

                    case FrameType.CLOSE:
                        {
                            IAgentStream s = FindStream(ch);
                            // Forget explicitly: a process-backed channel drops itself when the
                            // child exits, but an accepted -R channel the client refused was
                            // never pumping and nothing else would ever drop it.
                            if (s != null) { s.Kill(); Forget(ch); }
                        }
                        break;

                    case FrameType.WINDOW:
                        {
                            IAgentStream s = FindStream(ch);
                            if (s != null) s.AddCredit(Frame.PayloadUInt32(frame));
                        }
                        break;

                    default:
                        Log("unexpected frame type 0x" + type.ToString("X2"));
                        break;
                }
            }
            catch (Exception ex)
            {
                Log("frame 0x" + type.ToString("X2") + " failed: " + ex.Message);
                Send(Frame.MakeText(FrameType.FAIL, ch, ex.Message));
            }
        }

        public void CloseInbound()
        {
            Log("client closed the link");
            Stop();
        }

        public void Stop()
        {
            finished = true;
            lock (chanGate)
            {
                // Covers every kind at once, which is what makes SFTP's file handles release
                // here too rather than needing their own line.
                foreach (IAgentStream s in streams.Values) { try { s.Kill(); } catch { } }
                // Must happen here: a surviving listener keeps the port bound on the remote
                // until wsmprovhost exits, which the inactivity watchdog only bounds loosely.
                foreach (AgentListener l in listeners.Values) { try { l.Stop(); } catch { } }
                listeners.Clear();
            }
            foreach (PipeSink p in stripes) { try { p.Close(); } catch { } }
            outbound.Close();
        }

        private IAgentStream FindStream(uint ch)
        {
            lock (chanGate)
            {
                IAgentStream s;
                if (streams.TryGetValue(ch, out s)) return s;
                return null;
            }
        }

        // Only for the frames that are specific to a process-backed channel (RESIZE, SIGNAL);
        // everything shared goes through FindStream.
        private AgentChannel Find(uint ch) { return FindStream(ch) as AgentChannel; }

        private void StartChannel(uint ch, string command)
        {
            AgentChannel c = new AgentChannel(this, ch);
            lock (chanGate)
            {
                if (streams.ContainsKey(ch))
                {
                    Send(Frame.MakeText(FrameType.FAIL, ch, "channel already in use"));
                    return;
                }
                streams[ch] = c;
            }
            PtyRequest req = null;
            lock (chanGate)
            {
                if (pendingPty.TryGetValue(ch, out req)) pendingPty.Remove(ch);
            }

            Log("start on channel " + ch + (req != null ? " (pty): " : ": ") + command);
            if (!c.Start(command, req))
            {
                Send(Frame.MakeText(FrameType.FAIL, ch, "could not start command"));
                Forget(ch);
            }
        }

        private void StartSftp(uint ch)
        {
            AgentSftpChannel c = new AgentSftpChannel(this, ch);
            lock (chanGate)
            {
                if (streams.ContainsKey(ch))
                {
                    Send(Frame.MakeText(FrameType.FAIL, ch, "channel already in use"));
                    return;
                }
                streams[ch] = c;
            }
            Log("sftp subsystem on channel " + ch);
            c.Start();
        }

        internal void Forget(uint ch)
        {
            lock (chanGate) { streams.Remove(ch); }
        }

        // A connection arrived on a -R listener. Park it against a fresh channel id and tell
        // the client, which opens a forwarded-tcpip channel back to us; pumping starts only
        // once that channel is confirmed via ACCEPT_OK.
        internal void OnAccepted(AgentListener l, Socket accepted)
        {
            uint id;
            AgentTcpChannel c;
            lock (chanGate)
            {
                id = nextAccepted++;
                c = new AgentTcpChannel(this, id);
                streams[id] = c;
            }
            c.Adopt(accepted);

            string origAddr = "unknown";
            int origPort = 0;
            try
            {
                IPEndPoint rep = accepted.RemoteEndPoint as IPEndPoint;
                if (rep != null) { origAddr = rep.Address.ToString(); origPort = rep.Port; }
            }
            catch { }

            Log("accepted " + origAddr + ":" + origPort + " on forward port " + l.BoundPort + " as channel " + id);

            SshLikeWriter w = new SshLikeWriter();
            w.UInt32(l.ForwardId);
            w.UInt32((uint)l.BoundPort);
            w.Text(origAddr);
            w.UInt32((uint)origPort);
            Send(Frame.Make(FrameType.ACCEPTED, id, w.ToArray()));
        }
    }

    // ------------------------------------------------------------------- ConPTY
    //
    // A pty-backed channel cannot use System.Diagnostics.Process: the pseudoconsole is
    // attached through a PROC_THREAD_ATTRIBUTE on STARTUPINFOEX, which Process does not
    // expose. Hence raw CreateProcess.
    //
    // CreatePseudoConsole exists from Windows 10 1809 / Server 2019 only, so availability is
    // probed at startup and reported to the client, which then knows whether it may accept
    // pty-req. Verified working inside wsmprovhost in session 0, which has no console.

    internal sealed class PtyRequest
    {
        public uint Cols;
        public uint Rows;
        public string Term;

        // 0 means "the client does not know"; anything absurd would be a bad resize too.
        public static uint Clamp(uint value, uint fallback)
        {
            if (value == 0) return fallback;
            return value > 9999 ? 9999 : value;
        }
    }

    // Kills the whole process tree when closed. A shell spawns children, and
    // Process.Kill(true) does not exist on .NET Framework 4.8, so without this a terminated
    // shell would leave its children running on the remote.
    internal sealed class JobObject : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
            public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
            public uint LimitFlags;
            public IntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public IntPtr Affinity;
            public uint PriorityClass, SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public IntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
        }

        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
        private const int JobObjectExtendedLimitInformation = 9;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateJobObject(IntPtr sa, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint len);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);

        private IntPtr handle;

        public JobObject()
        {
            handle = CreateJobObject(IntPtr.Zero, null);
            if (handle == IntPtr.Zero) return;

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int len = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr p = Marshal.AllocHGlobal(len);
            try
            {
                Marshal.StructureToPtr(info, p, false);
                SetInformationJobObject(handle, JobObjectExtendedLimitInformation, p, (uint)len);
            }
            finally { Marshal.FreeHGlobal(p); }
        }

        public bool Assign(IntPtr process)
        {
            if (handle == IntPtr.Zero) return false;
            return AssignProcessToJobObject(handle, process);
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; }
        }
    }

    // How many bytes are already sitting in a pipe, without blocking. Works on anonymous
    // pipes, which is what both ConPTY output and redirected stdout are.
    internal static class PipePeek
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool PeekNamedPipe(IntPtr hPipe, IntPtr buffer, uint bufferSize,
            IntPtr bytesRead, out uint totalAvail, IntPtr bytesLeftThisMessage);

        public static uint Available(IntPtr handle)
        {
            if (handle == IntPtr.Zero) return 0;
            uint avail;
            if (!PeekNamedPipe(handle, IntPtr.Zero, 0, IntPtr.Zero, out avail, IntPtr.Zero)) return 0;
            return avail;
        }

        // Must be called before the stream has buffered anything: reading FileStream's
        // SafeFileHandle flushes it, and a pipe cannot be repositioned.
        public static IntPtr HandleOf(Stream s)
        {
            try
            {
                FileStream fs = s as FileStream;
                if (fs != null) return fs.SafeFileHandle.DangerousGetHandle();
            }
            catch (Exception) { }
            return IntPtr.Zero;
        }
    }

    internal sealed class ConPtySession : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct COORD { public short X; public short Y; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb; public string lpReserved; public string lpDesktop; public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private static readonly IntPtr PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = (IntPtr)0x00020016;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int CreatePseudoConsole(COORD size, IntPtr hIn, IntPtr hOut, uint flags, out IntPtr phPC);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int ResizePseudoConsole(IntPtr hPC, COORD size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void ClosePseudoConsole(IntPtr hPC);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr hRead, out IntPtr hWrite, IntPtr sa, int size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcess(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit,
            uint flags, IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value,
            IntPtr size, IntPtr prev, IntPtr ret);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr h, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr h, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr h, uint code);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr mod, string name);
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string name);

        private static int available = -1;   // -1 unknown, 0 no, 1 yes

        // Probes once: the export must exist AND a pseudoconsole must actually be creatable.
        // The second half matters because this runs inside a service-session host with no
        // console of its own.
        public static bool IsAvailable()
        {
            if (available >= 0) return available == 1;
            available = 0;
            try
            {
                IntPtr k = GetModuleHandle("kernel32.dll");
                if (k == IntPtr.Zero || GetProcAddress(k, "CreatePseudoConsole") == IntPtr.Zero) return false;

                IntPtr inR, inW, outR, outW, hPC;
                if (!CreatePipe(out inR, out inW, IntPtr.Zero, 0)) return false;
                if (!CreatePipe(out outR, out outW, IntPtr.Zero, 0))
                {
                    CloseHandle(inR); CloseHandle(inW); return false;
                }
                COORD sz; sz.X = 1; sz.Y = 1;
                int hr = CreatePseudoConsole(sz, inR, outW, 0, out hPC);
                CloseHandle(inR); CloseHandle(outW);
                if (hr == 0) { ClosePseudoConsole(hPC); available = 1; }
                CloseHandle(inW); CloseHandle(outR);
            }
            catch (Exception) { available = 0; }
            return available == 1;
        }

        private IntPtr hPC = IntPtr.Zero;
        private IntPtr hProcess = IntPtr.Zero;
        private IntPtr hThread = IntPtr.Zero;
        private IntPtr inWrite = IntPtr.Zero;
        private readonly JobObject job = new JobObject();

        public Stream Output;         // read: everything the terminal emits
        public Stream Input;          // write: keystrokes
        public IntPtr OutputHandle;   // for peeking how much is pending

        public bool Start(string commandLine, uint cols, uint rows)
        {
            IntPtr inR, inW, outR, outW;
            if (!CreatePipe(out inR, out inW, IntPtr.Zero, 0)) return false;
            if (!CreatePipe(out outR, out outW, IntPtr.Zero, 0))
            {
                CloseHandle(inR); CloseHandle(inW); return false;
            }

            COORD sz;
            sz.X = (short)(cols == 0 ? 80 : cols);
            sz.Y = (short)(rows == 0 ? 25 : rows);
            int hr = CreatePseudoConsole(sz, inR, outW, 0, out hPC);
            CloseHandle(inR); CloseHandle(outW);      // the pseudoconsole duplicated them
            if (hr != 0)
            {
                CloseHandle(inW); CloseHandle(outR);
                return false;
            }

            IntPtr attrList = IntPtr.Zero;
            PROCESS_INFORMATION pi;
            try
            {
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                attrList = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(attrList, 1, 0, ref size)) return false;
                if (!UpdateProcThreadAttribute(attrList, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hPC,
                        (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero)) return false;

                STARTUPINFOEX si = new STARTUPINFOEX();
                si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                si.lpAttributeList = attrList;

                if (!CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, false,
                        EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref si, out pi))
                    return false;
            }
            finally
            {
                if (attrList != IntPtr.Zero) { DeleteProcThreadAttributeList(attrList); Marshal.FreeHGlobal(attrList); }
            }

            hProcess = pi.hProcess;
            hThread = pi.hThread;
            inWrite = inW;
            job.Assign(hProcess);

            OutputHandle = outR;
            // Unbuffered: the pump peeks the pipe directly to decide whether to keep reading,
            // and a FileStream read buffer would make that peek disagree with what is pending.
            Output = new FileStream(new SafeFileHandle(outR, true), FileAccess.Read, 1, false);
            Input = new FileStream(new SafeFileHandle(inW, false), FileAccess.Write, 1, false);
            return true;
        }

        public void Resize(uint cols, uint rows)
        {
            if (hPC == IntPtr.Zero) return;
            COORD sz;
            sz.X = (short)(cols == 0 ? 80 : cols);
            sz.Y = (short)(rows == 0 ? 25 : rows);
            ResizePseudoConsole(hPC, sz);
        }

        public void WaitForExit() { if (hProcess != IntPtr.Zero) WaitForSingleObject(hProcess, 0xFFFFFFFF); }

        public uint ExitCode
        {
            get
            {
                uint code = 0;
                if (hProcess != IntPtr.Zero) GetExitCodeProcess(hProcess, out code);
                return code;
            }
        }

        public void Kill()
        {
            try { if (hProcess != IntPtr.Zero) TerminateProcess(hProcess, 1); } catch { }
            job.Dispose();      // takes the rest of the tree with it
        }

        public void Dispose()
        {
            // Closing the pseudoconsole is what makes the output reader see EOF.
            try { if (hPC != IntPtr.Zero) { ClosePseudoConsole(hPC); hPC = IntPtr.Zero; } } catch { }
            try { if (Input != null) Input.Dispose(); } catch { }
            try { if (hThread != IntPtr.Zero) { CloseHandle(hThread); hThread = IntPtr.Zero; } } catch { }
            try { if (hProcess != IntPtr.Zero) { CloseHandle(hProcess); hProcess = IntPtr.Zero; } } catch { }
            try { job.Dispose(); } catch { }
        }
    }

    // ------------------------------------------------------------------ agent channel
    //
    // Two modes that converge on the same shape: an output pump, a stdin writer, and a waiter
    // that emits EXIT then DONE. Only process creation differs -- and the fact that a pty has
    // a single merged output stream, because a terminal has no separate stderr.

    internal sealed class AgentChannel : IAgentStream
    {
        private const int READ_BUFFER = 65536;

        private readonly PwsshAgentHost host;
        private readonly uint channel;
        private readonly object creditGate = new object();
        private long credit = PwsshAgentHost.InitialCredit;

        private Process proc;              // pipe mode
        private ConPtySession pty;         // pty mode
        private JobObject job;             // pipe mode; the pty session owns its own
        private int pumpsDone;
        private int expectedPumps;
        private volatile bool killed;

        public AgentChannel(PwsshAgentHost h, uint ch) { host = h; channel = ch; }

        public bool HasPty { get { return pty != null; } }

        public void AddCredit(uint add)
        {
            lock (creditGate) { credit += add; Monitor.PulseAll(creditGate); }
        }

        // commandLine is a full command line: "cmd.exe" for a shell, "cmd.exe /c ..." for exec.
        // ptyReq is null when the client did not ask for a terminal, or when the remote cannot
        // provide one -- the client has already been told which, via the HELLO capabilities.
        public bool Start(string commandLine, PtyRequest ptyReq)
        {
            if (proc != null || pty != null) return false;

            if (ptyReq != null && ConPtySession.IsAvailable())
            {
                return StartPty(commandLine, ptyReq);
            }
            return StartPiped(commandLine);
        }

        private bool StartPty(string commandLine, PtyRequest req)
        {
            try
            {
                ConPtySession s = new ConPtySession();
                if (!s.Start(commandLine, req.Cols, req.Rows))
                {
                    host.Log("ConPTY start failed; falling back to pipes");
                    s.Dispose();
                    return StartPiped(commandLine);
                }
                pty = s;
                expectedPumps = 1;                      // one merged stream
                StartPump(pty.Output, false);
                Thread wait = new Thread(new ThreadStart(WaitForPtyExit));
                wait.IsBackground = true;
                wait.Start();
                host.Log("pty channel " + channel + " started " + req.Cols + "x" + req.Rows);
                return true;
            }
            catch (Exception ex)
            {
                host.Log("pty start failed: " + ex.Message);
                return StartPiped(commandLine);
            }
        }

        private bool StartPiped(string commandLine)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = PwsshAgentHost.ShellPath();
                // The shell itself takes no arguments; exec passes "/c <command>".
                string shell = psi.FileName;
                if (commandLine.Length > shell.Length + 1 &&
                    commandLine.StartsWith(shell, StringComparison.OrdinalIgnoreCase))
                {
                    psi.Arguments = commandLine.Substring(shell.Length).TrimStart();
                }
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardInput = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                proc = Process.Start(psi);

                job = new JobObject();
                try { job.Assign(proc.Handle); } catch (Exception ex) { host.Log("job assign failed: " + ex.Message); }

                expectedPumps = 2;
                StartPump(proc.StandardOutput.BaseStream, false);
                StartPump(proc.StandardError.BaseStream, true);

                Thread wait = new Thread(new ThreadStart(WaitForProcExit));
                wait.IsBackground = true;
                wait.Start();
                return true;
            }
            catch (Exception ex)
            {
                host.Log("start failed: " + ex.Message);
                return false;
            }
        }

        public void Resize(uint cols, uint rows)
        {
            if (pty != null) pty.Resize(cols, rows);
        }

        private void StartPump(Stream src, bool isStderr)
        {
            // The handle must be taken before anything is read: reading FileStream's
            // SafeFileHandle flushes it, and a pipe cannot be repositioned.
            IntPtr h = (pty != null && !isStderr) ? pty.OutputHandle : PipePeek.HandleOf(src);
            Thread t = new Thread(new ThreadStart(delegate { Pump(src, isStderr, h); }));
            t.IsBackground = true;
            t.Start();
        }

        // Raw streams only. PowerShell's native-command bridge decodes as text and splits
        // lines, which destroys binary: measured 128 of 256 byte values lost.
        private void Pump(Stream src, bool isStderr, IntPtr handle)
        {
            byte[] buf = new byte[READ_BUFFER];
            try
            {
                while (!killed)
                {
                    int n = src.Read(buf, 0, buf.Length);
                    if (n <= 0) break;

                    // Coalesce whatever is *already* pending into the same frame. Output that
                    // trickles out slowly would otherwise become hundreds of tiny frames, and
                    // each time the client's queue empties the refill costs a WinRM turnaround.
                    //
                    // The condition is "bytes are available right now", never a timer, so a
                    // lone keystroke echo is still sent immediately and interactive latency is
                    // unchanged. A misleading peek can only cost the optimisation, never data:
                    // the reads still go through the stream.
                    if (!PwsshAgentHost.DisableCoalescing && handle != IntPtr.Zero)
                    {
                        while (n < buf.Length && PipePeek.Available(handle) > 0)
                        {
                            int more = src.Read(buf, n, buf.Length - n);
                            if (more <= 0) break;
                            n += more;
                        }
                    }

                    SendPayload(buf, n, isStderr);
                }
            }
            catch (Exception ex)
            {
                host.Log("pump ended: " + ex.Message);
            }
            finally
            {
                Interlocked.Increment(ref pumpsDone);
            }
        }

        private void SendPayload(byte[] buf, int count, bool isStderr)
        {
            int off = 0;
            while (off < count && !killed)
            {
                int allowed;
                lock (creditGate)
                {
                    while (credit <= 0 && !killed) Monitor.Wait(creditGate, 500);
                    if (killed) return;
                    allowed = (int)Math.Min((long)(count - off), credit);
                    credit -= allowed;
                }
                if (allowed <= 0) continue;

                byte kind = isStderr ? FrameType.ERR : FrameType.OUT;

                // Adaptive: only send compressed when it pays, so already-compressed output is
                // not penalised. Credit stays in uncompressed bytes, matching the SSH window.
                byte[] packed = null;
                try { packed = Zip.Deflate(buf, off, allowed); }
                catch (Exception ex) { host.Log("deflate failed: " + ex.Message); }

                if (packed != null && packed.Length < allowed - (allowed / 8))
                {
                    host.Send(Frame.Make((byte)(kind | FrameType.COMPRESSED), channel, packed));
                }
                else
                {
                    host.Send(Frame.Make(kind, channel, buf, off, allowed));
                }
                off += allowed;
            }
        }

        // IAgentStream: for a process-backed channel the stream is the child's stdin.
        public void Write(byte[] frame, int offset, int count)
        {
            if (count <= 0) return;
            try
            {
                if (pty != null)
                {
                    pty.Input.Write(frame, offset, count);
                    pty.Input.Flush();
                }
                else if (proc != null && !proc.HasExited)
                {
                    proc.StandardInput.BaseStream.Write(frame, offset, count);
                    proc.StandardInput.BaseStream.Flush();
                }
            }
            catch (Exception ex) { host.Log("stdin write failed: " + ex.Message); }
        }

        public void CloseWrite()
        {
            try
            {
                if (pty != null) { pty.Input.Dispose(); }
                else if (proc != null) { proc.StandardInput.BaseStream.Close(); }
            }
            catch { }
        }

        private void WaitForProcExit()
        {
            try
            {
                proc.WaitForExit();
                DrainPumps();
                Finish((uint)proc.ExitCode);
            }
            catch (Exception ex)
            {
                host.Log("wait failed: " + ex.Message);
                host.Send(Frame.MakeText(FrameType.FAIL, channel, ex.Message));
                host.Forget(channel);
            }
        }

        private void WaitForPtyExit()
        {
            try
            {
                pty.WaitForExit();
                uint code = pty.ExitCode;
                // Closing the pseudoconsole is what makes the output pump see EOF, so it has
                // to happen before waiting for that pump to finish.
                pty.Dispose();
                DrainPumps();
                Finish(code);
            }
            catch (Exception ex)
            {
                host.Log("pty wait failed: " + ex.Message);
                host.Send(Frame.MakeText(FrameType.FAIL, channel, ex.Message));
                host.Forget(channel);
            }
        }

        private void DrainPumps()
        {
            for (int i = 0; i < 300 && pumpsDone < expectedPumps; i++) Thread.Sleep(10);
        }

        private void Finish(uint code)
        {
            host.Log("channel " + channel + " exited " + code);
            host.Send(Frame.MakeUInt32(FrameType.EXIT, channel, code));
            host.Send(Frame.Make(FrameType.DONE, channel, null));
            host.Forget(channel);
        }

        public void Kill()
        {
            killed = true;
            lock (creditGate) { Monitor.PulseAll(creditGate); }
            try { if (pty != null) pty.Kill(); } catch { }
            try { if (proc != null && !proc.HasExited) proc.Kill(); } catch { }
            try { if (job != null) job.Dispose(); } catch { }   // takes the child's children too
        }
    }

    // -------------------------------------------------------------- forwarded TCP
    //
    // The remote end of a direct-tcpip channel: connect outbound, then be a byte pipe.
    // Deliberately a sibling of AgentChannel rather than a subclass -- almost nothing is
    // shared beyond credit accounting, and a socket has neither stderr nor an exit status.

    internal sealed class AgentTcpChannel : IAgentStream
    {
        private const int READ_BUFFER = 65536;

        private readonly PwsshAgentHost host;
        private readonly uint channel;
        private readonly object creditGate = new object();
        private long credit = PwsshAgentHost.InitialTcpCredit;

        private Socket sock;
        private NetworkStream stream;
        private volatile bool killed;

        public AgentTcpChannel(PwsshAgentHost h, uint ch) { host = h; channel = ch; }

        public void AddCredit(uint add)
        {
            lock (creditGate) { credit += add; Monitor.PulseAll(creditGate); }
        }

        // Remote forwarding: the socket already exists, having been accepted by an
        // AgentListener. It is deliberately NOT read until the client confirms the channel,
        // or we would produce data for a channel that does not exist yet.
        public void Adopt(Socket accepted)
        {
            sock = accepted;
            try { sock.NoDelay = true; } catch { }
            stream = new NetworkStream(accepted, false);
        }

        public void StartPumping()
        {
            if (stream == null) return;
            Thread pump = new Thread(new ThreadStart(Pump));
            pump.IsBackground = true;
            pump.Name = "pwssh-tcp-pump";
            pump.Start();
        }

        // Connects on its own thread: this is called from the frame dispatch path, and a
        // blocking connect there would stall every other channel.
        public void BeginConnect(string hostName, int port)
        {
            Thread t = new Thread(new ThreadStart(delegate { Connect(hostName, port); }));
            t.IsBackground = true;
            t.Name = "pwssh-connect";
            t.Start();
        }

        private void Connect(string hostName, int port)
        {
            IPAddress[] addrs;
            try { addrs = Resolve(hostName); }
            catch (Exception ex) { Fail("cannot resolve " + hostName + ": " + ex.Message); return; }
            if (addrs.Length == 0) { Fail("no addresses for " + hostName); return; }

            // With more than one candidate, cap each attempt: an unroutable address family
            // otherwise burns the OS connect timeout (~21 s observed) before the next address
            // is tried, which is exactly the case a dual-stack host with dead IPv6 hits. A
            // single candidate keeps the OS default, so a legitimately slow target still works.
            int perAddressMs = (addrs.Length > 1) ? 8000 : -1;

            Exception last = null;
            for (int i = 0; i < addrs.Length && !killed; i++)
            {
                Socket s = null;
                try
                {
                    // A socket per address family. TcpClient's default constructor produces an
                    // IPv4-only socket, so pointing it at an IPv6 address fails with a bogus
                    // "socket is not connected" (WSAENOTCONN) instead of a routing error --
                    // which also meant a host with both AAAA and A records never fell back.
                    s = new Socket(addrs[i].AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    s.NoDelay = true;             // forwarded traffic is usually latency-bound

                    if (perAddressMs < 0)
                    {
                        s.Connect(new IPEndPoint(addrs[i], port));
                    }
                    else
                    {
                        IAsyncResult ar = s.BeginConnect(new IPEndPoint(addrs[i], port), null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(perAddressMs))
                            throw new TimeoutException("connect timed out after " + perAddressMs + " ms");
                        s.EndConnect(ar);
                    }

                    if (killed) { try { s.Close(); } catch { } return; }

                    sock = s;
                    stream = new NetworkStream(s, false);
                    host.Log("channel " + channel + " connected to " + addrs[i] + ":" + port);
                    host.Send(Frame.Make(FrameType.CONNECT_OK, channel, null));

                    Thread pump = new Thread(new ThreadStart(Pump));
                    pump.IsBackground = true;
                    pump.Name = "pwssh-tcp-pump";
                    pump.Start();
                    return;
                }
                catch (Exception ex)
                {
                    // Try the next address: a target with both AAAA and A records should still
                    // work on a host whose IPv6 has no route.
                    last = ex;
                    host.Log("channel " + channel + " could not reach " + addrs[i] + ":" + port + ": " + ex.Message);
                    if (s != null) { try { s.Close(); } catch { } }
                }
            }

            Fail(last == null ? "connect failed" : last.Message);
        }

        private static IPAddress[] Resolve(string hostName)
        {
            string h = (hostName == null) ? "" : hostName.Trim();
            // SOCKS clients can hand over a bracketed IPv6 literal.
            if (h.Length > 1 && h[0] == '[' && h[h.Length - 1] == ']') h = h.Substring(1, h.Length - 2);

            IPAddress literal;
            if (IPAddress.TryParse(h, out literal)) return new IPAddress[] { literal };
            return Dns.GetHostAddresses(h);
        }

        private void Fail(string message)
        {
            host.Log("channel " + channel + " connect failed: " + message);
            host.Send(Frame.MakeText(FrameType.CONNECT_FAIL, channel, message));
            host.Forget(channel);
        }

        private void Pump()
        {
            byte[] buf = new byte[READ_BUFFER];
            try
            {
                while (!killed)
                {
                    int n = stream.Read(buf, 0, buf.Length);
                    if (n <= 0) break;

                    // Same coalescing idea as the pipe pumps, but a socket cannot be peeked
                    // with PeekNamedPipe -- Socket.Available answers the same question.
                    if (!PwsshAgentHost.DisableCoalescing)
                    {
                        while (n < buf.Length && sock.Available > 0)
                        {
                            int more = stream.Read(buf, n, buf.Length - n);
                            if (more <= 0) break;
                            n += more;
                        }
                    }

                    SendPayload(buf, n);
                }
            }
            catch (Exception ex)
            {
                if (!killed) host.Log("tcp pump ended: " + ex.Message);
            }
            finally
            {
                // No exit status for a socket; DONE alone closes the channel.
                host.Send(Frame.Make(FrameType.DONE, channel, null));
                host.Forget(channel);
            }
        }

        private void SendPayload(byte[] buf, int count)
        {
            int off = 0;
            while (off < count && !killed)
            {
                int allowed;
                lock (creditGate)
                {
                    while (credit <= 0 && !killed) Monitor.Wait(creditGate, 500);
                    if (killed) return;
                    allowed = (int)Math.Min((long)(count - off), credit);
                    credit -= allowed;
                }
                if (allowed <= 0) continue;

                byte[] packed = null;
                try { packed = Zip.Deflate(buf, off, allowed); }
                catch (Exception ex) { host.Log("deflate failed: " + ex.Message); }

                if (packed != null && packed.Length < allowed - (allowed / 8))
                {
                    host.Send(Frame.Make((byte)(FrameType.OUT | FrameType.COMPRESSED), channel, packed));
                }
                else
                {
                    host.Send(Frame.Make(FrameType.OUT, channel, buf, off, allowed));
                }
                off += allowed;
            }
        }

        public void Write(byte[] frame, int offset, int count)
        {
            if (count <= 0) return;
            try
            {
                NetworkStream s = stream;
                if (s != null) { s.Write(frame, offset, count); s.Flush(); }
            }
            catch (Exception ex) { host.Log("tcp write failed: " + ex.Message); }
        }

        // SSH channel EOF is a half-close, so shut down only our sending direction and let
        // the peer keep replying.
        public void CloseWrite()
        {
            try { if (sock != null) sock.Shutdown(SocketShutdown.Send); } catch { }
        }

        public void Kill()
        {
            killed = true;
            lock (creditGate) { Monitor.PulseAll(creditGate); }
            try { if (sock != null) sock.Close(); } catch { }
        }
    }

    // ------------------------------------------------------------------------ SFTP
    //
    // An SFTP version 3 server. It runs here rather than in the client engine because the
    // files are here: the engine just carries channel bytes, exactly as it does for a child
    // process's stdio, and this speaks the protocol at the end of that pipe.
    //
    // Version 3 is what OpenSSH's client speaks and what Windows' own sftp-server answers
    // with, so it is the only version worth implementing.

    internal static class SftpType
    {
        public const byte INIT = 1;
        public const byte VERSION = 2;
        public const byte OPEN = 3;
        public const byte CLOSE = 4;
        public const byte READ = 5;
        public const byte WRITE = 6;
        public const byte LSTAT = 7;
        public const byte FSTAT = 8;
        public const byte SETSTAT = 9;
        public const byte FSETSTAT = 10;
        public const byte OPENDIR = 11;
        public const byte READDIR = 12;
        public const byte REMOVE = 13;
        public const byte MKDIR = 14;
        public const byte RMDIR = 15;
        public const byte REALPATH = 16;
        public const byte STAT = 17;
        public const byte RENAME = 18;
        public const byte READLINK = 19;
        public const byte SYMLINK = 20;

        public const byte STATUS = 101;
        public const byte HANDLE = 102;
        public const byte DATA = 103;
        public const byte NAME = 104;
        public const byte ATTRS = 105;

        public const byte EXTENDED = 200;
        public const byte EXTENDED_REPLY = 201;
    }

    internal static class SftpStatus
    {
        public const uint OK = 0;
        public const uint EOF = 1;
        public const uint NO_SUCH_FILE = 2;
        public const uint PERMISSION_DENIED = 3;
        public const uint FAILURE = 4;
        public const uint BAD_MESSAGE = 5;
        public const uint OP_UNSUPPORTED = 8;
    }

    // Attribute flags, and the file-type bits that go in 'permissions'. The type bits are not
    // decorative: the client tests S_ISDIR on them, so omitting them makes ls -l lie and makes
    // a recursive get treat directories as files.
    internal static class SftpAttr
    {
        public const uint SIZE = 0x00000001;
        public const uint UIDGID = 0x00000002;
        public const uint PERMISSIONS = 0x00000004;
        public const uint ACMODTIME = 0x00000008;
        public const uint EXTENDED = 0x80000000;

        public const uint S_IFDIR = 0x4000;
        public const uint S_IFREG = 0x8000;
        public const uint S_IFLNK = 0xA000;
    }

    internal sealed class AgentSftpChannel : IAgentStream
    {
        // Both ends of the protocol have a cap on message size. The client aborts hard on a
        // reply above its own, which is not documented but is consistent with 256 KiB given
        // that Windows' sftp-server advertises a 262144 max-packet. So: refuse anything larger
        // inbound, and keep our own replies comfortably below it.
        private const int MAX_MSG = 256 * 1024;

        // Read and write limits are deliberately asymmetric, and both are advertised through
        // limits@openssh.com -- which is the single highest-value part of this feature, because
        // the client raises its transfer buffer to whatever we report. Measured: it goes from
        // its 32 KiB default to 255 KiB, an 8x cut in round trips on a link where one costs
        // 600-900 ms.
        //
        // Writes stay at 64 KiB even so. Upstream is byte-rate limited at ~0.4 MiB/s, so 64
        // requests of 64 KiB is already ~10x the bandwidth-delay product and bigger writes buy
        // nothing; and the client's outbound frame queue is FIFO across all channels, so a
        // 16 MiB upload backlog would head-of-line-block keystrokes on a shell channel sharing
        // the connection.
        internal const uint MAX_READ = 261120;
        internal const uint MAX_WRITE = 65536;

        // A queue this deep should be unreachable: the client keeps at most ~64 requests
        // outstanding. It exists so that a misbehaving peer fails loudly instead of growing
        // wsmprovhost's heap until it dies.
        private const long MAX_QUEUED = 64L * 1024 * 1024;

        private readonly PwsshAgentHost host;
        private readonly uint channel;

        private readonly object creditGate = new object();
        private long credit = PwsshAgentHost.InitialCredit;

        // Inbound reassembly and the ready queue, both under 'gate'.
        private readonly object gate = new object();
        private byte[] buf = new byte[128 * 1024];
        private int len;
        private readonly Queue<byte[]> ready = new Queue<byte[]>();
        private long queuedBytes;
        private bool clientEof;

        private volatile bool killed;
        private int started;

        public AgentSftpChannel(PwsshAgentHost h, uint ch) { host = h; channel = ch; }

        [DllImport("kernel32.dll")]
        private static extern uint SetErrorMode(uint mode);
        private const uint SEM_FAILCRITICALERRORS = 0x0001;
        private static int errorModeSet;

        public void Start()
        {
            if (Interlocked.CompareExchange(ref started, 1, 0) != 0) return;

            // Once per process, before anything touches a drive. Without it, reaching an empty
            // card reader or optical drive can raise the "There is no disk in the drive" dialog
            // -- which, in a service session with no desktop, means the call simply blocks.
            if (Interlocked.CompareExchange(ref errorModeSet, 1, 0) == 0)
            {
                try { SetErrorMode(SetErrorMode(0) | SEM_FAILCRITICALERRORS); } catch (Exception) { }
            }

            Thread t = new Thread(new ThreadStart(Worker));
            t.IsBackground = true;
            t.Name = "pwssh-sftp";
            t.Start();
        }

        // ---- IAgentStream ----

        // Runs on the frame dispatch thread, so it does the minimum: append, peel off whole
        // packets, hand them to the worker. Anything blocking here -- file I/O, or waiting for
        // credit to send a reply -- would stall every other channel on the connection.
        public void Write(byte[] frame, int offset, int count)
        {
            if (count <= 0 || killed) return;
            string fail = null;
            lock (gate)
            {
                if (len + count > buf.Length)
                {
                    int want = buf.Length;
                    while (want < len + count) want *= 2;
                    byte[] bigger = new byte[want];
                    Array.Copy(buf, 0, bigger, 0, len);
                    buf = bigger;
                }
                Array.Copy(frame, offset, buf, len, count);
                len += count;

                // Peel every complete packet: 4-byte big-endian length, then that many bytes.
                int p = 0;
                while (len - p >= 4)
                {
                    long n = ((long)buf[p] << 24) | ((long)buf[p + 1] << 16)
                           | ((long)buf[p + 2] << 8) | buf[p + 3];
                    // A garbage length must not become a 4 GiB allocation.
                    if (n < 1 || n > MAX_MSG) { fail = "bad SFTP packet length " + n; break; }
                    if (len - p - 4 < n) break;              // incomplete, wait for more
                    byte[] msg = new byte[n];
                    Array.Copy(buf, p + 4, msg, 0, (int)n);
                    p += 4 + (int)n;
                    ready.Enqueue(msg);
                    queuedBytes += n;
                }
                if (fail == null && queuedBytes > MAX_QUEUED) fail = "SFTP queue overflow";
                if (p > 0)
                {
                    Array.Copy(buf, p, buf, 0, len - p);
                    len -= p;
                }
                Monitor.PulseAll(gate);
            }
            if (fail != null)
            {
                host.Log("sftp channel " + channel + ": " + fail);
                host.Send(Frame.MakeText(FrameType.FAIL, channel, fail));
                Kill();
            }
        }

        public void CloseWrite()
        {
            lock (gate) { clientEof = true; Monitor.PulseAll(gate); }
        }

        public void AddCredit(uint add)
        {
            lock (creditGate) { credit += add; Monitor.PulseAll(creditGate); }
        }

        public void Kill()
        {
            killed = true;
            lock (creditGate) { Monitor.PulseAll(creditGate); }
            lock (gate) { Monitor.PulseAll(gate); }
            CloseAllHandles();
        }

        // ---- worker ----

        private void Worker()
        {
            try
            {
                while (!killed)
                {
                    byte[] msg = null;
                    lock (gate)
                    {
                        while (ready.Count == 0 && !clientEof && !killed) Monitor.Wait(gate, 250);
                        if (killed) return;
                        if (ready.Count > 0)
                        {
                            msg = ready.Dequeue();
                            queuedBytes -= msg.Length;
                        }
                        else if (clientEof) break;           // nothing left and no more coming
                    }
                    if (msg != null) Dispatch(msg);
                }
            }
            catch (Exception ex)
            {
                if (!killed) host.Log("sftp worker ended: " + ex.Message);
            }
            finally
            {
                CloseAllHandles();
                // A subsystem is a process as far as the client is concerned, so it reports an
                // exit status the way sshd does when sftp-server exits normally. The forwarded
                // TCP channel deliberately sends only DONE; this is the difference.
                //
                // Skipped when killed, because that means the client closed the channel first
                // and the engine has already forgotten it -- there is nobody left to tell.
                if (!killed)
                {
                    host.Send(Frame.MakeUInt32(FrameType.EXIT, channel, 0));
                    host.Send(Frame.Make(FrameType.DONE, channel, null));
                }
                host.Forget(channel);
            }
        }

        // Every request must produce exactly one reply. A dropped reply is not an error the
        // client can see -- it waits until its own timeout, which on this link is
        // indistinguishable from ordinary slowness. Hence the catch-all.
        private void Dispatch(byte[] msg)
        {
            byte type = msg.Length > 0 ? msg[0] : (byte)0;
            uint id = 0;
            try
            {
                if (type == SftpType.INIT)
                {
                    SendVersion();
                    return;
                }

                SshLikeReader r = new SshLikeReader(msg, 1);
                id = r.UInt32();
                Handle(type, id, r, msg);
            }
            catch (Exception ex)
            {
                host.Log("sftp request 0x" + type.ToString("X2") + " failed: " + ex.Message);
                if (type != SftpType.INIT) SendStatus(id, StatusFor(ex), ex.Message);
            }
        }

        private void Handle(byte type, uint id, SshLikeReader r, byte[] msg)
        {
            switch (type)
            {
                case SftpType.OPEN: DoOpen(id, r); return;
                case SftpType.READ: DoRead(id, r); return;
                case SftpType.WRITE: DoWrite(id, r); return;
                case SftpType.REALPATH: DoRealPath(id, r.Text()); return;
                case SftpType.STAT: DoStat(id, r.Text(), true); return;
                case SftpType.LSTAT: DoStat(id, r.Text(), false); return;
                case SftpType.FSTAT: DoFStat(id, r.Text()); return;
                case SftpType.OPENDIR: DoOpenDir(id, r.Text()); return;
                case SftpType.READDIR: DoReadDir(id, r.Text()); return;
                case SftpType.CLOSE: DoClose(id, r.Text()); return;

                // Refused on purpose, not merely absent. Creating a symlink needs
                // SeCreateSymbolicLinkPrivilege, i.e. elevation, which this project does not
                // use anywhere; and resolving one needs DeviceIoControl plus a reverse path
                // mapping for no benefit, since the client skips links on a recursive get
                // rather than following them.
                case SftpType.SYMLINK:
                case SftpType.READLINK:
                    SendStatus(id, SftpStatus.OP_UNSUPPORTED, "links are not supported");
                    return;

                case SftpType.SETSTAT: DoSetStat(id, r); return;
                case SftpType.FSETSTAT: DoFSetStat(id, r); return;
                case SftpType.MKDIR: DoMkDir(id, r); return;
                case SftpType.RMDIR: DoRmDir(id, r.Text()); return;
                case SftpType.REMOVE: DoRemove(id, r.Text()); return;
                case SftpType.RENAME: DoRename(id, r.Text(), r.Text(), false); return;

                case SftpType.EXTENDED:
                    {
                        string name = r.Text();
                        if (name == "limits@openssh.com") { SendLimits(id); return; }
                        // The overwriting rename. v3's plain RENAME must fail when the target
                        // exists, but write-temp-then-rename-over is the standard safe-write
                        // idiom, so clients ask for this one by name.
                        if (name == "posix-rename@openssh.com") { DoRename(id, r.Text(), r.Text(), true); return; }
                        if (name == "fsync@openssh.com") { DoFsync(id, r.Text()); return; }
                        if (name == "hardlink@openssh.com") { DoHardLink(id, r.Text(), r.Text()); return; }
                        // Setting attributes without following a link. With no link resolution
                        // here in the first place, it is the same operation as SETSTAT.
                        if (name == "lsetstat@openssh.com") { DoSetStat(id, r); return; }
                        SendStatus(id, SftpStatus.OP_UNSUPPORTED, "unsupported extension: " + name);
                        return;
                    }
            }
            SendStatus(id, SftpStatus.OP_UNSUPPORTED, "not implemented");
        }

        // ---- files ----

        private const uint PF_READ = 0x1, PF_WRITE = 0x2, PF_APPEND = 0x4,
                           PF_CREAT = 0x8, PF_TRUNC = 0x10, PF_EXCL = 0x20;

        // Attributes as they arrive from the client. Any flag combination has to be tolerated,
        // and the extended block skipped exactly, or everything after it in the packet is
        // misread.
        private sealed class AttrsIn
        {
            public uint Flags;
            public ulong Size;
            public uint Permissions;
            public uint Atime, Mtime;
            public bool HasSize { get { return (Flags & SftpAttr.SIZE) != 0; } }
            public bool HasPerms { get { return (Flags & SftpAttr.PERMISSIONS) != 0; } }
            public bool HasTimes { get { return (Flags & SftpAttr.ACMODTIME) != 0; } }
        }

        private static AttrsIn ReadAttrs(SshLikeReader r)
        {
            AttrsIn a = new AttrsIn();
            a.Flags = r.UInt32();
            if ((a.Flags & SftpAttr.SIZE) != 0) a.Size = r.UInt64();
            if ((a.Flags & SftpAttr.UIDGID) != 0) { r.UInt32(); r.UInt32(); }
            if ((a.Flags & SftpAttr.PERMISSIONS) != 0) a.Permissions = r.UInt32();
            if ((a.Flags & SftpAttr.ACMODTIME) != 0) { a.Atime = r.UInt32(); a.Mtime = r.UInt32(); }
            if ((a.Flags & SftpAttr.EXTENDED) != 0)
            {
                uint n = r.UInt32();
                for (uint i = 0; i < n && !r.Exhausted; i++) { r.Text(); r.Text(); }
            }
            return a;
        }

        private void DoOpen(uint id, SshLikeReader r)
        {
            string path = r.Text();
            uint pflags = r.UInt32();
            AttrsIn attrs = ReadAttrs(r);
            string win = ToWindows(path);

            bool wantWrite = (pflags & (PF_WRITE | PF_APPEND | PF_TRUNC | PF_CREAT)) != 0;
            FileMode mode;
            if ((pflags & PF_EXCL) != 0) mode = FileMode.CreateNew;
            else if ((pflags & PF_TRUNC) != 0) mode = FileMode.Create;
            else if ((pflags & PF_CREAT) != 0) mode = ((pflags & PF_APPEND) != 0) ? FileMode.Append : FileMode.OpenOrCreate;
            else mode = FileMode.Open;

            FileAccess access = wantWrite
                ? (((pflags & PF_READ) != 0) ? FileAccess.ReadWrite : FileAccess.Write)
                : FileAccess.Read;
            // Read handles allow others to delete or rename the file underneath us, which is
            // what Windows otherwise forbids and what a client doing read-then-replace needs.
            FileShare share = wantWrite ? FileShare.None : (FileShare.ReadWrite | FileShare.Delete);

            SftpHandle h = NewHandle();
            if (h == null) { SendStatus(id, SftpStatus.FAILURE, "too many open handles"); return; }
            h.WinPath = win;
            try
            {
                h.File = new FileStream(win, mode, access, share, 64 * 1024,
                                        wantWrite ? FileOptions.None : FileOptions.SequentialScan);
            }
            catch (Exception)
            {
                DropHandle(h);
                throw;                      // the caller's catch maps it to a status
            }

            // Size in the OPEN attributes is honoured for the same reason SETSTAT honours it:
            // clients pre-size a file they are about to fill.
            if (wantWrite && attrs.HasSize)
            {
                try { h.File.SetLength((long)attrs.Size); } catch (Exception) { }
            }
            if (attrs.HasTimes) { h.HasTimes = true; h.Atime = attrs.Atime; h.Mtime = attrs.Mtime; }

            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.HANDLE);
            w.UInt32(id);
            w.Text(h.Id);
            Reply(w);
        }

        private void DoRead(uint id, SshLikeReader r)
        {
            string handleId = r.Text();
            ulong offset = r.UInt64();
            uint want = r.UInt32();

            SftpHandle h = GetHandle(handleId);
            if (h == null || h.File == null) { SendStatus(id, SftpStatus.FAILURE, "unknown handle"); return; }
            if (want > MAX_READ) want = MAX_READ;

            byte[] data = new byte[want];
            int got = 0;
            h.File.Position = (long)offset;
            // Loop until the request is satisfied or the file genuinely ends. A short reply is
            // not a harmless optimisation: measured against the reference, one short read made
            // the client re-request and then permanently shrink its request size for the rest
            // of the session, costing ~2.5x of the pipelining this feature depends on.
            while (got < (int)want)
            {
                int n = h.File.Read(data, got, (int)want - got);
                if (n <= 0) break;
                got += n;
            }

            if (got == 0) { SendStatus(id, SftpStatus.EOF, "end of file"); return; }

            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.DATA);
            w.UInt32(id);
            w.Blob(data, 0, got);
            Reply(w);
        }

        private void DoWrite(uint id, SshLikeReader r)
        {
            string handleId = r.Text();
            ulong offset = r.UInt64();
            int off, count;
            if (!r.Blob(out off, out count)) { SendStatus(id, SftpStatus.BAD_MESSAGE, "truncated write"); return; }

            SftpHandle h = GetHandle(handleId);
            if (h == null || h.File == null) { SendStatus(id, SftpStatus.FAILURE, "unknown handle"); return; }

            // The payload is written straight out of the request buffer -- no copy.
            h.File.Position = (long)offset;
            h.File.Write(r.Buffer, off, count);
            SendStatus(id, SftpStatus.OK, "");
        }

        // ---- attributes and mutation ----

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool MoveFileExW(string existing, string newName, uint flags);
        private const uint MOVEFILE_REPLACE_EXISTING = 0x1, MOVEFILE_COPY_ALLOWED = 0x2;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateHardLinkW(string link, string existing, IntPtr sa);

        // Applies whatever of the attribute set we can, and reports OK for the rest. Refusing
        // here would be wrong: the client sends the local file's mode in OPEN on *every* put,
        // and scp -p sends SETSTAT, so a failure breaks a transfer that otherwise worked
        // perfectly -- for a reason no user would guess.
        private void ApplyAttrs(string win, AttrsIn a)
        {
            if (a.HasSize)
            {
                using (FileStream fs = new FileStream(win, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    fs.SetLength((long)a.Size);
                }
            }
            if (a.HasTimes)
            {
                File.SetLastAccessTimeUtc(win, FromUnix(a.Atime));
                File.SetLastWriteTimeUtc(win, FromUnix(a.Mtime));
            }
            if (a.HasPerms)
            {
                // The owner write bit is the only part of a POSIX mode Windows has anywhere to
                // put it. Everything else is accepted and dropped.
                bool writable = (a.Permissions & 0x080) != 0;
                FileAttributes cur = File.GetAttributes(win);
                bool isReadOnly = (cur & FileAttributes.ReadOnly) != 0;
                if (writable && isReadOnly) File.SetAttributes(win, cur & ~FileAttributes.ReadOnly);
                else if (!writable && !isReadOnly) File.SetAttributes(win, cur | FileAttributes.ReadOnly);
            }
        }

        private void DoSetStat(uint id, SshLikeReader r)
        {
            string win = ToWindows(r.Text());
            ApplyAttrs(win, ReadAttrs(r));
            SendStatus(id, SftpStatus.OK, "");
        }

        private void DoFSetStat(uint id, SshLikeReader r)
        {
            SftpHandle h = GetHandle(r.Text());
            AttrsIn a = ReadAttrs(r);
            if (h == null) { SendStatus(id, SftpStatus.FAILURE, "unknown handle"); return; }

            if (a.HasSize && h.File != null) h.File.SetLength((long)a.Size);
            // Times are recorded, not applied: see SftpHandle.HasTimes for why they wait for
            // CLOSE. Permissions are applied now and any failure ignored, since an open handle
            // can legitimately refuse an attribute change.
            if (a.HasTimes) { h.HasTimes = true; h.Atime = a.Atime; h.Mtime = a.Mtime; }
            if (a.HasPerms && h.WinPath != null)
            {
                try
                {
                    AttrsIn permsOnly = new AttrsIn();
                    permsOnly.Flags = SftpAttr.PERMISSIONS;
                    permsOnly.Permissions = a.Permissions;
                    ApplyAttrs(h.WinPath, permsOnly);
                }
                catch (Exception) { }
            }
            SendStatus(id, SftpStatus.OK, "");
        }

        private void DoMkDir(uint id, SshLikeReader r)
        {
            string win = ToWindows(r.Text());
            ReadAttrs(r);                   // a mode we have nowhere to put
            // CreateDirectory is silently happy about an existing directory; the protocol is not.
            if (Directory.Exists(win) || File.Exists(win))
            {
                SendStatus(id, SftpStatus.FAILURE, "already exists");
                return;
            }
            Directory.CreateDirectory(win);
            SendStatus(id, SftpStatus.OK, "");
        }

        private void DoRmDir(uint id, string path)
        {
            string win = ToWindows(path);
            if (!Directory.Exists(win))
            {
                SendStatus(id, File.Exists(win) ? SftpStatus.FAILURE : SftpStatus.NO_SUCH_FILE,
                           File.Exists(win) ? "not a directory" : "no such directory");
                return;
            }
            Directory.Delete(win, false);   // never recursive: rmdir means rmdir
            SendStatus(id, SftpStatus.OK, "");
        }

        private void DoRemove(uint id, string path)
        {
            string win = ToWindows(path);
            // File.Delete is silent about a missing file, and would happily be asked to remove
            // a directory; both need to be reported.
            if (Directory.Exists(win)) { SendStatus(id, SftpStatus.FAILURE, "is a directory"); return; }
            if (!File.Exists(win)) { SendStatus(id, SftpStatus.NO_SUCH_FILE, "no such file"); return; }
            File.Delete(win);
            SendStatus(id, SftpStatus.OK, "");
        }

        private void DoRename(uint id, string oldPath, string newPath, bool replace)
        {
            string from = ToWindows(oldPath);
            string to = ToWindows(newPath);
            // MoveFileEx rather than File.Move, which has no overwrite overload on .NET
            // Framework 4.8. COPY_ALLOWED lets a move cross volumes -- non-atomically, which
            // is the standard trade and what every other server does too.
            uint flags = MOVEFILE_COPY_ALLOWED;
            if (replace) flags |= MOVEFILE_REPLACE_EXISTING;
            if (!MoveFileExW(from, to, flags))
            {
                int err = Marshal.GetLastWin32Error();
                // REPLACE_EXISTING will not replace a directory, and a plain rename onto an
                // existing name is a protocol-level failure rather than an error to retry.
                uint code = (err == 2 || err == 3) ? SftpStatus.NO_SUCH_FILE
                          : (err == 5 ? SftpStatus.PERMISSION_DENIED : SftpStatus.FAILURE);
                SendStatus(id, code, new System.ComponentModel.Win32Exception(err).Message);
                return;
            }
            SendStatus(id, SftpStatus.OK, "");
        }

        private void DoFsync(uint id, string handleId)
        {
            SftpHandle h = GetHandle(handleId);
            if (h == null || h.File == null) { SendStatus(id, SftpStatus.FAILURE, "unknown handle"); return; }
            h.File.Flush(true);             // true means through to the device, not just the OS
            SendStatus(id, SftpStatus.OK, "");
        }

        private void DoHardLink(uint id, string oldPath, string newPath)
        {
            string existing = ToWindows(oldPath);
            string link = ToWindows(newPath);
            if (!CreateHardLinkW(link, existing, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                uint code = (err == 2 || err == 3) ? SftpStatus.NO_SUCH_FILE
                          : (err == 5 ? SftpStatus.PERMISSION_DENIED : SftpStatus.FAILURE);
                SendStatus(id, code, new System.ComponentModel.Win32Exception(err).Message);
                return;
            }
            SendStatus(id, SftpStatus.OK, "");
        }

        // ---- namespace ----

        private void DoRealPath(uint id, string path)
        {
            string canonical;
            if (IsVirtualRoot(path)) canonical = "/";
            else canonical = ToSftp(ToWindows(path));

            // Deliberately does NOT require the path to exist: sftp put and every scp upload
            // realpath a destination that is not there yet, so failing here breaks all uploads.
            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.NAME);
            w.UInt32(id);
            w.UInt32(1);
            w.Text(canonical);
            w.Text(canonical);
            w.UInt32(0);                    // no attributes, matching the reference
            Reply(w);
        }

        private void DoStat(uint id, string path, bool followLinks)
        {
            Meta m = IsVirtualRoot(path) ? RootMeta() : Describe(ToWindows(path), followLinks);
            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.ATTRS);
            w.UInt32(id);
            WriteAttrs(w, m);
            Reply(w);
        }

        private void DoFStat(uint id, string handleId)
        {
            SftpHandle h = GetHandle(handleId);
            if (h == null) { SendStatus(id, SftpStatus.FAILURE, "unknown handle"); return; }
            Meta m;
            if (h.IsDir) m = Describe(h.WinPath, true);
            else
            {
                m = new Meta();
                m.Size = h.File != null ? h.File.Length : 0;
                try
                {
                    FileInfo fi = new FileInfo(h.WinPath);
                    m.MtimeUtc = fi.LastWriteTimeUtc; m.AtimeUtc = fi.LastAccessTimeUtc;
                }
                catch (Exception) { }
            }
            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.ATTRS);
            w.UInt32(id);
            WriteAttrs(w, m);
            Reply(w);
        }

        // ---- directories ----

        private void DoOpenDir(uint id, string path)
        {
            SftpHandle h = NewHandle();
            if (h == null) { SendStatus(id, SftpStatus.FAILURE, "too many open handles"); return; }
            h.IsDir = true;

            if (IsVirtualRoot(path))
            {
                // The virtual root lists the drives. Their attributes are NOT fetched: the
                // reference does not either (it reports size 0 and a 1979 date for empty
                // drives), and touching a card reader or empty optical drive can block for
                // seconds or raise a "no disk" dialog.
                h.WinPath = null;
                string[] drives = Directory.GetLogicalDrives();
                h.Names = new string[drives.Length];
                h.Metas = new Meta[drives.Length];
                for (int i = 0; i < drives.Length; i++)
                {
                    h.Names[i] = drives[i].Length >= 2 ? drives[i].Substring(0, 2) : drives[i];
                    h.Metas[i] = RootMeta();
                }
            }
            else
            {
                h.WinPath = ToWindows(path);
                DirectoryInfo di = new DirectoryInfo(h.WinPath);
                // Snapshot rather than a lazy enumerator: the client comes back for the next
                // batch a round trip later, and holding a FindFirstFile handle open across
                // seconds buys nothing.
                FileSystemInfo[] items = di.GetFileSystemInfos();
                h.Names = new string[items.Length];
                h.Metas = new Meta[items.Length];
                for (int i = 0; i < items.Length; i++)
                {
                    h.Names[i] = items[i].Name;
                    h.Metas[i] = FromInfo(items[i]);
                }
            }

            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.HANDLE);
            w.UInt32(id);
            w.Text(h.Id);
            Reply(w);
        }

        // A NAME reply is packed until it approaches the message cap rather than stopping at
        // the conventional ~100 entries. READDIR cannot be pipelined -- the handle is a cursor,
        // so the client issues them strictly one at a time -- and the reference needed 58
        // sequential round trips to list System32's 5,604 entries. At ~0.7 s each that is 40 s
        // for one ls. Packing to 200 KiB brings the same listing down to a handful of trips.
        //
        // 200 KiB rather than 256: the client aborts hard on an over-long message, and its cap
        // is inferred from the reference's advertised max-packet rather than documented.
        private const int READDIR_BATCH_BYTES = 200 * 1024;

        private void DoReadDir(uint id, string handleId)
        {
            SftpHandle h = GetHandle(handleId);
            if (h == null) { SendStatus(id, SftpStatus.FAILURE, "unknown handle"); return; }
            if (!h.IsDir) { SendStatus(id, SftpStatus.FAILURE, "not a directory handle"); return; }
            if (h.Index >= h.Names.Length) { SendStatus(id, SftpStatus.EOF, "end of directory"); return; }

            SshLikeWriter entries = new SshLikeWriter();
            uint count = 0;
            while (h.Index < h.Names.Length && entries.Length < READDIR_BATCH_BYTES)
            {
                string name = h.Names[h.Index];
                Meta m = h.Metas[h.Index];
                h.Index++;
                if (name == "." || name == "..") continue;    // the client skips these anyway
                entries.Text(name);
                entries.Text(LongName(name, m));
                WriteAttrs(entries, m);
                count++;
            }

            if (count == 0) { SendStatus(id, SftpStatus.EOF, "end of directory"); return; }

            byte[] body = entries.ToArray();
            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.NAME);
            w.UInt32(id);
            w.UInt32(count);
            w.Raw(body, 0, body.Length);
            Reply(w);
        }

        private void DoClose(uint id, string handleId)
        {
            SftpHandle h = GetHandle(handleId);
            if (h == null) { SendStatus(id, SftpStatus.FAILURE, "unknown handle"); return; }
            DropHandle(h);
            SendStatus(id, SftpStatus.OK, "");
        }

        // ---- replies ----

        private void SendVersion()
        {
            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.VERSION);
            w.UInt32(3);
            // Only extensions that earn their place; see the comments on MAX_READ for why
            // limits is the important one.
            w.Text("posix-rename@openssh.com"); w.Text("1");
            w.Text("fsync@openssh.com"); w.Text("1");
            w.Text("hardlink@openssh.com"); w.Text("1");
            w.Text("lsetstat@openssh.com"); w.Text("1");
            w.Text("limits@openssh.com"); w.Text("1");
            Reply(w);
            host.Log("sftp channel " + channel + " ready (version 3)");
        }

        private void SendLimits(uint id)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.EXTENDED_REPLY);
            w.UInt32(id);
            w.UInt64(MAX_READ + 1024);      // max-packet-length: the payload plus its header
            w.UInt64(MAX_READ);
            w.UInt64(MAX_WRITE);
            w.UInt64(0);                    // max-open-handles: 0 means unspecified, as sshd says
            Reply(w);
        }

        private void SendStatus(uint id, uint code, string message)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.Byte(SftpType.STATUS);
            w.UInt32(id);
            w.UInt32(code);
            // The message is the only diagnostic the user ever sees, so it always carries the
            // real reason rather than a generic one.
            w.Text(message == null ? "" : message);
            w.Text("");                     // language tag
            Reply(w);
        }

        // Maps a .NET exception onto the closest v3 status. v3 has no INVALID_FILENAME (that
        // arrived in v6), so reserved names, a stray colon reaching an alternate data stream,
        // trailing dots and over-long paths all land in FAILURE with the message attached --
        // which is fine, because the message is what the user actually reads.
        //
        // Note UnauthorizedAccessException covers both an ACL denial and "that is a directory",
        // so the handlers that care about the difference check Directory.Exists themselves.
        private static uint StatusFor(Exception ex)
        {
            if (ex is FileNotFoundException || ex is DirectoryNotFoundException) return SftpStatus.NO_SUCH_FILE;
            if (ex is UnauthorizedAccessException || ex is System.Security.SecurityException)
                return SftpStatus.PERMISSION_DENIED;
            return SftpStatus.FAILURE;
        }

        // Frames the reply with its 4-byte length and hands it to the credit-bounded sender.
        private void Reply(SshLikeWriter body)
        {
            byte[] payload = body.ToArray();
            byte[] packet = new byte[4 + payload.Length];
            int n = payload.Length;
            packet[0] = (byte)(n >> 24); packet[1] = (byte)(n >> 16);
            packet[2] = (byte)(n >> 8); packet[3] = (byte)n;
            Array.Copy(payload, 0, packet, 4, n);
            SendPayload(packet, packet.Length);
        }

        // Same shape as AgentTcpChannel.SendPayload: credit first, then adaptive deflate. File
        // data compresses well and this is the plaintext side of the WinRM hop, so it is worth
        // trying on every reply.
        private void SendPayload(byte[] data, int count)
        {
            int off = 0;
            while (off < count && !killed)
            {
                int allowed;
                lock (creditGate)
                {
                    while (credit <= 0 && !killed) Monitor.Wait(creditGate, 500);
                    if (killed) return;
                    allowed = (int)Math.Min((long)(count - off), credit);
                    credit -= allowed;
                }
                if (allowed <= 0) continue;

                byte[] packed = null;
                try { packed = Zip.Deflate(data, off, allowed); }
                catch (Exception ex) { host.Log("deflate failed: " + ex.Message); }

                if (packed != null && packed.Length < allowed - (allowed / 8))
                {
                    host.Send(Frame.Make((byte)(FrameType.OUT | FrameType.COMPRESSED), channel, packed));
                }
                else
                {
                    host.Send(Frame.Make(FrameType.OUT, channel, data, off, allowed));
                }
                off += allowed;
            }
        }

        // ---- path mapping ----
        //
        // The convention is Windows OpenSSH's, verified against its own sftp-server rather
        // than guessed: /C:/Users/kb <-> C:\Users\kb, with "/" a virtual root that lists the
        // drives. It is the only convention any client has ever seen from a Windows SFTP
        // server, so WinSCP and friends already cope with it.
        //
        // The invariant that matters in practice: realpath must be idempotent, and
        // realpath(dir) + "/" + a readdir name must open -- scp -r builds paths by
        // concatenating exactly that way.

        private string home;

        private string Home()
        {
            if (home == null)
            {
                // Not the process working directory: this runs inside wsmprovhost, whose cwd is
                // nothing the user chose.
                string h = Environment.GetEnvironmentVariable("USERPROFILE");
                if (string.IsNullOrEmpty(h)) h = Environment.GetEnvironmentVariable("SystemDrive") + "\\";
                if (string.IsNullOrEmpty(h)) h = "C:\\";
                home = h;
            }
            return home;
        }

        private static bool IsVirtualRoot(string p)
        {
            return p == "/" || p == "\\";
        }

        // Throws on anything we deliberately do not serve, so the caller's catch turns it into
        // a status with the reason attached.
        private string ToWindows(string sftpPath)
        {
            string p = sftpPath == null ? "" : sftpPath;
            if (p.Length == 0 || p == ".") return Home();

            // UNC and the \\?\ form have no agreed mapping under this convention -- Windows'
            // own server mangles \\?\C:\Users into /C:/?/C:/Users -- so refuse rather than
            // half-support them.
            if (p.StartsWith("//", StringComparison.Ordinal) || p.StartsWith("\\\\", StringComparison.Ordinal))
                throw new NotSupportedException("UNC paths are not supported: " + sftpPath);

            // "/C:/x" -> "C:/x". A leading slash before a drive letter is the wire form.
            if (p.Length >= 3 && (p[0] == '/' || p[0] == '\\') && char.IsLetter(p[1]) && p[2] == ':')
                p = p.Substring(1);

            string win;
            if (p.Length >= 2 && char.IsLetter(p[0]) && p[1] == ':')
            {
                if (p.Length == 2) win = p + "\\";                       // "C:" means the root
                else if (p[2] == '/' || p[2] == '\\') win = p;
                // "C:foo" is drive-relative on Windows, resolved against a per-process cwd
                // nobody set. Treat it as rooted on that drive instead of honouring it.
                else win = p.Substring(0, 2) + "\\" + p.Substring(2);
            }
            else if (p[0] == '/' || p[0] == '\\')
            {
                // A leading slash with no drive means the current drive's root, matching what
                // the reference does: "/Windows" -> "C:\Windows".
                string root = Path.GetPathRoot(Home());
                win = root + p.Substring(1);
            }
            else
            {
                win = Path.Combine(Home(), p);
            }

            win = win.Replace('/', '\\');
            // Collapses . and .. -- and throws on reserved names, trailing spaces and paths
            // past MAX_PATH, which is why every caller runs inside a try.
            return Path.GetFullPath(win);
        }

        private static string ToSftp(string windowsPath)
        {
            string s = windowsPath.Replace('\\', '/');
            if (s.Length == 0) return "/";
            if (s[0] != '/') s = "/" + s;
            // "/C:/" -> "/C:" so the result is stable under a second realpath.
            if (s.Length > 3 && s.EndsWith("/", StringComparison.Ordinal)) s = s.Substring(0, s.Length - 1);
            return s;
        }

        // ---- metadata ----

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        // v3 carries times as 32-bit unsigned seconds, and Windows really does hand out 1601
        // and 1979 dates, so clamp rather than let a negative cast produce garbage that a
        // subsequent -p would write back.
        private static uint ToUnix(DateTime utc)
        {
            double s = (utc - Epoch).TotalSeconds;
            if (s <= 0) return 0;
            if (s >= 4294967295.0) return 4294967295;
            return (uint)s;
        }

        private static DateTime FromUnix(uint t) { return Epoch.AddSeconds(t); }

        // What both the ATTRS reply and the ls-style longname are built from, gathered once so
        // a readdir does not stat every entry a second time.
        private sealed class Meta
        {
            public bool IsDir;
            public bool IsLink;
            public bool ReadOnly;
            public long Size;
            public DateTime MtimeUtc = Epoch;
            public DateTime AtimeUtc = Epoch;

            public uint Mode()
            {
                // Deliberately 0644/0755 rather than the reference's 0600/0700: a file fetched
                // with scp -p onto a Linux box otherwise lands mode 600, which surprises
                // people. Not derived from ACLs -- a per-entry ACL lookup during a 5,000-entry
                // readdir is far too expensive, and the reference's own bits look ACL-derived
                // and inconsistent anyway.
                if (IsLink) return SftpAttr.S_IFLNK | 0x1FF;             // 0777
                if (IsDir) return SftpAttr.S_IFDIR | (uint)(ReadOnly ? 0x16D : 0x1ED);  // 0555 : 0755
                return SftpAttr.S_IFREG | (uint)(ReadOnly ? 0x124 : 0x1A4);             // 0444 : 0644
            }
        }

        private static Meta FromInfo(FileSystemInfo fi)
        {
            Meta m = new Meta();
            try
            {
                FileAttributes a = fi.Attributes;
                m.IsDir = (a & FileAttributes.Directory) != 0;
                m.ReadOnly = (a & FileAttributes.ReadOnly) != 0;
                // Reparse points are reported as links even though we refuse READLINK, and
                // that is not cosmetic: C:\Users\All Users is a junction to C:\ProgramData and
                // AppData\Local\Application Data points at its own parent, so a client that
                // sees them as plain directories recurses forever on a recursive get. The
                // reference implementation gets this wrong; we deliberately do not copy it.
                m.IsLink = (a & FileAttributes.ReparsePoint) != 0;
                m.MtimeUtc = fi.LastWriteTimeUtc;
                m.AtimeUtc = fi.LastAccessTimeUtc;
                FileInfo f = fi as FileInfo;
                if (f != null && !m.IsDir) m.Size = f.Length;
            }
            catch (Exception)
            {
                // One unreadable entry must not fail a whole listing.
            }
            return m;
        }

        // followLinks distinguishes STAT from LSTAT. With no link resolution available on 4.8
        // the only difference we can express is whether the link bit is reported.
        private Meta Describe(string winPath, bool followLinks)
        {
            FileAttributes a = File.GetAttributes(winPath);      // throws if absent
            Meta m = new Meta();
            m.IsDir = (a & FileAttributes.Directory) != 0;
            m.ReadOnly = (a & FileAttributes.ReadOnly) != 0;
            m.IsLink = !followLinks && (a & FileAttributes.ReparsePoint) != 0;
            try
            {
                if (m.IsDir)
                {
                    DirectoryInfo di = new DirectoryInfo(winPath);
                    m.MtimeUtc = di.LastWriteTimeUtc; m.AtimeUtc = di.LastAccessTimeUtc;
                }
                else
                {
                    FileInfo fi = new FileInfo(winPath);
                    m.MtimeUtc = fi.LastWriteTimeUtc; m.AtimeUtc = fi.LastAccessTimeUtc;
                    m.Size = fi.Length;
                }
            }
            catch (Exception) { }
            return m;
        }

        private static Meta RootMeta()
        {
            Meta m = new Meta();
            m.IsDir = true;
            return m;
        }

        private static void WriteAttrs(SshLikeWriter w, Meta m)
        {
            // The same flag set the reference emits. uid/gid are 0 because Windows has no
            // meaningful mapping; clients display them as "-" or 0 either way.
            w.UInt32(SftpAttr.SIZE | SftpAttr.UIDGID | SftpAttr.PERMISSIONS | SftpAttr.ACMODTIME);
            w.UInt64((ulong)(m.Size < 0 ? 0 : m.Size));
            w.UInt32(0);
            w.UInt32(0);
            w.UInt32(m.Mode());
            w.UInt32(ToUnix(m.AtimeUtc));
            w.UInt32(ToUnix(m.MtimeUtc));
        }

        // An ls -l line. The client prints this verbatim for a directory listing, so the month
        // name must not come out localised: the agent runs under the remote's culture, and a
        // Danish or German remote would otherwise emit "maj" or "Mär" into a parsed field.
        private static string LongName(string name, Meta m)
        {
            uint mode = m.Mode();
            StringBuilder sb = new StringBuilder(80);
            sb.Append(m.IsLink ? 'l' : (m.IsDir ? 'd' : '-'));
            sb.Append((mode & 0x100) != 0 ? 'r' : '-');
            sb.Append((mode & 0x080) != 0 ? 'w' : '-');
            sb.Append((mode & 0x040) != 0 ? 'x' : '-');
            sb.Append((mode & 0x020) != 0 ? 'r' : '-');
            sb.Append((mode & 0x010) != 0 ? 'w' : '-');
            sb.Append((mode & 0x008) != 0 ? 'x' : '-');
            sb.Append((mode & 0x004) != 0 ? 'r' : '-');
            sb.Append((mode & 0x002) != 0 ? 'w' : '-');
            sb.Append((mode & 0x001) != 0 ? 'x' : '-');
            sb.Append("    1 ");
            // Owner and group are "-" rather than a name: resolving them means an ACL lookup
            // per entry, which a large listing cannot afford. The reference does the same.
            sb.Append("-        -        ");
            sb.Append(m.Size.ToString(CultureInfo.InvariantCulture).PadLeft(12));
            sb.Append(' ');
            DateTime local;
            try { local = m.MtimeUtc.ToLocalTime(); } catch (Exception) { local = Epoch; }
            TimeSpan age = DateTime.UtcNow - m.MtimeUtc;
            string when = (age.TotalDays > 180 || age.TotalDays < -1)
                ? local.ToString("MMM dd  yyyy", CultureInfo.InvariantCulture)
                : local.ToString("MMM dd HH:mm", CultureInfo.InvariantCulture);
            sb.Append(when);
            sb.Append(' ');
            sb.Append(name);
            return sb.ToString();
        }

        // ---- handles ----

        private sealed class SftpHandle
        {
            public string Id;
            public string WinPath;
            public FileStream File;          // null for a directory
            public string[] Names;           // directory snapshot
            public Meta[] Metas;             // parallel to Names
            public int Index;
            public bool IsDir;

            // Times requested through FSETSTAT (or in OPEN's attributes), applied on CLOSE
            // rather than immediately. scp -p sets them on the still-open handle, and NTFS
            // updates last-write when the handle's dirty data flushes -- i.e. after we set it.
            // Windows is believed to suppress that for a handle whose time was set explicitly,
            // but that is unverified and filesystem-dependent, so this sidesteps the question
            // entirely by setting the times by path once the handle is closed.
            public bool HasTimes;
            public uint Atime, Mtime;
        }

        private const int MAX_HANDLES = 256;
        private readonly Dictionary<string, SftpHandle> handles = new Dictionary<string, SftpHandle>();
        private uint nextHandle = 1;

        private SftpHandle NewHandle()
        {
            lock (gate)
            {
                if (handles.Count >= MAX_HANDLES) return null;
                SftpHandle h = new SftpHandle();
                // Never reused, so a stale handle from a client bug gets FAILURE rather than
                // silently addressing a different file.
                h.Id = (nextHandle++).ToString("x8", CultureInfo.InvariantCulture);
                handles[h.Id] = h;
                return h;
            }
        }

        private SftpHandle GetHandle(string id)
        {
            lock (gate)
            {
                SftpHandle h;
                if (id != null && handles.TryGetValue(id, out h)) return h;
                return null;
            }
        }

        private void DropHandle(SftpHandle h)
        {
            lock (gate) { handles.Remove(h.Id); }
            if (h.File != null) { try { h.File.Dispose(); } catch { } }
            ApplyDeferredTimes(h);
        }

        private void ApplyDeferredTimes(SftpHandle h)
        {
            if (!h.HasTimes || h.WinPath == null) return;
            try
            {
                File.SetLastAccessTimeUtc(h.WinPath, FromUnix(h.Atime));
                File.SetLastWriteTimeUtc(h.WinPath, FromUnix(h.Mtime));
            }
            catch (Exception ex) { host.Log("could not set times on " + h.WinPath + ": " + ex.Message); }
        }

        // Reached from CLOSE, from the worker's finally, and from Kill(). A leaked FileStream
        // holds an NTFS lock on the remote until wsmprovhost exits, which is worse than a
        // leaked port: the user's next attempt gets a sharing violation on their own file.
        private void CloseAllHandles()
        {
            SftpHandle[] all;
            lock (gate)
            {
                all = new SftpHandle[handles.Count];
                handles.Values.CopyTo(all, 0);
                handles.Clear();
            }
            for (int i = 0; i < all.Length; i++)
            {
                if (all[i].File != null) { try { all[i].File.Dispose(); } catch { } }
            }
        }
    }

    // ------------------------------------------------------------ remote forwarding (-R)
    //
    // Binds a port on the remote and reports each accepted connection to the client, which
    // then opens a forwarded-tcpip channel back to us. The accepted socket is parked until
    // that channel is confirmed.

    internal sealed class AgentListener
    {
        private readonly PwsshAgentHost host;
        private readonly uint forwardId;
        private readonly List<TcpListener> listeners = new List<TcpListener>();
        private volatile bool stopped;

        public AgentListener(PwsshAgentHost h, uint id) { host = h; forwardId = id; }

        public uint ForwardId { get { return forwardId; } }
        public int BoundPort { get; private set; }

        // Returns null on success, or the reason it could not bind.
        //
        // Note there is no privileged-port rule on Windows: a normal user can bind port 80 if
        // it is free. Binds fail because the port is already in use, or because it falls in an
        // excluded range (netsh interface ipv4 show excludedportrange).
        //
        // Runs on the frame dispatch thread, which binding is quick enough for. The exception is
        // a named bind address, which costs a DNS lookup and so briefly stalls every channel --
        // only reachable with -GatewayPorts, and only when the client names a host rather than
        // an address.
        public string Bind(string address, int port)
        {
            // One socket per address family, for the same reason -L needed it: a socket bound
            // to 127.0.0.1 does not accept ::1, and a dual-mode socket bound to a *specific*
            // v6 address does not accept mapped v4 either. So loopback and wildcard both mean
            // two sockets, and a program on the remote reaching "localhost" works whichever
            // family it resolves to.
            IPAddress[] addrs;
            try { addrs = ParseBindAddresses(address); }
            catch (Exception ex) { return ex.Message; }
            string firstError = null;
            int chosen = port;

            foreach (IPAddress addr in addrs)
            {
                TcpListener l = null;
                try
                {
                    l = new TcpListener(addr, chosen);
                    l.Start();
                    if (chosen == 0) chosen = ((IPEndPoint)l.LocalEndpoint).Port;
                    listeners.Add(l);
                }
                catch (Exception ex)
                {
                    try { if (l != null) l.Stop(); } catch { }
                    if (firstError == null) firstError = ex.Message;
                }
            }

            // Partial success is success: an IPv6-less remote must not fail an ordinary -R.
            if (listeners.Count == 0)
            {
                return firstError == null ? "no address to bind" : firstError;
            }

            BoundPort = chosen;
            foreach (TcpListener l in listeners)
            {
                TcpListener captured = l;
                Thread t = new Thread(delegate() { AcceptLoop(captured); });
                t.IsBackground = true;
                t.Name = "pwssh-listen-" + BoundPort;
                t.Start();
            }
            return null;
        }

        // An EMPTY address means wildcard, not loopback: that is what OpenSSH puts on the wire
        // for `-R *:port:...` (see the note in PwsshEngine.HandleGlobalRequest).
        private static IPAddress[] ParseBindAddresses(string address)
        {
            if (string.IsNullOrEmpty(address) || address == "*" || address == "0.0.0.0")
                return new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
            if (address == "::" || address == "[::]")
                return new IPAddress[] { IPAddress.IPv6Any };
            if (address == "localhost")
                return new IPAddress[] { IPAddress.Loopback, IPAddress.IPv6Loopback };
            IPAddress parsed;
            if (IPAddress.TryParse(address.Trim('[', ']'), out parsed))
            {
                // 127.0.0.1 is how the engine spells "loopback only", so widen it to both
                // families; any other literal is taken exactly as given.
                if (IPAddress.Loopback.Equals(parsed))
                    return new IPAddress[] { IPAddress.Loopback, IPAddress.IPv6Loopback };
                return new IPAddress[] { parsed };
            }
            IPAddress[] resolved = Dns.GetHostAddresses(address);
            if (resolved.Length == 0) throw new Exception("cannot resolve bind address " + address);
            return resolved;
        }

        private void AcceptLoop(TcpListener listener)
        {
            while (!stopped)
            {
                Socket s;
                try { s = listener.AcceptSocket(); }
                catch (Exception)
                {
                    break;                        // listener stopped
                }
                if (stopped) { try { s.Close(); } catch { } break; }

                try { host.OnAccepted(this, s); }
                catch (Exception ex)
                {
                    host.Log("accept handling failed: " + ex.Message);
                    try { s.Close(); } catch { }
                }
            }
        }

        public void Stop()
        {
            stopped = true;
            foreach (TcpListener l in listeners) { try { l.Stop(); } catch { } }
        }
    }

    // ------------------------------------------------------------- loopback wiring
    //
    // Connects a proxy to a host in-process through the real frame protocol, so the dev
    // harness exercises everything except the WinRM hop.

    public static class PwsshLoopback
    {
        public static IPwsshAgent Start()
        {
            PwsshAgentHost host = new PwsshAgentHost();
            PwsshAgentProxy proxy = new PwsshAgentProxy();
            host.Start();

            Thread up = new Thread(new ThreadStart(delegate
            {
                try
                {
                    while (true)
                    {
                        byte[] f = proxy.TakeOutboundFrame(200);
                        if (f != null) { host.PushInbound(f); continue; }
                        if (proxy.InboundClosed) break;
                    }
                }
                catch (Exception) { }
                finally { host.CloseInbound(); }
            }));
            up.IsBackground = true;
            up.Name = "pwssh-loopback-up";
            up.Start();

            Thread down = new Thread(new ThreadStart(delegate
            {
                try
                {
                    while (true)
                    {
                        byte[] f = host.TakeOutboundFrame(200);
                        if (f != null) { proxy.PushInbound(f); continue; }
                        if (host.Finished) break;
                    }
                }
                catch (Exception) { }
                finally { proxy.CloseInbound(); }
            }));
            down.IsBackground = true;
            down.Name = "pwssh-loopback-down";
            down.Start();

            return proxy;
        }
    }
}
