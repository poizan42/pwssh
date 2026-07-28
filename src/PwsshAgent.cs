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
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
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

        // agent -> client
        public const byte OUT = 0x81;     // payload: stdout bytes
        public const byte ERR = 0x82;     // payload: stderr bytes
        public const byte EXIT = 0x83;    // payload: uint32 exit status
        public const byte DONE = 0x84;    // no payload: channel finished
        public const byte HELLO = 0x85;   // payload: UTF-8 remote account name
        public const byte FAIL = 0x86;    // payload: UTF-8 message

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

        public void Text(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s == null ? "" : s);
            UInt32((uint)b.Length);
            ms.Write(b, 0, b.Length);
        }

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

        public string Text()
        {
            int n = (int)UInt32();
            if (n < 0 || p + n > b.Length) return "";
            string s = Encoding.UTF8.GetString(b, p, n);
            p += n;
            return s;
        }
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
        void OnAgentError(string message);
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

        public void Attach(IPwsshChannelSink s) { sink = s; }

        public bool InboundClosed { get { return inboundClosed; } }

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
                case FrameType.FAIL:
                    if (sink != null) sink.OnAgentError(Frame.PayloadText(frame));
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
        private readonly Dictionary<uint, AgentChannel> channels = new Dictionary<uint, AgentChannel>();
        private readonly object chanGate = new object();
        private readonly Queue<string> logQ = new Queue<string>();

        private volatile bool finished;
        private int lastInboundTick = Environment.TickCount;

        // If the client vanishes without closing the session the pipeline would otherwise
        // block forever and hold a WinRM shell until WinRM's own 2-hour timeout. 0 disables.
        public int InactivityTimeoutSeconds = 300;

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
                            req.Cols = r.UInt32();
                            req.Rows = r.UInt32();
                            req.Term = r.Text();
                            lock (chanGate) { pendingPty[ch] = req; }
                            Log("pty requested on channel " + ch + ": " + req.Cols + "x" + req.Rows + " " + req.Term);
                        }
                        break;

                    case FrameType.RESIZE:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            uint cols = r.UInt32();
                            uint rows = r.UInt32();
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

                    case FrameType.DATA:
                        {
                            AgentChannel c = Find(ch);
                            if (c != null) c.WriteStdin(frame, Frame.HEADER, Frame.PayloadLength(frame));
                        }
                        break;

                    case FrameType.EOF:
                        {
                            AgentChannel c = Find(ch);
                            if (c != null) c.CloseStdin();
                        }
                        break;

                    case FrameType.CLOSE:
                        {
                            AgentChannel c = Find(ch);
                            if (c != null) c.Kill();
                        }
                        break;

                    case FrameType.WINDOW:
                        {
                            AgentChannel c = Find(ch);
                            if (c != null) c.AddCredit(Frame.PayloadUInt32(frame));
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
                foreach (AgentChannel c in channels.Values) { try { c.Kill(); } catch { } }
            }
            foreach (PipeSink p in stripes) { try { p.Close(); } catch { } }
            outbound.Close();
        }

        private AgentChannel Find(uint ch)
        {
            lock (chanGate)
            {
                AgentChannel c;
                if (channels.TryGetValue(ch, out c)) return c;
                return null;
            }
        }

        private void StartChannel(uint ch, string command)
        {
            AgentChannel c = new AgentChannel(this, ch);
            lock (chanGate)
            {
                if (channels.ContainsKey(ch))
                {
                    Send(Frame.MakeText(FrameType.FAIL, ch, "channel already in use"));
                    return;
                }
                channels[ch] = c;
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

        internal void Forget(uint ch)
        {
            lock (chanGate) { channels.Remove(ch); }
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

    internal sealed class AgentChannel
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

        public void WriteStdin(byte[] frame, int offset, int count)
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

        public void CloseStdin()
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
