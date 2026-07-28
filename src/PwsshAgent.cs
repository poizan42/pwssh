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
using System.Text;
using System.Threading;

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

        // agent -> client
        public const byte OUT = 0x81;     // payload: stdout bytes
        public const byte ERR = 0x82;     // payload: stderr bytes
        public const byte EXIT = 0x83;    // payload: uint32 exit status
        public const byte DONE = 0x84;    // no payload: channel finished
        public const byte HELLO = 0x85;   // payload: UTF-8 remote account name
        public const byte FAIL = 0x86;    // payload: UTF-8 message
    }

    public static class Frame
    {
        public const int HEADER = 5;

        public static byte[] Make(byte type, uint channel, byte[] payload)
        {
            int n = (payload == null) ? 0 : payload.Length;
            byte[] f = new byte[HEADER + n];
            f[0] = type;
            f[1] = (byte)(channel >> 24); f[2] = (byte)(channel >> 16);
            f[3] = (byte)(channel >> 8); f[4] = (byte)channel;
            if (n > 0) Array.Copy(payload, 0, f, HEADER, n);
            return f;
        }

        public static byte[] Make(byte type, uint channel, byte[] payload, int offset, int count)
        {
            byte[] f = new byte[HEADER + count];
            f[0] = type;
            f[1] = (byte)(channel >> 24); f[2] = (byte)(channel >> 16);
            f[3] = (byte)(channel >> 8); f[4] = (byte)channel;
            if (count > 0) Array.Copy(payload, offset, f, HEADER, count);
            return f;
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

    // -------------------------------------------------------------- client contracts

    public interface IPwsshAgent
    {
        void Attach(IPwsshChannelSink sink);
        void Exec(uint channel, string command);
        void SendStdin(uint channel, byte[] data);
        void CloseStdin(uint channel);
        void CloseChannel(uint channel);
        void GrantWindow(uint channel, uint bytes);
        // Blocks for the agent's HELLO. The local SSH handshake is instant now, so userauth
        // can arrive before HELLO has made the round trip; blocking here lets session setup
        // and the handshake overlap instead of serialising.
        string WaitForRemoteUser(int timeoutMs);
    }

    public interface IPwsshChannelSink
    {
        void OnData(uint channel, byte[] data, bool stderr);
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
        private volatile bool inboundClosed;

        public void Attach(IPwsshChannelSink s) { sink = s; }

        public bool InboundClosed { get { return inboundClosed; } }

        // Transport side: drain frames to send to the remote.
        public byte[] TakeOutboundFrame(int timeoutMs) { return outbound.Take(timeoutMs); }

        public void PushInbound(byte[] frame)
        {
            if (!Frame.IsValid(frame)) return;
            byte type = Frame.Type(frame);
            uint ch = Frame.Channel(frame);

            switch (type)
            {
                case FrameType.OUT:
                    if (sink != null) sink.OnData(ch, Frame.Payload(frame), false);
                    break;
                case FrameType.ERR:
                    if (sink != null) sink.OnData(ch, Frame.Payload(frame), true);
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
                        remoteUser = Frame.PayloadText(frame);
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
        // Granted at EXEC and topped up by WINDOW frames. Large and eagerly refilled: each
        // WINDOW frame costs a full WinRM turnaround, so a small window would stall bulk
        // output once per round trip.
        public const uint INITIAL_CREDIT = 8 * 1024 * 1024;

        private readonly FrameQueue outbound = new FrameQueue();
        private readonly Dictionary<uint, AgentChannel> channels = new Dictionary<uint, AgentChannel>();
        private readonly object chanGate = new object();
        private readonly Queue<string> logQ = new Queue<string>();

        private volatile bool finished;
        private int lastInboundTick = Environment.TickCount;

        // If the client vanishes without closing the session the pipeline would otherwise
        // block forever and hold a WinRM shell until WinRM's own 2-hour timeout. 0 disables.
        public int InactivityTimeoutSeconds = 300;

        public bool Finished { get { return finished; } }

        public void Start()
        {
            string user;
            try { user = CurrentAccountName(); }
            catch (Exception ex) { user = ""; Log("cannot resolve current user: " + ex.Message); }
            outbound.Enqueue(Frame.MakeText(FrameType.HELLO, 0, user));
            Log("agent ready as '" + user + "'");

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

        internal void Send(byte[] frame) { outbound.Enqueue(frame); }

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
                        StartChannel(ch, Frame.PayloadText(frame));
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
                outbound.Enqueue(Frame.MakeText(FrameType.FAIL, ch, ex.Message));
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
                    outbound.Enqueue(Frame.MakeText(FrameType.FAIL, ch, "channel already in use"));
                    return;
                }
                channels[ch] = c;
            }
            Log("exec on channel " + ch + ": " + command);
            if (!c.StartExec(command))
            {
                outbound.Enqueue(Frame.MakeText(FrameType.FAIL, ch, "could not start command"));
                Forget(ch);
            }
        }

        internal void Forget(uint ch)
        {
            lock (chanGate) { channels.Remove(ch); }
        }
    }

    // ------------------------------------------------------------------ agent channel

    internal sealed class AgentChannel
    {
        private const int READ_BUFFER = 65536;

        private readonly PwsshAgentHost host;
        private readonly uint channel;
        private readonly object creditGate = new object();
        private long credit = PwsshAgentHost.INITIAL_CREDIT;

        private Process proc;
        private int pumpsDone;
        private volatile bool killed;

        public AgentChannel(PwsshAgentHost h, uint ch) { host = h; channel = ch; }

        public void AddCredit(uint add)
        {
            lock (creditGate) { credit += add; Monitor.PulseAll(creditGate); }
        }

        public bool StartExec(string command)
        {
            if (proc != null) return false;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Environment.GetEnvironmentVariable("ComSpec");
                if (string.IsNullOrEmpty(psi.FileName)) psi.FileName = "cmd.exe";
                psi.Arguments = "/c " + command;
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardInput = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                proc = Process.Start(psi);

                StartPump(proc.StandardOutput.BaseStream, false);
                StartPump(proc.StandardError.BaseStream, true);

                Thread wait = new Thread(new ThreadStart(WaitForExit));
                wait.IsBackground = true;
                wait.Start();
                return true;
            }
            catch (Exception ex)
            {
                host.Log("exec failed: " + ex.Message);
                return false;
            }
        }

        private void StartPump(Stream src, bool isStderr)
        {
            Thread t = new Thread(new ThreadStart(delegate { Pump(src, isStderr); }));
            t.IsBackground = true;
            t.Start();
        }

        // Raw BaseStream only. PowerShell's native-command bridge decodes as text and splits
        // lines, which destroys binary: measured 128 of 256 byte values lost.
        private void Pump(Stream src, bool isStderr)
        {
            byte[] buf = new byte[READ_BUFFER];
            try
            {
                while (!killed)
                {
                    int n = src.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
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
                host.Send(Frame.Make(isStderr ? FrameType.ERR : FrameType.OUT, channel, buf, off, allowed));
                off += allowed;
            }
        }

        public void WriteStdin(byte[] frame, int offset, int count)
        {
            try
            {
                if (proc != null && !proc.HasExited && count > 0)
                {
                    proc.StandardInput.BaseStream.Write(frame, offset, count);
                    proc.StandardInput.BaseStream.Flush();
                }
            }
            catch (Exception ex) { host.Log("stdin write failed: " + ex.Message); }
        }

        public void CloseStdin()
        {
            try { if (proc != null) proc.StandardInput.BaseStream.Close(); } catch { }
        }

        private void WaitForExit()
        {
            try
            {
                proc.WaitForExit();
                // Drain both pumps so no output is lost before the exit status.
                for (int i = 0; i < 200 && pumpsDone < 2; i++) Thread.Sleep(10);

                uint code = (uint)proc.ExitCode;
                host.Log("channel " + channel + " exited " + code);
                host.Send(Frame.MakeUInt32(FrameType.EXIT, channel, code));
                host.Send(Frame.Make(FrameType.DONE, channel, null));
            }
            catch (Exception ex)
            {
                host.Log("wait failed: " + ex.Message);
                host.Send(Frame.MakeText(FrameType.FAIL, channel, ex.Message));
            }
            finally
            {
                host.Forget(channel);
            }
        }

        public void Kill()
        {
            killed = true;
            lock (creditGate) { Monitor.PulseAll(creditGate); }
            try { if (proc != null && !proc.HasExited) proc.Kill(); } catch { }
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
