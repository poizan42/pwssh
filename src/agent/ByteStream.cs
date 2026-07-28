// Producer/consumer byte and frame queues, the inbound pump, and downstream striping.
//
// Part of the pwssh remote agent. Built to a .NET Framework 4.8 DLL by
// src/agent/PwsshAgent.csproj and pushed to the remote; also compiled together with
// the engine on the client, so it must stay free of any client-only dependency.

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
}
