// Drives the scp protocol directly, with no SSH and no engine in the loop.
//
// This is the LOAD-BEARING harness for the feature, not a convenience. Both this machine and the
// WinRM remote have a real scp.exe on PATH, so if the agent failed to recognise the command the
// exec would fall through to that binary and the transfer would succeed anyway -- an end-to-end
// test cannot tell the two apart from the outcome. Here the host is constructed directly, so no
// external binary can possibly be involved.
//
// It is also the only way to reach what no client will send: a hostile filename, a C line whose
// size disagrees with the bytes after it, a nacked control record.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Pwssh;

namespace Pwssh.Tests
{
    internal sealed class AgentScpDriver : IDisposable
    {
        private const uint Channel = 1;

        private readonly PwsshAgentHost host;
        private readonly MemoryStream pending = new MemoryStream();
        private int consumed;

        /// <summary>Starts an scp channel by pushing the EXEC frame a client would send.</summary>
        public AgentScpDriver(string command)
        {
            host = new PwsshAgentHost();
            host.Start();
            host.PushInbound(Frame.MakeText(FrameType.EXEC, Channel, command));
        }

        public string[] Log { get { return host.DrainLog(); } }

        public void Send(byte[] data)
        {
            host.PushInbound(Frame.Make(FrameType.DATA, Channel, data));
        }

        public void SendText(string s) { Send(Encoding.UTF8.GetBytes(s)); }
        public void SendByte(byte b) { Send(new byte[] { b }); }
        public void SendEof() { host.PushInbound(Frame.Make(FrameType.EOF, Channel, new byte[0])); }

        /// <summary>
        /// Reads exactly n bytes of whatever the agent has sent, waiting for them to arrive.
        /// Bounded, because a missing byte is one of the failures worth testing for and this
        /// protocol has no timeout of its own to rescue it.
        /// </summary>
        public byte[] Read(int n, int timeoutMs = 15000)
        {
            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (Available < n)
            {
                int remaining = unchecked(deadline - Environment.TickCount);
                if (remaining <= 0)
                    throw new TimeoutException("wanted " + n + " bytes, have " + Available + " after " + timeoutMs + " ms");
                Pump(Math.Min(remaining, 200));
            }
            byte[] all = pending.ToArray();
            byte[] outp = new byte[n];
            Array.Copy(all, consumed, outp, 0, n);
            consumed += n;
            return outp;
        }

        public byte ReadByte1() { return Read(1)[0]; }

        /// <summary>One status byte, decoded. Returns 0/1/2; the message is consumed for 1 and 2.</summary>
        public int ReadStatus(out string message)
        {
            message = null;
            byte b = ReadByte1();
            if (b == 1 || b == 2) message = ReadLine();
            return b;
        }

        public int ReadStatus() { string ignored; return ReadStatus(out ignored); }

        public string ReadLine(int timeoutMs = 15000)
        {
            List<byte> line = new List<byte>();
            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (true)
            {
                if (Available < 1)
                {
                    int remaining = unchecked(deadline - Environment.TickCount);
                    if (remaining <= 0) throw new TimeoutException("no newline within " + timeoutMs + " ms");
                    Pump(Math.Min(remaining, 200));
                    continue;
                }
                byte b = ReadByte1();
                if (b == (byte)'\n') break;
                line.Add(b);
            }
            return Encoding.UTF8.GetString(line.ToArray());
        }

        /// <summary>True once the channel has finished, i.e. DONE arrived.</summary>
        public bool Finished { get { Pump(50); return done; } }
        public uint ExitStatus { get { return exit; } }

        private bool done;
        private uint exit = 0xFFFFFFFF;

        public uint WaitForExit(int timeoutMs = 15000)
        {
            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (!done)
            {
                int remaining = unchecked(deadline - Environment.TickCount);
                if (remaining <= 0) throw new TimeoutException("channel did not finish within " + timeoutMs + " ms");
                Pump(Math.Min(remaining, 200));
            }
            return exit;
        }

        private int Available { get { return (int)pending.Length - consumed; } }

        private void Pump(int timeoutMs)
        {
            byte[] frame = host.TakeOutboundFrame(timeoutMs);
            if (frame == null) return;

            // The agent compresses whenever deflate saves an eighth, so matching on the raw type
            // byte alone misses most frames -- the same trap the SFTP driver hit first.
            byte raw = Frame.Type(frame);
            bool compressed = (raw & FrameType.COMPRESSED) != 0;
            byte type = (byte)(raw & ~FrameType.COMPRESSED);

            if (Frame.Channel(frame) != Channel) return;
            if (type == FrameType.EXIT) { exit = Frame.PayloadUInt32(frame); return; }
            if (type == FrameType.DONE) { done = true; return; }
            if (type == FrameType.FAIL) throw new IOException("agent reported failure: " + Frame.PayloadText(frame));
            if (type != FrameType.OUT) return;

            byte[] payload;
            if (compressed)
            {
                payload = Zip.Inflate(frame, Frame.HEADER, frame.Length - Frame.HEADER);
            }
            else
            {
                payload = new byte[frame.Length - Frame.HEADER];
                Array.Copy(frame, Frame.HEADER, payload, 0, payload.Length);
            }
            pending.Write(payload, 0, payload.Length);
        }

        public void Dispose()
        {
            try { host.PushInbound(Frame.Make(FrameType.CLOSE, Channel, new byte[0])); } catch { }
            try { host.Stop(); } catch { }
        }

        // ---------------------------------------------------------------- record builders

        public static string CFile(string mode, long size, string name)
        {
            return "C" + mode + " " + size + " " + name + "\n";
        }
        public static string DDir(string mode, string name) { return "D" + mode + " 0 " + name + "\n"; }
        public static string Times(long mtime, long atime) { return "T" + mtime + " 0 " + atime + " 0\n"; }
    }
}
