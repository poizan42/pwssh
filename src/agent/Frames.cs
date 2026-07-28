// The frame protocol, and the plumbing both sides share.
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
}
