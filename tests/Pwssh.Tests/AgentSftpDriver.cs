// Drives the SFTP server directly, with no SSH and no engine in the loop.
//
// The point is reach. SSH.NET's SftpClient can only send what its API models, so a whole class of
// requests is unreachable from it: a forged or stale handle, an unknown extension name, `statvfs`,
// `fsync`, `hardlink`, `lsetstat`, an INIT claiming version 4. Those are exactly the paths with no
// coverage today, because the stock `sftp` client has no command for them either.
//
// It goes through the real frame protocol rather than constructing AgentSftpChannel, which keeps the
// tests off a constructor signature and exercises the same dispatch the engine drives: a SUBSYSTEM
// frame opens the channel, DATA frames carry requests, OUT frames carry replies. Reachable because
// the test project compiles the product sources in.
//
// Deliberately synchronous and unpipelined: one request, one reply, asserted. Throughput is not what
// this layer is for, and serialising makes a missing reply show up as a timeout on the request that
// caused it rather than as a confusing hang later.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Pwssh;

namespace Pwssh.Tests
{
    internal sealed class AgentSftpDriver : IDisposable
    {
        private const uint Channel = 1;

        private readonly PwsshAgentHost host;
        private readonly MemoryStream pending = new MemoryStream();
        private uint nextId = 1;

        public AgentSftpDriver()
        {
            host = new PwsshAgentHost();
            host.Start();
            host.PushInbound(Frame.MakeText(FrameType.SUBSYSTEM, Channel, "sftp"));
        }

        public uint NextId()
        {
            return nextId++;
        }

        /// <summary>Sends one already-framed SFTP packet (with its 4-byte length prefix).</summary>
        public void Send(byte[] packet)
        {
            host.PushInbound(Frame.Make(FrameType.DATA, Channel, packet));
        }

        /// <summary>
        /// Reads the next complete SFTP reply, returning its body: type byte first, length prefix
        /// stripped. Bounded, because a missing reply is one of the failures worth testing for and
        /// SFTP itself has no timeout to rescue it.
        /// </summary>
        public byte[] Receive(int timeoutMs = 15000)
        {
            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (true)
            {
                byte[] msg = TakeBuffered();
                if (msg != null) return msg;

                int remaining = unchecked(deadline - Environment.TickCount);
                if (remaining <= 0) throw new TimeoutException("no SFTP reply within " + timeoutMs + " ms");

                byte[] frame = host.TakeOutboundFrame(Math.Min(remaining, 200));
                if (frame == null) continue;

                // The type byte carries a compression flag, and the agent sets it whenever deflate
                // saves at least an eighth -- which an SFTP reply comfortably does, so in practice
                // every reply arrives as OUT|COMPRESSED (0xC1) rather than OUT (0x81). Matching on
                // the raw byte therefore sees nothing at all, which is how this driver first failed.
                // Same decode as PwsshAgentProxy: strip the flag, then inflate.
                byte raw = Frame.Type(frame);
                bool compressed = (raw & FrameType.COMPRESSED) != 0;
                byte type = (byte)(raw & ~FrameType.COMPRESSED);

                // FAIL is worth surfacing rather than waiting out the timeout on; HELLO and anything
                // on another channel is simply not ours.
                if (type == FrameType.FAIL)
                    throw new IOException("agent reported failure: " + Frame.PayloadText(frame));
                if (type != FrameType.OUT || Frame.Channel(frame) != Channel) continue;

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

                byte[] all = pending.ToArray();
                pending.SetLength(0);
                pending.Write(all, 0, all.Length);
                pending.Write(payload, 0, payload.Length);
            }
        }

        private byte[] TakeBuffered()
        {
            byte[] buf = pending.ToArray();
            if (buf.Length < 4) return null;
            int len = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
            if (len <= 0 || buf.Length < 4 + len) return null;

            byte[] msg = new byte[len];
            Array.Copy(buf, 4, msg, 0, len);

            pending.SetLength(0);
            pending.Write(buf, 4 + len, buf.Length - 4 - len);
            return msg;
        }

        public void Dispose()
        {
            try { host.PushInbound(Frame.Make(FrameType.CLOSE, Channel, new byte[0])); } catch { }
            try { host.Stop(); } catch { }
        }

        // ------------------------------------------------------------------ request builders

        public static byte[] Init(uint version)
        {
            Writer w = new Writer();
            w.Byte(SftpTypeByte.Init);
            w.UInt32(version);
            return w.Framed();
        }

        /// <summary>A request shaped as type, id, then one string. Covers READLINK and REALPATH.</summary>
        public static byte[] OneString(byte type, uint id, string s)
        {
            Writer w = new Writer();
            w.Byte(type);
            w.UInt32(id);
            w.Text(s);
            return w.Framed();
        }

        public static byte[] TwoStrings(byte type, uint id, string a, string b)
        {
            Writer w = new Writer();
            w.Byte(type);
            w.UInt32(id);
            w.Text(a);
            w.Text(b);
            return w.Framed();
        }

        public static byte[] Read(uint id, string handle, ulong offset, uint length)
        {
            Writer w = new Writer();
            w.Byte(SftpTypeByte.Read);
            w.UInt32(id);
            w.Text(handle);
            w.UInt64(offset);
            w.UInt32(length);
            return w.Framed();
        }

        /// <summary>
        /// SSH_FXP_SYMLINK, with the arguments named so the order cannot be got wrong silently.
        /// OpenSSH sends them in the REVERSE of the draft's order — target first, then the link —
        /// and a swapped implementation creates the link under the wrong name with no error at all.
        /// Observed on the wire: `Sending SSH2_FXP_SYMLINK "TARGETSTRING-aaa" to "/C:/LINKSTRING-bbb"`.
        /// </summary>
        public static byte[] Symlink(uint id, string targetPath, string linkPath)
        {
            return TwoStrings(SftpTypeByte.Symlink, id, targetPath, linkPath);
        }

        /// <summary>The single name a REALPATH or READLINK reply carries.</summary>
        public static string ParseName(byte[] msg)
        {
            if (msg[0] != SftpTypeByte.Name)
                throw new InvalidDataException("expected NAME, got type " + msg[0]);
            Reader r = new Reader(msg, 1);
            r.UInt32();                                  // request id
            uint count = r.UInt32();
            if (count != 1) throw new InvalidDataException("expected exactly one name, got " + count);
            return r.Text();
        }

        public static byte[] Extended(uint id, string name)
        {
            Writer w = new Writer();
            w.Byte(SftpTypeByte.Extended);
            w.UInt32(id);
            w.Text(name);
            return w.Framed();
        }

        // ------------------------------------------------------------------ reply parsing

        /// <summary>The message type byte of a reply body.</summary>
        public static byte TypeOf(byte[] msg)
        {
            return msg[0];
        }

        /// <summary>The size an ATTRS reply carries, or -1 when it carries none.</summary>
        public static long SizeOf(byte[] msg)
        {
            if (msg[0] != SftpTypeByte.Attrs)
                throw new InvalidDataException("expected ATTRS, got type " + msg[0]);
            Reader r = new Reader(msg, 1);
            r.UInt32();                                  // request id
            uint flags = r.UInt32();
            if ((flags & 0x1) == 0) return -1;
            return ((long)r.UInt32() << 32) | r.UInt32();
        }

        /// <summary>
        /// Whether an ATTRS reply's permission word carries S_IFLNK. Layout is
        /// type, id, flags, [size], [uid, gid], [permissions], [atime, mtime] — the optional fields
        /// present only when their flag bit is set, so they have to be walked rather than indexed.
        /// </summary>
        public static bool IsSymlinkMode(byte[] msg)
        {
            if (msg[0] != SftpTypeByte.Attrs)
                throw new InvalidDataException("expected ATTRS, got type " + msg[0]);
            Reader r = new Reader(msg, 1);
            r.UInt32();                                  // request id
            uint flags = r.UInt32();
            if ((flags & 0x1) != 0) { r.UInt32(); r.UInt32(); }      // SIZE, a uint64
            if ((flags & 0x2) != 0) { r.UInt32(); r.UInt32(); }      // UIDGID
            if ((flags & 0x4) == 0) return false;                    // no PERMISSIONS to inspect
            uint mode = r.UInt32();
            return (mode & 0xF000) == 0xA000;                        // S_IFLNK
        }

        public sealed class Status
        {
            public uint Id;
            public uint Code;
            public string Message;
        }

        public static Status ParseStatus(byte[] msg)
        {
            if (msg[0] != SftpTypeByte.Status)
                throw new InvalidDataException("expected STATUS, got type " + msg[0]);
            Reader r = new Reader(msg, 1);
            Status s = new Status();
            s.Id = r.UInt32();
            s.Code = r.UInt32();
            s.Message = r.Remaining >= 4 ? r.Text() : null;
            return s;
        }

        /// <summary>Parses a VERSION reply into its version number and extension name/value pairs.</summary>
        public static void ParseVersion(byte[] msg, out uint version, out Dictionary<string, string> extensions)
        {
            if (msg[0] != SftpTypeByte.Version)
                throw new InvalidDataException("expected VERSION, got type " + msg[0]);
            Reader r = new Reader(msg, 1);
            version = r.UInt32();
            extensions = new Dictionary<string, string>(StringComparer.Ordinal);
            while (r.Remaining >= 4)
            {
                string name = r.Text();
                string value = r.Remaining >= 4 ? r.Text() : "";
                extensions[name] = value;
            }
        }

        /// <summary>The type bytes this driver needs, mirroring SftpType in src/agent/Sftp.cs.</summary>
        internal static class SftpTypeByte
        {
            public const byte Init = 1;
            public const byte Version = 2;
            public const byte Read = 5;
            public const byte Stat = 17;
            public const byte Lstat = 7;
            public const byte Attrs = 105;
            public const byte Realpath = 16;
            public const byte ReadLink = 19;
            public const byte Symlink = 20;
            public const byte Status = 101;
            public const byte Handle = 102;
            public const byte Name = 104;
            public const byte Extended = 200;
            public const byte ExtendedReply = 201;
        }

        /// <summary>Status codes, mirroring SftpStatus.</summary>
        internal static class StatusCode
        {
            public const uint Ok = 0;
            public const uint Eof = 1;
            public const uint NoSuchFile = 2;
            public const uint PermissionDenied = 3;
            public const uint Failure = 4;
            public const uint BadMessage = 5;
            public const uint OpUnsupported = 8;
        }

        // Minimal SSH-style writer/reader. The product's own SshLikeWriter is internal to the
        // read-ahead file and shaped for its needs; these are three methods and no coupling.
        private sealed class Writer
        {
            private readonly MemoryStream m = new MemoryStream();

            public void Byte(byte b) { m.WriteByte(b); }

            public void UInt32(uint v)
            {
                m.WriteByte((byte)(v >> 24)); m.WriteByte((byte)(v >> 16));
                m.WriteByte((byte)(v >> 8)); m.WriteByte((byte)v);
            }

            public void UInt64(ulong v)
            {
                UInt32((uint)(v >> 32));
                UInt32((uint)v);
            }

            public void Text(string s)
            {
                byte[] b = Encoding.UTF8.GetBytes(s ?? "");
                UInt32((uint)b.Length);
                m.Write(b, 0, b.Length);
            }

            /// <summary>The body with its 4-byte length prefix, which is what goes on the wire.</summary>
            public byte[] Framed()
            {
                byte[] body = m.ToArray();
                byte[] all = new byte[4 + body.Length];
                all[0] = (byte)(body.Length >> 24); all[1] = (byte)(body.Length >> 16);
                all[2] = (byte)(body.Length >> 8); all[3] = (byte)body.Length;
                Array.Copy(body, 0, all, 4, body.Length);
                return all;
            }
        }

        private sealed class Reader
        {
            private readonly byte[] b;
            private int i;

            public Reader(byte[] buffer, int offset) { b = buffer; i = offset; }

            public int Remaining { get { return b.Length - i; } }

            public uint UInt32()
            {
                uint v = (uint)((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]);
                i += 4;
                return v;
            }

            public string Text()
            {
                int n = (int)UInt32();
                string s = Encoding.UTF8.GetString(b, i, n);
                i += n;
                return s;
            }
        }
    }
}
