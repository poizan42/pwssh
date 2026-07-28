// pwssh SSH engine.
//
// Must compile as C# 5 (the .NET Framework 4.8 CodeDOM compiler used by Add-Type on
// Windows PowerShell 5.1): no string interpolation, no ?., no out-var, no tuples,
// no expression-bodied members.
//
// Transport agnostic: bytes in via PushInbound, bytes out via TakeOutbound. SSH needs a
// byte stream but WinRM delivers discrete messages, so reassembly lives here.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Pwssh
{
    public sealed class PwsshConfig
    {
        public string HostKey;              // opaque blob from PwsshKey.Generate
        // Optional: when unset it is resolved from the agent's HELLO frame at userauth time.
        public string ExpectedUser;
        public string ServerIdent = "SSH-2.0-pwssh_0.1";
        // Where channels actually run. Never null in practice.
        public IPwsshAgent Agent;

        // If the client vanishes without closing the session, the remote pipeline would
        // otherwise block forever and hold a WinRM shell until WinRM's own (2 hour)
        // timeout. Bounded here instead. 0 disables.
        public int InactivityTimeoutSeconds = 300;
    }

    // Host key persistence. Deliberately not ToXmlString/FromXmlString: their support
    // differs between .NET Framework 4.8 and .NET 8+, and the same engine runs on both.
    public static class PwsshKey
    {
        public static string Generate(int bits)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(bits);
            try { return Export(rsa.ExportParameters(true)); }
            finally { rsa.Clear(); }
        }

        public static string Export(RSAParameters p)
        {
            SshWriter w = new SshWriter();
            w.Str(p.Modulus); w.Str(p.Exponent); w.Str(p.D);
            w.Str(p.P); w.Str(p.Q); w.Str(p.DP); w.Str(p.DQ); w.Str(p.InverseQ);
            return Convert.ToBase64String(w.ToArray());
        }

        public static RSAParameters Import(string blob)
        {
            SshReader r = new SshReader(Convert.FromBase64String(blob));
            RSAParameters p = new RSAParameters();
            p.Modulus = r.Str(); p.Exponent = r.Str(); p.D = r.Str();
            p.P = r.Str(); p.Q = r.Str(); p.DP = r.Str(); p.DQ = r.Str(); p.InverseQ = r.Str();
            return p;
        }
    }

    internal static class Msg
    {
        public const byte DISCONNECT = 1, IGNORE = 2, UNIMPLEMENTED = 3, DEBUG = 4,
            SERVICE_REQUEST = 5, SERVICE_ACCEPT = 6, EXT_INFO = 7,
            KEXINIT = 20, NEWKEYS = 21,
            KEXDH_INIT = 30, KEXDH_REPLY = 31,
            USERAUTH_REQUEST = 50, USERAUTH_FAILURE = 51, USERAUTH_SUCCESS = 52,
            GLOBAL_REQUEST = 80, REQUEST_SUCCESS = 81, REQUEST_FAILURE = 82,
            CHANNEL_OPEN = 90, CHANNEL_OPEN_CONFIRMATION = 91, CHANNEL_OPEN_FAILURE = 92,
            CHANNEL_WINDOW_ADJUST = 93, CHANNEL_DATA = 94, CHANNEL_EXTENDED_DATA = 95,
            CHANNEL_EOF = 96, CHANNEL_CLOSE = 97, CHANNEL_REQUEST = 98,
            CHANNEL_SUCCESS = 99, CHANNEL_FAILURE = 100;
    }

    // ---------------------------------------------------------------- wire types

    internal sealed class SshWriter
    {
        private readonly MemoryStream ms = new MemoryStream();

        public void Byte(byte b) { ms.WriteByte(b); }
        public void Raw(byte[] b) { ms.Write(b, 0, b.Length); }
        public void Bool(bool v) { ms.WriteByte(v ? (byte)1 : (byte)0); }

        public void UInt32(uint v)
        {
            ms.WriteByte((byte)(v >> 24)); ms.WriteByte((byte)(v >> 16));
            ms.WriteByte((byte)(v >> 8)); ms.WriteByte((byte)v);
        }

        public void Str(byte[] s) { UInt32((uint)s.Length); ms.Write(s, 0, s.Length); }
        public void Str(string s) { Str(Encoding.UTF8.GetBytes(s)); }
        public void NameList(string[] names) { Str(string.Join(",", names)); }

        public void MpInt(BigInteger v)
        {
            if (v.Sign == 0) { Str(new byte[0]); return; }
            byte[] le = v.ToByteArray();          // little-endian two's complement
            Array.Reverse(le);                    // -> big-endian
            int i = 0;
            while (i < le.Length - 1 && le[i] == 0 && (le[i + 1] & 0x80) == 0) i++;
            byte[] o = new byte[le.Length - i];
            Array.Copy(le, i, o, 0, o.Length);
            Str(o);
        }

        public byte[] ToArray() { return ms.ToArray(); }
    }

    internal sealed class SshReader
    {
        private readonly byte[] b;
        private int p;

        public SshReader(byte[] data) { b = data; p = 0; }

        public byte Byte() { return b[p++]; }
        public bool Bool() { return b[p++] != 0; }

        public uint UInt32()
        {
            uint v = ((uint)b[p] << 24) | ((uint)b[p + 1] << 16) | ((uint)b[p + 2] << 8) | b[p + 3];
            p += 4; return v;
        }

        public byte[] Str()
        {
            int n = (int)UInt32();
            if (n < 0 || p + n > b.Length) throw new Exception("malformed string field");
            byte[] o = new byte[n];
            Array.Copy(b, p, o, 0, n);
            p += n;
            return o;
        }

        public string StrUtf8() { return Encoding.UTF8.GetString(Str()); }

        public BigInteger MpInt()
        {
            byte[] s = Str();
            if (s.Length == 0) return BigInteger.Zero;
            byte[] le = new byte[s.Length + 1];   // extra zero keeps it positive
            for (int i = 0; i < s.Length; i++) le[i] = s[s.Length - 1 - i];
            return new BigInteger(le);
        }

        public bool AtEnd { get { return p >= b.Length; } }
    }

    // ByteChannel and PwsshPump now live in PwsshAgent.cs, which has to be self-contained
    // because the remote can only compile a single source string. This file is always
    // compiled together with it (Add-Type -Path on the client).

    // ------------------------------------------------------------------ AES-256-CTR

    internal sealed class AesCtr
    {
        // The keystream is produced in bulk. Calling TransformBlock once per 16-byte block
        // costs a CNG transition per block and measured ~0.16 MiB/s end to end; batching
        // 256 blocks per call removes that entirely. ECB has no chaining, so encrypting a
        // buffer of consecutive counter blocks is identical to encrypting them one by one.
        private const int BATCH = 4096;

        private readonly ICryptoTransform ecb;
        private readonly byte[] counter = new byte[16];
        private readonly byte[] ctrBuf = new byte[BATCH];
        private readonly byte[] ks = new byte[BATCH];
        private int ksPos = BATCH;

        public AesCtr(byte[] key, byte[] iv)
        {
            SymmetricAlgorithm aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = new byte[16];
            ecb = aes.CreateEncryptor();
            Array.Copy(iv, 0, counter, 0, 16);
        }

        private void Refill()
        {
            for (int off = 0; off < BATCH; off += 16)
            {
                Array.Copy(counter, 0, ctrBuf, off, 16);
                Increment();
            }
            ecb.TransformBlock(ctrBuf, 0, BATCH, ks, 0);
            ksPos = 0;
        }

        public void Xor(byte[] data, int off, int len)
        {
            int i = 0;
            while (i < len)
            {
                if (ksPos >= BATCH) Refill();
                int n = Math.Min(len - i, BATCH - ksPos);
                for (int j = 0; j < n; j++) data[off + i + j] ^= ks[ksPos + j];
                ksPos += n;
                i += n;
            }
        }

        private void Increment()
        {
            for (int i = 15; i >= 0; i--) { counter[i]++; if (counter[i] != 0) break; }
        }
    }

    // --------------------------------------------------------------- packet layer

    internal sealed class PacketLayer
    {
        private readonly ByteChannel inb;
        private readonly ByteChannel outb;
        private readonly object writeGate = new object();
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private uint seqIn, seqOut;
        private AesCtr encOut, decIn;
        private HMACSHA256 macOut, macIn;
        private bool encrypted;

        public PacketLayer(ByteChannel inbound, ByteChannel outbound)
        {
            inb = inbound; outb = outbound;
        }

        public void EnableEncryption(byte[] ivC2S, byte[] keyC2S, byte[] macC2S,
                                    byte[] ivS2C, byte[] keyS2C, byte[] macS2C)
        {
            lock (writeGate)
            {
                decIn = new AesCtr(keyC2S, ivC2S);
                macIn = new HMACSHA256(macC2S);
                encOut = new AesCtr(keyS2C, ivS2C);
                macOut = new HMACSHA256(macS2C);
                encrypted = true;
            }
        }

        private static void PutBE(byte[] b, int off, uint v)
        {
            b[off] = (byte)(v >> 24); b[off + 1] = (byte)(v >> 16);
            b[off + 2] = (byte)(v >> 8); b[off + 3] = (byte)v;
        }

        private static uint GetBE(byte[] b, int off)
        {
            return ((uint)b[off] << 24) | ((uint)b[off + 1] << 16) | ((uint)b[off + 2] << 8) | b[off + 3];
        }

        public byte[] ReadPacket()
        {
            if (!encrypted)
            {
                byte[] hdr = new byte[5];
                inb.ReadExact(hdr, 0, 5);
                uint len = GetBE(hdr, 0);
                if (len < 5 || len > 262144) throw new Exception("bad packet length " + len);
                byte pad = hdr[4];
                byte[] rest = new byte[len - 1];
                inb.ReadExact(rest, 0, rest.Length);
                seqIn++;
                int payloadLen = (int)len - 1 - pad;
                if (payloadLen < 0) throw new Exception("bad padding");
                byte[] payload = new byte[payloadLen];
                Array.Copy(rest, 0, payload, 0, payloadLen);
                return payload;
            }
            else
            {
                // ETM: length plaintext, then encrypted(padlen||payload||pad), then MAC.
                byte[] lenb = new byte[4];
                inb.ReadExact(lenb, 0, 4);
                uint len = GetBE(lenb, 0);
                if (len < 16 || len > 1048576 || (len % 16) != 0)
                    throw new Exception("bad encrypted packet length " + len);
                byte[] ct = new byte[len];
                inb.ReadExact(ct, 0, ct.Length);
                byte[] mac = new byte[32];
                inb.ReadExact(mac, 0, 32);

                // Hashed incrementally: the previous version copied the whole ciphertext into
                // a scratch buffer for every packet purely to compute the MAC.
                byte[] pre = new byte[8];
                PutBE(pre, 0, seqIn);
                Array.Copy(lenb, 0, pre, 4, 4);
                macIn.Initialize();
                macIn.TransformBlock(pre, 0, 8, null, 0);
                macIn.TransformFinalBlock(ct, 0, ct.Length);
                if (!ConstantTimeEquals(macIn.Hash, mac)) throw new Exception("MAC verification failed");

                decIn.Xor(ct, 0, ct.Length);
                seqIn++;
                byte pad = ct[0];
                int payloadLen = ct.Length - 1 - pad;
                if (payloadLen < 0 || pad < 4) throw new Exception("bad padding");
                byte[] payload = new byte[payloadLen];
                Array.Copy(ct, 1, payload, 0, payloadLen);
                return payload;
            }
        }

        public void WritePacket(byte[] payload)
        {
            lock (writeGate)
            {
                if (!encrypted)
                {
                    int blk = 8;
                    int padLen = blk - ((5 + payload.Length) % blk);
                    if (padLen < 4) padLen += blk;
                    uint pktLen = (uint)(1 + payload.Length + padLen);
                    byte[] outb2 = new byte[4 + pktLen];
                    PutBE(outb2, 0, pktLen);
                    outb2[4] = (byte)padLen;
                    Array.Copy(payload, 0, outb2, 5, payload.Length);
                    byte[] pad = new byte[padLen];
                    rng.GetBytes(pad);
                    Array.Copy(pad, 0, outb2, 5 + payload.Length, padLen);
                    seqOut++;
                    outb.Write(outb2);
                }
                else
                {
                    int blk = 16;
                    int padLen = blk - ((1 + payload.Length) % blk);
                    if (padLen < 4) padLen += blk;
                    int encLen = 1 + payload.Length + padLen;

                    // Assembled straight into the final buffer: length, padding count,
                    // payload, random padding, then encrypt and MAC in place.
                    byte[] frame = new byte[4 + encLen + 32];
                    PutBE(frame, 0, (uint)encLen);
                    frame[4] = (byte)padLen;
                    Array.Copy(payload, 0, frame, 5, payload.Length);
                    rng.GetBytes(frame, 5 + payload.Length, padLen);

                    encOut.Xor(frame, 4, encLen);
                    AppendMac(frame, encLen);
                    seqOut++;
                    outb.WriteOwned(frame);
                }
            }
        }

        // MAC over seq || length || ciphertext, written into the tail of the frame.
        private void AppendMac(byte[] frame, int encLen)
        {
            byte[] pre = new byte[8];
            PutBE(pre, 0, seqOut);
            Array.Copy(frame, 0, pre, 4, 4);
            macOut.Initialize();
            macOut.TransformBlock(pre, 0, 8, null, 0);
            macOut.TransformFinalBlock(frame, 4, encLen);
            Array.Copy(macOut.Hash, 0, frame, 4 + encLen, 32);
        }

        // Channel data is the bulk path, so it gets a dedicated assembler: one copy of the
        // payload, versus four in the generic path (caller's slice, SshWriter's buffer,
        // ToArray, and packet assembly).
        public void WriteChannelData(uint channel, byte[] data, int offset, int count, bool stderr)
        {
            lock (writeGate)
            {
                if (!encrypted)
                {
                    // Channel data only flows after NEWKEYS; correct fallback regardless.
                    SshWriter w = new SshWriter();
                    if (stderr)
                    {
                        w.Byte(Msg.CHANNEL_EXTENDED_DATA); w.UInt32(channel); w.UInt32(1);
                    }
                    else
                    {
                        w.Byte(Msg.CHANNEL_DATA); w.UInt32(channel);
                    }
                    byte[] slice = new byte[count];
                    Array.Copy(data, offset, slice, 0, count);
                    w.Str(slice);
                    WritePacket(w.ToArray());
                    return;
                }

                int hdr = stderr ? 13 : 9;          // msg + channel [+ data type] + length
                int payloadLen = hdr + count;
                int blk = 16;
                int padLen = blk - ((1 + payloadLen) % blk);
                if (padLen < 4) padLen += blk;
                int encLen = 1 + payloadLen + padLen;

                byte[] frame = new byte[4 + encLen + 32];
                PutBE(frame, 0, (uint)encLen);
                int p = 4;
                frame[p++] = (byte)padLen;
                frame[p++] = stderr ? Msg.CHANNEL_EXTENDED_DATA : Msg.CHANNEL_DATA;
                PutBE(frame, p, channel); p += 4;
                if (stderr) { PutBE(frame, p, 1); p += 4; }   // SSH_EXTENDED_DATA_STDERR
                PutBE(frame, p, (uint)count); p += 4;
                Array.Copy(data, offset, frame, p, count); p += count;
                rng.GetBytes(frame, p, padLen);

                encOut.Xor(frame, 4, encLen);
                AppendMac(frame, encLen);
                seqOut++;
                outb.WriteOwned(frame);
            }
        }

        private static bool ConstantTimeEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            int d = 0;
            for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
            return d == 0;
        }
    }

    // ----------------------------------------------------------------------- engine

    public sealed class PwsshEngine : IByteReceiver, IPwsshChannelSink
    {
        private const string KEX_ALG = "diffie-hellman-group14-sha256";
        private const string HOSTKEY_ALG = "rsa-sha2-256";
        private const string CIPHER_ALG = "aes256-ctr";
        private const string MAC_ALG = "hmac-sha2-256-etm@openssh.com";

        private const uint INITIAL_WINDOW = 2 * 1024 * 1024;
        private const uint MAX_PACKET = 32768;

        // RFC 3526 group 14 (2048-bit MODP)
        private const string P_HEX =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
            "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

        private readonly PwsshConfig cfg;
        private readonly ByteChannel inbound = new ByteChannel();
        private readonly ByteChannel outbound = new ByteChannel();
        private PacketLayer pkt;
        private Thread worker;

        private volatile bool finished;
        private string lastError;

        private RSACryptoServiceProvider hostKey;
        private byte[] sessionId;
        private string clientIdent;
        private byte[] clientKexInit, serverKexInit;
        private bool authenticated;
        private int authFailures;

        private SessionChannel channel;

        public PwsshEngine(PwsshConfig config)
        {
            cfg = config;
            pkt = new PacketLayer(inbound, outbound);
        }

        public bool Finished { get { return finished; } }
        public string LastError { get { return lastError; } }

        private int lastInboundTick = Environment.TickCount;

        public void PushInbound(byte[] data)
        {
            lastInboundTick = Environment.TickCount;
            inbound.Write(data);
        }
        public byte[] TakeOutbound(int timeoutMs) { return outbound.TakeAll(timeoutMs); }
        public void CloseInbound() { inbound.Close(); }

        public void Start()
        {
            worker = new Thread(new ThreadStart(Run));
            worker.IsBackground = true;
            worker.Name = "pwssh-protocol";
            worker.Start();

            if (cfg.InactivityTimeoutSeconds > 0)
            {
                Thread wd = new Thread(new ThreadStart(Watchdog));
                wd.IsBackground = true;
                wd.Name = "pwssh-watchdog";
                wd.Start();
            }
        }

        // The protocol thread blocks in ReadPacket, so the timeout needs its own thread.
        private void Watchdog()
        {
            int limitMs = cfg.InactivityTimeoutSeconds * 1000;
            while (!finished)
            {
                Thread.Sleep(5000);
                if (finished) return;
                if (unchecked(Environment.TickCount - lastInboundTick) > limitMs)
                {
                    Log("no inbound data for " + cfg.InactivityTimeoutSeconds + "s; shutting down");
                    Stop();
                    return;
                }
            }
        }

        public void Stop()
        {
            finished = true;
            inbound.Close();
            outbound.Close();
            if (channel != null) channel.Kill();
        }

        // Diagnostics are queued rather than delivered by callback: the engine logs from
        // several background threads, and a PowerShell scriptblock delegate invoked off
        // its runspace would throw. Callers drain this from whatever thread they like.
        private readonly Queue<string> logQ = new Queue<string>();

        public string[] DrainLog()
        {
            lock (logQ)
            {
                string[] a = logQ.ToArray();
                logQ.Clear();
                return a;
            }
        }

        private void Log(string m)
        {
            lock (logQ)
            {
                if (logQ.Count > 1000) logQ.Dequeue();
                logQ.Enqueue(m);
            }
        }

        private void Run()
        {
            try
            {
                hostKey = new RSACryptoServiceProvider();
                hostKey.ImportParameters(PwsshKey.Import(cfg.HostKey));

                if (cfg.Agent != null) cfg.Agent.Attach(this);

                ExchangeIdent();
                SendKexInit();
                Loop();
            }
            catch (EndOfStreamException)
            {
                Log("transport closed");
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                Log("fatal: " + ex.ToString());
            }
            finally
            {
                finished = true;
                if (channel != null) channel.Kill();
                // let the transport drain whatever is already queued
                outbound.Close();
            }
        }

        // -------------------------------------------------------------- identification

        private void ExchangeIdent()
        {
            byte[] mine = Encoding.ASCII.GetBytes(cfg.ServerIdent + "\r\n");
            outbound.Write(mine);

            // Client may send arbitrary lines before its identification.
            for (int attempt = 0; attempt < 64; attempt++)
            {
                string line = ReadLine();
                if (line.StartsWith("SSH-", StringComparison.Ordinal))
                {
                    clientIdent = line;
                    Log("client ident: " + line);
                    if (!line.StartsWith("SSH-2.0-", StringComparison.Ordinal))
                        throw new Exception("unsupported protocol version: " + line);
                    return;
                }
            }
            throw new Exception("no identification string received");
        }

        private string ReadLine()
        {
            MemoryStream ms = new MemoryStream();
            while (true)
            {
                byte b = inbound.ReadByte1();
                if (b == (byte)'\n') break;
                if (b != (byte)'\r') ms.WriteByte(b);
                if (ms.Length > 255) throw new Exception("identification line too long");
            }
            return Encoding.ASCII.GetString(ms.ToArray());
        }

        // ------------------------------------------------------------------------ KEX

        private void SendKexInit()
        {
            SshWriter w = new SshWriter();
            w.Byte(Msg.KEXINIT);
            byte[] cookie = new byte[16];
            RandomNumberGenerator.Create().GetBytes(cookie);
            w.Raw(cookie);
            w.NameList(new string[] { KEX_ALG });
            w.NameList(new string[] { HOSTKEY_ALG });
            w.NameList(new string[] { CIPHER_ALG });   // c2s
            w.NameList(new string[] { CIPHER_ALG });   // s2c
            w.NameList(new string[] { MAC_ALG });      // c2s
            w.NameList(new string[] { MAC_ALG });      // s2c
            w.NameList(new string[] { "none" });       // compression c2s
            w.NameList(new string[] { "none" });       // compression s2c
            w.NameList(new string[] { "" });           // languages c2s
            w.NameList(new string[] { "" });           // languages s2c
            w.Bool(false);                             // first_kex_packet_follows
            w.UInt32(0);
            serverKexInit = w.ToArray();
            pkt.WritePacket(serverKexInit);
        }

        private void HandleKexInit(byte[] payload)
        {
            clientKexInit = payload;
            SshReader r = new SshReader(payload);
            r.Byte();
            byte[] cookie = new byte[16];
            for (int i = 0; i < 16; i++) cookie[i] = r.Byte();

            string kex = r.StrUtf8();
            string hk = r.StrUtf8();
            string encC2S = r.StrUtf8();
            string encS2C = r.StrUtf8();
            string macC2S = r.StrUtf8();
            string macS2C = r.StrUtf8();

            Require(kex, KEX_ALG, "key exchange");
            Require(hk, HOSTKEY_ALG, "host key");
            Require(encC2S, CIPHER_ALG, "cipher c2s");
            Require(encS2C, CIPHER_ALG, "cipher s2c");
            Require(macC2S, MAC_ALG, "mac c2s");
            Require(macS2C, MAC_ALG, "mac s2c");
            Log("kexinit ok");
        }

        private static void Require(string clientList, string needed, string what)
        {
            string[] offered = clientList.Split(',');
            for (int i = 0; i < offered.Length; i++)
                if (offered[i] == needed) return;
            throw new Exception("no overlap for " + what + "; need " + needed + ", client offered: " + clientList);
        }

        private byte[] HostKeyBlob()
        {
            RSAParameters p = hostKey.ExportParameters(false);
            SshWriter w = new SshWriter();
            w.Str("ssh-rsa");                                  // key format id stays ssh-rsa (RFC 8332)
            w.MpInt(PositiveInt(p.Exponent));
            w.MpInt(PositiveInt(p.Modulus));
            return w.ToArray();
        }

        private static BigInteger PositiveInt(byte[] bigEndian)
        {
            byte[] le = new byte[bigEndian.Length + 1];
            for (int i = 0; i < bigEndian.Length; i++) le[i] = bigEndian[bigEndian.Length - 1 - i];
            return new BigInteger(le);
        }

        private void HandleKexDhInit(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            BigInteger e = r.MpInt();

            BigInteger p = BigInteger.Parse("0" + P_HEX, NumberStyles.AllowHexSpecifier);
            BigInteger g = new BigInteger(2);
            if (e <= BigInteger.One || e >= p - BigInteger.One)
                throw new Exception("client DH value out of range");

            byte[] xb = new byte[64];
            RandomNumberGenerator.Create().GetBytes(xb);
            byte[] xle = new byte[xb.Length + 1];
            Array.Copy(xb, xle, xb.Length);
            BigInteger x = new BigInteger(xle);

            BigInteger f = BigInteger.ModPow(g, x, p);
            BigInteger k = BigInteger.ModPow(e, x, p);

            byte[] ks = HostKeyBlob();

            SshWriter hw = new SshWriter();
            hw.Str(clientIdent);
            hw.Str(cfg.ServerIdent);
            hw.Str(clientKexInit);
            hw.Str(serverKexInit);
            hw.Str(ks);
            hw.MpInt(e);
            hw.MpInt(f);
            hw.MpInt(k);
            byte[] h;
            using (SHA256 sha = SHA256.Create()) h = sha.ComputeHash(hw.ToArray());

            if (sessionId == null) sessionId = h;

            byte[] rawSig = hostKey.SignData(h, "SHA256");
            SshWriter sw = new SshWriter();
            sw.Str(HOSTKEY_ALG);
            sw.Str(rawSig);
            byte[] sigBlob = sw.ToArray();

            SshWriter reply = new SshWriter();
            reply.Byte(Msg.KEXDH_REPLY);
            reply.Str(ks);
            reply.MpInt(f);
            reply.Str(sigBlob);
            pkt.WritePacket(reply.ToArray());

            SshWriter nk = new SshWriter();
            nk.Byte(Msg.NEWKEYS);
            pkt.WritePacket(nk.ToArray());

            // Derive but do not activate until the client's NEWKEYS arrives.
            pendingIvC2S = Derive(k, h, 'A', 16);
            pendingIvS2C = Derive(k, h, 'B', 16);
            pendingKeyC2S = Derive(k, h, 'C', 32);
            pendingKeyS2C = Derive(k, h, 'D', 32);
            pendingMacC2S = Derive(k, h, 'E', 32);
            pendingMacS2C = Derive(k, h, 'F', 32);
            Log("kex complete");
        }

        private byte[] pendingIvC2S, pendingIvS2C, pendingKeyC2S, pendingKeyS2C, pendingMacC2S, pendingMacS2C;

        private byte[] Derive(BigInteger k, byte[] h, char letter, int need)
        {
            SshWriter w = new SshWriter();
            w.MpInt(k);
            byte[] kBytes = w.ToArray();

            MemoryStream seed = new MemoryStream();
            seed.Write(kBytes, 0, kBytes.Length);
            seed.Write(h, 0, h.Length);
            seed.WriteByte((byte)letter);
            seed.Write(sessionId, 0, sessionId.Length);

            using (SHA256 sha = SHA256.Create())
            {
                byte[] block = sha.ComputeHash(seed.ToArray());
                if (need <= block.Length)
                {
                    byte[] o = new byte[need];
                    Array.Copy(block, o, need);
                    return o;
                }
                // Not needed for SHA-256 sizes here, but keep it correct.
                MemoryStream acc = new MemoryStream();
                acc.Write(block, 0, block.Length);
                while (acc.Length < need)
                {
                    MemoryStream nxt = new MemoryStream();
                    nxt.Write(kBytes, 0, kBytes.Length);
                    nxt.Write(h, 0, h.Length);
                    byte[] so = acc.ToArray();
                    nxt.Write(so, 0, so.Length);
                    byte[] more = sha.ComputeHash(nxt.ToArray());
                    acc.Write(more, 0, more.Length);
                }
                byte[] res = new byte[need];
                Array.Copy(acc.ToArray(), res, need);
                return res;
            }
        }

        // ----------------------------------------------------------------- main loop

        private void Loop()
        {
            while (!finished)
            {
                byte[] payload = pkt.ReadPacket();
                if (payload.Length == 0) continue;
                byte type = payload[0];

                switch (type)
                {
                    case Msg.KEXINIT:
                        if (sessionId != null)
                        {
                            // Rekey is not implemented; disconnect rather than corrupt state.
                            Disconnect(2, "pwssh does not support rekeying");
                            return;
                        }
                        HandleKexInit(payload);
                        break;

                    case Msg.KEXDH_INIT:
                        HandleKexDhInit(payload);
                        break;

                    case Msg.NEWKEYS:
                        pkt.EnableEncryption(pendingIvC2S, pendingKeyC2S, pendingMacC2S,
                                             pendingIvS2C, pendingKeyS2C, pendingMacS2C);
                        Log("encryption active");
                        break;

                    case Msg.SERVICE_REQUEST:
                        HandleServiceRequest(payload);
                        break;

                    case Msg.USERAUTH_REQUEST:
                        HandleUserAuth(payload);
                        break;

                    case Msg.CHANNEL_OPEN:
                        HandleChannelOpen(payload);
                        break;

                    case Msg.CHANNEL_REQUEST:
                        HandleChannelRequest(payload);
                        break;

                    case Msg.CHANNEL_DATA:
                        HandleChannelData(payload);
                        break;

                    case Msg.CHANNEL_WINDOW_ADJUST:
                        {
                            SshReader r = new SshReader(payload);
                            r.Byte(); r.UInt32();
                            uint add = r.UInt32();
                            if (channel != null) channel.AddRemoteWindow(add);
                        }
                        break;

                    case Msg.CHANNEL_EOF:
                        if (channel != null) channel.ClientEof();
                        break;

                    case Msg.CHANNEL_CLOSE:
                        Log("client closed channel");
                        if (channel != null) channel.Kill();
                        finished = true;
                        return;

                    case Msg.DISCONNECT:
                        Log("client disconnected");
                        finished = true;
                        return;

                    case Msg.IGNORE:
                    case Msg.DEBUG:
                    case Msg.UNIMPLEMENTED:
                    case Msg.EXT_INFO:
                        break;

                    case Msg.GLOBAL_REQUEST:
                        {
                            SshReader r = new SshReader(payload);
                            r.Byte();
                            r.StrUtf8();
                            bool wantReply = r.Bool();
                            if (wantReply)
                            {
                                SshWriter w = new SshWriter();
                                w.Byte(Msg.REQUEST_FAILURE);
                                pkt.WritePacket(w.ToArray());
                            }
                        }
                        break;

                    default:
                        Log("unimplemented message type " + type);
                        SshWriter u = new SshWriter();
                        u.Byte(Msg.UNIMPLEMENTED);
                        u.UInt32(0);
                        pkt.WritePacket(u.ToArray());
                        break;
                }
            }
        }

        private void Disconnect(uint reason, string text)
        {
            try
            {
                SshWriter w = new SshWriter();
                w.Byte(Msg.DISCONNECT);
                w.UInt32(reason);
                w.Str(text);
                w.Str("");
                pkt.WritePacket(w.ToArray());
            }
            catch { }
            finished = true;
            Log("disconnect: " + text);
        }

        private void HandleServiceRequest(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            string svc = r.StrUtf8();
            if (svc != "ssh-userauth" && svc != "ssh-connection")
            {
                Disconnect(7, "service not available: " + svc);
                return;
            }
            SshWriter w = new SshWriter();
            w.Byte(Msg.SERVICE_ACCEPT);
            w.Str(svc);
            pkt.WritePacket(w.ToArray());
        }

        // Authentication is delegated to the WinRM layer; we only check that the
        // requested user matches the account this process is already running as.
        private void HandleUserAuth(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            string user = r.StrUtf8();
            string service = r.StrUtf8();
            string method = r.StrUtf8();

            // The handshake is local now, so userauth can arrive before the agent's HELLO has
            // made the round trip. Blocking here lets session setup overlap the handshake
            // instead of serialising it.
            if (string.IsNullOrEmpty(cfg.ExpectedUser) && cfg.Agent != null)
            {
                string remote = cfg.Agent.WaitForRemoteUser(30000);
                if (string.IsNullOrEmpty(remote))
                {
                    Disconnect(11, "could not determine the remote account");
                    return;
                }
                cfg.ExpectedUser = remote;
                Log("remote account: " + remote);
            }

            if (UserMatches(user))
            {
                authenticated = true;
                SshWriter w = new SshWriter();
                w.Byte(Msg.USERAUTH_SUCCESS);
                pkt.WritePacket(w.ToArray());
                Log("auth ok for '" + user + "' via '" + method + "'");
                return;
            }

            authFailures++;
            Log("auth rejected: '" + user + "' != '" + cfg.ExpectedUser + "'");
            if (authFailures >= 3)
            {
                Disconnect(14, "user does not match the remote session account");
                return;
            }
            SshWriter f = new SshWriter();
            f.Byte(Msg.USERAUTH_FAILURE);
            f.NameList(new string[] { "none" });
            f.Bool(false);
            pkt.WritePacket(f.ToArray());
        }

        private bool UserMatches(string requested)
        {
            if (string.IsNullOrEmpty(requested)) return false;
            string want = Normalize(cfg.ExpectedUser);
            string got = Normalize(requested);
            return string.Equals(want, got, StringComparison.OrdinalIgnoreCase);
        }

        // DOMAIN\user, user@domain and bare user all reduce to the account name.
        private static string Normalize(string name)
        {
            if (name == null) return "";
            string s = name.Trim();
            int bs = s.LastIndexOf('\\');
            if (bs >= 0) s = s.Substring(bs + 1);
            int at = s.IndexOf('@');
            if (at > 0) s = s.Substring(0, at);
            return s;
        }

        private void HandleChannelOpen(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            string kind = r.StrUtf8();
            uint peerChannel = r.UInt32();
            uint peerWindow = r.UInt32();
            uint peerMaxPacket = r.UInt32();

            if (!authenticated || kind != "session" || channel != null)
            {
                SshWriter f = new SshWriter();
                f.Byte(Msg.CHANNEL_OPEN_FAILURE);
                f.UInt32(peerChannel);
                f.UInt32(3);
                f.Str(authenticated ? ("unsupported channel type: " + kind) : "not authenticated");
                f.Str("");
                pkt.WritePacket(f.ToArray());
                return;
            }

            channel = new SessionChannel(this, pkt, cfg.Agent, peerChannel, peerWindow, peerMaxPacket);

            SshWriter w = new SshWriter();
            w.Byte(Msg.CHANNEL_OPEN_CONFIRMATION);
            w.UInt32(peerChannel);
            w.UInt32(0);                  // our channel id
            w.UInt32(INITIAL_WINDOW);
            w.UInt32(MAX_PACKET);
            pkt.WritePacket(w.ToArray());
            Log("session channel open");
        }

        private void HandleChannelRequest(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            uint localChannel = r.UInt32();
            string req = r.StrUtf8();
            bool wantReply = r.Bool();

            bool ok = false;
            if (channel != null)
            {
                if (req == "exec")
                {
                    string cmd = r.StrUtf8();
                    Log("exec: " + cmd);
                    ok = channel.StartExec(cmd);
                }
                else if (req == "env")
                {
                    ok = true;              // accepted and ignored
                }
                // pty-req, shell, subsystem: not supported in this version -> failure
            }

            if (wantReply)
            {
                SshWriter w = new SshWriter();
                w.Byte(ok ? Msg.CHANNEL_SUCCESS : Msg.CHANNEL_FAILURE);
                w.UInt32(channel != null ? channel.PeerChannel : 0);
                pkt.WritePacket(w.ToArray());
            }
        }

        private void HandleChannelData(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            r.UInt32();
            byte[] data = r.Str();
            if (channel != null) channel.WriteFromClient(data);
        }

        internal void NotifyChannelFinished() { finished = true; }
        internal uint InitialWindow { get { return INITIAL_WINDOW; } }
        internal void LogInternal(string m) { Log(m); }

        // ---- IPwsshChannelSink: called from the agent side, must not block ----

        public void OnData(uint ch, byte[] buffer, int offset, int count, bool stderr)
        {
            SessionChannel c = channel;
            if (c != null && c.PeerChannel == ch) c.OnAgentData(buffer, offset, count, stderr);
        }

        public void OnExit(uint ch, uint status)
        {
            SessionChannel c = channel;
            if (c != null && c.PeerChannel == ch) c.OnAgentExit(status);
        }

        public void OnClose(uint ch)
        {
            SessionChannel c = channel;
            if (c != null && c.PeerChannel == ch) c.OnAgentClose();
        }

        public void OnAgentError(string message)
        {
            Log("agent error: " + message);
            lastError = "agent: " + message;
        }
    }

    // --------------------------------------------------------------- stdio bridge
    //
    // ssh hands the ProxyCommand raw binary on stdin and reads the reply from stdout. Both
    // directions run on dedicated threads here rather than from the PowerShell loop, which
    // matters for more than tidiness: it lets the whole SSH handshake complete locally while
    // New-PSSession is still connecting, instead of waiting for it. Only userauth then has to
    // wait for the agent, and only for its HELLO frame.
    //
    // No System.Management.Automation reference is needed, so this stays plain C#.
    public static class PwsshStdioBridge
    {
        private static int started;

        public static void Start(PwsshEngine engine, int maxChunk)
        {
            if (Interlocked.CompareExchange(ref started, 1, 0) != 0) return;

            Thread inbound = new Thread(new ThreadStart(delegate
            {
                try
                {
                    Stream si = Console.OpenStandardInput();
                    byte[] buf = new byte[maxChunk];
                    while (true)
                    {
                        int n = si.Read(buf, 0, buf.Length);
                        if (n <= 0) break;
                        byte[] c = new byte[n];
                        Array.Copy(buf, 0, c, 0, n);
                        engine.PushInbound(c);
                    }
                }
                catch (Exception)
                {
                    // treated as EOF
                }
                finally
                {
                    engine.CloseInbound();
                }
            }));
            inbound.IsBackground = true;
            inbound.Name = "pwssh-ssh-in";
            inbound.Start();

            Thread outbound = new Thread(new ThreadStart(delegate
            {
                try
                {
                    Stream so = Console.OpenStandardOutput();
                    while (true)
                    {
                        byte[] b = engine.TakeOutbound(100);
                        if (b != null && b.Length > 0)
                        {
                            so.Write(b, 0, b.Length);
                            so.Flush();
                            continue;
                        }
                        if (engine.Finished)
                        {
                            // Drain anything queued as the engine stopped, then stop.
                            byte[] last = engine.TakeOutbound(0);
                            while (last != null && last.Length > 0)
                            {
                                so.Write(last, 0, last.Length);
                                so.Flush();
                                last = engine.TakeOutbound(0);
                            }
                            break;
                        }
                    }
                }
                catch (Exception)
                {
                    // ssh went away
                }
            }));
            outbound.IsBackground = true;
            outbound.Name = "pwssh-ssh-out";
            outbound.Start();
        }
    }

    // -------------------------------------------------------------- session channel

    internal sealed class SessionChannel
    {
        // Queued rather than emitted inline: OnAgentData runs on the client's pump loop, and
        // blocking there for ssh window credit would stop the same loop that drains ssh stdin
        // and the remoting output -- an immediate deadlock. A dedicated sender thread owns all
        // window waiting, and the queue also keeps data/exit/close strictly ordered.
        private sealed class Chunk
        {
            public const int DATA = 0, EXIT = 1, DONE = 2;
            public int Kind;
            public byte[] Data;      // may be a whole frame buffer; Offset/Count select the payload
            public int Offset;
            public int Count;
            public bool Stderr;
            public uint Status;
        }

        private readonly PwsshEngine engine;
        private readonly PacketLayer pkt;
        private readonly IPwsshAgent agent;
        private readonly uint peerChannel;
        private readonly uint peerMaxPacket;

        private readonly object windowGate = new object();
        private long remoteWindow;                 // credit the ssh client has granted us

        private readonly Queue<Chunk> outQ = new Queue<Chunk>();
        private readonly object outGate = new object();

        // Credit is returned to the agent in batches. Granting per SSH packet meant ~256 tiny
        // WINDOW frames for an 8 MiB download, all travelling upstream -- the slow direction --
        // and competing with the download on the same link. The threshold must stay well below
        // PwsshAgentHost.INITIAL_CREDIT so the agent never actually runs dry.
        private const int GRANT_THRESHOLD = 1024 * 1024;
        private long pendingGrant;

        private Thread sender;
        private volatile bool killed;
        private bool execStarted;

        public SessionChannel(PwsshEngine e, PacketLayer p, IPwsshAgent a,
                              uint peer, uint window, uint maxPacket)
        {
            engine = e; pkt = p; agent = a; peerChannel = peer;
            remoteWindow = window;
            peerMaxPacket = maxPacket == 0 ? 32768 : maxPacket;
        }

        public uint PeerChannel { get { return peerChannel; } }

        public void AddRemoteWindow(uint add)
        {
            lock (windowGate) { remoteWindow += add; Monitor.PulseAll(windowGate); }
        }

        public bool StartExec(string command)
        {
            if (execStarted) return false;
            execStarted = true;

            sender = new Thread(new ThreadStart(SenderLoop));
            sender.IsBackground = true;
            sender.Name = "pwssh-channel-sender";
            sender.Start();

            agent.Exec(peerChannel, command);
            return true;
        }

        // ---- called from the agent side (must not block) ----

        public void OnAgentData(byte[] buffer, int offset, int count, bool stderr)
        {
            Chunk c = new Chunk();
            c.Kind = Chunk.DATA; c.Data = buffer; c.Offset = offset; c.Count = count; c.Stderr = stderr;
            Enqueue(c);
        }

        public void OnAgentExit(uint status)
        {
            Chunk c = new Chunk();
            c.Kind = Chunk.EXIT; c.Status = status;
            Enqueue(c);
        }

        public void OnAgentClose()
        {
            Chunk c = new Chunk();
            c.Kind = Chunk.DONE;
            Enqueue(c);
        }

        private void Enqueue(Chunk c)
        {
            lock (outGate) { outQ.Enqueue(c); Monitor.PulseAll(outGate); }
        }

        // ---- called from the ssh side ----

        public void WriteFromClient(byte[] data)
        {
            agent.SendStdin(peerChannel, data);

            // Eager window adjust: a lazy threshold would cost a full round trip, and on this
            // transport a round trip is ~600-900 ms.
            SshWriter w = new SshWriter();
            w.Byte(Msg.CHANNEL_WINDOW_ADJUST);
            w.UInt32(peerChannel);
            w.UInt32((uint)data.Length);
            pkt.WritePacket(w.ToArray());
        }

        public void ClientEof() { agent.CloseStdin(peerChannel); }

        public void Kill()
        {
            killed = true;
            lock (windowGate) { Monitor.PulseAll(windowGate); }
            lock (outGate) { Monitor.PulseAll(outGate); }
            try { agent.CloseChannel(peerChannel); } catch { }
        }

        // ---- sender ----

        private void SenderLoop()
        {
            try
            {
                while (!killed)
                {
                    Chunk c = null;
                    lock (outGate)
                    {
                        while (outQ.Count == 0 && !killed) Monitor.Wait(outGate, 250);
                        if (killed) return;
                        c = outQ.Dequeue();
                    }

                    if (c.Kind == Chunk.DATA) { SendData(c.Data, c.Offset, c.Count, c.Stderr); }
                    else if (c.Kind == Chunk.EXIT) { SendExitStatus(c.Status); }
                    else { SendEofAndClose(); return; }
                }
            }
            catch (Exception ex)
            {
                engine.LogInternal("channel sender ended: " + ex.Message);
            }
        }

        private void SendData(byte[] data, int offset, int count, bool stderr)
        {
            int off = offset;
            int end = offset + count;
            while (off < end && !killed)
            {
                int want = Math.Min(end - off, (int)peerMaxPacket);
                int allowed;
                lock (windowGate)
                {
                    while (remoteWindow <= 0 && !killed) Monitor.Wait(windowGate, 500);
                    if (killed) return;
                    allowed = (int)Math.Min((long)want, remoteWindow);
                    remoteWindow -= allowed;
                }
                if (allowed <= 0) continue;

                // Written straight from the source range into the packet buffer.
                pkt.WriteChannelData(peerChannel, data, off, allowed, stderr);
                off += allowed;

                // Return credit in batches, so the agent's in-flight output stays bounded by
                // the initial grant without flooding the upstream direction with tiny frames.
                pendingGrant += allowed;
                if (pendingGrant >= GRANT_THRESHOLD)
                {
                    agent.GrantWindow(peerChannel, (uint)pendingGrant);
                    pendingGrant = 0;
                }
            }
        }

        private void SendExitStatus(uint code)
        {
            engine.LogInternal("child exited " + code);
            SshWriter req = new SshWriter();
            req.Byte(Msg.CHANNEL_REQUEST);
            req.UInt32(peerChannel);
            req.Str("exit-status");
            req.Bool(false);
            req.UInt32(code);
            pkt.WritePacket(req.ToArray());
        }

        private void SendEofAndClose()
        {
            SshWriter eof = new SshWriter();
            eof.Byte(Msg.CHANNEL_EOF);
            eof.UInt32(peerChannel);
            pkt.WritePacket(eof.ToArray());

            SshWriter cl = new SshWriter();
            cl.Byte(Msg.CHANNEL_CLOSE);
            cl.UInt32(peerChannel);
            pkt.WritePacket(cl.ToArray());
        }
    }
}
