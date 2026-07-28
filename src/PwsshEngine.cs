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

        // Whether a client-specified -R bind address is honoured. Off by default, matching
        // OpenSSH's GatewayPorts no, which means loopback only.
        public bool AllowGatewayPorts;

        // How far ahead an SFTP download may be fetched, in 255 KiB chunks; 0 disables read-ahead
        // entirely and is the escape hatch if it ever misbehaves. It exists as a knob mainly so
        // the effect can be measured by interleaved A/B rather than argued about -- this transport
        // has twice produced a single measurement that inverted a conclusion.
        public int SftpReadAheadChunks = 16;

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

        // Several channels can be live at once: ssh -L/-D opens one per forwarded connection,
        // and a session channel closing must no longer end the whole connection.
        //
        // Keyed by OUR local channel id, which is also the id the agent uses. Ours are
        // allocated monotonically and never reused, whereas the client recycles its channel
        // numbers after close -- keying the agent on those risks a close/open collision.
        private readonly Dictionary<uint, SessionChannel> channels = new Dictionary<uint, SessionChannel>();
        private readonly object chanGate = new object();
        private uint nextChannelId;

        private const int MAX_CHANNELS = 256;

        private SessionChannel Find(uint localId)
        {
            lock (chanGate)
            {
                SessionChannel c;
                if (channels.TryGetValue(localId, out c)) return c;
                return null;
            }
        }

        // Channels the engine opened for its own SFTP read-ahead. They are ordinary agent
        // channels sharing the same id space -- the agent cannot tell them apart from the
        // client's -- but no SessionChannel exists for them, because ssh knows nothing about
        // them and nothing they carry is ever written to it.
        private readonly Dictionary<uint, SftpReadAhead> prefetch = new Dictionary<uint, SftpReadAhead>();

        // Drawn from the same monotonic counter as client channels, which is what makes a
        // collision impossible rather than merely unlikely. Zero cannot signal failure here:
        // it is a perfectly good channel id, and the first one handed out.
        internal bool TryRegisterPrefetchChannel(SftpReadAhead owner, out uint id)
        {
            id = 0;
            lock (chanGate)
            {
                if (channels.Count + prefetch.Count >= MAX_CHANNELS) return false;
                id = nextChannelId++;
                prefetch[id] = owner;
                return true;
            }
        }

        internal void ForgetPrefetchChannel(uint id)
        {
            lock (chanGate) { prefetch.Remove(id); }
        }

        private SftpReadAhead FindPrefetch(uint id)
        {
            lock (chanGate)
            {
                SftpReadAhead r;
                if (prefetch.TryGetValue(id, out r)) return r;
                return null;
            }
        }

        private void ForgetChannel(uint localId)
        {
            lock (chanGate) { channels.Remove(localId); }
        }

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
            KillAllChannels();
        }

        private void KillAllChannels()
        {
            SessionChannel[] all;
            uint[] forwards;
            lock (chanGate)
            {
                all = new SessionChannel[channels.Count];
                channels.Values.CopyTo(all, 0);
                channels.Clear();
                forwards = new uint[activeForwards.Count];
                activeForwards.Keys.CopyTo(forwards, 0);
                activeForwards.Clear();
                forwardAddresses.Clear();
            }
            for (int i = 0; i < all.Length; i++) { try { all[i].Kill(); } catch { } }
            // -R listeners are not channels, and a surviving one keeps a port bound on the
            // remote. The agent also drops them when the link closes, but that relies on the
            // remote process going away, which is a slower and less certain thing.
            for (int i = 0; i < forwards.Length; i++)
            {
                try { if (cfg.Agent != null) cfg.Agent.Unlisten(forwards[i]); } catch { }
            }
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
                // Order matters: KillAllChannels queues UNLISTEN frames for the agent, and the
                // client's frame loop completes the remote pipeline as soon as it sees Finished.
                // Setting the flag first would let that happen before the frames were drained.
                KillAllChannels();
                finished = true;
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
                            r.Byte();
                            uint id = r.UInt32();
                            uint add = r.UInt32();
                            SessionChannel wc = Find(id);
                            if (wc != null) wc.AddRemoteWindow(add);
                        }
                        break;

                    case Msg.CHANNEL_EOF:
                        {
                            SshReader r = new SshReader(payload);
                            r.Byte();
                            SessionChannel ec = Find(r.UInt32());
                            if (ec != null) ec.ClientEof();
                        }
                        break;

                    case Msg.CHANNEL_CLOSE:
                        {
                            SshReader r = new SshReader(payload);
                            r.Byte();
                            uint id = r.UInt32();
                            SessionChannel cc = Find(id);
                            if (cc != null) { cc.Kill(); ForgetChannel(id); }
                            Log("channel " + id + " closed by client");
                            // Deliberately does NOT finish the session: other channels may
                            // still be live. The connection ends on DISCONNECT or on transport
                            // EOF when ssh closes our stdin.
                        }
                        break;

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
                        HandleGlobalRequest(payload);
                        break;

                    // Answers to channels WE opened, which only happens for -R's
                    // forwarded-tcpip. Previously these fell through to UNIMPLEMENTED.
                    case Msg.CHANNEL_OPEN_CONFIRMATION:
                        {
                            SshReader r = new SshReader(payload);
                            r.Byte();
                            uint mine = r.UInt32();
                            uint theirs = r.UInt32();
                            uint window = r.UInt32();
                            uint maxPacket = r.UInt32();
                            SessionChannel oc = Find(mine);
                            if (oc != null)
                            {
                                oc.ConfirmOpened(theirs, window, maxPacket);
                                Log("forwarded channel " + mine + " confirmed by client");
                            }
                            else Log("confirmation for unknown channel " + mine + "; ignoring");
                        }
                        break;

                    case Msg.CHANNEL_OPEN_FAILURE:
                        {
                            SshReader r = new SshReader(payload);
                            r.Byte();
                            uint mine = r.UInt32();
                            SessionChannel fc = Find(mine);
                            if (fc != null)
                            {
                                Log("client refused forwarded channel " + mine);
                                fc.Kill();
                                ForgetChannel(mine);
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

            int live;
            lock (chanGate) { live = channels.Count; }

            if (!authenticated || live >= MAX_CHANNELS)
            {
                RejectChannelOpen(peerChannel, 3,
                    authenticated ? "too many open channels" : "not authenticated");
                return;
            }

            if (kind == "session")
            {
                uint id = NewChannel(peerChannel, peerWindow, peerMaxPacket);
                ConfirmChannelOpen(peerChannel, id);
                Log("session channel " + id + " open");
                return;
            }

            if (kind == "direct-tcpip")
            {
                string target = r.StrUtf8();
                uint targetPort = r.UInt32();
                r.StrUtf8();                 // originator address, unused
                r.UInt32();                  // originator port, unused

                uint id = NewChannel(peerChannel, peerWindow, peerMaxPacket);
                Log("direct-tcpip channel " + id + " -> " + target + ":" + targetPort);

                // No reply yet. Whether the remote can reach that address is only known after
                // a round trip, and blocking here would stall every other channel, so the
                // confirmation is sent from OnConnectResult.
                Find(id).StartConnect(target, (int)targetPort);
                return;
            }

            RejectChannelOpen(peerChannel, 3, "unsupported channel type: " + kind);
        }

        private uint NewChannel(uint peerChannel, uint peerWindow, uint peerMaxPacket)
        {
            lock (chanGate)
            {
                uint id = nextChannelId++;
                channels[id] = new SessionChannel(this, pkt, cfg.Agent, id, peerChannel, peerWindow, peerMaxPacket);
                return id;
            }
        }

        private void ConfirmChannelOpen(uint peerChannel, uint localId)
        {
            SshWriter w = new SshWriter();
            w.Byte(Msg.CHANNEL_OPEN_CONFIRMATION);
            w.UInt32(peerChannel);
            w.UInt32(localId);
            w.UInt32(INITIAL_WINDOW);
            w.UInt32(MAX_PACKET);
            pkt.WritePacket(w.ToArray());
        }

        // ---- remote forwarding (-R) ----
        //
        // RFC 4254 matches global request replies to requests *in order*, not by any tag, so a
        // result that arrives for a request behind the head has to wait its turn. ssh normally
        // keeps one outstanding, but replying out of order would desynchronise every reply
        // after it.
        private sealed class PendingForward
        {
            public uint ForwardId;
            public bool WantReply;
            public bool Done;
            public bool Ok;
            public int BoundPort;
            public bool RequestedDynamicPort;
        }

        private readonly List<PendingForward> pendingForwards = new List<PendingForward>();
        private readonly Dictionary<uint, int> activeForwards = new Dictionary<uint, int>();  // id -> bound port
        // id -> the address string the CLIENT sent. ssh matches an incoming forwarded-tcpip
        // against its own forward list by (address, port), and its stored address is the one it
        // asked for -- not the one we actually bound -- so this is what has to be quoted back.
        private readonly Dictionary<uint, string> forwardAddresses = new Dictionary<uint, string>();
        private uint nextForwardId = 1;

        private void HandleGlobalRequest(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            string name = r.StrUtf8();
            bool wantReply = r.Bool();

            if (name == "tcpip-forward")
            {
                string bindAddr = r.StrUtf8();
                uint bindPort = r.UInt32();

                // Careful with the wire convention, which is the opposite way round from what
                // it looks like: OpenSSH's channel_rfwd_bind_host sends "localhost" for a plain
                // `-R port:...` and an EMPTY string for `-R *:port:...`. So empty means
                // wildcard, and only loopback is safe without -GatewayPorts. Refusing outright
                // beats silently binding somewhere narrower than the client asked for.
                bool loopbackOnly = bindAddr == "localhost" || bindAddr == "127.0.0.1"
                                    || bindAddr == "::1";
                if (!loopbackOnly && !cfg.AllowGatewayPorts)
                {
                    Log("refusing tcpip-forward on '" + bindAddr + "': needs -GatewayPorts");
                    if (wantReply) ReplyGlobal(false, 0);
                    return;
                }
                // The agent treats an empty address as wildcard, matching the wire convention.
                string effective = loopbackOnly ? "127.0.0.1" : bindAddr;

                uint id;
                lock (chanGate)
                {
                    id = nextForwardId++;
                    forwardAddresses[id] = bindAddr;
                }

                PendingForward pf = new PendingForward();
                pf.ForwardId = id;
                pf.WantReply = wantReply;
                pf.RequestedDynamicPort = (bindPort == 0);
                lock (pendingForwards) { pendingForwards.Add(pf); }

                Log("tcpip-forward '" + bindAddr + "' -> bind " + effective + ":" + bindPort);
                cfg.Agent.Listen(id, effective, (int)bindPort);
                return;                        // reply comes from OnListenResult
            }

            if (name == "cancel-tcpip-forward")
            {
                r.StrUtf8();                   // bind address
                uint port = r.UInt32();
                uint found = 0;
                lock (chanGate)
                {
                    foreach (KeyValuePair<uint, int> kv in activeForwards)
                    {
                        if (kv.Value == (int)port) { found = kv.Key; break; }
                    }
                    if (found != 0) { activeForwards.Remove(found); forwardAddresses.Remove(found); }
                }
                if (found != 0) cfg.Agent.Unlisten(found);
                // Replied immediately: a failure to unbind is not something the client can act
                // on, so waiting a round trip for confirmation buys nothing.
                if (wantReply) ReplyGlobal(found != 0, 0);
                return;
            }

            if (wantReply) ReplyGlobal(false, 0);
        }

        private void ReplyGlobal(bool ok, uint boundPort)
        {
            SshWriter w = new SshWriter();
            if (ok)
            {
                w.Byte(Msg.REQUEST_SUCCESS);
                if (boundPort != 0) w.UInt32(boundPort);   // only when the client asked for 0
            }
            else
            {
                w.Byte(Msg.REQUEST_FAILURE);
            }
            pkt.WritePacket(w.ToArray());
        }

        public void OnListenResult(uint forwardId, bool ok, int boundPort, string message)
        {
            if (ok)
            {
                lock (chanGate) { activeForwards[forwardId] = boundPort; }
                Log("forward " + forwardId + " bound to port " + boundPort);
            }
            else
            {
                lock (chanGate) { forwardAddresses.Remove(forwardId); }
                Log("forward " + forwardId + " failed: " + message);
            }

            // Mark this one done, then flush replies from the head while they are ready.
            lock (pendingForwards)
            {
                for (int i = 0; i < pendingForwards.Count; i++)
                {
                    if (pendingForwards[i].ForwardId == forwardId)
                    {
                        pendingForwards[i].Done = true;
                        pendingForwards[i].Ok = ok;
                        pendingForwards[i].BoundPort = boundPort;
                        break;
                    }
                }
                while (pendingForwards.Count > 0 && pendingForwards[0].Done)
                {
                    PendingForward head = pendingForwards[0];
                    pendingForwards.RemoveAt(0);
                    if (head.WantReply)
                    {
                        ReplyGlobal(head.Ok, head.RequestedDynamicPort ? (uint)head.BoundPort : 0);
                    }
                }
            }
        }

        // A connection arrived on a remote listener: open a forwarded-tcpip channel to the
        // client. This is the only place the engine initiates a channel.
        public void OnAccepted(uint ch, uint forwardId, int boundPort, string originAddress, int originPort)
        {
            SessionChannel c;
            string boundAddress;
            lock (chanGate)
            {
                if (!forwardAddresses.TryGetValue(forwardId, out boundAddress))
                {
                    // Raced a cancel-tcpip-forward, or the agent accepted on a listener we no
                    // longer know about. Either way ssh would refuse the open.
                    Log("accepted connection for unknown forward " + forwardId + "; dropping");
                    cfg.Agent.CloseChannel(ch);
                    return;
                }
                if (channels.Count >= MAX_CHANNELS)
                {
                    Log("too many channels; dropping accepted forward " + ch);
                    cfg.Agent.CloseChannel(ch);
                    return;
                }
                // Keyed by the id the agent chose, which comes from a disjoint range.
                c = new SessionChannel(this, pkt, cfg.Agent, ch, 0, 0, MAX_PACKET);
                channels[ch] = c;
            }

            SshWriter w = new SshWriter();
            w.Byte(Msg.CHANNEL_OPEN);
            w.Str("forwarded-tcpip");
            w.UInt32(ch);                  // our channel id
            w.UInt32(INITIAL_WINDOW);
            w.UInt32(MAX_PACKET);
            w.Str(boundAddress);
            w.UInt32((uint)boundPort);
            w.Str(originAddress);
            w.UInt32((uint)originPort);
            pkt.WritePacket(w.ToArray());
            Log("opening forwarded-tcpip " + ch + " from " + originAddress + ":" + originPort);
        }

        private void RejectChannelOpen(uint peerChannel, uint reason, string text)
        {
            SshWriter f = new SshWriter();
            f.Byte(Msg.CHANNEL_OPEN_FAILURE);
            f.UInt32(peerChannel);
            f.UInt32(reason);
            f.Str(text);
            f.Str("");
            pkt.WritePacket(f.ToArray());
            Log("channel open rejected: " + text);
        }

        private void HandleChannelRequest(byte[] payload)
        {
            SshReader r = new SshReader(payload);
            r.Byte();
            uint localChannel = r.UInt32();
            string req = r.StrUtf8();
            bool wantReply = r.Bool();

            SessionChannel channel = Find(localChannel);
            bool ok = false;
            if (channel != null)
            {
                if (req == "exec")
                {
                    string cmd = r.StrUtf8();
                    Log("exec: " + cmd);
                    ok = channel.StartExec(cmd);
                }
                else if (req == "shell")
                {
                    Log("shell");
                    ok = channel.StartShell();
                }
                else if (req == "pty-req")
                {
                    // term, cols, rows, pixel width, pixel height, encoded modes
                    string term = r.StrUtf8();
                    uint cols = r.UInt32();
                    uint rows = r.UInt32();
                    ok = channel.RequestPty(cols, rows, term);
                    // Refusing is a supported outcome, not an error: ssh reports "PTY
                    // allocation request failed" and carries on with a pipe-backed shell.
                    Log(ok ? ("pty-req " + cols + "x" + rows + " " + term)
                           : "pty-req refused: remote has no ConPTY");
                }
                else if (req == "window-change")
                {
                    uint cols = r.UInt32();
                    uint rows = r.UInt32();
                    channel.Resize(cols, rows);
                    ok = true;              // never carries want_reply
                }
                else if (req == "signal")
                {
                    string sig = r.StrUtf8();
                    Log("signal: " + sig);
                    channel.Signal(sig);
                    ok = true;
                }
                else if (req == "subsystem")
                {
                    string name = r.StrUtf8();
                    ok = channel.StartSubsystem(name);
                    Log(ok ? ("subsystem: " + name) : ("subsystem refused: " + name));
                }
                else if (req == "env")
                {
                    ok = true;              // accepted and ignored
                }
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
            uint id = r.UInt32();
            byte[] data = r.Str();
            SessionChannel c = Find(id);
            if (c != null) c.WriteFromClient(data);
        }

        internal void NotifyChannelFinished() { finished = true; }
        internal uint InitialWindow { get { return INITIAL_WINDOW; } }
        internal void LogInternal(string m) { Log(m); }
        internal bool SftpReadAheadEnabled { get { return cfg.SftpReadAheadChunks > 0; } }
        internal int SftpReadAheadChunks { get { return cfg.SftpReadAheadChunks; } }

        // ---- IPwsshChannelSink: called from the agent side, must not block ----

        // The agent addresses channels by our local id, so these are direct lookups.
        public void OnData(uint ch, byte[] buffer, int offset, int count, bool stderr)
        {
            // Prefetch channels are checked first and never fall through: their data belongs to
            // the read-ahead buffer, and writing any of it to ssh would corrupt the client's SFTP
            // stream with replies to requests the client never made.
            SftpReadAhead r = FindPrefetch(ch);
            if (r != null) { r.OnPrefetchData(ch, buffer, offset, count, stderr); return; }

            SessionChannel c = Find(ch);
            if (c != null) c.OnAgentData(buffer, offset, count, stderr);
        }

        public void OnExit(uint ch, uint status)
        {
            SessionChannel c = Find(ch);
            if (c != null) c.OnAgentExit(status);
        }

        public void OnClose(uint ch)
        {
            SessionChannel c = Find(ch);
            if (c != null) c.OnAgentClose();
            // A prefetch channel's agent-side worker has finished. Nothing to tell ssh: it never
            // knew this channel existed.
            SftpReadAhead r = FindPrefetch(ch);
            if (r != null) r.OnPrefetchClosed(ch);
        }

        // Completes a direct-tcpip open. Reason 2 is SSH_OPEN_CONNECT_FAILED, which is what
        // makes ssh print a useful "connect failed" rather than silently handing the user a
        // dead tunnel.
        public void OnConnectResult(uint ch, bool ok, string message)
        {
            SessionChannel c = Find(ch);
            if (c == null) return;

            if (ok)
            {
                ConfirmChannelOpen(c.PeerChannel, ch);
                c.BeginForwarding();
                Log("channel " + ch + " forward established");
            }
            else
            {
                RejectChannelOpen(c.PeerChannel, 2, string.IsNullOrEmpty(message) ? "connect failed" : message);
                ForgetChannel(ch);
            }
        }

        public void OnAgentError(uint ch, string message)
        {
            Log("agent error on channel " + ch + ": " + message);
            lastError = "agent: " + message;

            // Close the channel the agent named, reporting the reason on stderr first so the
            // user sees why. Nothing else does this: the agent's FAIL was previously only
            // logged, so a channel the remote could not start stayed open and ssh waited on it
            // forever. Everything goes through the channel's own queue, so it stays ordered
            // behind any output that did make it out.
            SessionChannel c = Find(ch);
            if (c == null) return;
            byte[] text = Encoding.UTF8.GetBytes("pwssh: " + message + "\r\n");
            c.OnAgentData(text, 0, text.Length, true);
            c.OnAgentExit(1);
            c.OnAgentClose();
            ForgetChannel(ch);
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
            // How much agent credit this chunk represents, which is not always Count. Bytes we
            // synthesised locally were never accrued and so must release nothing, or the
            // accounting drifts upward and eventually withholds credit for good.
            public int Credit;
        }

        private readonly PwsshEngine engine;
        private readonly PacketLayer pkt;
        private readonly IPwsshAgent agent;
        // Two identities: peerChannel addresses ssh, localId addresses the agent. They are
        // different numbers because the client reuses its channel ids and we never do.
        //
        // peerChannel and peerMaxPacket are not readonly because a channel WE open (-R's
        // forwarded-tcpip) exists before the client's confirmation tells us either.
        private readonly uint localId;
        private uint peerChannel;
        private uint peerMaxPacket;

        private readonly object windowGate = new object();
        private long remoteWindow;                 // credit the ssh client has granted us

        private readonly Queue<Chunk> outQ = new Queue<Chunk>();
        private readonly object outGate = new object();

        // Credit is returned to the agent in batches: granting per SSH packet meant ~256 tiny
        // WINDOW frames for an 8 MiB download, all travelling upstream -- the slow direction.
        //
        // Crucially it is returned when data is *received and queued*, not after it reaches
        // ssh. Granting after the send put two windows in series -- the agent's credit could
        // only come back as fast as ssh drained its own 2 MB channel window, so a 48 MiB
        // transfer serialised into ~48 upstream round trips and spent most of its time idle.
        // Queue depth provides the backpressure instead.
        private const int GRANT_THRESHOLD = 2 * 1024 * 1024;
        private const long MAX_PENDING = 32L * 1024 * 1024;
        private readonly object grantGate = new object();
        private long pendingGrant;      // credit earned but not yet announced
        private long pendingBytes;      // queued here, not yet handed to ssh

        private Thread sender;
        private volatile bool killed;
        private bool execStarted;

        // Non-null only on an sftp subsystem channel, and only when read-ahead is enabled.
        private SftpReadAhead sftp;

        public SessionChannel(PwsshEngine e, PacketLayer p, IPwsshAgent a,
                              uint local, uint peer, uint window, uint maxPacket)
        {
            engine = e; pkt = p; agent = a; localId = local; peerChannel = peer;
            remoteWindow = window;
            peerMaxPacket = maxPacket == 0 ? 32768 : maxPacket;
        }

        public uint PeerChannel { get { return peerChannel; } }
        public uint LocalId { get { return localId; } }

        public void AddRemoteWindow(uint add)
        {
            lock (windowGate) { remoteWindow += add; Monitor.PulseAll(windowGate); }
        }

        public bool StartExec(string command)
        {
            if (!BeginSending()) return false;
            agent.Exec(localId, command);
            return true;
        }

        public bool StartShell()
        {
            if (!BeginSending()) return false;
            agent.Shell(localId);
            return true;
        }

        // The name is checked HERE rather than on the remote, because CHANNEL_REQUEST must be
        // answered synchronously and there is no round trip to spend asking. That is sound:
        // sftp is the only subsystem the agent implements, and the agent's source is pushed
        // from this process on every connection, so the two halves cannot disagree. An unknown
        // name therefore gets a clean CHANNEL_FAILURE instead of a hang.
        public bool StartSubsystem(string name)
        {
            if (name != "sftp") return false;
            if (!BeginSending()) return false;
            // Also the only record that this channel is a subsystem, which the class otherwise
            // does not keep.
            if (engine.SftpReadAheadEnabled)
            {
                sftp = new SftpReadAhead(engine, agent, engine.SftpReadAheadChunks);
            }
            agent.Subsystem(localId, name);
            return true;
        }

        // direct-tcpip. The sender thread deliberately does not start here: nothing may be
        // written to the client until the channel has been confirmed, which happens only once
        // the remote socket is actually up.
        public void StartConnect(string host, int port) { agent.Connect(localId, host, port); }

        public void BeginForwarding() { BeginSending(); }

        // Server-initiated channel (-R): the client's confirmation supplies the identity and
        // limits we did not have when the channel was created.
        public void ConfirmOpened(uint peer, uint window, uint maxPacket)
        {
            peerChannel = peer;
            peerMaxPacket = maxPacket == 0 ? 32768 : maxPacket;
            lock (windowGate) { remoteWindow = window; Monitor.PulseAll(windowGate); }
            agent.AcceptOk(localId);
            BeginSending();
        }

        private bool BeginSending()
        {
            if (execStarted) return false;
            execStarted = true;

            sender = new Thread(new ThreadStart(SenderLoop));
            sender.IsBackground = true;
            sender.Name = "pwssh-channel-sender";
            sender.Start();
            return true;
        }

        // pty-req precedes shell/exec, matching SSH's own ordering; the agent holds the
        // parameters until the channel actually starts.
        public bool RequestPty(uint cols, uint rows, string term)
        {
            if (!agent.RemoteSupportsPty) return false;
            agent.RequestPty(localId, cols, rows, term);
            return true;
        }

        public void Resize(uint cols, uint rows) { agent.Resize(localId, cols, rows); }

        public void Signal(string name) { agent.Signal(localId, name); }

        // ---- called from the agent side (must not block) ----

        public void OnAgentData(byte[] buffer, int offset, int count, bool stderr)
        {
            // Gated on !stderr deliberately: OnAgentError synthesises human-readable text through
            // this same method, and parsing that as SFTP would be nonsense.
            if (sftp != null && !stderr) sftp.FromAgent(buffer, offset, count);

            Chunk c = new Chunk();
            c.Kind = Chunk.DATA; c.Data = buffer; c.Offset = offset; c.Count = count; c.Stderr = stderr;
            c.Credit = count;
            Enqueue(c);
            AccrueCredit(count);
        }

        // Credit is earned on arrival so it can travel back while ssh is still being fed, but
        // is withheld once too much is queued here -- otherwise a slow ssh would let the agent
        // fill this process's memory.
        private void AccrueCredit(int received)
        {
            uint grant = 0;
            lock (grantGate)
            {
                pendingBytes += received;
                pendingGrant += received;
                if (pendingGrant >= GRANT_THRESHOLD && pendingBytes < MAX_PENDING)
                {
                    grant = (uint)pendingGrant;
                    pendingGrant = 0;
                }
            }
            if (grant > 0) agent.GrantWindow(localId, grant);
        }

        // Called as the sender drains the queue: releases any credit held back by MAX_PENDING.
        private void ReleaseCredit(int sent)
        {
            uint grant = 0;
            lock (grantGate)
            {
                pendingBytes -= sent;
                if (pendingGrant >= GRANT_THRESHOLD && pendingBytes < MAX_PENDING)
                {
                    grant = (uint)pendingGrant;
                    pendingGrant = 0;
                }
            }
            if (grant > 0) agent.GrantWindow(localId, grant);
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

        // Several chunks that must reach ssh consecutively -- an SFTP reply's header followed by
        // its body segments. Two threads enqueue on an sftp channel (the pump thread forwards
        // replies, the protocol thread answers reads from the buffer), so taking outGate once
        // per chunk would let two multi-chunk writes interleave. The symptom would be SFTP
        // corruption that only appears under load, which is why this exists.
        private void EnqueueAll(Chunk[] chunks)
        {
            lock (outGate)
            {
                for (int i = 0; i < chunks.Length; i++) outQ.Enqueue(chunks[i]);
                Monitor.PulseAll(outGate);
            }
        }

        // ---- called from the ssh side ----

        public void WriteFromClient(byte[] data)
        {
            // Read-ahead observes the SFTP conversation here and may answer a READ from its own
            // buffer instead of letting it reach the remote. It never adds bytes to this stream:
            // its own requests go out on a private channel.
            bool forward = true;
            if (sftp != null) forward = sftp.FromClient(data, 0, data.Length);
            if (forward) agent.SendStdin(localId, data);

            // Eager window adjust: a lazy threshold would cost a full round trip, and on this
            // transport a round trip is ~600-900 ms.
            SshWriter w = new SshWriter();
            w.Byte(Msg.CHANNEL_WINDOW_ADJUST);
            w.UInt32(peerChannel);
            w.UInt32((uint)data.Length);
            pkt.WritePacket(w.ToArray());
        }

        public void ClientEof() { agent.CloseStdin(localId); }

        public void Kill()
        {
            killed = true;
            // Reported once, here, rather than per read: the ratio is the only interesting part,
            // and the tests assert on it because wall-clock on this transport is too noisy to
            // assert on at all.
            if (sftp != null)
            {
                engine.LogInternal(sftp.Summary());
                sftp.Dispose();          // drops any prefetch channel still open on the remote
                sftp = null;
            }
            lock (windowGate) { Monitor.PulseAll(windowGate); }
            lock (outGate) { Monitor.PulseAll(outGate); }
            try { agent.CloseChannel(localId); } catch { }
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

                    if (c.Kind == Chunk.DATA)
                    {
                        SendData(c.Data, c.Offset, c.Count, c.Stderr);
                        // Credit, not Count: see Chunk.Credit.
                        if (c.Credit > 0) ReleaseCredit(c.Credit);
                    }
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
