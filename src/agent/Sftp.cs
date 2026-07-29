// The SFTP version 3 server.
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
    // ------------------------------------------------------------------------ SFTP
    //
    // An SFTP version 3 server. It runs here rather than in the client engine because the
    // files are here, and this speaks the protocol at the end of the pipe the engine carries.
    //
    // The engine is no longer a pure conduit for those bytes, though, and a reader who assumes it
    // is will be surprised: src/PwsshSftpReadAhead.cs parses this conversation as it passes and
    // answers the client's READs from a buffer it fills over a SECOND, private sftp channel. That
    // is invisible from here by design -- the read-ahead's channel is an ordinary channel running
    // an ordinary AgentSftpChannel, and nothing in this file distinguishes it from the client's
    // own. Two consequences worth knowing while editing here: a session may have two of these
    // running against the same file, so nothing may assume one handle per path; and the paths
    // arriving on the private channel are the client's own strings, copied through byte for byte,
    // so path handling must stay identical on both.
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

        // Tripwire, and the cheapest one available. The client can only ever grant back bytes it
        // has actually received, so credit climbing above what it started at means it granted more
        // than arrived -- which silently defeats the bound this window exists to enforce, and is
        // invisible from either side otherwise. One line is proof; there is no arithmetic to
        // interpret. Logged once, because the condition is sticky and would otherwise repeat for
        // the rest of the transfer.
        private bool creditOverGrantLogged;

        public void AddCredit(uint add)
        {
            lock (creditGate)
            {
                credit += add;
                if (credit > PwsshAgentHost.InitialCredit && !creditOverGrantLogged)
                {
                    creditOverGrantLogged = true;
                    host.Log("sftp channel " + channel + ": credit " + credit + " exceeds the initial "
                             + PwsshAgentHost.InitialCredit + "; the client granted more than it received");
                }
                Monitor.PulseAll(creditGate);
            }
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
}
