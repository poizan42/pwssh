// Native file-system calls, so every path can carry the \\?\ extended-length prefix.
//
// Part of the pwssh remote agent. Built to a .NET Framework 4.8 DLL by
// src/agent/PwsshAgent.csproj and pushed to the remote; also compiled together with the engine on
// the client, so it must stay free of any client-only dependency.
//
// WHY NOT JUST USE System.IO WITH A PREFIXED PATH
//
// On .NET Framework 4.6.2 and later that does work -- measured on the test remote, where every
// managed API accepts \\?\ for both long and short paths. It stops working the moment legacy path
// handling is in force, which is the DEFAULT for anything targeting below 4.6.2, and older targets
// are on this project's roadmap. Under legacy handling the managed layer rejects \\?\ outright AND
// blocks paths past MAX_PATH, so there is no prefix trick that saves it. Going native once is
// cheaper than doing it twice.
//
// WHY THE PREFIX AT ALL
//
// An unprefixed path past MAX_PATH depends on the LongPathsEnabled machine policy *and* a
// longPathAware manifest on the host process. The test remote happens to have both, which is
// exactly why long paths appear to work there today and would fail for a user without the policy.
// \\?\ has been a Win32 contract since Windows 2000 and needs neither.
//
// WHAT THE PREFIX COSTS
//
// It disables all path normalisation: no ".", no "..", no forward slashes, no relative segments,
// and trailing dots and spaces are preserved rather than trimmed. Callers must hand over a fully
// normalised, rooted, backslash-only path -- see AgentSftpChannel.ToWindows. A ".." left in a
// prefixed path is not resolved, it is looked up as a directory with that literal name.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Pwssh
{
    internal static class Win32Fs
    {
        public const string Prefix = @"\\?\";

        // A struct-layout mistake in this file is silent: the wrong padding yields plausible-looking
        // garbage rather than an error, so it survives a bit-exactness check and only shows up as odd
        // names and 1601 timestamps. These are the documented native sizes; failing loudly at load is
        // worth four lines.
        static Win32Fs()
        {
            int find = Marshal.SizeOf(typeof(FindData));
            int attrs = Marshal.SizeOf(typeof(FileAttributeData));
            if (find != 592 || attrs != 36)
                throw new InvalidOperationException(
                    "Win32Fs struct layout is wrong: WIN32_FIND_DATAW is " + find + " bytes (expected 592), " +
                    "WIN32_FILE_ATTRIBUTE_DATA is " + attrs + " bytes (expected 36)");
        }

        // Observability. A long path taking the extended route is otherwise invisible from either
        // end, and "it works" on a machine with the policy enabled proves nothing about a machine
        // without it -- so record that the route was actually exercised.
        private static int longPathsSeen;
        private static int longestPath;

        public static int LongPathsSeen { get { return longPathsSeen; } }
        public static int LongestPath { get { return longestPath; } }

        public static string Extended(string fullPath)
        {
            if (fullPath == null) return null;
            if (fullPath.StartsWith(Prefix, StringComparison.Ordinal)) return fullPath;

            if (fullPath.Length > longestPath) longestPath = fullPath.Length;
            if (fullPath.Length >= 260) longPathsSeen++;
            return Prefix + fullPath;
        }

        // The inverse, for anything travelling back to the client: a prefixed path handed to
        // ToSftp would come out as "/?/C:/x".
        public static string Strip(string path)
        {
            if (path == null) return null;
            return path.StartsWith(Prefix, StringComparison.Ordinal) ? path.Substring(Prefix.Length) : path;
        }

        // ---- imports ----
        //
        // SetLastError on every one, and GetLastWin32Error is read immediately at each call site --
        // any intervening managed call, including anything in a finally, can overwrite it.

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
                                                         IntPtr security, uint disposition,
                                                         uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetFileAttributesExW")]
        private static extern bool GetFileAttributesExW(string path, int infoLevel, out FileAttributeData data);

        // CreateSymbolicLinkW returns BOOLEAN -- a single byte -- where every other import here
        // returns BOOL, four bytes. Default marshalling for a `bool` return is the 4-byte form, so
        // without the explicit U1 this reads three undefined bytes alongside the real answer and the
        // success test becomes intermittently wrong. Copying the CreateHardLinkW import next door,
        // which really is BOOL, is exactly how that happens.
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateSymbolicLinkW")]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool CreateSymbolicLinkW(string link, string target, uint flags);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
        private static extern bool DeviceIoControl(SafeFileHandle handle, uint code,
                                                   IntPtr inBuf, int inSize,
                                                   byte[] outBuf, int outSize,
                                                   out int returned, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SetFileAttributesW")]
        private static extern bool SetFileAttributesW(string path, uint attributes);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateDirectoryW")]
        private static extern bool CreateDirectoryW(string path, IntPtr security);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RemoveDirectoryW")]
        private static extern bool RemoveDirectoryW(string path);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "DeleteFileW")]
        private static extern bool DeleteFileW(string path);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "FindFirstFileW")]
        private static extern IntPtr FindFirstFileW(string pattern, out FindData data);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "FindNextFileW")]
        private static extern bool FindNextFileW(IntPtr handle, out FindData data);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileTime(SafeFileHandle handle, IntPtr creation,
                                               ref long lastAccess, ref long lastWrite);

        // Pack = 4 on both of these is load-bearing, not decoration. A FILETIME is two DWORDs, so
        // every member of the native structs is 4-byte aligned and nothing is padded. Declaring the
        // times as `long` makes the CLR want 8-byte alignment and insert four bytes after the
        // attributes, which shifts every field behind it: times read as 1601, sizes as 0, and a name
        // read two WCHARs late -- "shallow.txt" came back as "allow.txt", and "." and ".." came back
        // empty so they stopped being recognised and a recursive get recursed until the client's
        // 64-level limit. Found exactly that way.
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        private struct FileAttributeData
        {
            public uint Attributes;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public uint SizeHigh;
            public uint SizeLow;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
        private struct FindData
        {
            public uint Attributes;
            public long CreationTime;
            public long LastAccessTime;
            public long LastWriteTime;
            public uint SizeHigh;
            public uint SizeLow;
            public uint Reserved0;
            public uint Reserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AlternateName;
        }

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_WRITE_ATTRIBUTES = 0x0100;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
        private const uint FILE_ATTRIBUTE_NORMAL = 0x0080;
        private const int INVALID_FILE_ATTRIBUTES = -1;
        private const uint FILE_READ_ATTRIBUTES = 0x0080;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_SHARE_ALL = 0x1 | 0x2 | 0x4;      // read | write | delete

        private const uint FSCTL_GET_REPARSE_POINT = 0x000900A8;
        private const uint IO_REPARSE_TAG_SYMLINK = 0xA000000C;
        private const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;   // junctions
        private const uint SYMLINK_FLAG_RELATIVE = 0x1;
        private const int MAX_REPARSE_BUFFER = 16 * 1024;             // MAXIMUM_REPARSE_DATA_BUFFER_SIZE

        private const uint SYMBOLIC_LINK_FLAG_DIRECTORY = 0x1;
        // Lets CreateSymbolicLinkW succeed without SeCreateSymbolicLinkPrivilege when Developer Mode
        // is on, from Windows 10 build 14972. Measured, not assumed: on the machine this was written
        // on -- filtered token, privilege absent, Developer Mode on -- the call succeeds with this
        // flag and fails 1314 without it. Do not "simplify" it away.
        private const uint SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = 0x2;

        public const uint FILE_ATTRIBUTE_DIRECTORY = 0x0010;
        public const uint FILE_ATTRIBUTE_READONLY = 0x0001;
        public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x0400;

        // ---- what callers use ----

        public struct Info
        {
            public uint Attributes;
            public long Size;
            public DateTime AccessUtc;
            public DateTime WriteUtc;

            public bool IsDirectory { get { return (Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0; } }
            public bool IsReadOnly { get { return (Attributes & FILE_ATTRIBUTE_READONLY) != 0; } }
            public bool IsReparsePoint { get { return (Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0; } }
        }

        public sealed class Entry
        {
            public string Name;
            public Info Info;
        }

        public static bool TryGetInfo(string fullPath, out Info info)
        {
            info = new Info();
            FileAttributeData d;
            if (!GetFileAttributesExW(Extended(fullPath), 0, out d)) return false;
            info = ToInfo(d.Attributes, d.SizeHigh, d.SizeLow, d.LastAccessTime, d.LastWriteTime);
            return true;
        }

        public static Info GetInfo(string fullPath)
        {
            FileAttributeData d;
            if (!GetFileAttributesExW(Extended(fullPath), 0, out d))
                throw Error(Marshal.GetLastWin32Error(), fullPath);
            return ToInfo(d.Attributes, d.SizeHigh, d.SizeLow, d.LastAccessTime, d.LastWriteTime);
        }

        public static bool Exists(string fullPath)
        {
            Info ignored;
            return TryGetInfo(fullPath, out ignored);
        }

        public static bool DirectoryExists(string fullPath)
        {
            Info i;
            return TryGetInfo(fullPath, out i) && i.IsDirectory;
        }

        public static bool FileExists(string fullPath)
        {
            Info i;
            return TryGetInfo(fullPath, out i) && !i.IsDirectory;
        }

        private static Info ToInfo(uint attrs, uint hi, uint lo, long access, long write)
        {
            Info i = new Info();
            i.Attributes = attrs;
            i.Size = (long)(((ulong)hi << 32) | lo);
            i.AccessUtc = FromFileTime(access);
            i.WriteUtc = FromFileTime(write);
            return i;
        }

        // A zero or nonsensical FILETIME is what an empty drive or an odd filesystem reports; the
        // epoch is a better answer than an exception from DateTime.
        private static DateTime FromFileTime(long ft)
        {
            if (ft <= 0) return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            try { return DateTime.FromFileTimeUtc(ft); }
            catch (Exception) { return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); }
        }

        // The handle is wrapped in a FileStream rather than replaced by ReadFile/WriteFile, which is
        // what keeps this change small: only path resolution moves to Win32, while buffering,
        // Position, Read/Write, SetLength and Flush(true) all keep behaving exactly as before.
        public static FileStream Open(string fullPath, FileMode mode, FileAccess access,
                                      FileShare share, bool sequential, int bufferSize)
        {
            uint desired = 0;
            if ((access & FileAccess.Read) != 0) desired |= GENERIC_READ;
            if ((access & FileAccess.Write) != 0) desired |= GENERIC_WRITE;

            uint disposition;
            switch (mode)
            {
                case FileMode.CreateNew: disposition = 1; break;
                case FileMode.Create: disposition = 2; break;
                case FileMode.Open: disposition = 3; break;
                case FileMode.OpenOrCreate: disposition = 4; break;
                case FileMode.Truncate: disposition = 5; break;
                case FileMode.Append: disposition = 4; break;
                default: throw new ArgumentException("unsupported file mode " + mode);
            }

            uint flags = FILE_ATTRIBUTE_NORMAL;
            if (sequential) flags |= FILE_FLAG_SEQUENTIAL_SCAN;

            SafeFileHandle h = CreateFileW(Extended(fullPath), desired, ShareFlags(share),
                                          IntPtr.Zero, disposition, flags, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                h.Dispose();
                throw Error(err, fullPath);
            }

            FileStream fs = new FileStream(h, access, bufferSize);
            // FileStream over a handle does not know about append mode, so honour it here.
            if (mode == FileMode.Append) fs.Seek(0, SeekOrigin.End);
            return fs;
        }

        private static uint ShareFlags(FileShare share)
        {
            uint f = 0;
            if ((share & FileShare.Read) != 0) f |= 1;
            if ((share & FileShare.Write) != 0) f |= 2;
            if ((share & FileShare.Delete) != 0) f |= 4;
            return f;
        }

        public static void CreateDirectory(string fullPath)
        {
            if (CreateDirectoryW(Extended(fullPath), IntPtr.Zero)) return;
            throw Error(Marshal.GetLastWin32Error(), fullPath);
        }

        public static void RemoveDirectory(string fullPath)
        {
            if (RemoveDirectoryW(Extended(fullPath))) return;
            throw Error(Marshal.GetLastWin32Error(), fullPath);
        }

        public static void DeleteFile(string fullPath)
        {
            if (DeleteFileW(Extended(fullPath))) return;
            throw Error(Marshal.GetLastWin32Error(), fullPath);
        }

        public static void SetAttributes(string fullPath, uint attributes)
        {
            if (SetFileAttributesW(Extended(fullPath), attributes)) return;
            throw Error(Marshal.GetLastWin32Error(), fullPath);
        }

        // ---- links ----

        /// <summary>
        /// The target a reparse point names, exactly as stored. Handles symbolic links and junctions;
        /// any other tag throws, because the rest carry no path at all.
        /// </summary>
        /// <param name="relative">
        /// True when the link stores a relative target. Only symbolic links can: a junction has no
        /// Flags field and is always absolute.
        /// </param>
        public static string ReadLink(string fullPath, out bool relative)
        {
            relative = false;

            // No access rights at all: FSCTL_GET_REPARSE_POINT is FILE_ANY_ACCESS, so this reads a
            // link whose target -- or whose own DACL -- denies reading. OPEN_REPARSE_POINT to get the
            // link rather than what it points at, BACKUP_SEMANTICS because most reparse points on
            // Windows are directories and CreateFileW refuses those without it.
            SafeFileHandle h = CreateFileW(Extended(fullPath), 0, FILE_SHARE_ALL, IntPtr.Zero,
                                           OPEN_EXISTING,
                                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                                           IntPtr.Zero);
            if (h.IsInvalid)
            {
                int openErr = Marshal.GetLastWin32Error();
                h.Dispose();
                throw Error(openErr, fullPath);
            }

            byte[] buf = new byte[MAX_REPARSE_BUFFER];
            int returned;
            try
            {
                if (!DeviceIoControl(h, FSCTL_GET_REPARSE_POINT, IntPtr.Zero, 0, buf, buf.Length,
                                     out returned, IntPtr.Zero))
                    throw Error(Marshal.GetLastWin32Error(), fullPath);
            }
            finally { h.Dispose(); }

            // Parsed by hand at explicit offsets rather than through a [StructLayout] struct. The
            // static assertions at the top of this file exist because a layout mistake here is silent
            // and produces plausible-looking garbage; there is no fixed-size array to marshal, so
            // there is nothing to gain by reintroducing that hazard.
            //
            //   0  ReparseTag           uint32
            //   4  ReparseDataLength    uint16   -- counts everything from offset 8
            //   6  Reserved             uint16
            //   8  SubstituteNameOffset uint16   -- byte offsets INTO PathBuffer, NUL not counted
            //  10  SubstituteNameLength uint16
            //  12  PrintNameOffset      uint16
            //  14  PrintNameLength      uint16
            //  16  Flags                uint32   -- SYMLINK ONLY; a junction's PathBuffer starts here
            //  20  PathBuffer                    -- symlink
            if (returned < 8) throw new IOException("reparse reply too short: " + fullPath);
            uint tag = BitConverter.ToUInt32(buf, 0);
            int dataLen = BitConverter.ToUInt16(buf, 4);
            if (8 + dataLen > returned) throw new IOException("reparse reply truncated: " + fullPath);

            int pathBase;
            if (tag == IO_REPARSE_TAG_SYMLINK)
            {
                if (dataLen < 12) throw new IOException("symlink reparse data too short: " + fullPath);
                relative = (BitConverter.ToUInt32(buf, 16) & SYMLINK_FLAG_RELATIVE) != 0;
                pathBase = 20;
            }
            else if (tag == IO_REPARSE_TAG_MOUNT_POINT)
            {
                if (dataLen < 8) throw new IOException("junction reparse data too short: " + fullPath);
                pathBase = 16;
            }
            else
            {
                // Every reparse point is reported as a link by LSTAT, but most tags carry no path:
                // AppExecLink (0x8000001B) under WindowsApps, the cloud-provider tags OneDrive uses,
                // WSL's 0xA000001D. Naming the tag is what lets someone identify it.
                throw new IOException("not a path-bearing link (reparse tag 0x"
                    + tag.ToString("X8", CultureInfo.InvariantCulture) + "): " + fullPath);
            }

            int subOff = BitConverter.ToUInt16(buf, 8);
            int subLen = BitConverter.ToUInt16(buf, 10);
            int printOff = BitConverter.ToUInt16(buf, 12);
            int printLen = BitConverter.ToUInt16(buf, 14);

            // SubstituteName is what the filesystem actually follows; PrintName is a display hint that
            // nothing enforces, and it is empty for volume mount points. Prefer the former.
            //
            // The two names do NOT appear in a fixed order inside PathBuffer -- a live symlink here
            // stores PrintName first, a live junction stores SubstituteName first -- so both must be
            // located by their offsets and never by assuming a layout.
            string target = ReparseName(buf, pathBase, subOff, subLen, dataLen, fullPath);
            if (target.Length == 0)
                target = ReparseName(buf, pathBase, printOff, printLen, dataLen, fullPath);
            if (target.Length == 0) throw new IOException("link has no target: " + fullPath);

            // "\??\C:\x" is the object-manager form the substitute name uses; Strip is belt and braces
            // for a stored "\\?\" that came from somewhere else.
            if (target.StartsWith(@"\??\", StringComparison.Ordinal)) target = target.Substring(4);
            return Strip(target);
        }

        private static string ReparseName(byte[] buf, int pathBase, int off, int len, int dataLen, string path)
        {
            if (len <= 0) return "";
            if ((len & 1) != 0) throw new IOException("odd reparse name length: " + path);
            // Offsets are attacker-adjacent only in the sense that a corrupt filesystem could produce
            // them, but slicing outside the reply would be an out-of-range throw at best.
            if (off < 0 || pathBase + off + len > 8 + dataLen)
                throw new IOException("reparse name outside the reply: " + path);
            return Encoding.Unicode.GetString(buf, pathBase + off, len);
        }

        /// <summary>
        /// Creates a symbolic link. <paramref name="target"/> is stored verbatim and must NOT be
        /// extended-length prefixed: it is written into the link, not opened, and a "\\?\" would show
        /// up in every ordinary tool on the remote that displays it.
        /// </summary>
        public static void CreateSymbolicLink(string linkFullPath, string target, bool targetIsDirectory)
        {
            uint flags = targetIsDirectory ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0;

            if (CreateSymbolicLinkW(Extended(linkFullPath), target,
                                    flags | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE))
                return;
            int err = Marshal.GetLastWin32Error();

            // The unprivileged-create flag arrived in build 14972. Older builds -- Server 2016 and
            // below, which is exactly the population this project targets, since newer machines
            // already have an SSH server -- reject it in parameter validation, before touching the
            // filesystem. So retry without it, but ONLY on that one error: a blanket retry could run
            // a second creation attempt against a name the first attempt had already half-made.
            if (err != 87) throw Error(err, linkFullPath);          // ERROR_INVALID_PARAMETER

            if (CreateSymbolicLinkW(Extended(linkFullPath), target, flags)) return;
            throw Error(Marshal.GetLastWin32Error(), linkFullPath);
        }

        // By path rather than on an open handle, because scp -p sets times after the data handle has
        // been closed and flushed -- see the deferred-times note in Sftp.cs. BACKUP_SEMANTICS so the
        // same call works for a directory.
        /// <param name="noFollow">
        /// Stamp the link itself rather than what it points at. That is what lsetstat means, and
        /// without it the two differ only in name.
        /// </param>
        public static void SetTimesUtc(string fullPath, DateTime accessUtc, DateTime writeUtc, bool noFollow)
        {
            uint flags = FILE_FLAG_BACKUP_SEMANTICS;
            if (noFollow) flags |= FILE_FLAG_OPEN_REPARSE_POINT;
            SafeFileHandle h = CreateFileW(Extended(fullPath), FILE_WRITE_ATTRIBUTES,
                                           1 | 2 | 4, IntPtr.Zero, 3,
                                           flags, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int err = Marshal.GetLastWin32Error();
                h.Dispose();
                throw Error(err, fullPath);
            }
            try
            {
                long a = accessUtc.ToFileTimeUtc();
                long w = writeUtc.ToFileTimeUtc();
                if (!SetFileTime(h, IntPtr.Zero, ref a, ref w))
                    throw Error(Marshal.GetLastWin32Error(), fullPath);
            }
            finally { h.Dispose(); }
        }

        // One pass gives name, attributes, size and both times per entry, so a listing no longer
        // stats each name separately. Snapshotted rather than returned lazily: the client comes back
        // for the next batch a round trip later, and holding a Find handle open across that buys
        // nothing.
        public static List<Entry> List(string fullDirPath)
        {
            List<Entry> entries = new List<Entry>();
            string pattern = Extended(fullDirPath);
            if (!pattern.EndsWith("\\", StringComparison.Ordinal)) pattern += "\\";
            pattern += "*";

            FindData d;
            IntPtr h = FindFirstFileW(pattern, out d);
            if (h == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                // An empty directory still yields "." and "..", so NO_MORE_FILES here means the
                // directory itself was not readable rather than merely empty.
                if (err == 18) return entries;             // ERROR_NO_MORE_FILES
                throw Error(err, fullDirPath);
            }
            try
            {
                do
                {
                    // FindFirstFile returns "." and ".."; GetFileSystemInfos did not, and forgetting
                    // to drop them puts two bogus rows in every listing.
                    if (d.FileName == "." || d.FileName == "..") continue;
                    Entry e = new Entry();
                    e.Name = d.FileName;
                    e.Info = ToInfo(d.Attributes, d.SizeHigh, d.SizeLow, d.LastAccessTime, d.LastWriteTime);
                    entries.Add(e);
                }
                while (FindNextFileW(h, out d));
            }
            finally { FindClose(h); }
            return entries;
        }

        // ---- errors ----
        //
        // The TYPES here are load-bearing. AgentSftpChannel.StatusFor keys on them to choose the
        // SFTP status, so a Win32Exception everywhere would silently turn every "no such file" into
        // a generic failure and no bit-exactness test would notice.
        private static Exception Error(int err, string path)
        {
            switch (err)
            {
                case 2:                                     // ERROR_FILE_NOT_FOUND
                    return new FileNotFoundException("no such file: " + path, path);
                case 3:                                     // ERROR_PATH_NOT_FOUND
                case 15:                                    // ERROR_INVALID_DRIVE
                    return new DirectoryNotFoundException("no such directory: " + path);
                case 5:                                     // ERROR_ACCESS_DENIED
                    return new UnauthorizedAccessException("access denied: " + path);
                case 32:                                    // ERROR_SHARING_VIOLATION
                    return new IOException("in use by another process: " + path);
                case 80:                                    // ERROR_FILE_EXISTS
                case 183:                                   // ERROR_ALREADY_EXISTS
                    return new IOException("already exists: " + path);
                case 145:                                   // ERROR_DIR_NOT_EMPTY
                    return new IOException("directory not empty: " + path);
                case 267:                                   // ERROR_DIRECTORY
                    return new IOException("not a directory: " + path);
                case 206:                                   // ERROR_FILENAME_EXCED_RANGE
                    return new PathTooLongException("path too long even for the extended form: " + path);
                case 1314:                                  // ERROR_PRIVILEGE_NOT_HELD
                    // Deliberately does not say "elevation", which is the myth this replaced: an
                    // elevated INTERACTIVE token is still filtered, and what actually matters is
                    // which token the logon produced. Any one of the three routes below is enough.
                    //
                    // The trailing path is not decoration -- it names the LINK, and it is the only
                    // thing a caller can key on when this fires before any path is validated.
                    return new UnauthorizedAccessException(
                        "cannot create a symbolic link: the account needs SeCreateSymbolicLinkPrivilege "
                        + "in a non-restricted token (a remote logon normally carries it; a filtered or "
                        + "loopback token does not), or group policy leaving that privilege in the "
                        + "restricted token, or Developer Mode enabled on the remote: " + path);
                case 4390:                                  // ERROR_NOT_A_REPARSE_POINT
                    return new IOException("not a link: " + path);
                default:
                    return new IOException("win32 error " + err.ToString(CultureInfo.InvariantCulture)
                                           + " on " + path);
            }
        }
    }
}
