// Pseudoconsole support, plus the job object and pipe peek it needs.
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

        // 0 means "the client does not know"; anything absurd would be a bad resize too.
        public static uint Clamp(uint value, uint fallback)
        {
            if (value == 0) return fallback;
            return value > 9999 ? 9999 : value;
        }
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
        //
        // The result is computed into a local and published only at the end, which is load-bearing
        // rather than style. Assigning `available = 0` up front and raising it to 1 on success
        // publishes "no ConPTY here" for the whole duration of the probe, so a second thread arriving
        // in that window takes the early return and reports conpty=0 in its HELLO -- and pty-req is
        // then refused for that connection with nothing wrong. It is reachable: PwsshAgentHost.Start
        // calls this per connection and the dev host serves each connection on its own thread, so two
        // clients connecting together race. Found by the xUnit pty tests, whose readiness probe opens
        // a throwaway connection immediately before the real one.
        //
        // Two threads may now both probe, which is harmless: the probe has no side effects that
        // outlive it and both compute the same answer, so publishing is idempotent.
        public static bool IsAvailable()
        {
            if (available >= 0) return available == 1;

            int result = 0;
            try
            {
                IntPtr k = GetModuleHandle("kernel32.dll");
                if (k == IntPtr.Zero || GetProcAddress(k, "CreatePseudoConsole") == IntPtr.Zero)
                {
                    available = 0;
                    return false;
                }

                IntPtr inR, inW, outR, outW, hPC;
                if (!CreatePipe(out inR, out inW, IntPtr.Zero, 0))
                {
                    available = 0;
                    return false;
                }
                if (!CreatePipe(out outR, out outW, IntPtr.Zero, 0))
                {
                    CloseHandle(inR); CloseHandle(inW);
                    available = 0;
                    return false;
                }
                COORD sz; sz.X = 1; sz.Y = 1;
                int hr = CreatePseudoConsole(sz, inR, outW, 0, out hPC);
                CloseHandle(inR); CloseHandle(outW);
                if (hr == 0) { ClosePseudoConsole(hPC); result = 1; }
                CloseHandle(inW); CloseHandle(outR);
            }
            catch (Exception) { result = 0; }

            available = result;
            return result == 1;
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
}
