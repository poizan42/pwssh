// A channel backed by a child process: exec, shell, and pty sessions.
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
    // ------------------------------------------------------------------ agent channel
    //
    // Two modes that converge on the same shape: an output pump, a stdin writer, and a waiter
    // that emits EXIT then DONE. Only process creation differs -- and the fact that a pty has
    // a single merged output stream, because a terminal has no separate stderr.

    internal sealed class AgentChannel : IAgentStream
    {
        private const int READ_BUFFER = 65536;

        private readonly PwsshAgentHost host;
        private readonly uint channel;
        private readonly object creditGate = new object();
        private long credit = PwsshAgentHost.InitialCredit;

        private Process proc;              // pipe mode
        private ConPtySession pty;         // pty mode
        private JobObject job;             // pipe mode; the pty session owns its own
        private int pumpsDone;
        private int expectedPumps;
        private volatile bool killed;

        public AgentChannel(PwsshAgentHost h, uint ch) { host = h; channel = ch; }

        public bool HasPty { get { return pty != null; } }

        public void AddCredit(uint add)
        {
            lock (creditGate) { credit += add; Monitor.PulseAll(creditGate); }
        }

        // commandLine is a full command line: "cmd.exe" for a shell, "cmd.exe /c ..." for exec.
        // ptyReq is null when the client did not ask for a terminal, or when the remote cannot
        // provide one -- the client has already been told which, via the HELLO capabilities.
        public bool Start(string commandLine, PtyRequest ptyReq)
        {
            if (proc != null || pty != null) return false;

            if (ptyReq != null && ConPtySession.IsAvailable())
            {
                return StartPty(commandLine, ptyReq);
            }
            return StartPiped(commandLine);
        }

        private bool StartPty(string commandLine, PtyRequest req)
        {
            try
            {
                ConPtySession s = new ConPtySession();
                if (!s.Start(commandLine, req.Cols, req.Rows))
                {
                    host.Log("ConPTY start failed; falling back to pipes");
                    s.Dispose();
                    return StartPiped(commandLine);
                }
                pty = s;
                expectedPumps = 1;                      // one merged stream
                StartPump(pty.Output, false);
                Thread wait = new Thread(new ThreadStart(WaitForPtyExit));
                wait.IsBackground = true;
                wait.Start();
                host.Log("pty channel " + channel + " started " + req.Cols + "x" + req.Rows);
                return true;
            }
            catch (Exception ex)
            {
                host.Log("pty start failed: " + ex.Message);
                return StartPiped(commandLine);
            }
        }

        private bool StartPiped(string commandLine)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = PwsshAgentHost.ShellPath();
                // The shell itself takes no arguments; exec passes "/c <command>".
                string shell = psi.FileName;
                if (commandLine.Length > shell.Length + 1 &&
                    commandLine.StartsWith(shell, StringComparison.OrdinalIgnoreCase))
                {
                    psi.Arguments = commandLine.Substring(shell.Length).TrimStart();
                }
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardInput = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;

                proc = Process.Start(psi);

                job = new JobObject();
                try { job.Assign(proc.Handle); } catch (Exception ex) { host.Log("job assign failed: " + ex.Message); }

                expectedPumps = 2;
                StartPump(proc.StandardOutput.BaseStream, false);
                StartPump(proc.StandardError.BaseStream, true);

                Thread wait = new Thread(new ThreadStart(WaitForProcExit));
                wait.IsBackground = true;
                wait.Start();
                return true;
            }
            catch (Exception ex)
            {
                host.Log("start failed: " + ex.Message);
                return false;
            }
        }

        public void Resize(uint cols, uint rows)
        {
            if (pty != null) pty.Resize(cols, rows);
        }

        private void StartPump(Stream src, bool isStderr)
        {
            // The handle must be taken before anything is read: reading FileStream's
            // SafeFileHandle flushes it, and a pipe cannot be repositioned.
            IntPtr h = (pty != null && !isStderr) ? pty.OutputHandle : PipePeek.HandleOf(src);
            Thread t = new Thread(new ThreadStart(delegate { Pump(src, isStderr, h); }));
            t.IsBackground = true;
            t.Start();
        }

        // Raw streams only. PowerShell's native-command bridge decodes as text and splits
        // lines, which destroys binary: measured 128 of 256 byte values lost.
        private void Pump(Stream src, bool isStderr, IntPtr handle)
        {
            byte[] buf = new byte[READ_BUFFER];
            try
            {
                while (!killed)
                {
                    int n = src.Read(buf, 0, buf.Length);
                    if (n <= 0) break;

                    // Coalesce whatever is *already* pending into the same frame. Output that
                    // trickles out slowly would otherwise become hundreds of tiny frames, and
                    // each time the client's queue empties the refill costs a WinRM turnaround.
                    //
                    // The condition is "bytes are available right now", never a timer, so a
                    // lone keystroke echo is still sent immediately and interactive latency is
                    // unchanged. A misleading peek can only cost the optimisation, never data:
                    // the reads still go through the stream.
                    if (!PwsshAgentHost.DisableCoalescing && handle != IntPtr.Zero)
                    {
                        while (n < buf.Length && PipePeek.Available(handle) > 0)
                        {
                            int more = src.Read(buf, n, buf.Length - n);
                            if (more <= 0) break;
                            n += more;
                        }
                    }

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

                byte kind = isStderr ? FrameType.ERR : FrameType.OUT;

                // Adaptive: only send compressed when it pays, so already-compressed output is
                // not penalised. Credit stays in uncompressed bytes, matching the SSH window.
                byte[] packed = null;
                try { packed = Zip.Deflate(buf, off, allowed); }
                catch (Exception ex) { host.Log("deflate failed: " + ex.Message); }

                if (packed != null && packed.Length < allowed - (allowed / 8))
                {
                    host.Send(Frame.Make((byte)(kind | FrameType.COMPRESSED), channel, packed));
                }
                else
                {
                    host.Send(Frame.Make(kind, channel, buf, off, allowed));
                }
                off += allowed;
            }
        }

        // IAgentStream: for a process-backed channel the stream is the child's stdin.
        public void Write(byte[] frame, int offset, int count)
        {
            if (count <= 0) return;
            try
            {
                if (pty != null)
                {
                    pty.Input.Write(frame, offset, count);
                    pty.Input.Flush();
                }
                else if (proc != null && !proc.HasExited)
                {
                    proc.StandardInput.BaseStream.Write(frame, offset, count);
                    proc.StandardInput.BaseStream.Flush();
                }
            }
            catch (Exception ex) { host.Log("stdin write failed: " + ex.Message); }
        }

        public void CloseWrite()
        {
            try
            {
                if (pty != null) { pty.Input.Dispose(); }
                else if (proc != null) { proc.StandardInput.BaseStream.Close(); }
            }
            catch { }
        }

        private void WaitForProcExit()
        {
            try
            {
                proc.WaitForExit();
                DrainPumps();
                Finish((uint)proc.ExitCode);
            }
            catch (Exception ex)
            {
                host.Log("wait failed: " + ex.Message);
                host.Send(Frame.MakeText(FrameType.FAIL, channel, ex.Message));
                host.Forget(channel);
            }
        }

        private void WaitForPtyExit()
        {
            try
            {
                pty.WaitForExit();
                uint code = pty.ExitCode;
                // Closing the pseudoconsole is what makes the output pump see EOF, so it has
                // to happen before waiting for that pump to finish.
                pty.Dispose();
                DrainPumps();
                Finish(code);
            }
            catch (Exception ex)
            {
                host.Log("pty wait failed: " + ex.Message);
                host.Send(Frame.MakeText(FrameType.FAIL, channel, ex.Message));
                host.Forget(channel);
            }
        }

        private void DrainPumps()
        {
            for (int i = 0; i < 300 && pumpsDone < expectedPumps; i++) Thread.Sleep(10);
        }

        private void Finish(uint code)
        {
            host.Log("channel " + channel + " exited " + code);
            host.Send(Frame.MakeUInt32(FrameType.EXIT, channel, code));
            host.Send(Frame.Make(FrameType.DONE, channel, null));
            host.Forget(channel);
        }

        public void Kill()
        {
            killed = true;
            lock (creditGate) { Monitor.PulseAll(creditGate); }
            try { if (pty != null) pty.Kill(); } catch { }
            try { if (proc != null && !proc.HasExited) proc.Kill(); } catch { }
            try { if (job != null) job.Dispose(); } catch { }   // takes the child's children too
        }
    }
}
