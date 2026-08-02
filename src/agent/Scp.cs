// The legacy scp protocol -- rcp over ssh -- served in the agent.
//
// Part of the pwssh remote agent. Built to a .NET Framework 4.8 DLL by
// src/agent/PwsshAgent.csproj and pushed to the remote; also compiled together with the engine on
// the client, so it must stay free of any client-only dependency.
//
// WHY THIS EXISTS WHEN SFTP ALREADY DOES
//
// scp works against pwssh today only by accident of version: OpenSSH 9.x's scp speaks SFTP. Every
// other scp client speaks this protocol, and for that the client execs `scp -f path` or
// `scp -t path` AS A REMOTE COMMAND -- which needs an scp binary on the remote, exactly what a
// pwssh target is defined not to have. So `scp -O`, OpenSSH before 9.0, PuTTY's pscp, SSH.NET's
// ScpClient, JSch and paramiko's SCPClient all fail without this.
//
// WHAT THE PROTOCOL IS
//
// A byte stream of control records, each individually acknowledged with ONE status byte:
// 0 = ok, 1 = error + message + \n, 2 = fatal + message + \n. Records are
//   C<mode> <size> <name>\n   a file, followed by exactly <size> raw bytes
//   D<mode> 0 <name>\n        enter a directory (-r)
//   E\n                       leave it
//   T<mtime> 0 <atime> 0\n    times for the next entity (-p)
//
// Everything here was measured against the real C:\Program Files\OpenSSH\scp.exe rather than read
// out of a specification -- `scp -f` and `scp -t` are pure stdin/stdout programs, so both halves
// can be driven over pipes with no SSH in the loop, the same way `sftp -D` settled the SFTP
// conventions. Two results from that probe changed this code and are called out where they apply:
// E at depth 0 is ACCEPTED rather than refused, and a nacked C line makes a real source ABORT
// rather than skip to the next file.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace Pwssh
{
    // ------------------------------------------------------------------ the command line
    //
    // The command arrives as one raw string that a POSIX shell would normally have split, because
    // that is what a real remote would have done with it. So it has to be tokenised here.

    internal sealed class ScpCommand
    {
        public bool Source;                 // -f, we send
        public bool Sink;                   // -t, we receive
        public bool Recursive;              // -r
        public bool PreserveTimes;          // -p
        public bool TargetMustBeDir;        // -d
        public string BadFlag;              // set when an unknown flag was seen
        public readonly List<string> Paths = new List<string>();

        /// <summary>
        /// Recognises an scp server invocation. Returns false for anything else, which then runs
        /// as an ordinary command.
        /// </summary>
        public static bool TryParse(string commandLine, out ScpCommand cmd)
        {
            cmd = null;
            List<string> tokens;
            if (!TryTokenize(commandLine, out tokens)) return false;
            if (tokens.Count == 0) return false;

            // Exactly "scp", so that a user who genuinely wants to run some other program called
            // scp.exe, or a path to one, still gets the ordinary command behaviour.
            if (!string.Equals(tokens[0], "scp", StringComparison.Ordinal)) return false;

            ScpCommand c = new ScpCommand();
            int i = 1;
            bool endOfFlags = false;
            for (; i < tokens.Count; i++)
            {
                string t = tokens[i];
                if (!endOfFlags && t == "--") { endOfFlags = true; continue; }
                if (endOfFlags || t.Length < 2 || t[0] != '-') break;

                // Bundled and separate forms both occur in the wild and both must parse: OpenSSH
                // builds "scp%s%s%s%s" from " -v" " -r" " -p" " -d", i.e. separate flags, while
                // SSH.NET sends "scp -pf" and "scp -prf".
                for (int k = 1; k < t.Length; k++)
                {
                    switch (t[k])
                    {
                        case 'f': c.Source = true; break;
                        case 't': c.Sink = true; break;
                        case 'r': c.Recursive = true; break;
                        case 'p': c.PreserveTimes = true; break;
                        case 'd': c.TargetMustBeDir = true; break;
                        case 'v': case 'q': break;              // diagnostics, nothing to do here
                        default:
                            if (c.BadFlag == null) c.BadFlag = "-" + t[k];
                            break;
                    }
                }
            }
            for (; i < tokens.Count; i++) c.Paths.Add(tokens[i]);

            // Exactly one direction, or it is not an scp server invocation we understand.
            if (c.Source == c.Sink) return false;

            // An unknown flag does NOT fall through to the shell. Falling through would run the
            // remote's own scp.exe wherever one happens to be installed, which puts us back to
            // behaviour that depends on what the target has lying around -- the thing serving this
            // protocol ourselves exists to avoid. The channel starts and reports the bad flag.
            cmd = c;
            return true;
        }

        /// <summary>
        /// Splits the way /bin/sh roughly would, with one deliberate deviation for backslashes.
        /// </summary>
        public static bool TryTokenize(string s, out List<string> tokens)
        {
            tokens = new List<string>();
            if (s == null) return false;

            StringBuilder cur = new StringBuilder();
            bool has = false;                       // distinguishes "" from no token at all
            int i = 0;
            while (i < s.Length)
            {
                char ch = s[i];
                if (ch == ' ' || ch == '\t')
                {
                    if (has) { tokens.Add(cur.ToString()); cur.Length = 0; has = false; }
                    i++;
                    continue;
                }
                has = true;
                if (ch == '\'')
                {
                    int close = s.IndexOf('\'', i + 1);
                    if (close < 0) return false;                    // unterminated
                    cur.Append(s, i + 1, close - i - 1);            // single quotes are fully literal
                    i = close + 1;
                    continue;
                }
                if (ch == '"')
                {
                    i++;
                    bool closed = false;
                    while (i < s.Length)
                    {
                        char d = s[i];
                        if (d == '"') { closed = true; i++; break; }
                        // Inside double quotes a backslash escapes only these four, per POSIX.
                        if (d == '\\' && i + 1 < s.Length &&
                            (s[i + 1] == '"' || s[i + 1] == '\\' || s[i + 1] == '`' || s[i + 1] == '$'))
                        {
                            cur.Append(s[i + 1]); i += 2; continue;
                        }
                        cur.Append(d); i++;
                    }
                    if (!closed) return false;
                    continue;
                }
                if (ch == '\\' && i + 1 < s.Length)
                {
                    char n = s[i + 1];
                    // THE DELIBERATE DEVIATION. POSIX says \x yields x for any x, which would turn
                    // C:\Users\kb\f.txt into C:Userskbf.txt -- and Windows paths are what this
                    // project's users type. So a backslash escapes only the characters it plausibly
                    // needs to, and is an ordinary character everywhere else. This matches what the
                    // Microsoft port does in practice and still handles `-f a\ b`.
                    if (n == ' ' || n == '\t' || n == '\'' || n == '"' || n == '\\')
                    {
                        cur.Append(n); i += 2; continue;
                    }
                    cur.Append(ch); i++;
                    continue;
                }
                cur.Append(ch); i++;
            }
            if (has) tokens.Add(cur.ToString());
            return true;
        }
    }

    // ------------------------------------------------------------------ the channel

    internal sealed class AgentScpChannel : IAgentStream
    {
        // The same failsafe AgentSftpChannel carries. ByteChannel is unbounded, and the policy is
        // to fail loudly rather than let wsmprovhost's heap grow until it dies.
        private const long MAX_QUEUED = 64L * 1024 * 1024;
        private const int COPY_BUFFER = 64 * 1024;
        private const int MAX_DEPTH = 64;               // the client's own limit
        private const int MAX_LINE = 8192;

        private readonly PwsshAgentHost host;
        private readonly uint channel;
        private readonly ScpCommand cmd;
        private readonly SftpPathMap paths = new SftpPathMap();

        private readonly ByteChannel inbound = new ByteChannel();
        private readonly object countGate = new object();
        private long queued;

        private readonly object creditGate = new object();
        private long credit = PwsshAgentHost.InitialCredit;

        private volatile bool killed;
        private int started;
        private int errs;
        private FileStream open;                        // the sink's current destination

        public AgentScpChannel(PwsshAgentHost h, uint ch, ScpCommand c) { host = h; channel = ch; cmd = c; }

        public void Start()
        {
            if (Interlocked.CompareExchange(ref started, 1, 0) != 0) return;
            Thread t = new Thread(new ThreadStart(Worker));
            t.IsBackground = true;
            t.Name = "pwssh-scp";
            t.Start();
        }

        // ---- IAgentStream ----

        public void Write(byte[] frame, int offset, int count)
        {
            if (count <= 0 || killed) return;
            inbound.Write(frame, offset, count);
            bool over;
            lock (countGate) { queued += count; over = queued > MAX_QUEUED; }
            if (over)
            {
                host.Log("scp channel " + channel + ": inbound queue overflow");
                host.Send(Frame.MakeText(FrameType.FAIL, channel, "scp queue overflow"));
                Kill();
            }
        }

        // EOF from the client. Closing the ByteChannel is what lets a worker parked in ReadExact
        // see the end rather than wait for ever -- ReadExact has no timeout of its own.
        public void CloseWrite() { inbound.Close(); }

        public void AddCredit(uint add)
        {
            lock (creditGate) { credit += add; Monitor.PulseAll(creditGate); }
        }

        public void Kill()
        {
            killed = true;
            inbound.Close();                            // unblocks the worker's reads
            lock (creditGate) { Monitor.PulseAll(creditGate); }
            CloseOpenFile();
        }

        // ---- the worker ----

        private void Worker()
        {
            try
            {
                if (cmd.BadFlag != null)
                {
                    Fail("unknown option " + cmd.BadFlag);
                }
                else if (cmd.Sink) RunSink();
                else RunSource();
            }
            catch (EndOfStreamException)
            {
                // The client went away. Normal at the end of a sink transfer, an error mid-record;
                // the state machines distinguish those, so anything reaching here is a loss.
                if (!killed) host.Log("scp channel " + channel + ": client closed the stream");
            }
            catch (Exception ex)
            {
                if (!killed)
                {
                    host.Log("scp channel " + channel + ": " + ex.Message);
                    try { Fail(ex.Message); } catch (Exception) { }
                }
            }
            finally
            {
                CloseOpenFile();
                if (!killed)
                {
                    host.Send(Frame.MakeUInt32(FrameType.EXIT, channel, (uint)(errs != 0 ? 1 : 0)));
                    host.Send(Frame.Make(FrameType.DONE, channel, null));
                }
                host.Forget(channel);
            }
        }

        private void CloseOpenFile()
        {
            FileStream f = open;
            open = null;
            if (f != null) { try { f.Dispose(); } catch (Exception) { } }
        }

        // ---- reading ----

        private byte ReadOne()
        {
            byte b = inbound.ReadByte1();
            lock (countGate) { queued -= 1; }
            return b;
        }

        private void ReadFull(byte[] dst, int off, int n)
        {
            inbound.ReadExact(dst, off, n);
            lock (countGate) { queued -= n; }
        }

        /// <summary>Reads to the next newline. The name field may contain spaces, so records are
        /// split on the first two spaces only, never tokenised.</summary>
        private string ReadLine(byte first)
        {
            StringBuilder sb = new StringBuilder();
            if (first != 0) sb.Append((char)first);
            while (true)
            {
                byte b = ReadOne();
                if (b == (byte)'\n') break;
                sb.Append((char)b);
                if (sb.Length > MAX_LINE) throw new IOException("scp control record too long");
            }
            // The wire is UTF-8 -- the whole command was decoded that way -- so rebuild the bytes.
            byte[] raw = new byte[sb.Length];
            for (int i = 0; i < sb.Length; i++) raw[i] = (byte)sb[i];
            return Encoding.UTF8.GetString(raw);
        }

        /// <summary>
        /// Reads one status byte. Returns true for OK; on 1 or 2 consumes the message, records the
        /// error and returns false. Reading acks as a bare zero byte is the mistake that desyncs
        /// the session the moment anything goes wrong, which is why nothing here does that.
        /// </summary>
        private bool ReadAck()
        {
            byte b = ReadOne();
            if (b == 0) return true;
            if (b == 1 || b == 2)
            {
                string msg = ReadLine(0);
                errs++;
                host.Log("scp channel " + channel + ": peer reported " + msg);
                return false;
            }
            throw new IOException("scp protocol error: expected a status byte, got 0x" + b.ToString("x2"));
        }

        // ---- writing ----

        private void SendBytes(byte[] data, int count)
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
                    host.Send(Frame.Make((byte)(FrameType.OUT | FrameType.COMPRESSED), channel, packed));
                else
                    host.Send(Frame.Make(FrameType.OUT, channel, data, off, allowed));
                off += allowed;
            }
        }

        private void SendText(string s)
        {
            byte[] b = Encoding.UTF8.GetBytes(s);
            SendBytes(b, b.Length);
        }

        private void SendOk() { SendBytes(new byte[1], 1); }

        /// <summary>
        /// A recoverable error. Always 1 and never 2: measured, OpenSSH's own run_err sends 1 even
        /// for its fatal cases, and some third-party sinks handle 2 poorly.
        ///
        /// The "pwssh-scp:" prefix is not decoration. Both this machine and the test remote have a
        /// real scp.exe on PATH, so a failure to recognise the command would fall through and
        /// succeed anyway -- this text is what lets an end-to-end test tell our implementation from
        /// the system one.
        /// </summary>
        private void Warn(string message)
        {
            errs++;
            byte[] b = Encoding.UTF8.GetBytes("\x01pwssh-scp: " + message + "\n");
            SendBytes(b, b.Length);
        }

        private void Fail(string message) { Warn(message); }

        // ---- source mode (-f): we send ----

        private void RunSource()
        {
            // Read the client's ready byte BEFORE emitting anything. It always sends one, but if
            // its local target is unusable that first byte is an error instead, and answering into
            // a stream that is already unwinding desyncs the error path.
            if (!ReadAck()) return;

            for (int i = 0; i < cmd.Paths.Count; i++)
            {
                List<KeyValuePair<string, string>> matches;      // windows path -> name on the wire
                try { matches = Expand(cmd.Paths[i]); }
                catch (Exception ex) { Warn(Describe(cmd.Paths[i], ex)); continue; }

                if (matches.Count == 0) { Warn(cmd.Paths[i] + ": No such file or directory"); continue; }
                for (int k = 0; k < matches.Count; k++)
                {
                    if (!SendEntity(matches[k].Key, matches[k].Value, 0)) return;
                }
            }
        }

        /// <summary>
        /// Resolves one requested path to the entities to send. A real scp relies on the remote
        /// SHELL to have expanded a wildcard before scp ever sees it; there is no shell in this
        /// path, so without this `scp host:'dir/*.txt' .` would look for a file called "*.txt".
        /// </summary>
        private List<KeyValuePair<string, string>> Expand(string requested)
        {
            List<KeyValuePair<string, string>> outp = new List<KeyValuePair<string, string>>();
            string wire = Tilde(requested);
            int cut = Math.Max(wire.LastIndexOf('/'), wire.LastIndexOf('\\'));
            string lastComponent = cut >= 0 ? wire.Substring(cut + 1) : wire;

            if (lastComponent.IndexOf('*') < 0 && lastComponent.IndexOf('?') < 0)
            {
                string win = paths.ToWindows(wire);
                if (!Win32Fs.Exists(win)) return outp;
                // The name echoed back is the one the CLIENT asked for, not the on-disk casing.
                // Since 8.0 the client fnmatches every incoming name against its own request, and
                // that match is CASE-SENSITIVE: answer "file.txt" to a request for "File.TXT" --
                // which NTFS opens quite happily -- and the client rejects the transfer as an
                // attempted spoof.
                outp.Add(new KeyValuePair<string, string>(win, Leaf(lastComponent, win)));
                return outp;
            }

            string dirWire = cut >= 0 ? wire.Substring(0, cut) : ".";
            string dirWin = paths.ToWindows(dirWire.Length == 0 ? "/" : dirWire);
            List<Win32Fs.Entry> entries = Win32Fs.List(dirWin);
            for (int i = 0; i < entries.Count; i++)
            {
                string name = entries[i].Name;
                if (name == "." || name == "..") continue;
                // Matched case-insensitively because that is what a Windows user means, then kept
                // only if it ALSO matches case-sensitively -- because the client's own fnmatch is
                // case-sensitive and a name it did not ask for aborts the whole transfer.
                if (!Wildcard(lastComponent, name, true)) continue;
                if (!Wildcard(lastComponent, name, false))
                {
                    host.Log("scp channel " + channel + ": skipping " + name
                             + ", it matches '" + lastComponent + "' only case-insensitively and the client would refuse it");
                    continue;
                }
                outp.Add(new KeyValuePair<string, string>(
                    dirWin.EndsWith("\\", StringComparison.Ordinal) ? dirWin + name : dirWin + "\\" + name, name));
            }
            return outp;
        }

        private static string Leaf(string requestedLast, string win)
        {
            if (!string.IsNullOrEmpty(requestedLast) && requestedLast != "." && requestedLast != "..")
                return requestedLast;
            int i = win.LastIndexOf('\\');
            return i >= 0 ? win.Substring(i + 1) : win;
        }

        /// <summary>Returns false when the transfer should stop entirely.</summary>
        private bool SendEntity(string win, string name, int depth)
        {
            Win32Fs.Info info;
            try { info = Win32Fs.GetInfo(win); }
            catch (Exception ex) { Warn(Describe(name, ex)); return true; }

            if (info.IsDirectory)
            {
                if (!cmd.Recursive) { Warn(name + ": not a regular file"); return true; }
                return SendDirectory(win, name, info, depth);
            }
            return SendFile(win, name, info);
        }

        private bool SendFile(string win, string name, Win32Fs.Info info)
        {
            FileStream f;
            try
            {
                f = Win32Fs.Open(win, FileMode.Open, FileAccess.Read,
                                 FileShare.ReadWrite | FileShare.Delete, true, COPY_BUFFER);
            }
            catch (Exception ex) { Warn(Describe(name, ex)); return true; }

            try
            {
                if (cmd.PreserveTimes)
                {
                    // T is a record in its own right and is acked on its own. Treating T and C as
                    // one unit runs the whole transfer an ack behind -- which works until the first
                    // error and then reads message text as status bytes.
                    SendText("T" + Unix(info.WriteUtc) + " 0 " + Unix(info.AccessUtc) + " 0\n");
                    if (!ReadAck()) return true;
                }

                long size = f.Length;
                SendText("C" + Mode(info, false) + " " + size.ToString(CultureInfo.InvariantCulture) + " " + name + "\n");
                // A nack here means skip: the body must NOT be sent. Measured against the real
                // client, which then aborts rather than moving to the next file.
                if (!ReadAck()) return true;

                // The size in the C line is a contract. If the file shrinks or a read fails we
                // still owe exactly that many bytes -- pad, and report in the trailing status byte.
                // Truncating instead desynchronises everything after it.
                byte[] buf = new byte[COPY_BUFFER];
                long sent = 0;
                string readError = null;
                while (sent < size && !killed)
                {
                    int want = (int)Math.Min((long)buf.Length, size - sent);
                    int got = 0;
                    if (readError == null)
                    {
                        try { got = f.Read(buf, 0, want); }
                        catch (Exception ex) { readError = ex.Message; got = 0; }
                    }
                    if (got <= 0) { Array.Clear(buf, 0, want); got = want; if (readError == null) readError = "file shrank during transfer"; }
                    SendBytes(buf, got);
                    sent += got;
                }
                if (killed) return false;

                // Our own status byte for the body, then their verdict. Two bytes, opposite
                // directions, in that order -- reversing them is a mutual wait.
                if (readError == null) SendOk(); else Warn(name + ": " + readError);

                // Their verdict on the file. It is read because the protocol requires it -- leaving
                // the byte unread would make it the first character of the next record -- but a
                // refusal here does not stop the transfer: ReadAck has already counted it, and
                // whether to continue is the next entity's business, not this one's.
                ReadAck();
                return true;
            }
            finally { try { f.Dispose(); } catch (Exception) { } }
        }

        private bool SendDirectory(string win, string name, Win32Fs.Info info, int depth)
        {
            if (depth >= MAX_DEPTH) { Warn(name + ": maximum directory depth exceeded"); return true; }

            if (cmd.PreserveTimes)
            {
                SendText("T" + Unix(info.WriteUtc) + " 0 " + Unix(info.AccessUtc) + " 0\n");
                if (!ReadAck()) return true;
            }
            SendText("D" + Mode(info, true) + " 0 " + name + "\n");
            if (!ReadAck()) return true;

            List<Win32Fs.Entry> entries;
            try { entries = Win32Fs.List(win); }
            catch (Exception ex) { Warn(Describe(name, ex)); entries = new List<Win32Fs.Entry>(); }

            for (int i = 0; i < entries.Count; i++)
            {
                string child = entries[i].Name;
                if (child == "." || child == "..") continue;
                // Reparse points are skipped, not followed. C:\Users\All Users is a symlink to
                // C:\ProgramData and AppData\Local\Application Data points at its own parent, so
                // following them recurses until the client's depth limit stops it. This is the same
                // protection READDIR's LSTAT semantics give a recursive sftp get.
                if (entries[i].Info.IsReparsePoint)
                {
                    host.Log("scp channel " + channel + ": skipping link " + child);
                    continue;
                }
                string childWin = win.EndsWith("\\", StringComparison.Ordinal) ? win + child : win + "\\" + child;
                if (!SendEntity(childWin, child, depth + 1)) return false;
            }

            SendText("E\n");
            ReadAck();
            return true;
        }

        // ---- sink mode (-t): we receive ----

        private void RunSink()
        {
            if (cmd.Paths.Count != 1) { Fail("ambiguous target"); return; }
            string target = paths.ToWindows(Tilde(cmd.Paths[0]));
            bool targetIsDir = Win32Fs.DirectoryExists(target);

            // -d asserts the target is a directory, and the check runs BEFORE the ready byte --
            // its failure replaces that byte rather than following it. Measured: the reference
            // answers \1 "... Not a directory" as the very first thing it says.
            if (cmd.TargetMustBeDir && !targetIsDir) { Fail(target + ": Not a directory"); return; }

            // Everything else waits for this. Every upload client blocks on the ready byte, so
            // anything slow or lazy before it hangs all of them.
            SendOk();

            List<string> stack = new List<string>();     // directories entered via D
            List<DateTime[]> stackTimes = new List<DateTime[]>();
            DateTime[] pending = null;                   // times from a T record

            while (!killed)
            {
                byte b;
                try { b = ReadOne(); }
                catch (EndOfStreamException) { break; }  // end of transfer, and the normal exit

                if (b == 1 || b == 2) { string m = ReadLine(0); errs++; host.Log("scp channel " + channel + ": client reported " + m); continue; }

                string line = ReadLine(b);
                if (line.Length == 0) { Fail("protocol error: expected control record"); return; }

                char kind = line[0];
                string cwd = stack.Count > 0 ? stack[stack.Count - 1] : null;

                if (kind == 'T')
                {
                    try { pending = ParseTimes(line); SendOk(); }
                    catch (Exception) { Fail("protocol error: bad time record"); return; }
                    continue;
                }
                if (kind == 'E')
                {
                    // Accepted at depth 0 rather than refused: measured, the reference acks it and
                    // ends. Being stricter than the implementation this clones would break clients
                    // for no benefit.
                    if (stack.Count == 0) { SendOk(); break; }
                    string done = stack[stack.Count - 1];
                    DateTime[] t = stackTimes[stackTimes.Count - 1];
                    stack.RemoveAt(stack.Count - 1);
                    stackTimes.RemoveAt(stackTimes.Count - 1);
                    // A directory's times are applied on the way OUT: writing its entries updates
                    // its mtime, so anything set on the way in has already been overwritten.
                    if (t != null) { try { Win32Fs.SetTimesUtc(done, t[1], t[0], false); } catch (Exception) { } }
                    SendOk();
                    continue;
                }
                if (kind == 'D' || kind == 'C')
                {
                    string modeText, sizeText, name;
                    if (!SplitRecord(line, out modeText, out sizeText, out name))
                    { Fail("protocol error: bad control record"); return; }

                    if (kind == 'D' && !cmd.Recursive) { Fail("received directory without -r"); return; }

                    string dest;
                    if (kind == 'C' && cwd == null && !targetIsDir)
                    {
                        // The rename form. Measured: when the target is not an existing directory
                        // the sent name is IGNORED and the body lands at the target path. This is
                        // `scp -O f.txt host:C:/tmp/renamed.txt`, and it is common.
                        dest = target;
                    }
                    else
                    {
                        string why;
                        if (!ValidateEntryName(name, out why)) { Warn(name + ": " + why); if (kind == 'C') continue; return; }
                        string parent = cwd ?? target;
                        try { dest = paths.ToWindows(ToWire(parent) + "/" + name); }
                        catch (Exception ex) { Warn(name + ": " + ex.Message); continue; }
                        if (!Contains(parent, dest)) { Warn(name + ": path escapes the target directory"); continue; }
                    }

                    if (kind == 'D')
                    {
                        if (stack.Count >= MAX_DEPTH) { Fail("maximum directory depth exceeded"); return; }
                        try { if (!Win32Fs.DirectoryExists(dest)) Win32Fs.CreateDirectory(dest); }
                        catch (Exception ex) { Warn(Describe(name, ex)); return; }
                        stack.Add(dest);
                        stackTimes.Add(pending);
                        pending = null;
                        SendOk();
                        continue;
                    }

                    long size;
                    if (!long.TryParse(sizeText, NumberStyles.None, CultureInfo.InvariantCulture, out size) || size < 0)
                    { Fail("protocol error: size out of range"); return; }

                    ReceiveFile(dest, name, size, pending);
                    pending = null;
                    continue;
                }

                Fail("protocol error: expected control record");
                return;
            }
        }

        private void ReceiveFile(string dest, string name, long size, DateTime[] times)
        {
            // Opened BEFORE the ack, so that a failure here can be reported with a nack the client
            // answers by skipping the body -- which means there is nothing to drain.
            try
            {
                open = Win32Fs.Open(dest, FileMode.Create, FileAccess.Write, FileShare.None, false, COPY_BUFFER);
            }
            catch (Exception ex) { Warn(Describe(name, ex)); return; }
            SendOk();

            string writeError = null;
            byte[] buf = new byte[COPY_BUFFER];
            long left = size;
            while (left > 0)
            {
                int want = (int)Math.Min((long)buf.Length, left);
                ReadFull(buf, 0, want);
                left -= want;
                if (writeError != null) continue;        // keep draining: the framing depends on it
                try { open.Write(buf, 0, want); }
                catch (Exception ex) { writeError = ex.Message; }
            }

            // Their status byte for the body comes first, then our verdict. Skipping this read
            // leaves the byte to be mistaken for the next record's first character. A failure
            // reported here is already counted by ReadAck; it does not change what we write back,
            // because our verdict is about whether WE stored the bytes.
            ReadAck();

            try { open.Dispose(); } catch (Exception ex) { if (writeError == null) writeError = ex.Message; }
            open = null;

            // Applied by path, after the handle is closed: NTFS updates last-write when the dirty
            // data flushes, which is after any time set on the still-open handle.
            if (writeError == null && times != null)
            {
                try { Win32Fs.SetTimesUtc(dest, times[1], times[0], false); } catch (Exception) { }
            }

            if (writeError != null) Warn(name + ": " + writeError);
            else SendOk();
        }

        // ---- helpers ----

        /// <summary>
        /// The security boundary: this name came from the client. OpenSSH's own sink checks empty,
        /// "/" , "." and ".." and nothing else, because it is POSIX and has no drives, streams or
        /// backslashes to worry about.
        /// </summary>
        public static bool ValidateEntryName(string name, out string why)
        {
            why = null;
            if (string.IsNullOrEmpty(name)) { why = "empty filename"; return false; }
            if (name == "." || name == "..") { why = "unexpected filename: " + name; return false; }
            if (name.IndexOf('/') >= 0 || name.IndexOf('\\') >= 0)
            { why = "unexpected filename: " + name; return false; }
            // One character closes three doors: drive-absolute (C:evil), drive-relative, and NTFS
            // alternate data streams (f.txt:stream, f.txt::$DATA). No basename legitimately has one.
            if (name.IndexOf(':') >= 0) { why = "unexpected filename: " + name; return false; }
            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (c < 0x20 || c == 0x7F) { why = "filename contains a control character"; return false; }
                if (c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
                { why = "filename contains an invalid character"; return false; }
            }
            return true;
        }

        private static bool Contains(string parentWin, string childWin)
        {
            string p = parentWin.EndsWith("\\", StringComparison.Ordinal) ? parentWin : parentWin + "\\";
            return childWin.StartsWith(p, StringComparison.OrdinalIgnoreCase);
        }

        private static string ToWire(string win) { return "/" + win.Replace('\\', '/'); }

        /// <summary>A tilde arrives verbatim, because a real remote's shell would have expanded it
        /// and there is no shell here.</summary>
        private string Tilde(string p)
        {
            if (p == null || p.Length == 0) return p;
            if (p == "~") return ToWire(paths.Home());
            if (p.StartsWith("~/", StringComparison.Ordinal) || p.StartsWith("~\\", StringComparison.Ordinal))
                return ToWire(paths.Home()) + "/" + p.Substring(2);
            if (p[0] == '~') throw new NotSupportedException("~user paths are not supported");
            return p;
        }

        private static bool SplitRecord(string line, out string mode, out string size, out string name)
        {
            mode = size = name = null;
            // Split on the first two spaces only -- names contain spaces.
            int a = line.IndexOf(' ');
            if (a <= 1) return false;
            int b = line.IndexOf(' ', a + 1);
            if (b < 0) return false;
            mode = line.Substring(1, a - 1);
            size = line.Substring(a + 1, b - a - 1);
            name = line.Substring(b + 1);
            return name.Length > 0;
        }

        private static DateTime[] ParseTimes(string line)
        {
            string[] f = line.Substring(1).Split(' ');
            if (f.Length < 3) throw new IOException("bad T record");
            long m = long.Parse(f[0], CultureInfo.InvariantCulture);
            long a = long.Parse(f[2], CultureInfo.InvariantCulture);
            return new DateTime[] { FromUnix(m), FromUnix(a) };     // [0] = mtime, [1] = atime
        }

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        private static string Unix(DateTime utc)
        {
            if (utc < Epoch) return "0";
            return ((long)(utc - Epoch).TotalSeconds).ToString(CultureInfo.InvariantCulture);
        }
        private static DateTime FromUnix(long s) { return Epoch.AddSeconds(s); }

        // 0644/0755, matching what this project's SFTP layer reports rather than the reference's
        // 0666/0777 -- a file fetched with -p onto a Linux box should not land mode 666.
        private static string Mode(Win32Fs.Info info, bool dir)
        {
            if (dir) return info.IsReadOnly ? "0555" : "0755";
            return info.IsReadOnly ? "0444" : "0644";
        }

        private static string Describe(string name, Exception ex) { return name + ": " + ex.Message; }

        /// <summary>Wildcard match for * and ?, which is all a last component needs.</summary>
        public static bool Wildcard(string pattern, string text, bool ignoreCase)
        {
            int p = 0, t = 0, star = -1, mark = 0;
            while (t < text.Length)
            {
                if (p < pattern.Length && (pattern[p] == '?' || Same(pattern[p], text[t], ignoreCase)))
                { p++; t++; continue; }
                if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = t; continue; }
                if (star >= 0) { p = star + 1; t = ++mark; continue; }
                return false;
            }
            while (p < pattern.Length && pattern[p] == '*') p++;
            return p == pattern.Length;
        }

        private static bool Same(char a, char b, bool ignoreCase)
        {
            if (a == b) return true;
            if (!ignoreCase) return false;
            return char.ToUpperInvariant(a) == char.ToUpperInvariant(b);
        }
    }
}
