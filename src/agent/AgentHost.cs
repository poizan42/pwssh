// The remote half: owns the channels and dispatches inbound frames to them.
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
    // -------------------------------------------------------------------- agent host

    public sealed class PwsshAgentHost : IByteReceiver
    {
        // Granted at EXEC and topped up by WINDOW frames. Each WINDOW frame costs a full
        // WinRM turnaround, so a small window stalls bulk output once per round trip -- but
        // the credit is also what bounds how much the agent can push into the client's memory
        // before it must wait. Tunable so the trade-off can be measured rather than guessed.
        public static uint InitialCredit = 32 * 1024 * 1024;

        private readonly FrameQueue outbound = new FrameQueue();
        // One map for every channel kind. The four frames that apply to all of them -- DATA,
        // EOF, CLOSE, WINDOW -- would otherwise each need a lookup per kind, which is four
        // places to forget one every time a kind is added.
        private readonly Dictionary<uint, IAgentStream> streams = new Dictionary<uint, IAgentStream>();
        private readonly object chanGate = new object();
        private readonly Queue<string> logQ = new Queue<string>();

        private volatile bool finished;
        private int lastInboundTick = Environment.TickCount;

        // How long silence from the client is tolerated before giving up and releasing
        // everything; 0 disables. This is the only thing that ends an orphaned agent: ssh
        // TerminateProcesses its ProxyCommand, so the client normally dies without completing
        // the pipeline, and the remote would otherwise hold its child processes and any -R
        // listener until WinRM reclaimed the shell.
        //
        // It can be this short only because the client sends PING frames (see
        // PwsshAgentProxy.StartKeepAlive): before that, silence could equally mean an idle
        // interactive session, and a timeout of 120 s would have killed one after two minutes
        // of the user not typing.
        public int InactivityTimeoutSeconds = 120;

        // Testing hook: forces the no-ConPTY path on a remote that does have it, so the
        // graceful-degradation behaviour can be exercised rather than assumed.
        public static bool DisableConPty;

        // Testing hook: turns off read coalescing in the output pumps, so its effect can be
        // measured by interleaved A/B rather than asserted.
        public static bool DisableCoalescing;

        // The shell, matching what Windows OpenSSH runs by default.
        public static string ShellPath()
        {
            string s = Environment.GetEnvironmentVariable("ComSpec");
            if (string.IsNullOrEmpty(s)) s = "cmd.exe";
            return s;
        }

        // pty-req arrives before shell/exec, so the parameters wait here for the channel.
        private readonly Dictionary<uint, PtyRequest> pendingPty = new Dictionary<uint, PtyRequest>();

        // Forwarded connections get their own, much smaller window: a SOCKS client can have
        // dozens open at once, and the session default (32 MiB) each would be absurd. At a
        // ~0.5 s round trip 2 MiB still sustains several MiB/s per channel.
        public static uint InitialTcpCredit = 2 * 1024 * 1024;

        // Listeners are not channels -- nothing writes bytes to one -- so they keep their own map.
        private readonly Dictionary<uint, AgentListener> listeners = new Dictionary<uint, AgentListener>();

        // Channel ids for connections WE accept come from the top of the space; the engine
        // allocates upward from 0. Two allocators sharing one space would eventually collide,
        // and the symptom would be data surfacing on the wrong channel.
        private const uint ACCEPTED_ID_BASE = 0x80000000;
        private uint nextAccepted = ACCEPTED_ID_BASE;

        private AgentTcpChannel FindTcp(uint ch) { return FindStream(ch) as AgentTcpChannel; }

        public bool Finished { get { return finished; } }

        public void Start()
        {
            string user;
            try { user = CurrentAccountName(); }
            catch (Exception ex) { user = ""; Log("cannot resolve current user: " + ex.Message); }

            // Capabilities travel with HELLO so the client can answer pty-req immediately.
            // Asking later would cost a round trip on every interactive connection, and the
            // answer has to be known before the reply is sent.
            bool conpty = !DisableConPty && ConPtySession.IsAvailable();
            string hello = "user=" + user + ";conpty=" + (conpty ? "1" : "0");

            // Must go through Send: every frame needs a sequence number, or it collides with
            // the first sequenced frame and the client's resequencer drops one as a duplicate.
            Send(Frame.MakeText(FrameType.HELLO, 0, hello));
            Log("agent ready as '" + user + "', conpty=" + conpty);

            if (InactivityTimeoutSeconds > 0)
            {
                Thread wd = new Thread(new ThreadStart(Watchdog));
                wd.IsBackground = true;
                wd.Name = "pwssh-agent-watchdog";
                wd.Start();
            }
        }

        public static string CurrentAccountName()
        {
            string full = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
            int bs = full.LastIndexOf('\\');
            if (bs >= 0) return full.Substring(bs + 1);
            return full;
        }

        private void Watchdog()
        {
            int limitMs = InactivityTimeoutSeconds * 1000;
            while (!finished)
            {
                Thread.Sleep(5000);
                if (finished) return;
                if (unchecked(Environment.TickCount - lastInboundTick) > limitMs)
                {
                    Log("no inbound frames for " + InactivityTimeoutSeconds + "s; shutting down");
                    Stop();
                    return;
                }
            }
        }

        public byte[] TakeOutboundFrame(int timeoutMs) { return outbound.Take(timeoutMs); }

        private readonly List<PipeSink> stripes = new List<PipeSink>();
        private int seqCounter = -1;
        private int roundRobin = -1;

        // Called before Start(). Creates one named pipe per mule session; the client starts
        // the mules, which connect and forward whatever arrives to their own pipeline output.
        public void SetStripes(string pipePrefix, int count)
        {
            for (int i = 0; i < count; i++)
            {
                PipeSink p = new PipeSink(this, pipePrefix + "-" + i);
                stripes.Add(p);
                p.Start();
            }
            if (count > 0) Log("striping downstream across " + (count + 1) + " sessions");
        }

        internal void Send(byte[] frame)
        {
            // Stamp the order here, where it is serialised across all producing threads.
            Frame.SetSeq(frame, (uint)Interlocked.Increment(ref seqCounter));

            if (stripes.Count == 0) { outbound.Enqueue(frame); return; }

            int slot = Interlocked.Increment(ref roundRobin) % (stripes.Count + 1);
            if (slot == 0) { outbound.Enqueue(frame); return; }

            PipeSink sink = stripes[slot - 1];
            // Not connected yet (or gone): fall back to the primary session. Sequence numbers
            // mean the client reassembles correctly either way.
            if (sink.Connected) sink.Enqueue(frame); else outbound.Enqueue(frame);
        }

        public string[] DrainLog()
        {
            lock (logQ)
            {
                string[] a = logQ.ToArray();
                logQ.Clear();
                return a;
            }
        }

        internal void Log(string m)
        {
            lock (logQ)
            {
                if (logQ.Count > 500) logQ.Dequeue();
                logQ.Enqueue(m);
            }
        }

        public void PushInbound(byte[] frame)
        {
            lastInboundTick = Environment.TickCount;
            if (!Frame.IsValid(frame))
            {
                Log("discarding runt frame");
                return;
            }

            byte type = Frame.Type(frame);
            uint ch = Frame.Channel(frame);

            try
            {
                switch (type)
                {
                    case FrameType.EXEC:
                        StartChannel(ch, ShellPath() + " /c " + Frame.PayloadText(frame));
                        break;

                    case FrameType.SHELL:
                        StartChannel(ch, ShellPath());
                        break;

                    case FrameType.PTY:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            PtyRequest req = new PtyRequest();
                            // A client with no local terminal of its own sends 0x0 -- ssh -tt
                            // with redirected stdin does exactly that -- and a pseudoconsole
                            // with no cells has nothing to render. ConPtySession substitutes a
                            // default of its own, but do it here too so the size the agent
                            // reports and the size it uses cannot disagree.
                            req.Cols = PtyRequest.Clamp(r.UInt32(), 80);
                            req.Rows = PtyRequest.Clamp(r.UInt32(), 24);
                            req.Term = r.Text();
                            lock (chanGate) { pendingPty[ch] = req; }
                            Log("pty requested on channel " + ch + ": " + req.Cols + "x" + req.Rows + " " + req.Term);
                        }
                        break;

                    case FrameType.RESIZE:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            uint cols = PtyRequest.Clamp(r.UInt32(), 80);
                            uint rows = PtyRequest.Clamp(r.UInt32(), 24);
                            AgentChannel c = Find(ch);
                            if (c != null) c.Resize(cols, rows);
                        }
                        break;

                    case FrameType.SIGNAL:
                        {
                            AgentChannel c = Find(ch);
                            Log("signal " + Frame.PayloadText(frame) + " on channel " + ch);
                            if (c != null) c.Kill();
                        }
                        break;

                    // Nothing to do: arriving at all is the whole message, and the inbound
                    // timestamp that keeps the watchdog quiet has already been refreshed.
                    case FrameType.PING:
                        break;

                    case FrameType.SUBSYSTEM:
                        {
                            // The engine has already refused anything but "sftp", so the else
                            // is belt and braces rather than a real branch.
                            string name = Frame.PayloadText(frame);
                            if (name == "sftp") StartSftp(ch);
                            else
                            {
                                Log("unknown subsystem on channel " + ch + ": " + name);
                                Send(Frame.MakeText(FrameType.FAIL, ch, "unknown subsystem: " + name));
                            }
                        }
                        break;

                    case FrameType.CONNECT:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            string target = r.Text();
                            int port = (int)r.UInt32();
                            AgentTcpChannel c = new AgentTcpChannel(this, ch);
                            lock (chanGate) { streams[ch] = c; }
                            c.BeginConnect(target, port);
                        }
                        break;

                    case FrameType.LISTEN:
                        {
                            SshLikeReader r = new SshLikeReader(frame, Frame.HEADER);
                            string addr = r.Text();
                            int port = (int)r.UInt32();
                            AgentListener l = new AgentListener(this, ch);
                            string err = l.Bind(addr, port);
                            if (err == null)
                            {
                                lock (chanGate) { listeners[ch] = l; }
                                Log("listening on " + addr + ":" + l.BoundPort + " (forward " + ch + ")");
                                Send(Frame.MakeUInt32(FrameType.LISTEN_OK, ch, (uint)l.BoundPort));
                            }
                            else
                            {
                                Log("bind " + addr + ":" + port + " failed: " + err);
                                Send(Frame.MakeText(FrameType.LISTEN_FAIL, ch, err));
                            }
                        }
                        break;

                    case FrameType.UNLISTEN:
                        {
                            AgentListener l = null;
                            lock (chanGate)
                            {
                                if (listeners.TryGetValue(ch, out l)) listeners.Remove(ch);
                            }
                            if (l != null) { l.Stop(); Log("forward " + ch + " cancelled"); }
                        }
                        break;

                    case FrameType.ACCEPT_OK:
                        {
                            AgentTcpChannel t = FindTcp(ch);
                            if (t != null) t.StartPumping();
                        }
                        break;

                    // The remaining channel frames apply to every kind, which is what the
                    // IAgentStream map is for.
                    case FrameType.DATA:
                        {
                            IAgentStream s = FindStream(ch);
                            if (s != null) s.Write(frame, Frame.HEADER, Frame.PayloadLength(frame));
                        }
                        break;

                    case FrameType.EOF:
                        {
                            IAgentStream s = FindStream(ch);
                            if (s != null) s.CloseWrite();
                        }
                        break;

                    case FrameType.CLOSE:
                        {
                            IAgentStream s = FindStream(ch);
                            // Forget explicitly: a process-backed channel drops itself when the
                            // child exits, but an accepted -R channel the client refused was
                            // never pumping and nothing else would ever drop it.
                            if (s != null) { s.Kill(); Forget(ch); }
                        }
                        break;

                    case FrameType.WINDOW:
                        {
                            IAgentStream s = FindStream(ch);
                            if (s != null) s.AddCredit(Frame.PayloadUInt32(frame));
                        }
                        break;

                    default:
                        Log("unexpected frame type 0x" + type.ToString("X2"));
                        break;
                }
            }
            catch (Exception ex)
            {
                Log("frame 0x" + type.ToString("X2") + " failed: " + ex.Message);
                Send(Frame.MakeText(FrameType.FAIL, ch, ex.Message));
            }
        }

        public void CloseInbound()
        {
            Log("client closed the link");
            Stop();
        }

        public void Stop()
        {
            finished = true;
            lock (chanGate)
            {
                // Covers every kind at once, which is what makes SFTP's file handles release
                // here too rather than needing their own line.
                foreach (IAgentStream s in streams.Values) { try { s.Kill(); } catch { } }
                // Must happen here: a surviving listener keeps the port bound on the remote
                // until wsmprovhost exits, which the inactivity watchdog only bounds loosely.
                foreach (AgentListener l in listeners.Values) { try { l.Stop(); } catch { } }
                listeners.Clear();
            }
            foreach (PipeSink p in stripes) { try { p.Close(); } catch { } }
            outbound.Close();
        }

        private IAgentStream FindStream(uint ch)
        {
            lock (chanGate)
            {
                IAgentStream s;
                if (streams.TryGetValue(ch, out s)) return s;
                return null;
            }
        }

        // Only for the frames that are specific to a process-backed channel (RESIZE, SIGNAL);
        // everything shared goes through FindStream.
        private AgentChannel Find(uint ch) { return FindStream(ch) as AgentChannel; }

        private void StartChannel(uint ch, string command)
        {
            AgentChannel c = new AgentChannel(this, ch);
            lock (chanGate)
            {
                if (streams.ContainsKey(ch))
                {
                    Send(Frame.MakeText(FrameType.FAIL, ch, "channel already in use"));
                    return;
                }
                streams[ch] = c;
            }
            PtyRequest req = null;
            lock (chanGate)
            {
                if (pendingPty.TryGetValue(ch, out req)) pendingPty.Remove(ch);
            }

            Log("start on channel " + ch + (req != null ? " (pty): " : ": ") + command);
            if (!c.Start(command, req))
            {
                Send(Frame.MakeText(FrameType.FAIL, ch, "could not start command"));
                Forget(ch);
            }
        }

        private void StartSftp(uint ch)
        {
            AgentSftpChannel c = new AgentSftpChannel(this, ch);
            lock (chanGate)
            {
                if (streams.ContainsKey(ch))
                {
                    Send(Frame.MakeText(FrameType.FAIL, ch, "channel already in use"));
                    return;
                }
                streams[ch] = c;
            }
            Log("sftp subsystem on channel " + ch);
            c.Start();
        }

        internal void Forget(uint ch)
        {
            lock (chanGate) { streams.Remove(ch); }
        }

        // A connection arrived on a -R listener. Park it against a fresh channel id and tell
        // the client, which opens a forwarded-tcpip channel back to us; pumping starts only
        // once that channel is confirmed via ACCEPT_OK.
        internal void OnAccepted(AgentListener l, Socket accepted)
        {
            uint id;
            AgentTcpChannel c;
            lock (chanGate)
            {
                id = nextAccepted++;
                c = new AgentTcpChannel(this, id);
                streams[id] = c;
            }
            c.Adopt(accepted);

            string origAddr = "unknown";
            int origPort = 0;
            try
            {
                IPEndPoint rep = accepted.RemoteEndPoint as IPEndPoint;
                if (rep != null) { origAddr = rep.Address.ToString(); origPort = rep.Port; }
            }
            catch { }

            Log("accepted " + origAddr + ":" + origPort + " on forward port " + l.BoundPort + " as channel " + id);

            SshLikeWriter w = new SshLikeWriter();
            w.UInt32(l.ForwardId);
            w.UInt32((uint)l.BoundPort);
            w.Text(origAddr);
            w.UInt32((uint)origPort);
            Send(Frame.Make(FrameType.ACCEPTED, id, w.ToArray()));
        }
    }
}
