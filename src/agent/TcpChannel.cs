// A channel backed by a socket: direct-tcpip, and the accepted end of -R.
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
    // -------------------------------------------------------------- forwarded TCP
    //
    // The remote end of a direct-tcpip channel: connect outbound, then be a byte pipe.
    // Deliberately a sibling of AgentChannel rather than a subclass -- almost nothing is
    // shared beyond credit accounting, and a socket has neither stderr nor an exit status.

    internal sealed class AgentTcpChannel : IAgentStream
    {
        private const int READ_BUFFER = 65536;

        private readonly PwsshAgentHost host;
        private readonly uint channel;
        private readonly object creditGate = new object();
        private long credit = PwsshAgentHost.InitialTcpCredit;

        private Socket sock;
        private NetworkStream stream;
        private volatile bool killed;

        public AgentTcpChannel(PwsshAgentHost h, uint ch) { host = h; channel = ch; }

        public void AddCredit(uint add)
        {
            lock (creditGate) { credit += add; Monitor.PulseAll(creditGate); }
        }

        // Remote forwarding: the socket already exists, having been accepted by an
        // AgentListener. It is deliberately NOT read until the client confirms the channel,
        // or we would produce data for a channel that does not exist yet.
        public void Adopt(Socket accepted)
        {
            sock = accepted;
            try { sock.NoDelay = true; } catch { }
            stream = new NetworkStream(accepted, false);
        }

        public void StartPumping()
        {
            if (stream == null) return;
            Thread pump = new Thread(new ThreadStart(Pump));
            pump.IsBackground = true;
            pump.Name = "pwssh-tcp-pump";
            pump.Start();
        }

        // Connects on its own thread: this is called from the frame dispatch path, and a
        // blocking connect there would stall every other channel.
        public void BeginConnect(string hostName, int port)
        {
            Thread t = new Thread(new ThreadStart(delegate { Connect(hostName, port); }));
            t.IsBackground = true;
            t.Name = "pwssh-connect";
            t.Start();
        }

        private void Connect(string hostName, int port)
        {
            IPAddress[] addrs;
            try { addrs = Resolve(hostName); }
            catch (Exception ex) { Fail("cannot resolve " + hostName + ": " + ex.Message); return; }
            if (addrs.Length == 0) { Fail("no addresses for " + hostName); return; }

            // With more than one candidate, cap each attempt: an unroutable address family
            // otherwise burns the OS connect timeout (~21 s observed) before the next address
            // is tried, which is exactly the case a dual-stack host with dead IPv6 hits. A
            // single candidate keeps the OS default, so a legitimately slow target still works.
            int perAddressMs = (addrs.Length > 1) ? 8000 : -1;

            Exception last = null;
            for (int i = 0; i < addrs.Length && !killed; i++)
            {
                Socket s = null;
                try
                {
                    // A socket per address family. TcpClient's default constructor produces an
                    // IPv4-only socket, so pointing it at an IPv6 address fails with a bogus
                    // "socket is not connected" (WSAENOTCONN) instead of a routing error --
                    // which also meant a host with both AAAA and A records never fell back.
                    s = new Socket(addrs[i].AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    s.NoDelay = true;             // forwarded traffic is usually latency-bound

                    if (perAddressMs < 0)
                    {
                        s.Connect(new IPEndPoint(addrs[i], port));
                    }
                    else
                    {
                        IAsyncResult ar = s.BeginConnect(new IPEndPoint(addrs[i], port), null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(perAddressMs))
                            throw new TimeoutException("connect timed out after " + perAddressMs + " ms");
                        s.EndConnect(ar);
                    }

                    if (killed) { try { s.Close(); } catch { } return; }

                    sock = s;
                    stream = new NetworkStream(s, false);
                    host.Log("channel " + channel + " connected to " + addrs[i] + ":" + port);
                    host.Send(Frame.Make(FrameType.CONNECT_OK, channel, null));

                    Thread pump = new Thread(new ThreadStart(Pump));
                    pump.IsBackground = true;
                    pump.Name = "pwssh-tcp-pump";
                    pump.Start();
                    return;
                }
                catch (Exception ex)
                {
                    // Try the next address: a target with both AAAA and A records should still
                    // work on a host whose IPv6 has no route.
                    last = ex;
                    host.Log("channel " + channel + " could not reach " + addrs[i] + ":" + port + ": " + ex.Message);
                    if (s != null) { try { s.Close(); } catch { } }
                }
            }

            Fail(last == null ? "connect failed" : last.Message);
        }

        private static IPAddress[] Resolve(string hostName)
        {
            string h = (hostName == null) ? "" : hostName.Trim();
            // SOCKS clients can hand over a bracketed IPv6 literal.
            if (h.Length > 1 && h[0] == '[' && h[h.Length - 1] == ']') h = h.Substring(1, h.Length - 2);

            IPAddress literal;
            if (IPAddress.TryParse(h, out literal)) return new IPAddress[] { literal };
            return Dns.GetHostAddresses(h);
        }

        private void Fail(string message)
        {
            host.Log("channel " + channel + " connect failed: " + message);
            host.Send(Frame.MakeText(FrameType.CONNECT_FAIL, channel, message));
            host.Forget(channel);
        }

        private void Pump()
        {
            byte[] buf = new byte[READ_BUFFER];
            try
            {
                while (!killed)
                {
                    int n = stream.Read(buf, 0, buf.Length);
                    if (n <= 0) break;

                    // Same coalescing idea as the pipe pumps, but a socket cannot be peeked
                    // with PeekNamedPipe -- Socket.Available answers the same question.
                    if (!PwsshAgentHost.DisableCoalescing)
                    {
                        while (n < buf.Length && sock.Available > 0)
                        {
                            int more = stream.Read(buf, n, buf.Length - n);
                            if (more <= 0) break;
                            n += more;
                        }
                    }

                    SendPayload(buf, n);
                }
            }
            catch (Exception ex)
            {
                if (!killed) host.Log("tcp pump ended: " + ex.Message);
            }
            finally
            {
                // No exit status for a socket; DONE alone closes the channel.
                host.Send(Frame.Make(FrameType.DONE, channel, null));
                host.Forget(channel);
            }
        }

        private void SendPayload(byte[] buf, int count)
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
                try { packed = Zip.Deflate(buf, off, allowed); }
                catch (Exception ex) { host.Log("deflate failed: " + ex.Message); }

                if (packed != null && packed.Length < allowed - (allowed / 8))
                {
                    host.Send(Frame.Make((byte)(FrameType.OUT | FrameType.COMPRESSED), channel, packed));
                }
                else
                {
                    host.Send(Frame.Make(FrameType.OUT, channel, buf, off, allowed));
                }
                off += allowed;
            }
        }

        public void Write(byte[] frame, int offset, int count)
        {
            if (count <= 0) return;
            try
            {
                NetworkStream s = stream;
                if (s != null) { s.Write(frame, offset, count); s.Flush(); }
            }
            catch (Exception ex) { host.Log("tcp write failed: " + ex.Message); }
        }

        // SSH channel EOF is a half-close, so shut down only our sending direction and let
        // the peer keep replying.
        public void CloseWrite()
        {
            try { if (sock != null) sock.Shutdown(SocketShutdown.Send); } catch { }
        }

        public void Kill()
        {
            killed = true;
            lock (creditGate) { Monitor.PulseAll(creditGate); }
            try { if (sock != null) sock.Close(); } catch { }
        }
    }
}
