// Remote forwarding: binds a port here and reports connections to the client.
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
    // ------------------------------------------------------------ remote forwarding (-R)
    //
    // Binds a port on the remote and reports each accepted connection to the client, which
    // then opens a forwarded-tcpip channel back to us. The accepted socket is parked until
    // that channel is confirmed.

    internal sealed class AgentListener
    {
        private readonly PwsshAgentHost host;
        private readonly uint forwardId;
        private readonly List<TcpListener> listeners = new List<TcpListener>();
        private volatile bool stopped;

        public AgentListener(PwsshAgentHost h, uint id) { host = h; forwardId = id; }

        public uint ForwardId { get { return forwardId; } }
        public int BoundPort { get; private set; }

        // Returns null on success, or the reason it could not bind.
        //
        // Note there is no privileged-port rule on Windows: a normal user can bind port 80 if
        // it is free. Binds fail because the port is already in use, or because it falls in an
        // excluded range (netsh interface ipv4 show excludedportrange).
        //
        // Runs on the frame dispatch thread, which binding is quick enough for. The exception is
        // a named bind address, which costs a DNS lookup and so briefly stalls every channel --
        // only reachable with -GatewayPorts, and only when the client names a host rather than
        // an address.
        public string Bind(string address, int port)
        {
            // One socket per address family, for the same reason -L needed it: a socket bound
            // to 127.0.0.1 does not accept ::1, and a dual-mode socket bound to a *specific*
            // v6 address does not accept mapped v4 either. So loopback and wildcard both mean
            // two sockets, and a program on the remote reaching "localhost" works whichever
            // family it resolves to.
            IPAddress[] addrs;
            try { addrs = ParseBindAddresses(address); }
            catch (Exception ex) { return ex.Message; }
            string firstError = null;
            int chosen = port;

            foreach (IPAddress addr in addrs)
            {
                TcpListener l = null;
                try
                {
                    l = new TcpListener(addr, chosen);
                    l.Start();
                    if (chosen == 0) chosen = ((IPEndPoint)l.LocalEndpoint).Port;
                    listeners.Add(l);
                }
                catch (Exception ex)
                {
                    try { if (l != null) l.Stop(); } catch { }
                    if (firstError == null) firstError = ex.Message;
                }
            }

            // Partial success is success: an IPv6-less remote must not fail an ordinary -R.
            if (listeners.Count == 0)
            {
                return firstError == null ? "no address to bind" : firstError;
            }

            BoundPort = chosen;
            foreach (TcpListener l in listeners)
            {
                TcpListener captured = l;
                Thread t = new Thread(delegate() { AcceptLoop(captured); });
                t.IsBackground = true;
                t.Name = "pwssh-listen-" + BoundPort;
                t.Start();
            }
            return null;
        }

        // An EMPTY address means wildcard, not loopback: that is what OpenSSH puts on the wire
        // for `-R *:port:...` (see the note in PwsshEngine.HandleGlobalRequest).
        private static IPAddress[] ParseBindAddresses(string address)
        {
            if (string.IsNullOrEmpty(address) || address == "*" || address == "0.0.0.0")
                return new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
            if (address == "::" || address == "[::]")
                return new IPAddress[] { IPAddress.IPv6Any };
            if (address == "localhost")
                return new IPAddress[] { IPAddress.Loopback, IPAddress.IPv6Loopback };
            IPAddress parsed;
            if (IPAddress.TryParse(address.Trim('[', ']'), out parsed))
            {
                // 127.0.0.1 is how the engine spells "loopback only", so widen it to both
                // families; any other literal is taken exactly as given.
                if (IPAddress.Loopback.Equals(parsed))
                    return new IPAddress[] { IPAddress.Loopback, IPAddress.IPv6Loopback };
                return new IPAddress[] { parsed };
            }
            IPAddress[] resolved = Dns.GetHostAddresses(address);
            if (resolved.Length == 0) throw new Exception("cannot resolve bind address " + address);
            return resolved;
        }

        private void AcceptLoop(TcpListener listener)
        {
            while (!stopped)
            {
                Socket s;
                try { s = listener.AcceptSocket(); }
                catch (Exception)
                {
                    break;                        // listener stopped
                }
                if (stopped) { try { s.Close(); } catch { } break; }

                try { host.OnAccepted(this, s); }
                catch (Exception ex)
                {
                    host.Log("accept handling failed: " + ex.Message);
                    try { s.Close(); } catch { }
                }
            }
        }

        public void Stop()
        {
            stopped = true;
            foreach (TcpListener l in listeners) { try { l.Stop(); } catch { } }
        }
    }
}
