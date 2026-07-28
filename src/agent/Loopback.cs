// Development wiring: joins a proxy and a host in-process.
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
    // ------------------------------------------------------------- loopback wiring
    //
    // Connects a proxy to a host in-process through the real frame protocol, so the dev
    // harness exercises everything except the WinRM hop.

    public static class PwsshLoopback
    {
        public static IPwsshAgent Start()
        {
            PwsshAgentHost host = new PwsshAgentHost();
            PwsshAgentProxy proxy = new PwsshAgentProxy();
            host.Start();

            Thread up = new Thread(new ThreadStart(delegate
            {
                try
                {
                    while (true)
                    {
                        byte[] f = proxy.TakeOutboundFrame(200);
                        if (f != null) { host.PushInbound(f); continue; }
                        if (proxy.InboundClosed) break;
                    }
                }
                catch (Exception) { }
                finally { host.CloseInbound(); }
            }));
            up.IsBackground = true;
            up.Name = "pwssh-loopback-up";
            up.Start();

            Thread down = new Thread(new ThreadStart(delegate
            {
                try
                {
                    while (true)
                    {
                        byte[] f = host.TakeOutboundFrame(200);
                        if (f != null) { proxy.PushInbound(f); continue; }
                        if (host.Finished) break;
                    }
                }
                catch (Exception) { }
                finally { proxy.CloseInbound(); }
            }));
            down.IsBackground = true;
            down.Name = "pwssh-loopback-down";
            down.Start();

            return proxy;
        }
    }
}
