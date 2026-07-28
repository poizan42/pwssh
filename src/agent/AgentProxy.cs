// The client half: turns engine calls into frames and frames into sink callbacks.
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
    // ------------------------------------------------------------------ client proxy

    public sealed class PwsshAgentProxy : IPwsshAgent, IByteReceiver
    {
        private readonly FrameQueue outbound = new FrameQueue();
        private readonly object helloGate = new object();
        private IPwsshChannelSink sink;
        private string remoteUser;
        private volatile bool remotePty;
        private volatile bool inboundClosed;

        public bool RemoteSupportsPty { get { return remotePty; } }

        public void Attach(IPwsshChannelSink s)
        {
            sink = s;
            StartKeepAlive();
        }

        public bool InboundClosed { get { return inboundClosed; } }

        // Keepalive interval. The agent times out at four times this, so a couple of lost or
        // delayed pings are harmless.
        public static int KeepAliveMs = 30000;
        private int keepAliveStarted;

        // ssh TerminateProcesses its ProxyCommand on exit, so this process usually dies without
        // a chance to tell the remote anything. The agent therefore cannot distinguish an idle
        // client from a dead one by silence alone -- hence a ping while we are alive, and the
        // absence of one being what lets the agent give up and release its resources.
        private void StartKeepAlive()
        {
            if (KeepAliveMs <= 0) return;
            if (Interlocked.CompareExchange(ref keepAliveStarted, 1, 0) != 0) return;
            Thread t = new Thread(new ThreadStart(delegate
            {
                while (!inboundClosed)
                {
                    Thread.Sleep(KeepAliveMs);
                    if (inboundClosed) return;
                    try { outbound.Enqueue(Frame.Make(FrameType.PING, 0, null)); }
                    catch (Exception) { return; }
                }
            }));
            t.IsBackground = true;
            t.Name = "pwssh-keepalive";
            t.Start();
        }

        // Transport side: drain frames to send to the remote.
        public byte[] TakeOutboundFrame(int timeoutMs) { return outbound.Take(timeoutMs); }

        public void PushInbound(byte[] frame)
        {
            if (!Frame.IsValid(frame)) return;
            byte raw = Frame.Type(frame);
            bool compressed = (raw & FrameType.COMPRESSED) != 0;
            byte type = (byte)(raw & ~FrameType.COMPRESSED);
            uint ch = Frame.Channel(frame);

            switch (type)
            {
                case FrameType.OUT:
                case FrameType.ERR:
                    if (sink != null)
                    {
                        bool isErr = (type == FrameType.ERR);
                        if (compressed)
                        {
                            byte[] u = Zip.Inflate(frame, Frame.HEADER, Frame.PayloadLength(frame));
                            sink.OnData(ch, u, 0, u.Length, isErr);
                        }
                        else
                        {
                            // No copy: hand the frame buffer through as a range.
                            sink.OnData(ch, frame, Frame.HEADER, Frame.PayloadLength(frame), isErr);
                        }
                    }
                    break;
                case FrameType.EXIT:
                    if (sink != null) sink.OnExit(ch, Frame.PayloadUInt32(frame));
                    break;
                case FrameType.DONE:
                    if (sink != null) sink.OnClose(ch);
                    break;
                case FrameType.HELLO:
                    lock (helloGate)
                    {
                        // "user=kb;conpty=1"
                        string[] parts = Frame.PayloadText(frame).Split(';');
                        for (int i = 0; i < parts.Length; i++)
                        {
                            int eq = parts[i].IndexOf('=');
                            if (eq <= 0) continue;
                            string k = parts[i].Substring(0, eq);
                            string v = parts[i].Substring(eq + 1);
                            if (k == "user") remoteUser = v;
                            else if (k == "conpty") remotePty = (v == "1");
                        }
                        Monitor.PulseAll(helloGate);
                    }
                    break;
                case FrameType.CONNECT_OK:
                    if (sink != null) sink.OnConnectResult(ch, true, null);
                    break;
                case FrameType.CONNECT_FAIL:
                    if (sink != null) sink.OnConnectResult(ch, false, Frame.PayloadText(frame));
                    break;
                case FrameType.LISTEN_OK:
                    if (sink != null) sink.OnListenResult(ch, true, (int)Frame.PayloadUInt32(frame), null);
                    break;
                case FrameType.LISTEN_FAIL:
                    if (sink != null) sink.OnListenResult(ch, false, 0, Frame.PayloadText(frame));
                    break;
                case FrameType.ACCEPTED:
                    if (sink != null)
                    {
                        SshLikeReader ar = new SshLikeReader(frame, Frame.HEADER);
                        uint fwd = ar.UInt32();
                        int bPort = (int)ar.UInt32();
                        string oAddr = ar.Text();
                        int oPort = (int)ar.UInt32();
                        sink.OnAccepted(ch, fwd, bPort, oAddr, oPort);
                    }
                    break;
                case FrameType.FAIL:
                    if (sink != null) sink.OnAgentError(ch, Frame.PayloadText(frame));
                    break;
            }
        }

        public void CloseInbound()
        {
            inboundClosed = true;
            outbound.Close();
            lock (helloGate) { Monitor.PulseAll(helloGate); }
        }

        public string WaitForRemoteUser(int timeoutMs)
        {
            lock (helloGate)
            {
                if (remoteUser != null) return remoteUser;
                int waited = 0;
                while (remoteUser == null && !inboundClosed && waited < timeoutMs)
                {
                    Monitor.Wait(helloGate, 100);
                    waited += 100;
                }
                return remoteUser;
            }
        }

        public void Exec(uint channel, string command)
        {
            outbound.Enqueue(Frame.MakeText(FrameType.EXEC, channel, command));
        }

        public void Shell(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.SHELL, channel, null));
        }

        public void Subsystem(uint channel, string name)
        {
            outbound.Enqueue(Frame.MakeText(FrameType.SUBSYSTEM, channel, name));
        }

        public void Connect(uint channel, string host, int port)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.Text(host); w.UInt32((uint)port);
            outbound.Enqueue(Frame.Make(FrameType.CONNECT, channel, w.ToArray()));
        }

        public void Listen(uint forwardId, string bindAddress, int port)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.Text(bindAddress); w.UInt32((uint)port);
            outbound.Enqueue(Frame.Make(FrameType.LISTEN, forwardId, w.ToArray()));
        }

        public void Unlisten(uint forwardId)
        {
            outbound.Enqueue(Frame.Make(FrameType.UNLISTEN, forwardId, null));
        }

        public void AcceptOk(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.ACCEPT_OK, channel, null));
        }

        public void RequestPty(uint channel, uint cols, uint rows, string term)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.UInt32(cols); w.UInt32(rows); w.Text(term);
            outbound.Enqueue(Frame.Make(FrameType.PTY, channel, w.ToArray()));
        }

        public void Resize(uint channel, uint cols, uint rows)
        {
            SshLikeWriter w = new SshLikeWriter();
            w.UInt32(cols); w.UInt32(rows);
            outbound.Enqueue(Frame.Make(FrameType.RESIZE, channel, w.ToArray()));
        }

        public void Signal(uint channel, string name)
        {
            outbound.Enqueue(Frame.MakeText(FrameType.SIGNAL, channel, name));
        }

        public void SendStdin(uint channel, byte[] data)
        {
            outbound.Enqueue(Frame.Make(FrameType.DATA, channel, data));
        }

        public void CloseStdin(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.EOF, channel, null));
        }

        public void CloseChannel(uint channel)
        {
            outbound.Enqueue(Frame.Make(FrameType.CLOSE, channel, null));
        }

        public void GrantWindow(uint channel, uint bytes)
        {
            outbound.Enqueue(Frame.MakeUInt32(FrameType.WINDOW, channel, bytes));
        }
    }
}
