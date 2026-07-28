// The interfaces between the client engine, the proxy and the agent-side channels.
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
    // -------------------------------------------------------------- client contracts

    public interface IPwsshAgent
    {
        void Attach(IPwsshChannelSink sink);
        void Exec(uint channel, string command);
        void Shell(uint channel);
        // A subsystem channel. No round trip is available to ask whether the remote supports
        // one, so the engine decides locally -- see SessionChannel.StartSubsystem.
        void Subsystem(uint channel, string name);
        // direct-tcpip: the result arrives asynchronously via IPwsshChannelSink, because
        // blocking the protocol loop on a remote connect would stall every other channel.
        void Connect(uint channel, string host, int port);
        // Remote forwarding. Results arrive asynchronously via IPwsshChannelSink.
        void Listen(uint forwardId, string bindAddress, int port);
        void Unlisten(uint forwardId);
        void AcceptOk(uint channel);
        void RequestPty(uint channel, uint cols, uint rows, string term);
        void Resize(uint channel, uint cols, uint rows);
        void Signal(uint channel, string name);
        void SendStdin(uint channel, byte[] data);
        void CloseStdin(uint channel);
        void CloseChannel(uint channel);
        void GrantWindow(uint channel, uint bytes);
        // Whether the remote can provide a real terminal. Reported in HELLO, so pty-req can
        // be answered without an extra round trip.
        bool RemoteSupportsPty { get; }
        // Blocks for the agent's HELLO. The local SSH handshake is instant now, so userauth
        // can arrive before HELLO has made the round trip; blocking here lets session setup
        // and the handshake overlap instead of serialising.
        string WaitForRemoteUser(int timeoutMs);
    }

    public interface IPwsshChannelSink
    {
        // Takes a range rather than an array so the frame buffer can be passed straight
        // through: the client owns it exclusively, so copying the payload out is waste.
        void OnData(uint channel, byte[] buffer, int offset, int count, bool stderr);
        void OnExit(uint channel, uint status);
        void OnClose(uint channel);
        void OnConnectResult(uint channel, bool ok, string message);
        void OnListenResult(uint forwardId, bool ok, int boundPort, string message);
        void OnAccepted(uint channel, uint forwardId, int boundPort, string originAddress, int originPort);
        // Carries the channel the failure belongs to, so the engine can close it. Without that
        // the client keeps a channel open waiting for output that will never come, which looks
        // exactly like slowness on a link where seconds are normal.
        void OnAgentError(uint channel, string message);
    }

    // ---------------------------------------------------------- agent-side channel kinds
    //
    // What every channel kind on the remote has in common: bytes go in, credit is returned,
    // and it can be shut down. The kinds differ entirely in what they do with the bytes -- a
    // child process's stdin, a socket, or SFTP requests -- so this is all they share.
    //
    // Having it lets PwsshAgentHost keep one map instead of one per kind, which matters
    // because DATA/EOF/CLOSE/WINDOW apply to all of them: without it, adding a kind means
    // remembering to extend four separate lookups.
    internal interface IAgentStream
    {
        // The frame buffer is passed as a range, not copied. Runs on the frame dispatch
        // thread, so an implementation must not block: doing so stalls every other channel.
        void Write(byte[] frame, int offset, int count);
        void CloseWrite();
        void AddCredit(uint add);
        void Kill();
    }
}
