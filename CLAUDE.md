# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

**`exec` and `shell` both work end to end over WinRM.** `ssh pwssh-test whoami` returns the remote's `DOMAIN\user`, and `ssh pwssh-test` gives a cmd.exe session — with a real terminal when the client asks for one. The suite runs 99–109 cases per transport, and both are green: **WinRM 109/109, loopback 99/99**. A second suite, `tests/Pwssh.Tests`, adds **102 xUnit cases** for what the stock client cannot ask for — a mid-transfer backwards seek, raw SFTP packets, every symlink case, and the first automated coverage of pty, `window-change` and `signal`; see *The SSH.NET test project*. Loopback needs the dev host started with its own console, or the pty case fails on a harness artifact rather than a pwssh bug — see *Running and testing*. The two runs differ in composition rather than count — WinRM has the graceful-degradation and IPv6 cases plus the gateway-ports check; loopback has the wrong-username check that the WinRM alias takes from `ssh_config`, along with the reverse-forward release and bind-failure cases that need the far side to be this machine.

**A run that fails one case with `exit=255` is usually a flake, not a regression.** 255 is ssh's own error code for a connection that never came up, and it turns up after the remote has been hammered with dozens of sessions in a row. Re-run the case before believing it: the final WinRM run here failed "shell exit status propagates" that way and passed 3/3 immediately afterwards.

**SSH terminates in the client.** `pwssh-connect.ps1` runs the whole SSH engine locally and only plaintext agent frames cross the WinRM link. The remote does no cryptography at all. This was a deliberate change from an earlier design that ran the engine on the remote, and it bought:

| | remote termination | client termination |
|---|---|---|
| connect, `ssh host "echo x"` | 9,176 ms | **5,701 ms** (1.61×, interleaved over 5 rounds) |
| 8 MiB `exec`, compressible | 0.30 MiB/s | **1.13 MiB/s** (3.8×) |

The throughput gain is WinRM's own compression, which an encrypted stream made useless. The same suite reports **0.31 MiB/s for an incompressible 8 MiB payload** — essentially identical to what the old architecture managed on *compressible* data, which is exactly what the mechanism predicts and a good confirmation of it.

Implemented: version exchange, `diffie-hellman-group14-sha256` KEX, `rsa-sha2-256` host key, `aes256-ctr` + `hmac-sha2-256-etm@openssh.com`, `none` auth with username matching, session channel, `exec`, `shell`, `pty-req` via ConPTY, `window-change`, `signal`, `direct-tcpip` forwarding (`-L`/`-D`/`-W`, IPv4 and IPv6), `tcpip-forward` + `forwarded-tcpip` reverse forwarding (`-R`, loopback by default, `-GatewayPorts` to widen), the `sftp` subsystem (version 3, and therefore `scp`), paths past `MAX_PATH` via `\\?\` and Win32, rekeying, exit status, stderr as `CHANNEL_EXTENDED_DATA`, window management, credit-based flow control to the agent, `SYMLINK`/`READLINK`, `statvfs@openssh.com` (`df`), the legacy scp protocol (`scp -O`, pscp, `ScpClient`).

Not implemented: `expand-path@openssh.com` and `users-groups-by-id@openssh.com` (the only two extension names the client knows and we do not answer), strict KEX (deliberately — see *Rekeying*).

**The host key is now purely ceremonial.** It authenticates this proxy, not the remote machine — nothing about it crosses the link. It still has to be stable, because the client pins it in `known_hosts`.

## No remote configuration

**pwssh must work with nothing but an ordinary WinRM session.** Anyone who can reconfigure the remote can install OpenSSH instead and get a better result in every respect — so a change that requires admin there does not trade off against anything, it removes the project's reason to exist.

This rules out a class of otherwise reasonable optimisations permanently. `MaxEnvelopeSizekb`, WinRM service tuning, quota changes, installing runtimes or modules: all rejected regardless of how much they help. Treat any proposal that begins "just set X on the remote" as out of scope.

What the remote currently needs, and all it may ever need:

- a WinRM session the user can already open;
- permission to start a process as that same user;
- a local named pipe between two of the user's own processes (only when `-Streams` > 1).

Nothing is written to the remote's disk, no service is reconfigured, no elevation is used, and the host key never leaves the client.

## Repository layout

| Path | Role |
|---|---|
| `src/PwsshEngine.cs` | The SSH implementation — packet layer, KEX, cipher, MAC, auth, `SessionChannel`, plus `PwsshStdioBridge`. Runs on the **client** only. |
| `src/agent/*.cs` | Everything the remote needs, plus the plumbing shared with the engine (`ByteChannel`, `FrameQueue`, `PwsshPump`, `Frame`). Thirteen files: `Frames`, `ByteStream`, `Contracts`, `AgentProxy`, `AgentHost`, `ConPty`, `ProcessChannel`, `TcpChannel`, `Sftp`, `Scp`, `Win32Fs`, `Listener`, `Loopback`. |
| `src/agent/PwsshAgent.csproj` | Builds those into the net48 DLL that gets pushed to the remote. **This is the only compiler that matters for the agent's language level** — see *The agent is a prebuilt assembly*. |
| `src/PwsshCommon.ps1` | Client-only helpers: compilation with an on-disk cache, the agent-DLL lookup and staleness check, host key keystore. |
| `src/Start-PwsshAgent.ps1` | Runs on the remote: loads the pushed assembly and shuttles frames. No crypto, no host key, no compiler. Must stay a *simple* script — see the parameter-binding trap below. |
| `tools/Build-Agent.ps1` | Builds the agent DLL and stamps it with a hash of the sources it came from. |
| `pwssh-connect.ps1` | Client `ProxyCommand` entry point; runs the SSH engine. |
| `tools/Start-PwsshTcpHost.ps1`, `tools/PwsshTcpHost.cs` | Dev-only loopback host, using an in-process agent wired through the real frame protocol. |
| `tests/Invoke-PwsshTests.ps1` | End-to-end tests through the real `ssh` client, against either transport. |
| `tests/Pwssh.Tests/` | xUnit project for what the stock client cannot reach: SSH.NET over a socket, plus a frame-level SFTP driver. See *The SSH.NET test project*. |

### The agent is a prebuilt assembly

`src/agent/PwsshAgent.csproj` builds the agent to a **.NET Framework 4.8 DLL**, which the client pushes as a `byte[]` parameter and the remote loads with `[Reflection.Assembly]::Load`. It replaced sending ~156 KB of C# for the remote's CodeDOM to compile on every single connection.

Measured before committing to it:

| | source, compiled remotely | prebuilt DLL |
|---|---|---|
| raw size | 156,088 B | 55,808 B |
| on the wire (deflated) | 36,721 B | **26,671 B** |
| cost on the remote | **~480 ms** (453–726 across runs) | **4–141 ms** |
| connection setup, `ssh host "echo x"` | 3,875 ms median | **3,412 ms median** |

Two things about that are worth keeping straight. The DLL is *smaller on the wire despite compressing worse* — text deflates ~4.3× against a DLL's ~2.2×, but it starts three times the size, and upstream is the scarce direction. And connect is now faster than it was **before** SFTP existed (3,663 ms), even though the agent grew 54%.

**`Assembly.Load(byte[])` keeps the no-remote-footprint rule intact**: verified on the real remote, the assembly reports no `Location`, so nothing is written to the remote's disk. It also removes the reason the agent used to be one giant file — that constraint existed because an in-memory assembly has no `Location` for a *second* compilation to reference, and nothing on the remote compiles against it any more.

Consequences, all of them good, and all of them things the old design forbade:

- **The agent is C# 7.3, not C# 5.** `LangVersion` is pinned in the csproj. 7.3 is the ceiling that needs nothing from the runtime beyond net48; C# 8+ wants runtime support or polyfills for its headline features. `src/PwsshEngine.cs` is still compiled by `Add-Type` on the client, so it can go further, but there is no reason for the two to drift.
- **It is eleven files instead of one 3,627-line one.**
- **Warnings are errors**, and Roslyn's are much better than CodeDOM's.
- The remote no longer receives `PwsshCommon.ps1` at all, since it no longer compiles anything.

The costs, stated plainly. There is now a **build step** where there was none: `tools/Build-Agent.ps1`, needing the .NET SDK and the 4.8 targeting pack. The DLL is **not committed** — a binary nobody can diff has no place in a repo like this — so it is published with releases (`.github/workflows/release.yml`) and built locally otherwise. And a prebuilt artifact can go **stale**: the build stamps `PwsshAgent.dll.srchash` with a content hash of the sources, `Get-PwsshAgentDllState` compares it, and the client refuses to run a mismatch rather than silently executing old code on the remote. A DLL with no stamp is accepted, because that is what a release looks like and there is nothing to compare it against.

The hash is content-based and line-ending-normalised on purpose: a fresh clone changes every mtime and possibly every line ending without changing the code, and that must not invalidate a released DLL.

### Client ↔ agent frames

One transport item is exactly one frame; items cross intact and in order, so there is no length prefixing between frames — only a header:

```
[1 byte type][4 bytes big-endian channel id][4 bytes big-endian sequence][payload…]
```

Client → agent: `0x01 EXEC`, `0x02 DATA` (stdin), `0x03 EOF`, `0x04 CLOSE`, `0x05 WINDOW`, `0x06 SHELL`, `0x07 PTY`, `0x08 RESIZE`, `0x09 SIGNAL`, `0x0A CONNECT`. Agent → client: `0x81 DATA`, `0x82 STDERR`, `0x83 EXIT`, `0x84 DONE`, `0x85 HELLO`, `0x86 FAIL`, `0x87 CONNECT_OK`, `0x88 CONNECT_FAIL`. The high bit marks direction.

`HELLO` carries `key=value` pairs (`user=kb;conpty=1`), not a bare account name — see the shell section.

Two things about this are load-bearing:

- **`SessionChannel.OnAgentData` must never block.** It runs on the client's frame loop, and blocking there for ssh window credit would stop the same loop that drains the remoting output — an immediate deadlock. A dedicated sender thread owns all window waiting.
- **Credit is returned to the agent in batches, on receipt** (`GRANT_THRESHOLD`, 2 MiB). Granting per SSH packet produced ~256 tiny `WINDOW` frames for an 8 MiB download, all travelling upstream — the slow direction. Granting *after* the SSH write was worse still; see the credit round-trip note further down.
- **Every outbound frame must go through `PwsshAgentHost.Send`**, which is where the sequence number is stamped. Enqueuing straight onto the outbound queue leaves the sequence at 0, which collides with the first sequenced frame and makes the client's resequencer silently drop one as a duplicate. This bit the `HELLO` frame and produced a connection that succeeded with empty output.

### Shell channels and ConPTY

`ssh myremote` opens a shell channel running `%ComSpec%`, matching what Windows OpenSSH does by default and what `exec` already uses. Two modes:

- **pty requested** → ConPTY. Real terminal semantics: colour, `Ctrl+C`, resize, and programs that check for a console behave normally. A pty has one merged output stream, so nothing is sent as `CHANNEL_EXTENDED_DATA` in this mode — a terminal has no separate stderr.
- **no pty** (e.g. `echo cmd | ssh myremote`) → pipes, exactly like `exec`.

**Availability is negotiated in `HELLO`, not asked for.** `CreatePseudoConsole` exists only from Windows 10 1809 / Server 2019, and the client must answer `pty-req` immediately — asking the remote at that moment would cost a round trip on every interactive connection. The agent therefore probes at startup (resolve the export, *then* actually create and close a 1×1 pseudoconsole, because the export existing is not proof it works here) and reports `conpty=0|1`. Where it is 0, `pty-req` gets `CHANNEL_FAILURE`; ssh prints "PTY allocation request failed" and continues over pipes.

**ConPTY does work inside `wsmprovhost`**, which was the main risk — verified in session 0 on build 26200, a service session with no console of its own.

Implementation notes that are easy to get wrong:

- `System.Diagnostics.Process` **cannot** drive a ConPTY: the pseudoconsole attaches through a `PROC_THREAD_ATTRIBUTE` on `STARTUPINFOEX`, which `Process` does not expose. Hence raw `CreateProcess` in `ConPtySession`.
- **`ClosePseudoConsole` is what makes the output reader see EOF**, so it must happen after the child exits but *before* waiting for the output pump to drain — otherwise that wait hangs for its full timeout.
- Child processes are put in a **Job Object with `KILL_ON_JOB_CLOSE`**. A shell spawns children and `Process.Kill(true)` does not exist on .NET Framework 4.8, so without it a killed shell orphans its tree. Verified: killing the ssh client mid-`ping` takes the remote `ping` with it.
- `-DisableConPty` on the client forces the no-ConPTY path, so the degradation behaviour is tested rather than assumed.
- **`IsAvailable()` publishes its answer once, at the end, and that ordering is load-bearing.** It used to assign `available = 0` before probing and raise it to 1 on success, which advertises "no ConPTY here" for the whole duration of the probe — so a second thread arriving in that window took the early return, reported `conpty=0` in its `HELLO`, and had `pty-req` refused with nothing actually wrong. Reachable because `PwsshAgentHost.Start` calls it per connection and a host can serve connections concurrently. Found by the xUnit pty tests, whose readiness probe opens a throwaway connection immediately before the real one, and which failed intermittently until this was fixed. Two threads may now both probe; that is harmless, since the probe has no side effects that outlive it and both compute the same answer.

**`-tt` failing against a remote without ConPTY is correct, not a bug.** `-tt` *forces* pty allocation, so a refusal is fatal by design; the test asserts we refuse cleanly rather than that the command still runs.

**Interactive latency is unchanged by any of this.** Each keystroke is a WinRM round trip, so echo takes roughly 250–900 ms. ConPTY buys correctness, not responsiveness.

**Output pumps coalesce whatever is already pending** (`PipePeek.Available`, an anonymous-pipe `PeekNamedPipe`) instead of sending a frame per read. The condition is "bytes available right now", never a timer, so a lone keystroke echo is still sent immediately and interactive latency is untouched. `-DisableCoalescing` turns it off for measurement.

It is worth less than it looks. Interleaved over `ls C:\Windows\System32` under a pty, three rounds, coalescing winning each: **5,264 ms of streaming versus 5,634 ms, so 1.07×**, with 10 stalls instead of 11. The reason the gain is small is instructive — of ~5.3 s of streaming, ~4.5 s is stalls either way, and those stalls are PowerShell taking ~5 s to *produce* the listing (measured remote-side: 1.75 MB in 4.9 s with no gap over 100 ms). Coalescing cannot batch data that does not exist yet. Two things follow: a slow producer, not the transport, sets the pace for chatty interactive output; and `-Streams` is useless here, measured at 0.83× with identical total stall time, because parallel receive threads do not shorten a turnaround.

Note also that reading `FileStream.SafeFileHandle` flushes the stream, which a pipe cannot re-seek, so the handle is captured **before** the first read and the ConPTY streams are created unbuffered so the peek agrees with what is actually pending.

### Port forwarding (`direct-tcpip`)

`ssh -L`, `ssh -D` (SOCKS) and `ssh -W` all work, because the client does the listening and the SOCKS parsing itself and only asks us to open outbound connections — one channel type covers all three. `-R` is a separate mechanism; see below.

- **Channels are multiplexed.** The engine keys them by *our* local id, allocated monotonically. Client channel numbers are recycled after close, so keying remote state on them risks a close/open collision; the channel object holds both identities.
- **`CHANNEL_CLOSE` closes one channel, not the session.** The connection ends only on `DISCONNECT` or transport EOF. `ssh -N` therefore works with no session channel at all.
- **A `direct-tcpip` open is answered with the real connect result**, which means it cannot be answered synchronously: whether the remote can reach the target is only known a round trip later, and blocking the protocol loop there would stall every other channel. So the open is recorded, `CONNECT` is sent, and `OnConnectResult` sends either the confirmation or `CHANNEL_OPEN_FAILURE` with reason 2. That is what makes ssh print a real `connect failed: ... actively refused it` instead of handing the user a dead tunnel.
- **Forwarded channels get a much smaller window** (`InitialTcpCredit`, 2 MiB) than session channels (`-CreditMiB`, 32 MiB): a SOCKS client can hold dozens open at once. The cost is bulk through a single forward measuring ~0.85 MiB/s against ~1.2 MiB/s for a session channel; raise `InitialTcpCredit` if single-stream forwarded bulk ever matters more than many-channel memory.
- The pipe pumps coalesce with `PeekNamedPipe`, which does not work on sockets — `AgentTcpChannel` uses `Socket.Available` for the same test.
- **Never connect with `new TcpClient()`.** Its default constructor produces an `AddressFamily.InterNetwork` (IPv4) socket, so an IPv6 target fails with a nonsensical `WSAENOTCONN` — *"A request to send or receive data was disallowed because the socket is not connected"* — rather than a routing error. It also meant a host with both AAAA and A records never fell back to IPv4. `AgentTcpChannel` resolves the name, strips a bracketed IPv6 literal, and tries each address with a socket of that address family.
- **Each attempt is capped at 8 s when there is more than one candidate address.** A dual-stack host with dead IPv6 otherwise burns the OS connect timeout (~21 s observed) before trying IPv4, which is intolerable for SOCKS browsing. A single candidate keeps the OS default so a legitimately slow target still works.
- `ssh` itself rejects a bare `::1:5985` in `-W` with "Bad stdio forwarding specification"; IPv6 literals need brackets. Not our parsing.

**`-D` against a remote without IPv6 logs benign failures.** Confirmed with Firefox: a SOCKS client hands over a literal address, so there is one candidate and no fallback inside pwssh, and every AAAA attempt ends as `channel N: open failed: connect failed: ...` once the connect times out. Nothing is wrong — browsers race the families in parallel, so pages load over IPv4 with no user-visible delay. `ssh -q` (or `LogLevel QUIET`) silences the messages and does not change the exit code; disabling IPv6 in the browser removes the attempts altogether. A per-connect timeout knob was considered and rejected: with the parallel racing there is nothing to gain.

Measured: four concurrent forwarded connections complete in the time of about one (1.6 s), so opens pipeline rather than serialising. Bulk through a forward is bit-exact over 8 MiB.

### Remote forwarding (`-R`, `forwarded-tcpip`)

`ssh -R` works. It is the mirror image of `-L` and needed machinery the engine had never had: the remote binds the listening port, and **we** initiate the channel open when a connection arrives there. Frames: `LISTEN` / `UNLISTEN` / `ACCEPT_OK` outbound, `LISTEN_OK` / `LISTEN_FAIL` / `ACCEPTED` inbound.

- **`CHANNEL_OPEN_CONFIRMATION` and `CHANNEL_OPEN_FAILURE` are now handled.** They previously fell into `default` and drew an `UNIMPLEMENTED` reply, which was harmless only because nothing ever opened a channel from this side. A confirmation for an unknown id is ignored rather than fatal.
- **The channel id space is partitioned.** The engine allocates upward from 0; the agent allocates ids for connections *it* accepts from `0x80000000`. Without that split the two allocators would eventually collide, and the symptom would be data surfacing on the wrong channel.
- **A `SessionChannel` can now exist before its peer is known.** `ConfirmOpened(peer, window, maxPacket)` fills in the identity and limits from the client's confirmation and only then starts the sender thread — nothing may be written to the client before the channel is confirmed.
- **The wire convention for the bind address is the opposite way round from how it reads.** OpenSSH's `channel_rfwd_bind_host` sends `"localhost"` for a plain `-R port:...` and an **empty string** for `-R *:port:...`. So empty means *wildcard*, and only an explicitly-loopback address is safe without `-GatewayPorts`. Reading it the intuitive way silently binds loopback when the user asked for the world, which is the one failure mode worth being careful about here.
- **The address quoted back in `forwarded-tcpip` must be the one the client asked for**, not the one actually bound: ssh matches an incoming forwarded channel against its own forward list by (address, port). Hence `ACCEPTED` carries the *forward id* and the engine looks the address up in `forwardAddresses` — sending the agent's real bind address would leave ssh reporting `forwarding for unknown listen_port`.
- **Loopback and wildcard both mean two sockets**, one per address family, exactly as `-L` needed. A socket bound to `127.0.0.1` does not accept `::1`, and a dual-mode socket bound to a *specific* v6 address does not accept mapped v4 either — so a program on the remote reaching `localhost` works whichever family it resolves to. **A partial bind counts as success**, which is what sshd does and what an IPv6-less remote needs. Consequence for testing: occupying only one family does not make a bind fail.
- **The accepted socket is not read until `ACCEPT_OK`.** Reading earlier would produce data for a channel the client has not yet acknowledged.
- **Listeners are closed in three places**, because a leaked one keeps a port bound on the remote: `UNLISTEN`, `PwsshAgentHost.Stop()`, and `KillAllChannels()` on the engine side, which unlistens every active forward when the SSH connection ends. Relying on the remote process exiting is slower and less certain, and the leak is invisible without an explicit test — hence the "released on exit" case in the suite. **Ordering is load-bearing there:** `KillAllChannels()` queues those `UNLISTEN` frames and the client's frame loop completes the remote pipeline as soon as it sees `Finished`, so the flag is now set *after* the kill, not before.
- **Over WinRM the port survives the disconnect, because the client is killed before it can say anything.** `ssh` *TerminateProcesses* its ProxyCommand on exit (`ssh_kill_proxy_command`), so `pwssh-connect.ps1` never reaches its cleanup: the `UNLISTEN` is never delivered, `$inColl.Complete()` never runs, and the remote pipeline never ends. Verified directly — with `-LogFile` on the ProxyCommand the log stops at "session established" and never reaches "engine finished". So **every** connection leaves an orphaned shell, which is why 16 of them had accumulated on the test remote. Measured: both listener sockets still bound 30 s later, owned by a surviving `wsmprovhost`.

  What actually releases them is the **agent's own inactivity watchdog**, and that is why it now runs at 120 s with the client sending a `PING` frame every 30 s (`PwsshAgentProxy.StartKeepAlive`). The keepalive is what makes silence *mean* something: before it, silence was indistinguishable from an idle interactive session, so the timeout had to be generous — and at 300 s the watchdog would have killed a session where the user simply stopped typing for five minutes. The session's WinRM `IdleTimeout` then reclaims the shell afterwards, shortened from 180 s to 60 s for the same reason; a live client always has a WSMan receive outstanding, so it is never idle and a real session is untouched.

  Two practical consequences. Reconnecting with the same `-R` port inside that window still fails — the clean-shutdown paths (`ssh -N` killed locally, `DISCONNECT`, an engine error) release immediately, which is what the dev-host test asserts, but the ordinary `ssh host cmd` exit cannot. And **clear orphaned shells before testing `-R`**, or a leak from a previous run looks like a bug in the current one: that cost a debugging cycle when the "released on exit" probe hung for its full 180 s timeout against a listener with nothing behind it and the failure was reported as "ssh timed out". The probe now bounds every wait and reports `STILLBOUND` instead.
- **The remote cannot be told the client has gone, and this is architectural rather than an
  unturned stone.** The TCP death is known instantly — but only to HTTP.sys and the WinRM service,
  which live in other processes. Since WS-Man protocol 2.1 a shell must *survive* connection loss so
  that Disconnect/Reconnect can work, so the service deliberately absorbs the abort: the shell stays
  `Connected`, the plugin's receive operation stays open, and further output is buffered
  (`OutputBufferingMode` `Block`). The only signal the service ever sends into `wsmprovhost` is the
  per-operation `shutdownNotificationHandle`, and it signals that at shell **deletion** — i.e. at the
  idle timeout the watchdog already beats. Established three ways:

  - **Measured.** Client killed 20 s into a session; the shell's own row via
    `Get-WSManInstance -ResourceURI shell -Enumerate` (a loopback call from inside the session, which
    creates no second shell and can identify itself because the shell's `ProcessId` equals the
    agent's `$PID`) still read `State=Connected` 88 s later. `ShellInactivity` climbed at the same
    rate before and after the kill, so it means "no new shell operation", not client presence.
    `IdleTimeOut` there reports the service default `PT7200.000S`, not the 60 s the client requests.
  - **Decompiled.** `System.Management.Automation.Remoting.WSMan.WSManServerChannelEvents` is public
    and static with `ShuttingDown` and `ActiveSessionsChanged`, and handlers attach fine from inside a
    session — but an IL scan of 5.1's own SMA finds **exactly three** raiser call sites, matching
    PS Core master with no divergence: shell *added*, shell *deleted* (and only when
    `!context.isReceiveOperation`), and plugin *unloaded* by the service. **None can fire on client
    death.** A probe confirmed neither fired in the 60 s after a kill; the decompile proves that was
    not a timing artefact. `ActiveSessionsChangedEventArgs` has one member, `Int32
    ActiveSessionsCount` — it counts sessions the *host* serves, which is 1 in a per-shell
    `wsmprovhost`.
  - **In the open source.** `pwrshplugin` (github.com/PowerShell/PowerShell-Native) is pure
    marshaling; the WSMan plugin ABI has no disconnect or client-connectivity callback at all, only
    that per-operation shutdown handle.

  **Write-side detection does not work either, and this explains the pump-blocked symptom above.**
  The output path is synchronous from the emitting thread through `SendDataToClient` into native
  `WSManPluginReceiveResult`. With the client gone the service *buffers* rather than failing, so
  writes **succeed** until the buffer fills and then block the thread inside native code — no
  exception, no event, and no bounded managed queue to overflow observably. An error *would* be loud
  (`WSManTransportErrorOccured` → session teardown); it just never comes.

  Dead ends not worth re-walking: correlating the shell's `ClientIP` against the remote's TCP table
  (measured — 2 shells, 3 connections all from one address, and the connections are owned by PID 4,
  System/HTTP.sys, so there is neither a per-shell address nor a per-shell owning process; pwssh's own
  `-Streams` also opens several sessions from one client); `$PSSenderInfo`, which is static; and ETW,
  which needs admin to enable or consume. If repeating the event probes, compile the handler — these
  fire on arbitrary threads, and a scriptblock off a runspace thread throws "There is no Runspace
  available to run scripts in this thread."

- **The fix is on the client, where the death *is* instantly observable — see `src/Start-PwsshSentinel.ps1`.**
  `ssh_kill_proxy_command` TerminateProcesses its **direct child only**, so a grandchild survives. The
  sentinel is that grandchild: it waits on a handle to the ProxyCommand (a kernel wait, not a poll,
  so it costs nothing while idle) and on release deletes the shell with `Remove-WSManInstance` — the
  same cleanup this file already documents, just performed two minutes earlier. The service reacts to
  the delete by signalling the shell operation's shutdown handle, which tears the session down
  properly, so job objects reap the children and the `-R` sockets and NTFS locks go with them.
  **Measured: shell gone 1.3 s after the kill against the watchdog's 120 s** — parent exit observed
  at +0 ms, delete issued 33 ms later, completed after one 726 ms WinRM round trip.

  It needs the shell id, and the client already has it: **`PSSession.InstanceId` IS the WSMan
  `ShellId`** (verified by comparing it against what the remote reports for its own shell), so there
  is no round trip and no agent change. Two limits: it needs a credential it can load itself, so it
  only works with `-CredentialPath` and not an inline `-Credential`; and it cannot help when the
  client machine dies outright, which is why the watchdog stays as the backstop.

  **Do not name a parameter `-ShellId`.** `$ShellId` is a global **read-only** automatic variable
  holding `"Microsoft.PowerShell"`, so `param([string]$ShellId)` cannot bind at all — every
  invocation dies with *"Cannot overwrite variable ShellId because it is read-only or constant"*
  before a line of the body runs. Hence `-RemoteShell`.
- **`cancel-tcpip-forward` is answered immediately**, not after a round trip: a failure to unbind is not something the client can act on.
- **Global request replies are order-matched, not tagged.** RFC 4254 pairs them with requests in order, so `pendingForwards` is a FIFO and a result that arrives for a request behind the head waits its turn. ssh normally keeps one outstanding, but replying out of order would desynchronise every reply after it.
- **Windows has no privileged-port concept.** A normal user can bind port 80 if it is free, so low ports are not a failure case to design around; real bind failures are "already in use" or an excluded range (`netsh interface ipv4 show excludedportrange` — Hyper-V reserves large parts of the dynamic range). This makes loopback-by-default *more* valuable, not less: `-R 80:...` from an unprivileged remote account can genuinely succeed.

Measured: 512 KiB through a reverse forward is bit-exact, in ~1.1 s on loopback.

### SFTP subsystem

`sftp` works, and so does **`scp`** — which had no working path at all before, because scp 9.x speaks SFTP and its `-O` fallback needs `scp.exe` on the remote, exactly what a pwssh target does not have. `scp`, `scp -r` and `scp -p` all work over this subsystem with no scp-specific code. The `-O` fallback, and every client that is not OpenSSH 9.x, take a different route entirely — see *The legacy scp protocol*.

The server is **version 3, implemented in the agent** (`AgentSftpChannel`), reached through a `subsystem` channel request and one new frame, `SUBSYSTEM` (0x0F). Everything else reuses the existing channel frames: an SFTP subsystem is exactly a bidirectional byte stream that ends in an exit status, which `DATA`/`OUT`/`EOF`/`CLOSE`/`WINDOW`/`EXIT`/`DONE` already carry.

**The conventions were measured, not guessed.** Windows ships `C:\Windows\System32\OpenSSH\sftp-server.exe` even where no sshd runs, and `sftp -D <path>` drives it over a pipe with no SSH in the loop, which makes the reference implementation directly observable. That settled: version 3; paths as `/C:/Users/kb` (leading slash, drive *with* colon, forward slashes); `/` as a virtual root listing drive letters; ATTRS flags always `0x0f` with uid/gid 0; `realpath` **not** requiring the path to exist; and the `longname` shape. Worth re-running that probe before changing any of it.

Four findings that shaped the implementation:

- **`limits@openssh.com` is the highest-value part of the feature.** The client raises its transfer buffer to whatever we advertise — `server upload/download buffer sizes 65536 / 261120; using 65536 / 261120` — against a 32 KiB default. That is an 8× cut in round trips. **An explicit `sftp -B` suppresses the scaling**, so the advice is the counter-intuitive "do not pass `-B`".
- **Never answer a `READ` short.** The reference answered a 261120-byte request with 102400 bytes; the client logged `Short data block, re-requesting` and then *permanently* dropped its request size for the rest of the session. `DoRead` loops until the request is satisfied or the file genuinely ends.
- **Read and write limits are deliberately asymmetric** (255 KiB / 64 KiB). Upstream is byte-rate limited, so 64 × 64 KiB is already ~10× the bandwidth-delay product and bigger writes buy nothing; and the client's outbound frame queue is FIFO *across channels*, so a 16 MiB upload backlog would head-of-line-block keystrokes on a shell channel sharing the connection. It also keeps upload frames at 64 KiB, the largest payload the transport carried before this.
- **`READDIR` cannot be pipelined** — the handle is a cursor, so the client issues them one at a time. The reference needed **58 sequential round trips** to list System32's 5,604 entries, i.e. ~40 s. `READDIR_BATCH_BYTES` packs each reply to ~200 KiB instead of the conventional ~100 entries, bringing the same listing down to a handful. 200 rather than 256 KiB because the client's cap is *inferred* from the reference's advertised max-packet, and overshooting it is a hard client abort rather than a degradation.

Implementation points that are easy to get wrong:

- **Reparse points are reported as `S_IFLNK` in `LSTAT`/`READDIR`, and the reference gets this wrong.** `C:\Users\All Users` is a *symlink* to `C:\ProgramData` (`C:\Users\Default User` is the junction) and `AppData\Local\Application Data` points at its own parent, so a client that sees them as plain directories recurses forever on `get -r`. `STAT` follows and `LSTAT` does not — they are **not** interchangeable. See *Symlinks* below for how each is now implemented.
- **Deferred times.** `scp -p` sends `FSETSTAT` on a still-open handle, and NTFS updates last-write when the handle's dirty data flushes — after the timestamp was set. Windows is believed to suppress that for a handle whose time was set explicitly, but rather than depend on unverified filesystem behaviour the times are recorded on the handle and applied **by path after `Dispose()`**.
- **`SETSTAT` must not fail on permissions.** The client sends the local file's mode in `OPEN` attrs on *every* `put`. Only the owner-write bit has anywhere to go (`FILE_ATTRIBUTE_READONLY`); the rest is accepted and dropped, and the reply is `OK`.
- **`MoveFileEx`, not `File.Move`** — 4.8 has no overwrite overload. Plain `RENAME` uses `COPY_ALLOWED` only and reports failure when the target exists (the v3 semantic); `posix-rename@openssh.com` adds `REPLACE_EXISTING`.
- **Every request produces exactly one reply**, enforced by a catch-all that turns any exception into a `STATUS`. A dropped reply is not an error the client can see: it waits until its own timeout, which on this link is indistinguishable from ordinary slowness. `SftpEnabled`-style staging exists for the same reason — during development, accepting the subsystem before it could answer produced exactly that hang.
- **Modes are `0644`/`0755`**, not the reference's `0600`/`0700`, so that `scp -p` onto a Linux box does not land everything mode 600. A judgement call, and commented as one. Never derived from ACLs: a per-entry lookup during a 5,600-entry readdir is unaffordable.
- **`SetErrorMode(SEM_FAILCRITICALERRORS)`** once per process, and the virtual root does not stat the drives it lists — the reference does not either. Reaching an empty card reader otherwise raises the "no disk" dialog, which in a session with no desktop means the call blocks.
- **Handle ids are never reused**, so a stale handle gets `FAILURE` instead of silently addressing a different file. Handles are disposed in three places (`CLOSE`, the worker's `finally`, `Kill`) because a leaked `FileStream` holds an NTFS lock until `wsmprovhost` exits — worse than a leaked port, since the user's next attempt fails on their own file.

#### Disk free space (`statvfs@openssh.com`)

`sftp`'s `df` works, along with `df -h` and `df -i`. Both halves of the documented pair are implemented — `statvfs@openssh.com` takes a path, `fstatvfs@openssh.com` takes a handle — even though no CLI command sends the second; answering half of a pair is an odd thing to advertise, and it cost five lines.

**Advertised at `"2"`, not `"1"`.** The client compares the value against `"2"` *exactly* before it will use either extension, so `"1"` reads to it as no support at all — and the symptom is the same `Server does not support statvfs@openssh.com extension` you get from advertising nothing, against a server that implements it perfectly. Asserted in the suite for that reason.

**This is the first SFTP feature here with no reference server to copy.** Every other convention in this section was settled by driving `C:\Windows\System32\OpenSSH\sftp-server.exe` over a pipe with `sftp -D`. That does not work here: the Microsoft port compiles statvfs under `HAVE_STATVFS`, which Windows does not have, so their server does not implement it either. The format therefore comes from OpenSSH's `PROTOCOL`, and the numbers are checked against `DriveInfo` — a weaker oracle, and the test says so, because `DriveInfo` is `GetDiskFreeSpaceEx` underneath and so shares its source.

| field | source |
|---|---|
| `f_bsize`, `f_frsize` | `GetDiskFreeSpaceW`: sectors-per-cluster × bytes-per-sector |
| `f_blocks` | `GetDiskFreeSpaceExW` `TotalNumberOfBytes` ÷ frsize |
| `f_bfree` | `TotalNumberOfFreeBytes` ÷ frsize, **clamped** |
| `f_bavail` | `FreeBytesAvailableToCaller` ÷ frsize |
| `f_files`, `f_ffree`, `f_favail` | 0 |
| `f_fsid` | volume serial |
| `f_flag` | `ST_RDONLY` from `FILE_READ_ONLY_VOLUME`, `ST_NOSUID` always |
| `f_namemax` | `lpMaximumComponentLength`, 255 |

**`f_bfree` is clamped to `f_blocks`, and without it a quota'd volume prints garbage.** `GetDiskFreeSpaceEx` reports its *total* as what the calling user may use — quota-limited — while its *free* figure is the whole disk and is not. Left alone, a small quota on a mostly-empty volume gives `f_bfree` above `f_blocks`, and the client computes Used as `f_blocks - f_bfree` in unsigned 64-bit, which underflows to an astronomical number rather than erroring. Quotas turn up on managed domain machines, i.e. exactly this project's population. Neither test machine has one, so the clamp is reasoned rather than demonstrated; it costs nothing on an unquota'd volume. Note the consequence that remains: **`f_blocks` is the caller's quota'd total, not the filesystem size** POSIX means. That is the only figure this API family offers.

**Inode counts are zero, and that is the honest answer rather than a shortcut.** Windows has no inode concept; the nearest thing is the MFT record count, which is NTFS-only and needs a raw volume handle — admin on the remote, so out of scope on principle. Zero is what POSIX means by *unknown* and what Linux btrfs actually reports, so any client that copes with an ordinary btrfs server copes with this. Confirmed in OpenSSH at both `V_9_5_P1` and `V_9_7_P1`: `do_df` guards the division and prints `ERR` in the capacity column. The suite asserts that `ERR` against the running binary, because a division by zero would kill the user's client rather than print a wrong number.

**Exactly eleven fields, and the strictness is one-directional.** `get_decode_statvfs` calls `fatal_fr()` on a field it cannot read — so a reply one field short *kills the user's `sftp.exe`* rather than reporting an error — while it ignores anything trailing. The frame-level parser in the tests therefore refuses a reply with trailing bytes as well as a short one.

**Geometry from `GetDiskFreeSpaceW`, every byte count from the `Ex` form.** That call also reports cluster *counts*, and they must not be used: they are `DWORD`s, so they overflow on a large enough volume, and they are quota-adjusted as well. Sectors-per-cluster × bytes-per-sector is immune to both. If it fails outright the block size falls back to **1**, which keeps the capacity figures exact while claiming nothing about allocation — a judgement call, and it also guarantees the division is never by zero.

**The `\\?\` prefix is carried through all four calls rather than stripped**, so `Win32Fs` keeps one path convention and the existing suite exercises the extended route. Probed rather than assumed: `C:\` against `\\?\C:\` for all three volume queries, on this client and on the net48 remote, byte-identical every time. `GetVolumePathNameW` returns a *prefixed* root for prefixed input, which is what makes that matter.

Two more things about `GetVolumePathNameW`. Its output buffer is sized from the *input*, not fixed at `MAX_PATH`: one character short and the call **succeeds** but drops the trailing backslash, which `GetVolumeInformationW` then rejects; anything shorter fails outright. And it **succeeds on a path that does not exist**, handing back the root — measured, `\\?\C:\no-such-dir-xyz\deeper` → `\\?\C:\` — which is why `DoStatVfs` stats the path first. Without that, `df` on a typo would confidently describe the volume.

**`f_namemax` is 255, and that is not a contradiction of the long-path work.** `LongPathsEnabled` and the `\\?\` prefix raise the limit on a whole *path*; the limit on a single *component* is unchanged.

**`DoFStatVfs` deliberately omits the `h.File == null` guard** that every other handle-taking request uses. Those all read or write bytes; this one does not, and a directory is a perfectly ordinary thing to ask which filesystem it is on. Inheriting that line by copying the request next door is the bug the directory-handle test exists to catch.

**`df /` is refused, and the user sees nothing at all.** `/` here is a listing of drive letters the server invents rather than a filesystem, so there are no honest numbers for it. The refusal is a choice rather than a necessity — the client's guard means a reply of zeroes would print `ERR` — but a fabricated table is worse than a failure. The sharp edge, found by the suite rather than by reading: **`do_df` calls `sftp_statvfs` with `quiet=1`**, so a server-side failure status prints *nothing*, and the message the server takes care to word is never shown to an `sftp` user. It does reach a library client and `-vvv`. What the suite pins instead is the batch behaviour — unprefixed, the failure aborts the run before the next command; with `-`, everything after it still works.

**A `df` mid-session discards the read-ahead's held metadata**, because `EXTENDED` lands in `PwsshSftpReadAhead`'s catch-all invalidation. Left alone deliberately: `posix-rename` and `fsync` are `EXTENDED` too and genuinely do change things, so the type cannot be exempted wholesale — it would have to be exempted by *name*, which means parsing the name in the path every bulk transfer goes through, to save a couple of round trips on a command a user types once.

#### Symlinks, and the elevation claim that was wrong

`ln -s` works over both transports, and `READLINK` resolves the reparse points Windows ships. What used to be here said creating a symlink "needs elevation on Windows, which this project does not use anywhere" — **that was wrong, and the error mattered**, because it made the feature look impossible under the *No remote configuration* rule when in fact the common deployment already satisfies it. Creating one needs any **one** of:

1. `SeCreateSymbolicLinkPrivilege` in a **non-restricted** token. An administrator gets a UAC-filtered token when logging on interactively, but PowerShell remoting normally does not hand one out — so over WinRM, which is this project's entire deployment, an admin's token typically already carries it. Precisely: that holds for **domain** accounts; a **local** account over the network is still filtered unless `LocalAccountTokenFilterPolicy=1`, and a non-admin never holds the privilege at all.
2. Group policy configured not to strip the privilege from the restricted token.
3. **Developer Mode** on, plus `SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE` (0x2), Windows 10 build 14972 or later.

None of the three requires configuring the remote, so nothing here trades against the footprint rule.

**Both live routes are covered, one per transport, and that is why the flag is not redundant.** This client machine runs the tests under a filtered token — `whoami /priv` does not list the privilege at all — and Developer Mode is on, so loopback creation **can only** be route 3. The WinRM remote's token holds the privilege (measured, and *Enabled*), so route 1 alone would carry it. The flag is passed on both, so a single call cannot be attributed; what is falsifiable is the counterfactual — **remove the `0x2` flag and loopback fails while WinRM stays green.** That asymmetry is the whole reason to run the suite on both transports for this feature.

The flag is passed first and dropped **only on `ERROR_INVALID_PARAMETER` (87)**, which is how builds older than 14972 reject it — in parameter validation, before touching the filesystem. A blanket retry would risk a second attempt against a half-created name, and the fallback is the mainline for this project's demographic rather than garnish: net48 is the floor precisely because the targets are old.

**`CreateSymbolicLinkW` returns `BOOLEAN` — one byte, not `BOOL`.** `[return: MarshalAs(UnmanagedType.U1)]` is mandatory; copying the `CreateHardLinkW` import beside it gives a 4-byte read of a 1-byte return with undefined upper bytes, i.e. a success check that is intermittently wrong. Nothing about that fails loudly.

**OpenSSH sends `SSH_FXP_SYMLINK` with its arguments reversed relative to the draft** — **target first, link second**. Confirmed from primary evidence twice: `sftp-server.exe` carries `symlink old "%s" new "%s"` and `sftp.exe` carries `Sending SSH2_FXP_SYMLINK "%s" to "%s"`. Getting it wrong is **silent** — the link is created under the wrong name and nothing errors — which is why the argument order is pinned by a test that needs no privilege and creates nothing: because `Win32Fs.Error` appends the *link* path, a `SYMLINK` into a directory that does not exist must name the link in its failure message and not the target.

Implementation points:

- **The target does not go through `ToWindows`, and must not.** `ToWindows` resolves anything relative against `USERPROFILE` and `Normalize` upper-cases the drive and trims trailing dots — all correct for a path being opened, all wrong for a string being *stored*. Absolute targets map; relative ones keep their text with separators converted only. The target is never `Extended()`ed either: a `\\?\` visible in the `PrintName` is a mark left on a machine we promise to leave unchanged.
- **Windows types the link at creation** (file or directory), so the target is probed first — and **the probe path must go through `Normalize` before `TryGetInfo`**. `TryGetInfo` prefixes with `\\?\`, under which a `..` segment is looked up as a directory with that literal name rather than resolved, so `parent + "\\..\\x"` always probes as absent, falls through to the dangling heuristic, and a link to an existing **directory** is created file-typed — which on Windows does not traverse. The obvious relative test case points at a *file* and passes while this is broken, so the suite has a relative-target-to-a-directory case specifically.
- **`READLINK` prefers `SubstituteName`**, falling back to `PrintName` when its length is zero: it is what the filesystem actually follows, and `PrintName` is empty for volume mount points. The reparse buffer is parsed with `BitConverter` at explicit offsets rather than a `[StructLayout]` struct — there is no fixed-size array to justify marshalling, and **the two tags put the two names at different offsets**: `PathBuffer` starts at 20 for a symlink (`0xA000000C`, `Flags` at 16 carrying `SYMLINK_FLAG_RELATIVE`) and at 16 for a junction (`0xA0000003`). Index by offset, never by assumption. Every offset is validated against `ReparseDataLength` before slicing.
- **A relative target comes back with no leading slash**, because `ToSftp` would prepend one and turn it absolute. Drive-rooted targets go through `ToSftp`; anything else (`Volume{…}`, UNC) has its separators converted and is reported honestly rather than refused.
- **1314 `ERROR_PRIVILEGE_NOT_HELD` maps to `PERMISSION_DENIED`, not `OP_UNSUPPORTED`.** It is morally `EPERM` and it is what OpenSSH maps it to; `OP_UNSUPPORTED` would be a claim about the operation when it is this token that is unentitled, and it invites clients to stop asking. The message names all three routes and deliberately does **not** say "elevation" — that is the myth being corrected, and it sends users somewhere that does not help. 4390 `ERROR_NOT_A_REPARSE_POINT` maps to `FAILURE`, matching `EINVAL`.
- **`AdjustTokenPrivileges` was measured to be unnecessary and is therefore not written.** `kernelbase!CreateSymbolicLinkW` acquires the privilege itself via `RtlAcquirePrivilege`, which is why `mklink` works from a shell whose token shows it merely *Disabled*; confirmed on the remote before any token code existed. Writing it would also not have rescued the loopback case, where the privilege is **absent** rather than disabled.

**`STAT` follows links; `LSTAT` does not.** `GetFileAttributesExW` does not traverse, so `STAT` used to report the link's own size and merely suppress the link bit — wrong the moment a link could exist, since `ls -l` and a download's progress meter both read from it and a directory link reports size zero. Reparse points are now re-stated through a handle opened *without* `FILE_FLAG_OPEN_REPARSE_POINT`, using `GetFileInformationByHandle`; only reparse points pay for the second call. Two flags on that handle are load-bearing rather than incidental: **`FILE_FLAG_BACKUP_SEMANTICS`**, because `CreateFileW` refuses to open a directory without it and `STAT` would start erroring on every junction on the machine; and **`FILE_READ_ATTRIBUTES` rather than `GENERIC_READ`**, because cloud placeholders are reparse points too and a read request would recall their contents over the network. `LSTAT` is deliberately unchanged — its link bit is the junction-recursion protection.

Both directions of that are visible from the real client, and asserted: `ls -l <dir>` goes through `READDIR` (LSTAT semantics) and shows the link as a link, while `ls -l <link>` goes through `STAT` and reports the target's type and size.

Three consequences, all correct and all documented rather than treated as regressions:

- **A dangling link's `STAT` now reports `NO_SUCH_FILE`**, as POSIX `stat` does.
- **A reparse tag whose target cannot be opened** — a WSL symlink (`0xA000001D`), an `AppExecLink` — now errors where it used to return the link's own attributes. The read-ahead survives both, because `OnMetaData` already holds and replays `STATUS` as well as `ATTRS`.
- **`READLINK` refuses tags that carry no path**, with `FAILURE` naming the tag, while `LSTAT` still reports every reparse point as `S_IFLNK`. That asymmetry is real and deliberate: narrowing the link bit to match is what would restart the `get -r` recursion.

Two adjacent warts were fixed in the same work, both of which this feature would otherwise have created:

- **`rm` on a directory link.** `DoRemove` refused anything carrying `FILE_ATTRIBUTE_DIRECTORY`, which a directory symlink or junction has — so `rm link` failed and only `rmdir link` worked, the opposite of POSIX. `RemoveDirectoryW` is used when `IsDirectory && IsReparsePoint`; on a name surrogate it deletes the link only, never the target, and is never recursive, so "rmdir means rmdir" still holds.
- **`lsetstat@openssh.com` now means what its name says**, taking `FILE_FLAG_OPEN_REPARSE_POINT` through to `SetTimesUtc` and skipping the size branch for a reparse point. Almost nothing sends it; the reason to do it is that its old comment became actively false the moment links existed.

**Documented, not fixed**, all pre-existing and all newly *visible* once links exist:

- `Normalize` pops `..` lexically, before any link resolution, where POSIX resolves after — so `get link/../x` addresses the link's lexical sibling. That matches Windows' own non-`\\?\` semantics and is not cheaply fixable.
- `DoRealPath` stays purely lexical and never resolves links.
- `SETSTAT` on a symlink follows for size and times but never for the read-only bit, because `SetFileAttributesW` does not traverse, where POSIX `chmod` follows.
- `get -r` and `scp -r` still skip links, because recursion keys on `READDIR`'s LSTAT-semantics attributes — which is the junction-recursion protection working as designed.

**Not done, deliberately**: advertising an extension for any of this (links are core v3, and the reference advertises nothing for them), and printing `-> target` in `READDIR` longnames (the reference does not, and it would cost a `CreateFile` plus a `DeviceIoControl` per entry in the hottest path in the server — the same one that already refuses per-entry ACL lookups).

#### Measured, and the one thing that is not fixable from here

All bit-exact, including 0, 1, and ±1 around every chunk boundary. Same compressible payload over both paths, same session:

| 8 MiB download | | 32 MiB download | |
|---|---|---|---|
| `exec` | 1.55 MiB/s | `exec` | 6.76 MiB/s |
| `sftp`, no read-ahead | 0.49 MiB/s | `sftp`, no read-ahead | 2.22 MiB/s |
| `sftp`, default depth 64 | 0.76 MiB/s | `sftp`, default depth 64 | 3.29 MiB/s |

Upload measured **0.35 MiB/s**, which is the transport's upstream ceiling — uploads are already optimal and no design change would help them.

**Putting SFTP in the agent used to be paid for by `ssh host whoami` as well**, because the remote recompiled the agent source on every connection with no cache. Measured at the time, since it was the strongest argument against the agent-side design: the agent grew 54% (2,356 → 3,627 lines) and connection setup went from a **3,663 ms** median to **3,875 ms**, about 210 ms. That whole objection is now gone — the agent is a prebuilt assembly and the remote compiles nothing, which took connect to **3,412 ms**, i.e. faster than before SFTP was written. Kept here because it is the measurement that motivated the build step.

Downloads *were* **round-trip-bound, not bandwidth-bound** — this is the diagnosis that motivated the read-ahead below, kept because it is what the numbers in the table above are measuring. The evidence was unambiguous: compressible and incompressible 8 MiB downloads measured 0.49 and 0.43 MiB/s, a 1.14× ratio where `exec` shows 4.5×; and 32 MiB costs only 2.7 s more than 2 MiB, i.e. 16× the data for a quarter more time. The cause is the client's request ramp — **`num_requests` starts at 1 and grows by one per reply**, so moving *C* chunks costs about √(2C) round trips before the window is deep enough to matter, plus a fixed ~4 round trips per file for the client's `LSTAT`, `STAT`, `OPEN` and `CLOSE`. At ~0.85 s per trip that is the ~11 s of fixed cost the table shows.

**None of it can be fixed on the *server* side** — the pacing is inside the client. It can be fixed on the client side, and now is: see *SFTP read-ahead* immediately below. The ramp is gone; the four fixed round trips per file remain, deliberately.

#### SFTP read-ahead (`-SftpReadAheadChunks`, default 64)

The engine opens a **second, private SFTP subsystem channel** to the agent and reads ahead on that, answering the client's `READ`s from a local buffer. The client's own channel stays byte-verbatim apart from the reads that are suppressed because they were answered locally.

Why a private channel rather than injecting requests into the client's stream — the design that looks obvious and is wrong. `strings` on the real `sftp.exe` yields **`Unable to resume download of "%s": server reordered requests`**: the client detects an out-of-order server and abandons the transfer. Alongside `Can't find request for ID %u` and `Received more data than asked for`, that makes an injected id space a silent-hang risk rather than a tidy optimisation. A private channel gives a disjoint id space by construction, its own agent worker thread, its own credit pool, and no bytes ever added to the client's stream — which is what makes the safety valve **a flag flip at any instant**: leftover replies land where the client cannot see them. The client→agent stream is also not message-aligned (one `CHANNEL_DATA` is one `DATA` frame, which is why the agent has a reassembler at all), so injected bytes would splice into the middle of a client message.

Measured, interleaved, medians — depth is the whole story and the bandwidth-delay arithmetic that suggested 16 was simply wrong:

| 32 MiB compressible | | |
|---|---|---|
| read-ahead off | 2.31 MiB/s | — |
| depth 16 | 2.32 | 0.97× |
| depth 32 | 2.89 | 1.20× |
| **depth 64** | **3.29** | **1.42×** |
| depth 128 | 3.05 | 1.32× |

**Depth 128 turns back down for a reason worth keeping**: 128 × 261120 is 33.4 MB, just past the agent's 32 MiB credit (`InitialCredit`, `-CreditMiB`), so the far side blocks on window instead of reading. Past the credit there is nothing to buy, which is why `SftpReadAhead.MAX_DEPTH` clamps at 128 — a ceiling on nonsense, not a tuning value. That clamp exists because a **misparsed depth of 326,496 built a single 10.6 MB request frame and WinRM rejected the object outright** (*"deserialized object size … exceeded the allowed maximum"*), killing the pipeline mid-download. Reproducible, and it would have been reachable by anyone typing a large number.

At 8 MiB the same change is only **1.17×** (0.65 → 0.76), and incompressible 8 MiB does not move at all (0.48 → 0.53, with the paired rounds disagreeing in direction — noise, and expected, since that case is already at the downstream ceiling). The reason 8 MiB gains so little is arithmetic: ~3.4 s of connect plus ~3.4 s of the four fixed per-file round trips is ~6.8 s of an ~11 s transfer, and read-ahead cannot touch either. **Quote the 32 MiB figure; the 8 MiB one is mostly fixed cost.**

**Per-file round trips dominate anything that is not one large file**, and read-ahead never touched them: 40 files of 900 bytes each — 36 KB in total — took **~150 s** whether it was on or off (152.7 s at depth 64 against 153.8 s and 148.8 s off, on the 300 ms dev host). That is `LSTAT`/`STAT`/`OPEN`/`CLOSE` per file and nothing else. Two of those four are now removed — see *Per-file round trips* below, which takes the same case to **94 s**. It also settles a risk worth having checked: read-ahead issues up to `depth` requests before it learns where the file ends, so a small file costs ~64 requests instead of one — and it measures as **no regression**, because those requests pipeline into one frame and the fixed round trips swamp them. The plan's optional "cap the window from a passing `STAT`" was therefore left unimplemented, on measurement rather than argument.

Hit ratio is the assertion that matters, since wall-clock on this transport has inverted conclusions twice. On the 300 ms dev host an 8 MiB download reports `clientReads=34 served=34 forwarded=0 parked=1 prefetchKiB=8192 nonSeq=0 valveTrips=0` — every read answered locally, prefetched bytes exactly equal to the file, no valve trips — in 6.5 s against 10.0 s with read-ahead off (1.54×).

**The counters are logged when the client closes the file, not only at channel teardown.** `Kill()` does not run for an ordinary sftp session: ssh `TerminateProcesses` its ProxyCommand (`ssh_kill_proxy_command`), so the teardown summary was unobservable over WinRM — exactly where it is wanted. A `CLOSE` always arrives first. `Kill()` still reports when nothing else has, which covers a transfer that died part way.

Other things load-bearing enough to state:

- **The engine must never interpret a path.** The client's path string is copied byte-for-byte into our own `OPEN` and the agent does the mapping, as it does for the client. The loopback dev host **cannot** catch a violation — both sides are the same machine there — so an engine that resolved a remote path against its own drives would pass loopback and fail only over WinRM.
- **Serve strictly FIFO.** It costs nothing (the agent's worker is serial and frames arrive in order, so the buffer fills in increasing offset order and the oldest parked read is always the first to become answerable) and it deletes the `server reordered requests` failure mode outright.
- **Never answer short except at an agent-confirmed EOF.** One mid-file short reply makes the client permanently shrink its request size for the rest of the session, ~2.5×. Every other case parks or forwards.
- **A trip owes the framer's held bytes, and dropping them corrupts the stream.** This was a real corruption, seen once in a suite run and then unreproducible for a dozen attempts. The framer holds bytes it has consumed for a message that is not yet complete, and only ever forwards *whole* messages — so those held bytes are owed to the far side. `Trip` flipped the mode and `FromClient` then returned the caller's buffer verbatim for ever after, so the held bytes vanished and **every byte behind them arrived shifted**. The agent either rejected an absurd length — `bad SFTP packet length 83886080`, which is `0x05000000`: a `READ` type byte plus the top three bytes of a request id below 256, i.e. exactly a bare 4-byte length prefix having been dropped — or, when the bogus length happened to be plausible, waited for bytes that never came and the transfer hung. The hang is the more likely shape, and may be hiding in past `exit=255` "flakes".

  The invariant to hold on to: **every byte the framer consumes must reach the far side exactly once, in order.** `SftpFramer.TakeResidue` exists for that, and both passthrough shortcuts (client and agent direction) flush it ahead of the raw buffer. Draining on the *next* call rather than inside `Trip` is deliberate: `Trip` can be raised from either direction's thread, and the flush has to happen on the thread that owns the stream so it cannot race the caller's own send.

  Two things this exposed alongside it. `FlushHeld` did not flush held bytes despite its name and its call-site comment saying it must — it only rebuilt completed messages, which is how the whole class escaped notice. And a trip part way through a feed could still arm a new optimistic-`CLOSE` suppression via `Inspect`, which does not check the mode, while the reply direction had already stopped honouring them — two replies for one id, fatal to the client. `TryAnswerCloseEarly` now refuses once tripped, and the reply direction keeps suppressing until `closeAnswered` drains rather than taking the passthrough shortcut.

  **My first hypothesis was wrong and worth recording as such**: I suspected `SftpFramer` mishandled a feed boundary falling inside the 4-byte length prefix. It does not — `NeededForResidue` guards with `if (residueLen < 4) return 4 - residueLen;` before ever reading the prefix. The framer is correct; the bug was the mode transition discarding its state, one door down.

  **`PWSSH_SFTP_SPLIT_CLIENT_FEED` is what makes this testable at all.** Reproducing needed the trip *and* a held partial message; the trip is guaranteed by the fault hook, but whether a feed ends mid-message was down to how ssh happened to packetise the client's writes. Splitting each client payload forces it, and turns a once-in-a-dozen-runs corruption into a deterministic case. The valve trip now logs how many bytes each framer holds, kept permanently as a tripwire — a trip with residue is precisely the condition that used to corrupt, and it is otherwise invisible.
- **Tripping the valve must abandon the prefetch, not just flip the mode.** This was a hang waiting to happen and the fault injector found it before any user did: a read parked at the moment of the trip is waiting on data the prefetch would have delivered, and passthrough means nothing ever will. `Trip` now calls `AbandonPrefetch`, which replays those reads to the remote — safe, because a parked read was never forwarded, and the framer never forwards a partial message so the agent's stream is always at a boundary when this runs. The park deadline deliberately does **not** skip passthrough mode, because a backstop that trusts the thing it is backing up is not one.
- **`PWSSH_SFTP_FAULT_AFTER_KIB` / `-SftpFaultAfterKiB` trips the valve deliberately**, part way through a transfer. It is an environment variable as well as a parameter because that is what lets one test process exercise it: ssh spawns the ProxyCommand fresh per connection and it inherits the suite's environment, so no second `ssh_config` alias is needed. Verified at 2 MiB into an 8 MiB download — tripped at 2,295 KiB, replayed the parked read, finished **bit-exact** in 8.4 s, between the 6.5 s clean run and the 10.0 s with read-ahead off. The suite case is WinRM-only and SKIPs on loopback, because the dev host's engine runs in a process started before the test and cannot see the variable; use `-SftpFaultAfterKiB` there.
- **A parked read has a 30 s deadline**, carried on the engine's existing watchdog tick. Parking is normally a fraction of a round trip, but a lost reply would otherwise hang the client for good — SFTP has no timeout of its own. Past the deadline the read goes to the remote after all, which is always safe: a parked read was never forwarded, so the remote has not seen it.
- **Prefetch credit is released as bytes leave the buffer**, and synthesised chunks carry `Credit = 0`. Releasing the *sent* count rather than the *accrued* count drifts by 13 bytes per reply and eventually withholds the agent's window for good.
- **Credit is accounted as an absolute balance, and it has to be**, because the agent splits a reply across frames whenever its window is smaller than what is left to send (`SendPayload`: `allowed = min(count - off, credit)`). The old per-feed arithmetic — `count - retainedThisFeed`, discarded when negative — granted a non-completing fragment's whole length and then granted the completed blob again on consumption, so the surplus was permanent because nothing remembered it. `Received`/`Granted`/`Retained` live on the `Prefetch`, and `owe = Received - Granted - Retained` self-corrects: an overshooting feed grants nothing and later feeds grant correspondingly less.

  **The framer's residue is deliberately *not* withheld, and that was learned by breaking it.** Subtracting it looks obviously right — those bytes have arrived but are not progress — and it deadlocks on the spot whenever the window is smaller than one message: the client waits for the message to complete, the agent cannot send the rest of it without credit, neither moves. A 64 KiB window against 255 KiB replies hung for ten minutes before that was understood. So residue counts as progress, which lets the balance run ahead of what has arrived by at most one message — **bounded per channel, and channels are per file**. Measured at a 64 KiB window: surplus 194,475 / 194,371 / 194,163 bytes for 2 / 4 / 8 MiB, i.e. flat at ~0.74 chunks rather than growing with the transfer. Under the old accounting it grew with it.

  `creditGranted` ending **below** `creditRecv` is normal, not a fault: retirement closes the channel and the balance freezes there, so credit for bytes served afterwards is deliberately not granted — it would be an upstream WINDOW frame the agent discards. `creditRecv`/`creditGranted` in the summary are for spotting the *over*-grant direction; the unambiguous detector is agent-side, where `credit` climbing above `InitialCredit` can never happen legitimately and is logged.
- **`-CreditMiB` below 2 deadlocks, and is clamped.** A session channel announces credit only once `GRANT_THRESHOLD` (2 MiB) has accrued, so an agent window smaller than that is exhausted before the first grant is ever sent. Found by setting it to 1 during this work: a transfer that fell back to the client's own channel — which is what happens after a valve trip, or with read-ahead off — stopped dead. The prefetch channel is safe at any size because it grants immediately, which is why a 64 KiB window works there and is what the dev host's `-CreditKiB` is for; that knob is deliberately left unclamped and carries the hazard in a comment.
- **Each prefetch owns its framer.** One shared instance carried residue and a sticky `Error` from one file's channel to the next: `Feed` returns immediately once `Error` is set, so a single desync would silently disable read-ahead for the rest of the session, and an abandon part way through a split reply left a partial `DATA` that the next file's bytes appended to. Same class as the valve dropping held bytes — framer state outliving what it belonged to.
- Tripling download throughput reaches OpenSSH's ~1 GiB rekey threshold three times sooner in wall-clock. That was the argument for implementing rekeying, which is now done — see *Rekeying*.

**The chunk-alignment assumption turned out not to be load-bearing.** That the client's read offsets are multiples of 261120 was inferred from its `-vvv` output, not read from its source, and the design was built so that a wrong guess would only cost hit ratio. `sftp -B 32768` and `-B 262144` are now in the suite and both download bit-exact, so the splice path is exercised rather than assumed. `-R 1` (no client pipelining at all) is there too, as is a run with read-ahead disabled — the path a valve trip degrades *to*, which is worth having end to end because everything else is worthless if the fallback is broken.

What is **not** covered, and would need a client that behaves differently from `sftp`:

- ~~**A true mid-transfer backwards seek**~~ — **now covered**, by `tests/Pwssh.Tests` driving SSH.NET's `SftpFileStream.Seek`; see *The SSH.NET test project*. The entry used to say the `nonSequential` counter "and the 3-restart thrash limit" were untested. **There is no 3-restart thrash limit** — `grep` for `thrash|restart|MAX_RESTART` across `src/*.cs` and `src/agent/*.cs` finds nothing, and never did. The actual behaviour is simpler: a read below `BufStart` increments `nonSequential` and calls `AbandonPrefetch` **once**, closing the private channel, replaying anything parked and setting `active = null`. It does *not* flip the channel to passthrough, so a later file in the same session still gets a fresh prefetch — which is now asserted rather than assumed.
- **Two files prefetching at once.** Still only one prefetch fetches at a time by design — `sftp` and `scp -r` read one file after another. Genuine concurrent handles do not arise from the CLI, but SSH.NET can hold two open, and that case is now tested: a second `OPEN` arriving while a finished buffer is still held drops the buffer and starts the new prefetch, which is what keeps the many-small-files case from losing its read-ahead.
- **A single transfer exceeding the credit pool** has no dedicated case, but the depth sweep crossed that boundary in anger: depth 128 asks for 33.4 MB against a 32 MiB credit and completed bit-exact twice, which is the condition the credit-deadlock worry was about.

#### A finished prefetch keeps serving its buffer

Found by the SSH.NET tests, and the first genuinely new thing they turned up. The retirement at the tail of `HandlePrefetchReply` — `if ((p.Eof || p.Failed) && p.Outstanding <= 0)` — used to close the remote handle and channel **and** set `active = null`. Nothing checked whether the buffer still held bytes the client had not read, and `TryServeRead` refuses the moment `active` is null, so every remaining read was forwarded to the remote and those bytes were fetched a second time.

Measured on an 8 MiB file read in 128 KiB increments, default depth, zero-latency loopback: **`served=18 forwarded=111 prefetchKiB=8192`** — the whole file prefetched, six sevenths re-fetched, and no counter flagging it. After the fix the same case is **`served=131 forwarded=0 servedKiB=8192 unreadKiB=0`**: every read answered from one fetch.

**Measured as wall-clock too, on the case that suffered.** `sftp -B 32768` makes the stock client read in 32 KiB increments, which is exactly the shape that used to lose its buffer, so it needs no library to reproduce. Interleaved over three rounds against the dev host at 20 ms injected latency, 8 MiB, the fix winning every round: **1,017 ms before against 861 ms after, i.e. 1.18×**. Do not scale that number up carelessly — 20 ms is a fraction of WinRM's 600–900 ms round trip, and what the fix removes is *round trips* (111 forwarded reads down to 0), so the saving grows with the link's latency rather than staying a fixed ratio. The stock client at its default buffer size shows no change at all, because at 255 KiB per read it kept pace with the prefetch and never had the problem.

Depth does not bound the buffer — `SftpReadAheadChunks` bounds *outstanding requests*, so the prefetch keeps issuing until the file runs out. The agent's credit is the real bound, 32 MiB by default, and it is unchanged by this: what changed is that the buffer is now held until the client's `CLOSE` rather than freed at EOF. Peak is the same, duration is longer. In *pinned* bytes it is roughly twice the accounted figure, because `Segment.Data` holds whole inbound frames by reference and a partly consumed head segment pins its entire frame — true before as well, just for less time.

**The channel is still closed at EOF**, which is the part not to "simplify" later: the agent frees a channel's handles inside `Kill()` on its serial inbound frame loop, so closing there is what stops a client that downloads a file and immediately uploads over it from racing our teardown. Only the buffer outlives the fetch. `Prefetch.ChannelClosed` marks that state, and it is the one state in which a non-null `active` means "a buffer" rather than "a fetch".

**The worse half of the same bug was a hang, and it was not hypothetical.** Retirement runs from inside `OnPrefetchData`'s per-message loop; nulling `active` there made the loop break and skipped the `DrainWaiting` after it. `FinishPrefetch` never replayed parked reads — only `AbandonPrefetch` did — and `CheckParkDeadline` reads `active`, so the 30 s backstop could not see the orphaned prefetch either. **A read parked at that instant was never answered and never forwarded, and SFTP has no timeout: the client waited for ever.** Reproduced at `SftpReadAheadChunks = 1`: `clientReads=19 served=15 forwarded=0 servedKiB=959` of 1024 — four reads unanswered, 65 KiB never delivered, and SSH.NET timed out after 48 s. Retirement now drains, then replays anything left, before releasing anything.

**The dominant trigger was `p.Failed`, not EOF**, and at any depth: a non-OK STATUS stops `Refill`, `Outstanding` drains over the in-flight replies, and the last one retires with reads still parked. At depth ≥ 2 on the EOF path the reply that proves EOF leaves `Outstanding > 0`, so the drain always ran first — which is why this stayed invisible. A failed prefetch is now retired *fully* (buffer discarded, `active` cleared), since `TryServeRead` refuses on `Failed` and its buffer would serve nobody. The `Failed` entry point has no dedicated test: it needs a fault hook the agent does not have, and the replay code it depends on is what the depth-one case exercises.

Three consequences worth knowing:

- **`unreadKiB` is in the summary** because the fix removes the `forwarded` signal that made the old waste visible and replaces it with a quieter one — fetching up to the whole credit and dropping it. Small values are normal (the prefetch reads in 255 KiB chunks and files rarely end on one); a figure near the file size means the client stopped early. Accounted in `AbandonPrefetch`, the single funnel every drop passes through.
- **The client's view of where the file ends is frozen** at the moment our prefetch proved it, for as long as it holds the handle, so a `get` of a file being appended to reads short. The EOF shortcut that does this went from near-dead code to always live. Avoiding it costs a forwarded round trip per file — the one the metadata speculation was built to remove — and a real server racing a writer gives no better guarantee.
- **Credit freezes at `ChannelClosed`** rather than being released onward. Releasing would be arithmetically fine and land on a dead channel the agent ignores, but each grant is an upstream WINDOW frame on the scarce direction, ~130 of them for a full buffer. So `creditGranted` legitimately ends below `creditRecv`; the direction that matters is the other one, and `ReleasePrefetchCredit` now takes its prefetch as a parameter so a stale `active` cannot make it over-grant on a *live* channel.

### Per-file round trips (`LSTAT`/`STAT` speculation and early `CLOSE`)

Measured with `sftp -vvv` rather than inferred, the client spends ~5 round trips per file:

```
LSTAT  →  STAT  →  OPEN  →  (data)  →  CLOSE
```

Two of those are now free, taking 40 files of 900 bytes from **~150 s to 94 s** on the 300 ms dev host — a 1.59×, in the case that was by far the worst.

**Speculative metadata is a parallel fetch, not a cache.** On the client's first `LSTAT`/`STAT` for a path the engine forwards it untouched *and* asks the remote the other question on a channel of its own. The speculative request leaves at essentially the moment the client's own would have, so the answer is at most one round trip staler than what the client would have received, and nothing is held across an operation that could change it. Metadata is **never synthesised**: the client gets the remote's own answer to a byte-identical request with only the **4-byte request id patched**, because re-encoding an ATTRS payload could corrupt it and patching four bytes cannot.

**`LSTAT` and `STAT` are not interchangeable** — `DoStat`'s `followLinks` — and a client that sees a junction as a directory recurses for ever. That is exactly why this issues a real second request rather than reusing the first reply, and why the held answers are keyed on *(type, path)* so a `STAT` can only ever be answered by a `STAT`.

**The first attempt measured 80 speculations and zero hits**, and the miss trace said why: **a globbed get does not interleave one file's requests with the next.** It `LSTAT`s every match up front to expand the glob, and only then walks the files doing `STAT`, `OPEN`, reads, `CLOSE` one at a time. With a single held answer each `LSTAT` overwrote the last, so by the time `STAT(first)` arrived we held `STAT(last)`. A bounded **map** turns that glob phase — which the client pays for regardless — into preparation that makes every per-file `STAT` free.

**Invalidation granularity is load-bearing for the same reason.** A request naming one path drops only that path, because a globbed get's own per-file `OPEN` and `CLOSE` would otherwise wipe the answers prepared for every later file. Read-only requests — including `OPENDIR`, `READDIR` and `REALPATH`, which a glob and a session start use — drop nothing. Everything else, known or not, drops the lot.

**Early `CLOSE`** answers a read handle's close at once while still forwarding it, so the remote frees the `FileStream`. Only handles seen to be opened **read-only** qualify: a write handle's close is where an upload commits, and reporting that early could tell the client a transfer worked when it did not.

The sharp edge there is that **the remote's own reply must be dropped**, or the client gets two replies for one id and hits `Can't find request for ID`. That is the one thing in this change that touches the bulk download path, so it keeps a zero-copy fast path (a feed is normally exactly one SFTP message, because the agent sends one frame per reply) and only rebuilds while a suppression is owed. **Rebuild mode is entered only on a message boundary**, since switching part way through a half-received message would either duplicate or lose the bytes it straddles.

**A prefetch is torn down with `CloseChannel`, not an EOF frame, and that is an ordering guarantee rather than tidiness.** The agent frees a channel's handles inside `Kill()`, which runs on its **serial inbound frame loop**, so by the time any later frame is dispatched the prefetch's read handle is provably gone. An EOF frame instead leaves the release to that channel's *own worker thread*, which is asynchronous with the client channel's worker — so a client that downloads a file and immediately uploads over it would be racing our teardown, and `DoOpen` uses `FileShare.None` for writes.

The race was never observed, and could not easily be: at least one full round trip — the `put`'s own `STAT` — separates the two events, while the worker needs microseconds to wake and dispose. 200 get-then-put pairs on a 900-byte file, where the two are as close together as this design can put them, came back clean both before and after the change. But "the scheduler would have to starve a runnable thread for a round trip" is a weaker thing to rely on than "the frame loop already did it", and the two directions of the argument are worth keeping straight: **the abandon path was always safe by construction** (it already closed the channel), and only the EOF path was probabilistic.

The general rule this is an instance of: **the client's outbound frame queue is one FIFO across all channels** (`PwsshAgentProxy.outbound`), and the agent's `PushInbound` is serial, so anything done *inside* that loop is ordered against every later frame. Anything handed to a per-channel worker is not.

**Why the `OPEN` round trip stays**, recorded because the reason is a hazard rather than a preference:

- **Speculating it would break `put` over an existing file.** Metadata requests do not reveal direction, so an open speculated at `STAT` time would be a read handle — and `DoOpen` uses `FileShare.None` for writes, so the client's subsequent write-open would fail against it. Uploads must not be loosened to speed up downloads.
- **Answering the client's `OPEN` locally needs handle translation.** `handles` is an instance field of `AgentSftpChannel`, so handles are per-channel and one minted on a private channel is invalid on the client's. It would mean a synthetic handle rewritten in every forwarded `READ`/`FSTAT`/`CLOSE`, those routed to the private channel, and ids translated back — the id-translating proxy the read-ahead design deliberately avoided — and an open error would surface at the first `READ` instead. **Left as future work**, with that cost.

Also considered and dropped: caching attributes from `READDIR` replies. It helps only globbed gets, `READDIR` carries `LSTAT` semantics so it could not answer a `STAT` anyway, and speculation subsumes it while also helping a single-file get.

**The archive trick still beats all of this** for a large tree, and the README should keep saying so: ~3 round trips per file remain, so a 40-file tree is still on the order of a minute.

### The legacy scp protocol

`scp -O` works, and so do PuTTY's `pscp`, SSH.NET's `ScpClient`, JSch, paramiko's `SCPClient` and any OpenSSH before 9.0.

Until this existed, `scp` worked here only by accident of version. OpenSSH 9.x's `scp` speaks **SFTP**, which pwssh implements; every other client speaks the original rcp-over-ssh protocol, and for that the client execs `scp -f <path>` or `scp -t <path>` **as a remote command** — which needs an `scp` binary on the remote, exactly what a pwssh target is defined not to have. `AgentScpChannel` serves that protocol in the agent instead, so nothing is installed and nothing is spawned.

**Interception is in the `EXEC` frame** (`AgentHost.cs`), before the command is concatenated into `cmd.exe /c`. Recognition is narrow: the first token, after unquoting, must be exactly `scp`, and the flags must include `-f` or `-t`. Two guards on top of that:

- **A pending `pty-req` suppresses it.** scp clients never ask for a terminal, so a pty means a human typed `ssh -t host "scp -f x"` and should get the shell's error rather than a byte stream in their terminal.
- **An unknown flag does not fall through.** Falling back to the shell would run the remote's own `scp.exe` wherever one is installed, which puts behaviour back to depending on what the target happens to have — the thing serving this ourselves exists to avoid. The channel starts and reports the bad flag.

**Everything about the wire format was measured, not read.** `scp -f` and `scp -t` are pure stdin/stdout programs, so both halves of the reference can be driven over pipes with no SSH in the loop — the same trick `sftp -D` gave for SFTP, and worth re-running before changing any of this:

```powershell
printf '\0\0\0\0' | & 'C:\Program Files\OpenSSH\scp.exe' -f somefile
```

That yields `C0666 853 NuGet.config\n`, the raw bytes, then a trailing `\0`; `-pf` prepends `T<mtime> 0 <atime> 0\n`; `-rf` wraps entries in `D0777 0 <name>\n` … `E\n`. Driving `scp -t <dir>` the other way settles the sink. **Two of those measurements contradicted the design and are the reason this works at all:**

- **`E` at depth 0 is *accepted*, not refused** — the reference acks it and ends. Refusing would have made pwssh stricter than the implementation it clones, breaking clients for no benefit.
- **The byte after a file body is the *source's* own status**, and only then does the sink answer with its verdict. Two bytes, opposite directions. Reversing them is a mutual wait — both sides read, and it hangs.

**Every control record is acknowledged individually, including `T`.** Treating `T` and the `C` that follows it as one unit runs the whole transfer an ack behind: it works perfectly until the first error, and then reads message text as status bytes. An ack is one byte — `\0` ok, `\1` error + message + `\n`, `\2` fatal — never a bare zero, and a `\1` in reply to a `C` line means **skip: the body must not be sent** (measured: a real source then aborts rather than moving to the next file).

**The size in a `C` line is a contract.** Once it is out, exactly that many bytes must follow. If the file shrinks or a read fails part way, pad to the promised count and report the failure in the trailing status byte; truncating desynchronises everything after it, and a bit-exactness check on a single file would not notice.

**Downloads echo back the name the client asked for, not the on-disk casing.** Since 8.0 the client `fnmatch`es every incoming name against its own request and that match is **case-sensitive** — so `scp -O host:File.TXT .` opens quite happily on NTFS but is rejected as an attempted spoof if the reply says `file.txt`. Globs are expanded case-insensitively, which is what a Windows user means, and then filtered to names that *also* match case-sensitively, because a name the client did not ask for aborts the transfer rather than being skipped.

**Wildcards are expanded server-side at all**, which a real scp never does — it relies on the remote *shell* to have expanded them before scp is executed, and there is no shell in this path. Only the last component, and only `*` and `?`.

**Recursive downloads skip reparse points.** `C:\Users\All Users` is a symlink and `AppData\Local\Application Data` points at its own parent, so following them recurses until the client's own 64-level limit stops it. Same protection READDIR's LSTAT semantics give a recursive `sftp get`.

#### Measured: bulk downloads are 1.5x faster than SFTP

Source mode streams the body with **no per-chunk acknowledgement** — no request ramp, no round
trip per read. That is exactly the pathology the SFTP read-ahead exists to mitigate, and it simply
does not arise here. Interleaved, three rounds, medians, 32 MiB compressible over WinRM, every
transfer hashed (`tools/Measure-ScpVsSftp.ps1`):

| 32 MiB download | median | |
|---|---|---|
| `scp -O` | 5,559 ms | **5.76 MiB/s** |
| `sftp` (read-ahead on) | 8,495 ms | 3.77 MiB/s |

**1.53x, and the direction was consistent across all three rounds** — which matters on a link
whose run-to-run variance has inverted conclusions twice before.

**The harness's third column is not a usable ceiling, and the number it produces should be
ignored.** It runs `cmd /c type <file>`, which routes the whole payload through cmd.exe's own I/O
and measured 3.72 MiB/s — slower than either file protocol, and nothing like the 6.76 MiB/s this
file records for `exec` at 32 MiB, which was produced by a different generator. `type` is a
bottleneck in its own right, so it bounds nothing. Left in the script because a broken reference
that is labelled as broken is more useful than a missing one; do not quote it.

**Per-file cost is a different story, and the arithmetic says so before any measurement.** The `C`
record must be acknowledged before the body may flow, and that ack cannot be pipelined — a ``
there means "skip this file", so the source genuinely cannot start sending. That is 2 round trips
per file, 3 with `-p`, against SFTP's ~3. Comparable, not better. The README's advice to tar a large
tree and move one archive applies to `scp -O` exactly as it does to `sftp`.

Measured, same shape — 40 files of 900 bytes, three rounds, medians, all 40 arriving every time:

| 40 x 900 B tree | median | |
|---|---|---|
| `scp -O -r` | 49,187 ms | |
| `sftp get -r` | 54,100 ms | **1.10x** |

So a slight edge rather than the wash the arithmetic suggested, consistent in direction across all
three rounds — 1.23 s per file against 1.35 s. Not a reason to restructure anything: the archive
trick still beats both by an order of magnitude, and that advice applies to `scp -O` exactly as it
does to `sftp`.

**The first attempt at that number was nonsense, and it is worth recording why.** It reported
medians of 50,634 ms for `scp -O -r` against 4,965 ms for `sftp get -r` — a ten-fold difference
that would have been published as a decisive result. Three of its six runs had transferred **zero
files**: both variants in a round shared one destination directory, so the second landed on the
first's leftovers and failed fast, and the median duly averaged a real transfer against a failure.
What caught it was printing the file count beside each timing; without that column the number
looked clean. `tools/Measure-ScpVsSftp.ps1` now scopes the destination per round *and* per variant,
and counts a round only when the expected number of files arrived. **A timing for an incomplete
transfer is not a timing, and nothing downstream will notice on your behalf.**

#### Upload filenames are the security boundary

The names in `C` and `D` records come from the client, so sink mode is where a hostile or buggy peer could write outside the directory the user named. OpenSSH's own sink checks **empty, `/`, `.` and `..`** and stops there, because it is POSIX and has no drives, streams or backslashes to worry about. `ValidateEntryName` adds what Windows needs, and is applied to every record at every depth:

| rejected | why |
|---|---|
| empty, `.`, `..` | the CVE-2018-20685 set, and OpenSSH's whole check |
| `/` and `\` | either separator escapes or invents structure |
| `:` | drive-absolute (`C:evil`), drive-relative, **and** NTFS alternate data streams (`f.txt:stream`, `f.txt::$DATA`) — one character, three doors |
| control characters, `* ? " < > \|` | NTFS refuses most of these anyway; rejecting up front gives a better message |

After joining, the path goes through `Normalize` — which trims trailing dots and spaces, and throws on a segment that trims to nothing — and then the result is re-checked to still sit under the target directory, `OrdinalIgnoreCase`. That last check is belt and braces, because `Normalize` pops `..` lexically. Reserved names (`CON`, `NUL`) stay ordinary files under `\\?\`, consistent with the settled SFTP decision. A symlink planted at the destination is followed, which is exactly what OpenSSH does — at parity, documented rather than fixed.

**The target is not always a directory.** `scp -O f.txt host:C:/tmp/renamed.txt` sends `scp -t C:/tmp/renamed.txt`, and when the target is not an existing directory the received name is **ignored** and the body lands at the target path. Measured against the reference; implementing only the directory case breaks upload-with-rename, which is a very common command.

#### Parsing the command line

The command arrives as one raw string a POSIX shell would normally have split, so it is tokenised here — single quotes literal, double quotes escaping only before `"` `\` `` ` `` `$`. **With one deliberate deviation**: a bare backslash escapes only before space, tab, quote or backslash, and is an ordinary character everywhere else. POSIX rules would turn `C:\Users\kb\f.txt` into `C:Userskbf.txt`, and Windows paths are exactly what this project's users type.

**Two client dialects, both of which must parse.** OpenSSH builds `scp%s%s%s%s` from `" -v"`, `" -r"`, `" -p"`, `" -d"` — **separate** flags, with `-- ` inserted only when the path starts with `-`. SSH.NET sends **bundled** flags and a **double-quoted** path: `scp -pf "…"`, `scp -prf "…"`. A parser handling only one form passes everything else and fails on exactly one client.

`~` arrives verbatim, because a real remote's shell would have expanded it; `~` and `~/rest` map to the home directory and `~user` is refused.

#### Why the tests are shaped the way they are

**Both this machine and the test remote have `scp.exe` on PATH** — the remote has two. So if the agent failed to recognise the command, the exec would fall through to that binary and the transfer would succeed anyway: **an end-to-end test cannot tell a working implementation from a silent fall-through**, because both produce the right bytes.

Two things address that. `tests/Pwssh.Tests/AgentScpDriver.cs` pushes an `EXEC` frame into a directly-constructed `PwsshAgentHost`, where no external binary can be involved — that is the load-bearing proof, and it is also the only route to what no client will send: a hostile filename, a `C` line whose size disagrees with the bytes after it, a nacked control record. And every error message carries a **`pwssh-scp:`** prefix, so the real-client cases have a discriminator too; a fall-through would say `scp:`.

`\1` is used even for unrecoverable errors: measured, OpenSSH's own `run_err` never emits `\2`, and some third-party sinks handle it poorly.

#### Flow control and teardown

The channel reuses `ByteChannel` (`src/agent/ByteStream.cs`) for inbound bytes rather than growing another reassembler — `Write` copies and pulses without blocking, which the `IAgentStream` contract demands since it runs on the frame dispatch thread, while `ReadExact` blocks on the worker thread and throws `EndOfStreamException` at EOF. scp's framing is mode-dependent (a line, then exactly N bytes, then one byte), so a blocking reader is the natural fit where SFTP's self-delimiting messages needed a framer.

**`Kill()` and `CloseWrite()` both close it**, and that is not tidiness: `ReadExact` waits with no timeout, so otherwise a client that dies mid-upload leaves a worker parked until the watchdog, holding an open `FileStream` — the NTFS-lock leak the SFTP section warns about. The worker's `finally` disposes any open handle, and the inbound queue carries the same `MAX_QUEUED` tripwire `AgentSftpChannel` has.

Unlike `AgentSftpChannel`, which hard-codes exit 0, the scp channel tracks errors and reports a **real exit status** — OpenSSH's client ORs the remote status into its own, so `scp -O …; echo $?` depends on it.

`RESIZE` and `SIGNAL` resolve through `as AgentChannel` and so no-op on an scp channel, exactly as they do for SFTP. Teardown comes from the `CLOSE` frame when ssh exits.

### Long paths (`Win32Fs` and the `\\?\` prefix)

Paths past `MAX_PATH` work, up to Win32's ~32,767. `src/agent/Win32Fs.cs` replaces the managed file-system calls with `CreateFileW`, `GetFileAttributesExW`, `FindFirstFileW`, `CreateDirectoryW`, `RemoveDirectoryW`, `DeleteFileW`, `SetFileAttributesW` and `SetFileTime`, and **every path it hands to Win32 carries `\\?\`**.

**The failure this fixed could not be demonstrated on the available machines, and that is worth being straight about.** The known-limits entry claimed a 4.8 app-config switch was the cause; the red test refused to reproduce, and probing showed why — `UseLegacyPathHandling` and `BlockLongPaths` are both false here, the test remote has `LongPathsEnabled` by group policy, and both candidate host binaries declare `longPathAware`. So long paths already worked *on this remote*. What was actually wrong is that they worked **for a reason no other user is obliged to have**, and that older targets — explicitly on the roadmap — would fail outright, since under legacy path handling the managed layer rejects both `\\?\` and any path past `MAX_PATH` before it ever calls Win32.

`\\?\` has been a Win32 contract since Windows 2000 and needs neither the policy nor a manifest. That is the whole reason for going native rather than prefixing a managed call.

**Every path is prefixed, not just long ones.** One code path, so all the existing suite cases exercise it rather than leaving the long-path route as the branch that rots. `Win32Fs.Extended` does the prefixing at the single point of use, so `ToWindows` returns an ordinary unprefixed path, `WinPath` stays readable in logs, and `ToSftp` needs no stripping — which also removes the trap where a prefixed path fed back to the client would realpath as `/?/C:/…`.

**The prefix means we own normalisation, and it has to be complete.** `\\?\` disables *all* of the OS's path handling, so a `..` left in the path is not resolved — it is looked up as a directory with that literal name, which is a path escaping where the caller meant rather than an error. `AgentSftpChannel.Normalize` replaces `Path.GetFullPath` (which throws on length under legacy handling, so it could not stay): split on `\`, drop empty and `.` segments, pop for `..` stopping at the root, and reject anything not rooted on a drive. It has direct tests, `..` at the root and repeated separators included.

Two behaviour changes follow, both deliberate and both asserted in the suite rather than left to surprise someone:

- **Trailing dots and spaces are trimmed** by the normaliser. `\\?\` would preserve them, which creates names that no ordinary tool on the remote could open again — so trimming keeps the prefix from changing what a name *means*.
- **Reserved names are ordinary files.** `CON`, `NUL`, `PRN`, `COM1`–`COM9`, `LPT1`–`LPT9` stop resolving to devices. Correct for a file server, but note the consequence for anything else touching them: the far side's own managed APIs would still resolve an unprefixed `C:\dir\CON` to the console, so the suite creates and removes that file through sftp only.

**Error mapping is the part that silently changes meaning.** `StatusFor` keys on exception *type*, so the native wrappers must throw the same types the managed APIs did or every error-status case in the suite quietly starts reporting something else: 2 → `FileNotFoundException`, 3 and 15 → `DirectoryNotFoundException`, 5 → `UnauthorizedAccessException`, 206 → `PathTooLongException`, and everything else → `IOException`, which maps to `FAILURE` exactly as before. `SetLastError = true` on every import, with `Marshal.GetLastWin32Error()` read immediately.

**A P/Invoke struct-layout mistake here is silent, and this one produced plausible output.** `WIN32_FIND_DATAW` and `WIN32_FILE_ATTRIBUTE_DATA` need **`Pack = 4`**. A native `FILETIME` is two `DWORD`s, so every member is 4-byte aligned and nothing is padded; declaring the times as `long` makes the CLR want 8-byte alignment and insert four bytes after the attributes, shifting every field behind it. The symptoms were sizes of 0, timestamps of `Jan 01 1601`, and **names read two `WCHAR`s late** — `shallow.txt` came back as `allow.txt`, which is what identified it. Worse, `.` and `..` came back empty so they stopped being recognised as themselves, and a `get -r` recursed until the client's own *"Maximum directory depth exceeded: 64 levels"*. None of that is visible to a bit-exactness check, because reads go through a `FileStream` on a handle and never consult the struct. A static constructor now asserts `sizeof` is 592 and 36.

**`FindFirstFileW` yielding name, attributes, size and both times in one pass buys nothing, and the plan was wrong to expect it to.** The reasoning was that `READDIR` would stop stat-ing each name separately — but `DirectoryInfo.GetFileSystemInfos` never did: the `FileSystemInfo` objects it returns cache the `WIN32_FIND_DATA` from the enumeration, so reading `.Length` or `.LastWriteTimeUtc` was already free. There was no per-entry syscall to remove. Measured on System32 (5,692 entries) over loopback, interleaved, three rounds: **177 ms against 189 ms medians, with the direction disagreeing between rounds and the within-variant spread wider than the difference** — i.e. no change, which is the correct outcome for work that was never doing anything. Entry counts agree exactly. Recorded because the premise was plausible and false.

Verified on both transports. Loopback is a genuine test here because the agent runs against this machine's own filesystem; **the WinRM run is the one that matters for this file**, because it is the only place `Win32Fs` executes on the runtime it targets — the remote reports PS 5.1 / CLR 4.0.30319, i.e. real .NET Framework 4.8, where the csproj compiling clean is not the same claim. Ten cases at ~350 characters, both green: the whole cycle (`mkdir`, `put`, bit-exact `get`, `ls -l` asserted on name *and* size, `rename`, `chmod`, `rm`, `rmdir`), `get -r` through the deep tree, both behaviour changes, removal of the tree afterwards, and the existing error statuses unchanged.

**What no test here can show is the policy-independence, and it is the entire point of the change.** Both available machines have `LongPathsEnabled` on, so an unprefixed path would pass too. The claim rests on the documented Win32 contract plus inspection that every path handed to Win32 goes through `Extended` — and on the agent's counters (`LongPathsSeen`, `LongestPath`, logged once per channel, visible with `-EmitRemoteLog`) proving the extended route was actually taken. A machine with the policy off would settle it properly.

### Idle sessions (the client-side keepalive)

`lastInboundTick` is refreshed only in `PwsshEngine.PushInbound` — inbound SSH bytes *from the ssh client* — and the watchdog gives up after `InactivityTimeoutSeconds` (300) without any. An idle `ssh` sends nothing (`ServerAliveInterval` defaults to 0; `TCPKeepAlive` works below the SSH layer), so **a session left sitting was dropped after five minutes**. Verified rather than assumed: with the timeout turned down, `echo` before an idle period worked, the client was already gone afterwards, and it reported `Connection to 127.0.0.1 closed by remote host`.

The engine now sends **`keepalive@openssh.com` as a global request with `want_reply = true`**, from the watchdog tick that already existed. The client does not implement it and answers `REQUEST_FAILURE`, which is all that is needed — RFC 4254 §4 requires a reply to any `want_reply` global request, and `sshd`'s own `ClientAliveInterval` relies on exactly this. Confirmed from the client's side: `client_input_global_request: rtype keepalive@openssh.com want_reply 1`, once per interval.

This is **the mirror image of the agent's `PING`** and exists for the reason recorded there — silence has to be made to mean something before it can be acted on. The one difference is direction: the agent's ping is one-way because the *agent* is the one timing out, whereas here we need the peer to speak, so it has to be a request it is obliged to answer.

- **It costs nothing on the slow link**, which is worth stating where a round trip is most of a second: the SSH transport is local stdio between `ssh.exe` and the ProxyCommand, so neither the request nor its reply touches WinRM or wakes the remote.
- **The interval is derived, not configured** — a quarter of the timeout, capped at 60 s, floored at 1 s. The same ratio the agent uses, so a couple of missed keepalives are harmless, and one knob then makes the whole mechanism testable: a 10 s timeout yields a 2.5 s keepalive with nothing to keep in step. The watchdog's own tick drops below 5 s to match when the timeout is short.
- **`InactivityTimeoutSeconds` stays at 300 and shutdown stays purely time-based.** The obvious follow-on — give up after N unanswered keepalives, and shorten the timeout as the agent side did once its ping landed — is deliberately not done. A client that ignored an unknown `want_reply` request would be violating the RFC, but it would then be *killed* rather than merely inconvenienced; leaving the time-based backstop alone means such a client behaves exactly as it did before, so this change can only help.
- **Inbound `REQUEST_SUCCESS`/`REQUEST_FAILURE` are now handled** (ignored). They previously fell into `Loop`'s `default` and drew an `UNIMPLEMENTED` reply to something perfectly legitimate. Treating any of them as ours is safe *because the keepalive is the only global request this engine sends*; a second kind would need its replies order-matched, as the client's own already are in `pendingForwards`.
- **The orphan protection still fires**, and that was worth testing rather than assuming: a keepalive that accidentally kept a dead session alive for ever would be a worse bug than the drop it fixes. A client that connects and never speaks is still given up on at the timeout — our own keepalive is outbound and cannot refresh `lastInboundTick`.
- **Confirmed at the shipped default, not only at the test's**: an interactive session over WinRM, idle for 380 s against the 300 s timeout, still ran a command afterwards (411 s in total). That is a different claim from the suite's — at 300 s the derived interval is the 60 s cap rather than a few seconds, so this is the only run that exercises the interval a user actually gets. The suite case uses 12 s because five minutes per transport is not something a run can absorb.

### Rekeying

`ssh` rekeys after ~1 GiB on AES-CTR, and until this existed a post-established `KEXINIT` drew `SSH_MSG_DISCONNECT` — so **any single transfer over ~1 GiB died part way through**, and the read-ahead's 1.42× brought that 1.42× nearer in wall-clock. It was the only known failure that turned a slow transfer into a broken one.

Most of the cryptography was already right, which is worth knowing before touching it: `sessionId` is captured on the **first** exchange only (`if (sessionId == null) sessionId = h;`) and `Derive` feeds it, which is exactly RFC 4253 §7.2's rule for rekeys; `V_C`/`V_S` in the hash stay the original identification strings; and sequence numbers already never reset. **`HandleKexDhInit` needed no change at all** — it recomputes `H` from the new `KEXINIT` pair, re-signs with the same host key (so `known_hosts` is untouched), and fills the pending keys.

**We answer; we never initiate.** The client rekeys at its own `RekeyLimit`, so that covers every case that occurs, and initiating buys nothing here — AES-CTR counter reuse needs 2^68 bytes, and encryption in pwssh is ceremonial rather than confidential. The real reason, though, is that responding-only makes the send restriction **provably deadlock-free**: the gate closes when we *receive* a `KEXINIT`, and since the input stream is in order, everything the client sent earlier is already processed and the client — now mid-rekey itself — sends no more channel data. At the instant the gate closes the protocol thread has no non-transport write pending. Initiating would remove that guarantee and require draining the sender threads first.

- **The send gate is the whole change, and it is gated by message number, not by a flag threaded through call sites.** RFC 4253 §7.1 permits only transport-layer messages (1–49) between `KEXINIT` and `NEWKEYS`, and OpenSSH errors on a `CHANNEL_DATA` arriving mid-KEX, so this is interop rather than tidiness. `WritePacket` inspects `payload[0]` and waits while `rekeying && type >= 50`; `WriteChannelData` always waits. The number *is* the rule, so a call site added later cannot get it wrong — and it automatically leaves the protocol thread able to send the two things it must still send during a rekey, `UNIMPLEMENTED` from `Loop`'s `default` case and `DISCONNECT`. **A gate that blocked all writes would deadlock exactly there**, because the thread that has to receive the client's `NEWKEYS` would be parked waiting to send.
- **The wait is bounded (10 s) and throws.** A logic error must end the connection rather than hang it, as with the park deadline and both watchdogs.
- **Both key directions still switch together**, on receipt of the client's `NEWKEYS`, rather than outgoing-at-ours and incoming-at-theirs as the RFC describes. That is safe *only* because the gate means we send nothing in between, which makes our `NEWKEYS` the last packet of the old epoch either way. It is commented as depending on the gate, and it must be split if initiation is ever added.
- `AesCtr` gained `Dispose`, and superseded ciphers/MACs are now released. One leak per gigabyte would not have mattered; a `RekeyLimit=256K` test run makes thousands.

**Strict KEX (`kex-strict-s-v00@openssh.com`) is deliberately not implemented.** It would require resetting sequence numbers at every `NEWKEYS`; we never advertise the server marker, so it cannot be negotiated and the current no-reset behaviour is correct. It mitigates Terrapin, which needs an attacker able to inject into the transport — here, between `ssh.exe` and its own ProxyCommand, two processes on the same machine under the same user. There is no such position.

**Testing this is cheap because a rekey never touches WinRM.** SSH terminates in the client, so the transport is local stdio and a rekey is two modexps plus a signature — all local. `ssh -o RekeyLimit=256K` (OpenSSH's documented minimum) forces ~11 rekeys into 8 MiB, turning a once-per-gigabyte path into a few seconds of test. Measured cost, interleaved over three rounds: **2.99 s with 11 rekeys against 2.96 s without** — no detectable difference, and at the real 1 GiB default it is one rekey per gigabyte.

The suite asserts bit-exactness under forced rekeys for both `exec` and `sftp`, that the exit status survives, and — because otherwise the cases could pass by never rekeying — that `ssh -vv` logged more than one `SSH2_MSG_KEXINIT sent`. The SFTP case is the one that matters: it has the read-ahead synthesising `CHANNEL_DATA` from its own thread while the protocol thread drives the rekey, which is precisely what the gate exists to serialise. Verified with `valveTrips=0`.

Also verified by hand, because the suite cannot easily wait it out: a **time**-triggered rekey with `RekeyLimit "256K 10s"` on an idle interactive shell. Two rekeys fired with nothing flowing and the session still echoed afterwards — a different path from the data-triggered one, where the gate opens and closes with no traffic to serialise against.

### Striping across sessions (`-Streams N`, default 1)

Each PSSession gets its own WSMan receive thread on the client, and that thread is the ceiling, so extra sessions multiply receive capacity. Sessions beyond the first are receive-only "mules": they run `src/Start-PwsshMule.ps1`, which connects to a local named pipe published by the agent and relays whatever arrives to its own pipeline output. Mules need no compilation — they never inspect a frame. Everything the client *sends* still goes to the primary session, so there is only one ordering problem, solved by `FrameResequencer`.

A mule lives in a different `wsmprovhost` process from the agent that owns the child, which is why the hand-off is a named pipe rather than a method call.

**It is opt-in because it is not a general win.** Measured over 24 MiB, interleaved:

| | 1 stream | 4 streams | |
|---|---|---|---|
| incompressible | 0.35 MiB/s | **1.00 MiB/s** | 2.83× |
| compressible | 2.98 MiB/s | 2.46 MiB/s | **0.83× — worse** |

Frame compression and striping relieve the *same* bottleneck. Once compression has done so, three extra sessions are just ~2 s of setup on an 8 s transfer. Use `-Streams 4` for bulk incompressible traffic (already-compressed archives, media, encrypted blobs); leave it at 1 for ordinary command output.

## Running and testing

**Build the agent first, and rebuild it after touching `src/agent/`** — the client refuses a stale DLL rather than pushing old code:

```powershell
pwsh -NoProfile -File .\tools\Build-Agent.ps1
pwsh -NoProfile -File .\tools\Build-Agent.ps1 -CheckOnly   # is the built DLL current?
```

The dev host is unaffected: it runs the agent in-process from the sources, so it needs no DLL. Only the WinRM path pushes one.

Dev host (loopback only, fast iteration — no WinRM in the loop):

```powershell
pwsh -NoProfile -File .\tools\Start-PwsshTcpHost.ps1 -Port 2222
pwsh -NoProfile -File .\tests\Invoke-PwsshTests.ps1 -Target "$env:USERNAME@127.0.0.1" -Port 2222
```

Through WinRM, using a test `ssh_config` rather than touching `~/.ssh/config`:

```powershell
pwsh -NoProfile -File .\tests\Invoke-PwsshTests.ps1 -Target pwssh-test -Port 0 -ConfigFile tmp/ssh_config -KnownHostsFile tmp/known_hosts_winrm
```

A single manual call: `ssh -F tmp/ssh_config pwssh-test whoami`. Add `-Diagnostics` to the ProxyCommand for stderr progress, which is off by default because ssh shows a ProxyCommand's stderr in the user's terminal on every connection.

**Run the suite from a shell whose PATH finds the WINDOWS OpenSSH client, not Git for Windows'.** This is the single most expensive trap found so far: launching the suite from Git Bash — or from anything that inherits its PATH, including a `pwsh` started by it — resolves `sftp` to `/usr/bin/sftp`, the MSYS build. That build treats a drive-letter path as **relative**, so the harness's `C:/Users/.../scratch` is joined to the remote working directory and every request goes to `/C:/Users/kb/C:/Users/kb/...`. The first `put` fails and takes about thirty cases with it, all of them looking like a server-side path regression. Measured directly, same command against the same remote:

| client | `ls C:/Users/kb/AppData/Local/Temp/x` |
|---|---|
| `C:\Program Files\OpenSSH\sftp.exe` (10.0p2) | works |
| `C:\Windows\System32\OpenSSH\sftp.exe` (9.5p2) | works |
| `/usr/bin/sftp` (Git for Windows, MSYS) | **doubles the path and fails** |

The Windows builds special-case `X:/…` as absolute; the MSYS build does not. Nothing in the failure output points at the client, so check `(Get-Command sftp).Source` before believing a path regression.

**Never pipe a live `PSDataCollection`, including `$ps.Streams.Error`.** Enumerating one BLOCKS until the collection is closed, and a runspace's error stream stays open for as long as the runspace runs — so `$svc.Streams.Error | ForEach-Object {...}` on a still-running background service deadlocks the whole run, silently, with the case's own assertion never printing. It looks exactly like a transport hang and it is not. `.Count` and the indexer do not block; use those. This cost several 20-minute runs and three wrong diagnoses before the block was timed in isolation, which located it immediately: runspace creation 8 ms, `BeginInvoke` 2 ms, readiness poll 122 ms, then nothing.

**Check which `ssh`/`sftp` a run actually used before trusting a client-behaviour claim.** This machine has three OpenSSH installs and they are not the same version: `C:\Windows\System32\OpenSSH` is 9.5p2, Git for Windows ships 9.7p1 and shadows it inside Git Bash, and `C:\Program Files\OpenSSH` is 10.0p2 — which is what PATH resolves for `pwsh`, and therefore what the suite runs. Anything settled by reading strings out of a binary has to come from that one. Note `strings` defaults to a 4-character minimum, which hides the 3-character `ERR` the `df -i` case depends on; use `strings -n 3`.

**To compare against the reference SFTP server, no sshd required.** Windows ships `sftp-server.exe` even on machines with no SSH service, and `sftp -D` drives it over a pipe with SSH entirely out of the loop:

```powershell
'pwd' | sftp -b - -D "C:\Windows\System32\OpenSSH\sftp-server.exe" x
```

Add `-vvv` to see what the client negotiates (`server upload/download buffer sizes … using …` is the line that matters). This is how the path convention, the extension set, the `limits` values and the request-ramp behaviour were established rather than guessed, and it is the fastest way to settle any further question about what a real client expects. Note it does *not* mean pwssh could shell out to that binary instead: it arrives with the Server capability, i.e. on precisely the machines that do not need pwssh.

The full WinRM run needs the optional targets too — `pwssh-nopty` for the ConPTY degradation cases and `pwssh-test-gw` (same block plus `-GatewayPorts`) for the reverse-forward gateway case:

```powershell
pwsh -NoProfile -File .\tests\Invoke-PwsshTests.ps1 -Target pwssh-test -Port 0 -ConfigFile tmp/ssh_config -KnownHostsFile tmp/known_hosts_winrm -DegradedTarget pwssh-nopty -DegradedConfigFile tmp/ssh_config_nopty -ForwardTarget '127.0.0.1:5985' -ForwardTarget6 '[::1]:5985' -GatewayTarget pwssh-test-gw -GatewayConfigFile tmp/ssh_config
```

The SFTP section needs no extra targets and has no transport-conditional skips, which makes it the best regression signal in the suite — but it is also the slowest part of a run, since every case is at least one full `sftp` connection. `-SkipSftp` drops it while iterating on something else.

**Start the dev host with its own console, or the pty case fails for a reason that has nothing to do with pwssh.** ConPTY does not work in a process whose **stdout is redirected** — so a dev host launched from a harness that captures its output (`Start-Process -RedirectStandardOutput`, a backgrounded `pwsh … > log`, most CI runners) fails `pty session produces output`, while the same host launched detached with its own console passes. Measured 3/3 each way, deterministic:

```powershell
# fails the pty case                     # passes it
Start-Process pwsh -ArgumentList (...) `  Start-Process pwsh -ArgumentList (...) `
    -RedirectStandardOutput host.log          -WindowStyle Hidden
```

The failing run's VT stream is the tell: it emits `ESC[?9001l ESC[?1004l` immediately after enabling those modes — win32-input-mode and focus events being turned straight back off — and the payload never arrives. `Start-PwsshTcpHost.ps1` now warns when its own stdout is redirected, so this announces itself rather than being rediscovered.

**This corrects a long-standing entry here that wrote the failure off as a property of this client machine**, on the strength of a minimal `CreatePseudoConsole` + `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` repro that "still failed with no pwssh code in it". That repro was almost certainly run with its output captured too, so it reproduced the harness artifact rather than a machine defect — which is a good reminder that a minimal repro only isolates the variables you thought to vary. Loopback is **72/72** once the host has a console. The entry mattered because a documented permanent failure is exactly where a real regression would have hidden.

**A `-R` port must be bindable on the *remote*, which is not the same as free here.** The suite used to pick its reverse-forward port by asking the local OS for an ephemeral one, which lands in 49152–65535 — and Windows reserves large blocks of exactly that range. On the test remote, `netsh interface ipv4 show excludedportrange protocol=tcp` lists 49773–49972 and 50000–50459 among others, so the pick was coming from the one band most likely to be unbindable there. That produced an intermittent failure of the `-R` round trip which looked like a pwssh bug: port 50802 failed reproducibly while 28080 bound fine. Worse, the two cases that *expect* a refusal (`wildcard reverse bind is refused by default`) would have passed for entirely the wrong reason. `Get-FarSidePort` picks from 28000–28899 instead; `Get-FreePort` remains correct for ports that only have to be free on this machine.

**Every wait in the suite must be bounded, including the ones that look incidental.** `Invoke-Ssh` bounded `WaitForExit` but not the `CopyToAsync` that drains stdout, and ssh exiting does not guarantee that pipe is closed — a surviving grandchild can hold it. One stuck case then stopped the whole run producing output, which reads as a hang of unknown origin rather than a failure; it cost a debugging cycle chasing a `-R` failure that had already been explained.

### The SSH.NET test project

`tests/Pwssh.Tests` exists because the PowerShell suite is driven entirely through the stock OpenSSH client, and a client cannot ask for what it has no command for. **102 tests, ~35 s**, `dotnet test tests/Pwssh.Tests`. It needs no dev host and no DLL — it compiles the product sources in and hosts the engine itself.

```powershell
dotnet test tests\Pwssh.Tests\Pwssh.Tests.csproj
```

Two layers, and the second is the more valuable one:

- **SSH.NET over a real loopback socket**, for client *behaviours* `sftp` never produces: a mid-transfer backwards seek above all. `PwsshTestHost` is a near-copy of `TcpHost.Serve` with four differences — port 0 with the assigned port readable, a stop path, captured engine log lines, and bounded waits in teardown. `TcpHost.Run` itself cannot be reused: it is an unstoppable `while (true)` accept loop whose listener is a local variable, and it never exposes the port it got.
- **A frame-level SFTP driver** (`AgentSftpDriver`), which sends a `SUBSYSTEM` frame and then raw SFTP packets straight to `PwsshAgentHost`. No SSH, no engine, no round trips — **7 to 70 ms per test** against seconds for the SSH.NET ones. This is what reaches a forged handle, an unknown extension name, an `INIT` claiming version 6, and the one-reply-per-request invariant; several of those code paths had never executed. The same goes for `statvfs`: the frame-level cases are the only place the eleven reply fields are readable at all, since `df` prints a formatted table, and `fstatvfs` has no CLI command whatsoever. It is also where the symlink cases that no client can reach live: `sftp` has no `readlink` command at all, and it renders a status through its own `fx2txt` rather than showing the server's *message* — so the tag parsing, the argument order and the text naming the three privilege routes are assertable only from here. The nine cases in the PowerShell suite cover the other half, which is the part only a real client produces: the reversed wire order of `SSH_FXP_SYMLINK`.

**Compiling the sources in rather than referencing an assembly** is what makes `SftpReadAhead`, `SftpFramer`, `AgentSftpChannel` and `PacketLayer` reachable with no `InternalsVisibleTo` — which matters because that attribute would need a file, and a new `.cs` under `src/agent/` would change the agent source hash and invalidate every built and released DLL. Confirmed safe: `Build-Agent.ps1 -CheckOnly` still reports `current` with the project in place.

**It is not the language gate.** It compiles the agent sources at `LangVersion latest`, so a C# 8+ construct added to one of them would build here and fail only in `Build-Agent.ps1`. No worse than the status quo — the client's own `Add-Type` uses PowerShell 7's Roslyn — but the csproj remains what catches you.

Four things about it are worth knowing before writing another test:

- **A zero-latency loopback is not merely faster, it changes which paths run.** The SFTP prefetch buffers whatever comes back, bounded by the agent's credit rather than by depth, so on a bare loopback it fetches an entire 8 MiB file before the client has consumed a megabyte. It then keeps serving from that buffer (see *A finished prefetch keeps serving its buffer*), so a test that needs the fetch to be genuinely still in flight — a parked read, a seek landing mid-fetch — must slow the link: `PwsshTestHost(latencyMs:)` and `DelayedLoopback` mirror the dev host's `-LatencyMs`, frame-stamped rather than sleeping in the shuttle. "Mid-transfer" therefore has to mean *early*, while requests are demonstrably still in flight.
- **Every SFTP reply arrives as `OUT|COMPRESSED` (0xC1), not `OUT` (0x81).** The agent sets the flag whenever deflate saves an eighth, which an SFTP reply comfortably does. A driver matching on the raw type byte sees nothing at all, which is exactly how the frame-level driver first failed. Strip the flag and inflate, as `PwsshAgentProxy` does.
- **pty tests need a console, and a pseudoconsole of our own does not provide one.** `dotnet test` redirects stdout, and ConPTY cannot attach in that state. Creating a pseudoconsole here and launching the host with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` was tried and does not work: the attribute sets the child's *console*, not its *std handles*, which still come from this process — observed directly, the host's banner landed on the test runner's stdout while the pseudoconsole capture stayed empty. There is no documented way for a creating process to obtain handles to the client side of a pseudoconsole it made. `ConsoleHostFixture` uses **`CREATE_NO_WINDOW`** instead, which gets a real console with no window and correct handles for all three streams. The cost is that nothing may be redirected — not being redirected is *why* it works — so the dev host's log is unreadable from the test and readiness is detected by polling the port.
- **Over pipes, `cmd` needs `\r\n`.** Only ConPTY's console turns a bare CR into a line, so a pipe-mode shell driven with `\r` starts, prints its banner and then sits there — which looks exactly like a broken shell channel. Hence `ShellDriver.PtyNewline` versus `PipeNewline`.

**Do not run this suite and the WinRM suite at the same time.** Doing so produced **seven failures out of the first 34 cases**, all reporting `Connection timed out during banner exchange` — which reads as a transport regression and is nothing of the kind. The ProxyCommand has to start `pwsh`, load the engine and open a WinRM session before ssh's banner timeout, and `dotnet test` running dev hosts and multi-megabyte transfers alongside it is enough local contention to lose that race. The tell is clustering: cases 1–18 passed, the failures began exactly when the xUnit run started, and a re-run on a quiet machine was 82/82. Same class of mistake as the orphaned-shell trap — an environmental cost that presents as a code fault.

**Serialized, not parallel** (`CollectionBehavior(DisableTestParallelization = true)`). Per-connection state is genuinely isolated, but `PwsshAgentHost.InitialCredit` / `InitialTcpCredit` / `DisableConPty` / `DisableCoalescing`, `PwsshAgentProxy.KeepAliveMs` and `Win32Fs`'s counters are process-wide mutable statics, and serializing also keeps each host's captured log attributable to the test that produced it.

**The SSH.NET version floor has two independent causes, both load-bearing.** 2024.0.0 is the first release carrying `hmac-sha2-256-etm@openssh.com`, which pwssh offers as its only MAC with no non-ETM framing to fall back on. **2025.1.0** is the first with `ShellStream.ChangeWindowSize`, which is the only public route to a `window-change` request — in 2024.2.0 the request exists solely on the non-public `ChannelSession`, and the resize path could not be automated at all. Worth knowing when the pin is next touched: dropping below either floor silently removes a whole test rather than failing to compile.

**Both of the requests that looked unreachable turned out to have public wrappers**, and the lesson is worth keeping: searching for public *types* (`SignalRequestInfo`, `ChannelSession`) found nothing and led to the wrong conclusion twice. `signal` is sent by `SshCommand.CancelAsync(forceKill)` and `window-change` by `ShellStream.ChangeWindowSize`; the underlying request classes stay non-public in both cases. Look for the method that does the thing, not the type that models it.

**`NuGet.config` at the repo root is required, not incidental.** The machine this was written on had a user-level config declaring `nuget.org` twice with the second entry winning, leaving the retired `https://www.nuget.org/api/v2/` gallery as the only source. A `<clear />` plus the v3 index makes the restore reproducible. Nothing else in the repo restores packages.

**Clean up orphaned WinRM shells** after interrupted runs. A killed client leaves the remote pump blocked, and `Remove-PSSession` cannot remove a Busy shell — the WSMan API can:

```powershell
$uri = 'http://<host>:5985/wsman'
Get-WSManInstance -ConnectionURI $uri -ResourceURI shell -Enumerate -Credential $cred -Authentication Negotiate |
    ForEach-Object { Remove-WSManInstance -ConnectionURI $uri -ResourceURI shell -SelectorSet @{ShellId = $_.ShellId } -Credential $cred -Authentication Negotiate }
```

Both ends have an inactivity watchdog so orphans self-terminate rather than waiting out WinRM's 2-hour timeout: `PwsshConfig.InactivityTimeoutSeconds` (default 300) on the client, and `PwsshAgentHost.InactivityTimeoutSeconds` (default 120) on the remote, the latter backed by a 30 s `PING` from the client so that silence reliably means the client is gone. The remote one is what releases child processes and `-R` listeners after an abrupt disconnect, which is every disconnect — see the `-R` section.

**A client that cannot authenticate is not a pwssh failure, and it looks exactly like one.** The whole WinRM suite went from passing to failing every case with `exit=255` mid-session, which reads as a regression in whatever was last touched. It was not: a direct `New-PSSession` failed identically, from both pwsh 7 and Windows PowerShell 5.1. Separate the two before debugging anything:

```powershell
New-PSSession -ComputerName <host> -Authentication Negotiate -Credential (Import-CliXml -Path <cred>.xml)
```

If that fails, the ProxyCommand is irrelevant. The distinguishing symptoms were **`0x8009030e SEC_E_NO_CREDENTIALS`** ("a specified logon session does not exist") on the Negotiate/NTLM path and **`0x80090311 SEC_E_NO_AUTHENTICATING_AUTHORITY`** ("your domain isn't available") on Kerberos, while the network was demonstrably fine — 5985 open, both DCs answering on 88 and 389, DNS resolving.

The cause was **client-side WinRM configuration, and nothing to do with this project**: `WSMan:\localhost\Client\TrustedHosts` no longer listed the test remote. That is required here because there is **no trust between the client's domain and the remote's** — `nltest /domain_trusts` lists only the primary domain, and the credential is stored in NetBIOS form (`REMOTEDOM\kb`), which `nltest /dsgetdc:REMOTEDOM` cannot resolve at all (`ERROR_NO_SUCH_DOMAIN`). So Kerberos has no realm to ask, Negotiate falls back to NTLM, and NTLM against a server it cannot mutually authenticate over plain HTTP demands a `TrustedHosts` entry. The DNS form resolves fine (`nltest /dsgetdc:remote.example` → `dc1.remote.example`), so storing the credential as the UPN `kb@remote.example` fixes it with no admin and no `TrustedHosts` entry, by letting Kerberos work. **Confirmed**: re-exporting the credential with the UPN username restored the whole suite to 82/82, and it is the better arrangement anyway — Kerberos actually authenticates the server, where NTLM plus a `TrustedHosts` entry is a decision to trust an unverified one.

**Two plausible theories were wrong, and both cost time worth saving.** Hyper-V's install *had* activated Credential Guard (`DeviceGuard\Scenarios\CredentialGuard\Enabled = 1`, `lsaiso.exe` running — note `Win32_DeviceGuard.SecurityServicesConfigured` reads 0 and `LsaCfgFlags` is absent, so neither of those is a reliable check), and the client's WinRM service was `Stopped`. Neither was the cause: starting the service changed nothing, and **CIM over DCOM with the same credential object succeeded**, which proves explicit-credential cross-domain NTLM works and so exonerates Credential Guard. That DCOM/WSMan asymmetry is the diagnostic worth remembering — RPC has no `TrustedHosts` requirement, so a credential that works there and fails over WinRM points at `TrustedHosts` rather than at anything about credentials. The timing was coincidence: `TrustedHosts` is persistent config, and a `Set-Item` without `-Concatenate` overwrites it.

## Implementation traps

Each of these cost a debugging cycle and none are obvious from the docs.

- **An *advanced* script cannot receive streamed pipeline input.** Adding `[Parameter()]` attributes — even just `[Parameter(Mandatory=$true)]` — makes a script advanced, exactly as `[CmdletBinding()]` does, and advanced scripts route pipeline input through *parameter binding*. With no `ValueFromPipeline` parameter, every input object is rejected with *"The input object cannot be bound to any parameters for the command"* and `$input` stays empty. Measured, sending three `byte[]` through `BeginInvoke(input, output)`:

  | Script form | Result |
  |---|---|
  | `param([Parameter(Mandatory=$true)][string]$Cfg)` | `items=0`, 3 binding errors |
  | `param([string]$Cfg)` (simple) | `items=3` ✓ |
  | advanced + `[Parameter(ValueFromPipeline=$true)]$In` | `items=3` ✓ |
  | `[CmdletBinding()]` + `param([string]$Cfg)` | `items=0`, 3 binding errors |

  Named parameters bound correctly in all four cases; only the input was lost. So parameters and streamed input *do* coexist — in a simple script, or with an explicit `ValueFromPipeline` parameter. `src/Start-PwsshServer.ps1` relies on this and **must stay a simple script**: adding `[Parameter()]` to any of its parameters, or `[CmdletBinding()]`, will silently break the byte stream.

  An earlier version split this across two pipelines (init with parameters, pump with input) in the belief the two were incompatible. They are not, and the split bought nothing measurable: an interleaved A/B of connection time gave **8,741 ms for one pipeline vs 8,710 ms for two** — a 31 ms difference, with individual runs ranging 7.7–21 s. A predicted "saves one round trip" gain did not materialise.
- **`Write-Warning` goes to STDOUT under `pwsh -File`.** Verified directly: stdout received `WARNING: ...`. In a ProxyCommand that corrupts the SSH stream. The same applies to warnings raised on the *remote* — they are surfaced to the client's host and land on the client's stdout. All diagnostics therefore go to `[Console]::Error`, and the client silences the warning/verbose/information/progress preferences outright. Remote logging is opt-in and documented as debug-only.
- **`Add-Type -ReferencedAssemblies` replaces the default reference set on PowerShell 7** rather than adding to it, so a partial list breaks types as basic as `Thread`. Referencing `System.Management.Automation` also drags in reference-vs-implementation assembly conflicts (`Thread` "forwarded to System.Private.CoreLib"). The engine avoids the whole problem by never referencing SMA; `PwsshPump` unwraps `PSObject` reflectively instead.
- **`Add-Type -Path` with multiple files** is how the dev host references engine types: an in-memory `Add-Type` assembly has no `Location`, so it cannot be referenced from a second compilation.
- **`RSA.ToXmlString`/`FromXmlString` support differs** between .NET Framework 4.8 and .NET 8+. `PwsshKey` serialises `RSAParameters` explicitly instead.
- **`FileSystemAccessRule`'s 5-argument overload takes the access type LAST.** Passing `'Allow'` third silently binds it to `InheritanceFlags` and throws.
- Windows PowerShell needs `System.Numerics` and `System.Core` named explicitly for `BigInteger` and `Aes`; PowerShell 7 resolves them from its default set. `Import-PwsshEngine` branches on `$PSVersionTable.PSEdition`.
- **PowerShell variables are case-insensitive**, so `$k` and `$K` are the same variable — an inner loop counter silently destroyed an outer bound.
- **Compiling the C# costs ~1.1–1.7 s on every connection**, so `Import-PwsshFiles` caches the result as a DLL under `%LOCALAPPDATA%\pwssh\cache`, keyed on the sources' size and mtime: ~200 ms to load instead. `Add-Type -OutputAssembly` does work on PowerShell 7 despite having been unsupported in earlier PS Core versions. The build goes to a private temp name and is moved into place, so concurrent connections cannot load a half-written assembly. This is the *client's* copy; the remote's is a separate prebuilt DLL, and the two caches are unrelated.
- **Two compilers, one set of agent sources.** `src/agent/*.cs` is compiled by the csproj for the remote and by `Add-Type -Path` for the client, so a change has to satisfy both. In practice that means net48-compatible APIs and `LangVersion` 7.3 or lower — the client's Roslyn is newer and more permissive, so it is the csproj that will catch you.
- **`powershell.exe` writes a CLIXML progress record to stderr** ("Preparing modules for first use"), which is faithfully relayed as `CHANNEL_EXTENDED_DATA` and will be interleaved with anything the far side writes there deliberately. `New-FarSideCommand` in the tests sets `$ProgressPreference = 'SilentlyContinue'` for this reason. Worth remembering when interpreting stderr from any remote command.

## Goal

A lightweight SSH server implementation whose only transport is PowerShell Remoting over WinRM. The purpose is to let standard industry tooling that speaks SSH (and expects an SSH endpoint) work against remote machines that are reachable *only* via PowerShell remoting — i.e. hosts with no SSH server installed.

Implementation language: mostly PowerShell, with embedded C# via `Add-Type` where PowerShell is impractical (packet handling, crypto).

## Architecture

```
ssh client
  │  (stdin/stdout = the SSH transport, via ProxyCommand)
  ▼
pwssh-connect.ps1                (runs locally)
  │  opens a PSSession over WinRM
  │  pushes any missing files to the remote (Copy-Item -ToSession), kept minimal
  │  bridges binary data both directions
  ▼
SSH server implementation        (runs on the remote, inside the PSSession)
  └── session + exec/shell channels
```

The SSH "network connection" is the PowerShell remoting pipe. There is no listening socket anywhere. The client is configured entirely through `ProxyCommand`, e.g.:

```
Host myremote
    User myuser
    ProxyCommand pwsh -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Bypass -Command "& /path/to/pwssh-connect.ps1 -ComputerName myremote -Credential (Import-CliXml -Path '/my/path/cred.xml') -Authentication Negotiate"
```

Credentials may be cached as above, or omitted so the proxy command prompts interactively.

## Settled design decisions

These come from the project owner and should not be revisited without asking.

- **Authentication and security are delegated to the PowerShell remoting layer.** WinRM has already authenticated the user before the SSH implementation runs.
- **No real SSH authentication.** No `password` and no `publickey` method. The client's requested username is accepted if — and only if — it matches the current user of the remote PowerShell session; otherwise the connection is rejected.
- **Encryption exists only for client compatibility,** not for confidentiality. An unpatched OpenSSH client refuses to connect without it. Because it is not load-bearing for security, hand-rolled crypto is acceptable here.
- **Modern algorithms only.** No legacy ciphers, no CBC, no SHA-1-based MACs.
- **The host key must be stable across connections.** See *Host key identity* below.
- **Scope for v1: `session` channels with `exec` and `shell`.** Port forwarding (`direct-tcpip`) and the SFTP subsystem are explicitly deferred to later work.
- **Assume an old PowerShell on the remote.** Newer, well-maintained environments generally already have an SSH server, so they are not the target. Design for Windows PowerShell 5.1 / .NET Framework 4.x. This rules out `System.Security.Cryptography.AesGcm`, `ChaCha20Poly1305`, and `Span<byte>` (all .NET Core 3.0+), and means the agent must stay runnable on 4.x — its csproj targets `net48` for exactly this reason. Note this constrains the *runtime*, not the *language*: since the agent is compiled by Roslyn rather than by the remote's CodeDOM, C# 7.3 is available (see *The agent is a prebuilt assembly*). It was C# 5 until the build step existed.

## Host key identity

The SSH client caches the server's host key in `known_hosts` on first connect and hard-fails with `REMOTE HOST IDENTIFICATION HAS CHANGED` on any later mismatch. The requirement this imposes is **stability, not authenticity** — a host key generated freshly on the remote for each connection would break every connection after the first.

This is why the host key will most likely be **pushed from the client**, which looks contradictory to a host key's usual purpose but is consistent with not relying on the SSH layer for authenticity.

Intended approach: `pwssh-connect.ps1` maintains a client-side keystore with one key per target (e.g. `~/.pwssh/hostkeys/<computername>`), generated lazily on first connect, and supplies it to the remote at startup. This keeps `known_hosts` stable, requires no persistent state on the remote, and still presents distinct keys for distinct hosts so the entries remain meaningful.

Consequences:

- **Transfer the private key in memory** — as a parameter or here-string into the remote script — never via `Copy-Item`. The WinRM channel is already encrypted, so transit is not the concern; leaving the key on the remote's disk is.
- **Startup ordering is forced.** The key must be present on the remote before the host-key signature during KEX, so the sequence is: open session → push script and key material → start the remote server → begin the SSH banner exchange.
- **Accepted failure mode:** losing the client-side keystore produces the `known_hosts` mismatch warning and the user must clear the stale entry.

Alternatives, both viable, neither chosen:

- *Persist the key on the remote* (user profile, DPAPI-protected) — more faithful to SSH semantics and survives the user changing client machines, but requires remote state, which cuts against the minimal-footprint goal. Mirror-image failure mode: a fresh remote profile yields a new key.
- *Sidestep host key checking entirely* with `StrictHostKeyChecking no` and `UserKnownHostsFile NUL` in the client's `Host` block. Defensible given the threat model and needs no key management at all, but makes some tooling noisy and moves the burden into user configuration. Worth documenting as an escape hatch regardless of what the implementation does.

## Algorithm set (primitives validated on a real remote)

Chosen as the intersection of "still enabled by default in OpenSSH 9.x" and "already implemented in .NET Framework 4.x", which avoids hand-rolling any cryptographic primitive. Every primitive below was executed successfully against a live PS 5.1 / .NET Framework 4.8 remote (see *Measured transport behaviour*); the timings are from that machine:

| Role | Choice | Status on remote |
|---|---|---|
| KEX | `diffie-hellman-group14-sha256` | `BigInteger.ModPow` over the RFC 3526 group14 prime: **15 ms** per 2048-bit modexp. Needs `Add-Type -AssemblyName System.Numerics`. |
| Host key | `rsa-sha2-256` | `RSACryptoServiceProvider`: 2048-bit keygen + `SignData(...,'SHA256')` = **42 ms** total, 256-byte signature. |
| Cipher | `aes256-ctr` | `[Aes]::Create()` yields `AesCryptoServiceProvider`; ECB + `Padding=None` gives the CTR keystream. |
| MAC | `hmac-sha2-256-etm@openssh.com` | `HMACSHA256` native in mscorlib. |

Inline C# via `Add-Type -TypeDefinition` also compiles on the remote. The only things written by hand are packet framing, the RFC 4253 §7.2 key derivation, and the transport/connection state machines.

When probing type availability on the remote, **run the primitive — do not use `[type]::GetType()`**. `GetType` searches only loaded assemblies, and partial assembly names don't resolve even after `LoadWithPartialName`, so `BigInteger`, `AesManaged` and the CNG types all report absent on a machine that has them. Functional probes are the only trustworthy kind here.

`curve25519-sha256` and `chacha20-poly1305@openssh.com` are the modern defaults but require implementing field arithmetic by hand on .NET Framework, so they are candidates for later rather than v1.

## Measured transport behaviour

Full-duplex binary transfer over PowerShell remoting was the principal open risk. It has been validated against a live remote (PS 5.1 Desktop, .NET Framework 4.8, LAN with 0 ms ICMP). **It works.** `Copy-Item`'s base64 chunking turned out to be unnecessary.

### The mechanism that works

Take the `Runspace` from an established `PSSession`, attach a `[PowerShell]` instance to it, and `BeginInvoke` a long-running script with an input and an output `PSDataCollection[psobject]`:

```powershell
$ps = [PowerShell]::Create(); $ps.Runspace = $session.Runspace
$null = $ps.AddScript({ foreach ($item in $input) { , $item } })   # , preserves byte[] as one object
$h = $ps.BeginInvoke($inColl, $outColl)
$inColl.Add([psobject]$bytes)      # client -> remote, streams immediately
$outColl[$i]                       # remote -> client, filled by a background thread
```

Non-obvious details, each of which cost a debugging cycle:

- **`byte[]` crosses natively and bit-exact.** PS remoting serialises it as base64 internally, so no manual encoding layer is needed. Verified identical by SHA-256 over a 64 KiB array containing all 256 byte values.
- **Read output with `.psobject.BaseObject`, not `.BaseObject`.** PowerShell transparently unwraps `PSObject` on member access, so `$outColl[0].BaseObject` looks for a `BaseObject` property on the `byte[]` itself and silently yields `$null`. A `[byte[]]` cast works too.
- **Emit arrays from the remote with `, $item`** (or `Write-Output -NoEnumerate`), otherwise the pipeline enumerates the array into individual bytes.
- **Signal EOF with `$inColl.Complete()`; do not use an in-band sentinel that makes the remote `break` out of its `foreach`.** Having the remote exit its loop while the client still holds the input collection open races the transport teardown and throws `NullReferenceException` inside `Fragmentor.Fragment` on a background thread, which kills the *client process outright* (unhandled, exit code 5). Let the remote loop end naturally when input completes.

### Why `byte[]` and not `String`

CLIXML represents `byte[]` as base64 (`<BA>AQID/w==</BA>`) and `String` as `<S>` with `_xHHHH_` escaping for XML-invalid characters (`<S>A_x0000__x0001__x000B_B_x001F_C</S>`).

Measured on 64 KiB of random data, both cost the same **1.335×** on the wire (87,486 vs 87,484 bytes of CLIXML) — unsurprising, since `byte[]` *is* base64 underneath. **This ~33% expansion is unavoidable** and is already reflected in the throughput figures below; SSH payload is encrypted and so incompressible, meaning WSMan compression cannot recover it.

Packing two payload bytes per UTF-16 `char` to beat base64 **does not work**, because CLIXML goes on the wire as **UTF-8** — Windows' internal UTF-16 never reaches it. ~97% of 16-bit code units are ≥ `U+0800` and cost 3 UTF-8 bytes per 2 payload bytes ≈ **1.5×**, worse than base64, before the 7-byte `_xHHHH_` escapes for control values.

**Ascii85 was evaluated and rejected for now.** Measured CLIXML wire cost for 65,536 payload bytes:

| Encoding | Chars/byte | Actual wire cost |
|---|---|---|
| `byte[]` native / base64 | 1.3334 | **1.3349×** |
| Ascii85, standard Adobe alphabet (`!`…`u`) | 1.2500 | **1.3967×** — *worse* |
| Ascii85, custom XML-safe alphabet | 1.2500 | **1.2515×** |

Standard Ascii85 loses because its alphabet contains `&`, `<` and `>`; 2,833 of 81,920 encoded chars hit them and expand to `&amp;`/`&lt;`/`&gt;`. A custom 85-char alphabet excluding space, `&`, `<`, `>` and `_` (the last because PowerShell escaping is `_xHHHH_`-based) does achieve 1.2515×, a real 6.2% saving — 89 printable candidates remain, so 85 is comfortable.

Because upstream is byte-rate limited (see *Numbers*), that 6.2% **would** convert to ~6% more upstream throughput. CPU is not the objection either: the hand-rolled encoder managed 32.9 MiB/s on modern .NET against native base64's 312 MiB/s, and even at a third of that on .NET Framework 4.8 it retains ~25× headroom over a 0.4 MiB/s channel. It is deferred purely because 6% does not justify hand-rolled codecs at both ends and forfeiting the free native `<BA>` path, when SSH-level `zlib@openssh.com` compression offers a multiple rather than a percentage. Revisit only if that route is rejected.

Note one trap for anyone testing this: the public `PSSerializer::Serialize` API **throws** on `U+FFFE` (`invalid character`), so PowerShell escapes C0 controls and `NUL` but not `U+FFFE`/`U+FFFF`. The live remoting serialiser is more permissive than that API — over a real PS 7 → PS 5.1 channel, all non-surrogate code units *including* `U+FFFE`/`U+FFFF`, a lone surrogate `U+D800`, and embedded `NUL` all round-tripped bit-identical. That leniency is undocumented and must not be relied on; use `byte[]`.

### Numbers

**Measure with interleaved, repeated A/B runs.** Run-to-run variance on this link is ~2×, and single measurements have already produced two wrong conclusions (see the compression note below). A one-shot number is not evidence.

| Measurement | Result |
|---|---|
| Session establishment | ~1.5 s |
| Round-trip latency, idle channel | **~575–900 ms**, varies between runs |
| — flat from 64 B to 32 KiB | a fixed *turnaround* cost, not bandwidth |
| Round-trip via `Invoke-Command` per call | worse than a persistent pipeline, so use the pipeline |
| Network baseline | ICMP 0 ms; TCP connect to 5985 ~20 ms — the latency is **not** the network |
| Upstream throughput (client→remote) | **~0.4 MiB/s** |
| Downstream throughput (remote→client) | **~3.5–4 MiB/s** (earlier runs reached 5–6) |
| Full duplex | works; bounded by the upstream direction |

**Per-message overhead is effectively zero once the pipe is busy** — this is the key finding. 400 × 64 B messages round-tripped in 1,004 ms with the *first* arriving at 993 ms, i.e. **0.03 ms/msg** steady state; upstream-only managed 400 × 64 B in 191 ms (2,093 msg/s). Pipelining hides the turnaround almost perfectly.

**Upstream is byte-rate limited, not message limited.** A 4 MiB upload took ~8–10 s whether sent as 512 × 8 KiB or 8 × 512 KiB — message count varying 64× changed nothing. So coalescing writes does not improve throughput (though batching per wakeup still avoids extra turnarounds).

**Keep WSMan compression enabled (the default).** `-NoCompression` was measured over 3 interleaved rounds on an idle remote (6% CPU): downstream collapsed from **4.04 to 0.31 MiB/s (13×, reproducible 3/3)**, and its apparent upstream gain was a first-run artifact — the median was slightly worse. An earlier single-shot measurement suggested a 2.2× upstream *win*; that was drift.

### What this means for the design

- **Never ping-pong at the SSH layer.** Each idle-channel exchange costs ~600–900 ms. This is a protocol constraint, not a tuning knob.
- **Advertise large SSH channel windows and send `SSH_MSG_CHANNEL_WINDOW_ADJUST` eagerly** — as soon as data is consumed, not at a 50% threshold. This is the highest-value single decision: OpenSSH defaults to a 2 MB window, and advertising a small one would stall the client for a full turnaround per window, dominating everything else.
- **Bulk transfer is fine** because messages pipeline; `exec` and (later) SFTP reads will behave acceptably.
- **Interactive `shell` will feel laggy.** ~600–900 ms keystroke echo, satellite-link territory. Inherent to WinRM exchange on this path, not to the design, and *not* fixable by batching, since a single keystroke cannot be pipelined with anything.
- **Upstream is the scarce direction (~10× worse).** Route bulk downstream where the design has a choice; SFTP reads will be fine, writes slow.
- **`zlib@openssh.com` is the only lever with multiple-x potential.** SSH compresses *before* encryption, which is the one remaining place compressibility exists — WSMan's own compression cannot touch our encrypted payload. Caveat: it needs `Z_SYNC_FLUSH` per packet, which .NET Framework 4.8's `DeflateStream` cannot do, so it means embedding a small deflate implementation.
- **Parallel sessions**: aggregate upstream measured 0.53 → 0.80 → 0.89 MiB/s at 1/2/4 sessions — ~1.7× and sublinear, but measured under `-NoCompression` amid drift, so **unconfirmed**. It also requires mule runspaces to hand bytes to the single SSH state machine on the remote, plus sequencing and reassembly. Only pursue if upstream bulk becomes a real pain point.
- Untested config lever: raising the remote's `MaxEnvelopeSizekb` (currently 500). Requires an admin WinRM service change.

### Native process I/O on the remote (the `exec` / `shell` channels)

**PowerShell's native-command bridging cannot carry binary. Do not use it.** When a native command runs in a remote runspace, PowerShell decodes the child's stdout as text using the host's `[Console]::OutputEncoding`, splits it into lines, and emits `String` objects. Measured against a file of all 256 byte values via `& cmd /c type`:

- 256 bytes arrived as **3 `String` objects totalling 254 chars**;
- **128 `U+FFFD`** replacement characters — every byte ≥ 0x80 destroyed by UTF-8 decoding, unrecoverably;
- the `0x0A` and `0x0D` bytes were consumed by line splitting (hence 3 lines, 2 chars short);
- naive re-encoding produced 510 bytes, not 256.

`0x1A` passed through fine, so Ctrl-Z-as-EOF is *not* the hazard; text decoding and line splitting are. Piping *into* a native command is equally unsafe: the remote's `$OutputEncoding` is **`us-ascii`** by default under PS 5.1.

**The working approach** — verified bit-exact for all 256 byte values — is to have the remote script drive the child itself:

```powershell
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $env:ComSpec
$psi.RedirectStandardOutput = $true; $psi.RedirectStandardInput = $true
$psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)
$p.StandardOutput.BaseStream.Read(...)      # raw bytes, no decoding
```

So the remote script is a **byte shuttle** between the remoting `byte[]` channel and the child's raw `BaseStream` handles.

**There is no PTY on the remote.** `[Console]::WindowWidth` throws `IOException`, both standard streams report redirected, and the host is `ServerRemoteHost`. Children therefore see pipes, not a terminal, and will disable colour and line editing. Because the child must be launched via .NET anyway, `pty-req` is still reachable later via **ConPTY** (`CreatePseudoConsole`, Windows 10 1809+; the test remote is build 26200) through `Add-Type` P/Invoke. Not needed for v1, but it is the correct answer for interactive `shell` rather than a workaround.

### Open question

Whether the ~600–900 ms turnaround can be reduced. It is not the network, not specific to streaming (per-call `Invoke-Command` is worse), and not compression (`-NoCompression` tested: no latency benefit, and it wrecks downstream throughput). Remaining untested levers: HTTPS vs HTTP transport, alternative `-Authentication` modes, raising the remote's `MaxEnvelopeSizekb`, and the classic Nagle/delayed-ACK interaction that often manifests in this latency range.

This only affects interactive `shell` responsiveness — bulk transfer already pipelines around it — so it is worth one focused experiment, not a sustained effort.

## Known limits and open items

- ~~**No rekeying**~~ — **implemented**; see *Rekeying* below. It had stopped being theoretical: a single `scp` over ~1 GiB died part way through with `pwssh does not support rekeying`.
- ~~**Seen once: the client→agent SFTP stream lost 4 bytes of alignment during a valve trip**~~ — **found and fixed**; see *A trip owes the framer's held bytes* under the read-ahead section.
- ~~**Long paths fail**~~ — **implemented**; see *Long paths* below. The entry that used to be here said .NET Framework 4.8 needs an app-config switch that cannot be set on the remote, and **that diagnosis was wrong**: the red test would not reproduce. A 327-character path works on the test remote today, because it has `LongPathsEnabled` set by group policy and both candidate hosts declare `longPathAware`. So the reason to do the work was never a failure that could be demonstrated here — it was that the current behaviour depends on a policy no other user is obliged to have, and on older targets that are on the roadmap it would fail outright.
- ~~**The loopback dev host cannot catch a round-trip regression**~~ — **done**, and it is how the read-ahead and the per-file round-trip work were developed. `-LatencyMs` on `tools/Start-PwsshTcpHost.ps1` stamps each frame on arrival and releases it when due, so a burst stays a burst; a `Thread.Sleep` in the shuttle loop would have serialised the link and made a correctly pipelined design measure as though it were not. It lives in the dev-only `tools/PwsshTcpHost.cs` rather than `PwsshLoopback` deliberately, so the agent source hash is untouched.
- ~~**Not manually verified**~~ — **all confirmed**, by the project owner at a real interactive session: colour rendering, `Ctrl+C` interrupting a running command, and `window-change` reflowing output. Two of those three still have no other kind of evidence available. **`window-change` now does**: `tests/Pwssh.Tests` drives `ShellStream.ChangeWindowSize` and then asks the remote what width its own console reports, so the whole path — the request, `SessionChannel.Resize`, the `RESIZE` frame, `ResizePseudoConsole` — is asserted rather than eyeballed. It needed SSH.NET 2025.1.0; before that the request was reachable only through a non-public type.

  The reflow evidence is **`vim` over a live session, resized**, which is a considerably stronger test than the one this entry originally asked for. A full-screen editor repaints on a size change, so it exercises the alternate screen buffer, absolute cursor addressing, colour and `window-change` → `ResizePseudoConsole` together — and a wrong size or a dropped resize would show up immediately as a corrupted screen rather than as something subtle. It also confirms the interactive latency figure from the other direction: usable, and slow exactly as the ~250–900 ms per keystroke predicts.

  Worth keeping straight what `Ctrl+C` proves: the **data** path, where the keystroke arrives as ordinary channel data and ConPTY's console handles it. It says nothing about the `signal` channel request, which is a different mechanism the stock client rarely sends — that one is now covered separately by `tests/Pwssh.Tests`, driven through `SshCommand.CancelAsync`.
- ~~**A long-idle interactive session is dropped after 5 minutes**~~ — **fixed**; see *Idle sessions* below. It was real, not "probably": verified as a genuine failure first, with the client reporting `Connection to 127.0.0.1 closed by remote host` after an idle period. No `ServerAliveInterval 60` workaround is needed any more.
- ~~**`signal` is implemented but effectively untested**~~ — **now covered.** OpenSSH rarely sends `SSH_MSG_CHANNEL_REQUEST "signal"` (under a pty, `Ctrl+C` arrives as ordinary channel data and the console handles it), but SSH.NET reaches it through **`SshCommand.CancelAsync(forceKill)`**, which sends `TERM` or `KILL`. `tests/Pwssh.Tests` asserts the part that actually matters: not that the request is accepted, but that the **child tree** dies. `exec` runs as `%ComSpec% /c <cmd>`, so in `ping -n 60 127.0.0.1` the ping is a *grandchild* — killing only the direct `cmd.exe` would leave it running, and its output would stop reaching the client either way, so early completion proves nothing on its own. The tests watch the process table for the specific ping they started and assert it is gone, which is what the Job Object with `KILL_ON_JOB_CLOSE` is for. Also asserted: the signal name arrives intact (`signal: TERM` / `signal: KILL` in the engine log) and the session survives a signalled channel.
- **Throughput was well below the channel's capability** — since explained, and superseded by *Throughput: profiled* two entries below; kept for the two hypotheses it rules out, because both are the first things a reader would suspect. Measured at the time on an 8 MiB `exec` payload: **0.25 MiB/s over WinRM**, against ~3.5–4 MiB/s for the raw transport — roughly 14× down. Both hypotheses were largely ruled out:
  - *AES-CTR cost.* The keystream is now generated 4 KiB at a time instead of per 16-byte block (`TransformBlock` per block costs a CNG transition). This did not move the WinRM figure (0.18 → 0.18) and slightly *reduced* loopback (1.35 → 1.04 MiB/s), so the cipher is not the constraint. The batching is kept because it is strictly less work.
  - *Idle poll latency.* Shortening the remote pump's `TakeOutbound` timeout from 200 ms to 25 ms gained 39% (0.18 → 0.25 MiB/s), so idle wait was a real but partial factor.
  
  The most likely remaining cause is **channel-window stalls**: `ExecChannel.SendData` blocks when the client's window is exhausted, and every `SSH_MSG_CHANNEL_WINDOW_ADJUST` costs a full ~600–900 ms WinRM turnaround. That would be invisible on loopback (where the same code reaches ~1 MiB/s) and dominant over WinRM, which fits the evidence. Instrumenting adjust arrivals against send stalls is the next step. Note the loopback number is itself unexplained and includes `powershell.exe` start-up on the far side, so it is not a clean ceiling.
- **Upstream remains ~10× slower than downstream** as a property of the transport, so uploads will be slow whatever we do here.
- **Throughput: profiled, and the remaining cost is mostly not ours.** Two things were confounding the earlier numbers:

  1. **The 8 MiB test is dominated by connection setup.** The same transfer at 48 MiB runs at **2.70 MiB/s** versus 1.13 MiB/s at 8 MiB — roughly 3–4 s of fixed cost (PSSession, agent compile, HELLO) being amortised. Quote steady-state figures from a large transfer; the 8 MiB number is a connect-plus-transfer measurement.
  2. **The client is CPU-bound, not waiting.** During an 8 MiB transfer the ProxyCommand `pwsh` used 4.39 s of CPU against 6.31 s wall (70% of one core); `ssh.exe` used 0.27 s.

  A `dotnet-trace` CPU profile of the proxy (48 MiB transfer, 12 s sample) attributes managed CPU as:

  | | managed CPU | share |
  |---|---|---|
  | `WSManClientSessionTransportManager.StartReceivingData` | 4,580 ms | **35.3%** |
  | `GC.AllocateUninitializedArray` + `PollGC` | 2,220 ms | **17.1%** |
  | crypto (AES-CTR + HMAC) | 1,849 ms | 14.3% |
  | Roslyn compile (one-off at startup) | 696 ms | 5.4% |
  | **all `Pwssh.*` code** | **34 ms** | **0.3%** |

  Per-thread attribution is what makes this actionable: **one thread sits at 89.1% of a core**, and 4,580 of its 4,790 ms is that WSMan receive method. Every other thread is at 19–21%. So a single SMA thread is the ceiling, and reducing our *total* CPU — for example the 17% of allocation churn — would not raise throughput at all, because that work is on threads with headroom.

  What does help is putting **fewer bytes through that one thread**. WinRM's own compression cannot: it decompresses below the PowerShell layer, so the receive thread still parses full-size CLIXML and base64. Compressing inside the frame payload does, and was implemented (`FrameType.COMPRESSED`, raw deflate, applied adaptively only when it saves ≥12.5%):

  | 48 MiB transfer | before | after |
  |---|---|---|
  | compressible | 2.70 MiB/s | **4.58 MiB/s** (1.7×) |
  | incompressible | 0.38 MiB/s | 0.38 MiB/s (falls back to raw, by design) |

  **Striping across sessions was then implemented** (see above): 2.83× on incompressible data, but 0.83× on compressible, because it relieves the same bottleneck compression already does. It is opt-in via `-Streams`.

  Raising the remote's `MaxEnvelopeSizekb` from 500 would cut fragment count, but it needs admin on the remote and is therefore **rejected on principle** — see *No remote configuration* below.

  **The allocation churn was then addressed**, and the result is a useful negative: the copies are gone and throughput did not move, which is what the profile predicted. A payload byte used to be copied roughly eight times between the agent's read and ssh's stdout; it is now copied about twice. What changed:

  - `PacketLayer.WriteChannelData` assembles a `CHANNEL_DATA` packet straight into its final buffer — length, padding count, header, payload, random padding — then encrypts and MACs in place. That collapses four copies (caller's slice, `SshWriter`'s buffer, `ToArray`, packet assembly) into one.
  - The MAC is computed with `TransformBlock`/`TransformFinalBlock` instead of building a `seq || length || ciphertext` scratch array. That removes **a full copy of every packet in each direction** — a cost that was not even in the original eight.
  - `ByteChannel.WriteOwned` skips the defensive copy for buffers the packet layer has just built and will never touch again, and `TakeAll` returns a single pending buffer directly rather than concatenating through a `MemoryStream`.
  - `IPwsshChannelSink.OnData` takes `(buffer, offset, count)`, so an uncompressed frame is passed through as a range instead of having its payload copied out.
  - Compressed payloads carry their uncompressed length, so inflate allocates the output exactly once instead of growing a `MemoryStream` and copying it out.

  Effect: `GC.AllocateUninitializedArray`, previously 8.8% of managed CPU, no longer appears in the profile's top frames. Throughput over 48 MiB measured 4.16–5.15 MiB/s (mean 4.80) against 4.58 before — unchanged within noise. Worth having for memory pressure; it was never going to be a speed win.

### The profiler's CPU numbers are inflated — check them against the process

Two leads from the post-refactor profile were investigated and **both were dead ends, one of them because the tool lied**.

`SharedArrayPool.InitializeTlsBucketsAndTrimming` appeared to peg the finalizer thread at 100% of a core. Its full stack is `…Trimming` ← `Gen2GcCallback.Finalize` ← `GC.RunFinalizers`: the runtime's own array-pool trimming, not our allocation. And it is not real CPU. Ground truth settles it: during a 48 MiB transfer the proxy process used **0.33 cores average**, while the same trace attributed **1.89 cores**. The EventPipe sampler samples every managed thread on a timer and labels a managed top frame `CPU_TIME` whether or not the thread is running, so threads parked inside managed frames accumulate phantom CPU.

**Always sanity-check a trace's absolute CPU against `Process.TotalProcessorTime`.** Relative ranking between genuinely busy threads still seems sound; absolute figures are not.

The `Monitor.Enter_Slowpath` contention was real but not ours: the stack is `PSMemberSet.ReplicateInstance` ← `PSObject.GetPSStandardMember`, i.e. PowerShell's own member-collection locking while constructing received `PSObject`s. Same for `WindowsIdentity.GetTokenInformation` ← `ReceiveDataCollection.ProcessRawData` — SMA re-checks the impersonated identity for every received chunk. Nothing to fix on our side.

### Credit round trips were the real bulk-transfer cost

Chasing those leads turned up the actual problem. Facts that did not add up: the remote can produce and deflate the test payload at **43 MiB/s**, compression takes it to **0.9%** of its size (48 MiB → ~440 KB on the wire), and the client uses a third of a core — yet the transfer took 13 s.

The cause was **two windows in series**. Credit was returned to the agent only *after* data had been written to ssh, so it was gated by ssh's own 2 MB channel window as well as costing a WinRM round trip per grant. A 48 MiB transfer serialised into dozens of upstream round trips.

Fixed by returning credit when data is *received and queued* (`SessionChannel.AccrueCredit`), with queue depth (`MAX_PENDING`) providing the backpressure instead of ssh's consumption. Window size is now tunable via `-CreditMiB` (default 32), since the credit is also what bounds how much the agent can buffer in the client before it must wait.

Interleaved over 48 MiB compressible, four rounds, credit 64 winning every round:

| credit | throughput |
|---|---|
| 8 MiB | 4.71 MiB/s |
| 32 MiB | 6.91 MiB/s |
| 64 MiB | 7.76 MiB/s |

32 MiB captures nearly all of it at half the worst-case memory, hence the default. Note the first single-sample measurement of this change read 6.04 and the second read 4.38 — **the spread on this transport is wide enough to invert a conclusion, and only the interleaved run settled it.**

  **Tooling note:** `dotnet-trace` from NuGet is 9.0 and produces an empty trace against pwsh 7.6, which runs on .NET 10 — 0 samples and a "potentially broken trace" warning. Version 10.0.731102 is not on NuGet (broken publish pipeline); get the signed binary from the [dotnet/diagnostics release](https://github.com/dotnet/diagnostics/releases/tag/v10.0.731102). Also make sure the traced process **outlives the trace duration**: if it exits mid-session the rundown never happens and stacks cannot be resolved. The speedscope output is *evented*, and hangs `CPU_TIME`/`UNMANAGED_CODE_TIME` pseudo-leaves under each real frame, so self time must be credited to the nearest real ancestor — and `UNMANAGED_CODE_TIME` is mostly blocked threads, not CPU.
- **Encrypting before WinRM costs ~29× of throughput.** WinRM compression is enabled by default, and an SSH-encrypted payload is incompressible, so that compression is wasted. Measured downstream over 8 MiB, interleaved across 3 rounds: incompressible **0.36–0.39 MiB/s** versus compressible plaintext **6.3–11.3 MiB/s**. (The ratio is the reliable figure; absolute numbers vary between sessions — earlier runs on smaller payloads reached 3.5–4 MiB/s incompressible.) This is the strongest argument for terminating SSH in the client-side ProxyCommand rather than on the remote: it makes the WinRM payload plaintext, which also removes all crypto from the remote and turns the ~10 SSH handshake round trips into local ones.
- **Connection setup costs ~8–9 s** for `ssh host "echo x"`, and is dominated by round trips: an SSH handshake plus exec is roughly ten sequential exchanges at ~600–900 ms each, on top of ~2 s to establish the PSSession. Variance is large (7.7–21 s observed). Reducing the exchange count is the only lever that would matter, and most of the sequence is fixed by the protocol.

## Prior art

- zssh — https://github.com/TomCrypto/zssh
- nano_ssh_server — https://github.com/eisbaw/nano_ssh_server
- wolfSSH — https://github.com/wolfSSL/wolfssh
