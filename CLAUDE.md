# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

**`exec` and `shell` both work end to end over WinRM.** `ssh pwssh-test whoami` returns the remote's `DOMAIN\user`, and `ssh pwssh-test` gives a cmd.exe session — with a real terminal when the client asks for one. The suite runs 29 cases against each transport and passes, with one environmental exception: loopback is **28/29**, the failure being the pty case that this client machine's ConPTY breaks (see *Running and testing*). The two runs differ in composition rather than count — WinRM has the graceful-degradation and IPv6 cases plus the gateway-ports check; loopback has the wrong-username check that the WinRM alias takes from `ssh_config`, along with the reverse-forward release and bind-failure cases that need the far side to be this machine.

**A run that fails one case with `exit=255` is usually a flake, not a regression.** 255 is ssh's own error code for a connection that never came up, and it turns up after the remote has been hammered with dozens of sessions in a row. Re-run the case before believing it: the final WinRM run here failed "shell exit status propagates" that way and passed 3/3 immediately afterwards.

**SSH terminates in the client.** `pwssh-connect.ps1` runs the whole SSH engine locally and only plaintext agent frames cross the WinRM link. The remote does no cryptography at all. This was a deliberate change from an earlier design that ran the engine on the remote, and it bought:

| | remote termination | client termination |
|---|---|---|
| connect, `ssh host "echo x"` | 9,176 ms | **5,701 ms** (1.61×, interleaved over 5 rounds) |
| 8 MiB `exec`, compressible | 0.30 MiB/s | **1.13 MiB/s** (3.8×) |

The throughput gain is WinRM's own compression, which an encrypted stream made useless. The same suite reports **0.31 MiB/s for an incompressible 8 MiB payload** — essentially identical to what the old architecture managed on *compressible* data, which is exactly what the mechanism predicts and a good confirmation of it.

Implemented: version exchange, `diffie-hellman-group14-sha256` KEX, `rsa-sha2-256` host key, `aes256-ctr` + `hmac-sha2-256-etm@openssh.com`, `none` auth with username matching, session channel, `exec`, `shell`, `pty-req` via ConPTY, `window-change`, `signal`, `direct-tcpip` forwarding (`-L`/`-D`/`-W`, IPv4 and IPv6), `tcpip-forward` + `forwarded-tcpip` reverse forwarding (`-R`, loopback by default, `-GatewayPorts` to widen), exit status, stderr as `CHANNEL_EXTENDED_DATA`, window management, credit-based flow control to the agent.

Not implemented: SFTP, rekeying.

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
| `src/PwsshAgent.cs` | Everything the remote needs, plus the plumbing shared with the engine (`ByteChannel`, `FrameQueue`, `PwsshPump`, `Frame`). **Must stay self-contained**: the remote can only compile one source string, because an in-memory `Add-Type` assembly has no `Location` for a second compilation to reference. The client compiles it *together with* the engine via `Add-Type -Path`. |
| `src/PwsshCommon.ps1` | Shared helpers: compilation (with an on-disk assembly cache), host key keystore. Sent to the remote as text. |
| `src/Start-PwsshAgent.ps1` | Runs on the remote: compiles the agent and shuttles frames. No crypto, no host key. Must stay a *simple* script — see the parameter-binding trap below. |
| `pwssh-connect.ps1` | Client `ProxyCommand` entry point; runs the SSH engine. |
| `tools/Start-PwsshTcpHost.ps1`, `tools/PwsshTcpHost.cs` | Dev-only loopback host, using an in-process agent wired through the real frame protocol. |
| `tests/Invoke-PwsshTests.ps1` | End-to-end tests through the real `ssh` client, against either transport. |

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
- **`cancel-tcpip-forward` is answered immediately**, not after a round trip: a failure to unbind is not something the client can act on.
- **Global request replies are order-matched, not tagged.** RFC 4254 pairs them with requests in order, so `pendingForwards` is a FIFO and a result that arrives for a request behind the head waits its turn. ssh normally keeps one outstanding, but replying out of order would desynchronise every reply after it.
- **Windows has no privileged-port concept.** A normal user can bind port 80 if it is free, so low ports are not a failure case to design around; real bind failures are "already in use" or an excluded range (`netsh interface ipv4 show excludedportrange` — Hyper-V reserves large parts of the dynamic range). This makes loopback-by-default *more* valuable, not less: `-R 80:...` from an unprivileged remote account can genuinely succeed.

Measured: 512 KiB through a reverse forward is bit-exact, in ~1.1 s on loopback.

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

The full WinRM run needs the optional targets too — `pwssh-nopty` for the ConPTY degradation cases and `pwssh-test-gw` (same block plus `-GatewayPorts`) for the reverse-forward gateway case:

```powershell
pwsh -NoProfile -File .\tests\Invoke-PwsshTests.ps1 -Target pwssh-test -Port 0 -ConfigFile tmp/ssh_config -KnownHostsFile tmp/known_hosts_winrm -DegradedTarget pwssh-nopty -DegradedConfigFile tmp/ssh_config_nopty -ForwardTarget '127.0.0.1:5985' -ForwardTarget6 '[::1]:5985' -GatewayTarget pwssh-test-gw -GatewayConfigFile tmp/ssh_config
```

**ConPTY does not work on this client machine, only on the remote.** The loopback dev host therefore fails the pty case while the WinRM run passes it, and that difference is not a pwssh bug: reduced to a minimal, textbook-correct `CreatePseudoConsole` + `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` program with no pwssh code in it, the child still writes to the parent's inherited stdout instead of the pseudoconsole — the attribute is silently ignored. `FreeConsole()` in the parent first makes no difference. So `pty session produces output` failing on loopback and passing over WinRM is the expected shape here; investigate only if it starts failing over WinRM too.

**Clean up orphaned WinRM shells** after interrupted runs. A killed client leaves the remote pump blocked, and `Remove-PSSession` cannot remove a Busy shell — the WSMan API can:

```powershell
$uri = 'http://<host>:5985/wsman'
Get-WSManInstance -ConnectionURI $uri -ResourceURI shell -Enumerate -Credential $cred -Authentication Negotiate |
    ForEach-Object { Remove-WSManInstance -ConnectionURI $uri -ResourceURI shell -SelectorSet @{ShellId = $_.ShellId } -Credential $cred -Authentication Negotiate }
```

Both ends have an inactivity watchdog so orphans self-terminate rather than waiting out WinRM's 2-hour timeout: `PwsshConfig.InactivityTimeoutSeconds` (default 300) on the client, and `PwsshAgentHost.InactivityTimeoutSeconds` (default 120) on the remote, the latter backed by a 30 s `PING` from the client so that silence reliably means the client is gone. The remote one is what releases child processes and `-R` listeners after an abrupt disconnect, which is every disconnect — see the `-R` section.

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
- **Compiling the C# costs ~1.1–1.7 s on every connection**, so `Import-PwsshFiles` caches the result as a DLL under `%LOCALAPPDATA%\pwssh\cache`, keyed on the sources' size and mtime: ~200 ms to load instead. `Add-Type -OutputAssembly` does work on PowerShell 7 despite having been unsupported in earlier PS Core versions. The build goes to a private temp name and is moved into place, so concurrent connections cannot load a half-written assembly.
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
- **Assume an old PowerShell on the remote.** Newer, well-maintained environments generally already have an SSH server, so they are not the target. Design for Windows PowerShell 5.1 / .NET Framework 4.x. This rules out `System.Security.Cryptography.AesGcm`, `ChaCha20Poly1305`, and `Span<byte>` (all .NET Core 3.0+), and means any embedded C# must stay 4.x-compatible.

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

- **No rekeying.** OpenSSH rekeys after ~1 GiB or 1 hour; on a post-established `KEXINIT` the server sends `SSH_MSG_DISCONNECT` rather than corrupt cipher state. Long or very large sessions will drop.
- **Not manually verified**, because they cannot be asserted from a script: colour rendering, `Ctrl+C` interrupting a running command, and `window-change` actually reflowing output. The code paths exist (`ResizePseudoConsole` is wired to `window-change`) and the automated tests confirm a pty session runs and emits VT sequences, but a human should sit at an interactive session once.
- **A long-idle interactive session is probably dropped after 5 minutes, from the client side.** The engine's watchdog fires after `InactivityTimeoutSeconds` (300) without inbound SSH traffic, and ssh sends none while idle: `ServerAliveInterval` defaults to 0, and `TCPKeepAlive` operates below the SSH layer. The agent side no longer has this problem — the `PING` keepalive means its 120 s timeout only ever sees a genuinely dead client — but nothing sends the equivalent *towards* the client, so the asymmetry now sits here. Not directly verified (it needs a 5-minute idle session), and the workaround is `ServerAliveInterval 60` in the `Host` block. Worth fixing properly if interactive use becomes common.
- **`signal` is implemented but effectively untested.** OpenSSH rarely sends `SSH_MSG_CHANNEL_REQUEST "signal"` — with a pty, `Ctrl+C` arrives as data and the console handles it — so there is no practical way to exercise it through the stock client. It maps to killing the child tree.
- **Throughput is well below the channel's capability and not yet explained.** Measured on an 8 MiB `exec` payload: **0.25 MiB/s over WinRM**, against ~3.5–4 MiB/s for the raw transport — roughly 14× down. Two hypotheses have been tested and largely ruled out:
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
