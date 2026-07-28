# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

**`exec` works end to end over WinRM.** `ssh pwssh-test whoami` returns `REMOTEDOM\kb`. The suite passes against both transports (13/13 loopback, 12/12 WinRM — the extra loopback case is the wrong-username check, which the WinRM alias takes from `ssh_config`).

**SSH terminates in the client.** `pwssh-connect.ps1` runs the whole SSH engine locally and only plaintext agent frames cross the WinRM link. The remote does no cryptography at all. This was a deliberate change from an earlier design that ran the engine on the remote, and it bought:

| | remote termination | client termination |
|---|---|---|
| connect, `ssh host "echo x"` | 9,176 ms | **5,701 ms** (1.61×, interleaved over 5 rounds) |
| 8 MiB `exec`, compressible | 0.30 MiB/s | **1.13 MiB/s** (3.8×) |

The throughput gain is WinRM's own compression, which an encrypted stream made useless. The same suite reports **0.31 MiB/s for an incompressible 8 MiB payload** — essentially identical to what the old architecture managed on *compressible* data, which is exactly what the mechanism predicts and a good confirmation of it.

Implemented: version exchange, `diffie-hellman-group14-sha256` KEX, `rsa-sha2-256` host key, `aes256-ctr` + `hmac-sha2-256-etm@openssh.com`, `none` auth with username matching, session channel, `exec`, exit status, stderr as `CHANNEL_EXTENDED_DATA`, window management, credit-based flow control to the agent.

Not implemented: `shell`, PTY, port forwarding, SFTP, rekeying.

**The host key is now purely ceremonial.** It authenticates this proxy, not the remote machine — nothing about it crosses the link. It still has to be stable, because the client pins it in `known_hosts`.

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
[1 byte type][4 bytes big-endian channel id][payload…]
```

Client → agent: `0x01 EXEC`, `0x02 DATA` (stdin), `0x03 EOF`, `0x04 CLOSE`, `0x05 WINDOW`. Agent → client: `0x81 DATA`, `0x82 STDERR`, `0x83 EXIT`, `0x84 DONE`, `0x85 HELLO`, `0x86 FAIL`. The high bit marks direction. Channel ids exist so `direct-tcpip` can be added without reworking the protocol.

Two things about this are load-bearing:

- **`SessionChannel.OnAgentData` must never block.** It runs on the client's frame loop, and blocking there for ssh window credit would stop the same loop that drains the remoting output — an immediate deadlock. A dedicated sender thread owns all window waiting.
- **Credit is returned to the agent in 1 MiB batches** (`GRANT_THRESHOLD`). Granting per SSH packet produced ~256 tiny `WINDOW` frames for an 8 MiB download, all travelling upstream — the slow direction — and cost ~25% of throughput.

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

**Clean up orphaned WinRM shells** after interrupted runs. A killed client leaves the remote pump blocked, and `Remove-PSSession` cannot remove a Busy shell — the WSMan API can:

```powershell
$uri = 'http://<host>:5985/wsman'
Get-WSManInstance -ConnectionURI $uri -ResourceURI shell -Enumerate -Credential $cred -Authentication Negotiate |
    ForEach-Object { Remove-WSManInstance -ConnectionURI $uri -ResourceURI shell -SelectorSet @{ShellId = $_.ShellId } -Credential $cred -Authentication Negotiate }
```

The engine also has an inactivity watchdog (`PwsshConfig.InactivityTimeoutSeconds`, default 300) so orphans self-terminate rather than waiting out WinRM's 2-hour timeout.

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
- **`pty-req` is refused**, so interactive use is out of scope until `shell`/ConPTY lands. `exec` is unaffected.
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

  Remaining ideas, in order of expected value: **striping frames across several PSSessions**, since each has its own receive thread and this bottleneck is per-thread (measured ~1.7× at four sessions in an earlier experiment, at the cost of reassembly ordering); raising the remote's `MaxEnvelopeSizekb` from 500 to reduce fragment count (needs admin); and only then the allocation churn — a payload byte is still copied roughly eight times between the agent's read and ssh's stdout (`Frame.Make`, `Frame.Payload`, the `SendData` slice, `SshWriter` plus `ToArray`, packet assembly, `ByteChannel.Write`'s defensive copy, `TakeAll`'s concatenation), which is worth fixing for memory pressure even though it will not move throughput.

  **Tooling note:** `dotnet-trace` from NuGet is 9.0 and produces an empty trace against pwsh 7.6, which runs on .NET 10 — 0 samples and a "potentially broken trace" warning. Version 10.0.731102 is not on NuGet (broken publish pipeline); get the signed binary from the [dotnet/diagnostics release](https://github.com/dotnet/diagnostics/releases/tag/v10.0.731102). Also make sure the traced process **outlives the trace duration**: if it exits mid-session the rundown never happens and stacks cannot be resolved. The speedscope output is *evented*, and hangs `CPU_TIME`/`UNMANAGED_CODE_TIME` pseudo-leaves under each real frame, so self time must be credited to the nearest real ancestor — and `UNMANAGED_CODE_TIME` is mostly blocked threads, not CPU.
- **Encrypting before WinRM costs ~29× of throughput.** WinRM compression is enabled by default, and an SSH-encrypted payload is incompressible, so that compression is wasted. Measured downstream over 8 MiB, interleaved across 3 rounds: incompressible **0.36–0.39 MiB/s** versus compressible plaintext **6.3–11.3 MiB/s**. (The ratio is the reliable figure; absolute numbers vary between sessions — earlier runs on smaller payloads reached 3.5–4 MiB/s incompressible.) This is the strongest argument for terminating SSH in the client-side ProxyCommand rather than on the remote: it makes the WinRM payload plaintext, which also removes all crypto from the remote and turns the ~10 SSH handshake round trips into local ones.
- **Connection setup costs ~8–9 s** for `ssh host "echo x"`, and is dominated by round trips: an SSH handshake plus exec is roughly ten sequential exchanges at ~600–900 ms each, on top of ~2 s to establish the PSSession. Variance is large (7.7–21 s observed). Reducing the exchange count is the only lever that would matter, and most of the sequence is fixed by the protocol.

## Prior art

- zssh — https://github.com/TomCrypto/zssh
- nano_ssh_server — https://github.com/eisbaw/nano_ssh_server
- wolfSSH — https://github.com/wolfSSL/wolfssh
