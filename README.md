# pwssh

An SSH server that speaks only PowerShell Remoting over WinRM.

The point is to let ordinary SSH tooling reach Windows machines that have **no SSH server
installed** and that you have no rights to change — as long as you can already open a
PowerShell remoting session to them. `ssh`, and anything built on it, then works against a
host that has never heard of SSH.

```
ssh client
  │  SSH protocol on stdin/stdout, via ProxyCommand
  ▼
pwssh-connect.ps1 ── the SSH engine runs HERE, on your machine
  │
  │  plaintext agent frames over a PSSession (WinRM)
  ▼
remote agent ── starts a process, shuttles its output. No crypto, nothing on disk.
```

## Status

`exec`, `shell`, port forwarding and file transfer all work end to end. `ssh myremote whoami`
returns the remote account; `ssh myremote` gives an interactive `cmd.exe` session with a real
terminal, including colour, `Ctrl+C` and terminal resizing, where the remote supports ConPTY —
full-screen applications such as `vim` work, slowly but correctly. `sftp myremote` or
`scp file myremote:` transfers files, with **no SFTP server on the remote** — pwssh implements
the protocol itself.

| | |
|---|---|
| Implemented | version exchange, `diffie-hellman-group14-sha256` KEX, `rsa-sha2-256` host key, `aes256-ctr` + `hmac-sha2-256-etm@openssh.com`, session channels, `exec`, `shell`, `pty-req` (ConPTY), `window-change`, `signal`, port forwarding — `-L`, `-D`, `-W` and `-R`, IPv4 and IPv6 — **SFTP subsystem (and therefore `scp`)**, exit status, separate stderr, flow control |
| Not implemented | symlink creation (needs elevation on Windows) |

Tested against OpenSSH 9.5p2 on Windows, with a Windows PowerShell 5.1 / .NET Framework 4.8
remote. The test suite drives the real `ssh`, `sftp` and `scp` binaries: 69 cases over WinRM and
62 against a loopback dev host.

Two warts worth knowing:

- **`-R` ports linger.** `ssh` kills its `ProxyCommand` when it exits, so pwssh gets no chance
  to tell the remote to unbind the listening port. The remote's own watchdog releases it about
  two minutes later, so reconnecting with the *same* `-R` port inside that window fails.
- **SFTP pays round trips per file, and that dominates anything but one large file.** The client
  stats, opens and closes each file separately, so on a link where a round trip is most of a
  second a small file costs a couple of seconds however few bytes it holds: 40 files of 900 bytes
  measured **~150 s**, now **~94 s** — pwssh answers the second of the client's two metadata
  requests from a parallel fetch of its own and acknowledges a read-only close without waiting.
  Roughly three round trips per file remain. One large file is fine: pwssh reads ahead on a
  private channel and downloads measured 3.29 MiB/s at 32 MiB (1.42× over forwarding the client's
  requests one at a time), and 0.76 MiB/s at 8 MiB, where fixed cost is most of the transfer.
  Uploads, at ~0.35 MiB/s, are already at the link's upstream ceiling. **Do not pass `sftp -B`**
  — it suppresses the buffer negotiation that keeps this from being far worse.

## What it needs on the remote

Nothing you have to install or configure:

- a WinRM session the user can already open;
- permission to start a process as that same user;
- a local named pipe between two of the user's own processes — only when `-Streams` > 1.

Nothing is written to the remote's disk, no service is reconfigured, and no elevation is used.
This is deliberate and permanent: anyone who *can* reconfigure the remote should install
OpenSSH instead and get a better result in every respect, so any change requiring admin there
would remove this project's reason to exist.

## Security model — read this

**The SSH layer provides no security here.** It exists so that an unmodified SSH client will
talk to us at all.

- **Authentication is WinRM's.** There is no `password` or `publickey` method. The client's
  username is accepted only if it matches the account the remote session is already running
  as; otherwise the connection is refused.
- **Confidentiality is WinRM's.** SSH terminates on *your* machine, so the SSH ciphertext
  never crosses the network. What crosses the WinRM hop is plaintext frames, protected by
  WinRM's own encryption (Kerberos/Negotiate, or HTTPS).
- **The host key is ceremonial.** It is generated and kept on the client, so it identifies
  this proxy rather than the remote machine. It exists because SSH clients pin a host key in
  `known_hosts` and hard-fail on a change; per-target keys are cached under
  `~/.pwssh/hostkeys/` so that stays quiet. Losing that directory produces the usual
  `REMOTE HOST IDENTIFICATION HAS CHANGED` warning and the entry must be cleared.

If you need end-to-end cryptographic protection between client and remote host, this is not
the tool for that — use a real SSH server.

## Setup

Requires PowerShell 7 on the client (the engine compiles C# at startup and caches it) and an
OpenSSH client.

**You also need the agent assembly**, which is what runs on the remote. It is not committed —
a binary nobody can diff does not belong in a repo whose job is touching other people's
machines — so either take `PwsshAgent.dll` from a
[release](https://github.com/poizan42/pwssh/releases) and drop it beside `pwssh-connect.ps1`,
or build it once:

```bash
pwsh -File ./tools/Build-Agent.ps1
```

Building needs the .NET SDK and the .NET Framework 4.8 targeting pack; running pwssh does not.
The client checks the DLL against the sources on disk and refuses to run a stale one, so
editing the agent and forgetting to rebuild is an error rather than a mystery.

Then add a `Host` block:

```
Host myremote
    HostName remote.example.com
    User myuser
    ProxyCommand pwsh -NonInteractive -NoProfile -NoLogo -File C:/path/to/pwssh-connect.ps1 -ComputerName remote.example.com -CredentialPath C:/path/to/cred.xml
```

Then `ssh myremote`, `ssh myremote whoami`, and so on.

`-CredentialPath` points at a credential saved with
`Get-Credential | Export-CliXml -Path C:/path/to/cred.xml` — it exists because a nested
PowerShell expression quotes badly through `cmd.exe`, which is what Windows OpenSSH runs
`ProxyCommand` under. Omit it to be prompted, or pass `-Credential` when invoking directly.

Useful options on `pwssh-connect.ps1`:

| | |
|---|---|
| `-Authentication` | WinRM auth mode, default `Negotiate` |
| `-AgentDllPath` | where to find `PwsshAgent.dll`. Defaults to the build output, then to a copy beside the script |
| `-CreditMiB` | bulk transfer window, default 32. Larger means fewer round trips on big transfers, at the cost of how much the agent may buffer client-side |
| `-Streams N` | extra receive sessions for bulk **incompressible** transfers (see below), default 1 |
| `-SftpReadAheadChunks` | how far ahead an SFTP download is fetched, in 255 KiB chunks, default 64 (≈16 MiB held client-side). `0` turns read-ahead off and restores byte-for-byte forwarding |
| `-GatewayPorts` | let `ssh -R` bind a non-loopback address on the remote. Off by default, matching OpenSSH's `GatewayPorts no`; a request for a wider address is refused rather than quietly narrowed |
| `-Diagnostics` | progress to stderr. Off by default, since ssh shows a ProxyCommand's stderr on every connection |

## Performance, honestly

The transport is high-latency and asymmetric, and that shapes everything.

| | |
|---|---|
| Connection setup | ~4–5 s, dominated by opening the PSSession |
| Keystroke echo, interactive | ~250–900 ms — one WinRM round trip per keystroke |
| Bulk download via `exec`, compressible | ~7 MiB/s |
| Bulk download via `exec`, incompressible | ~0.4 MiB/s, or ~1 MiB/s with `-Streams 4` |
| Bulk download via `sftp`/`scp` | ~0.76 MiB/s at 8 MiB, ~3.3 MiB/s at 32 MiB |
| Many small files via `sftp`/`scp` | ~2 s each, whatever their size — round trips per file, not bytes |
| Upload, any path | ~0.35–0.4 MiB/s — the link's upstream ceiling |

Three notes on the numbers. Compressible output is much faster because WinRM compresses the
link and pwssh sends plaintext through it — which is precisely why SSH terminates on the
client rather than the remote. `-Streams` only helps *incompressible* bulk data: it adds
parallel receive threads, so once compression has already relieved that bottleneck extra
sessions merely cost setup time. It measured **2.8× on incompressible** data and **0.83×
— slower — on compressible** data, hence opt-in.

And SFTP is still slower than `exec` for the same bytes because it is a request/response
protocol whose pacing the *client* controls. Read-ahead removes the client's slow request ramp
but not its four round trips per file — see the wart above. If you are moving a directory tree,
archiving it on the far side and transferring one file will beat `scp -r` by a wide margin:

```bash
ssh myremote "powershell -c Compress-Archive -Path C:/data -DestinationPath C:/data.zip"
scp myremote:C:/data.zip .
```

Interactive use is usable but feels like a satellite link, and no amount of tuning changes
that: a keystroke cannot be pipelined with anything.

## Development

A loopback dev host runs the same engine over a TCP socket with an in-process agent, so the
protocol can be exercised without WinRM in the loop:

```powershell
pwsh -NoProfile -File .\tools\Start-PwsshTcpHost.ps1 -Port 2222
pwsh -NoProfile -File .\tests\Invoke-PwsshTests.ps1 -Target "$env:USERNAME@127.0.0.1" -Port 2222
```

It binds `127.0.0.1` only and is not part of the `ProxyCommand` path.

`CLAUDE.md` carries the design rationale, the measurements behind each decision, and the
PowerShell and WinRM traps found the hard way — worth reading before changing anything.

## License

MIT — see [LICENSE](LICENSE).
