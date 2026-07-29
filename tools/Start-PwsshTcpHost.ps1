<#
.SYNOPSIS
    Development harness: serves pwssh over loopback TCP with an in-process agent, so the
    protocol can be tested against the real ssh client without WinRM.
.DESCRIPTION
    Binds 127.0.0.1 only. This is a development tool, not part of the ProxyCommand path.
    The in-process agent is wired through the real frame protocol, so the only thing missing
    compared with production is the WinRM hop. Authentication is the same username check the
    real path uses, so it accepts only the account it is running as.
#>
[CmdletBinding()]
param(
    [int]$Port = 2222,
    [string]$HostKeyPath,
    # Honour a client-specified bind address for -R, as pwssh-connect.ps1's -GatewayPorts does.
    [switch]$GatewayPorts,
    # Inject a one-way delay into the in-process link, in milliseconds, so this harness can
    # reproduce a round-trip-bound transfer. The real transport is 600-900 ms per round trip;
    # 300 here means 600 there. Without it the dev host proves correctness and hides every
    # round-trip cost, which makes it useless for judging anything that reduces them.
    [int]$LatencyMs = 0,
    # SFTP read-ahead depth in 255 KiB chunks, as pwssh-connect.ps1's -SftpReadAheadChunks does.
    # -1 leaves the engine's own default, so only a run that is specifically about read-ahead
    # has to name a value.
    [int]$SftpReadAheadChunks = -1,
    # Testing hook: trip the read-ahead's safety valve after this many KiB have been served.
    [int]$SftpFaultAfterKiB = 0,
    # Idle shutdown, as pwssh-connect.ps1's -InactivityTimeoutSeconds. -1 keeps the engine's
    # default of 300; a small value makes the idle watchdog reachable in seconds.
    [int]$InactivityTimeoutSeconds = -1,
    # The agent's flow-control window, in KiB. This host runs the agent in-process, so setting it
    # here is the only way to force a reply to be SPLIT across frames locally: SendPayload
    # fragments by whatever credit is available, so a window below one 255 KiB chunk guarantees
    # fragmentation. 0 leaves the agent's 32 MiB default.
    #
    # SHARP EDGE, deliberately not clamped here as pwssh-connect.ps1's -CreditMiB is: this sets a
    # static, so it shrinks EVERY channel's window, and a session channel announces credit only
    # once GRANT_THRESHOLD (2 MiB) has accrued. Below that, anything the client's own SFTP channel
    # has to carry -- a transfer after the valve trips, or with read-ahead off -- deadlocks. Useful
    # for testing the prefetch channel, which grants immediately and is safe at any size; do not
    # read a hang under 2 MiB as a bug in the thing you were testing.
    [int]$CreditKiB = 0,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. "$repo\src\PwsshCommon.ps1"

if (-not $HostKeyPath) { $HostKeyPath = Join-Path $PSScriptRoot '.devhostkey' }

# Everything compiles together: the dev host references engine types and the engine references
# plumbing in the agent, and an in-memory Add-Type assembly has no Location for a second
# compilation to reference. The dev host runs the agent in-process, so it uses the sources
# rather than the prebuilt net48 DLL the real path pushes to the remote.
Import-PwsshFiles -Path (@(Get-PwsshAgentFiles -Repo $repo) + @(
    "$repo\src\PwsshEngine.cs",
    "$repo\src\PwsshSftpReadAhead.cs",
    "$PSScriptRoot\PwsshTcpHost.cs"
)) -ProbeType 'Pwssh.Dev.TcpHost'

$key = Get-PwsshHostKey -Path $HostKeyPath

# Static on the agent host, and this process IS the agent, so it must be set before any channel
# is constructed -- each one snapshots it into its own credit field.
if ($CreditKiB -gt 0) {
    [Pwssh.PwsshAgentHost]::InitialCredit = [uint32]($CreditKiB * 1024)
    Write-Host "  agent credit forced to $CreditKiB KiB (replies will fragment)"
}

Write-Host "pwssh dev host: 127.0.0.1:$Port  hostkey=$HostKeyPath$(if ($LatencyMs -gt 0) { "  latency=${LatencyMs}ms" })"

# ConPTY does not work in a process whose stdout is redirected: the child writes to the inherited
# handle instead of the pseudoconsole, and the pty test cases fail with nothing wrong in pwssh. This
# cost a real debugging cycle and was written into CLAUDE.md as a permanent property of the machine
# before it was measured, so say it out loud rather than let it be rediscovered.
if ([Console]::IsOutputRedirected) {
    [Console]::Error.WriteLine(
        "warning: this host's stdout is redirected, so ConPTY cannot attach and the pty test cases " +
        "will fail. Start it with its own console (Start-Process -WindowStyle Hidden, no " +
        "-RedirectStandardOutput) if you need those cases.")
}
[Pwssh.Dev.TcpHost]::Run($Port, $key, (-not $Quiet), [bool]$GatewayPorts, $LatencyMs,
                         $SftpReadAheadChunks, $SftpFaultAfterKiB, $InactivityTimeoutSeconds)
