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

Write-Host "pwssh dev host: 127.0.0.1:$Port  hostkey=$HostKeyPath$(if ($LatencyMs -gt 0) { "  latency=${LatencyMs}ms" })"
[Pwssh.Dev.TcpHost]::Run($Port, $key, (-not $Quiet), [bool]$GatewayPorts, $LatencyMs, $SftpReadAheadChunks)
