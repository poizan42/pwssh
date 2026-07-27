# Runs inside the remote runspace as a single pipeline: compiles the engine, starts it, and
# shuttles bytes. Sent as script text with the engine source and helpers as parameters, so
# nothing is written to the remote's disk and the host key stays in memory.
#
# This MUST remain a *simple* script. Adding [Parameter()] attributes to any parameter -- or
# [CmdletBinding()] -- makes it advanced, and advanced scripts route pipeline input through
# parameter binding: raw byte[] is then rejected with "The input object cannot be bound to
# any parameters..." and $input stays empty. Hence plain typed parameters and manual
# validation below rather than [Parameter(Mandatory = $true)].
#
# The pipeline thread emits outbound bytes; inbound is drained by a background thread
# (Pwssh.PwsshPump) because enumerating $input blocks and this is the only thread here.
#
# Only protocol bytes may reach the output stream. The warning stream is not safe either:
# remote warnings are surfaced to the client's host, which writes them to the client's
# stdout. Failures go to the error stream, which the client reads separately.

param(
    [string]$CsSource,
    [string]$HostKey,
    [string]$CommonSource,
    [string]$ExpectedUser,
    [bool]$EmitLog = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$engine = $null
try {
    if ([string]::IsNullOrEmpty($CsSource)) { throw 'pwssh: CsSource parameter is required' }
    if ([string]::IsNullOrEmpty($HostKey)) { throw 'pwssh: HostKey parameter is required' }
    if ([string]::IsNullOrEmpty($CommonSource)) { throw 'pwssh: CommonSource parameter is required' }

    . ([scriptblock]::Create($CommonSource))

    Import-PwsshEngine -CsSource $CsSource

    if ([string]::IsNullOrEmpty($ExpectedUser)) { $ExpectedUser = Get-PwsshCurrentUserName }

    $cfg = New-Object Pwssh.PwsshConfig
    $cfg.HostKey = $HostKey
    $cfg.ExpectedUser = $ExpectedUser

    $engine = New-Object Pwssh.PwsshEngine $cfg
    $engine.Start()
    $null = [Pwssh.PwsshPump]::StartInbound($input, $engine)

    while (-not $engine.Finished) {
        # Short poll: the sender stalls whenever the SSH channel window is exhausted, and a
        # long idle wait here adds latency to every one of those stalls.
        $chunk = $engine.TakeOutbound(25)
        if ($null -ne $chunk -and $chunk.Length -gt 0) { , $chunk }
        if ($EmitLog) {
            foreach ($line in $engine.DrainLog()) { Write-Warning $line }
        }
    }

    # Flush whatever was queued before the engine stopped: a trailing CHANNEL_CLOSE or
    # DISCONNECT still has to reach the client.
    while ($true) {
        $chunk = $engine.TakeOutbound(0)
        if ($null -eq $chunk -or $chunk.Length -eq 0) { break }
        , $chunk
    }

    if ($EmitLog) {
        foreach ($line in $engine.DrainLog()) { Write-Warning $line }
    }
    if ($engine.LastError) { throw "pwssh engine error: $($engine.LastError)" }
}
finally {
    if ($engine) { try { $engine.Stop() } catch { } }
}
