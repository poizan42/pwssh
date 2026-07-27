# Runs inside the remote runspace as the SECOND pipeline. Deliberately has NO param()
# block: that is what allows $input to receive the raw byte[] stream (see the comment in
# Initialize-PwsshServer.ps1). Reads $global:PwsshEngine, left there by that pipeline.
#
# The pipeline thread emits outbound bytes; inbound is drained by a background thread,
# because enumerating $input blocks and PowerShell has only this one thread here.
#
# Only protocol bytes may be written to the output stream. Note that the warning stream is
# NOT safe here either: remote warning records are surfaced to the client's host, which
# writes them to the client's stdout and corrupts the SSH stream. So diagnostics are
# emitted only when explicitly enabled for debugging.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$engine = $global:PwsshEngine
if ($null -eq $engine) { throw 'pwssh engine not initialised' }
$emitLog = [bool]$global:PwsshEmitLog

$null = [Pwssh.PwsshPump]::StartInbound($input, $engine)

while (-not $engine.Finished) {
    # Short poll: the sender stalls whenever the SSH channel window is exhausted, and a
    # long idle wait here adds latency to every one of those stalls.
    $chunk = $engine.TakeOutbound(25)
    if ($null -ne $chunk -and $chunk.Length -gt 0) { , $chunk }
    if ($emitLog) {
        foreach ($line in $engine.DrainLog()) { Write-Warning $line }
    }
}

# Flush whatever was queued before the engine stopped (a trailing CHANNEL_CLOSE or
# DISCONNECT still needs to reach the client).
while ($true) {
    $chunk = $engine.TakeOutbound(0)
    if ($null -eq $chunk -or $chunk.Length -eq 0) { break }
    , $chunk
}

if ($emitLog) {
    foreach ($line in $engine.DrainLog()) { Write-Warning $line }
    if ($engine.LastError) { Write-Warning "engine error: $($engine.LastError)" }
}
