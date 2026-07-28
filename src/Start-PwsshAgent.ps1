# Runs inside the remote runspace. Sent as script text with the agent source and helper
# functions as parameters, so nothing is written to the remote's disk.
#
# There is no cryptography here and no host key: SSH terminates in the client, so what
# crosses this link is plaintext frames, which lets WinRM's own compression work.
#
# This MUST remain a *simple* script. Adding [Parameter()] attributes to any parameter -- or
# [CmdletBinding()] -- makes it advanced, and advanced scripts route pipeline input through
# parameter binding: raw byte[] is then rejected with "The input object cannot be bound to any
# parameters..." and $input stays empty. Hence plain typed parameters and manual validation.
#
# The pipeline thread emits outbound frames; inbound is drained by a background thread
# (Pwssh.PwsshPump) because enumerating $input blocks and this is the only thread here.
#
# Only frames may reach the output stream. The warning stream is not safe either: remote
# warnings are surfaced to the client's host, which writes them to the client's stdout.
# Failures go to the error stream, which the client reads separately.

param(
    [string]$CsSource,
    [string]$CommonSource,
    [bool]$EmitLog = $false,
    # Downstream striping: one named pipe per mule session, which the client starts
    # separately. Zero means everything goes through this session.
    [string]$PipePrefix,
    [int]$Stripes = 0,
    # Bulk-transfer window, in MiB. Also bounds how much the agent can push into the
    # client's memory before it must wait for credit.
    [int]$CreditMiB = 32,
    # Testing hook: forces the no-ConPTY path so the graceful-degradation behaviour can be
    # exercised on a remote that does have ConPTY.
    [bool]$DisableConPty = $false,
    # Testing hook: turn off output read coalescing, for measuring its effect.
    [bool]$DisableCoalescing = $false
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$agent = $null
try {
    if ([string]::IsNullOrEmpty($CsSource)) { throw 'pwssh: CsSource parameter is required' }
    if ([string]::IsNullOrEmpty($CommonSource)) { throw 'pwssh: CommonSource parameter is required' }

    . ([scriptblock]::Create($CommonSource))

    Import-PwsshSource -CsSource $CsSource

    if ($CreditMiB -gt 0) { [Pwssh.PwsshAgentHost]::InitialCredit = [uint32]($CreditMiB * 1MB) }
    [Pwssh.PwsshAgentHost]::DisableConPty = $DisableConPty
    [Pwssh.PwsshAgentHost]::DisableCoalescing = $DisableCoalescing

    $agent = New-Object Pwssh.PwsshAgentHost
    # Pipes must exist before Start(), so the mules have something to connect to while the
    # first frames (HELLO) are already being produced.
    if ($Stripes -gt 0 -and -not [string]::IsNullOrEmpty($PipePrefix)) {
        $agent.SetStripes($PipePrefix, $Stripes)
    }
    $agent.Start()
    $null = [Pwssh.PwsshPump]::StartInbound($input, $agent)

    while (-not $agent.Finished) {
        # Short poll, then drain everything queued: frames are discrete, and one item per
        # frame keeps the header unambiguous on the far side.
        $frame = $agent.TakeOutboundFrame(25)
        while ($null -ne $frame) {
            , $frame
            $frame = $agent.TakeOutboundFrame(0)
        }
        if ($EmitLog) {
            foreach ($line in $agent.DrainLog()) { Write-Warning $line }
        }
    }

    # Flush whatever was queued as the agent stopped.
    $frame = $agent.TakeOutboundFrame(0)
    while ($null -ne $frame) {
        , $frame
        $frame = $agent.TakeOutboundFrame(0)
    }

    if ($EmitLog) {
        foreach ($line in $agent.DrainLog()) { Write-Warning $line }
    }
}
finally {
    if ($agent) { try { $agent.Stop() } catch { } }
}
