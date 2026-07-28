<#
.SYNOPSIS
    ssh ProxyCommand that reaches a host over PowerShell remoting (WinRM).
.DESCRIPTION
    SSH terminates HERE, in this script. ssh hands us the protocol on stdin/stdout, the engine
    runs locally, and only plaintext agent frames cross the WinRM link. That is deliberate:

      * the handshake's ~10 round trips become local instead of ~600-900 ms each;
      * the WinRM payload is compressible, which WinRM already does (~29x measured);
      * the remote does no cryptography at all, so it needs nothing but process plumbing.

    Security is unchanged, because it was never provided by the SSH layer: WinRM authenticates
    and encrypts the hop. One consequence worth knowing: the host key now identifies this
    proxy, not the remote machine, so known_hosts is ceremonial.

    stdout carries protocol bytes ONLY. All diagnostics go to stderr or -LogFile; a stray
    Write-Output here corrupts the SSH stream.
.EXAMPLE
    Host myremote
        User myuser
        ProxyCommand pwsh -NonInteractive -NoProfile -NoLogo -File C:/path/pwssh-connect.ps1 -ComputerName myremote -CredentialPath C:/path/cred.xml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    # Path to an Export-CliXml'd credential. Lets ProxyCommand avoid a nested PowerShell
    # expression, which quotes badly through cmd.exe.
    [string]$CredentialPath,
    [string]$Authentication = 'Negotiate',
    [int]$Port,
    [switch]$UseSSL,
    [string]$ConfigurationName,
    [string]$HostKeyDirectory,
    # Extra PSSessions used only to carry downstream frames. Each session gets its own WSMan
    # receive thread on this side, and that thread is the throughput ceiling; measured
    # downstream on incompressible data, 2 sessions ~2.7x and 4 sessions ~3.3x. Costs one
    # extra wsmprovhost per stream on the remote and ~1-2 s of setup each.
    [int]$Streams = 1,
    [string]$LogFile,
    # Progress messages on stderr. Off by default: ssh shows the ProxyCommand's stderr
    # directly in the user's terminal, so it would be noise on every connection.
    [switch]$Diagnostics,
    # DEBUG ONLY: remote warnings are surfaced to this process's stdout by the host, which
    # corrupts the SSH stream. Use only with a probe harness, never with a real ssh client.
    [switch]$EmitRemoteLog
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# stdout belongs to the SSH protocol. Under `pwsh -File` the warning, verbose and information
# streams are written to STDOUT, so they are silenced outright.
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

function Write-Diag([string]$Message) {
    $line = "[pwssh] $Message"
    if ($Diagnostics -or $EmitRemoteLog) {
        try { [Console]::Error.WriteLine($line) } catch { }
    }
    if ($LogFile) {
        try { Add-Content -LiteralPath $LogFile -Value "$([DateTime]::Now.ToString('HH:mm:ss.fff')) $line" } catch { }
    }
}

# Failures are always reported: ssh will otherwise just say the connection closed.
function Write-Fatal([string]$Message) {
    try { [Console]::Error.WriteLine("[pwssh] $Message") } catch { }
    if ($LogFile) {
        try { Add-Content -LiteralPath $LogFile -Value "$([DateTime]::Now.ToString('HH:mm:ss.fff')) [pwssh] $Message" } catch { }
    }
}

$session = $null
$ps = $null
$inColl = $null
$engine = $null
$mules = @()

try {
    . "$PSScriptRoot\src\PwsshCommon.ps1"

    # PwsshEngine.cs depends on plumbing that lives in PwsshAgent.cs, so both compile together.
    Import-PwsshFiles -Path @("$PSScriptRoot\src\PwsshAgent.cs", "$PSScriptRoot\src\PwsshEngine.cs")

    if (-not $HostKeyDirectory) { $HostKeyDirectory = Join-Path $HOME '.pwssh\hostkeys' }
    $safeName = ($ComputerName.ToLowerInvariant() -replace '[^a-z0-9._-]', '_')
    $hostKey = Get-PwsshHostKey -Path (Join-Path $HostKeyDirectory $safeName)

    # --- start SSH immediately -------------------------------------------------
    # Before the session exists, so the handshake runs while WinRM is still connecting.
    $proxy = New-Object Pwssh.PwsshAgentProxy
    $cfg = New-Object Pwssh.PwsshConfig
    $cfg.HostKey = $hostKey
    $cfg.Agent = $proxy          # ExpectedUser is left unset: resolved from the agent's HELLO

    $engine = New-Object Pwssh.PwsshEngine $cfg
    $engine.Start()
    [Pwssh.PwsshStdioBridge]::Start($engine, 32768)
    Write-Diag 'ssh engine started'

    # --- open the session -----------------------------------------------------
    if (-not $Credential -and $CredentialPath) {
        $Credential = Import-CliXml -LiteralPath $CredentialPath
    }

    $sp = @{ ComputerName = $ComputerName; Authentication = $Authentication }
    if ($Credential) { $sp['Credential'] = $Credential }
    if ($Port) { $sp['Port'] = $Port }
    if ($UseSSL) { $sp['UseSSL'] = $true }
    if ($ConfigurationName) { $sp['ConfigurationName'] = $ConfigurationName }
    # Compression stays enabled -- it is the whole point of sending plaintext. IdleTimeout
    # bounds orphan cleanup if this client dies before closing the link.
    $sp['SessionOption'] = New-PSSessionOption -IdleTimeout 180000

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $session = New-PSSession @sp
    Write-Diag ("session established in {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds)

    # --- start the remote agent ----------------------------------------------
    $commonSource = [System.IO.File]::ReadAllText("$PSScriptRoot\src\PwsshCommon.ps1")
    $agentSource = [System.IO.File]::ReadAllText("$PSScriptRoot\src\PwsshAgent.cs")
    $agentScript = [System.IO.File]::ReadAllText("$PSScriptRoot\src\Start-PwsshAgent.ps1")

    $stripes = [Math]::Max(0, $Streams - 1)
    $pipePrefix = "pwssh-$([guid]::NewGuid().ToString('N'))"

    $ps = [PowerShell]::Create()
    $ps.Runspace = $session.Runspace
    $null = $ps.AddScript($agentScript)
    $null = $ps.AddParameter('CsSource', $agentSource)
    $null = $ps.AddParameter('CommonSource', $commonSource)
    if ($EmitRemoteLog) { $null = $ps.AddParameter('EmitLog', $true) }
    if ($stripes -gt 0) {
        $null = $ps.AddParameter('PipePrefix', $pipePrefix)
        $null = $ps.AddParameter('Stripes', $stripes)
    }

    $inColl = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $outColl = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $handle = $ps.BeginInvoke($inColl, $outColl)

    # --- mule sessions --------------------------------------------------------
    # Receive-only: they relay frames the agent pushes down a named pipe. Everything the
    # client sends still goes to the primary session, so only one ordering problem exists
    # and the resequencer below solves it.
    $muleScript = [System.IO.File]::ReadAllText("$PSScriptRoot\src\Start-PwsshMule.ps1")
    $mules = @()
    for ($i = 0; $i -lt $stripes; $i++) {
        try {
            $ms = New-PSSession @sp
            $mps = [PowerShell]::Create()
            $mps.Runspace = $ms.Runspace
            $null = $mps.AddScript($muleScript)
            $null = $mps.AddParameter('PipeName', "$pipePrefix-$i")
            $mOut = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
            $mHandle = $mps.BeginInvoke((New-Object 'System.Management.Automation.PSDataCollection[psobject]'), $mOut)
            $mules += [pscustomobject]@{ Session = $ms; PS = $mps; Out = $mOut; Handle = $mHandle }
        }
        catch {
            # A mule is an optimisation, never a requirement: the agent falls back to the
            # primary session for any stripe that never connects.
            Write-Diag "mule $i unavailable: $($_.Exception.Message)"
        }
    }
    if ($stripes -gt 0) { Write-Diag "streams: 1 primary + $($mules.Count) mule(s)" }

    $reseq = New-Object Pwssh.FrameResequencer

    # --- shuttle agent frames -------------------------------------------------
    # ssh <-> engine is handled by PwsshStdioBridge on its own threads, so this loop only
    # moves frames between the proxy and the remoting collections. One item per frame.
    $frameEof = $false
    while ($true) {
        $did = $false

        if (-not $frameEof) {
            $f = $proxy.TakeOutboundFrame(0)
            while ($null -ne $f) {
                $inColl.Add([psobject]$f)
                $did = $true
                $f = $proxy.TakeOutboundFrame(0)
            }
        }

        # Frames arrive from the primary and from every mule. Each path is FIFO but they
        # interleave, so delivery order comes from the sequence numbers, not arrival order.
        $items = $outColl.ReadAll()
        foreach ($m in $mules) {
            $mi = $m.Out.ReadAll()
            if ($mi.Count -gt 0) { $items = @($items) + @($mi) }
        }
        if ($items.Count -gt 0) {
            foreach ($it in $items) {
                $bytes = $it.psobject.BaseObject -as [byte[]]
                if ($bytes) {
                    foreach ($f in $reseq.Accept($bytes)) { $proxy.PushInbound($f) }
                }
            }
            $did = $true
        }

        if ($ps.Streams.Error.Count -gt 0) {
            foreach ($e in $ps.Streams.Error.ReadAll()) { Write-Fatal "remote error: $($e.Exception.Message)" }
        }
        if ($ps.Streams.Warning.Count -gt 0) {
            foreach ($w in $ps.Streams.Warning.ReadAll()) { Write-Diag "remote: $w" }
        }

        # The engine finishing is the real end of the conversation; tell the agent so its
        # pipeline can complete, then leave once the remote side is done.
        if ($engine.Finished -and -not $frameEof) {
            $frameEof = $true
            # Never Add after Complete: that race throws inside Fragmentor.Fragment on a
            # background thread and takes the whole process down.
            try { $inColl.Complete() } catch { }
            Write-Diag 'engine finished; input completed'
        }

        if ($handle.IsCompleted -and $items.Count -eq 0) { break }
        if (-not $did) { [System.Threading.Thread]::Sleep(5) }
    }

    Write-Diag 'remote pipeline completed'
    foreach ($e in $ps.Streams.Error) { Write-Fatal "remote error: $($e.Exception.Message)" }
    if ($ps.InvocationStateInfo.Reason) {
        Write-Fatal "remote pipeline failed: $($ps.InvocationStateInfo.Reason.Message)"
    }
    if ($engine.LastError) { Write-Fatal "engine error: $($engine.LastError)" }
}
catch {
    Write-Fatal "fatal: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($engine) { try { $engine.Stop() } catch { } }
    if ($inColl) { try { $inColl.Complete() } catch { } }
    if ($ps) {
        try { if ($handle -and -not $handle.IsCompleted) { $ps.Stop() } } catch { }
        try { $ps.Dispose() } catch { }
    }
    foreach ($m in $mules) {
        try { if ($m.Handle -and -not $m.Handle.IsCompleted) { $m.PS.Stop() } } catch { }
        try { $m.PS.Dispose() } catch { }
        try { Remove-PSSession $m.Session } catch { }
    }
    if ($session) { try { Remove-PSSession $session } catch { } }
}
