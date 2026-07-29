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
    # The prebuilt net48 agent assembly to push. Defaults to the build output, then to a
    # PwsshAgent.dll dropped beside this script, which is where a release is meant to land.
    [string]$AgentDllPath,
    # Extra PSSessions used only to carry downstream frames. Each session gets its own WSMan
    # receive thread on this side, and that thread is the throughput ceiling; measured
    # downstream on incompressible data, 2 sessions ~2.7x and 4 sessions ~3.3x. Costs one
    # extra wsmprovhost per stream on the remote and ~1-2 s of setup each.
    [int]$Streams = 1,
    # Bulk-transfer window in MiB. Larger means fewer credit round trips on big transfers,
    # at the cost of how much the agent may buffer in this process before it has to wait.
    [int]$CreditMiB = 32,
    # How far ahead an SFTP download is fetched, in 255 KiB chunks; 0 turns read-ahead off.
    # A knob mainly so the effect can be settled by interleaved A/B rather than argued about.
    # 64 by measurement: 1.42x on 32 MiB, where 16 gave nothing at all and 128 gave less than
    # 64 because it asks for more than -CreditMiB allows to be in flight. Clamped to 128.
    [int]$SftpReadAheadChunks = 64,
    # Give up if the ssh client stops speaking for this long, so a ProxyCommand that outlives
    # its client cannot hold a WinRM shell open. The engine sends its own keepalive toward the
    # client, so an idle interactive session refreshes this and is never dropped by it.
    [int]$InactivityTimeoutSeconds = 300,
    # Testing hook: trip the SFTP read-ahead's safety valve part way through a transfer, once
    # this many KiB have been served from the buffer. Also readable as
    # PWSSH_SFTP_FAULT_AFTER_KIB, which is how the suite reaches it: ssh spawns this script
    # fresh per connection and it inherits the test's environment, so one test process can
    # exercise the valve without a second ssh_config alias to switch between.
    [int]$SftpFaultAfterKiB = 0,
    # Testing hook: force the no-ConPTY path, so pty-req is refused and the shell falls
    # back to pipes even on a remote that supports ConPTY.
    [switch]$DisableConPty,
    # Testing hook: turn off output read coalescing on the agent.
    [switch]$DisableCoalescing,
    # Honour a client-specified bind address for -R. Off by default, so a reverse forward
    # binds loopback on the remote rather than exposing it to the remote's network.
    [switch]$GatewayPorts,
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

    # The prebuilt agent assembly is located before anything else, because a missing or stale
    # one is a setup problem the user has to fix and there is no point starting a handshake
    # first. The remote gets this DLL; this process compiles the same sources itself below.
    $agentDllState = Get-PwsshAgentDllState -Repo $PSScriptRoot -DllPath $AgentDllPath
    switch ($agentDllState.State) {
        'missing' {
            throw ("pwssh: the agent assembly is missing. Build it once with " +
                   "'pwsh -File $PSScriptRoot\tools\Build-Agent.ps1', or take PwsshAgent.dll " +
                   "from a release and put it at $($agentDllState.Path).")
        }
        'stale' {
            throw ("pwssh: $($agentDllState.Path) was built from different sources " +
                   "($($agentDllState.Detail)). Rebuild with " +
                   "'pwsh -File $PSScriptRoot\tools\Build-Agent.ps1'.")
        }
    }
    $agentDll = [System.IO.File]::ReadAllBytes($agentDllState.Path)

    # The engine depends on plumbing that lives in the agent sources, so they compile together
    # here. This side is PowerShell 7, i.e. Roslyn, and the result is cached as a DLL.
    Import-PwsshFiles -Path (@(Get-PwsshAgentFiles -Repo $PSScriptRoot) + @("$PSScriptRoot\src\PwsshEngine.cs", "$PSScriptRoot\src\PwsshSftpReadAhead.cs"))

    if (-not $HostKeyDirectory) { $HostKeyDirectory = Join-Path $HOME '.pwssh\hostkeys' }
    $safeName = ($ComputerName.ToLowerInvariant() -replace '[^a-z0-9._-]', '_')
    $hostKey = Get-PwsshHostKey -Path (Join-Path $HostKeyDirectory $safeName)

    # --- start SSH immediately -------------------------------------------------
    # Before the session exists, so the handshake runs while WinRM is still connecting.
    $proxy = New-Object Pwssh.PwsshAgentProxy
    $cfg = New-Object Pwssh.PwsshConfig
    $cfg.HostKey = $hostKey
    $cfg.Agent = $proxy          # ExpectedUser is left unset: resolved from the agent's HELLO
    $cfg.AllowGatewayPorts = [bool]$GatewayPorts
    # The environment is consulted only when the parameter was not given, and exists for the same
    # reason the fault hook does: the suite drives an unmodified ssh_config and cannot add a second
    # alias per variation.
    $cfg.SftpReadAheadChunks =
        if ($PSBoundParameters.ContainsKey('SftpReadAheadChunks')) { $SftpReadAheadChunks }
        elseif ($null -ne $env:PWSSH_SFTP_READAHEAD_CHUNKS -and $env:PWSSH_SFTP_READAHEAD_CHUNKS -ne '') {
            [int]$env:PWSSH_SFTP_READAHEAD_CHUNKS
        }
        else { $SftpReadAheadChunks }
    $fault = if ($SftpFaultAfterKiB -gt 0) { $SftpFaultAfterKiB }
             elseif ($env:PWSSH_SFTP_FAULT_AFTER_KIB) { [int]$env:PWSSH_SFTP_FAULT_AFTER_KIB }
             else { 0 }
    $cfg.SftpFaultAfterKiB = $fault
    # As with the read-ahead knobs, the environment is consulted only when the parameter was not
    # given: the suite drives an unmodified ssh_config and cannot add an alias per variation, and
    # a five-minute idle is not something a test can wait out.
    $cfg.InactivityTimeoutSeconds =
        if ($PSBoundParameters.ContainsKey('InactivityTimeoutSeconds')) { $InactivityTimeoutSeconds }
        elseif ($null -ne $env:PWSSH_INACTIVITY_TIMEOUT_SECONDS -and $env:PWSSH_INACTIVITY_TIMEOUT_SECONDS -ne '') {
            [int]$env:PWSSH_INACTIVITY_TIMEOUT_SECONDS
        }
        else { $InactivityTimeoutSeconds }

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
    # Compression stays enabled -- it is the whole point of sending plaintext.
    #
    # IdleTimeout reclaims the shell, and it is not a theoretical case: ssh TerminateProcesses
    # its ProxyCommand on exit, so this script never gets to complete the remote pipeline or
    # remove the session, and every connection leaves an orphan behind. What releases the
    # remote's own resources -- child processes, -R listeners -- is the agent's inactivity
    # watchdog; this only cleans up the shell afterwards. 60 s rather than the 180 s used
    # before: a live client keeps a WSMan receive outstanding at all times, so it is never idle
    # and nothing here shortens a real session.
    $sp['SessionOption'] = New-PSSessionOption -IdleTimeout 60000

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $session = New-PSSession @sp
    Write-Diag ("session established in {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds)

    # --- start the remote agent ----------------------------------------------
    # Only the launcher script and the assembly go over: the remote no longer needs
    # PwsshCommon.ps1, because it no longer compiles anything.
    $agentScript = [System.IO.File]::ReadAllText("$PSScriptRoot\src\Start-PwsshAgent.ps1")

    $stripes = [Math]::Max(0, $Streams - 1)
    $pipePrefix = "pwssh-$([guid]::NewGuid().ToString('N'))"

    $ps = [PowerShell]::Create()
    $ps.Runspace = $session.Runspace
    $null = $ps.AddScript($agentScript)
    $null = $ps.AddParameter('AgentDll', $agentDll)
    if ($EmitRemoteLog) { $null = $ps.AddParameter('EmitLog', $true) }
    $null = $ps.AddParameter('CreditMiB', $CreditMiB)
    $null = $ps.AddParameter('DisableConPty', [bool]$DisableConPty)
    $null = $ps.AddParameter('DisableCoalescing', [bool]$DisableCoalescing)
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

        # The engine logs from several background threads into a bounded queue and cannot write
        # anywhere itself -- a scriptblock delegate invoked off its runspace would throw. Nothing
        # drained it on this path until now, so every engine diagnostic was discarded; the dev
        # host was the only place they were ever visible. Draining here routes them to -LogFile
        # and to -Diagnostics like everything else.
        if ($Diagnostics -or $LogFile) {
            foreach ($line in $engine.DrainLog()) { Write-Diag $line }
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
