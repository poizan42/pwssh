<#
.SYNOPSIS
    ssh ProxyCommand that carries the SSH stream over PowerShell remoting (WinRM).
.DESCRIPTION
    ssh hands this script the SSH protocol on stdin/stdout. The stream is relayed to a
    PSSession, where the pwssh engine runs entirely in memory. Nothing is written to the
    remote's disk.

    stdout carries protocol bytes ONLY. All diagnostics go to stderr or -LogFile; a
    stray Write-Output here corrupts the SSH stream.
.EXAMPLE
    Host myremote
        User myuser
        ProxyCommand pwsh -NonInteractive -NoProfile -NoLogo -Command "& C:/path/pwssh-connect.ps1 -ComputerName myremote -Credential (Import-CliXml C:/path/cred.xml) -Authentication Negotiate"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ComputerName,
    [System.Management.Automation.PSCredential]$Credential,
    # Path to an Export-CliXml'd credential. Lets ProxyCommand avoid a nested
    # PowerShell expression, which quotes badly through cmd.exe.
    [string]$CredentialPath,
    [string]$Authentication = 'Negotiate',
    [int]$Port,
    [switch]$UseSSL,
    [string]$ConfigurationName,
    [string]$HostKeyDirectory,
    [string]$LogFile,
    # Progress messages on stderr. Off by default: ssh shows the ProxyCommand's stderr
    # directly in the user's terminal, so it would be noise on every connection.
    [switch]$Diagnostics,
    # DEBUG ONLY: remote warnings are surfaced to this process's stdout by the host, which
    # corrupts the SSH stream. Use only with the probe harness, never with a real ssh client.
    [switch]$EmitRemoteLog
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

# stdout belongs to the SSH protocol. Under `pwsh -File` the warning, verbose and
# information streams are written to STDOUT, so they are silenced outright; every
# diagnostic goes through Write-Diag to stderr instead.
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

try {
    . "$PSScriptRoot\src\PwsshCommon.ps1"

    $engineSource = [System.IO.File]::ReadAllText("$PSScriptRoot\src\PwsshEngine.cs")

    # Compiled locally for the host key helpers and the stdin reader thread.
    Import-PwsshEngine -CsSource $engineSource

    if (-not $HostKeyDirectory) {
        $HostKeyDirectory = Join-Path $HOME '.pwssh\hostkeys'
    }
    $safeName = ($ComputerName.ToLowerInvariant() -replace '[^a-z0-9._-]', '_')
    $hostKeyPath = Join-Path $HostKeyDirectory $safeName
    $hostKey = Get-PwsshHostKey -Path $hostKeyPath
    Write-Diag "host key: $hostKeyPath"

    # --- open the session -----------------------------------------------------
    if (-not $Credential -and $CredentialPath) {
        $Credential = Import-CliXml -LiteralPath $CredentialPath
        Write-Diag "credential loaded from $CredentialPath"
    }

    $sp = @{ ComputerName = $ComputerName; Authentication = $Authentication }
    if ($Credential) { $sp['Credential'] = $Credential }
    if ($Port) { $sp['Port'] = $Port }
    if ($UseSSL) { $sp['UseSSL'] = $true }
    if ($ConfigurationName) { $sp['ConfigurationName'] = $ConfigurationName }
    # Compression stays enabled: disabling it measured 13x worse downstream throughput.
    # IdleTimeout bounds orphan cleanup: if this client dies, the remote pump never sees
    # input EOF and would hold a WinRM shell for the 2-hour default.
    $sp['SessionOption'] = New-PSSessionOption -IdleTimeout 180000

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $session = New-PSSession @sp
    Write-Diag ("session established in {0:N0} ms" -f $sw.Elapsed.TotalMilliseconds)

    # --- start the remote server ---------------------------------------------
    # Two pipelines on the same runspace. Parameters and streamed pipeline input cannot
    # coexist on one invocation: a param() block makes PowerShell bind the input objects to
    # parameters, which fails for raw byte[] and leaves $input empty. So initialisation
    # takes parameters with no input, and the pump takes input with no parameters.
    $commonSource = [System.IO.File]::ReadAllText("$PSScriptRoot\src\PwsshCommon.ps1")
    $initScript = [System.IO.File]::ReadAllText("$PSScriptRoot\src\Initialize-PwsshServer.ps1")
    $pumpScript = [System.IO.File]::ReadAllText("$PSScriptRoot\src\PwsshPumpLoop.ps1")

    $init = [PowerShell]::Create()
    try {
        $init.Runspace = $session.Runspace
        $null = $init.AddScript($initScript)
        $null = $init.AddParameter('CsSource', $engineSource)
        $null = $init.AddParameter('HostKey', $hostKey)
        $null = $init.AddParameter('CommonSource', $commonSource)
        if ($EmitRemoteLog) { $null = $init.AddParameter('EmitLog', $true) }
        $ready = $init.Invoke()
        foreach ($e in $init.Streams.Error) { Write-Diag "remote init error: $($e.Exception.Message)" }
        if ($init.Streams.Error.Count -gt 0) { throw 'remote initialisation failed' }
        Write-Diag "remote: $($ready -join ' ')"
    }
    finally { try { $init.Dispose() } catch { } }

    $ps = [PowerShell]::Create()
    $ps.Runspace = $session.Runspace
    $null = $ps.AddScript($pumpScript)

    $inColl = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $outColl = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $handle = $ps.BeginInvoke($inColl, $outColl)

    # --- pump ----------------------------------------------------------------
    # C# owns only the blocking stdin read; both hand-offs happen here so that no
    # PSDataCollection reference is needed from C# (which caused type-forwarding
    # conflicts between the reference and implementation assemblies on PS 7).
    [Pwssh.PwsshStdin]::Start(32768)
    $stdout = [Console]::OpenStandardOutput()
    $stdinDone = $false

    while ($true) {
        $did = $false

        if (-not $stdinDone) {
            $b = [Pwssh.PwsshStdin]::TakeAll(0)
            if ($null -ne $b -and $b.Length -gt 0) {
                $inColl.Add([psobject]$b)
                $did = $true
            }
            elseif ([Pwssh.PwsshStdin]::Eof) {
                $stdinDone = $true
                $inColl.Complete()          # EOF signalled by Complete(), never a sentinel
                Write-Diag 'stdin EOF'
            }
        }

        $items = $outColl.ReadAll()
        if ($items.Count -gt 0) {
            foreach ($it in $items) {
                $bytes = $it.psobject.BaseObject -as [byte[]]
                if ($bytes) { $stdout.Write($bytes, 0, $bytes.Length) }
            }
            $stdout.Flush()
            $did = $true
        }

        # Drained inline rather than via Register-ObjectEvent: an -Action handler only
        # runs when the pipeline is idle, and this loop never is.
        if ($ps.Streams.Warning.Count -gt 0) {
            foreach ($w in $ps.Streams.Warning.ReadAll()) { Write-Diag "remote: $w" }
        }

        if ($handle.IsCompleted -and $items.Count -eq 0) { break }
        if (-not $did) { [System.Threading.Thread]::Sleep(5) }
    }

    Write-Diag 'remote pipeline completed'
}
catch {
    Write-Fatal "fatal: $($_.Exception.Message)"
    exit 1
}
finally {
    try { [Pwssh.Client.StdioPump]::Stop() } catch { }
    # Never Add after Complete: that race throws inside Fragmentor.Fragment on a
    # background thread and takes the whole process down.
    if ($inColl) { try { $inColl.Complete() } catch { } }
    if ($ps) {
        try { if ($handle -and -not $handle.IsCompleted) { $ps.Stop() } } catch { }
        try { $ps.Dispose() } catch { }
    }
    if ($session) { try { Remove-PSSession $session } catch { } }
}
