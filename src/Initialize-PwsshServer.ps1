# Runs inside the remote runspace as the FIRST pipeline: compiles the engine and starts
# it, leaving it in $global:PwsshEngine for the streaming pipeline that follows.
#
# Why two pipelines: a script with a param() block makes PowerShell bind pipeline input to
# parameters, which fails for raw byte[] ("The input object cannot be bound to any
# parameters..."), so $input never receives the data. Parameters and streamed input cannot
# coexist on one invocation. This pipeline takes parameters and no input; PwsshPumpLoop.ps1
# takes input and no parameters. Runspace state persists between them.
#
# Nothing is written to the remote's disk and the host key stays in memory.

param(
    [Parameter(Mandatory = $true)][string]$CsSource,
    [Parameter(Mandatory = $true)][string]$HostKey,
    [Parameter(Mandatory = $true)][string]$CommonSource,
    [string]$ExpectedUser,
    # DEBUG ONLY. Remote warning records are surfaced to the client's host, which writes
    # them to the client's STDOUT and therefore corrupts the SSH stream. Never enable this
    # against a real ssh client.
    [switch]$EmitLog
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

. ([scriptblock]::Create($CommonSource))

Import-PwsshEngine -CsSource $CsSource

if ([string]::IsNullOrEmpty($ExpectedUser)) { $ExpectedUser = Get-PwsshCurrentUserName }

$cfg = New-Object Pwssh.PwsshConfig
$cfg.HostKey = $HostKey
$cfg.ExpectedUser = $ExpectedUser

$global:PwsshEmitLog = [bool]$EmitLog
$global:PwsshEngine = New-Object Pwssh.PwsshEngine $cfg
$global:PwsshEngine.Start()

# The only thing this pipeline emits, so the client can confirm startup.
"pwssh-ready user=$ExpectedUser"
