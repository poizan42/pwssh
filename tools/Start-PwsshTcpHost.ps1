<#
.SYNOPSIS
    Development harness: serves pwssh over loopback TCP so the protocol can be tested
    against the real ssh client without WinRM.
.DESCRIPTION
    Binds 127.0.0.1 only. This is a development tool, not part of the ProxyCommand path.
    Authentication is the same username check the real server uses, so it accepts only
    the account it is running as.
#>
[CmdletBinding()]
param(
    [int]$Port = 2222,
    [string]$HostKeyPath,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. "$repo\src\PwsshCommon.ps1"

if (-not $HostKeyPath) { $HostKeyPath = Join-Path $PSScriptRoot '.devhostkey' }

# Both sources must be compiled together: the dev host references engine types, and an
# in-memory Add-Type assembly has no Location to reference from a second compilation.
Add-Type -Path @("$repo\src\PwsshEngine.cs", "$PSScriptRoot\PwsshTcpHost.cs") -ErrorAction Stop

$key = Get-PwsshHostKey -Path $HostKeyPath
$user = Get-PwsshCurrentUserName

Write-Host "pwssh dev host: 127.0.0.1:$Port  user=$user  hostkey=$HostKeyPath"
[Pwssh.Dev.TcpHost]::Run($Port, $key, $user, (-not $Quiet))
