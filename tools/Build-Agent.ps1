<#
.SYNOPSIS
    Builds the remote agent into a .NET Framework 4.8 DLL.
.DESCRIPTION
    The client pushes this DLL to the remote as bytes and loads it there with
    Assembly.Load, which is worth ~480 ms of every connection over compiling the source
    remotely with CodeDOM, and lets the agent be written in C# 7.3 across several files
    instead of C# 5 in one.

    Requires the .NET SDK and the 4.8 targeting pack. If you would rather not build, take
    the DLL from a release; the client looks in the same place either way.

    Alongside the DLL this writes PwsshAgent.dll.srchash, a hash of the sources it was
    built from. The client compares it against the sources on disk and refuses to run a
    DLL that no longer matches -- otherwise editing a .cs file and forgetting to rebuild
    silently runs stale code on the remote, which is a miserable thing to debug.
.EXAMPLE
    pwsh -NoProfile -File .\tools\Build-Agent.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',
    # Print what would happen and check whether the existing DLL is current, without building.
    [switch]$CheckOnly
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
. "$repo\src\PwsshCommon.ps1"

$proj = Join-Path $repo 'src\agent\PwsshAgent.csproj'
$outDir = Join-Path $repo "src\agent\bin\$Configuration\net48"
$dll = Join-Path $outDir 'PwsshAgent.dll'

$expected = Get-PwsshAgentSourceHash -Repo $repo
Write-Host "agent sources hash: $expected"

if ($CheckOnly) {
    $state = Get-PwsshAgentDllState -Repo $repo
    Write-Host "dll: $($state.Path)"
    Write-Host "state: $($state.State)$(if ($state.Detail) { " -- $($state.Detail)" })"
    if ($state.State -ne 'current') { exit 1 }
    exit 0
}

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'The .NET SDK is required to build the agent. Install it, or take PwsshAgent.dll from a release.'
}

Write-Host "building $proj ($Configuration)"
& dotnet build $proj -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet build failed with exit code $LASTEXITCODE" }
if (-not (Test-Path -LiteralPath $dll)) { throw "build reported success but $dll is missing" }

Set-Content -LiteralPath "$dll.srchash" -Value $expected -Encoding ascii -NoNewline
$len = (Get-Item -LiteralPath $dll).Length
Write-Host "built $dll ($len bytes), stamped with the source hash" -ForegroundColor Green
