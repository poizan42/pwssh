# Shared helpers, used on the client only. This used to be pushed to the remote so it could
# compile the agent from source; the remote now loads a prebuilt assembly instead and needs
# nothing from here.

function Write-PwsshDiag([string]$Message) {
    # Never Write-Warning/Write-Output here. Under `pwsh -File` the warning stream is written
    # to STDOUT, which in a ProxyCommand corrupts the SSH stream. stderr is the only safe
    # diagnostic channel on the client; on the remote there is no console and it goes nowhere.
    try { [Console]::Error.WriteLine("[pwssh] $Message") } catch { }
}

function Get-PwsshAgentFiles {
    <#
      The agent's C# sources, in a stable order so the hash below is reproducible. The client
      compiles these together with the engine; the csproj compiles the same set for the remote.
    #>
    param([Parameter(Mandatory = $true)][string]$Repo)
    return Get-ChildItem -LiteralPath (Join-Path $Repo 'src\agent') -Filter '*.cs' -File |
        Sort-Object Name | ForEach-Object { $_.FullName }
}

function Get-PwsshAgentSourceHash {
    <#
      Identifies the agent sources so a built DLL can be checked against them. Content-based
      rather than mtime-based on purpose: a fresh clone or checkout changes every timestamp
      but not the code, and that must not invalidate a released DLL.
    #>
    param([Parameter(Mandatory = $true)][string]$Repo)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $ms = New-Object System.IO.MemoryStream
    foreach ($f in (Get-PwsshAgentFiles -Repo $Repo)) {
        # The name is included so that moving code between files is a change, not a no-op.
        $nameBytes = [System.Text.Encoding]::UTF8.GetBytes((Split-Path -Leaf $f) + "`0")
        $ms.Write($nameBytes, 0, $nameBytes.Length)
        # Line endings are normalised: git checkout settings must not change the hash.
        $text = ([System.IO.File]::ReadAllText($f)) -replace "`r`n", "`n"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        $ms.Write($bytes, 0, $bytes.Length)
    }
    $ms.Position = 0
    # BitConverter rather than Convert::ToHexString, which is .NET 5+: this file is also
    # dot-sourced on the remote under Windows PowerShell 5.1.
    return [BitConverter]::ToString($sha.ComputeHash($ms)).Replace('-', '').ToLowerInvariant()
}

function Get-PwsshAgentDllState {
    <#
      Locates the prebuilt agent DLL and reports whether it can be trusted. Returns an object
      with Path, State ('current' | 'missing' | 'stale' | 'unstamped') and Detail.

      'stale' is the case worth having: editing a .cs file and forgetting to rebuild would
      otherwise silently run old code on the remote. 'unstamped' is a DLL with no recorded
      hash -- taken from a release rather than built here -- which is accepted, because there
      is nothing to compare it against and the release is the authority.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Repo,
        [string]$DllPath
    )

    if (-not $DllPath) {
        # Where Build-Agent.ps1 leaves it, and where a release is meant to be unpacked.
        $candidates = @(
            (Join-Path $Repo 'src\agent\bin\Release\net48\PwsshAgent.dll'),
            (Join-Path $Repo 'src\agent\bin\Debug\net48\PwsshAgent.dll'),
            (Join-Path $Repo 'PwsshAgent.dll')
        )
        $DllPath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if (-not $DllPath) {
            return [pscustomobject]@{ Path = $candidates[0]; State = 'missing'; Detail = '' }
        }
    }
    elseif (-not (Test-Path -LiteralPath $DllPath)) {
        return [pscustomobject]@{ Path = $DllPath; State = 'missing'; Detail = '' }
    }

    $stampPath = "$DllPath.srchash"
    if (-not (Test-Path -LiteralPath $stampPath)) {
        return [pscustomobject]@{ Path = $DllPath; State = 'unstamped'; Detail = 'no .srchash beside the DLL' }
    }
    $stamped = ([System.IO.File]::ReadAllText($stampPath)).Trim()
    $actual = Get-PwsshAgentSourceHash -Repo $Repo
    if ($stamped -ne $actual) {
        return [pscustomobject]@{
            Path = $DllPath; State = 'stale'
            Detail = "built from $($stamped.Substring(0, 12))..., sources are now $($actual.Substring(0, 12))..."
        }
    }
    return [pscustomobject]@{ Path = $DllPath; State = 'current'; Detail = '' }
}

function Import-PwsshFiles {
    <#
      Compiles several C# files together for use in THIS process. PwsshEngine.cs depends on
      plumbing that lives in the agent sources, so they must be in one compilation.

      Note this is the client's own copy, compiled by PowerShell 7's Roslyn. It is unrelated to
      the net48 DLL pushed to the remote, which src/agent/PwsshAgent.csproj builds from the same
      sources -- two compilers, one set of sources.

      The result is cached as a DLL keyed on the sources' size and mtime: compiling costs
      ~1.1 s and is otherwise paid on every single connection, against ~0.3 s to load the
      cached assembly. Any failure falls back to compiling in memory.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$Path,
        [string]$ProbeType = 'Pwssh.PwsshEngine',
        [switch]$NoCache
    )

    if ($ProbeType -as [type]) { return }

    if (-not $NoCache) {
        try {
            $sb = New-Object System.Text.StringBuilder
            foreach ($p in ($Path | Sort-Object)) {
                $fi = Get-Item -LiteralPath $p -ErrorAction Stop
                [void]$sb.Append($fi.FullName).Append('|').Append($fi.Length).Append('|').Append($fi.LastWriteTimeUtc.Ticks).Append(';')
            }
            $md5 = [System.Security.Cryptography.MD5]::Create()
            $hash = ([BitConverter]::ToString($md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sb.ToString()))) -replace '-', '').Substring(0, 16)

            $cacheDir = Join-Path $env:LOCALAPPDATA 'pwssh\cache'
            $dll = Join-Path $cacheDir "pwssh-$hash.dll"

            if (Test-Path -LiteralPath $dll) {
                Add-Type -Path $dll -ErrorAction Stop
                return
            }

            if (-not (Test-Path -LiteralPath $cacheDir)) {
                New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
            }

            # Build under a private name and move into place, so concurrent connections cannot
            # load a half-written assembly or collide on the output file.
            $tmp = "$dll.$PID.tmp"
            Add-Type -Path $Path -OutputAssembly $tmp -ErrorAction Stop
            try { Move-Item -LiteralPath $tmp -Destination $dll -Force -ErrorAction Stop }
            catch { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

            Add-Type -Path $dll -ErrorAction Stop
            return
        }
        catch {
            Write-PwsshDiag "type cache unavailable ($($_.Exception.Message)); compiling in memory"
        }
    }

    Add-Type -Path $Path -ErrorAction Stop
}

function Get-PwsshHostKey {
    <#
      Returns the host key blob for a target, generating and persisting it on first use.
      Stability is the point: the SSH client pins the key in known_hosts and hard-fails on a
      mismatch, so a per-connection key would break every connection after the first.

      Note the key now stays on this machine -- SSH terminates locally -- so it authenticates
      the proxy rather than the remote host. known_hosts is ceremonial.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        return ([System.IO.File]::ReadAllText($Path)).Trim()
    }

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $blob = [Pwssh.PwsshKey]::Generate(2048)
    [System.IO.File]::WriteAllText($Path, $blob)

    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        # 3-argument overload: (identity, rights, accessControlType). The 5-argument form takes
        # the type LAST, with inheritance/propagation flags in between.
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        Write-PwsshDiag "could not restrict ACL on $Path : $($_.Exception.Message)"
    }

    return $blob
}
