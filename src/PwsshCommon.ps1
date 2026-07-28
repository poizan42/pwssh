# Shared helpers. Also sent to the remote as script text, so nothing here may depend on
# anything existing on the remote's disk.

function Write-PwsshDiag([string]$Message) {
    # Never Write-Warning/Write-Output here. Under `pwsh -File` the warning stream is written
    # to STDOUT, which in a ProxyCommand corrupts the SSH stream. stderr is the only safe
    # diagnostic channel on the client; on the remote there is no console and it goes nowhere.
    try { [Console]::Error.WriteLine("[pwssh] $Message") } catch { }
}

function Import-PwsshSource {
    <#
      Compiles one C# source string. Used by the remote, which can only ever compile a single
      string: an in-memory Add-Type assembly has no Location for a second compilation to
      reference. Windows PowerShell needs System.Numerics/System.Core named explicitly;
      PowerShell 7 resolves them from its default set, and passing -ReferencedAssemblies there
      would *replace* that set rather than extend it.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$CsSource,
        [string]$ProbeType = 'Pwssh.PwsshAgentHost'
    )

    if ($ProbeType -as [type]) { return }

    $isDesktop = ($PSVersionTable.PSEdition -eq 'Desktop') -or (-not $PSVersionTable.PSEdition)
    if ($isDesktop) {
        Add-Type -TypeDefinition $CsSource -ReferencedAssemblies 'System.Numerics', 'System.Core', 'System', 'System.IO.Compression' -ErrorAction Stop
    }
    else {
        Add-Type -TypeDefinition $CsSource -ErrorAction Stop
    }
}

function Import-PwsshFiles {
    <#
      Compiles several C# files together. Only usable where the files exist on disk, i.e. the
      client. PwsshEngine.cs depends on plumbing that lives in PwsshAgent.cs, so both must be
      in one compilation.

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
