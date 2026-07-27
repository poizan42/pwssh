# Shared helpers, used by both the client and the remote server. Sent to the remote as
# script text, so it must not depend on anything existing on the remote's disk.

function Write-PwsshDiag([string]$Message) {
    # Never Write-Warning/Write-Output here. Under `pwsh -File` the warning stream is
    # written to STDOUT, which in a ProxyCommand corrupts the SSH stream. stderr is the
    # only safe diagnostic channel on the client; on the remote there is no console and
    # the write simply goes nowhere.
    try { [Console]::Error.WriteLine("[pwssh] $Message") } catch { }
}

function Import-PwsshEngine {
    <#
      Compiles the engine. Reference sets differ: Windows PowerShell 5.1 uses the
      CodeDOM compiler and needs System.Numerics/System.Core named explicitly,
      while PowerShell 7 (Roslyn) resolves them from its default set.
    #>
    param([Parameter(Mandatory = $true)][string]$CsSource)

    if ('Pwssh.PwsshEngine' -as [type]) { return }

    $isDesktop = ($PSVersionTable.PSEdition -eq 'Desktop') -or (-not $PSVersionTable.PSEdition)
    if ($isDesktop) {
        Add-Type -TypeDefinition $CsSource -ReferencedAssemblies 'System.Numerics', 'System.Core', 'System' -ErrorAction Stop
    }
    else {
        Add-Type -TypeDefinition $CsSource -ErrorAction Stop
    }
}

function Get-PwsshHostKey {
    <#
      Returns the host key blob for a target, generating and persisting it on first use.
      Stability is the point: the SSH client caches the key in known_hosts and hard-fails
      on a mismatch, so a per-connection key would break every connection after the first.
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

    # Private key on disk: restrict to the current user. Not security-critical here
    # (WinRM provides the real protection) but there is no reason to leave it readable.
    try {
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        # 3-argument overload: (identity, rights, accessControlType). The 5-argument form
        # takes the type LAST, with inheritance/propagation flags in between.
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')
        $acl.SetAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    catch {
        Write-PwsshDiag "could not restrict ACL on $Path : $($_.Exception.Message)"
    }

    return $blob
}

function Get-PwsshCurrentUserName {
    # sAMAccountName of the account we are running as; what the SSH username must match.
    $full = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $bs = $full.LastIndexOf('\')
    if ($bs -ge 0) { return $full.Substring($bs + 1) }
    return $full
}
