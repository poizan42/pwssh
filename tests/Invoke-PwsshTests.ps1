<#
.SYNOPSIS
    End-to-end tests driven through the real ssh client.
.DESCRIPTION
    Works against either transport:
      TCP dev host : -Target "$env:USERNAME@127.0.0.1" -Port 2222
      WinRM        : -Target pwssh-test            (ProxyCommand from ~/.ssh/config)
    Payloads are generated on the far side via powershell -EncodedCommand, which avoids
    all shell quoting and needs no pre-existing files on the remote.
#>
[CmdletBinding()]
param(
    [string]$Target = "$env:USERNAME@127.0.0.1",
    [int]$Port = 2222,
    [string]$KnownHostsFile = 'tmp/known_hosts',
    [string]$ConfigFile,
    [switch]$SkipLarge
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $repo $KnownHostsFile)) -Force | Out-Null

$script:pass = 0
$script:fail = 0

function Get-SshArgs([string]$Command) {
    $a = New-Object System.Collections.Generic.List[string]
    if ($ConfigFile) { $a.Add('-F'); $a.Add($ConfigFile) }
    if ($Port -gt 0) { $a.Add('-p'); $a.Add("$Port") }
    $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
    $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
    $a.Add('-o'); $a.Add('BatchMode=yes')
    $a.Add('-o'); $a.Add('ConnectTimeout=20')
    $a.Add($Target)
    $a.Add($Command)
    return $a
}

# ssh is driven via Process so stdout can be read as raw bytes; PowerShell's own
# redirection would decode it as text and destroy binary payloads.
function Invoke-Ssh {
    param([string]$Command, [byte[]]$StdinBytes)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'ssh'
    foreach ($a in (Get-SshArgs $Command)) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    $outMs = New-Object System.IO.MemoryStream
    $outTask = $p.StandardOutput.BaseStream.CopyToAsync($outMs)
    $errTask = $p.StandardError.ReadToEndAsync()

    if ($StdinBytes) { $p.StandardInput.BaseStream.Write($StdinBytes, 0, $StdinBytes.Length) }
    $p.StandardInput.BaseStream.Flush()
    $p.StandardInput.BaseStream.Close()

    if (-not $p.WaitForExit(180000)) { try { $p.Kill() } catch {}; throw 'ssh timed out' }
    $outTask.Wait(); $null = $errTask.Result

    [pscustomobject]@{
        ExitCode = $p.ExitCode
        Stdout   = $outMs.ToArray()
        Stderr   = $errTask.Result
    }
}

function Get-Sha([byte[]]$b) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return [Convert]::ToBase64String($sha.ComputeHash($b))
}

function New-FarSideCommand([string]$Script) {
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Script))
    return "powershell -NoProfile -NonInteractive -EncodedCommand $enc"
}

function Assert-That([string]$Name, [bool]$Condition, [string]$Detail) {
    if ($Condition) {
        $script:pass++
        Write-Host ("  PASS  {0}" -f $Name) -ForegroundColor Green
    }
    else {
        $script:fail++
        Write-Host ("  FAIL  {0}" -f $Name) -ForegroundColor Red
        if ($Detail) { Write-Host ("        {0}" -f $Detail) -ForegroundColor DarkYellow }
    }
}

Write-Host "pwssh tests -> target '$Target'$(if ($Port -gt 0) { " port $Port" })" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. basic exec
$r = Invoke-Ssh -Command 'echo hello'
$txt = [System.Text.Encoding]::ASCII.GetString($r.Stdout).Trim()
Assert-That 'exec returns stdout' ($txt -eq 'hello') "got '$txt' exit=$($r.ExitCode) stderr=$($r.Stderr)"
Assert-That 'exec exit code 0' ($r.ExitCode -eq 0) "exit=$($r.ExitCode)"

# ------------------------------------------------------------ 2. exit status
$r = Invoke-Ssh -Command 'exit 3'
Assert-That 'exit status propagates' ($r.ExitCode -eq 3) "exit=$($r.ExitCode) stderr=$($r.Stderr)"

# --------------------------------------------------------- 3. stderr separation
$r = Invoke-Ssh -Command 'echo oops 1>&2'
$so = [System.Text.Encoding]::ASCII.GetString($r.Stdout).Trim()
Assert-That 'stderr routed to stderr' ($r.Stderr -match 'oops') "stderr='$($r.Stderr)'"
Assert-That 'stderr not mixed into stdout' ($so -eq '') "stdout='$so'"

# ------------------------------------------------------- 4. binary fidelity
$size = 65536
$expected = New-Object byte[] $size
for ($i = 0; $i -lt $size; $i++) { $expected[$i] = $i % 256 }
$gen = @"
`$b = New-Object byte[] $size
for (`$i = 0; `$i -lt `$b.Length; `$i++) { `$b[`$i] = `$i % 256 }
`$o = [Console]::OpenStandardOutput()
`$o.Write(`$b, 0, `$b.Length)
`$o.Flush()
"@
$r = Invoke-Ssh -Command (New-FarSideCommand $gen)
Assert-That 'binary length exact (64 KiB, all byte values)' ($r.Stdout.Length -eq $size) `
    "got $($r.Stdout.Length) expected $size stderr=$($r.Stderr)"
Assert-That 'binary content bit-exact' ((Get-Sha $r.Stdout) -eq (Get-Sha $expected)) `
    "sha mismatch; got $($r.Stdout.Length) bytes"

# ------------------------------------------------------------- 5. stdin inbound
$inBytes = New-Object byte[] 65536
(New-Object Random 11).NextBytes($inBytes)
$inSha = Get-Sha $inBytes
$sink = @"
`$i = [Console]::OpenStandardInput()
`$ms = New-Object System.IO.MemoryStream
`$buf = New-Object byte[] 16384
while ((`$n = `$i.Read(`$buf, 0, `$buf.Length)) -gt 0) { `$ms.Write(`$buf, 0, `$n) }
`$sha = [System.Security.Cryptography.SHA256]::Create()
[Console]::Out.Write([Convert]::ToBase64String(`$sha.ComputeHash(`$ms.ToArray())))
"@
$r = Invoke-Ssh -Command (New-FarSideCommand $sink) -StdinBytes $inBytes
$got = [System.Text.Encoding]::ASCII.GetString($r.Stdout).Trim()
Assert-That 'stdin delivered bit-exact (64 KiB)' ($got -eq $inSha) "far side hash '$got' expected '$inSha' stderr=$($r.Stderr)"

# -------------------------------------------- 6. payload larger than the window
if (-not $SkipLarge) {
    $big = 8 * 1024 * 1024      # > 2 MiB initial window, so WINDOW_ADJUST must work
    $genBig = @"
`$chunk = New-Object byte[] 65536
for (`$i = 0; `$i -lt `$chunk.Length; `$i++) { `$chunk[`$i] = `$i % 251 }
`$o = [Console]::OpenStandardOutput()
for (`$k = 0; `$k -lt $($big / 65536); `$k++) { `$o.Write(`$chunk, 0, `$chunk.Length) }
`$o.Flush()
"@
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Ssh -Command (New-FarSideCommand $genBig)
    $sw.Stop()

    $chunk = New-Object byte[] 65536
    for ($i = 0; $i -lt 65536; $i++) { $chunk[$i] = $i % 251 }
    $exp = New-Object System.IO.MemoryStream
    for ($k = 0; $k -lt ($big / 65536); $k++) { $exp.Write($chunk, 0, $chunk.Length) }

    Assert-That 'payload beyond initial window completes (8 MiB)' ($r.Stdout.Length -eq $big) `
        "got $($r.Stdout.Length) expected $big stderr=$($r.Stderr)"
    Assert-That '8 MiB content bit-exact' ((Get-Sha $r.Stdout) -eq (Get-Sha $exp.ToArray())) 'sha mismatch'
    Write-Host ("        throughput: {0:N2} MiB/s" -f (8 / $sw.Elapsed.TotalSeconds)) -ForegroundColor DarkGray
}

# --------------------------------------------------------- 7. username rejected
$saved = $Target
$Target = "definitelynotthisuser@$($Target.Split('@')[-1])"
if ($saved -notmatch '@') { $Target = $saved }   # WinRM alias: user comes from ssh_config
if ($Target -ne $saved) {
    $r = Invoke-Ssh -Command 'echo nope'
    Assert-That 'wrong username is rejected' ($r.ExitCode -ne 0) "exit=$($r.ExitCode)"
}
$Target = $saved

Write-Host ''
Write-Host ("passed {0}, failed {1}" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail -gt 0) { exit 1 }
