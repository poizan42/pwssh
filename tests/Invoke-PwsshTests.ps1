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
    # Optional second target whose agent runs with -DisableConPty, so the graceful-degradation
    # path can be exercised on a remote that does support ConPTY.
    [string]$DegradedTarget,
    [string]$DegradedConfigFile,
    # host:port that is reachable *from the far side* and sends something on connect. For the
    # WinRM target its own WinRM listener works; for the loopback host, the dev host's own
    # port works, since an SSH server greets with its identification string.
    [string]$ForwardTarget,
    [string]$ForwardExpect = 'HTTP/1\.1|^SSH-',
    # 0 picks a free port at run time. A fixed one collides with leftovers from a previous
    # run and then the failure looks like a forwarding bug rather than a bind conflict.
    [int]$ForwardLocalPort = 0,
    [switch]$SkipLarge
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $repo $KnownHostsFile)) -Force | Out-Null

$script:pass = 0
$script:fail = 0

function Get-SshArgs([string]$Command, [string[]]$Extra, [string]$UseTarget, [string]$UseConfig) {
    $a = New-Object System.Collections.Generic.List[string]
    $cfg = if ($UseConfig) { $UseConfig } else { $ConfigFile }
    $tgt = if ($UseTarget) { $UseTarget } else { $Target }
    if ($cfg) { $a.Add('-F'); $a.Add($cfg) }
    if ($Port -gt 0) { $a.Add('-p'); $a.Add("$Port") }
    $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
    $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
    $a.Add('-o'); $a.Add('BatchMode=yes')
    $a.Add('-o'); $a.Add('ConnectTimeout=20')
    if ($Extra) { foreach ($e in $Extra) { $a.Add($e) } }
    $a.Add($tgt)
    # Empty command means a shell session rather than exec.
    if ($Command) { $a.Add($Command) }
    return $a
}

# ssh is driven via Process so stdout can be read as raw bytes; PowerShell's own
# redirection would decode it as text and destroy binary payloads.
function Invoke-Ssh {
    param([string]$Command, [byte[]]$StdinBytes, [string[]]$Extra, [string]$UseTarget, [string]$UseConfig)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'ssh'
    foreach ($a in (Get-SshArgs $Command $Extra $UseTarget $UseConfig)) { $psi.ArgumentList.Add($a) }
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
    # powershell.exe emits a CLIXML progress record ("Preparing modules for first use") on
    # stderr, which is faithfully relayed as CHANNEL_EXTENDED_DATA and would otherwise be
    # mixed into anything the far side writes there deliberately.
    $full = "`$ProgressPreference = 'SilentlyContinue'`n" + $Script
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($full))
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

# ------------------------------- 6b. incompressible payload (worst-case throughput)
# The test above uses a repeating pattern, which WinRM compresses well now that the link
# carries plaintext. This measures the other end of the range.
if (-not $SkipLarge) {
    $big = 8 * 1024 * 1024
    $genRand = @"
`$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
`$sha = [System.Security.Cryptography.SHA256]::Create()
`$chunk = New-Object byte[] 65536
`$o = [Console]::OpenStandardOutput()
for (`$k = 0; `$k -lt $($big / 65536); `$k++) {
    `$rng.GetBytes(`$chunk)
    `$null = `$sha.TransformBlock(`$chunk, 0, `$chunk.Length, `$null, 0)
    `$o.Write(`$chunk, 0, `$chunk.Length)
}
`$o.Flush()
`$null = `$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
[Console]::Error.Write([Convert]::ToBase64String(`$sha.Hash))
"@
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $r = Invoke-Ssh -Command (New-FarSideCommand $genRand)
    $sw.Stop()

    Assert-That 'incompressible 8 MiB arrives complete' ($r.Stdout.Length -eq $big) `
        "got $($r.Stdout.Length) expected $big"
    # The far side reports its own hash on stderr, so this also proves the two streams stay
    # separated while stdout is saturated. Matched by pattern rather than compared whole, so
    # any incidental host noise on stderr cannot fail an otherwise correct transfer.
    $remoteHash = ''
    if ($r.Stderr -match '([A-Za-z0-9+/]{43}=)') { $remoteHash = $Matches[1] }
    Assert-That 'incompressible 8 MiB bit-exact' ((Get-Sha $r.Stdout) -eq $remoteHash) `
        "local $(Get-Sha $r.Stdout) vs remote '$remoteHash'"
    Write-Host ("        throughput (incompressible): {0:N2} MiB/s" -f (8 / $sw.Elapsed.TotalSeconds)) -ForegroundColor DarkGray
}

# ------------------------------------------------------------------ 7. shell
# No command means a shell channel. stdin is not a terminal, so ssh does not request a pty
# and the shell runs over pipes -- the path tooling uses.
$r = Invoke-Ssh -Command '' -StdinBytes ([System.Text.Encoding]::ASCII.GetBytes("echo hello-from-shell`r`nexit`r`n"))
$so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
Assert-That 'shell channel runs piped commands' ($so -match 'hello-from-shell') `
    "stdout='$($so -replace '\s+', ' ')' stderr='$($r.Stderr)'"

$r = Invoke-Ssh -Command '' -StdinBytes ([System.Text.Encoding]::ASCII.GetBytes("exit 3`r`n"))
Assert-That 'shell exit status propagates' ($r.ExitCode -eq 3) "exit=$($r.ExitCode)"

# -tt forces pty allocation, so this proves pty-req was accepted and ConPTY drove a real
# console. The output carries VT sequences, hence a substring match.
$r = Invoke-Ssh -Command 'echo hello-from-pty' -Extra @('-tt')
$so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
Assert-That 'pty session produces output' ($so -match 'hello-from-pty') `
    "stdout='$(($so -replace '\x1b','<ESC>') -replace '\s+', ' ')' stderr='$($r.Stderr)'"
Assert-That 'pty session emits VT sequences' ($so.Contains([char]27)) 'no escape sequences seen'

# ----------------------------------------- 7b. graceful degradation without ConPTY
if ($DegradedTarget) {
    # -tt *forces* a pty, so a refusal is fatal by design -- exiting with the diagnostic is
    # the correct outcome, and what we assert is that we refuse cleanly rather than hang.
    $r = Invoke-Ssh -Command 'echo nope' -Extra @('-tt') -UseTarget $DegradedTarget -UseConfig $DegradedConfigFile
    Assert-That 'pty-req refused cleanly when ConPTY is unavailable' `
        ($r.Stderr -match 'PTY allocation request failed') "stderr='$($r.Stderr)'"

    # And the fallback is actually usable: a shell over pipes still works on that remote.
    $r = Invoke-Ssh -Command '' -StdinBytes ([System.Text.Encoding]::ASCII.GetBytes("echo hello-degraded`r`nexit`r`n")) `
        -UseTarget $DegradedTarget -UseConfig $DegradedConfigFile
    $so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
    Assert-That 'shell still works without ConPTY' ($so -match 'hello-degraded') `
        "stdout='$($so -replace '\s+', ' ')'"
}

# ------------------------------------------------------------ 7c. port forwarding
if ($ForwardTarget) {
    $probe = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: localhost`r`n`r`n")

    # -W is the simplest forward: our stdin goes to the remote socket, its replies to stdout.
    $r = Invoke-Ssh -Command '' -Extra @('-W', $ForwardTarget) -StdinBytes $probe
    $so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
    Assert-That 'stdio forward (-W) reaches the target' ($so -match $ForwardExpect) `
        "got '$(($so -split "`r?`n")[0])' stderr='$($r.Stderr)'"

    # A refused connection must be reported as a channel-open failure, not left as a tunnel
    # that silently swallows data. Port 9 (discard) is not listening on the test remote.
    $r = Invoke-Ssh -Command '' -Extra @('-W', '127.0.0.1:9') -StdinBytes $probe
    Assert-That 'refused forward reports failure' `
        (($r.ExitCode -ne 0) -and ($r.Stderr -match 'open failed|connect failed|forwarding failed')) `
        "exit=$($r.ExitCode) stderr='$($r.Stderr)'"

    # -L exercises the client-side listener, and -N proves the engine copes with a connection
    # that never opens a session channel at all.
    if ($ForwardLocalPort -le 0) {
        $probeListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $probeListener.Start()
        $ForwardLocalPort = $probeListener.LocalEndpoint.Port
        $probeListener.Stop()
    }

    $lpsi = New-Object System.Diagnostics.ProcessStartInfo
    $lpsi.FileName = 'ssh'
    foreach ($a in (Get-SshArgs '' @('-N', '-L', "${ForwardLocalPort}:$ForwardTarget"))) { $lpsi.ArgumentList.Add($a) }
    $lpsi.UseShellExecute = $false
    $lpsi.RedirectStandardOutput = $true; $lpsi.RedirectStandardError = $true
    $lp = [System.Diagnostics.Process]::Start($lpsi)
    $lErr = $lp.StandardError.ReadToEndAsync()
    $null = $lp.StandardOutput.ReadToEndAsync()

    function Test-LocalPort([int]$port) {
        try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect('127.0.0.1', $port); $c.Close(); $true }
        catch { $false }
    }
    $deadline = (Get-Date).AddSeconds(60)
    while (-not (Test-LocalPort $ForwardLocalPort) -and (Get-Date) -lt $deadline -and -not $lp.HasExited) {
        Start-Sleep -Milliseconds 300
    }
    # Never touch $lErr.Result while ssh is still running: reading it blocks until the stream
    # closes, i.e. until ssh exits, which stalls the test until the session idle-times out.
    Assert-That 'local forward (-L -N) listens' (Test-LocalPort $ForwardLocalPort) `
        "ssh already exited=$($lp.HasExited) on port $ForwardLocalPort"

    function Probe-Local([int]$port) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', $port)
            $s = $c.GetStream(); $s.ReadTimeout = 40000
            $q = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: localhost`r`n`r`n")
            $s.Write($q, 0, $q.Length); $s.Flush()
            $b = New-Object byte[] 4096
            $n = $s.Read($b, 0, $b.Length)
            $c.Close()
            if ($n -le 0) { return '' }
            return [System.Text.Encoding]::ASCII.GetString($b, 0, $n)
        }
        catch { return '' }
    }

    $probed = Probe-Local $ForwardLocalPort
    Assert-That 'local forward carries a connection' ($probed -match $ForwardExpect) `
        "port $ForwardLocalPort got '$(($probed -split "`r?`n")[0])'"

    # Several at once: this is what the multi-channel work was for.
    $shells = 1..4 | ForEach-Object {
        [powershell]::Create().AddScript({
            param($port, $expect)
            try {
                $c = New-Object System.Net.Sockets.TcpClient
                $c.Connect('127.0.0.1', $port)
                $s = $c.GetStream(); $s.ReadTimeout = 40000
                $q = [System.Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.0`r`nHost: localhost`r`n`r`n")
                $s.Write($q, 0, $q.Length); $s.Flush()
                $b = New-Object byte[] 4096
                $n = $s.Read($b, 0, $b.Length)
                $c.Close()
                ($n -gt 0) -and ([System.Text.Encoding]::ASCII.GetString($b, 0, $n) -match $expect)
            }
            catch { $false }
        }).AddArgument($ForwardLocalPort).AddArgument($ForwardExpect)
    }
    $hs = $shells | ForEach-Object { $_.BeginInvoke() }
    $okCount = 0
    for ($i = 0; $i -lt $shells.Count; $i++) {
        if (($shells[$i].EndInvoke($hs[$i]) | Select-Object -First 1) -eq $true) { $okCount++ }
        $shells[$i].Dispose()
    }
    Assert-That 'four concurrent forwarded connections' ($okCount -eq 4) "$okCount of 4 succeeded"

    try { if (-not $lp.HasExited) { $lp.Kill() } } catch { }
    $lp.WaitForExit(5000) | Out-Null
    # Safe to read now that ssh has exited.
    $lStderr = ($lErr.Result -split "`r?`n" | Where-Object { $_ -and $_ -notmatch 'Killed by' }) -join ' | '
    if ($lStderr) { Write-Host ("        forward ssh stderr: {0}" -f $lStderr) -ForegroundColor DarkGray }
}

# --------------------------------------------------------- 8. username rejected
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
