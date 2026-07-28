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
    # Optional IPv6 form of the same target, e.g. '[::1]:5985'. Only meaningful where the far
    # side actually listens on IPv6; the loopback dev host binds IPv4 only.
    [string]$ForwardTarget6,
    # 0 picks a free port at run time. A fixed one collides with leftovers from a previous
    # run and then the failure looks like a forwarding bug rather than a bind conflict.
    [int]$ForwardLocalPort = 0,
    # Reverse forwarding (-R). Requires the far side to be able to run powershell.exe, which
    # every target here already does. 0 picks free ports at run time.
    [switch]$SkipReverse,
    [int]$ReversePort = 0,
    # Optional third target whose ProxyCommand passes -GatewayPorts, so the accept side of the
    # gateway policy can be checked. Without it only the refusal is tested.
    [string]$GatewayTarget,
    [string]$GatewayConfigFile,
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
# exit 255 is ssh's own failure code rather than the shell's, so stderr is what distinguishes
# a broken status path from a connection that never came up.
Assert-That 'shell exit status propagates' ($r.ExitCode -eq 3) `
    "exit=$($r.ExitCode) stderr='$($r.Stderr -replace "`r?`n", ' | ')'"

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

    # IPv6 must work too. This regressed once because TcpClient's default constructor makes an
    # IPv4-only socket, so an IPv6 target failed with a nonsensical WSAENOTCONN.
    if ($ForwardTarget6) {
        $r = Invoke-Ssh -Command '' -Extra @('-W', $ForwardTarget6) -StdinBytes $probe
        $so6 = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
        Assert-That 'stdio forward reaches an IPv6 target' ($so6 -match $ForwardExpect) `
            "target $ForwardTarget6 got '$(($so6 -split "`r?`n")[0])' stderr='$($r.Stderr)'"
    }

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

# --------------------------------------------------- 7d. reverse forwarding (-R)
if (-not $SkipReverse) {
    # Free ports are picked by binding and releasing. The remote-side port has to be free on
    # the far side, which for the WinRM target is a different machine -- but a port in the
    # ephemeral range that is free here is overwhelmingly likely to be free there too, and a
    # collision surfaces as an explicit bind failure rather than a confusing hang.
    function Get-FreePort {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $l.Start(); $p = $l.LocalEndpoint.Port; $l.Stop(); return $p
    }
    if ($ReversePort -le 0) { $ReversePort = Get-FreePort }

    # Probe run on the far side: connect to the forwarded port and report what came back.
    #
    # Every wait is bounded. A leaked listener accepts and then never sends anything, so an
    # unbounded ReadToEnd here would hang until ssh's own timeout and report the failure as
    # "ssh timed out" rather than as the leak it is.
    function New-ReverseProbe([int]$port) {
        New-FarSideCommand @"
try {
    `$c = New-Object System.Net.Sockets.TcpClient
    `$ar = `$c.BeginConnect('127.0.0.1', $port, `$null, `$null)
    if (-not `$ar.AsyncWaitHandle.WaitOne(8000)) { [Console]::Out.Write('NOCONNECT'); exit }
    `$c.EndConnect(`$ar)
    `$s = `$c.GetStream()
    `$s.ReadTimeout = 20000
    `$ms = New-Object System.IO.MemoryStream
    `$b = New-Object byte[] 65536
    try { while (`$true) { `$n = `$s.Read(`$b, 0, `$b.Length); if (`$n -le 0) { break }; `$ms.Write(`$b, 0, `$n) } }
    catch { [Console]::Out.Write('STILLBOUND:' + `$ms.Length); `$c.Close(); exit }
    `$c.Close()
    if (`$ms.Length -eq 0) { [Console]::Out.Write('STILLBOUND:0') }
    else { [Console]::Out.Write('GOT:' + [System.Text.Encoding]::ASCII.GetString(`$ms.ToArray())) }
} catch { [Console]::Out.Write('REFUSED') }
"@
    }

    # A one-shot local service for the forward to point at, in its own runspace so ssh can run
    # in the foreground. The port is chosen here rather than by the listener, because the
    # runspace cannot hand a value back before ssh needs it.
    $marker = "PWSSH-R-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    $servicePort = Get-FreePort
    $svc = [powershell]::Create().AddScript({
            param($port, $text)
            $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
            $l.Start()
            try {
                $c = $l.AcceptTcpClient()
                $s = $c.GetStream()
                $b = [System.Text.Encoding]::ASCII.GetBytes($text)
                $s.Write($b, 0, $b.Length); $s.Flush()
                # Half-close so the far side's read loop sees EOF instead of waiting for us.
                $c.Client.Shutdown('Send')
                Start-Sleep -Milliseconds 1000
                $c.Close()
            }
            finally { $l.Stop() }
        }).AddArgument($servicePort).AddArgument($marker)
    $null = $svc.BeginInvoke()
    Start-Sleep -Milliseconds 400

    # One ssh invocation proves the whole path: global request accepted, port bound on the far
    # side, connection accepted there, forwarded-tcpip opened by us, confirmed, bytes flowing.
    $r = Invoke-Ssh -Command (New-ReverseProbe $ReversePort) `
        -Extra @('-R', "${ReversePort}:127.0.0.1:$servicePort")
    $so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
    Assert-That 'reverse forward (-R) round trip' ($so -match "GOT:$marker") `
        "port $ReversePort -> 127.0.0.1:$servicePort got '$($so -replace '\s+', ' ')' stderr='$($r.Stderr -replace "`r?`n", ' | ')'"
    try { $svc.Stop(); $svc.Dispose() } catch { }

    # The listener must go away when the SSH connection ends. A leak is invisible without this
    # check and keeps a port bound on the far side.
    #
    # Only assertable against the dev host. Over WinRM ssh TerminateProcesses its ProxyCommand
    # on exit, so the engine's UNLISTEN never reaches the remote and the port stays bound until
    # WinRM reclaims the orphaned shell (IdleTimeout, 60 s). Waiting that out here would add a
    # minute to the run to test WinRM's reclamation rather than any of our code.
    if ($Port -gt 0) {
        $r = Invoke-Ssh -Command (New-ReverseProbe $ReversePort)
        $so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
        Assert-That 'reverse forward is released on exit' ($so -match 'REFUSED|NOCONNECT') `
            "port $ReversePort still answers: '$($so -replace '\s+', ' ')'"
    }
    else {
        Write-Host '  SKIP  reverse forward is released on exit (WinRM: ssh kills the ProxyCommand; see CLAUDE.md)' -ForegroundColor DarkGray
    }

    # Port 0 asks the far side to choose, and the chosen port comes back in the reply.
    $r = Invoke-Ssh -Command 'echo dyn' -Extra @('-v', '-R', '0:127.0.0.1:9')
    Assert-That 'reverse forward with a dynamic port reports it' `
        ($r.Stderr -match 'Allocated port \d+ for remote forward') `
        "stderr='$(($r.Stderr -split "`r?`n" | Where-Object { $_ -match 'forward|Allocated' }) -join ' | ')'"

    # A bind that cannot succeed must be reported, and must not poison the session. Both
    # loopback families have to be occupied: we bind 127.0.0.1 and ::1, and -- as sshd does --
    # count a partial bind as success, so occupying one leaves the other free.
    $busyPort = Get-FreePort
    $busy4 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $busyPort)
    $busy6 = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::IPv6Loopback, $busyPort)
    $bothBusy = $true
    try { $busy4.Start(); $busy6.Start() } catch { $bothBusy = $false }
    # $Port > 0 means the loopback dev host, i.e. the far side is this machine. Against a real
    # remote the port we occupied here is free there, so the bind would simply succeed.
    if ($bothBusy -and $Port -gt 0) {
        $r = Invoke-Ssh -Command 'echo after-fail' -Extra @('-R', "${busyPort}:127.0.0.1:9")
        $so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
        Assert-That 'reverse forward reports a bind failure' `
            ($r.Stderr -match 'remote port forwarding failed') `
            "port $busyPort stderr='$($r.Stderr -replace "`r?`n", ' | ')'"
        Assert-That 'session survives a failed reverse bind' ($so -match 'after-fail') `
            "stdout='$($so -replace '\s+', ' ')'"
    }
    try { $busy4.Stop(); $busy6.Stop() } catch { }

    # Gateway policy. Note the wire convention is the opposite way round from how it reads:
    # OpenSSH sends "localhost" for a plain -R and an EMPTY address for -R *:...
    $wildPort = Get-FreePort
    $r = Invoke-Ssh -Command 'echo wild' -Extra @('-R', "*:${wildPort}:127.0.0.1:9")
    Assert-That 'wildcard reverse bind is refused by default' `
        ($r.Stderr -match 'remote port forwarding failed') `
        "stderr='$($r.Stderr -replace "`r?`n", ' | ')'"

    if ($GatewayTarget) {
        $wildPort = Get-FreePort
        $r = Invoke-Ssh -Command (New-ReverseProbe $wildPort) `
            -Extra @('-R', "*:${wildPort}:127.0.0.1:9") `
            -UseTarget $GatewayTarget -UseConfig $GatewayConfigFile
        $so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
        # The target is port 9 (discard), so the connection is refused *after* the bind
        # succeeded; what matters here is that the bind was allowed at all.
        Assert-That 'wildcard reverse bind is allowed with -GatewayPorts' `
            ($r.Stderr -notmatch 'remote port forwarding failed') `
            "stdout='$($so -replace '\s+', ' ')' stderr='$($r.Stderr -replace "`r?`n", ' | ')'"
    }

    # Bulk through a reverse forward, bit-exact. Same shape as the round trip above but with a
    # payload big enough to cross window and compression boundaries.
    if (-not $SkipLarge) {
        $size = 512 * 1024
        $payload = New-Object byte[] $size
        (New-Object System.Random 20260728).NextBytes($payload)
        $want = Get-Sha $payload

        $bulkPort = Get-FreePort
        $bulkService = Get-FreePort
        $bsvc = [powershell]::Create().AddScript({
                param($port, $bytes)
                $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
                $l.Start()
                try {
                    $c = $l.AcceptTcpClient()
                    $s = $c.GetStream()
                    $s.Write($bytes, 0, $bytes.Length); $s.Flush()
                    $c.Client.Shutdown('Send')
                    Start-Sleep -Milliseconds 2000
                    $c.Close()
                }
                finally { $l.Stop() }
            }).AddArgument($bulkService).AddArgument($payload)
        $null = $bsvc.BeginInvoke()
        Start-Sleep -Milliseconds 400

        $bulkProbe = New-FarSideCommand @"
`$c = New-Object System.Net.Sockets.TcpClient
`$c.Connect('127.0.0.1', $bulkPort)
`$s = `$c.GetStream()
`$ms = New-Object System.IO.MemoryStream
`$b = New-Object byte[] 65536
while (`$true) { `$n = `$s.Read(`$b, 0, `$b.Length); if (`$n -le 0) { break }; `$ms.Write(`$b, 0, `$n) }
`$c.Close()
`$h = [System.Security.Cryptography.SHA256]::Create().ComputeHash(`$ms.ToArray())
[Console]::Out.Write('LEN=' + `$ms.Length + ' SHA=' + [Convert]::ToBase64String(`$h))
"@
        $r = Invoke-Ssh -Command $bulkProbe -Extra @('-R', "${bulkPort}:127.0.0.1:$bulkService")
        $so = [System.Text.Encoding]::ASCII.GetString($r.Stdout)
        Assert-That 'bulk through a reverse forward is bit-exact' `
            ($so -match ("LEN=$size SHA=" + [regex]::Escape($want))) `
            "got '$($so -replace '\s+', ' ')' want LEN=$size SHA=$want"
        try { $bsvc.Stop(); $bsvc.Dispose() } catch { }
    }
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
