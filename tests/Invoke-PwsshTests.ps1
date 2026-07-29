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
    # SFTP needs nothing the other sections do not already assume, so unlike the forwarding
    # cases it runs identically on both transports and has no conditional skips.
    [switch]$SkipSftp,
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

# sftp and scp take -P for the port where ssh takes -p, and sftp reads a batch script from
# stdin with '-b -', which keeps the suite's "nothing written to disk" property.
#
# The timeout names the phase it died in. sftp exits 1 for every kind of failure, so a bare
# "timed out" would say nothing about whether the hang was the open, the read or the close --
# and a hang is the failure mode this protocol produces when a reply goes missing.
function Invoke-Sftp {
    param([string]$Batch, [string]$Phase = 'sftp', [string[]]$Extra, [string]$UseTarget, [string]$UseConfig,
          [int]$TimeoutMs = 240000)

    $cfg = if ($UseConfig) { $UseConfig } else { $ConfigFile }
    $tgt = if ($UseTarget) { $UseTarget } else { $Target }
    $a = New-Object System.Collections.Generic.List[string]
    if ($cfg) { $a.Add('-F'); $a.Add($cfg) }
    if ($Port -gt 0) { $a.Add('-P'); $a.Add("$Port") }
    $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
    $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
    $a.Add('-o'); $a.Add('BatchMode=yes')
    if ($Extra) { foreach ($e in $Extra) { $a.Add($e) } }
    $a.Add('-b'); $a.Add('-')
    $a.Add($tgt)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'sftp'
    foreach ($x in $a) { $psi.ArgumentList.Add($x) }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $p.StandardInput.Write($Batch)
    $p.StandardInput.Close()
    $hung = -not $p.WaitForExit($TimeoutMs)
    if ($hung) { try { $p.Kill() } catch { } }

    [pscustomobject]@{
        ExitCode = $p.ExitCode
        Out      = $o.Result
        Err      = $e.Result
        Hung     = $hung
        Phase    = if ($hung) { "SFTP-HANG-$Phase" } else { '' }
    }
}

function Invoke-Scp {
    param([string[]]$ScpArgs, [int]$TimeoutMs = 240000)
    $a = New-Object System.Collections.Generic.List[string]
    if ($ConfigFile) { $a.Add('-F'); $a.Add($ConfigFile) }
    if ($Port -gt 0) { $a.Add('-P'); $a.Add("$Port") }
    $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
    $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
    $a.Add('-o'); $a.Add('BatchMode=yes')
    foreach ($x in $ScpArgs) { $a.Add($x) }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'scp'
    foreach ($x in $a) { $psi.ArgumentList.Add($x) }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    $hung = -not $p.WaitForExit($TimeoutMs)
    if ($hung) { try { $p.Kill() } catch { } }
    [pscustomobject]@{ ExitCode = $p.ExitCode; Out = $o.Result; Err = $e.Result; Hung = $hung }
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

    # ---- 6a. the same transfer across repeated rekeys.
    #
    # OpenSSH rekeys after ~1 GiB on AES-CTR, so before this worked a single large scp died part
    # way through with "pwssh does not support rekeying" -- the one known failure that turned a
    # slow transfer into a broken one. RekeyLimit=256K (OpenSSH's documented minimum) forces
    # ~11 rekeys into 8 MiB, so a once-per-gigabyte path is exercised in a few seconds.
    #
    # What this really tests is the send gate: between the client's KEXINIT and its NEWKEYS we may
    # send only transport-layer messages, and OpenSSH errors on a CHANNEL_DATA that arrives
    # mid-KEX. The failure is loud rather than subtle, which is why bit-exactness is enough.
    $r = Invoke-Ssh -Command (New-FarSideCommand $genBig) -Extra @('-o', 'RekeyLimit=256K', '-vv')
    Assert-That '8 MiB bit-exact across forced rekeys' `
        (($r.Stdout.Length -eq $big) -and ((Get-Sha $r.Stdout) -eq (Get-Sha $exp.ToArray()))) `
        "got $($r.Stdout.Length) expected $big"
    Assert-That 'exit status survives a rekey' ($r.ExitCode -eq 0) "exit=$($r.ExitCode)"

    # Without this the case above could pass by never rekeying at all. ssh logs one
    # "SSH2_MSG_KEXINIT sent" per exchange, so more than one means a rekey really happened.
    $kexSent = (($r.Stderr -split "`r?`n") | Where-Object { $_ -match 'SSH2_MSG_KEXINIT sent' }).Count
    Assert-That 'the client really did rekey' ($kexSent -ge 2) `
        "saw $kexSent KEXINIT sent; expected the initial one plus at least one rekey"
    Write-Host ("        rekeys observed: {0}" -f ($kexSent - 1)) -ForegroundColor DarkGray
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

# ------------------------------------------------------- 7e. SFTP subsystem (and scp)
if (-not $SkipSftp) {
    $bs = [char]92
    $sftpTag = [guid]::NewGuid().ToString('N').Substring(0, 8)

    # Far-side scratch directory, reported back so the tests need no knowledge of the remote's
    # layout. Everything below lives in here and it is removed at the end -- the suite creates
    # nothing persistent on the remote and this must not change that.
    $mk = Invoke-Ssh -Command (New-FarSideCommand @"
`$d = Join-Path `$env:TEMP 'pwssh-sftp-$sftpTag'
New-Item -ItemType Directory -Path `$d -Force | Out-Null
[Console]::Out.Write(`$d + '|' + `$env:USERPROFILE)
"@)
    $mkOut = ([System.Text.Encoding]::ASCII.GetString($mk.Stdout)).Trim()
    $farDir = ($mkOut -split '\|')[0]
    $farHome = ($mkOut -split '\|')[-1]
    $farFwd = $farDir.Replace($bs, '/')

    function Far-Sftp([string]$Script) {
        $r = Invoke-Ssh -Command (New-FarSideCommand $Script)
        return ([System.Text.Encoding]::ASCII.GetString($r.Stdout)).Trim()
    }
    # The far side hashes its own copy, so an upload is verified independently rather than by
    # fetching it back -- which would hide corruption that is symmetric in both directions.
    function Far-Hash([string]$farPath) {
        return Far-Sftp @"
if (Test-Path -LiteralPath '$farPath') {
    [Console]::Out.Write([Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes('$farPath'))))
} else { [Console]::Out.Write('MISSING') }
"@
    }

    Assert-That 'sftp scratch directory created on the far side' ($farDir -match '\S') "got '$mkOut'"

    # ---- 1. the subsystem starts, and realpath answers in the documented shape
    $r = Invoke-Sftp "pwd`nquit`n" 'realpath'
    Assert-That 'sftp subsystem starts' (($r.ExitCode -eq 0) -and -not $r.Hung) `
        "$($r.Phase) exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"
    Assert-That 'realpath returns a /X:/ path' ($r.Out -match 'Remote working directory: /[A-Za-z]:/') `
        "out='$($r.Out -replace "`r?`n", ' | ')'"
    # Compared against the REMOTE's profile, not the tester's: over WinRM they are different
    # machines, and hardcoding the local one would pass loopback and fail WinRM.
    $wantPwd = '/' + $farHome.Replace($bs, '/')
    Assert-That 'realpath starts in the remote home' ($r.Out -match [regex]::Escape($wantPwd)) `
        "want '$wantPwd' out='$($r.Out -replace "`r?`n", ' | ')'"

    # ---- 2. the virtual root lists drives
    $r = Invoke-Sftp "ls /`nquit`n" 'lsroot'
    Assert-That 'ls / lists drive letters' ($r.Out -match '/[A-Za-z]:') `
        "out='$($r.Out -replace "`r?`n", ' | ')'"

    # ---- 3. upload, verified by the far side's own hash
    $payload = New-Object byte[] (256 * 1024)
    (New-Object System.Random 20260729).NextBytes($payload)
    for ($i = 0; $i -lt 256; $i++) { $payload[$i] = [byte]$i }   # every byte value must survive
    $wantHash = Get-Sha $payload
    $localUp = Join-Path $repo "tmp/sftp-up-$sftpTag.bin"
    [System.IO.File]::WriteAllBytes($localUp, $payload)

    $r = Invoke-Sftp "put $($localUp.Replace($bs,'/')) $farFwd/up.bin`nquit`n" 'put'
    Assert-That 'sftp put succeeds' (($r.ExitCode -eq 0) -and -not $r.Hung) `
        "$($r.Phase) err='$($r.Err -replace "`r?`n", ' | ')'"
    Assert-That 'sftp upload is bit-exact' ((Far-Hash "$farDir${bs}up.bin") -eq $wantHash) `
        'far-side hash differs'

    # ---- 4. download the same bytes back
    $localDown = Join-Path $repo "tmp/sftp-down-$sftpTag.bin"
    if (Test-Path $localDown) { [System.IO.File]::Delete($localDown) }
    $r = Invoke-Sftp "get $farFwd/up.bin $($localDown.Replace($bs,'/'))`nquit`n" 'get'
    $gotHash = if (Test-Path $localDown) { Get-Sha ([System.IO.File]::ReadAllBytes($localDown)) } else { 'MISSING' }
    Assert-That 'sftp download is bit-exact' ($gotHash -eq $wantHash) `
        "$($r.Phase) got $gotHash want $wantHash err='$($r.Err -replace "`r?`n", ' | ')'"

    # ---- 5. sizes either side of the chunk boundaries.
    # A server that answers a full-size READ with a short block silently loses the tail of every
    # file whose size is not a multiple of the chunk, and the client then permanently shrinks
    # its request size -- so the +/-1 cases matter more than they look.
    $edges = @(0, 1, 32768, 261119, 261120, 261121)
    $badEdges = @()
    foreach ($n in $edges) {
        $b = New-Object byte[] $n
        if ($n -gt 0) { (New-Object System.Random $n).NextBytes($b) }
        $lp = Join-Path $repo "tmp/sftp-e$n-$sftpTag.bin"
        [System.IO.File]::WriteAllBytes($lp, $b)
        $null = Invoke-Sftp "put $($lp.Replace($bs,'/')) $farFwd/e$n.bin`nquit`n" "put$n"
        if ((Far-Hash "$farDir${bs}e$n.bin") -ne (Get-Sha $b)) { $badEdges += $n }
    }
    Assert-That 'chunk-boundary sizes transfer exactly' ($badEdges.Count -eq 0) `
        "wrong at: $($badEdges -join ', ')"

    # ---- 5b. the same boundaries in the DOWNLOAD direction.
    # Case 5 only covers upload, and case 4 downloads a single 256 KiB file, so a server that
    # mis-handles the tail of a read would go unnoticed. Truncation is the one failure mode with
    # no diagnostic: the client reports success and the bytes are simply missing. All the sizes
    # are created in one far-side call and fetched in one sftp batch, because over WinRM each
    # extra connection costs several seconds.
    $dlEdges = @(0, 1, 32768, 261119, 261120, 261121, 522240, 522241)
    $mkEdges = New-Object System.Text.StringBuilder
    foreach ($n in $dlEdges) {
        [void]$mkEdges.AppendLine("`$b = New-Object byte[] $n")
        [void]$mkEdges.AppendLine("if ($n -gt 0) { (New-Object System.Random $n).NextBytes(`$b) }")
        [void]$mkEdges.AppendLine("[System.IO.File]::WriteAllBytes('$farDir${bs}d$n.bin', `$b)")
        [void]$mkEdges.AppendLine("[Console]::Out.Write([Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash(`$b)) + '|')")
    }
    $farHashes = (Far-Sftp $mkEdges.ToString()) -split '\|'

    $getBatch = New-Object System.Text.StringBuilder
    foreach ($n in $dlEdges) {
        $lp = (Join-Path $repo "tmp/sftp-d$n-$sftpTag.bin").Replace($bs, '/')
        if (Test-Path $lp) { [System.IO.File]::Delete($lp) }
        [void]$getBatch.AppendLine("get $farFwd/d$n.bin $lp")
    }
    [void]$getBatch.AppendLine('quit')
    $r = Invoke-Sftp $getBatch.ToString() 'getedges'

    $badDl = @()
    for ($i = 0; $i -lt $dlEdges.Count; $i++) {
        $n = $dlEdges[$i]
        $lp = Join-Path $repo "tmp/sftp-d$n-$sftpTag.bin"
        $got = if (Test-Path $lp) { Get-Sha ([System.IO.File]::ReadAllBytes($lp)) } else { 'MISSING' }
        if ($got -ne $farHashes[$i]) { $badDl += "$n($got vs $($farHashes[$i]))" }
    }
    Assert-That 'chunk-boundary sizes download exactly' ($badDl.Count -eq 0) `
        "$($r.Phase) wrong at: $($badDl -join ', ')"

    # ---- 5c. the client must never be answered short in the middle of a file.
    # A mid-file short reply makes it re-request and then *permanently* shrink its request size
    # for the rest of the session, which measured ~2.5x -- and nothing surfaces it except the
    # client's own debug output.
    #
    # The size is deliberately an exact multiple of the 261120-byte chunk, so a correct server
    # produces no short reply at all and the assertion needs no tolerance. A file that is NOT a
    # multiple legitimately yields exactly one short reply at the tail: the client asks for a
    # whole chunk spanning the end and gets the bytes that exist, which is what the reference
    # server does too. Asserting against that would be testing the protocol, not this code.
    $r = Invoke-Sftp "get $farFwd/d522240.bin $((Join-Path $repo "tmp/sftp-vv-$sftpTag.bin").Replace($bs,'/'))`nquit`n" 'vvv' @('-vvv')
    Assert-That 'no short data blocks mid-file' `
        ($r.Err -notmatch 'Short data block') `
        "stderr: $(($r.Err -split "`r?`n" | Where-Object { $_ -match 'Short data|re-request' }) -join ' | ')"
    Assert-That 'the client adopts the advertised transfer limits' `
        ($r.Err -match 'buffer sizes 65536 / 261120; using 65536 / 261120') `
        "stderr: $(($r.Err -split "`r?`n" | Where-Object { $_ -match 'buffer sizes' }) -join ' | ')"

    # ---- 5d. resuming a download must not trip the client's reordering check. sftp.exe abandons a
    # resume outright with "server reordered requests" if replies arrive out of order, and that one
    # string is the reason the read-ahead answers the client strictly FIFO rather than as soon as
    # each read happens to be satisfiable. Nothing else here would catch a violation: an ordinary
    # transfer tolerates reordering, so only the resume path checks.
    $full522 = Join-Path $repo "tmp/sftp-d522240-$sftpTag.bin"
    $resume = Join-Path $repo "tmp/sftp-resume-$sftpTag.bin"
    if (Test-Path $full522) {
        $fullBytes = [System.IO.File]::ReadAllBytes($full522)
        $partial = New-Object byte[] 300000
        [Array]::Copy($fullBytes, $partial, 300000)
        [System.IO.File]::WriteAllBytes($resume, $partial)
        $r = Invoke-Sftp "reget $farFwd/d522240.bin $($resume.Replace($bs,'/'))`nquit`n" 'reget' @('-vvv')
        $resumed = if (Test-Path $resume) { Get-Sha ([System.IO.File]::ReadAllBytes($resume)) } else { 'MISSING' }
        Assert-That 'reget resumes bit-exact, with no reordered replies' `
            (($r.Err -notmatch 'reordered requests') -and ($resumed -eq (Get-Sha $fullBytes))) `
            "$($r.Phase) hash=$resumed want=$(Get-Sha $fullBytes) stderr: $(($r.Err -split "`r?`n" | Where-Object { $_ -match 'reorder|resume' }) -join ' | ')"
    }

    # ---- 5e. the same file twice in one session, which is what cycles handles. A prefetch that
    # stayed marked active past the first file would leave the second with no read-ahead at all --
    # invisible in a hash check, so this asserts both copies rather than just the second.
    $twiceA = Join-Path $repo "tmp/sftp-twice-a-$sftpTag.bin"
    $twiceB = Join-Path $repo "tmp/sftp-twice-b-$sftpTag.bin"
    $r = Invoke-Sftp @"
get $farFwd/d522240.bin $($twiceA.Replace($bs,'/'))
get $farFwd/d522240.bin $($twiceB.Replace($bs,'/'))
quit
"@ 'twice'
    $hA = if (Test-Path $twiceA) { Get-Sha ([System.IO.File]::ReadAllBytes($twiceA)) } else { 'MISSING-A' }
    $hB = if (Test-Path $twiceB) { Get-Sha ([System.IO.File]::ReadAllBytes($twiceB)) } else { 'MISSING-B' }
    Assert-That 'the same file downloads twice in one session' (($hA -eq $hB) -and ($hA -notlike 'MISSING*')) `
        "$($r.Phase) a=$hA b=$hB"

    # ---- 5f. buffer sizes the read-ahead was not designed around. Our chunks are 261120 bytes and
    # the belief that the client's read offsets are multiples of that is an *inference* from its
    # -vvv "using 65536 / 261120" line, not something read from its source. -B forces other sizes,
    # so reads stop matching chunk boundaries and every one has to be spliced out of the buffer --
    # and -R 1 removes the client's pipelining entirely, so each read is issued alone. A splice or
    # accounting bug shows up here as corruption, which is why these assert hashes and not timing.
    $idx522 = $dlEdges.IndexOf(522240)
    if ($idx522 -ge 0) {
        foreach ($variant in @(@('-B', '32768'), @('-B', '262144'), @('-R', '1'))) {
            $vtag = ($variant -join '')
            $vLocal = Join-Path $repo "tmp/sftp-v$vtag-$sftpTag.bin"
            if (Test-Path $vLocal) { [System.IO.File]::Delete($vLocal) }
            $r = Invoke-Sftp "get $farFwd/d522240.bin $($vLocal.Replace($bs,'/'))`nquit`n" "opt$vtag" $variant
            $vh = if (Test-Path $vLocal) { Get-Sha ([System.IO.File]::ReadAllBytes($vLocal)) } else { 'MISSING' }
            Assert-That "sftp $($variant -join ' ') downloads bit-exact" ($vh -eq $farHashes[$idx522]) `
                "$($r.Phase) got $vh want $($farHashes[$idx522])"
        }
    }

    # ---- 5g. read-ahead switched off is the valve's floor: the code path a trip degrades *to*,
    # end to end. If this ever fails, no amount of read-ahead correctness matters, because the
    # fallback is broken too. WinRM only, for the same reason as the fault case below.
    if ($Port -eq 0) {
        $offLocal = Join-Path $repo "tmp/sftp-raoff-$sftpTag.bin"
        if (Test-Path $offLocal) { [System.IO.File]::Delete($offLocal) }
        [Environment]::SetEnvironmentVariable('PWSSH_SFTP_READAHEAD_CHUNKS', '0')
        try {
            $r = Invoke-Sftp "get $farFwd/d522240.bin $($offLocal.Replace($bs,'/'))`nquit`n" 'raoff'
        } finally {
            [Environment]::SetEnvironmentVariable('PWSSH_SFTP_READAHEAD_CHUNKS', $null)
        }
        $oh = if (Test-Path $offLocal) { Get-Sha ([System.IO.File]::ReadAllBytes($offLocal)) } else { 'MISSING' }
        Assert-That 'a download with read-ahead disabled is bit-exact' ($oh -eq $farHashes[$idx522]) `
            "$($r.Phase) got $oh want $($farHashes[$idx522])"
    }
    else {
        Write-Host '  SKIP  a download with read-ahead disabled is bit-exact (dev host: use -SftpReadAheadChunks 0)' -ForegroundColor DarkGray
    }

    # ---- 6. listings show what is there, and render a directory as a directory
    $r = Invoke-Sftp "mkdir $farFwd/adir`nls -l $farFwd`nquit`n" 'lsl'
    Assert-That 'ls shows an uploaded file' ($r.Out -match 'up\.bin') `
        "out='$($r.Out -replace "`r?`n", ' | ')'"
    Assert-That 'ls -l marks a directory with d' ($r.Out -match 'd[rwx-]{9}.*adir') `
        "out='$($r.Out -replace "`r?`n", ' | ')'"

    # ---- 7. mutating operations, each checked on the far side rather than by exit code.
    # The rename lands on an existing name, which is the posix-rename path: plain v3 RENAME is
    # required to fail there.
    $r = Invoke-Sftp @"
put $($localUp.Replace($bs,'/')) $farFwd/adir/a.bin
put $($localUp.Replace($bs,'/')) $farFwd/adir/b.bin
rename $farFwd/adir/a.bin $farFwd/adir/b.bin
rm $farFwd/adir/b.bin
rmdir $farFwd/adir
quit
"@ 'mutate'
    $after = Far-Sftp @"
[Console]::Out.Write((Test-Path -LiteralPath '$farDir${bs}adir').ToString())
"@
    Assert-That 'mkdir/put/rename-over/rm/rmdir all take effect' `
        (($r.ExitCode -eq 0) -and ($after -eq 'False')) `
        "$($r.Phase) exit=$($r.ExitCode) dirStillThere=$after err='$($r.Err -replace "`r?`n", ' | ')'"

    # ---- 8. a failure is reported as itself, and does not poison the session.
    # The '-' prefix is sftp's own "do not abort the batch here"; without it batch mode stops on
    # the first error and the test would be measuring sftp rather than us.
    $r = Invoke-Sftp "-get $farFwd/definitely-absent.bin $($repo.Replace($bs,'/'))/tmp/never.bin`npwd`nquit`n" 'missing'
    Assert-That 'a missing file reports a real error' ($r.Err -match 'not found|No such file') `
        "err='$($r.Err -replace "`r?`n", ' | ')'"
    Assert-That 'the session survives a failed get' ($r.Out -match 'Remote working directory') `
        "out='$($r.Out -replace "`r?`n", ' | ')'"

    # ---- 9. an unknown subsystem is refused rather than left hanging
    $r = Invoke-Ssh -Command 'definitely-not-a-subsystem' -Extra @('-s')
    Assert-That 'an unknown subsystem is refused' `
        (($r.ExitCode -ne 0) -and ($r.Stderr -match 'subsystem request failed')) `
        "exit=$($r.ExitCode) stderr='$($r.Stderr -replace "`r?`n", ' | ')'"

    # ---- 10. path forms: absolute, drive-prefixed without the leading slash, and home-relative
    $r = Invoke-Sftp "get $farFwd/up.bin $($repo.Replace($bs,'/'))/tmp/p1-$sftpTag.bin`nquit`n" 'path1'
    $r = Invoke-Sftp "get $($farFwd.TrimStart('/'))/up.bin $($repo.Replace($bs,'/'))/tmp/p2-$sftpTag.bin`nquit`n" 'path2'
    $h1 = $(if (Test-Path (Join-Path $repo "tmp/p1-$sftpTag.bin")) { Get-Sha ([System.IO.File]::ReadAllBytes((Join-Path $repo "tmp/p1-$sftpTag.bin"))) } else { 'none' })
    $h2 = $(if (Test-Path (Join-Path $repo "tmp/p2-$sftpTag.bin")) { Get-Sha ([System.IO.File]::ReadAllBytes((Join-Path $repo "tmp/p2-$sftpTag.bin"))) } else { 'none' })
    Assert-That 'absolute and drive-prefixed paths reach the same file' `
        (($h1 -eq $wantHash) -and ($h2 -eq $wantHash)) "withSlash=$h1 withoutSlash=$h2"

    # ---- 11. scp, which speaks SFTP on OpenSSH 9.x and so comes free with the subsystem.
    # -p additionally exercises SETSTAT/FSETSTAT: without them scp reports failure on a file it
    # transferred perfectly well.
    $stamp = [datetime]::SpecifyKind([datetime]'2019-02-03 04:05:06', 'Utc')
    [System.IO.File]::SetLastWriteTimeUtc($localUp, $stamp)
    $scpTgt = if ($Target -match '@') { $Target } else { $Target }
    $r = Invoke-Scp @('-p', $localUp, "${scpTgt}:$farFwd/scp-up.bin")
    Assert-That 'scp upload succeeds' (($r.ExitCode -eq 0) -and -not $r.Hung) `
        "exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"
    Assert-That 'scp upload is bit-exact' ((Far-Hash "$farDir${bs}scp-up.bin") -eq $wantHash) 'far-side hash differs'
    $farMtime = Far-Sftp @"
[Console]::Out.Write([System.IO.File]::GetLastWriteTimeUtc('$farDir${bs}scp-up.bin').ToString('o'))
"@
    $farParsed = [datetime]::MinValue
    $parsedOk = [datetime]::TryParse($farMtime, [ref]$farParsed)
    Assert-That 'scp -p preserves mtime on upload' `
        ($parsedOk -and ([math]::Abs(($farParsed.ToUniversalTime() - $stamp).TotalSeconds) -lt 2)) `
        "far mtime '$farMtime' want '$($stamp.ToString('o'))'"

    $scpDown = Join-Path $repo "tmp/sftp-scpdown-$sftpTag.bin"
    if (Test-Path $scpDown) { [System.IO.File]::Delete($scpDown) }
    $r = Invoke-Scp @('-p', "${scpTgt}:$farFwd/scp-up.bin", $scpDown)
    $sh = if (Test-Path $scpDown) { Get-Sha ([System.IO.File]::ReadAllBytes($scpDown)) } else { 'MISSING' }
    Assert-That 'scp download is bit-exact' ($sh -eq $wantHash) `
        "got $sh err='$($r.Err -replace "`r?`n", ' | ')'"
    if (Test-Path $scpDown) {
        $dm = [System.IO.File]::GetLastWriteTimeUtc($scpDown)
        Assert-That 'scp -p preserves mtime on download' ([math]::Abs(($dm - $stamp).TotalSeconds) -lt 2) `
            "got $($dm.ToString('o')) want $($stamp.ToString('o'))"
    }

    # ---- 12. bulk, and the throughput number that keeps CLAUDE.md's table honest
    if (-not $SkipLarge) {
        $big = 8 * 1024 * 1024
        $mkBig = Far-Sftp @"
`$b = New-Object byte[] $big
(New-Object System.Random 606).NextBytes(`$b)
[System.IO.File]::WriteAllBytes('$farDir${bs}big.bin', `$b)
[Console]::Out.Write([Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash(`$b)))
"@
        $bigLocal = Join-Path $repo "tmp/sftp-big-$sftpTag.bin"
        if (Test-Path $bigLocal) { [System.IO.File]::Delete($bigLocal) }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Invoke-Sftp "get $farFwd/big.bin $($bigLocal.Replace($bs,'/'))`nquit`n" 'bulk' @() '' '' 600000
        $sw.Stop()
        $bh = if (Test-Path $bigLocal) { Get-Sha ([System.IO.File]::ReadAllBytes($bigLocal)) } else { 'MISSING' }
        Assert-That 'bulk sftp download is bit-exact (8 MiB)' ($bh -eq $mkBig) `
            "$($r.Phase) got $bh want $mkBig"
        Write-Host ("        sftp download: {0:N2} MiB/s (includes ~4-6 s of connect)" -f (8 / $sw.Elapsed.TotalSeconds)) -ForegroundColor DarkGray

        # ---- 12a. the same bulk download across repeated rekeys.
        #
        # The most valuable rekey case, and the reason it lives here rather than beside the exec
        # one: an SFTP download has the read-ahead synthesising CHANNEL_DATA from its own thread
        # while the protocol thread drives the rekey. Serialising those two is exactly what the
        # send gate is for, so this is where a gate bug shows up. valveTrips would also have to
        # stay 0, which the engine log shows when -Diagnostics is on.
        $rkLocal = Join-Path $repo "tmp/sftp-rekey-$sftpTag.bin"
        if (Test-Path $rkLocal) { [System.IO.File]::Delete($rkLocal) }
        $r = Invoke-Sftp "get $farFwd/big.bin $($rkLocal.Replace($bs,'/'))`nquit`n" 'rekey' `
             @('-o', 'RekeyLimit=256K') '' '' 600000
        $rkh = if (Test-Path $rkLocal) { Get-Sha ([System.IO.File]::ReadAllBytes($rkLocal)) } else { 'MISSING' }
        Assert-That 'sftp download is bit-exact across forced rekeys' ($rkh -eq $mkBig) `
            "$($r.Phase) got $rkh want $mkBig err='$($r.Err -replace "`r?`n", ' | ')'"

        # ---- 12b. the read-ahead's safety valve, exercised rather than claimed. It degrades to
        # verbatim forwarding on any anomaly, and the whole argument for the private-channel design
        # is that this is safe at ANY instant -- including part way through a transfer with a read
        # parked on data already in flight. So trip it there deliberately and check the bytes.
        #
        # This is the case that would have caught a hang: Trip() used to abandon nothing, leaving
        # parked reads with no one to answer them and no SFTP timeout to rescue the client.
        #
        # WinRM only. The dev host's engine lives in a process started before this script, so it
        # cannot see the variable; there the same path is reached with -SftpFaultAfterKiB.
        if ($Port -eq 0) {
            $faultLocal = Join-Path $repo "tmp/sftp-fault-$sftpTag.bin"
            if (Test-Path $faultLocal) { [System.IO.File]::Delete($faultLocal) }
            [Environment]::SetEnvironmentVariable('PWSSH_SFTP_FAULT_AFTER_KIB', '2048')
            try {
                $r = Invoke-Sftp "get $farFwd/big.bin $($faultLocal.Replace($bs,'/'))`nquit`n" 'fault' @() '' '' 600000
            } finally {
                [Environment]::SetEnvironmentVariable('PWSSH_SFTP_FAULT_AFTER_KIB', $null)
            }
            $fh = if (Test-Path $faultLocal) { Get-Sha ([System.IO.File]::ReadAllBytes($faultLocal)) } else { 'MISSING' }
            Assert-That 'a valve trip mid-transfer still downloads bit-exact' ($fh -eq $mkBig) `
                "$($r.Phase) got $fh want $mkBig err='$($r.Err -replace "`r?`n", ' | ')'"
        }
        else {
            Write-Host '  SKIP  a valve trip mid-transfer still downloads bit-exact (dev host: use -SftpFaultAfterKiB)' -ForegroundColor DarkGray
        }
    }

    # ---- teardown
    $null = Far-Sftp "Remove-Item -LiteralPath '$farDir' -Recurse -Force -ErrorAction SilentlyContinue"
    Get-ChildItem (Join-Path $repo 'tmp') -Filter "*$sftpTag*" -ErrorAction SilentlyContinue |
        ForEach-Object { try { [System.IO.File]::Delete($_.FullName) } catch { } }
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
