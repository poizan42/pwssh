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

    if (-not $p.WaitForExit(180000)) {
        # Kill first, which closes the pipes and lets the reader tasks complete, then report what
        # ssh had managed to say. A bare 'ssh timed out' names neither the case nor the reason, and
        # the stderr it discards is usually the whole diagnosis.
        try { $p.Kill() } catch { }
        $so = ''
        try { if ($errTask.Wait(5000)) { $so = $errTask.Result } } catch { }
        $tail = (($so -split "`r?`n") | Where-Object { $_ -match '\S' } | Select-Object -Last 6) -join ' | '
        throw ("ssh timed out after 180s; stderr tail: " + $tail)
    }
    # Bounded deliberately. ssh having exited does not guarantee the stdout pipe is closed -- a
    # surviving grandchild can hold it -- and an unbounded Wait() here turns one stuck case into a
    # run that stops producing output altogether, which is far harder to diagnose than a failure.
    if (-not $outTask.Wait(30000)) { throw 'ssh exited but its stdout never closed' }
    # Bounded for exactly the same reason, and it was not. The ProxyCommand inherits ssh's stderr
    # handle, and ssh only TerminateProcesses it on its own clean exit paths -- so a surviving
    # proxy holds this pipe open and `.Result` blocks for ever. That is worse than the stdout case
    # it sits next to: there is no timeout to trip and no message, so the whole run simply stops
    # mid-case with no output and nothing to attribute it to. Two runs were lost to it.
    if (-not $errTask.Wait(30000)) { throw 'ssh exited but its stderr never closed' }
    $null = $errTask.Result

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

# ---- 7a. an idle session must not be dropped by our own watchdog.
#
# ssh sends nothing while the user is not typing -- ServerAliveInterval defaults to 0 and
# TCPKeepAlive works below the SSH layer -- so before the engine sent its own keepalive, silence
# was indistinguishable from a dead client and a session left sitting died at
# InactivityTimeoutSeconds. Verified as a real failure before the fix, not assumed.
#
# The timeout comes from the environment because five minutes is not something a suite can wait
# out, and because -o cannot reach a ProxyCommand parameter. WinRM only, for the same reason as
# the valve fault case: the dev host's engine lives in a process started before this script and
# cannot see the variable. Use -InactivityTimeoutSeconds on the dev host there.
if ($Port -eq 0) {
    $idleTimeout = 12
    [Environment]::SetEnvironmentVariable('PWSSH_INACTIVITY_TIMEOUT_SECONDS', "$idleTimeout")
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'ssh'
        foreach ($a in (Get-SshArgs '' @('-o', 'ServerAliveInterval=0'))) { $psi.ArgumentList.Add($a) }
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $ip = [System.Diagnostics.Process]::Start($psi)
        $iso = $ip.StandardOutput.ReadToEndAsync()
        $ise = $ip.StandardError.ReadToEndAsync()
        $ip.StandardInput.WriteLine('echo idle-before')
        $ip.StandardInput.Flush()
        Start-Sleep -Seconds 6
        Start-Sleep -Seconds ($idleTimeout * 2)          # well past the timeout, saying nothing
        $stillUp = -not $ip.HasExited
        # Guarded: if the session HAS been dropped the pipe is already gone, which is the failure
        # being tested rather than an error in the test.
        try { $ip.StandardInput.WriteLine('echo idle-after'); $ip.StandardInput.Flush() } catch { }
        Start-Sleep -Seconds 6
        try { $ip.StandardInput.WriteLine('exit'); $ip.StandardInput.Close() } catch { }
        $null = $ip.WaitForExit(60000)
        if (-not $ip.HasExited) { try { $ip.Kill() } catch { } }
        $iout = $iso.Result
        Assert-That 'an idle session is not dropped by the inactivity watchdog' `
            ($stillUp -and ($iout -match 'idle-before') -and ($iout -match 'idle-after')) `
            ("idle $($idleTimeout * 2)s against a ${idleTimeout}s timeout: alive=$stillUp " +
             "before=$($iout -match 'idle-before') after=$($iout -match 'idle-after') " +
             "stderr='$(($ise.Result -split "`r?`n" | Where-Object { $_ -match 'closed|reset' }) -join ' | ')'")
    } finally {
        [Environment]::SetEnvironmentVariable('PWSSH_INACTIVITY_TIMEOUT_SECONDS', $null)
    }
}
else {
    Write-Host '  SKIP  an idle session is not dropped by the inactivity watchdog (dev host: use -InactivityTimeoutSeconds)' -ForegroundColor DarkGray
}

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

    # A port the FAR side has to be able to bind, which is a different question from one free here.
    # Asking the local OS for an ephemeral port lands in 49152-65535, and Windows reserves large
    # blocks of exactly that range -- on the test remote, `netsh interface ipv4 show
    # excludedportrange protocol=tcp` lists 49773-49972 and 50000-50459 among others. A -R onto an
    # excluded port fails to bind for reasons that have nothing to do with pwssh, which showed up
    # as an intermittent failure of the -R round trip (port 50802, reproducible on that port and
    # clean on 28080). Worse, the two cases that EXPECT a refusal would pass for the wrong reason.
    function Get-FarSidePort { return 28000 + (Get-Random -Maximum 900) }

    if ($ReversePort -le 0) { $ReversePort = Get-FarSidePort }

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
    # Far-side port on purpose: the refusal being asserted must come from the gateway POLICY, and
    # an excluded port would produce the same message for an entirely different reason.
    $wildPort = Get-FarSidePort
    $r = Invoke-Ssh -Command 'echo wild' -Extra @('-R', "*:${wildPort}:127.0.0.1:9")
    Assert-That 'wildcard reverse bind is refused by default' `
        ($r.Stderr -match 'remote port forwarding failed') `
        "stderr='$($r.Stderr -replace "`r?`n", ' | ')'"

    if ($GatewayTarget) {
        $wildPort = Get-FarSidePort
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

        # Get-FarSidePort, not Get-FreePort: this one is bound on the REMOTE, and an ephemeral
        # local pick lands in 49152-65535, large parts of which Windows reserves -- so the bind
        # fails there while looking perfectly free here. The service port below really is local,
        # so it stays on Get-FreePort. Missed when Get-FarSidePort was introduced for the other
        # -R cases, and it presents as a 180 s timeout rather than as a bind error.
        $bulkPort = Get-FarSidePort
        $bulkService = Get-FreePort
        # Named because a -R failure is otherwise impossible to attribute afterwards: the remote
        # port and the local one fail for entirely different reasons.
        Write-Host ("        reverse bulk: remote -R {0} -> local service {1}" -f $bulkPort, $bulkService) -ForegroundColor DarkGray
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
        $bulkHandle = $bsvc.BeginInvoke()
        # Wait for the listener to actually accept rather than sleeping and hoping. 400 ms is
        # plenty on an idle machine and not always enough after the suite has been running for
        # several minutes -- and when it is not, the failure lands on the far side as a connect to
        # nothing, which used to present as a 180 s hang rather than as a setup problem.
        # Asked of the OS rather than by connecting: the service accepts exactly one client, so a
        # throwaway probe connection consumes the accept the forward needs and the payload is
        # written to the probe's dead socket instead. That yields LEN=0 -- a clean EOF with no
        # bytes -- which is a convincing-looking wrong answer rather than an obvious mistake.
        # GetActiveTcpListeners, not Get-NetTCPConnection: the latter is a CIM call costing well
        # over a second each time on a busy machine, so a hundred of them is minutes rather than
        # the seconds this is meant to take. Measured here at 18 ms against 1326 ms for one call.
        $bulkReady = $false
        foreach ($i in 1..100) {
            $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
            if (@($listeners | Where-Object { $_.Port -eq $bulkService }).Count -gt 0) { $bulkReady = $true; break }
            Start-Sleep -Milliseconds 50
        }
        # BeginInvoke swallows anything the runspace throws, so without this a failed listener is
        # completely silent and only ever shows up as a missing payload.
        #
        # Indexed, never piped. Streams.Error is a PSDataCollection and it stays OPEN for as long
        # as the runspace runs; enumerating an open one BLOCKS waiting for data that will never
        # come, and here the runspace cannot finish until the forward it is waiting for completes
        # -- which cannot happen while this line is holding up the ssh invocation that would carry
        # it. `$bsvc.Streams.Error | ForEach-Object {...}` deadlocks the whole run, silently, with
        # the case's own assertion never printing. Count and the indexer do not block.
        $bulkErr = ''
        for ($e = 0; $e -lt $bsvc.Streams.Error.Count; $e++) { $bulkErr += $bsvc.Streams.Error[$e].ToString() + ' ' }
        Assert-That 'the local service for the reverse forward is listening' $bulkReady `
            "port $bulkService never accepted; runspace errors: '$bulkErr'"

        # The read loop is bounded. An unbounded one here is how this case used to hang for the
        # full 180 s and report nothing at all: if the forward never delivers, Read blocks for
        # ever, the far-side powershell never exits, and so neither does ssh. ReceiveTimeout turns
        # that into a short, self-describing failure. The -R round-trip probe above was given the
        # same treatment long ago; this one was missed.
        $bulkProbe = New-FarSideCommand @"
try {
    `$c = New-Object System.Net.Sockets.TcpClient
    `$c.Connect('127.0.0.1', $bulkPort)
    `$c.ReceiveTimeout = 30000
    `$s = `$c.GetStream()
    `$ms = New-Object System.IO.MemoryStream
    `$b = New-Object byte[] 65536
    try { while (`$true) { `$n = `$s.Read(`$b, 0, `$b.Length); if (`$n -le 0) { break }; `$ms.Write(`$b, 0, `$n) } }
    catch { [Console]::Out.Write('STALLED after ' + `$ms.Length + ' bytes: ' + `$_.Exception.Message); `$c.Close(); exit }
    `$c.Close()
    `$h = [System.Security.Cryptography.SHA256]::Create().ComputeHash(`$ms.ToArray())
    [Console]::Out.Write('LEN=' + `$ms.Length + ' SHA=' + [Convert]::ToBase64String(`$h))
} catch { [Console]::Out.Write('CONNECTFAILED: ' + `$_.Exception.Message) }
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

    # ---- 5h. a globbed get of several files, which is what the metadata speculation is for.
    #
    # The client expands a glob by LSTATing every match up front, and only then walks the files
    # doing STAT, OPEN, reads, CLOSE. The engine speculates each STAT during that glob phase and
    # answers a read handle's CLOSE without waiting, so this exercises both mechanisms per file.
    #
    # Run with -vvv and asserted on the client's OWN complaints, because the way either mechanism
    # fails is by producing a reply the client did not ask for -- "Can't find request for ID" or
    # "Unexpected reply". Those are the tell, and bit-exactness alone would not catch them.
    $globN = 6
    $mkGlob = New-Object System.Text.StringBuilder
    [void]$mkGlob.AppendLine("New-Item -ItemType Directory -Path '$farDir${bs}glob' -Force | Out-Null")
    for ($i = 1; $i -le $globN; $i++) {
        [void]$mkGlob.AppendLine("[System.IO.File]::WriteAllText('$farDir${bs}glob${bs}g$i.txt', ('g' * (100 * $i)))")
    }
    [void]$mkGlob.AppendLine("[Console]::Out.Write('ok')")
    $null = Far-Sftp $mkGlob.ToString()

    $globDir = Join-Path $repo "tmp/sftp-glob-$sftpTag"
    if (-not (Test-Path $globDir)) { $null = New-Item -ItemType Directory -Path $globDir }
    $star = [string][char]42
    $r = Invoke-Sftp "get $farFwd/glob/$star $($globDir.Replace($bs,'/'))/`nquit`n" 'glob' @('-vvv')
    $globBad = @()
    for ($i = 1; $i -le $globN; $i++) {
        $lp = Join-Path $globDir "g$i.txt"
        $want = 'g' * (100 * $i)
        $got = if (Test-Path $lp) { [System.IO.File]::ReadAllText($lp) } else { 'MISSING' }
        if ($got -ne $want) { $globBad += "g$i" }
    }
    Assert-That 'a globbed get of several files is bit-exact' ($globBad.Count -eq 0) `
        "$($r.Phase) wrong at: $($globBad -join ', ')"
    Assert-That 'the client never sees a reply it did not ask for' `
        ($r.Err -notmatch "Can't find request for ID|Unexpected reply|ID mismatch") `
        "stderr: $(($r.Err -split "`r?`n" | Where-Object { $_ -match 'find request|Unexpected reply|mismatch' }) -join ' | ')"

    # ---- 5i. download a file then immediately overwrite it, twice.
    #
    # The read-ahead's own read handle is closed on a different channel from the one the client's
    # write-open arrives on, and the agent opens write handles FileShare.None, so these two are not
    # ordered against each other. Answering the CLOSE early makes the put arrive sooner still.
    # Checked before this work existed as well, so a failure here is a regression and not a
    # discovery.
    # Several pairs rather than one. The window is narrow by construction -- the agent frees a
    # channel's handles on its serial frame loop, and a full round trip separates the two events --
    # so a single pair proves very little. 200 pairs on a 900-byte file were run by hand; four here
    # is what fits in a suite that also has to finish.
    $rpLocal = Join-Path $repo "tmp/sftp-rp-$sftpTag.bin"
    $rpBatch = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt 4; $i++) {
        [void]$rpBatch.AppendLine("get $farFwd/glob/g1.txt $($rpLocal.Replace($bs,'/'))")
        [void]$rpBatch.AppendLine("put $($localUp.Replace($bs,'/')) $farFwd/replace.bin")
    }
    [void]$rpBatch.AppendLine('quit')
    $r = Invoke-Sftp $rpBatch.ToString() 'replace'
    $rpFar = Far-Sftp "[Console]::Out.Write([Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes('$farDir${bs}replace.bin'))))"
    Assert-That 'get then overwrite the same path leaves the upload intact' `
        ($rpFar -eq (Get-Sha ([System.IO.File]::ReadAllBytes($localUp)))) `
        "$($r.Phase) far=$rpFar want=$(Get-Sha ([System.IO.File]::ReadAllBytes($localUp))) err='$($r.Err -replace "`r?`n", ' | ')'"

    # ---- 5j. the attributes the client is given must be the right file's.
    # A speculation answered from the wrong path or the wrong request type would show up as a
    # wrong size here, which no hash comparison would ever notice.
    $r = Invoke-Sftp "ls -l $farFwd/glob`nquit`n" 'lsattrs'
    Assert-That 'listed sizes are the real ones' `
        (($r.Out -match "\s$(100 * $globN)\s") -and ($r.Out -match '\s100\s')) `
        "out='$($r.Out -replace "`r?`n", ' | ')'"

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

    # ---- 10b. paths past MAX_PATH, which is what the \\?\ extended-length prefix exists for.
    #
    # The tree is built with sftp's own mkdir rather than a far-side helper, so every level is itself
    # a test of the native CreateDirectoryW route and the fixture needs nothing the feature does not
    # already provide. It is torn down the same way, because the far side's own Remove-Item -Recurse
    # cannot be relied on to reach past MAX_PATH.
    #
    # What this case shows is that the whole cycle works at ~350 characters. What it CANNOT show is
    # policy-independence: both machines available here have LongPathsEnabled on, so an unprefixed
    # path would work too. That claim rests on the Win32 contract -- see CLAUDE.md.
    $lpRoot = "$farFwd/lp-$sftpTag"
    $lpLeaf = $lpRoot
    $lpLevels = New-Object System.Collections.Generic.List[string]
    foreach ($i in 1..8) {
        $lpLeaf = "$lpLeaf/seg-{0:00}-{1}" -f $i, ('pad' * 9)
        $lpLevels.Add($lpLeaf)
    }
    Assert-That 'the long-path fixture really is past MAX_PATH' ($lpLeaf.Length -gt 260) `
        "leaf is only $($lpLeaf.Length) chars, so this case would prove nothing"

    $lpBack = Join-Path $repo "tmp/lp-back-$sftpTag.bin"
    if (Test-Path $lpBack) { [System.IO.File]::Delete($lpBack) }
    $lpBatch = (@("mkdir $lpRoot") + ($lpLevels | ForEach-Object { "mkdir $_" })) -join "`n"
    $lpBatch += @"

put $($localUp.Replace($bs,'/')) $lpLeaf/up.bin
put $($localUp.Replace($bs,'/')) $lpRoot/shallow.bin
get $lpLeaf/up.bin $($lpBack.Replace($bs,'/'))
rename $lpLeaf/up.bin $lpLeaf/moved.bin
mkdir $lpLeaf/sub
rmdir $lpLeaf/sub
chmod 644 $lpLeaf/moved.bin
ls -l $lpLeaf
quit
"@
    $r = Invoke-Sftp $lpBatch 'longpath' -TimeoutMs 480000
    Assert-That 'the whole cycle works on a path past MAX_PATH' (($r.ExitCode -eq 0) -and -not $r.Hung) `
        "$($r.Phase) exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"
    $lpHash = if (Test-Path $lpBack) { Get-Sha ([System.IO.File]::ReadAllBytes($lpBack)) } else { 'MISSING' }
    Assert-That 'a download from a long path is bit-exact' ($lpHash -eq $wantHash) "got $lpHash"

    # The listing is what caught a struct-packing bug that produced plausible garbage: names read two
    # WCHARs late, sizes 0 and times 1601. So assert the name AND the size, not just that a row exists.
    $lpRows = ($r.Out -split "`r?`n") | Where-Object { $_ -match '^[-d]rw' }
    Assert-That 'a long-path listing shows the real name and size' `
        (@($lpRows | Where-Object { $_ -match "\s$($payload.Length)\s" -and $_ -match 'moved\.bin' }).Count -eq 1) `
        "rows='$($lpRows -join ' | ')'"
    Assert-That 'rmdir inside a long path removes the directory' `
        (@($lpRows | Where-Object { $_ -match '^drw' }).Count -eq 0) "rows='$($lpRows -join ' | ')'"

    # ---- 10c. a recursive get whose leaves are deep. This is the shape the original bug report
    # described, and it is also the regression test for '.' and '..' being skipped in a listing:
    # when they were not, the client recursed until its own "Maximum directory depth exceeded".
    $lpRecv = Join-Path $repo "tmp/r-$sftpTag"
    if ([System.IO.Directory]::Exists($lpRecv)) { [System.IO.Directory]::Delete($lpRecv, $true) }
    $null = [System.IO.Directory]::CreateDirectory($lpRecv)
    $r = Invoke-Sftp "get -r $lpRoot $($lpRecv.Replace($bs,'/'))`nquit`n" 'longpath-r' -TimeoutMs 600000
    $lpGot = @([System.IO.Directory]::GetFiles($lpRecv, '*', [System.IO.SearchOption]::AllDirectories))
    Assert-That 'a recursive get walks into a directory past MAX_PATH' `
        ((@($lpGot | Where-Object { $_ -match 'moved\.bin$' }).Count -eq 1) -and
         (@($lpGot | Where-Object { $_ -match 'shallow\.bin$' }).Count -eq 1)) `
        "retrieved $($lpGot.Count) files: $(($lpGot | ForEach-Object { Split-Path $_ -Leaf }) -join ',')"
    Assert-That 'a recursive get does not recurse into . or ..' ($r.Err -notmatch 'directory depth') `
        "err='$($r.Err -replace "`r?`n", ' | ')'"

    # ---- 10d. the two behaviour changes the prefix brings, asserted rather than left to surprise
    # someone. \\?\ preserves trailing dots and spaces, which would create names no ordinary tool on
    # the remote could reopen, so the normaliser trims them; and it stops treating reserved names as
    # devices, so CON becomes an ordinary file. Both are deliberate.
    #
    # CON is created and removed inside one batch on purpose: the far side's own managed APIs would
    # resolve an unprefixed C:\...\CON to the console device, so nothing but sftp may touch it.
    $r = Invoke-Sftp @"
put $($localUp.Replace($bs,'/')) $farFwd/trailing...
put $($localUp.Replace($bs,'/')) $farFwd/CON
ls -l $farFwd
rm $farFwd/CON
quit
"@ 'prefixnames' -TimeoutMs 300000
    $nameRows = ($r.Out -split "`r?`n") | Where-Object { $_ -match '^[-d]rw' }
    Assert-That 'trailing dots are trimmed, so the name stays reopenable' `
        ((@($nameRows | Where-Object { $_ -match '\strailing$' }).Count -eq 1) -and
         (@($nameRows | Where-Object { $_ -match 'trailing\.' }).Count -eq 0)) `
        "rows='$($nameRows -join ' | ')'"
    Assert-That 'a reserved name is an ordinary file, not a device' `
        (@($nameRows | Where-Object { $_ -match "\s$($payload.Length)\s.*\sCON$" }).Count -eq 1) `
        "rows='$($nameRows -join ' | ')'"

    # Remove the deep tree through sftp, deepest first. Left behind, the far side's teardown would
    # silently fail to reach it and the suite would stop being footprint-free.
    $lpRm = New-Object System.Collections.Generic.List[string]
    $lpRm.Add("rm $lpLeaf/moved.bin")
    $lpRm.Add("rm $lpRoot/shallow.bin")
    for ($i = $lpLevels.Count - 1; $i -ge 0; $i--) { $lpRm.Add("rmdir $($lpLevels[$i])") }
    $lpRm.Add("rmdir $lpRoot")
    $lpRm.Add('quit')
    $r = Invoke-Sftp (($lpRm -join "`n") + "`n") 'longpath-rm' -TimeoutMs 480000
    Assert-That 'a long-path tree can be removed again' `
        ((Far-Sftp "[Console]::Out.Write((Test-Path -LiteralPath '$($lpRoot.Replace('/', $bs))').ToString())") -eq 'False') `
        "err='$($r.Err -replace "`r?`n", ' | ')'"
    if ([System.IO.Directory]::Exists($lpRecv)) { [System.IO.Directory]::Delete($lpRecv, $true) }

    # ---- 10e. symlinks, through the client that produces the real byte order.
    #
    # OpenSSH sends SSH_FXP_SYMLINK with the arguments REVERSED relative to the draft -- target
    # first, link second -- and a swapped server creates the link under the wrong name with no
    # error at all. Nothing but a real client can catch that, which is what this section is for:
    # every capable case below asserts the LINK is the name that came into existence and the
    # TARGET is the string stored in it, so a reversal fails loudly rather than subtly.
    #
    # Every target stays inside $farDir. PS 5.1's Remove-Item -Recurse traverses directory reparse
    # points, so a link pointing outside it would make the suite's own teardown delete somebody
    # else's files -- and the links are removed through sftp here, before that teardown runs.
    #
    # Far-side link inspection uses the 5.1 ETS .Target, not FileSystemInfo.LinkTarget: the far
    # side is Windows PowerShell on .NET Framework 4.8, where that .NET 6 property is silently
    # $null and the assertion could never pass.
    function Far-Link([string]$farPath) {
        return Far-Sftp @"
`$p = '$farPath'
if (-not (Test-Path -LiteralPath `$p)) { [Console]::Out.Write('ABSENT||') }
else {
    `$i = Get-Item -LiteralPath `$p -Force
    `$isLink = ((`$i.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    `$t = `$i.Target
    if (`$null -ne `$t -and `$t -isnot [string]) { `$t = @(`$t)[0] }
    [Console]::Out.Write('PRESENT|' + `$isLink + '|' + [string]`$t)
}
"@
    }

    # The capability probe is an ordinary attempt rather than a query, because there is no query:
    # the three routes (an unrestricted token holding SeCreateSymbolicLinkPrivilege, group policy
    # leaving it in the restricted one, or Developer Mode plus the unprivileged-create flag) are
    # not all visible from user space. The two transports are expected to take different routes --
    # this client runs filtered with Developer Mode on, the WinRM remote holds the privilege -- so
    # both are exercised across a full run, and neither branch is a skip.
    $r = Invoke-Sftp "ln -s $farFwd/up.bin $farFwd/abs.lnk`nquit`n" 'symlink'
    $canLink = ($r.ExitCode -eq 0) -and -not $r.Hung

    if (-not $canLink) {
        # sftp renders the status code through its own fx2txt, not the server's message, so the
        # actionable text naming the three routes is asserted in the xUnit suite where the STATUS
        # string is readable. What the real client can prove is the mapping: PERMISSION_DENIED,
        # not OP_UNSUPPORTED, which is what stops a client concluding we never do links at all.
        Assert-That 'a machine that cannot create links says permission, not unsupported' `
            (($r.Err -match 'Permission denied') -and ($r.Err -notmatch 'not supported|unsupported')) `
            "err='$($r.Err -replace "`r?`n", ' | ')'"
    }
    else {
        $absLink = Far-Link "$farDir${bs}abs.lnk"
        Assert-That 'ln -s creates a link under the name the client asked for' `
            ($absLink -eq "PRESENT|True|$farDir${bs}up.bin") "got '$absLink'"

        # A link is only useful if it can be read through, and this is the STAT-follows-links path
        # as well: the client sizes the transfer from STAT, so a link-sized answer truncates it.
        $lnkLocal = Join-Path $repo "tmp/sftp-lnk-$sftpTag.bin"
        $r = Invoke-Sftp @"
get $farFwd/abs.lnk $($lnkLocal.Replace($bs,'/'))
ls -l $farFwd
ls -l $farFwd/abs.lnk
quit
"@ 'symget'
        Assert-That 'a download through a symlink is bit-exact' `
            ((Test-Path -LiteralPath $lnkLocal) -and ((Get-Sha ([System.IO.File]::ReadAllBytes($lnkLocal))) -eq $wantHash)) `
            "$($r.Phase) err='$($r.Err -replace "`r?`n", ' | ')'"

        # The two listings above disagree, and that disagreement IS the LSTAT/STAT distinction --
        # the one thing in this change that a client can see. Listing the DIRECTORY goes through
        # READDIR, which carries LSTAT semantics, so the link shows as a link; that bit is what
        # stops a recursive get walking into a junction for ever. Naming the link DIRECTLY goes
        # through STAT, which now follows, so it reports the target's type and the target's size.
        # A directory row ends in the bare name, a single-path row in the full /C:/ path, which is
        # what tells the two apart here.
        $lsRows = $r.Out -split "`r?`n"
        Assert-That 'a directory listing reports a symlink with a leading l' `
            (@($lsRows | Where-Object { $_ -match '^l.*\sabs\.lnk$' }).Count -eq 1) `
            "out='$($r.Out -replace "`r?`n", ' | ')'"
        Assert-That 'naming the link directly follows it, reporting the target size' `
            (@($lsRows | Where-Object { $_ -match "^-.*\s$($payload.Length)\s.*/abs\.lnk$" }).Count -eq 1) `
            "out='$($r.Out -replace "`r?`n", ' | ')'"

        # The relative target is the case ToWindows would silently mangle -- it resolves anything
        # relative against USERPROFILE -- so the stored string must come back byte-for-byte. The
        # link sits one directory down so the target is a real ../ rather than a bare name, and
        # ../up.bin still lands inside $farDir.
        $r = Invoke-Sftp @"
mkdir $farFwd/lnkdir
ln -s ../up.bin $farFwd/lnkdir/rel.lnk
quit
"@ 'symrel'
        $relLink = Far-Link "$farDir${bs}lnkdir${bs}rel.lnk"
        Assert-That 'a relative target is stored unmodified' `
            ($relLink -eq "PRESENT|True|..${bs}up.bin") "got '$relLink'"

        # A dangling link must still be created -- POSIX allows it, and refusing would break the
        # ordinary case of laying down a link before its target -- and must still read as a link.
        # Listed through the directory again, deliberately: naming it directly would go through
        # STAT, which now fails on a dangling link, and the case would then be asserting sftp's
        # fallback rather than ours. That STAT does fail is asserted in the xUnit suite instead.
        $r = Invoke-Sftp "ln -s $farFwd/nothing-here.bin $farFwd/dangle.lnk`nls -l $farFwd`nquit`n" 'symdangle'
        Assert-That 'a link to a missing target is created and reads as a link' `
            ((($r.ExitCode -eq 0) -and -not $r.Hung) -and
             (@(($r.Out -split "`r?`n") | Where-Object { $_ -match '^l.*\sdangle\.lnk$' }).Count -eq 1)) `
            "$($r.Phase) out='$($r.Out -replace "`r?`n", ' | ')'"

        $r = Invoke-Sftp "ln -s $farFwd/up.bin $farFwd/abs.lnk`nquit`n" 'symdup'
        Assert-That 'creating a link over an existing name fails' ($r.ExitCode -ne 0) `
            "exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"

        # rm on a DIRECTORY link. It carries FILE_ATTRIBUTE_DIRECTORY, so the old DoRemove refused
        # it and only rmdir worked -- the opposite of POSIX, and a wart this feature would have
        # created. RemoveDirectoryW on a name surrogate deletes the link and never the target,
        # which is the half worth asserting: lnkdir and its contents must survive.
        $r = Invoke-Sftp "ln -s $farFwd/lnkdir $farFwd/dirlnk`nrm $farFwd/dirlnk`nquit`n" 'symdirrm'
        $survivor = Far-Sftp "[Console]::Out.Write((Test-Path -LiteralPath '$farDir${bs}lnkdir${bs}rel.lnk').ToString())"
        Assert-That 'rm removes a directory link without touching its target' `
            ((($r.ExitCode -eq 0) -and -not $r.Hung) -and
             ((Far-Link "$farDir${bs}dirlnk") -eq 'ABSENT||') -and ($survivor -eq 'True')) `
            "$($r.Phase) survivor=$survivor err='$($r.Err -replace "`r?`n", ' | ')'"

        # Removed here rather than left to the blanket teardown, which traverses directory links.
        $r = Invoke-Sftp @"
rm $farFwd/abs.lnk
rm $farFwd/dangle.lnk
rm $farFwd/lnkdir/rel.lnk
rmdir $farFwd/lnkdir
quit
"@ 'symrm'
        Assert-That 'the links are removed again, leaving nothing behind' `
            ((Far-Link "$farDir${bs}lnkdir") -eq 'ABSENT||') `
            "$($r.Phase) err='$($r.Err -replace "`r?`n", ' | ')'"
    }

    # ---- 10f. df, i.e. statvfs@openssh.com.
    #
    # The client renders the reply through its own fx2txt and formatting rather than showing the
    # server's numbers raw, so this section asserts the shape of what a user sees; the eleven
    # fields themselves are pinned in the xUnit suite where they are readable.
    #
    # Note there are three OpenSSH installs on the development machine -- System32's 9.5p2, Git for
    # Windows' 9.7p1, and 10.0p2 under Program Files, which is the one PATH resolves for pwsh and
    # therefore the one these cases actually exercise. All three carry the guard the -i case below
    # depends on, but it is worth knowing which binary a result came from.
    $r = Invoke-Sftp "df $farFwd`nquit`n" 'df'
    Assert-That 'df succeeds' (($r.ExitCode -eq 0) -and -not $r.Hung) `
        "$($r.Phase) err='$($r.Err -replace "`r?`n", ' | ')'"
    # The negative is the one that proves the advertisement landed. If the VERSION reply omitted
    # the extension, or advertised it as "1" -- which the client compares against "2" exactly --
    # every positive assertion below would still hold on the header line alone.
    Assert-That 'the client does not report the extension as missing' `
        (($r.Out + $r.Err) -notmatch 'does not support statvfs') `
        "out='$($r.Out -replace "`r?`n", ' | ')' err='$($r.Err -replace "`r?`n", ' | ')'"
    Assert-That 'df prints a capacity table' `
        (($r.Out -match 'Size\s+Used\s+Avail') -and
         (@(($r.Out -split "`r?`n") | Where-Object { $_ -match '^\s*\d+\s+\d+\s+\d+\s+\d+\s+\d+%\s*$' }).Count -eq 1)) `
        "out='$($r.Out -replace "`r?`n", ' | ')'"

    # The suffix is two characters -- "820GB", not "820G" -- which is fmt_scaled's convention and
    # not the one a df on Linux would print.
    $r = Invoke-Sftp "df -h $farFwd`nquit`n" 'dfh'
    Assert-That 'df -h scales the figures' `
        (@(($r.Out -split "`r?`n") | Where-Object { $_ -match '^\s*\d+(\.\d+)?[KMGT]?B\s+\d+(\.\d+)?[KMGT]?B\s' }).Count -eq 1) `
        "out='$($r.Out -replace "`r?`n", ' | ')'"

    # Windows has no inode count, so the reply reports zero and the client prints ERR in the
    # capacity column rather than dividing by it. This is the only place that decision is checked
    # against the binary a user actually runs, rather than against the source of do_df -- and the
    # failure it guards against is not a wrong number but the client dying on a division by zero.
    $r = Invoke-Sftp "df -i $farFwd`nquit`n" 'dfi'
    Assert-That 'df -i reports unknown inodes without dividing by zero' `
        ((($r.ExitCode -eq 0) -and -not $r.Hung) -and
         ($r.Out -match 'Inodes\s+Used\s+Avail') -and ($r.Out -match 'ERR')) `
        "$($r.Phase) exit=$($r.ExitCode) out='$($r.Out -replace "`r?`n", ' | ')'"

    # The virtual root is a listing of drive letters we invent, not a filesystem, so it is refused.
    #
    # The refusal cannot be asserted on the client's output, because there is none: do_df calls
    # sftp_statvfs with quiet=1, so a server-side failure status prints NOTHING at all and the
    # message our server takes care to word is never shown to an sftp user. (It does reach a
    # library client and `-vvv`.) What is observable is the batch behaviour: unprefixed, the
    # failure aborts the run before `pwd`, which is what these two cases pin between them.
    $r = Invoke-Sftp "df /`npwd`nquit`n" 'dfroot'
    Assert-That 'df on the virtual root is refused' `
        (($r.ExitCode -ne 0) -and ($r.Out -notmatch 'Remote working directory')) `
        "$($r.Phase) exit=$($r.ExitCode) out='$($r.Out -replace "`r?`n", ' | ')'"

    # And with the '-' prefix that suppresses the abort, everything after it still runs -- so the
    # refusal costs the connection nothing.
    $r = Invoke-Sftp "-df /`npwd`nquit`n" 'dfroot2'
    Assert-That 'the session survives a refused df' `
        ((($r.ExitCode -eq 0) -and -not $r.Hung) -and ($r.Out -match 'Remote working directory: /[A-Za-z]:/')) `
        "$($r.Phase) exit=$($r.ExitCode) out='$($r.Out -replace "`r?`n", ' | ')'"

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

    # ---- 11b. the LEGACY scp protocol, via scp -O.
    #
    # Everything in section 11 above rides SFTP, because OpenSSH 9.x's scp does. `-O` forces the
    # original rcp-over-ssh protocol instead, which is what every other client speaks -- pscp,
    # SSH.NET's ScpClient, JSch, paramiko, and OpenSSH before 9.0 -- and which normally requires an
    # scp binary on the remote.
    #
    # These cases prove INTEROPERABILITY. They cannot by themselves prove the agent served the
    # protocol, because both this machine and the test remote have a real scp.exe on PATH: had the
    # command not been recognised, the exec would have fallen through to that binary and the
    # transfer would have succeeded anyway. The `pwssh-scp:` message asserted below is the
    # discriminator, and tests/Pwssh.Tests drives the protocol against a directly-constructed
    # agent where no external binary can be involved at all.
    $oScp = @('-O', '-p')

    $r = Invoke-Scp ($oScp + @($localUp, "${scpTgt}:$farFwd/o-up.bin"))
    Assert-That 'scp -O upload succeeds' (($r.ExitCode -eq 0) -and -not $r.Hung) `
        "exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"
    Assert-That 'scp -O upload is bit-exact' ((Far-Hash "$farDir${bs}o-up.bin") -eq $wantHash) `
        'far-side hash differs'

    $oDown = Join-Path $repo "tmp/sftp-odown-$sftpTag.bin"
    if (Test-Path -LiteralPath $oDown) { [System.IO.File]::Delete($oDown) }
    $r = Invoke-Scp ($oScp + @("${scpTgt}:$farFwd/o-up.bin", $oDown))
    $oh = if (Test-Path -LiteralPath $oDown) { Get-Sha ([System.IO.File]::ReadAllBytes($oDown)) } else { 'MISSING' }
    Assert-That 'scp -O download is bit-exact' ($oh -eq $wantHash) `
        "got $oh err='$($r.Err -replace "`r?`n", ' | ')'"

    # -p on the legacy path exercises the T record, which is acknowledged on its own -- treating it
    # and the following C record as one unit runs the whole transfer an ack behind.
    if (Test-Path -LiteralPath $oDown) {
        $odm = [System.IO.File]::GetLastWriteTimeUtc($oDown)
        Assert-That 'scp -O -p preserves mtime' ([math]::Abs(($odm - $stamp).TotalSeconds) -lt 2) `
            "got $($odm.ToString('o')) want $($stamp.ToString('o'))"
    }

    # The rename form: the target is not an existing directory, so the name in the C record is
    # ignored and the body lands at the target path. Measured against the reference, and easy to
    # get wrong by assuming the target is always a directory.
    $r = Invoke-Scp ($oScp + @($localUp, "${scpTgt}:$farFwd/o-renamed.bin"))
    Assert-That 'scp -O upload with rename lands at the target path' `
        ((Far-Hash "$farDir${bs}o-renamed.bin") -eq $wantHash) 'far-side hash differs'

    # A tree, which is the D/E nesting plus per-entry C records.
    $mkTree = New-FarSideCommand @"
New-Item -ItemType Directory -Path '$farDir${bs}otree${bs}inner' -Force | Out-Null
[System.IO.File]::WriteAllText('$farDir${bs}otree${bs}top.txt', 'TOP')
[System.IO.File]::WriteAllText('$farDir${bs}otree${bs}inner${bs}leaf.txt', 'LEAF')
[Console]::Out.Write('ok')
"@
    $null = Invoke-Ssh -Command $mkTree
    $oTreeDst = Join-Path $repo "tmp/sftp-otree-$sftpTag"
    if ([System.IO.Directory]::Exists($oTreeDst)) { [System.IO.Directory]::Delete($oTreeDst, $true) }
    New-Item -ItemType Directory -Path $oTreeDst -Force | Out-Null
    $r = Invoke-Scp @('-O', '-r', "${scpTgt}:$farFwd/otree", $oTreeDst.Replace($bs, '/'))
    $top = Join-Path $oTreeDst 'otree/top.txt'
    $leaf = Join-Path $oTreeDst 'otree/inner/leaf.txt'
    Assert-That 'scp -O -r brings the whole tree' `
        ((Test-Path -LiteralPath $top) -and (Test-Path -LiteralPath $leaf) -and
         ((Get-Content -LiteralPath $top -Raw) -eq 'TOP') -and ((Get-Content -LiteralPath $leaf -Raw) -eq 'LEAF')) `
        "exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"

    # A wildcard. A real scp relies on the remote SHELL to expand this before scp ever sees it;
    # there is no shell in that path here, so without server-side expansion it would look for a
    # file literally named "*.txt".
    $r = Invoke-Scp @('-O', "${scpTgt}:$farFwd/otree/$star.txt", $oTreeDst.Replace($bs, '/'))
    Assert-That 'scp -O expands a wildcard the remote shell would have' `
        ((Test-Path -LiteralPath (Join-Path $oTreeDst 'top.txt')) -and
         ((Get-Content -LiteralPath (Join-Path $oTreeDst 'top.txt') -Raw) -eq 'TOP')) `
        "exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"

    # A missing source, and the assertion that makes this section able to detect a fall-through:
    # our own message prefix. A real scp.exe would say "scp: ...: No such file or directory".
    $r = Invoke-Scp @('-O', "${scpTgt}:$farFwd/definitely-not-here.bin", (Join-Path $repo 'tmp').Replace($bs, '/'))
    Assert-That 'scp -O reports a missing source, and it is OUR implementation reporting it' `
        (($r.ExitCode -ne 0) -and ($r.Err -match 'pwssh-scp')) `
        "exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"

    # A directory without -r is refused rather than silently producing nothing.
    $r = Invoke-Scp @('-O', "${scpTgt}:$farFwd/otree", (Join-Path $repo 'tmp/never-dir.bin').Replace($bs, '/'))
    Assert-That 'scp -O refuses a directory without -r' `
        (($r.ExitCode -ne 0) -and ($r.Err -match 'not a regular file')) `
        "exit=$($r.ExitCode) err='$($r.Err -replace "`r?`n", ' | ')'"

    # Rekeying under the legacy protocol. The scp channel is an ordinary exec channel, so the
    # existing send gate covers it -- cheap to prove, since a rekey never touches WinRM.
    $r = Invoke-Scp @('-O', '-o', 'RekeyLimit=256K', "${scpTgt}:$farFwd/o-up.bin",
                      (Join-Path $repo "tmp/sftp-orekey-$sftpTag.bin").Replace($bs, '/'))
    $rkh = if (Test-Path -LiteralPath (Join-Path $repo "tmp/sftp-orekey-$sftpTag.bin")) {
        Get-Sha ([System.IO.File]::ReadAllBytes((Join-Path $repo "tmp/sftp-orekey-$sftpTag.bin"))) } else { 'MISSING' }
    Assert-That 'scp -O survives forced rekeys' ($rkh -eq $wantHash) `
        "got $rkh err='$($r.Err -replace "`r?`n", ' | ')'"

    if ([System.IO.Directory]::Exists($oTreeDst)) { [System.IO.Directory]::Delete($oTreeDst, $true) }

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

        # ---- 12d. a download whose replies are SPLIT across frames.
        #
        # The agent fragments a reply by whatever credit is available, so a window narrower than the
        # backlog makes a 255 KiB DATA reply arrive as several feeds. Nothing exercised that path
        # before: at the 32 MiB default with a prompt consumer, credit never approaches zero and no
        # reply ever splits -- which is exactly why the accounting bug in that path sat unnoticed.
        # 4 MiB: far below the read-ahead's ~16 MiB backlog, so replies split, but above the 2 MiB
        # GRANT_THRESHOLD a session channel needs before it announces any credit at all. Going under
        # that floor deadlocks rather than splitting, which is why the knob is now clamped.
        if ($Port -eq 0) {
            $splitLocal = Join-Path $repo "tmp/sftp-split-$sftpTag.bin"
            if (Test-Path $splitLocal) { [System.IO.File]::Delete($splitLocal) }
            [Environment]::SetEnvironmentVariable('PWSSH_CREDIT_MIB', '4')
            try {
                $r = Invoke-Sftp "get $farFwd/big.bin $($splitLocal.Replace($bs,'/'))`nquit`n" `
                     'split' @() '' '' 600000
            } finally {
                [Environment]::SetEnvironmentVariable('PWSSH_CREDIT_MIB', $null)
            }
            $splith = if (Test-Path $splitLocal) { Get-Sha ([System.IO.File]::ReadAllBytes($splitLocal)) } else { 'MISSING' }
            Assert-That 'a download with split replies is bit-exact' ($splith -eq $mkBig) `
                "$($r.Phase) got $splith want $mkBig err='$($r.Err -replace "`r?`n", ' | ')'"
        }
        else {
            Write-Host '  SKIP  a download with split replies is bit-exact (dev host: use -CreditKiB)' -ForegroundColor DarkGray
        }

        # ---- 12c. a valve trip while the framer holds an incomplete message.
        #
        # This is the case that caught a real corruption, and it needed both halves to coincide:
        # the valve has to trip, AND the framer has to be holding bytes it consumed for a
        # half-received message. The trip is guaranteed by the fault hook; whether a feed ends
        # mid-message was otherwise left to how ssh happened to packetise the client's writes,
        # which is why the bug appeared once and then hid for a dozen runs.
        # PWSSH_SFTP_SPLIT_CLIENT_FEED forces the second condition.
        #
        # The failure was not subtle once provoked: the held bytes were dropped, so everything
        # after arrived shifted, and the remote either rejected an absurd length ("bad SFTP packet
        # length 83886080" -- a READ type byte read as one) or, when the bogus length happened to
        # be plausible, waited for bytes that never came and the transfer hung. Hence a bounded
        # timeout here rather than the default.
        if ($Port -eq 0) {
            $resLocal = Join-Path $repo "tmp/sftp-residue-$sftpTag.bin"
            if (Test-Path $resLocal) { [System.IO.File]::Delete($resLocal) }
            [Environment]::SetEnvironmentVariable('PWSSH_SFTP_FAULT_AFTER_KIB', '2048')
            [Environment]::SetEnvironmentVariable('PWSSH_SFTP_SPLIT_CLIENT_FEED', '4')
            try {
                $r = Invoke-Sftp "get $farFwd/big.bin $($resLocal.Replace($bs,'/'))`nquit`n" `
                     'residue' @() '' '' 300000
            } finally {
                [Environment]::SetEnvironmentVariable('PWSSH_SFTP_FAULT_AFTER_KIB', $null)
                [Environment]::SetEnvironmentVariable('PWSSH_SFTP_SPLIT_CLIENT_FEED', $null)
            }
            $resh = if (Test-Path $resLocal) { Get-Sha ([System.IO.File]::ReadAllBytes($resLocal)) } else { 'MISSING' }
            Assert-That 'a valve trip with held bytes still downloads bit-exact' ($resh -eq $mkBig) `
                "$($r.Phase) got $resh want $mkBig err='$($r.Err -replace "`r?`n", ' | ')'"
        }
        else {
            Write-Host '  SKIP  a valve trip with held bytes still downloads bit-exact (dev host: env hooks are not visible to it)' -ForegroundColor DarkGray
        }

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
    # Directories as well as files: the globbed-get and recursive-get cases leave whole trees behind,
    # and File.Delete throws on a directory rather than removing it. The exception was swallowed by
    # the catch, so every run leaked a fixture directory until 15 of them had piled up.
    Get-ChildItem (Join-Path $repo 'tmp') -Filter "*$sftpTag*" -Force -ErrorAction SilentlyContinue |
        ForEach-Object {
            try {
                if ($_.PSIsContainer) { [System.IO.Directory]::Delete($_.FullName, $true) }
                else { [System.IO.File]::Delete($_.FullName) }
            } catch { }
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
