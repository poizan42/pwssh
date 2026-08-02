# Compares the legacy scp protocol against SFTP for downloads, over whichever transport is given.
#
# Interleaved and repeated, because run-to-run variance on the WinRM link is wide enough to invert
# a conclusion -- it has done so twice in this project's history, and a single sample is not
# evidence. Each round runs every variant once, in the same order, and the reported figure is the
# median of the rounds.
#
# Three variants, because two of them bound the third:
#   exec  -- `ssh host "type file"`, the raw channel with no file protocol at all: the ceiling
#   sftp  -- what pwssh does today, read-ahead included
#   scp -O -- the legacy protocol, which streams the body with no per-chunk acknowledgement
#
# Every transfer is hashed. Throughput for corrupted bytes is not throughput.

param(
    [Parameter(Mandatory = $true)][string]$Target,
    [int]$Port = 0,
    [string]$ConfigFile,
    [string]$KnownHostsFile = 'tmp/known_hosts_winrm',
    [int]$SizeMiB = 32,
    [int]$Rounds = 3,
    [switch]$Incompressible,
    [switch]$SmallFiles,
    [int]$SmallCount = 40
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$bs = [char]92
$tag = [guid]::NewGuid().ToString('N').Substring(0, 8)

function Ssh-Args([string[]]$Extra) {
    $a = New-Object System.Collections.Generic.List[string]
    if ($ConfigFile) { $a.Add('-F'); $a.Add($ConfigFile) }
    if ($Port -gt 0) { $a.Add('-p'); $a.Add("$Port") }
    $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
    $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
    $a.Add('-o'); $a.Add('BatchMode=yes')
    foreach ($e in $Extra) { $a.Add($e) }
    return $a
}

function Run([string]$Exe, [string[]]$ArgList, [int]$TimeoutMs = 900000) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    foreach ($x in $ArgList) { $psi.ArgumentList.Add($x) }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $o = New-Object System.IO.MemoryStream
    $ot = $p.StandardOutput.BaseStream.CopyToAsync($o)
    $et = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($TimeoutMs)) { try { $p.Kill() } catch { }; throw "timed out: $Exe" }
    [void]$ot.Wait(30000)
    [void]$et.Wait(30000)
    return [pscustomobject]@{ Exit = $p.ExitCode; Bytes = $o.ToArray(); Err = $et.Result }
}

function Sha([byte[]]$b) {
    return [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash($b))
}

# The far side builds its own payload, so nothing large crosses the link on the way in.
$farDir = $null
$mk = @"
`$ProgressPreference = 'SilentlyContinue'
`$d = Join-Path `$env:TEMP 'pwssh-perf-$tag'
New-Item -ItemType Directory -Path `$d -Force | Out-Null
[Console]::Out.Write(`$d)
"@
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($mk))
$r = Run 'ssh' ((Ssh-Args @()) + @($Target, "powershell -NoProfile -NonInteractive -EncodedCommand $enc"))
$farDir = ([System.Text.Encoding]::ASCII.GetString($r.Bytes)).Trim()
if (-not $farDir) { throw "could not create the far-side scratch dir: $($r.Err)" }
$farFwd = $farDir.Replace($bs, '/')
Write-Host "far side: $farDir"

$results = @{}
function Note([string]$name, [double]$ms) {
    if (-not $results.ContainsKey($name)) { $results[$name] = New-Object System.Collections.Generic.List[double] }
    $results[$name].Add($ms)
}

if ($SmallFiles) {
    # The per-file case. scp costs two round trips per file (three with -p) because the C record
    # must be acknowledged before the body may flow, and that ack cannot be pipelined; SFTP costs
    # about three. Neither can do better, which is the honest framing.
    $mkMany = @"
`$ProgressPreference = 'SilentlyContinue'
`$d = '$farDir${bs}many'
New-Item -ItemType Directory -Path `$d -Force | Out-Null
for (`$i = 0; `$i -lt $SmallCount; `$i++) {
  [System.IO.File]::WriteAllText((Join-Path `$d ("f`$i.txt")), ('x' * 900))
}
[Console]::Out.Write('ok')
"@
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($mkMany))
    $null = Run 'ssh' ((Ssh-Args @()) + @($Target, "powershell -NoProfile -NonInteractive -EncodedCommand $enc"))

    for ($round = 1; $round -le $Rounds; $round++) {
        foreach ($variant in @('scp -O -r', 'sftp get -r')) {
            # Unique per round AND per variant. Sharing one directory between the two variants of a
            # round made the second one land on the first's leftovers, and the runs after the first
            # silently transferred nothing -- which then averaged into a median that compared a real
            # transfer against a failure. Hence also the explicit count check below: a timing for
            # zero files is not a timing.
            $safe = $variant.Replace(' ', '').Replace('-', '')
            $dst = Join-Path $repo "tmp/perf-$tag-many-$round-$safe"
            if ([System.IO.Directory]::Exists($dst)) { [System.IO.Directory]::Delete($dst, $true) }
            New-Item -ItemType Directory -Path $dst -Force | Out-Null
            $sw = [Diagnostics.Stopwatch]::StartNew()
            if ($variant -eq 'scp -O -r') {
                $a = New-Object System.Collections.Generic.List[string]
                if ($ConfigFile) { $a.Add('-F'); $a.Add($ConfigFile) }
                if ($Port -gt 0) { $a.Add('-P'); $a.Add("$Port") }
                $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
                $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
                $a.Add('-o'); $a.Add('BatchMode=yes')
                $a.Add('-O'); $a.Add('-r')
                $a.Add("${Target}:$farFwd/many"); $a.Add($dst.Replace($bs, '/'))
                $null = Run 'scp' $a
            }
            else {
                $batch = "get -r $farFwd/many $($dst.Replace($bs,'/'))`nquit`n"
                $a = New-Object System.Collections.Generic.List[string]
                if ($ConfigFile) { $a.Add('-F'); $a.Add($ConfigFile) }
                if ($Port -gt 0) { $a.Add('-P'); $a.Add("$Port") }
                $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
                $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
                $a.Add('-o'); $a.Add('BatchMode=yes')
                $a.Add('-b'); $a.Add('-'); $a.Add($Target)
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'sftp'
                foreach ($x in $a) { $psi.ArgumentList.Add($x) }
                $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
                $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.StandardInput.Write($batch); $p.StandardInput.Close()
                [void]$p.StandardOutput.ReadToEndAsync().Wait(900000)
                [void]$p.WaitForExit(900000)
            }
            $sw.Stop()
            $n = @(Get-ChildItem -Recurse -File $dst -ErrorAction SilentlyContinue).Count
            $ok = ($n -eq $SmallCount)
            Write-Host ("round {0} {1,-12} {2,8:N0} ms  files={3}{4}" -f `
                $round, $variant, $sw.Elapsed.TotalMilliseconds, $n, $(if ($ok) { '' } else { "  !! expected $SmallCount -- NOT COUNTED" }))
            # Only a complete transfer is a data point. Counting a partial or empty one is how a
            # median ends up comparing a real transfer against a failure.
            if ($ok) { Note $variant $sw.Elapsed.TotalMilliseconds }
            [System.IO.Directory]::Delete($dst, $true)
        }
    }
}
else {
    $size = $SizeMiB * 1024 * 1024
    $fill = if ($Incompressible) { '(New-Object System.Random 909).NextBytes($b)' } else { '' }
    $mkBig = @"
`$ProgressPreference = 'SilentlyContinue'
`$b = New-Object byte[] $size
$fill
[System.IO.File]::WriteAllBytes('$farDir${bs}big.bin', `$b)
[Console]::Out.Write([Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash(`$b)))
"@
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($mkBig))
    $r = Run 'ssh' ((Ssh-Args @()) + @($Target, "powershell -NoProfile -NonInteractive -EncodedCommand $enc"))
    $want = ([System.Text.Encoding]::ASCII.GetString($r.Bytes)).Trim()
    Write-Host ("payload: {0} MiB, {1}, sha {2}" -f $SizeMiB, $(if ($Incompressible) { 'incompressible' } else { 'compressible' }), $want.Substring(0, 12))

    for ($round = 1; $round -le $Rounds; $round++) {
        foreach ($variant in @('exec', 'sftp', 'scp -O')) {
            $dst = Join-Path $repo "tmp/perf-$tag-$round.bin"
            if (Test-Path -LiteralPath $dst) { [System.IO.File]::Delete($dst) }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $got = $null
            if ($variant -eq 'exec') {
                $rr = Run 'ssh' ((Ssh-Args @()) + @($Target, "cmd /c type `"$farDir${bs}big.bin`""))
                $got = Sha $rr.Bytes
            }
            elseif ($variant -eq 'scp -O') {
                $a = New-Object System.Collections.Generic.List[string]
                if ($ConfigFile) { $a.Add('-F'); $a.Add($ConfigFile) }
                if ($Port -gt 0) { $a.Add('-P'); $a.Add("$Port") }
                $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
                $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
                $a.Add('-o'); $a.Add('BatchMode=yes'); $a.Add('-O')
                $a.Add("${Target}:$farFwd/big.bin"); $a.Add($dst.Replace($bs, '/'))
                $null = Run 'scp' $a
                if (Test-Path -LiteralPath $dst) { $got = Sha ([System.IO.File]::ReadAllBytes($dst)) }
            }
            else {
                $a = New-Object System.Collections.Generic.List[string]
                if ($ConfigFile) { $a.Add('-F'); $a.Add($ConfigFile) }
                if ($Port -gt 0) { $a.Add('-P'); $a.Add("$Port") }
                $a.Add('-o'); $a.Add("UserKnownHostsFile=$KnownHostsFile")
                $a.Add('-o'); $a.Add('StrictHostKeyChecking=accept-new')
                $a.Add('-o'); $a.Add('BatchMode=yes')
                $a.Add('-b'); $a.Add('-'); $a.Add($Target)
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = 'sftp'
                foreach ($x in $a) { $psi.ArgumentList.Add($x) }
                $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
                $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
                $p = [System.Diagnostics.Process]::Start($psi)
                $p.StandardInput.Write("get $farFwd/big.bin $($dst.Replace($bs,'/'))`nquit`n")
                $p.StandardInput.Close()
                [void]$p.StandardOutput.ReadToEndAsync().Wait(900000)
                [void]$p.WaitForExit(900000)
                if (Test-Path -LiteralPath $dst) { $got = Sha ([System.IO.File]::ReadAllBytes($dst)) }
            }
            $sw.Stop()
            $ok = ($got -eq $want)
            $mib = $SizeMiB / ($sw.Elapsed.TotalSeconds)
            Write-Host ("round {0} {1,-8} {2,8:N0} ms  {3,6:N2} MiB/s  exact={4}" -f $round, $variant, $sw.Elapsed.TotalMilliseconds, $mib, $ok)
            if (-not $ok) { Write-Host "  !! NOT BIT-EXACT -- the timing is meaningless" -ForegroundColor Red }
            Note $variant $sw.Elapsed.TotalMilliseconds
            if (Test-Path -LiteralPath $dst) { [System.IO.File]::Delete($dst) }
        }
    }
}

Write-Host ""
Write-Host "medians:"
foreach ($k in $results.Keys) {
    $v = @($results[$k] | Sort-Object)
    if ($v.Count -eq 0) { Write-Host ("  {0,-12} no valid rounds" -f $k); continue }
    if ($v.Count -lt $Rounds) { Write-Host ("  (only {0} of {1} rounds counted for {2})" -f $v.Count, $Rounds, $k) }
    $med = $v[[int]([math]::Floor($v.Count / 2))]
    if ($SmallFiles) { Write-Host ("  {0,-12} {1,8:N0} ms" -f $k, $med) }
    else { Write-Host ("  {0,-8} {1,8:N0} ms  {2,6:N2} MiB/s" -f $k, $med, ($SizeMiB / ($med / 1000))) }
}

$cleanup = "Remove-Item -LiteralPath '$farDir' -Recurse -Force -ErrorAction SilentlyContinue"
$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($cleanup))
$null = Run 'ssh' ((Ssh-Args @()) + @($Target, "powershell -NoProfile -NonInteractive -EncodedCommand $enc"))
Write-Host "far side cleaned"
