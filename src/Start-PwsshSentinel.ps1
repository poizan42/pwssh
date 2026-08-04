# Deletes the remote WinRM shell as soon as the ProxyCommand dies.
#
# WHY THIS EXISTS
#
# `ssh` calls TerminateProcess on its ProxyCommand when it exits (ssh_kill_proxy_command), which on
# Windows is unblockable -- no finally runs, so pwssh-connect.ps1 never gets to say goodbye. The
# remote therefore learns nothing, and cannot: the WinRM service deliberately absorbs the client's
# disappearance so that a shell stays reconnectable, and the plugin ABI has no client-connectivity
# surface at all (see CLAUDE.md, "Why the remote cannot be told the client has gone"). The remote
# only recovers via its own 120 s inactivity watchdog, which is why -R listeners, child processes
# and NTFS locks linger.
#
# TerminateProcess kills the direct child ONLY. A grandchild survives -- and that is the whole
# trick. This script is that grandchild: it waits on a handle to its parent, which is signalled the
# instant ssh kills it, and then deletes the shell. The service reacts to the delete by signalling
# the shell operation's shutdown handle, which tears the session down properly, so the far side's
# job objects reap the children and the listener sockets and file handles go with them.
#
# The agent's watchdog stays as the backstop for the case this cannot cover: genuine network death,
# or the client machine losing power, where the sentinel dies with everything else.
#
# It needs no elevation and changes nothing on the remote -- Remove-WSManInstance against one's own
# shell is exactly the documented cleanup in CLAUDE.md, done a couple of minutes earlier.

param(
    # The process to watch. Normally the ProxyCommand's own PID.
    [int]$ParentPid,

    # The WinRM shell to delete. This is the client-side PSSession.InstanceId, which IS the WSMan
    # ShellId -- verified by comparing it against what the remote reports for its own shell.
    #
    # Deliberately NOT called -ShellId. `$ShellId` is a global READ-ONLY automatic variable holding
    # "Microsoft.PowerShell", so `param([string]$ShellId)` cannot bind at all -- every invocation
    # dies with "Cannot overwrite variable ShellId because it is read-only or constant", before a
    # line of the body runs. A plain assignment anywhere in a script fails the same way, which is
    # how this was found.
    #
    # Plural because -Streams opens a shell per mule, and every one of them lingers the same way.
    [string[]]$RemoteShell,

    [string]$ComputerName,

    # A credential file to load, for standalone or manual use.
    [string]$CredentialPath,

    # What pwssh-connect.ps1 actually uses: the credential arrives as CLIXML on stdin, so an inline
    # -Credential works exactly as well as a -CredentialPath and nothing is written to disk. The
    # password rides in the `<SS>` element that the CLIXML serializer produces, which is DPAPI-
    # encrypted to this user and machine -- parent and child are both, so it round-trips.
    #
    # stdin rather than an argument or an environment variable: a command line is readable by any
    # process of the same user and tends to end up in logs, and so does an environment block.
    [switch]$CredentialOnStdin,

    [string]$Authentication = 'Negotiate',
    [int]$Port = 0,
    [switch]$UseSSL,

    # Diagnostics only. Never write to stdout: a sentinel started with inherited handles would be
    # writing into the SSH transport.
    [string]$LogFile
)

$ErrorActionPreference = 'Stop'

function Note([string]$m) {
    if ($LogFile) {
        try { [IO.File]::AppendAllText($LogFile, (Get-Date).ToString('HH:mm:ss.fff') + "  $m`r`n") } catch { }
    }
}

Note "sentinel up: watching pid $ParentPid for shell(s) $($RemoteShell -join ', ') on $ComputerName"

if ($ParentPid -le 0 -or -not $RemoteShell -or [string]::IsNullOrEmpty($ComputerName)) {
    Note 'missing required arguments; nothing to do'
    return
}

# Take the credential BEFORE waiting, not after. The parent writes it and closes stdin immediately,
# so until it is read it sits in the pipe buffer -- fine for a ~1 KB credential, but reading it up
# front means the parent's write can never block on a full pipe, and the handle is not held open for
# what may be days of session.
$cred = $null
if ($CredentialOnStdin) {
    # Read to EOF. The caller must close the child's stdin -- pwssh-connect.ps1 always does, even
    # with nothing to send -- or this would wait for ever.
    try {
        $xml = [Console]::In.ReadToEnd()
        if (-not [string]::IsNullOrWhiteSpace($xml)) {
            $cred = [System.Management.Automation.PSSerializer]::Deserialize($xml)
            Note "credential received on stdin for $($cred.UserName)"
        }
    }
    catch { Note "could not read the credential from stdin: $($_.Exception.Message.Split([char]10)[0])" }
}
if (-not $cred -and $CredentialPath -and (Test-Path -LiteralPath $CredentialPath)) {
    try { $cred = Import-CliXml -Path $CredentialPath }
    catch { Note "could not load the credential: $($_.Exception.Message.Split([char]10)[0])" }
}
# No credential at all is a perfectly good case rather than a failure: with Negotiate against a
# machine the user can already reach as themselves, Remove-WSManInstance authenticates implicitly,
# which is exactly the situation of someone running pwssh with no -Credential.

# Wait for the parent, with no timeout: an interactive session may legitimately last for days, and
# a sentinel that gave up early would leave exactly the mess it exists to prevent. The wait itself
# is free -- it is a kernel object, not a poll.
try {
    $parent = Get-Process -Id $ParentPid -ErrorAction Stop
    Note 'parent found, waiting'
    $parent.WaitForExit()
    Note 'parent exited'
}
catch {
    # Already gone, or not openable. Either way, proceed to clean up.
    Note "parent not waitable ($($_.Exception.Message.Split([char]10)[0])); cleaning up anyway"
}

# From here everything is bounded and best-effort. A sentinel that throws is invisible.
$scheme = if ($UseSSL) { 'https' } else { 'http' }
$p = if ($Port -gt 0) { $Port } elseif ($UseSSL) { 5986 } else { 5985 }
$uri = "${scheme}://${ComputerName}:${p}/wsman"

foreach ($shell in $RemoteShell) {
    if ([string]::IsNullOrWhiteSpace($shell)) { continue }
    try {
        # Not $args, which is the automatic arguments array -- writable, unlike $ShellId, so it
        # would have worked, but shadowing an automatic in a script that also splats is asking for
        # a confusing afternoon.
        $removeArgs = @{
            ConnectionURI  = $uri
            ResourceURI    = 'shell'
            SelectorSet    = @{ ShellId = $shell }
            Authentication = $Authentication
            ErrorAction    = 'Stop'
        }
        if ($cred) { $removeArgs['Credential'] = $cred }

        Remove-WSManInstance @removeArgs
        Note "removed $shell"
    }
    catch {
        # The common and harmless case: pwssh-connect exited cleanly, tore its own session down, and
        # the shell is already gone. Each shell is attempted independently so one stale id cannot
        # strand the others.
        Note "could not remove $shell (usually already gone): $($_.Exception.Message.Split([char]10)[0])"
    }
}
Note 'done'
