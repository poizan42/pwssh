# A "mule" session: carries downstream frames only.
#
# Each PSSession gets its own WSMan receive thread on the client, and that thread is the
# throughput ceiling, so extra sessions multiply receive capacity. A mule runs in a different
# wsmprovhost process from the agent that owns the child process, so frames reach it over a
# local named pipe; it forwards each one to its own pipeline output and nothing else.
#
# No C# is compiled here -- the mule never inspects a frame, it just relays bytes. That keeps
# mule startup to the cost of the session itself.
#
# Simple script (no [Parameter()] attributes, no [CmdletBinding()]): it takes no pipeline
# input, but the same rule is kept for consistency with the other remote scripts.

param(
    [string]$PipeName,
    [int]$ConnectTimeoutMs = 60000
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

if ([string]::IsNullOrEmpty($PipeName)) { throw 'pwssh: PipeName parameter is required' }

$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', $PipeName, [System.IO.Pipes.PipeDirection]::In)
try {
    $pipe.Connect($ConnectTimeoutMs)

    $lenBuf = New-Object byte[] 4
    while ($true) {
        # Read the 4-byte length exactly; a short read here would desynchronise the stream.
        $got = 0
        while ($got -lt 4) {
            $n = $pipe.Read($lenBuf, $got, 4 - $got)
            if ($n -le 0) { break }
            $got += $n
        }
        if ($got -lt 4) { break }        # pipe closed

        $len = ([int]$lenBuf[0] -shl 24) -bor ([int]$lenBuf[1] -shl 16) -bor ([int]$lenBuf[2] -shl 8) -bor [int]$lenBuf[3]
        if ($len -le 0 -or $len -gt 33554432) { throw "pwssh: implausible frame length $len" }

        $frame = New-Object byte[] $len
        $got = 0
        while ($got -lt $len) {
            $n = $pipe.Read($frame, $got, $len - $got)
            if ($n -le 0) { break }
            $got += $n
        }
        if ($got -lt $len) { break }     # truncated; agent is gone

        , $frame
    }
}
finally {
    try { $pipe.Dispose() } catch { }
}
