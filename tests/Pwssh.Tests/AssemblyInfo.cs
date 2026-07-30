// Serialized rather than parallel, on purpose.
//
// Everything a test normally needs is per-connection state on PwsshConfig, so parallelism would be
// safe for most of it. But several knobs are process-wide mutable statics -- PwsshAgentHost's
// InitialCredit, InitialTcpCredit, DisableConPty and DisableCoalescing, PwsshAgentProxy.KeepAliveMs,
// and Win32Fs's LongPathsSeen/LongestPath counters -- and a test that touches one of those would
// silently poison whatever ran beside it. Serializing also keeps each host's captured engine log
// attributable to the test that produced it, which is the only diagnostic a transport-level failure
// leaves behind.
//
// Revisit if the suite grows enough for wall-clock to matter; the fix then is a single collection
// for the static-touching tests rather than turning this back on wholesale.

using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]
