// The `signal` channel request, which CLAUDE.md listed as "implemented but effectively untested".
//
// OpenSSH rarely sends SSH_MSG_CHANNEL_REQUEST "signal" -- under a pty, Ctrl+C arrives as ordinary
// channel data and the console handles it -- so there was no way to exercise it through the stock
// client. SSH.NET reaches it through SshCommand.CancelAsync, which calls SendSignalRequest with
// "TERM" or, with forceKill, "KILL".
//
// The interesting claim is not that the request is accepted but that it "maps to killing the child
// tree". `exec` runs the command as `%ComSpec% /c <cmd>`, so `ping` is a GRANDchild: killing only the
// direct cmd.exe would leave it running, and its output would stop reaching us either way, so quick
// completion on its own proves nothing. These tests therefore watch the process table for the
// specific ping that was started, which is what the Job Object with KILL_ON_JOB_CLOSE exists for.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using Renci.SshNet;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class SignalTests
    {
        // Long enough that finishing on its own could never be mistaken for being killed.
        private const string LongCommand = "ping -n 60 127.0.0.1";
        private const int CommandWouldTakeMs = 60000;

        private readonly ITestOutputHelper output;

        public SignalTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        private static HashSet<int> PingPids()
        {
            HashSet<int> pids = new HashSet<int>();
            // GetProcessesByName is case-insensitive and takes the name without .exe.
            foreach (Process p in Process.GetProcessesByName("PING"))
            {
                try { pids.Add(p.Id); } catch (Exception) { }
                p.Dispose();
            }
            return pids;
        }

        /// <summary>
        /// Waits for every pid in <paramref name="pids"/> to be gone. Bounded: a signal that does not
        /// kill the tree is exactly the failure under test, so this must not wait forever.
        /// </summary>
        private static bool AllGone(HashSet<int> pids, int timeoutMs)
        {
            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (unchecked(Environment.TickCount - deadline) < 0)
            {
                bool any = false;
                foreach (int pid in pids)
                {
                    try
                    {
                        using (Process p = Process.GetProcessById(pid))
                        {
                            if (!p.HasExited) { any = true; break; }
                        }
                    }
                    catch (ArgumentException)
                    {
                        // Already gone, which is what we are waiting for.
                    }
                }
                if (!any) return true;
                Thread.Sleep(100);
            }
            return false;
        }

        private void RunSignalCase(bool forceKill, string expectedName)
        {
            using (PwsshTestHost host = new PwsshTestHost())
            using (SshClient ssh = SshNetClient.Ssh(host))
            {
                ssh.Connect();
                using (SshCommand cmd = ssh.CreateCommand(LongCommand))
                {
                    // Anything already pinging on this machine is not ours, so take the difference
                    // rather than the absolute count.
                    HashSet<int> before = PingPids();

                    IAsyncResult ar = cmd.BeginExecute();

                    HashSet<int> ours = new HashSet<int>();
                    int deadline = unchecked(Environment.TickCount + 30000);
                    while (unchecked(Environment.TickCount - deadline) < 0)
                    {
                        foreach (int pid in PingPids())
                            if (!before.Contains(pid)) ours.Add(pid);
                        if (ours.Count > 0) break;
                        Thread.Sleep(100);
                    }
                    Assert.True(ours.Count > 0, "the remote command never started a ping to signal");
                    output.WriteLine("ping pid(s): " + string.Join(", ", ours));

                    Stopwatch sw = Stopwatch.StartNew();
                    cmd.CancelAsync(forceKill);
                    Assert.True(ar.AsyncWaitHandle.WaitOne(30000), "the command did not complete after the signal");
                    sw.Stop();

                    // Finishing early is necessary but not sufficient, so it is asserted alongside the
                    // process check rather than instead of it.
                    Assert.True(sw.ElapsedMilliseconds < CommandWouldTakeMs / 2,
                        "the command took " + sw.ElapsedMilliseconds + " ms, so it may just have run out");

                    // The claim that matters: the grandchild is gone, not merely detached.
                    Assert.True(AllGone(ours, 15000), "the signalled command left a ping running");

                    // And the request really was dispatched as a signal, with the name intact.
                    Assert.True(host.WaitForLog("signal: " + expectedName),
                        "no 'signal: " + expectedName + "' in the engine log");
                }
            }
        }

        [Fact]
        public void A_term_signal_kills_the_remote_child_tree()
        {
            RunSignalCase(false, "TERM");
        }

        [Fact]
        public void A_kill_signal_kills_the_remote_child_tree()
        {
            // The agent does not interpret the name -- any signal kills the channel -- so this is
            // about the name surviving the trip intact, and about KILL not taking a different path
            // by accident.
            RunSignalCase(true, "KILL");
        }

        [Fact]
        public void The_session_survives_a_signalled_channel()
        {
            // A signal tears down one channel, not the connection. Worth pinning because the engine
            // reaches Kill() through a different route here than on a normal exit.
            using (PwsshTestHost host = new PwsshTestHost())
            using (SshClient ssh = SshNetClient.Ssh(host))
            {
                ssh.Connect();
                using (SshCommand doomed = ssh.CreateCommand(LongCommand))
                {
                    IAsyncResult ar = doomed.BeginExecute();
                    Thread.Sleep(1500);           // let it actually start before signalling it
                    doomed.CancelAsync();
                    Assert.True(ar.AsyncWaitHandle.WaitOne(30000), "the command did not complete after the signal");
                }

                using (SshCommand after = ssh.CreateCommand("echo still-alive"))
                {
                    Assert.Contains("still-alive", after.Execute());
                }
            }
        }
    }
}
