// An in-process agent with a round trip, for tests that need one.
//
// This is the same mechanism as StartDelayedLoopback/DelayedLink in tools/PwsshTcpHost.cs, which is
// private there. Duplicated rather than exposed, because tools/ is dev-only and the test project
// deliberately does not compile it.
//
// WHY A TEST NEEDS LATENCY AT ALL, which is not obvious and cost a debugging cycle to learn.
//
// A bare loopback does not merely hide round-trip costs, it changes which code paths run. The SFTP
// read-ahead issues up to `depth` requests and buffers whatever comes back, bounded in practice by
// the agent's credit rather than by depth; on a zero-latency link the whole of an 8 MiB file arrives
// before the client has consumed a megabyte of it. Refill then sees `p.Eof && p.Outstanding <= 0`
// and calls FinishPrefetch, which sets `active = null` -- so every remaining client read is forwarded
// to the remote and the buffered bytes are simply orphaned. Measured on an 8 MiB sequential read at
// the default depth: served=45, forwarded=212, with no park, abandon or nonSeq recorded, because
// none of those paths were reached.
//
// So a test wanting a LIVE prefetch -- a mid-transfer seek, a parked read, anything about the
// non-sequential path -- must keep the prefetch from winning that race. Latency is the honest way:
// it is what the real transport has, and it is why the dev host grew the same knob.
//
// The delay is deliberately NOT a Thread.Sleep in the shuttle loop. That models one frame per
// interval instead of an interval per frame: it serialises the link, so a correctly pipelined design
// measures as though it were not pipelined. Every frame is stamped on arrival and released when due,
// so a burst handed over together stays together.

using System;
using System.Collections.Generic;
using System.Threading;
using Pwssh;

namespace Pwssh.Tests
{
    internal static class DelayedLoopback
    {
        /// <param name="latencyMs">One-way delay, so a round trip costs twice this.</param>
        public static IPwsshAgent Start(int latencyMs)
        {
            PwsshAgentHost host = new PwsshAgentHost();
            PwsshAgentProxy proxy = new PwsshAgentProxy();
            host.Start();

            DelayedLink up = new DelayedLink(latencyMs, host, "up");
            DelayedLink down = new DelayedLink(latencyMs, proxy, "down");

            Thread upPump = new Thread((ThreadStart)delegate
            {
                try
                {
                    while (true)
                    {
                        byte[] f = proxy.TakeOutboundFrame(200);
                        if (f != null) { up.Offer(f); continue; }
                        if (proxy.InboundClosed) break;
                    }
                }
                catch (Exception) { }
                finally { up.Close(); }
            });
            upPump.IsBackground = true;
            upPump.Name = "pwssh-test-delayed-up";
            upPump.Start();

            Thread downPump = new Thread((ThreadStart)delegate
            {
                try
                {
                    while (true)
                    {
                        byte[] f = host.TakeOutboundFrame(200);
                        if (f != null) { down.Offer(f); continue; }
                        if (host.Finished) break;
                    }
                }
                catch (Exception) { }
                finally { down.Close(); }
            });
            downPump.IsBackground = true;
            downPump.Name = "pwssh-test-delayed-down";
            downPump.Start();

            return proxy;
        }

        // One direction. Order is preserved for free: every frame gets the same delay, so arrival
        // order is release order and a plain FIFO suffices.
        private sealed class DelayedLink
        {
            private sealed class Pending
            {
                public int DueTick;
                public byte[] Frame;
            }

            private readonly int delayMs;
            private readonly IByteReceiver sink;
            private readonly Queue<Pending> q = new Queue<Pending>();
            private readonly object gate = new object();
            private bool closing;

            public DelayedLink(int delayMs, IByteReceiver sink, string name)
            {
                this.delayMs = delayMs;
                this.sink = sink;
                Thread t = new Thread((ThreadStart)Deliver);
                t.IsBackground = true;
                t.Name = "pwssh-test-delay-" + name;
                t.Start();
            }

            public void Offer(byte[] frame)
            {
                Pending p = new Pending();
                p.Frame = frame;
                p.DueTick = unchecked(Environment.TickCount + delayMs);
                lock (gate) { q.Enqueue(p); Monitor.PulseAll(gate); }
            }

            public void Close()
            {
                lock (gate) { closing = true; Monitor.PulseAll(gate); }
            }

            private void Deliver()
            {
                while (true)
                {
                    Pending p = null;
                    lock (gate)
                    {
                        while (q.Count == 0 && !closing) Monitor.Wait(gate, 50);
                        if (q.Count == 0)
                        {
                            if (closing) break;
                            continue;
                        }
                        Pending head = q.Peek();
                        int remaining = unchecked(head.DueTick - Environment.TickCount);
                        if (remaining > 0)
                        {
                            Monitor.Wait(gate, remaining);
                            continue;                      // recheck: something may have been queued
                        }
                        p = q.Dequeue();
                    }
                    try { sink.PushInbound(p.Frame); } catch (Exception) { }
                }
                try { sink.CloseInbound(); } catch (Exception) { }
            }
        }
    }
}
