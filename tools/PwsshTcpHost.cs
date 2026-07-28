// DEVELOPMENT ONLY. Runs the engine over a loopback TCP socket so the protocol can be
// exercised against the real ssh client without WinRM in the loop. Not part of the
// ProxyCommand path and never bound to anything but 127.0.0.1.

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Pwssh.Dev
{
    public static class TcpHost
    {
        public static void Run(int port, string hostKey, bool verbose)
        {
            Run(port, hostKey, verbose, false, 0);
        }

        public static void Run(int port, string hostKey, bool verbose, bool gatewayPorts)
        {
            Run(port, hostKey, verbose, gatewayPorts, 0);
        }

        public static void Run(int port, string hostKey, bool verbose, bool gatewayPorts, int latencyMs)
        {
            Run(port, hostKey, verbose, gatewayPorts, latencyMs, -1, 0);
        }

        public static void Run(int port, string hostKey, bool verbose, bool gatewayPorts,
                               int latencyMs, int readAheadChunks)
        {
            Run(port, hostKey, verbose, gatewayPorts, latencyMs, readAheadChunks, 0);
        }

        // readAheadChunks: -1 leaves PwsshConfig's default alone, which is what every caller that
        // is not specifically testing read-ahead wants. 0 disables it, and is how the suite gets a
        // byte-for-byte forwarding run to compare against without needing WinRM.
        public static void Run(int port, string hostKey, bool verbose, bool gatewayPorts,
                               int latencyMs, int readAheadChunks, int faultAfterKiB)
        {
            TcpListener l = new TcpListener(IPAddress.Loopback, port);
            l.Start();
            Console.Error.WriteLine("[pwssh] listening on 127.0.0.1:" + port
                + (latencyMs > 0 ? ("  latency " + latencyMs + " ms each way") : "")
                + (readAheadChunks >= 0 ? ("  read-ahead " + readAheadChunks) : "")
                + (faultAfterKiB > 0 ? ("  VALVE FAULT after " + faultAfterKiB + " KiB") : ""));
            while (true)
            {
                TcpClient c = l.AcceptTcpClient();
                Thread t = new Thread(new ParameterizedThreadStart(Serve));
                t.IsBackground = true;
                t.Start(new object[] { c, hostKey, verbose, gatewayPorts, latencyMs,
                                       readAheadChunks, faultAfterKiB });
            }
        }

        private static void Serve(object state)
        {
            object[] a = (object[])state;
            TcpClient c = (TcpClient)a[0];
            string hostKey = (string)a[1];
            bool verbose = (bool)a[2];
            bool gatewayPorts = (bool)a[3];
            int latencyMs = (int)a[4];
            int readAheadChunks = (int)a[5];
            int faultAfterKiB = (int)a[6];

            Console.Error.WriteLine("[pwssh] connection from " + c.Client.RemoteEndPoint);
            PwsshEngine eng = null;
            try
            {
                NetworkStream ns = c.GetStream();
                PwsshConfig cfg = new PwsshConfig();
                cfg.HostKey = hostKey;
                cfg.AllowGatewayPorts = gatewayPorts;
                if (readAheadChunks >= 0) cfg.SftpReadAheadChunks = readAheadChunks;
                cfg.SftpFaultAfterKiB = faultAfterKiB;
                // In-process agent wired through the real frame protocol, so this harness
                // exercises everything except the WinRM hop. ExpectedUser is deliberately left
                // unset so the HELLO round trip is exercised too.
                //
                // With no latency asked for this is the agent's own wiring, untouched, so the
                // default dev-host path is exactly what it always was.
                cfg.Agent = latencyMs > 0 ? StartDelayedLoopback(latencyMs) : PwsshLoopback.Start();
                eng = new PwsshEngine(cfg);
                eng.Start();

                PwsshEngine engRef = eng;
                Thread writer = new Thread(new ThreadStart(delegate
                {
                    try
                    {
                        while (true)
                        {
                            byte[] b = engRef.TakeOutbound(200);
                            Drain(engRef, verbose);
                            if (b != null && b.Length > 0)
                            {
                                ns.Write(b, 0, b.Length);
                                ns.Flush();
                            }
                            else if (engRef.Finished)
                            {
                                break;
                            }
                        }
                        try { c.Client.Shutdown(SocketShutdown.Send); } catch { }
                    }
                    catch (Exception ex) { Console.Error.WriteLine("[pwssh] writer: " + ex.Message); }
                }));
                writer.IsBackground = true;
                writer.Start();

                byte[] buf = new byte[32768];
                while (true)
                {
                    int n = ns.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    byte[] chunk = new byte[n];
                    Array.Copy(buf, 0, chunk, 0, n);
                    eng.PushInbound(chunk);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[pwssh] connection: " + ex.Message);
            }
            finally
            {
                if (eng != null)
                {
                    Drain(eng, verbose);
                    if (eng.LastError != null) Console.Error.WriteLine("[pwssh] ERROR: " + eng.LastError);
                    eng.Stop();
                }
                try { c.Close(); } catch { }
                Console.Error.WriteLine("[pwssh] connection closed");
            }
        }

        private static void Drain(PwsshEngine eng, bool verbose)
        {
            if (!verbose) return;
            string[] lines = eng.DrainLog();
            for (int i = 0; i < lines.Length; i++) Console.Error.WriteLine("[pwssh] " + lines[i]);
        }

        // ---------------------------------------------------------- injected latency
        //
        // The real transport's round trip is 600-900 ms, and that is the whole reason several
        // design decisions in this project exist. This harness normally has none, so it proves
        // correctness and hides every round-trip cost -- which makes it useless for judging any
        // change that sets out to reduce them.
        //
        // The delay is deliberately NOT a Thread.Sleep in the shuttle loop. That models one
        // frame per interval rather than an interval per frame: it serialises the link, so a
        // correctly pipelined design measures as though it were not pipelined at all, which is
        // the exact wrong answer. Instead every frame is stamped on arrival and released by a
        // delivery thread when it comes due, so a burst handed over together stays together and
        // arrives back to back one delay later.

        private static IPwsshAgent StartDelayedLoopback(int latencyMs)
        {
            PwsshAgentHost host = new PwsshAgentHost();
            PwsshAgentProxy proxy = new PwsshAgentProxy();
            host.Start();

            DelayedLink up = new DelayedLink(latencyMs, host, "up");
            DelayedLink down = new DelayedLink(latencyMs, proxy, "down");

            Thread upPump = new Thread(new ThreadStart(delegate
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
            }));
            upPump.IsBackground = true;
            upPump.Name = "pwssh-delayed-up";
            upPump.Start();

            Thread downPump = new Thread(new ThreadStart(delegate
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
            }));
            downPump.IsBackground = true;
            downPump.Name = "pwssh-delayed-down";
            downPump.Start();

            return proxy;
        }

        // One direction of the delayed link. Order is preserved for free: every frame gets the
        // same delay, so arrival order is release order and a plain FIFO suffices.
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
                Thread t = new Thread(new ThreadStart(Deliver));
                t.IsBackground = true;
                t.Name = "pwssh-delay-" + name;
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
                            // Everything queued has been delivered and no more is coming.
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
