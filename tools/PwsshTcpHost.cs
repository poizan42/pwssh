// DEVELOPMENT ONLY. Runs the engine over a loopback TCP socket so the protocol can be
// exercised against the real ssh client without WinRM in the loop. Not part of the
// ProxyCommand path and never bound to anything but 127.0.0.1.

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Pwssh.Dev
{
    public static class TcpHost
    {
        public static void Run(int port, string hostKey, bool verbose)
        {
            Run(port, hostKey, verbose, false);
        }

        public static void Run(int port, string hostKey, bool verbose, bool gatewayPorts)
        {
            TcpListener l = new TcpListener(IPAddress.Loopback, port);
            l.Start();
            Console.Error.WriteLine("[pwssh] listening on 127.0.0.1:" + port);
            while (true)
            {
                TcpClient c = l.AcceptTcpClient();
                Thread t = new Thread(new ParameterizedThreadStart(Serve));
                t.IsBackground = true;
                t.Start(new object[] { c, hostKey, verbose, gatewayPorts });
            }
        }

        private static void Serve(object state)
        {
            object[] a = (object[])state;
            TcpClient c = (TcpClient)a[0];
            string hostKey = (string)a[1];
            bool verbose = (bool)a[2];
            bool gatewayPorts = (bool)a[3];

            Console.Error.WriteLine("[pwssh] connection from " + c.Client.RemoteEndPoint);
            PwsshEngine eng = null;
            try
            {
                NetworkStream ns = c.GetStream();
                PwsshConfig cfg = new PwsshConfig();
                cfg.HostKey = hostKey;
                cfg.AllowGatewayPorts = gatewayPorts;
                // In-process agent wired through the real frame protocol, so this harness
                // exercises everything except the WinRM hop. ExpectedUser is deliberately left
                // unset so the HELLO round trip is exercised too.
                cfg.Agent = PwsshLoopback.Start();
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
    }
}
