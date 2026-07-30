// Types a command into a shell stream and reads until a marker comes back.
//
// The line ending is a parameter, and that is not fussiness. Under a pty, ConPTY's console turns a
// bare CR into a line the way a terminal does. Over PIPES nothing does that translation, so cmd.exe
// reads the CR as part of the line and never executes it -- the shell starts, prints its banner, and
// then sits there. That failure looks exactly like a broken shell channel, so the distinction is
// worth having in one place with a name.

using System;
using System.Text;
using System.Threading;
using Renci.SshNet;

namespace Pwssh.Tests
{
    internal static class ShellDriver
    {
        /// <summary>What a terminal sends: ConPTY's console turns this into a line.</summary>
        public const string PtyNewline = "\r";

        /// <summary>What a pipe needs: nothing is translating on the way in.</summary>
        public const string PipeNewline = "\r\n";

        /// <summary>
        /// Bounded on purpose: a shell that never echoes is the failure being tested for, so an
        /// unbounded read would turn a clear assertion into a hung run.
        /// </summary>
        public static string Run(ShellStream shell, string command, string marker, string newline, int timeoutMs)
        {
            StringBuilder seen = new StringBuilder();
            shell.Write(command + newline);
            shell.Flush();

            int deadline = unchecked(Environment.TickCount + timeoutMs);
            while (unchecked(Environment.TickCount - deadline) < 0)
            {
                string s = shell.Read();
                if (!string.IsNullOrEmpty(s)) seen.Append(s);
                if (seen.ToString().IndexOf(marker, StringComparison.Ordinal) >= 0) break;
                Thread.Sleep(50);
            }
            return seen.ToString();
        }
    }
}
