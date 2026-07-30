// The frame protocol itself, which nothing else asserts directly.
//
// Both of these earned their place by breaking something. The compression flag is why the frame-level
// driver first saw no replies at all: it matched on the raw type byte, and every SFTP reply arrives as
// OUT|COMPRESSED (0xC1) rather than OUT (0x81), because deflate saves well over the eighth that makes
// the agent set the flag. And HELLO carrying key=value pairs rather than a bare account name is what
// lets the client answer pty-req without a round trip.

using System;
using Pwssh;
using Xunit;
using Xunit.Abstractions;

namespace Pwssh.Tests
{
    public sealed class AgentFrameTests
    {
        private readonly ITestOutputHelper output;

        public AgentFrameTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void Hello_arrives_first_and_carries_the_negotiated_capabilities()
        {
            PwsshAgentHost host = new PwsshAgentHost();
            try
            {
                host.Start();
                byte[] f = host.TakeOutboundFrame(10000);
                Assert.NotNull(f);
                Assert.Equal(FrameType.HELLO, Frame.Type(f));
                Assert.Equal(0u, Frame.Channel(f));

                string hello = Frame.PayloadText(f);
                output.WriteLine("HELLO: " + hello);
                // key=value pairs, not a bare account name: the client parses conpty out of this to
                // answer pty-req immediately, and asking later would cost a round trip per session.
                Assert.Contains("user=", hello);
                Assert.Contains("conpty=", hello);
            }
            finally
            {
                host.Stop();
            }
        }

        [Fact]
        public void An_sftp_reply_arrives_as_out_with_the_compression_flag_set()
        {
            PwsshAgentHost host = new PwsshAgentHost();
            try
            {
                host.Start();
                host.PushInbound(Frame.MakeText(FrameType.SUBSYSTEM, 1, "sftp"));
                host.PushInbound(Frame.Make(FrameType.DATA, 1, AgentSftpDriver.Init(3)));

                byte[] reply = null;
                int deadline = unchecked(Environment.TickCount + 10000);
                while (unchecked(Environment.TickCount - deadline) < 0)
                {
                    byte[] f = host.TakeOutboundFrame(200);
                    if (f == null) continue;
                    if ((byte)(Frame.Type(f) & ~FrameType.COMPRESSED) == FrameType.OUT
                        && Frame.Channel(f) == 1u)
                    {
                        reply = f;
                        break;
                    }
                }

                Assert.NotNull(reply);
                output.WriteLine(string.Format("reply type=0x{0:X2}", Frame.Type(reply)));
                Assert.Equal(FrameType.COMPRESSED, (byte)(Frame.Type(reply) & FrameType.COMPRESSED));

                // And it really does inflate to the VERSION reply, so the flag is not merely set.
                byte[] payload = Zip.Inflate(reply, Frame.HEADER, reply.Length - Frame.HEADER);
                Assert.Equal(AgentSftpDriver.SftpTypeByte.Version, payload[4]);
            }
            finally
            {
                host.Stop();
            }
        }
    }
}
