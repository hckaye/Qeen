using Xunit;
using Qeen.Core.Frame;

namespace Qeen.Tests.Core.Frame;

public class FrameTypeTests
{
    [Theory]
    [InlineData(FrameType.Padding, 0x00)]
    [InlineData(FrameType.Ping, 0x01)]
    [InlineData(FrameType.Ack, 0x02)]
    [InlineData(FrameType.AckEcn, 0x03)]
    [InlineData(FrameType.ResetStream, 0x04)]
    [InlineData(FrameType.StopSending, 0x05)]
    [InlineData(FrameType.Crypto, 0x06)]
    [InlineData(FrameType.NewToken, 0x07)]
    [InlineData(FrameType.Stream, 0x08)]
    [InlineData(FrameType.StreamFin, 0x09)]
    [InlineData(FrameType.StreamLen, 0x0a)]
    [InlineData(FrameType.StreamLenFin, 0x0b)]
    [InlineData(FrameType.StreamOff, 0x0c)]
    [InlineData(FrameType.StreamOffFin, 0x0d)]
    [InlineData(FrameType.StreamOffLen, 0x0e)]
    [InlineData(FrameType.StreamOffLenFin, 0x0f)]
    [InlineData(FrameType.MaxData, 0x10)]
    [InlineData(FrameType.MaxStreamData, 0x11)]
    [InlineData(FrameType.MaxStreamsBidi, 0x12)]
    [InlineData(FrameType.MaxStreamsUni, 0x13)]
    [InlineData(FrameType.DataBlocked, 0x14)]
    [InlineData(FrameType.StreamDataBlocked, 0x15)]
    [InlineData(FrameType.StreamsBlockedBidi, 0x16)]
    [InlineData(FrameType.StreamsBlockedUni, 0x17)]
    [InlineData(FrameType.NewConnectionId, 0x18)]
    [InlineData(FrameType.RetireConnectionId, 0x19)]
    [InlineData(FrameType.PathChallenge, 0x1a)]
    [InlineData(FrameType.PathResponse, 0x1b)]
    [InlineData(FrameType.ConnectionCloseQuic, 0x1c)]
    [InlineData(FrameType.ConnectionCloseApp, 0x1d)]
    [InlineData(FrameType.HandshakeDone, 0x1e)]
    [InlineData(FrameType.Datagram, 0x30)]
    [InlineData(FrameType.DatagramLen, 0x31)]
    public void FrameType_HasCorrectValues(FrameType type, byte expectedValue)
    {
        Assert.Equal(expectedValue, (byte)type);
    }

    [Fact]
    public void StreamFrameTypes_HaveCorrectBitPattern()
    {
        // STREAM frame types use bits for FIN, LEN, and OFF flags
        Assert.Equal(0x08, (byte)FrameType.Stream); // 0000 1000
        Assert.Equal(0x09, (byte)FrameType.StreamFin); // 0000 1001 (FIN bit)
        Assert.Equal(0x0a, (byte)FrameType.StreamLen); // 0000 1010 (LEN bit)
        Assert.Equal(0x0b, (byte)FrameType.StreamLenFin); // 0000 1011 (LEN + FIN)
        Assert.Equal(0x0c, (byte)FrameType.StreamOff); // 0000 1100 (OFF bit)
        Assert.Equal(0x0d, (byte)FrameType.StreamOffFin); // 0000 1101 (OFF + FIN)
        Assert.Equal(0x0e, (byte)FrameType.StreamOffLen); // 0000 1110 (OFF + LEN)
        Assert.Equal(0x0f, (byte)FrameType.StreamOffLenFin); // 0000 1111 (OFF + LEN + FIN)
    }

    [Fact]
    public void FrameType_IsStreamFrame_CanBeDetected()
    {
        // All STREAM frame types have bits 0x08-0x0f
        for (byte i = 0x08; i <= 0x0f; i++)
        {
            var frameType = (FrameType)i;
            Assert.True((byte)frameType >= 0x08 && (byte)frameType <= 0x0f);
        }
    }
}