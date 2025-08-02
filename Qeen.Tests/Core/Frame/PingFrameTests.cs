using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class PingFrameTests
{
    [Fact]
    public void PingFrame_Instance_HasCorrectType()
    {
        var frame = PingFrame.Instance;
        Assert.Equal(FrameType.Ping, frame.Type);
    }
    
    [Fact]
    public void PingFrame_Encode_WritesSingleByte()
    {
        var frame = PingFrame.Instance;
        var buffer = new byte[10];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        Assert.Equal(1, writer.BytesWritten);
        Assert.Equal(0x01, buffer[0]);
    }
    
    [Fact]
    public void PingFrame_IsAllowedInPacketType_NotInZeroRtt()
    {
        var frame = PingFrame.Instance;
        
        Assert.True(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.False(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void PingFrame_TryDecode_Success()
    {
        var data = new byte[] { 0x01 };
        var reader = new FrameReader(data);
        reader.ReadByte(); // Frame type already read
        
        Assert.True(PingFrame.TryDecode(reader, out var frame));
        Assert.Equal(PingFrame.Instance, frame);
    }
}