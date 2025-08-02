using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class PaddingFrameTests
{
    [Fact]
    public void PaddingFrame_Constructor_ValidLength()
    {
        var frame = new PaddingFrame(10);
        Assert.Equal(10, frame.Length);
        Assert.Equal(FrameType.Padding, frame.Type);
    }
    
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void PaddingFrame_Constructor_InvalidLength_Throws(int length)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new PaddingFrame(length));
    }
    
    [Fact]
    public void PaddingFrame_Encode_WritesZeroBytes()
    {
        var frame = new PaddingFrame(5);
        var buffer = new byte[10];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        Assert.Equal(5, writer.BytesWritten);
        Assert.All(buffer.Take(5), b => Assert.Equal(0, b));
    }
    
    [Fact]
    public void PaddingFrame_IsAllowedInPacketType_AlwaysTrue()
    {
        var frame = new PaddingFrame(1);
        
        Assert.True(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.True(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void PaddingFrame_TryDecode_SingleByte()
    {
        var data = new byte[] { 0x00, 0x01 }; // One padding byte followed by non-padding
        var reader = new FrameReader(data.AsSpan(1)); // Start after first 0x00
        
        Assert.True(PaddingFrame.TryDecode(reader, out var frame));
        Assert.Equal(1, frame.Length);
    }
    
    [Fact]
    public void PaddingFrame_TryDecode_MultipleBytes()
    {
        var data = new byte[] { 0x00, 0x00, 0x00, 0x01 }; // Three padding bytes
        var reader = new FrameReader(data.AsSpan(1)); // Start after first 0x00
        
        Assert.True(PaddingFrame.TryDecode(reader, out var frame));
        Assert.Equal(3, frame.Length); // 1 (initial) + 2 (additional)
    }
}