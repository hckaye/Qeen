using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class PathValidationFrameTests
{
    [Fact]
    public void PathChallengeFrame_Constructor_ValidData()
    {
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var frame = new PathChallengeFrame(data);
        
        Assert.Equal(8, frame.Data.Length);
        Assert.Equal(FrameType.PathChallenge, frame.Type);
    }
    
    [Theory]
    [InlineData(0)]
    [InlineData(7)]
    [InlineData(9)]
    public void PathChallengeFrame_Constructor_InvalidLength_Throws(int length)
    {
        var data = new byte[length];
        Assert.Throws<ArgumentException>(() => new PathChallengeFrame(data));
    }
    
    [Fact]
    public void PathChallengeFrame_EncodeDecode()
    {
        var data = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        var frame = new PathChallengeFrame(data);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        Assert.Equal(9, writer.BytesWritten); // 1 byte type + 8 bytes data
        Assert.Equal(0x1a, buffer[0]); // Frame type
        
        var reader = new FrameReader(buffer.AsSpan(1, 8));
        Assert.True(PathChallengeFrame.TryDecode(reader, out var decoded));
        Assert.Equal(data, decoded.Data.ToArray());
    }
    
    [Fact]
    public void PathResponseFrame_EncodeDecode()
    {
        var data = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
        var frame = new PathResponseFrame(data);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        Assert.Equal(9, writer.BytesWritten);
        Assert.Equal(0x1b, buffer[0]); // Frame type
        
        var reader = new FrameReader(buffer.AsSpan(1, 8));
        Assert.True(PathResponseFrame.TryDecode(reader, out var decoded));
        Assert.Equal(data, decoded.Data.ToArray());
    }
    
    [Fact]
    public void PathChallengeFrame_IsAllowedInPacketType()
    {
        var frame = new PathChallengeFrame(new byte[8]);
        
        // Not allowed in 0-RTT
        Assert.True(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.False(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void PathResponseFrame_IsAllowedInPacketType()
    {
        var frame = new PathResponseFrame(new byte[8]);
        
        // Only allowed in 1-RTT
        Assert.False(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.False(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.False(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void PathChallengeResponse_SameData()
    {
        var challengeData = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
        var challenge = new PathChallengeFrame(challengeData);
        
        // Response should echo the same data
        var response = new PathResponseFrame(challenge.Data);
        
        Assert.Equal(challenge.Data.ToArray(), response.Data.ToArray());
    }
}