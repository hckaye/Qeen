using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class AckFrameTests
{
    [Fact]
    public void AckFrame_Constructor_ValidInput()
    {
        var ranges = new List<AckRange> { new AckRange(0, 10) };
        var frame = new AckFrame(100, 50, ranges);
        
        Assert.Equal(100u, frame.LargestAcknowledged);
        Assert.Equal(50u, frame.AckDelay);
        Assert.Single(frame.AckRanges);
        Assert.Equal(FrameType.Ack, frame.Type);
    }
    
    [Fact]
    public void AckFrame_Constructor_EmptyRanges_Throws()
    {
        Assert.Throws<ArgumentException>(() => new AckFrame(100, 50, new List<AckRange>()));
    }
    
    [Fact]
    public void AckFrame_Encode_SingleRange()
    {
        var ranges = new List<AckRange> { new AckRange(0, 10) };
        var frame = new AckFrame(100, 50, ranges);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x02, reader.ReadByte()); // Frame type
        Assert.True(reader.TryReadVariableLength(out var largest));
        Assert.Equal(100u, largest);
        Assert.True(reader.TryReadVariableLength(out var delay));
        Assert.Equal(50u, delay);
        Assert.True(reader.TryReadVariableLength(out var rangeCount));
        Assert.Equal(0u, rangeCount); // Count - 1
        Assert.True(reader.TryReadVariableLength(out var firstRange));
        Assert.Equal(10u, firstRange);
    }
    
    [Fact]
    public void AckFrame_Encode_MultipleRanges()
    {
        var ranges = new List<AckRange> 
        { 
            new AckRange(0, 10),
            new AckRange(2, 5),
            new AckRange(1, 3)
        };
        var frame = new AckFrame(100, 50, ranges);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x02, reader.ReadByte()); // Frame type
        reader.TryReadVariableLength(out var largest);
        reader.TryReadVariableLength(out var delay);
        Assert.True(reader.TryReadVariableLength(out var rangeCount));
        Assert.Equal(2u, rangeCount); // Count - 1
    }
    
    [Fact]
    public void AckFrame_IsAllowedInPacketType_NotInZeroRtt()
    {
        var ranges = new List<AckRange> { new AckRange(0, 10) };
        var frame = new AckFrame(100, 50, ranges);
        
        Assert.True(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.False(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void AckFrame_TryDecode_Success()
    {
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        // Write test data
        writer.WriteVariableLength(100); // Largest acknowledged
        writer.WriteVariableLength(50);  // ACK delay
        writer.WriteVariableLength(0);   // Range count (1 range)
        writer.WriteVariableLength(10);  // First range length
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.True(AckFrame.TryDecode(reader, out var frame));
        Assert.Equal(100u, frame.LargestAcknowledged);
        Assert.Equal(50u, frame.AckDelay);
        Assert.Single(frame.AckRanges);
        Assert.Equal(10u, frame.AckRanges[0].Length);
    }
}