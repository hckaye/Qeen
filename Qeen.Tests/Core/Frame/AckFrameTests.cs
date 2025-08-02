using Qeen.Core.Constants;
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
        var frame = new AckFrame(100, 400, ranges); // 400 microseconds
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x02, reader.ReadByte()); // Frame type
        Assert.True(reader.TryReadVariableLength(out var largest));
        Assert.Equal(100u, largest);
        Assert.True(reader.TryReadVariableLength(out var delay));
        // With default exponent 3: 400 / 8 = 50
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
        writer.WriteVariableLength(50);  // ACK delay (encoded)
        writer.WriteVariableLength(0);   // Range count (1 range)
        writer.WriteVariableLength(10);  // First range length
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.True(AckFrame.TryDecode(reader, out var frame));
        Assert.Equal(100u, frame.LargestAcknowledged);
        // With default exponent 3: 50 * 8 = 400 microseconds
        Assert.Equal(400u, frame.AckDelay);
        Assert.Single(frame.AckRanges);
        Assert.Equal(10u, frame.AckRanges[0].Length);
    }
    
    [Fact]
    public void AckFrame_EncodeDecodeWithCustomExponent_RoundTrip()
    {
        // Arrange
        byte ackDelayExponent = 5; // 2^5 = 32
        var ranges = new List<AckRange> { new AckRange(0, 15) };
        var originalFrame = new AckFrame(200, 3200, ranges); // 3200 microseconds
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        // Act - Encode with custom exponent
        originalFrame.Encode(ref writer, ackDelayExponent);
        
        // Verify encoded value
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        Assert.Equal(0x02, reader.ReadByte()); // Frame type
        reader.TryReadVariableLength(out var largest);
        reader.TryReadVariableLength(out var encodedDelay);
        // 3200 / 32 = 100
        Assert.Equal(100u, encodedDelay);
        
        // Decode with same exponent
        reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1)); // Skip frame type
        Assert.True(AckFrame.TryDecode(reader, ackDelayExponent, out var decodedFrame));
        
        // Assert
        Assert.Equal(originalFrame.LargestAcknowledged, decodedFrame.LargestAcknowledged);
        Assert.Equal(originalFrame.AckDelay, decodedFrame.AckDelay);
        Assert.Equal(originalFrame.AckRanges.Count, decodedFrame.AckRanges.Count);
    }
    
    [Fact]
    public void AckFrame_EncodeWithLargeDelay_HandlesCorrectly()
    {
        // Arrange
        var ranges = new List<AckRange> { new AckRange(0, 5) };
        ulong largeMicroseconds = 1_000_000; // 1 second in microseconds
        var frame = new AckFrame(500, largeMicroseconds, ranges);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        // Act
        frame.Encode(ref writer);
        
        // Assert
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        Assert.Equal(0x02, reader.ReadByte());
        reader.TryReadVariableLength(out var largest);
        reader.TryReadVariableLength(out var encodedDelay);
        // With default exponent 3: 1_000_000 / 8 = 125_000
        Assert.Equal(125_000u, encodedDelay);
    }
    
    [Fact]
    public void AckFrame_Constructor_TooManyRanges_Throws()
    {
        // Create more ranges than allowed
        var ranges = new List<AckRange>();
        for (ulong i = 0; i <= QuicLimits.MaxAckRanges; i++)
        {
            ranges.Add(new AckRange(i, 1));
        }
        
        // Should throw when exceeding max ranges
        Assert.Throws<ArgumentException>(() => 
            new AckFrame(100, 50, ranges));
    }
    
    [Fact]
    public void AckFrame_Constructor_MaxRanges_Succeeds()
    {
        // Create exactly the maximum number of ranges
        var ranges = new List<AckRange>();
        for (ulong i = 0; i < QuicLimits.MaxAckRanges; i++)
        {
            ranges.Add(new AckRange(i, 1));
        }
        
        // Should succeed with max ranges
        var frame = new AckFrame(100, 50, ranges);
        Assert.Equal((int)QuicLimits.MaxAckRanges, frame.AckRanges.Count);
    }
    
    [Fact]
    public void AckFrame_Constructor_InvalidPacketNumber_Throws()
    {
        var ranges = new List<AckRange> { new AckRange(0, 10) };
        
        // Packet number exceeds maximum
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            new AckFrame(ulong.MaxValue, 50, ranges));
    }
    
    [Fact]
    public void AckFrame_Constructor_InvalidAckDelay_Throws()
    {
        var ranges = new List<AckRange> { new AckRange(0, 10) };
        
        // ACK delay exceeds maximum
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            new AckFrame(100, ulong.MaxValue, ranges));
    }
    
    [Fact]
    public void AckFrame_TryDecode_TooManyRanges_Fails()
    {
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(100); // Largest acknowledged
        writer.WriteVariableLength(50);  // ACK delay
        writer.WriteVariableLength(QuicLimits.MaxAckRanges); // Too many ranges (count is 0-based)
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        // Should fail due to too many ranges
        Assert.False(AckFrame.TryDecode(reader, out _));
    }
    
    [Fact]
    public void AckFrame_MaxValues_RoundTrip()
    {
        // Test with maximum allowed values
        var ranges = new List<AckRange> { new AckRange(0, 100) };
        var maxPacketNumber = QuicLimits.MaxPacketNumber;
        var frame = new AckFrame(maxPacketNumber, 1000000, ranges);
        
        var buffer = new byte[200];
        var writer = new FrameWriter(buffer);
        
        // Encode
        frame.Encode(ref writer);
        
        // Decode (skip frame type byte)
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1));
        Assert.True(AckFrame.TryDecode(reader, out var decodedFrame));
        
        // Verify
        Assert.Equal(maxPacketNumber, decodedFrame.LargestAcknowledged);
    }
}