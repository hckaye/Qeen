using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class StreamFrameTests
{
    [Fact]
    public void StreamFrame_Constructor_ValidInput()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var frame = new StreamFrame(123, 456, data, true);
        
        Assert.Equal(123u, frame.StreamId);
        Assert.Equal(456u, frame.Offset);
        Assert.Equal(5, frame.Data.Length);
        Assert.True(frame.Fin);
    }
    
    [Theory]
    [InlineData(false, false, false, 0x08)] // No flags
    [InlineData(true, false, false, 0x09)]  // FIN
    [InlineData(false, true, false, 0x0a)]  // LEN
    [InlineData(true, true, false, 0x0b)]   // FIN + LEN
    [InlineData(false, false, true, 0x0c)]  // OFF
    [InlineData(true, false, true, 0x0d)]   // FIN + OFF
    [InlineData(false, true, true, 0x0e)]   // LEN + OFF
    [InlineData(true, true, true, 0x0f)]    // FIN + LEN + OFF
    public void StreamFrame_Type_CorrectFlags(bool fin, bool hasData, bool hasOffset, byte expectedType)
    {
        var data = hasData ? new byte[] { 1, 2, 3 } : Array.Empty<byte>();
        var offset = hasOffset ? 100u : 0u;
        var frame = new StreamFrame(42, offset, data, fin);
        
        Assert.Equal((FrameType)expectedType, frame.Type);
    }
    
    [Fact]
    public void StreamFrame_Encode_WithAllFields()
    {
        var data = new byte[] { 0xAA, 0xBB, 0xCC };
        var frame = new StreamFrame(123, 456, data, true);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x0f, reader.ReadByte()); // Type with all flags
        Assert.True(reader.TryReadVariableLength(out var streamId));
        Assert.Equal(123u, streamId);
        Assert.True(reader.TryReadVariableLength(out var offset));
        Assert.Equal(456u, offset);
        Assert.True(reader.TryReadVariableLength(out var length));
        Assert.Equal(3u, length);
        var readData = reader.ReadBytes(3);
        Assert.Equal(data, readData.ToArray());
    }
    
    [Fact]
    public void StreamFrame_Encode_NoOffset()
    {
        var data = new byte[] { 0xAA, 0xBB };
        var frame = new StreamFrame(42, 0, data, false);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x0a, reader.ReadByte()); // Type with LEN flag only
        Assert.True(reader.TryReadVariableLength(out var streamId));
        Assert.Equal(42u, streamId);
        // No offset
        Assert.True(reader.TryReadVariableLength(out var length));
        Assert.Equal(2u, length);
    }
    
    [Fact]
    public void StreamFrame_IsAllowedInPacketType()
    {
        var frame = new StreamFrame(1, 0, Array.Empty<byte>());
        
        Assert.False(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.True(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.False(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void StreamFrame_TryDecode_WithAllFields()
    {
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(123); // Stream ID
        writer.WriteVariableLength(456); // Offset
        writer.WriteVariableLength(3);   // Length
        writer.WriteBytes(new byte[] { 0xAA, 0xBB, 0xCC });
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.True(StreamFrame.TryDecode(reader, 0x0f, out var frame));
        Assert.Equal(123u, frame.StreamId);
        Assert.Equal(456u, frame.Offset);
        Assert.Equal(3, frame.Data.Length);
        Assert.True(frame.Fin);
    }
}