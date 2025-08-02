using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class CryptoFrameTests
{
    [Fact]
    public void CryptoFrame_Constructor_ValidInput()
    {
        var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var frame = new CryptoFrame(100, data);
        
        Assert.Equal(100u, frame.Offset);
        Assert.Equal(4, frame.Data.Length);
        Assert.Equal(FrameType.Crypto, frame.Type);
    }
    
    [Fact]
    public void CryptoFrame_Encode()
    {
        var data = new byte[] { 0xCA, 0xFE, 0xBA, 0xBE };
        var frame = new CryptoFrame(42, data);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x06, reader.ReadByte()); // CRYPTO frame type
        Assert.True(reader.TryReadVariableLength(out var offset));
        Assert.Equal(42u, offset);
        Assert.True(reader.TryReadVariableLength(out var length));
        Assert.Equal(4u, length);
        var readData = reader.ReadBytes(4);
        Assert.Equal(data, readData.ToArray());
    }
    
    [Fact]
    public void CryptoFrame_IsAllowedInPacketType()
    {
        var frame = new CryptoFrame(0, Array.Empty<byte>());
        
        Assert.True(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.False(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void CryptoFrame_TryDecode_Success()
    {
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        var expectedData = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        
        writer.WriteVariableLength(256); // Offset
        writer.WriteVariableLength(4);   // Length
        writer.WriteBytes(expectedData);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.True(CryptoFrame.TryDecode(reader, out var frame));
        Assert.Equal(256u, frame.Offset);
        Assert.Equal(4, frame.Data.Length);
        Assert.Equal(expectedData, frame.Data.ToArray());
    }
    
    [Fact]
    public void CryptoFrame_TryDecode_EmptyData()
    {
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(0); // Offset
        writer.WriteVariableLength(0); // Length
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.True(CryptoFrame.TryDecode(reader, out var frame));
        Assert.Equal(0u, frame.Offset);
        Assert.Equal(0, frame.Data.Length);
    }
}