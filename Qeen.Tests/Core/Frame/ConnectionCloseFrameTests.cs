using System.Text;
using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class ConnectionCloseFrameTests
{
    [Fact]
    public void ConnectionCloseFrame_Constructor_ApplicationError()
    {
        var frame = new ConnectionCloseFrame(0x123, "Test reason");
        
        Assert.True(frame.IsApplicationClose);
        Assert.Equal(0x123u, frame.ErrorCode);
        Assert.Null(frame.FrameType);
        Assert.Equal("Test reason", frame.ReasonPhrase);
        Assert.Equal(FrameType.ConnectionCloseApp, frame.Type);
    }
    
    [Fact]
    public void ConnectionCloseFrame_Constructor_TransportError()
    {
        var frame = new ConnectionCloseFrame(0x456, 0x01, "Frame error");
        
        Assert.False(frame.IsApplicationClose);
        Assert.Equal(0x456u, frame.ErrorCode);
        Assert.Equal(0x01u, frame.FrameType);
        Assert.Equal("Frame error", frame.ReasonPhrase);
        Assert.Equal(FrameType.ConnectionCloseQuic, frame.Type);
    }
    
    [Fact]
    public void ConnectionCloseFrame_Encode_ApplicationError()
    {
        var frame = new ConnectionCloseFrame(0x123, "Test");
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x1d, reader.ReadByte()); // CONNECTION_CLOSE_APP
        Assert.True(reader.TryReadVariableLength(out var errorCode));
        Assert.Equal(0x123u, errorCode);
        Assert.True(reader.TryReadVariableLength(out var reasonLength));
        Assert.Equal(4u, reasonLength);
        var reasonBytes = reader.ReadBytes((int)reasonLength);
        Assert.Equal("Test", Encoding.UTF8.GetString(reasonBytes));
    }
    
    [Fact]
    public void ConnectionCloseFrame_Encode_TransportError()
    {
        var frame = new ConnectionCloseFrame(0x456, 0x02, "Error");
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.Equal(0x1c, reader.ReadByte()); // CONNECTION_CLOSE_QUIC
        Assert.True(reader.TryReadVariableLength(out var errorCode));
        Assert.Equal(0x456u, errorCode);
        Assert.True(reader.TryReadVariableLength(out var frameType));
        Assert.Equal(0x02u, frameType);
        Assert.True(reader.TryReadVariableLength(out var reasonLength));
        Assert.Equal(5u, reasonLength);
    }
    
    [Fact]
    public void ConnectionCloseFrame_IsAllowedInPacketType_AlwaysTrue()
    {
        var frame = new ConnectionCloseFrame(0, "");
        
        Assert.True(frame.IsAllowedInPacketType(PacketType.Initial));
        Assert.True(frame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(frame.IsAllowedInPacketType(PacketType.Handshake));
        Assert.True(frame.IsAllowedInPacketType(PacketType.OneRtt));
    }
    
    [Fact]
    public void ConnectionCloseFrame_TryDecode_ApplicationError()
    {
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(0x123); // Error code
        writer.WriteVariableLength(4);     // Reason length
        writer.WriteBytes(Encoding.UTF8.GetBytes("Test"));
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.True(ConnectionCloseFrame.TryDecode(reader, true, out var frame));
        Assert.True(frame.IsApplicationClose);
        Assert.Equal(0x123u, frame.ErrorCode);
        Assert.Equal("Test", frame.ReasonPhrase);
    }
    
    [Fact]
    public void ConnectionCloseFrame_TryDecode_TransportError()
    {
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(0x456); // Error code
        writer.WriteVariableLength(0x02);  // Frame type
        writer.WriteVariableLength(5);     // Reason length
        writer.WriteBytes(Encoding.UTF8.GetBytes("Error"));
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        Assert.True(ConnectionCloseFrame.TryDecode(reader, false, out var frame));
        Assert.False(frame.IsApplicationClose);
        Assert.Equal(0x456u, frame.ErrorCode);
        Assert.Equal(0x02u, frame.FrameType);
        Assert.Equal("Error", frame.ReasonPhrase);
    }
}