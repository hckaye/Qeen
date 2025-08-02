using System.Text;
using Qeen.Core.Constants;
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
        var frame = new ConnectionCloseFrame(0x03, 0x01, "Frame error"); // 0x03 = FLOW_CONTROL_ERROR
        
        Assert.False(frame.IsApplicationClose);
        Assert.Equal(0x03u, frame.ErrorCode);
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
    
    [Fact]
    public void ConnectionCloseFrame_Constructor_ValidErrorCodes_Succeed()
    {
        // RFC 9000: Any valid error code should work (up to 62-bit max)
        // Standard transport error
        var transportFrame = new ConnectionCloseFrame(0x0a, 0x01, "Protocol violation");
        Assert.Equal(0x0au, transportFrame.ErrorCode);
        
        // Crypto error code
        var cryptoFrame = new ConnectionCloseFrame(0x0150, 0x01, "Crypto error");
        Assert.Equal(0x0150u, cryptoFrame.ErrorCode);
        
        // Custom error code (valid per RFC 9000)
        var customFrame = new ConnectionCloseFrame(0x456, 0x01, "Custom error");
        Assert.Equal(0x456u, customFrame.ErrorCode);
    }
    
    [Fact]
    public void ConnectionCloseFrame_Constructor_ReasonPhraseTooLong_Throws()
    {
        // Create a reason phrase that exceeds the maximum length
        var longReason = new string('a', QuicLimits.MaxReasonPhraseLength + 1);
        
        // Should throw for application close
        Assert.Throws<ArgumentException>(() => 
            new ConnectionCloseFrame(0x123, longReason));
        
        // Should throw for transport close
        Assert.Throws<ArgumentException>(() => 
            new ConnectionCloseFrame(0x03, 0x01, longReason));
    }
    
    [Fact]
    public void ConnectionCloseFrame_Constructor_MaxReasonPhraseLength_Succeeds()
    {
        // Create a reason phrase at exactly the maximum length
        var maxReason = new string('a', QuicLimits.MaxReasonPhraseLength);
        
        // Should succeed for application close
        var appFrame = new ConnectionCloseFrame(0x123, maxReason);
        Assert.Equal(maxReason, appFrame.ReasonPhrase);
        
        // Should succeed for transport close
        var transportFrame = new ConnectionCloseFrame(0x03, 0x01, maxReason);
        Assert.Equal(maxReason, transportFrame.ReasonPhrase);
    }
    
    [Fact]
    public void ConnectionCloseFrame_Constructor_InvalidFrameType_Throws()
    {
        // Frame type exceeds maximum
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            new ConnectionCloseFrame(0x03, ulong.MaxValue, "Error"));
    }
    
    [Fact]
    public void ConnectionCloseFrame_Constructor_InvalidErrorCode_Throws()
    {
        // Error code exceeds maximum variable integer (62-bit limit)
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            new ConnectionCloseFrame(ulong.MaxValue, "Error"));
        
        // Transport error code exceeds maximum
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            new ConnectionCloseFrame(ulong.MaxValue, 0x01, "Error"));
    }
    
    [Fact]
    public void ConnectionCloseFrame_TryDecode_ReasonPhraseTooLong_Fails()
    {
        var buffer = new byte[2000];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(0x123); // Error code
        writer.WriteVariableLength((ulong)(QuicLimits.MaxReasonPhraseLength + 1)); // Reason length (too long)
        
        var reader = new FrameReader(buffer.AsSpan(0, writer.BytesWritten));
        
        // Should fail due to reason phrase being too long
        Assert.False(ConnectionCloseFrame.TryDecode(reader, true, out _));
    }
}