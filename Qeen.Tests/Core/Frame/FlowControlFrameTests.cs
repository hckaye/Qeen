using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class FlowControlFrameTests
{
    [Fact]
    public void MaxDataFrame_EncodeDecode()
    {
        var frame = new MaxDataFrame(1234567);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1)); // Skip frame type
        Assert.True(MaxDataFrame.TryDecode(reader, out var decoded));
        Assert.Equal(1234567u, decoded.MaximumData);
    }
    
    [Fact]
    public void MaxStreamDataFrame_EncodeDecode()
    {
        var frame = new MaxStreamDataFrame(42, 987654);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1));
        Assert.True(MaxStreamDataFrame.TryDecode(reader, out var decoded));
        Assert.Equal(42u, decoded.StreamId);
        Assert.Equal(987654u, decoded.MaximumStreamData);
    }
    
    [Fact]
    public void MaxStreamsFrame_Bidirectional_EncodeDecode()
    {
        var frame = new MaxStreamsFrame(true, 100);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        Assert.Equal(FrameType.MaxStreamsBidi, frame.Type);
        
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1));
        Assert.True(MaxStreamsFrame.TryDecode(reader, true, out var decoded));
        Assert.True(decoded.IsBidirectional);
        Assert.Equal(100u, decoded.MaximumStreams);
    }
    
    [Fact]
    public void MaxStreamsFrame_Unidirectional_EncodeDecode()
    {
        var frame = new MaxStreamsFrame(false, 50);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        Assert.Equal(FrameType.MaxStreamsUni, frame.Type);
        
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1));
        Assert.True(MaxStreamsFrame.TryDecode(reader, false, out var decoded));
        Assert.False(decoded.IsBidirectional);
        Assert.Equal(50u, decoded.MaximumStreams);
    }
    
    [Fact]
    public void DataBlockedFrame_EncodeDecode()
    {
        var frame = new DataBlockedFrame(65535);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1));
        Assert.True(DataBlockedFrame.TryDecode(reader, out var decoded));
        Assert.Equal(65535u, decoded.DataLimit);
    }
    
    [Fact]
    public void StreamDataBlockedFrame_EncodeDecode()
    {
        var frame = new StreamDataBlockedFrame(8, 32768);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1));
        Assert.True(StreamDataBlockedFrame.TryDecode(reader, out var decoded));
        Assert.Equal(8u, decoded.StreamId);
        Assert.Equal(32768u, decoded.StreamDataLimit);
    }
    
    [Fact]
    public void StreamsBlockedFrame_Bidirectional_EncodeDecode()
    {
        var frame = new StreamsBlockedFrame(true, 10);
        var buffer = new byte[100];
        var writer = new FrameWriter(buffer);
        
        frame.Encode(ref writer);
        
        Assert.Equal(FrameType.StreamsBlockedBidi, frame.Type);
        
        var reader = new FrameReader(buffer.AsSpan(1, writer.BytesWritten - 1));
        Assert.True(StreamsBlockedFrame.TryDecode(reader, true, out var decoded));
        Assert.True(decoded.IsBidirectional);
        Assert.Equal(10u, decoded.StreamLimit);
    }
    
    [Fact]
    public void FlowControlFrames_IsAllowedInPacketType()
    {
        var maxDataFrame = new MaxDataFrame(1000);
        var maxStreamDataFrame = new MaxStreamDataFrame(0, 1000);
        var dataBlockedFrame = new DataBlockedFrame(1000);
        
        // Should be allowed in 0-RTT and 1-RTT
        Assert.True(maxDataFrame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(maxDataFrame.IsAllowedInPacketType(PacketType.OneRtt));
        Assert.False(maxDataFrame.IsAllowedInPacketType(PacketType.Initial));
        Assert.False(maxDataFrame.IsAllowedInPacketType(PacketType.Handshake));
        
        Assert.True(maxStreamDataFrame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(maxStreamDataFrame.IsAllowedInPacketType(PacketType.OneRtt));
        
        Assert.True(dataBlockedFrame.IsAllowedInPacketType(PacketType.ZeroRtt));
        Assert.True(dataBlockedFrame.IsAllowedInPacketType(PacketType.OneRtt));
    }
}