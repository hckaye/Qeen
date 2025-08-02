using Qeen.Core.Stream;
using Xunit;

namespace Qeen.Tests.Core.Stream;

public class StreamManagerTests
{
    [Fact]
    public void StreamManager_CreateStream_ClientBidirectional()
    {
        var manager = new StreamManager(isClient: true);
        
        var stream = manager.CreateStream(StreamType.Bidirectional);
        
        Assert.Equal(0u, stream.StreamId);
        Assert.Equal(StreamType.Bidirectional, stream.Type);
        
        var stream2 = manager.CreateStream(StreamType.Bidirectional);
        Assert.Equal(4u, stream2.StreamId);
    }
    
    [Fact]
    public void StreamManager_CreateStream_ClientUnidirectional()
    {
        var manager = new StreamManager(isClient: true);
        
        var stream = manager.CreateStream(StreamType.Unidirectional);
        
        Assert.Equal(2u, stream.StreamId);
        Assert.Equal(StreamType.Unidirectional, stream.Type);
        
        var stream2 = manager.CreateStream(StreamType.Unidirectional);
        Assert.Equal(6u, stream2.StreamId);
    }
    
    [Fact]
    public void StreamManager_CreateStream_ServerBidirectional()
    {
        var manager = new StreamManager(isClient: false);
        
        var stream = manager.CreateStream(StreamType.Bidirectional);
        
        Assert.Equal(1u, stream.StreamId);
        Assert.Equal(StreamType.Bidirectional, stream.Type);
        
        var stream2 = manager.CreateStream(StreamType.Bidirectional);
        Assert.Equal(5u, stream2.StreamId);
    }
    
    [Fact]
    public void StreamManager_CreateStream_ServerUnidirectional()
    {
        var manager = new StreamManager(isClient: false);
        
        var stream = manager.CreateStream(StreamType.Unidirectional);
        
        Assert.Equal(3u, stream.StreamId);
        Assert.Equal(StreamType.Unidirectional, stream.Type);
        
        var stream2 = manager.CreateStream(StreamType.Unidirectional);
        Assert.Equal(7u, stream2.StreamId);
    }
    
    [Fact]
    public void StreamManager_TryGetStream_ExistingStream()
    {
        var manager = new StreamManager(isClient: true);
        var stream = manager.CreateStream(StreamType.Bidirectional);
        
        Assert.True(manager.TryGetStream(0, out var retrieved));
        Assert.NotNull(retrieved);
        Assert.Equal(stream.StreamId, retrieved!.StreamId);
    }
    
    [Fact]
    public void StreamManager_TryGetStream_NonExistentStream()
    {
        var manager = new StreamManager(isClient: true);
        
        Assert.False(manager.TryGetStream(100, out var stream));
        Assert.Null(stream);
    }
    
    [Fact]
    public void StreamManager_ProcessIncomingStream_ValidPeerStream()
    {
        var manager = new StreamManager(isClient: true);
        
        // Server-initiated bidirectional stream
        manager.ProcessIncomingStream(1, StreamType.Bidirectional);
        
        Assert.True(manager.TryGetStream(1, out var stream));
        Assert.NotNull(stream);
        Assert.Equal(1u, stream!.StreamId);
    }
    
    [Fact]
    public void StreamManager_ProcessIncomingStream_InvalidLocalStream_Throws()
    {
        var manager = new StreamManager(isClient: true);
        
        // Client-initiated stream ID used by server - invalid
        Assert.Throws<Qeen.Core.Exceptions.QuicException>(() => 
            manager.ProcessIncomingStream(0, StreamType.Bidirectional));
    }
    
    [Fact]
    public void StreamManager_UpdateStreamLimits()
    {
        var manager = new StreamManager(isClient: true);
        
        // Initially, peer limits are set to default (100)
        // Update to a lower limit
        manager.UpdateStreamLimits(1, StreamType.Bidirectional);
        
        // Create one stream - should succeed
        manager.CreateStream(StreamType.Bidirectional);
        
        // Try to create another - should fail
        Assert.Throws<InvalidOperationException>(() => 
            manager.CreateStream(StreamType.Bidirectional));
        
        // Update limits to allow more
        manager.UpdateStreamLimits(10, StreamType.Bidirectional);
        
        // Now should succeed
        var stream = manager.CreateStream(StreamType.Bidirectional);
        Assert.Equal(4u, stream.StreamId);
    }
    
    [Fact]
    public void StreamManager_GetNextStreamId()
    {
        var manager = new StreamManager(isClient: true);
        
        Assert.Equal(0u, manager.GetNextStreamId(StreamType.Bidirectional));
        Assert.Equal(2u, manager.GetNextStreamId(StreamType.Unidirectional));
        
        manager.CreateStream(StreamType.Bidirectional);
        
        Assert.Equal(4u, manager.GetNextStreamId(StreamType.Bidirectional));
    }
    
    [Fact]
    public void StreamManager_CloseStream()
    {
        var manager = new StreamManager(isClient: true);
        var stream = manager.CreateStream(StreamType.Bidirectional);
        
        manager.CloseStream(0);
        
        Assert.False(manager.TryGetStream(0, out _));
    }
    
    [Fact]
    public void StreamManager_GetActiveStreams()
    {
        var manager = new StreamManager(isClient: true);
        
        var stream1 = manager.CreateStream(StreamType.Bidirectional);
        var stream2 = manager.CreateStream(StreamType.Unidirectional);
        
        var activeStreams = manager.GetActiveStreams().ToList();
        
        Assert.Equal(2, activeStreams.Count);
        Assert.Contains(activeStreams, s => s.StreamId == 0);
        Assert.Contains(activeStreams, s => s.StreamId == 2);
    }
}