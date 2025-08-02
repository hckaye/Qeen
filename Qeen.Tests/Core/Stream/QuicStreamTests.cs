using Qeen.Core.Stream;
using Xunit;

namespace Qeen.Tests.Core.Stream;

public class QuicStreamTests
{
    [Fact]
    public void QuicStream_Constructor_SetsProperties()
    {
        var stream = new QuicStream(42, StreamType.Bidirectional, true, 1000);
        
        Assert.Equal(42u, stream.StreamId);
        Assert.Equal(StreamType.Bidirectional, stream.Type);
        Assert.Equal(StreamState.Open, stream.State);
    }
    
    [Fact]
    public void QuicStream_Constructor_UnidirectionalLocallyInitiated_SendOnly()
    {
        var stream = new QuicStream(2, StreamType.Unidirectional, true, 1000);
        
        Assert.Equal(StreamState.Open, stream.State);
    }
    
    [Fact]
    public void QuicStream_Constructor_UnidirectionalRemotelyInitiated_ReceiveOnly()
    {
        var stream = new QuicStream(3, StreamType.Unidirectional, false, 1000);
        
        Assert.Equal(StreamState.ReceiveOnly, stream.State);
    }
    
    [Fact]
    public async Task QuicStream_WriteAsync_UpdatesState()
    {
        var stream = new QuicStream(0, StreamType.Bidirectional, true, 1000);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        
        await stream.WriteAsync(data);
        
        Assert.Equal(StreamState.Open, stream.State);
    }
    
    [Fact]
    public async Task QuicStream_WriteAsync_WithFin_UpdatesState()
    {
        var stream = new QuicStream(0, StreamType.Bidirectional, true, 1000);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        
        await stream.WriteAsync(data, fin: true);
        
        Assert.Equal(StreamState.SendClosed, stream.State);
    }
    
    [Fact]
    public async Task QuicStream_WriteAsync_AfterFin_Throws()
    {
        var stream = new QuicStream(0, StreamType.Bidirectional, true, 1000);
        var data = new byte[] { 1, 2, 3 };
        
        await stream.WriteAsync(data, fin: true);
        
        await Assert.ThrowsAsync<InvalidOperationException>(async () => 
            await stream.WriteAsync(data));
    }
    
    [Fact]
    public async Task QuicStream_WriteAsync_UnidirectionalReceiveStream_Throws()
    {
        var stream = new QuicStream(3, StreamType.Unidirectional, false, 1000);
        var data = new byte[] { 1, 2, 3 };
        
        await Assert.ThrowsAsync<InvalidOperationException>(async () => 
            await stream.WriteAsync(data));
    }
    
    [Fact]
    public async Task QuicStream_ReadAsync_UnidirectionalSendStream_Throws()
    {
        var stream = new QuicStream(2, StreamType.Unidirectional, true, 1000);
        var buffer = new byte[10];
        
        await Assert.ThrowsAsync<InvalidOperationException>(async () => 
            await stream.ReadAsync(buffer));
    }
    
    [Fact]
    public async Task QuicStream_CloseAsync_ClosesStream()
    {
        var stream = new QuicStream(0, StreamType.Bidirectional, true, 1000);
        
        await stream.CloseAsync();
        
        Assert.Equal(StreamState.Closed, stream.State);
    }
    
    [Fact]
    public async Task QuicStream_DeliverData_CanBeRead()
    {
        var stream = new QuicStream(1, StreamType.Bidirectional, false, 1000);
        var data = new byte[] { 1, 2, 3, 4, 5 };
        
        // Cast to QuicStream to access internal method
        var quicStream = stream as QuicStream;
        Assert.NotNull(quicStream);
        await quicStream!.DeliverData(0, data, false);
        
        // Read the data
        var buffer = new byte[10];
        var bytesRead = await stream.ReadAsync(buffer);
        
        Assert.Equal(5, bytesRead);
        Assert.Equal(data, buffer.Take(5).ToArray());
    }
}