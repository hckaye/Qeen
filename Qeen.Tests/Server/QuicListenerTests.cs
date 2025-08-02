using System.Net;
using Qeen.Server;
using Xunit;

namespace Qeen.Tests.Server;

public class QuicListenerTests
{
    [Fact]
    public void QuicListener_Constructor_Succeeds()
    {
        using var listener = new QuicListener();
        
        Assert.NotNull(listener);
        Assert.False(listener.IsListening);
        Assert.Null(listener.LocalEndPoint);
        Assert.Equal(0, listener.ActiveConnectionCount);
    }
    
    [Fact]
    public async Task QuicListener_StartAsync_WithNullEndpoint_Throws()
    {
        using var listener = new QuicListener();
        var config = new QuicServerConfiguration();
        
        await Assert.ThrowsAsync<ArgumentNullException>(() => 
            listener.StartAsync(null!, config));
    }
    
    [Fact]
    public async Task QuicListener_StartAsync_WithNullConfiguration_Throws()
    {
        using var listener = new QuicListener();
        var endpoint = new IPEndPoint(IPAddress.Any, 4433);
        
        await Assert.ThrowsAsync<ArgumentNullException>(() => 
            listener.StartAsync(endpoint, null!));
    }
    
    [Fact]
    public async Task QuicListener_StartAsync_SetsIsListening()
    {
        using var listener = new QuicListener();
        var endpoint = new IPEndPoint(IPAddress.Any, 0); // Use port 0 for automatic assignment
        var config = new QuicServerConfiguration();
        
        await listener.StartAsync(endpoint, config);
        
        Assert.True(listener.IsListening);
        Assert.NotNull(listener.LocalEndPoint);
    }
    
    [Fact]
    public async Task QuicListener_StartAsync_WhenAlreadyListening_Throws()
    {
        using var listener = new QuicListener();
        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        var config = new QuicServerConfiguration();
        
        await listener.StartAsync(endpoint, config);
        
        await Assert.ThrowsAsync<InvalidOperationException>(() => 
            listener.StartAsync(endpoint, config));
    }
    
    [Fact]
    public async Task QuicListener_AcceptConnectionAsync_WhenNotListening_Throws()
    {
        using var listener = new QuicListener();
        
        await Assert.ThrowsAsync<InvalidOperationException>(() => 
            listener.AcceptConnectionAsync());
    }
    
    [Fact]
    public async Task QuicListener_Stop_SetsIsListeningToFalse()
    {
        using var listener = new QuicListener();
        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        var config = new QuicServerConfiguration();
        
        await listener.StartAsync(endpoint, config);
        Assert.True(listener.IsListening);
        
        listener.Stop();
        
        Assert.False(listener.IsListening);
    }
    
    [Fact]
    public void QuicListener_Stop_WhenNotListening_DoesNotThrow()
    {
        using var listener = new QuicListener();
        
        listener.Stop(); // Should not throw
        
        Assert.False(listener.IsListening);
    }
    
    [Fact]
    public void QuicListener_Dispose_CanBeCalledMultipleTimes()
    {
        var listener = new QuicListener();
        
        listener.Dispose();
        listener.Dispose(); // Should not throw
    }
    
    [Fact]
    public async Task QuicListener_Dispose_StopsListening()
    {
        var listener = new QuicListener();
        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        var config = new QuicServerConfiguration();
        
        await listener.StartAsync(endpoint, config);
        Assert.True(listener.IsListening);
        
        listener.Dispose();
        
        Assert.False(listener.IsListening);
    }
}