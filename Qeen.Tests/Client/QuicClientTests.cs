using System.Net;
using Qeen.Client;
using Xunit;

namespace Qeen.Tests.Client;

public class QuicClientTests
{
    [Fact]
    public void QuicClient_Constructor_Succeeds()
    {
        using var client = new QuicClient();
        
        Assert.NotNull(client);
        Assert.False(client.IsClosed);
    }
    
    [Fact]
    public void QuicClient_Close_SetsIsClosed()
    {
        var client = new QuicClient();
        
        client.Close();
        
        Assert.True(client.IsClosed);
    }
    
    [Fact]
    public async Task QuicClient_ConnectAsync_WithNullEndpoint_Throws()
    {
        using var client = new QuicClient();
        var config = new QuicClientConfiguration();
        
        await Assert.ThrowsAsync<ArgumentNullException>(() => 
            client.ConnectAsync((EndPoint)null!, config));
    }
    
    [Fact]
    public async Task QuicClient_ConnectAsync_WithNullConfiguration_Throws()
    {
        using var client = new QuicClient();
        var endpoint = new IPEndPoint(IPAddress.Loopback, 4433);
        
        await Assert.ThrowsAsync<ArgumentNullException>(() => 
            client.ConnectAsync(endpoint, null!));
    }
    
    [Fact]
    public async Task QuicClient_ConnectAsync_WithInvalidHost_Throws()
    {
        using var client = new QuicClient();
        var config = new QuicClientConfiguration();
        
        await Assert.ThrowsAsync<ArgumentNullException>(() => 
            client.ConnectAsync(null!, 4433, config));
    }
    
    [Fact]
    public async Task QuicClient_ConnectAsync_WithInvalidPort_Throws()
    {
        using var client = new QuicClient();
        var config = new QuicClientConfiguration();
        
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => 
            client.ConnectAsync("localhost", 0, config));
        
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => 
            client.ConnectAsync("localhost", 70000, config));
    }
    
    [Fact]
    public void QuicClient_Dispose_CanBeCalledMultipleTimes()
    {
        var client = new QuicClient();
        
        client.Dispose();
        client.Dispose(); // Should not throw
        
        Assert.True(client.IsClosed);
    }
    
    [Fact]
    public async Task QuicClient_ConnectAsync_AfterDispose_Throws()
    {
        var client = new QuicClient();
        var config = new QuicClientConfiguration();
        var endpoint = new IPEndPoint(IPAddress.Loopback, 4433);
        
        client.Dispose();
        
        await Assert.ThrowsAsync<ObjectDisposedException>(() => 
            client.ConnectAsync(endpoint, config));
    }
}