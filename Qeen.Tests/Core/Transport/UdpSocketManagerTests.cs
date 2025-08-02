using System.Net;
using System.Net.Sockets;
using Qeen.Core.Transport;
using Xunit;

namespace Qeen.Tests.Core.Transport;

public class UdpSocketManagerTests
{
    [Fact]
    public void UdpSocketManager_Constructor_Succeeds()
    {
        using var manager = new UdpSocketManager();
        
        Assert.NotNull(manager);
        Assert.False(manager.IsBound);
        Assert.Null(manager.LocalEndPoint);
    }
    
    [Fact]
    public void UdpSocketManager_ConstructorWithIPv6_Succeeds()
    {
        using var manager = new UdpSocketManager(AddressFamily.InterNetworkV6);
        
        Assert.NotNull(manager);
        Assert.False(manager.IsBound);
    }
    
    [Fact]
    public void UdpSocketManager_Bind_SetsIsBound()
    {
        using var manager = new UdpSocketManager();
        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        
        manager.Bind(endpoint);
        
        Assert.True(manager.IsBound);
        Assert.NotNull(manager.LocalEndPoint);
    }
    
    [Fact]
    public void UdpSocketManager_Bind_WhenAlreadyBound_Throws()
    {
        using var manager = new UdpSocketManager();
        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        
        manager.Bind(endpoint);
        
        Assert.Throws<InvalidOperationException>(() => manager.Bind(endpoint));
    }
    
    [Fact]
    public void UdpSocketManager_Bind_AfterDispose_Throws()
    {
        var manager = new UdpSocketManager();
        var endpoint = new IPEndPoint(IPAddress.Any, 0);
        
        manager.Dispose();
        
        Assert.Throws<ObjectDisposedException>(() => manager.Bind(endpoint));
    }
    
    [Fact]
    public async Task UdpSocketManager_SendAsync_AfterDispose_Throws()
    {
        var manager = new UdpSocketManager();
        var endpoint = new IPEndPoint(IPAddress.Loopback, 4433);
        var buffer = new byte[100];
        
        manager.Dispose();
        
        await Assert.ThrowsAsync<ObjectDisposedException>(() => 
            manager.SendAsync(buffer, endpoint));
    }
    
    [Fact]
    public async Task UdpSocketManager_ReceiveAsync_WhenNotBound_Throws()
    {
        using var manager = new UdpSocketManager();
        var buffer = new byte[100];
        
        await Assert.ThrowsAsync<InvalidOperationException>(() => 
            manager.ReceiveAsync(buffer));
    }
    
    [Fact]
    public async Task UdpSocketManager_SendReceive_Works()
    {
        // Create two socket managers for send/receive
        using var sender = new UdpSocketManager();
        using var receiver = new UdpSocketManager();
        
        // Bind receiver
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var receiverEndpoint = receiver.LocalEndPoint!;
        
        // Send data
        var sendData = new byte[] { 1, 2, 3, 4, 5 };
        var bytesSent = await sender.SendAsync(sendData, receiverEndpoint);
        Assert.Equal(sendData.Length, bytesSent);
        
        // Receive data
        var receiveBuffer = new byte[100];
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        var result = await receiver.ReceiveAsync(receiveBuffer, cts.Token);
        
        Assert.Equal(sendData.Length, result.BytesReceived);
        Assert.Equal(sendData, receiveBuffer.Take(result.BytesReceived).ToArray());
    }
    
    [Fact]
    public void UdpSocketManager_SetReceiveBufferSize_Works()
    {
        using var manager = new UdpSocketManager();
        
        manager.SetReceiveBufferSize(65536);
        
        // No exception means success
        Assert.True(true);
    }
    
    [Fact]
    public void UdpSocketManager_SetSendBufferSize_Works()
    {
        using var manager = new UdpSocketManager();
        
        manager.SetSendBufferSize(65536);
        
        // No exception means success
        Assert.True(true);
    }
    
    [Fact]
    public void UdpSocketManager_SetBufferSize_AfterDispose_Throws()
    {
        var manager = new UdpSocketManager();
        
        manager.Dispose();
        
        Assert.Throws<ObjectDisposedException>(() => manager.SetReceiveBufferSize(65536));
        Assert.Throws<ObjectDisposedException>(() => manager.SetSendBufferSize(65536));
    }
    
    [Fact]
    public void UdpSocketManager_Dispose_CanBeCalledMultipleTimes()
    {
        var manager = new UdpSocketManager();
        
        manager.Dispose();
        manager.Dispose(); // Should not throw
    }
}