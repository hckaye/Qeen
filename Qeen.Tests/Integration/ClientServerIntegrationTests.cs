using System.Net;
using Qeen.Client;
using Qeen.Server;
using Xunit;

namespace Qeen.Tests.Integration;

public class ClientServerIntegrationTests : IDisposable
{
    private readonly QuicListener _listener;
    private readonly QuicClient _client;
    
    public ClientServerIntegrationTests()
    {
        _listener = new QuicListener();
        _client = new QuicClient();
    }
    
    [Fact]
    public async Task ClientServer_BasicConnection_Works()
    {
        // Start server
        var serverConfig = new QuicServerConfiguration
        {
            MaxConnections = 10,
            IdleTimeout = TimeSpan.FromSeconds(10)
        };
        
        await _listener.StartAsync(new IPEndPoint(IPAddress.Loopback, 0), serverConfig);
        var serverEndpoint = _listener.LocalEndPoint!;
        
        // Accept connections in background
        var acceptTask = Task.Run(async () =>
        {
            try
            {
                return await _listener.AcceptConnectionAsync();
            }
            catch (OperationCanceledException)
            {
                return null;
            }
        });
        
        // Connect client
        var clientConfig = new QuicClientConfiguration
        {
            ConnectionTimeout = TimeSpan.FromSeconds(5),
            IdleTimeout = TimeSpan.FromSeconds(10)
        };
        
        // Connect and perform basic handshake
        var clientConnection = await _client.ConnectAsync(serverEndpoint, clientConfig);
        var serverConnection = await acceptTask;
        
        Assert.NotNull(clientConnection);
        Assert.NotNull(serverConnection);
    }
    
    [Fact]
    public async Task Listener_CanStartAndStop()
    {
        var config = new QuicServerConfiguration();
        
        await _listener.StartAsync(new IPEndPoint(IPAddress.Any, 0), config);
        Assert.True(_listener.IsListening);
        
        _listener.Stop();
        Assert.False(_listener.IsListening);
    }
    
    [Fact]
    public void Client_CanCreateAndDispose()
    {
        var client = new QuicClient();
        Assert.False(client.IsClosed);
        
        client.Dispose();
        Assert.True(client.IsClosed);
    }
    
    public void Dispose()
    {
        _client?.Dispose();
        _listener?.Dispose();
    }
}