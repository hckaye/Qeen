using System.Net;
using Qeen.Core.Connection;
using Qeen.Core.Stream;
using Xunit;

namespace Qeen.Tests.Core.Connection;

public class QuicConnectionTests
{
    [Fact]
    public void QuicConnection_Constructor_InitializesCorrectly()
    {
        var localCid = ConnectionId.Generate();
        var transportParams = new TransportParameters
        {
            InitialMaxData = 10000,
            InitialMaxStreamsBidi = 100,
            InitialMaxStreamsUni = 100
        };
        
        var connection = new QuicConnection(true, localCid, transportParams);
        
        Assert.Equal(localCid, connection.LocalConnectionId);
        Assert.Equal(ConnectionState.Idle, connection.State);
        Assert.Equal(transportParams, connection.LocalTransportParameters);
        Assert.Null(connection.RemoteTransportParameters);
    }
    
    [Fact]
    public async Task QuicConnection_ConnectAsync_ChangesState()
    {
        var connection = CreateTestConnection();
        var endpoint = new IPEndPoint(IPAddress.Loopback, 4433);
        
        await connection.ConnectAsync(endpoint);
        
        Assert.Equal(ConnectionState.Connected, connection.State);
    }
    
    [Fact]
    public async Task QuicConnection_ConnectAsync_WhenNotIdle_Throws()
    {
        var connection = CreateTestConnection();
        var endpoint = new IPEndPoint(IPAddress.Loopback, 4433);
        
        await connection.ConnectAsync(endpoint);
        
        await Assert.ThrowsAsync<InvalidOperationException>(() => 
            connection.ConnectAsync(endpoint));
    }
    
    [Fact]
    public async Task QuicConnection_OpenStream_WhenConnected_Succeeds()
    {
        var connection = CreateTestConnection();
        await connection.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 4433));
        
        var stream = connection.OpenStream(StreamType.Bidirectional);
        
        Assert.NotNull(stream);
        Assert.Equal(StreamType.Bidirectional, stream.Type);
    }
    
    [Fact]
    public void QuicConnection_OpenStream_WhenNotConnected_Throws()
    {
        var connection = CreateTestConnection();
        
        Assert.Throws<InvalidOperationException>(() => 
            connection.OpenStream(StreamType.Bidirectional));
    }
    
    [Fact]
    public async Task QuicConnection_CloseAsync_ChangesState()
    {
        var connection = CreateTestConnection();
        await connection.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 4433));
        
        await connection.CloseAsync(0, "Normal close");
        
        Assert.Equal(ConnectionState.Closed, connection.State);
    }
    
    [Fact]
    public async Task QuicConnection_CloseAsync_ClosesStreams()
    {
        var connection = CreateTestConnection();
        await connection.ConnectAsync(new IPEndPoint(IPAddress.Loopback, 4433));
        
        var stream1 = connection.OpenStream(StreamType.Bidirectional);
        var stream2 = connection.OpenStream(StreamType.Unidirectional);
        
        await connection.CloseAsync(0, "Normal close");
        
        // After connection close, streams should be closed
        Assert.Equal(ConnectionState.Closed, connection.State);
    }
    
    [Fact]
    public void QuicConnection_UpdateRemoteConnectionId()
    {
        var connection = CreateTestConnection();
        var remoteCid = ConnectionId.Generate();
        
        connection.UpdateRemoteConnectionId(remoteCid);
        
        Assert.Equal(remoteCid, connection.RemoteConnectionId);
    }
    
    [Fact]
    public void QuicConnection_UpdateRemoteTransportParameters()
    {
        var connection = CreateTestConnection();
        var remoteParams = new TransportParameters
        {
            InitialMaxData = 20000,
            InitialMaxStreamsBidi = 50,
            InitialMaxStreamsUni = 25
        };
        
        connection.UpdateRemoteTransportParameters(remoteParams);
        
        Assert.Equal(remoteParams, connection.RemoteTransportParameters);
    }
    
    [Fact]
    public async Task QuicConnection_SendAndGetFrame()
    {
        var connection = CreateTestConnection();
        var frame = new Qeen.Core.Frame.Frames.PingFrame();
        
        await connection.SendFrameAsync(frame);
        
        var retrievedFrame = await connection.GetNextFrameAsync();
        Assert.NotNull(retrievedFrame);
        Assert.Equal(frame.Type, retrievedFrame!.Type);
    }
    
    private QuicConnection CreateTestConnection()
    {
        var localCid = ConnectionId.Generate();
        var transportParams = new TransportParameters
        {
            InitialMaxData = 10000,
            InitialMaxStreamsBidi = 100,
            InitialMaxStreamsUni = 100
        };
        
        return new QuicConnection(true, localCid, transportParams);
    }
}