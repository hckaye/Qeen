using System.Net;
using System.Net.Sockets;
using Qeen.Core.Connection;
using Qeen.Core.Packet;
using Qeen.Core.Transport;
using Qeen.Security.Tls;
using Qeen.CongestionControl;
using Qeen.CongestionControl.Loss;

namespace Qeen.Client;

/// <summary>
/// Implementation of a QUIC client.
/// </summary>
public class QuicClient : IQuicClient
{
    private readonly IUdpSocketManager _socketManager;
    private readonly Dictionary<ConnectionId, QuicConnection> _connections;
    private readonly SemaphoreSlim _connectionLock;
    private bool _disposed;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicClient"/> class.
    /// </summary>
    public QuicClient() : this(new UdpSocketManager())
    {
    }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicClient"/> class with a custom socket manager.
    /// </summary>
    /// <param name="socketManager">The UDP socket manager to use.</param>
    public QuicClient(IUdpSocketManager socketManager)
    {
        _socketManager = socketManager ?? throw new ArgumentNullException(nameof(socketManager));
        _connections = new Dictionary<ConnectionId, QuicConnection>();
        _connectionLock = new SemaphoreSlim(1, 1);
    }
    
    /// <inheritdoc/>
    public bool IsClosed => _disposed;
    
    /// <inheritdoc/>
    public async Task<IQuicConnection> ConnectAsync(
        string host,
        int port,
        QuicClientConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentNullException(nameof(host));
            
        if (port < 1 || port > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));
            
        // Resolve host to IP address
        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        if (addresses.Length == 0)
            throw new InvalidOperationException($"Failed to resolve host: {host}");
            
        var endpoint = new IPEndPoint(addresses[0], port);
        return await ConnectAsync(endpoint, configuration, cancellationToken);
    }
    
    /// <inheritdoc/>
    public async Task<IQuicConnection> ConnectAsync(
        EndPoint remoteEndpoint,
        QuicClientConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(QuicClient));
            
        if (remoteEndpoint == null)
            throw new ArgumentNullException(nameof(remoteEndpoint));
            
        if (configuration == null)
            throw new ArgumentNullException(nameof(configuration));
            
        await _connectionLock.WaitAsync(cancellationToken);
        try
        {
            // Bind socket if not already bound
            if (!_socketManager.IsBound)
            {
                var localEndpoint = remoteEndpoint.AddressFamily == AddressFamily.InterNetworkV6
                    ? new IPEndPoint(IPAddress.IPv6Any, 0)
                    : new IPEndPoint(IPAddress.Any, 0);
                _socketManager.Bind(localEndpoint);
                
                // Start receive loop
                _ = Task.Run(() => ReceiveLoop(cancellationToken), cancellationToken);
            }
            
            // Create connection
            var localConnectionId = ConnectionId.Generate();
            var transportParams = CreateTransportParameters(configuration);
            var connection = new QuicConnection(true, localConnectionId, transportParams);
            
            // Store connection
            _connections[localConnectionId] = connection;
            
            // Initiate connection
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(configuration.ConnectionTimeout);
            
            await connection.ConnectAsync(remoteEndpoint, cts.Token);
            
            // Perform QUIC handshake
            var serverName = GetServerNameFromEndpoint(remoteEndpoint);
            var applicationProtocols = configuration.ApplicationProtocol != null 
                ? new List<string> { configuration.ApplicationProtocol }
                : null;
                
            var initialPacket = connection.HandshakeManager.StartClientHandshake(serverName, applicationProtocols);
            
            // Send Initial packet
            var packetBuffer = new byte[1500];
            var packetLength = initialPacket.Encode(packetBuffer);
            await _socketManager.SendAsync(packetBuffer.AsMemory(0, packetLength), remoteEndpoint, cts.Token);
            
            // Wait for handshake completion (simplified)
            // In a real implementation, this would involve multiple packet exchanges
            await Task.Delay(100, cts.Token); // Simulate handshake time
            
            return connection;
        }
        finally
        {
            _connectionLock.Release();
        }
    }
    
    /// <summary>
    /// Creates transport parameters from client configuration.
    /// </summary>
    private static TransportParameters CreateTransportParameters(QuicClientConfiguration config)
    {
        return new TransportParameters
        {
            InitialMaxData = config.InitialMaxData,
            InitialMaxStreamDataBidiLocal = config.InitialMaxStreamDataBidiLocal,
            InitialMaxStreamDataBidiRemote = config.InitialMaxStreamDataBidiRemote,
            InitialMaxStreamDataUni = config.InitialMaxStreamDataUni,
            InitialMaxStreamsBidi = config.InitialMaxStreamsBidi,
            InitialMaxStreamsUni = config.InitialMaxStreamsUni,
            IdleTimeout = (ulong)config.IdleTimeout.TotalMilliseconds,
            MaxDatagramFrameSize = 1200,
            ActiveConnectionIdLimit = 8
        };
    }
    
    /// <summary>
    /// Receives packets in a loop.
    /// </summary>
    private async Task ReceiveLoop(CancellationToken cancellationToken)
    {
        var buffer = new byte[65536]; // Maximum UDP packet size
        
        while (!cancellationToken.IsCancellationRequested && !_disposed)
        {
            try
            {
                var result = await _socketManager.ReceiveAsync(buffer, cancellationToken);
                if (result.BytesReceived > 0)
                {
                    await ProcessReceivedPacket(
                        buffer.AsMemory(0, result.BytesReceived),
                        result.RemoteEndPoint,
                        cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                // Expected when cancellation is requested
                break;
            }
            catch (ObjectDisposedException)
            {
                // Socket was disposed
                break;
            }
            catch (Exception ex)
            {
                // Log error and continue
                Console.WriteLine($"Error in receive loop: {ex.Message}");
            }
        }
    }
    
    /// <summary>
    /// Processes a received packet.
    /// </summary>
    private async Task ProcessReceivedPacket(
        ReadOnlyMemory<byte> packet,
        EndPoint remoteEndpoint,
        CancellationToken cancellationToken)
    {
        // Try to parse as Initial packet
        if (Qeen.Core.Packet.InitialPacket.TryDecode(packet.Span, out var initialPacket))
        {
            // Find connection by destination connection ID
            var connection = _connections.Values.FirstOrDefault(c => 
                c.LocalConnectionId == initialPacket.DestinationConnectionId);
                
            if (connection != null && connection.IsClient)
            {
                // Process server's Initial packet
                var handshakePacket = connection.HandshakeManager.ProcessClientInitial(initialPacket);
                if (handshakePacket != null)
                {
                    // Send Handshake packet (simplified)
                    // In a real implementation, this would be properly encoded
                    var frame = handshakePacket.Frames.FirstOrDefault();
                    if (frame != null)
                    {
                        await connection.SendFrameAsync(frame, cancellationToken);
                    }
                }
            }
        }
        
        await Task.CompletedTask;
    }
    
    /// <summary>
    /// Gets the server name from an endpoint.
    /// </summary>
    private static string GetServerNameFromEndpoint(EndPoint endpoint)
    {
        if (endpoint is DnsEndPoint dnsEndpoint)
            return dnsEndpoint.Host;
            
        if (endpoint is IPEndPoint ipEndpoint)
            return ipEndpoint.Address.ToString();
            
        return "localhost";
    }
    
    /// <inheritdoc/>
    public void Close()
    {
        if (_disposed)
            return;
            
        _disposed = true;
        
        // Close all connections
        foreach (var connection in _connections.Values)
        {
            try
            {
                connection.CloseAsync(0, "Client closing").Wait(TimeSpan.FromSeconds(1));
            }
            catch
            {
                // Ignore errors during shutdown
            }
        }
        
        _connections.Clear();
        _socketManager?.Dispose();
        _connectionLock?.Dispose();
    }
    
    /// <inheritdoc/>
    public void Dispose()
    {
        Close();
    }
}