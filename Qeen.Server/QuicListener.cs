using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using Qeen.Core.Connection;
using Qeen.Core.Packet;
using Qeen.Core.Transport;

namespace Qeen.Server;

/// <summary>
/// Implementation of a QUIC listener that accepts incoming connections.
/// </summary>
public class QuicListener : IQuicListener
{
    private readonly IUdpSocketManager _socketManager;
    private readonly ConcurrentDictionary<ConnectionId, QuicConnection> _connections;
    private readonly Channel<QuicConnection> _acceptQueue;
    private QuicServerConfiguration? _configuration;
    private CancellationTokenSource? _listenCts;
    private Task? _receiveTask;
    private bool _isListening;
    private bool _disposed;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicListener"/> class.
    /// </summary>
    public QuicListener() : this(new UdpSocketManager())
    {
    }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicListener"/> class with a custom socket manager.
    /// </summary>
    /// <param name="socketManager">The UDP socket manager to use.</param>
    public QuicListener(IUdpSocketManager socketManager)
    {
        _socketManager = socketManager ?? throw new ArgumentNullException(nameof(socketManager));
        _connections = new ConcurrentDictionary<ConnectionId, QuicConnection>();
        _acceptQueue = Channel.CreateUnbounded<QuicConnection>(new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false
        });
    }
    
    /// <inheritdoc/>
    public EndPoint? LocalEndPoint => _socketManager.LocalEndPoint;
    
    /// <inheritdoc/>
    public bool IsListening => _isListening;
    
    /// <inheritdoc/>
    public int ActiveConnectionCount => _connections.Count;
    
    /// <inheritdoc/>
    public async Task StartAsync(
        EndPoint localEndpoint,
        QuicServerConfiguration configuration,
        CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(QuicListener));
            
        if (_isListening)
            throw new InvalidOperationException("Listener is already started");
            
        if (localEndpoint == null)
            throw new ArgumentNullException(nameof(localEndpoint));
            
        if (configuration == null)
            throw new ArgumentNullException(nameof(configuration));
            
        _configuration = configuration;
        
        // Bind socket
        _socketManager.Bind(localEndpoint);
        
        // Set buffer sizes for better performance
        _socketManager.SetReceiveBufferSize(1024 * 1024); // 1 MB
        _socketManager.SetSendBufferSize(1024 * 1024); // 1 MB
        
        // Start listening
        _isListening = true;
        _listenCts = new CancellationTokenSource();
        
        // Start receive loop
        _receiveTask = Task.Run(() => ReceiveLoop(_listenCts.Token), _listenCts.Token);
        
        await Task.CompletedTask;
    }
    
    /// <inheritdoc/>
    public async Task<IQuicConnection> AcceptConnectionAsync(
        CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(QuicListener));
            
        if (!_isListening)
            throw new InvalidOperationException("Listener is not started");
            
        // Wait for a connection to be available
        var connection = await _acceptQueue.Reader.ReadAsync(cancellationToken);
        return connection;
    }
    
    /// <inheritdoc/>
    public void Stop()
    {
        if (!_isListening)
            return;
            
        _isListening = false;
        
        if (_disposed)
            return;
        
        // Cancel receive loop
        _listenCts?.Cancel();
        
        // Wait for receive task to complete
        try
        {
            _receiveTask?.Wait(TimeSpan.FromSeconds(5));
        }
        catch
        {
            // Ignore errors during shutdown
        }
        
        // Close all connections
        foreach (var connection in _connections.Values)
        {
            try
            {
                connection.CloseAsync(0, "Server stopping").Wait(TimeSpan.FromSeconds(1));
            }
            catch
            {
                // Ignore errors during shutdown
            }
        }
        
        _connections.Clear();
        _acceptQueue.Writer.TryComplete();
        
        _listenCts?.Dispose();
        _listenCts = null;
        _receiveTask = null;
    }
    
    /// <summary>
    /// Receives packets in a loop.
    /// </summary>
    private async Task ReceiveLoop(CancellationToken cancellationToken)
    {
        var buffer = new byte[65536]; // Maximum UDP packet size
        
        while (!cancellationToken.IsCancellationRequested && _isListening)
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
        // TODO: Parse packet header to determine packet type and connection ID
        
        // For now, this is a simplified implementation
        // In a real implementation, we would:
        // 1. Parse the packet header
        // 2. Check if it's an Initial packet for a new connection
        // 3. If new connection, validate and create connection
        // 4. If existing connection, route to that connection
        // 5. Process the packet (decrypt, parse frames, etc.)
        
        // Check if we can accept more connections
        if (_connections.Count >= _configuration!.MaxConnections)
        {
            // Send CONNECTION_CLOSE or ignore
            return;
        }
        
        // Create a new connection (simplified)
        var connectionId = ConnectionId.Generate();
        var transportParams = CreateTransportParameters(_configuration);
        var connection = new QuicConnection(false, connectionId, transportParams);
        
        // Store connection
        if (_connections.TryAdd(connectionId, connection))
        {
            // Add to accept queue
            await _acceptQueue.Writer.WriteAsync(connection, cancellationToken);
        }
    }
    
    /// <summary>
    /// Creates transport parameters from server configuration.
    /// </summary>
    private static TransportParameters CreateTransportParameters(QuicServerConfiguration config)
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
            ActiveConnectionIdLimit = 8,
            StatelessResetToken = config.StatelessResetToken
        };
    }
    
    /// <summary>
    /// Removes a connection from the active connections.
    /// </summary>
    internal void RemoveConnection(ConnectionId connectionId)
    {
        _connections.TryRemove(connectionId, out _);
    }
    
    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
            return;
            
        _disposed = true;
        
        Stop();
        _socketManager?.Dispose();
    }
}