using System.Net;
using System.Net.Sockets;

namespace Qeen.Core.Transport;

/// <summary>
/// Manages UDP socket operations for QUIC communication.
/// </summary>
public class UdpSocketManager : IUdpSocketManager
{
    private readonly Socket _socket;
    private EndPoint? _localEndPoint;
    private bool _disposed;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="UdpSocketManager"/> class.
    /// </summary>
    /// <param name="addressFamily">The address family (IPv4 or IPv6).</param>
    public UdpSocketManager(AddressFamily addressFamily = AddressFamily.InterNetwork)
    {
        _socket = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
        
        // Enable dual-stack for IPv6
        if (addressFamily == AddressFamily.InterNetworkV6)
        {
            try
            {
                _socket.DualMode = true;
            }
            catch (NotSupportedException)
            {
                // Dual-stack not supported on this platform
            }
        }
        
        // Set socket options for better performance
        if (OperatingSystem.IsWindows())
        {
            // Disable SIO_UDP_CONNRESET on Windows to prevent exceptions
            try
            {
                const int SIO_UDP_CONNRESET = -1744830452;
                _socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null);
            }
            catch
            {
                // Ignore if not supported
            }
        }
    }
    
    /// <inheritdoc/>
    public EndPoint? LocalEndPoint => _localEndPoint;
    
    /// <inheritdoc/>
    public bool IsBound => _localEndPoint != null;
    
    /// <inheritdoc/>
    public void Bind(EndPoint localEndpoint)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(UdpSocketManager));
            
        if (IsBound)
            throw new InvalidOperationException("Socket is already bound");
            
        _socket.Bind(localEndpoint);
        _localEndPoint = _socket.LocalEndPoint;
    }
    
    /// <inheritdoc/>
    public async Task<int> SendAsync(
        ReadOnlyMemory<byte> buffer,
        EndPoint remoteEndpoint,
        CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(UdpSocketManager));
            
        try
        {
            return await _socket.SendToAsync(buffer, SocketFlags.None, remoteEndpoint, cancellationToken);
        }
        catch (SocketException ex)
        {
            throw new InvalidOperationException($"Failed to send UDP packet: {ex.Message}", ex);
        }
    }
    
    /// <inheritdoc/>
    public async Task<UdpReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(UdpSocketManager));
            
        if (!IsBound)
            throw new InvalidOperationException("Socket is not bound");
            
        try
        {
            var result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, CreateEndPoint(), cancellationToken);
            return new UdpReceiveResult(result.ReceivedBytes, result.RemoteEndPoint);
        }
        catch (SocketException ex)
        {
            throw new InvalidOperationException($"Failed to receive UDP packet: {ex.Message}", ex);
        }
    }
    
    /// <inheritdoc/>
    public void SetReceiveBufferSize(int size)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(UdpSocketManager));
            
        _socket.ReceiveBufferSize = size;
    }
    
    /// <inheritdoc/>
    public void SetSendBufferSize(int size)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(UdpSocketManager));
            
        _socket.SendBufferSize = size;
    }
    
    /// <summary>
    /// Creates an appropriate endpoint based on the socket's address family.
    /// </summary>
    private EndPoint CreateEndPoint()
    {
        return _socket.AddressFamily switch
        {
            AddressFamily.InterNetwork => new IPEndPoint(IPAddress.Any, 0),
            AddressFamily.InterNetworkV6 => new IPEndPoint(IPAddress.IPv6Any, 0),
            _ => throw new NotSupportedException($"Address family {_socket.AddressFamily} is not supported")
        };
    }
    
    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
            return;
            
        _disposed = true;
        
        try
        {
            if (_socket.Connected)
            {
                _socket.Shutdown(SocketShutdown.Both);
            }
        }
        catch
        {
            // Ignore shutdown errors
        }
        
        _socket.Close();
        _socket.Dispose();
    }
}