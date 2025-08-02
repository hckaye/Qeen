using System.Net;

namespace Qeen.Core.Transport;

/// <summary>
/// Interface for managing UDP socket operations.
/// </summary>
public interface IUdpSocketManager : IDisposable
{
    /// <summary>
    /// Sends data asynchronously to a remote endpoint.
    /// </summary>
    /// <param name="buffer">The data to send.</param>
    /// <param name="remoteEndpoint">The remote endpoint.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of bytes sent.</returns>
    Task<int> SendAsync(
        ReadOnlyMemory<byte> buffer,
        EndPoint remoteEndpoint,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Receives data asynchronously.
    /// </summary>
    /// <param name="buffer">The buffer to receive data into.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The receive result containing bytes received and remote endpoint.</returns>
    Task<UdpReceiveResult> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Binds the socket to a local endpoint.
    /// </summary>
    /// <param name="localEndpoint">The local endpoint to bind to.</param>
    void Bind(EndPoint localEndpoint);
    
    /// <summary>
    /// Gets the local endpoint.
    /// </summary>
    EndPoint? LocalEndPoint { get; }
    
    /// <summary>
    /// Gets whether the socket is bound.
    /// </summary>
    bool IsBound { get; }
    
    /// <summary>
    /// Sets the receive buffer size.
    /// </summary>
    /// <param name="size">The buffer size in bytes.</param>
    void SetReceiveBufferSize(int size);
    
    /// <summary>
    /// Sets the send buffer size.
    /// </summary>
    /// <param name="size">The buffer size in bytes.</param>
    void SetSendBufferSize(int size);
}