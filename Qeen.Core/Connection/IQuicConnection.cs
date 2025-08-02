using System.Net;
using Qeen.Core.Stream;

namespace Qeen.Core.Connection;

/// <summary>
/// Represents a QUIC connection.
/// </summary>
public interface IQuicConnection
{
    /// <summary>
    /// Gets the local connection ID.
    /// </summary>
    ConnectionId LocalConnectionId { get; }
    
    /// <summary>
    /// Gets the remote connection ID.
    /// </summary>
    ConnectionId RemoteConnectionId { get; }
    
    /// <summary>
    /// Gets the current connection state.
    /// </summary>
    ConnectionState State { get; }
    
    /// <summary>
    /// Gets the local transport parameters.
    /// </summary>
    TransportParameters LocalTransportParameters { get; }
    
    /// <summary>
    /// Gets the remote transport parameters.
    /// </summary>
    TransportParameters? RemoteTransportParameters { get; }
    
    /// <summary>
    /// Connects to a remote endpoint.
    /// </summary>
    /// <param name="remoteEndpoint">The remote endpoint to connect to.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task ConnectAsync(EndPoint remoteEndpoint, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Opens a new stream.
    /// </summary>
    /// <param name="type">The type of stream to open.</param>
    /// <returns>The newly created stream.</returns>
    IQuicStream OpenStream(StreamType type);
    
    /// <summary>
    /// Closes the connection.
    /// </summary>
    /// <param name="errorCode">The error code to send.</param>
    /// <param name="reason">The reason for closing.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task CloseAsync(ulong errorCode, string reason, CancellationToken cancellationToken = default);
}