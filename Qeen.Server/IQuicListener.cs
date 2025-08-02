using System.Net;
using Qeen.Core.Connection;

namespace Qeen.Server;

/// <summary>
/// Interface for a QUIC listener that accepts incoming connections.
/// </summary>
public interface IQuicListener : IDisposable
{
    /// <summary>
    /// Starts listening for incoming connections on the specified endpoint.
    /// </summary>
    /// <param name="localEndpoint">The local endpoint to listen on.</param>
    /// <param name="configuration">The server configuration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task StartAsync(
        EndPoint localEndpoint,
        QuicServerConfiguration configuration,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Accepts an incoming connection.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The accepted QUIC connection.</returns>
    Task<IQuicConnection> AcceptConnectionAsync(
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Stops listening for new connections.
    /// </summary>
    void Stop();
    
    /// <summary>
    /// Gets the local endpoint the listener is bound to.
    /// </summary>
    EndPoint? LocalEndPoint { get; }
    
    /// <summary>
    /// Gets whether the listener is currently listening.
    /// </summary>
    bool IsListening { get; }
    
    /// <summary>
    /// Gets the number of active connections.
    /// </summary>
    int ActiveConnectionCount { get; }
}