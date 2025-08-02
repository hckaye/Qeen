using System.Net;
using Qeen.Core.Connection;

namespace Qeen.Client;

/// <summary>
/// Interface for a QUIC client.
/// </summary>
public interface IQuicClient : IDisposable
{
    /// <summary>
    /// Connects to a QUIC server at the specified endpoint.
    /// </summary>
    /// <param name="remoteEndpoint">The remote endpoint to connect to.</param>
    /// <param name="configuration">The client configuration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The established QUIC connection.</returns>
    Task<IQuicConnection> ConnectAsync(
        EndPoint remoteEndpoint,
        QuicClientConfiguration configuration,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Connects to a QUIC server at the specified host and port.
    /// </summary>
    /// <param name="host">The host name or IP address.</param>
    /// <param name="port">The port number.</param>
    /// <param name="configuration">The client configuration.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The established QUIC connection.</returns>
    Task<IQuicConnection> ConnectAsync(
        string host,
        int port,
        QuicClientConfiguration configuration,
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Closes the client and releases all resources.
    /// </summary>
    void Close();
    
    /// <summary>
    /// Gets whether the client is closed.
    /// </summary>
    bool IsClosed { get; }
}