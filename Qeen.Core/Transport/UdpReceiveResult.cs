using System.Net;

namespace Qeen.Core.Transport;

/// <summary>
/// Represents the result of a UDP receive operation.
/// </summary>
public readonly struct UdpReceiveResult
{
    /// <summary>
    /// Gets the number of bytes received.
    /// </summary>
    public int BytesReceived { get; init; }
    
    /// <summary>
    /// Gets the remote endpoint from which the data was received.
    /// </summary>
    public EndPoint RemoteEndPoint { get; init; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="UdpReceiveResult"/> struct.
    /// </summary>
    /// <param name="bytesReceived">The number of bytes received.</param>
    /// <param name="remoteEndPoint">The remote endpoint.</param>
    public UdpReceiveResult(int bytesReceived, EndPoint remoteEndPoint)
    {
        BytesReceived = bytesReceived;
        RemoteEndPoint = remoteEndPoint;
    }
}