namespace Qeen.Core.Connection;

/// <summary>
/// Represents the state of a QUIC connection
/// </summary>
public enum ConnectionState
{
    /// <summary>
    /// Connection is idle, not yet started
    /// </summary>
    Idle,

    /// <summary>
    /// Connection is in the process of connecting
    /// </summary>
    Connecting,

    /// <summary>
    /// Handshake in progress
    /// </summary>
    Handshake,

    /// <summary>
    /// Connection is established and ready for data transfer
    /// </summary>
    Connected,

    /// <summary>
    /// Connection is in the process of closing
    /// </summary>
    Closing,

    /// <summary>
    /// Connection is closed
    /// </summary>
    Closed,

    /// <summary>
    /// Connection was aborted due to an error
    /// </summary>
    Aborted
}