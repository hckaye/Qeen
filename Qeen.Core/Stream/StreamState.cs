namespace Qeen.Core.Stream;

/// <summary>
/// Represents the state of a QUIC stream as defined in RFC 9000
/// </summary>
public enum StreamState
{
    /// <summary>
    /// Initial state (idle)
    /// </summary>
    Idle,

    /// <summary>
    /// Stream is open for sending
    /// </summary>
    Open,

    /// <summary>
    /// Local side has finished sending (FIN sent)
    /// </summary>
    LocallyClosed,

    /// <summary>
    /// Remote side has finished sending (FIN received)
    /// </summary>
    RemotelyClosed,

    /// <summary>
    /// Both sides have finished sending
    /// </summary>
    Closed,

    /// <summary>
    /// Stream was reset by local side
    /// </summary>
    ResetSent,

    /// <summary>
    /// Stream was reset by remote side
    /// </summary>
    ResetReceived,

    /// <summary>
    /// Stream is fully closed after reset
    /// </summary>
    ResetClosed
}