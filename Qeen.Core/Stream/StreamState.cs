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
    /// Stream can only receive data (unidirectional receive stream)
    /// </summary>
    ReceiveOnly,
    
    /// <summary>
    /// Stream can only send data (unidirectional send stream)
    /// </summary>
    SendOnly,
    
    /// <summary>
    /// Local side has finished sending (FIN sent)
    /// </summary>
    SendClosed,

    /// <summary>
    /// Remote side has finished sending (FIN received)
    /// </summary>
    ReceiveClosed,

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