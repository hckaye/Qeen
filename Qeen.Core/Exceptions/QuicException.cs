namespace Qeen.Core.Exceptions;

/// <summary>
/// Base exception for all QUIC-related errors
/// </summary>
public class QuicException : Exception
{
    /// <summary>
    /// Creates a new QuicException
    /// </summary>
    public QuicException() : base()
    {
    }

    /// <summary>
    /// Creates a new QuicException with a message
    /// </summary>
    public QuicException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new QuicException with a message and inner exception
    /// </summary>
    public QuicException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

/// <summary>
/// Exception thrown when a QUIC connection error occurs
/// </summary>
public class QuicConnectionException : QuicException
{
    /// <summary>
    /// Gets the transport error code
    /// </summary>
    public TransportErrorCode ErrorCode { get; }

    /// <summary>
    /// Gets the frame type that caused the error (if applicable)
    /// </summary>
    public FrameType? FrameType { get; }

    /// <summary>
    /// Gets additional reason phrase
    /// </summary>
    public string? ReasonPhrase { get; }

    /// <summary>
    /// Creates a new QuicConnectionException
    /// </summary>
    public QuicConnectionException(TransportErrorCode errorCode, string? reasonPhrase = null, FrameType? frameType = null)
        : base($"QUIC connection error: {errorCode}" + (reasonPhrase != null ? $" - {reasonPhrase}" : ""))
    {
        ErrorCode = errorCode;
        ReasonPhrase = reasonPhrase;
        FrameType = frameType;
    }

    /// <summary>
    /// Creates a new QuicConnectionException with an inner exception
    /// </summary>
    public QuicConnectionException(TransportErrorCode errorCode, string reasonPhrase, Exception innerException)
        : base($"QUIC connection error: {errorCode} - {reasonPhrase}", innerException)
    {
        ErrorCode = errorCode;
        ReasonPhrase = reasonPhrase;
    }
}

/// <summary>
/// Exception thrown when a QUIC stream error occurs
/// </summary>
public class QuicStreamException : QuicException
{
    /// <summary>
    /// Gets the stream ID
    /// </summary>
    public long StreamId { get; }

    /// <summary>
    /// Gets the application error code
    /// </summary>
    public long ErrorCode { get; }

    /// <summary>
    /// Creates a new QuicStreamException
    /// </summary>
    public QuicStreamException(long streamId, long errorCode, string message)
        : base($"Stream {streamId} error ({errorCode}): {message}")
    {
        StreamId = streamId;
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Exception thrown when a QUIC protocol violation occurs
/// </summary>
public class QuicProtocolViolationException : QuicException
{
    /// <summary>
    /// Gets the transport error code
    /// </summary>
    public TransportErrorCode ErrorCode { get; }

    /// <summary>
    /// Creates a new QuicProtocolViolationException
    /// </summary>
    public QuicProtocolViolationException(TransportErrorCode errorCode, string message)
        : base($"QUIC protocol violation ({errorCode}): {message}")
    {
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Transport error codes as defined in RFC 9000
/// </summary>
public enum TransportErrorCode : ulong
{
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    CryptoError = 0x100 // Base for crypto errors (0x100-0x1ff)
}