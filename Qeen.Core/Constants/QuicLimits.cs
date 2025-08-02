namespace Qeen.Core.Constants;

/// <summary>
/// Defines limits and constraints specified in RFC 9000.
/// </summary>
public static class QuicLimits
{
    /// <summary>
    /// Maximum packet number value (2^62 - 1) as specified in RFC 9000 Section 17.1.
    /// </summary>
    public const ulong MaxPacketNumber = (1UL << 62) - 1;
    
    /// <summary>
    /// Maximum stream ID value (2^62 - 1) as specified in RFC 9000 Section 2.1.
    /// </summary>
    public const ulong MaxStreamId = (1UL << 62) - 1;
    
    /// <summary>
    /// Maximum variable-length integer value (2^62 - 1) as specified in RFC 9000 Section 16.
    /// </summary>
    public const ulong MaxVarInt = (1UL << 62) - 1;
    
    /// <summary>
    /// Maximum reason phrase length in CONNECTION_CLOSE frame.
    /// While RFC 9000 doesn't specify an explicit limit, we use a reasonable maximum
    /// to prevent DoS attacks and memory exhaustion.
    /// </summary>
    public const int MaxReasonPhraseLength = 1024;
    
    /// <summary>
    /// Maximum number of ACK ranges in an ACK frame.
    /// RFC 9000 doesn't specify an explicit limit, but we use a reasonable maximum
    /// to prevent DoS attacks. The value must fit in a variable-length integer.
    /// </summary>
    public const ulong MaxAckRanges = 256;
    
    /// <summary>
    /// Maximum ACK delay value in microseconds (2^62 - 1).
    /// This is the maximum value that can be encoded in a variable-length integer.
    /// </summary>
    public const ulong MaxAckDelay = MaxVarInt;
    
    /// <summary>
    /// Maximum error code value for transport errors.
    /// RFC 9000 Section 20.1 defines error codes from 0x00 to 0x0f for transport errors.
    /// </summary>
    public const ulong MaxTransportErrorCode = 0x0f;
    
    /// <summary>
    /// Maximum error code value for application errors.
    /// Application error codes can use the full variable-length integer range.
    /// </summary>
    public const ulong MaxApplicationErrorCode = MaxVarInt;
    
    /// <summary>
    /// Maximum frame type value that can be encoded.
    /// Frame types are encoded as variable-length integers.
    /// </summary>
    public const ulong MaxFrameType = MaxVarInt;
    
    /// <summary>
    /// Maximum initial packet size as specified in RFC 9000 Section 14.1.
    /// Initial packets must be at least 1200 bytes.
    /// </summary>
    public const int MinInitialPacketSize = 1200;
    
    /// <summary>
    /// Maximum UDP payload size as specified in RFC 9000 Section 14.
    /// The maximum IP packet size is 65535 bytes, minus IP and UDP headers.
    /// </summary>
    public const int MaxUdpPayloadSize = 65527;
    
    /// <summary>
    /// Minimum QUIC packet size (1 byte header + 1 byte payload).
    /// </summary>
    public const int MinPacketSize = 2;
    
    /// <summary>
    /// Maximum connection ID length as specified in RFC 9000 Section 17.2.
    /// Connection IDs can be 0 to 20 bytes.
    /// </summary>
    public const int MaxConnectionIdLength = 20;
    
    /// <summary>
    /// Maximum number of connection IDs per connection.
    /// While not explicitly limited by RFC, we use a reasonable maximum.
    /// </summary>
    public const int MaxConnectionIds = 8;
    
    /// <summary>
    /// Maximum retry token length.
    /// While not explicitly limited by RFC, we use a reasonable maximum.
    /// </summary>
    public const int MaxRetryTokenLength = 256;
    
    /// <summary>
    /// Maximum stateless reset token length as specified in RFC 9000 Section 10.3.
    /// Stateless reset tokens are exactly 16 bytes.
    /// </summary>
    public const int StatelessResetTokenLength = 16;
    
    /// <summary>
    /// Checks if a value is a valid variable-length integer.
    /// </summary>
    /// <param name="value">The value to check.</param>
    /// <returns>True if the value is valid, false otherwise.</returns>
    public static bool IsValidVarInt(ulong value)
    {
        return value <= MaxVarInt;
    }
    
    /// <summary>
    /// Checks if a packet number is valid.
    /// </summary>
    /// <param name="packetNumber">The packet number to check.</param>
    /// <returns>True if the packet number is valid, false otherwise.</returns>
    public static bool IsValidPacketNumber(ulong packetNumber)
    {
        return packetNumber <= MaxPacketNumber;
    }
    
    /// <summary>
    /// Checks if a stream ID is valid.
    /// </summary>
    /// <param name="streamId">The stream ID to check.</param>
    /// <returns>True if the stream ID is valid, false otherwise.</returns>
    public static bool IsValidStreamId(ulong streamId)
    {
        return streamId <= MaxStreamId;
    }
    
    /// <summary>
    /// Checks if a connection ID length is valid.
    /// </summary>
    /// <param name="length">The connection ID length to check.</param>
    /// <returns>True if the length is valid, false otherwise.</returns>
    public static bool IsValidConnectionIdLength(int length)
    {
        return length >= 0 && length <= MaxConnectionIdLength;
    }
    
    /// <summary>
    /// Checks if a transport error code is valid according to RFC 9000.
    /// </summary>
    /// <param name="errorCode">The error code to check.</param>
    /// <returns>True if the error code is a valid transport error code, false otherwise.</returns>
    public static bool IsValidTransportErrorCode(ulong errorCode)
    {
        // RFC 9000 Section 20.1: Transport error codes are 0x00 to 0x0f
        // Plus crypto error codes 0x0100 to 0x01ff
        return errorCode <= MaxTransportErrorCode || 
               (errorCode >= 0x0100 && errorCode <= 0x01ff);
    }
}