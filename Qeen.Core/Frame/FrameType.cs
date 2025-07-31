namespace Qeen.Core.Frame;

/// <summary>
/// QUIC frame types as defined in RFC 9000
/// </summary>
public enum FrameType : byte
{
    /// <summary>
    /// PADDING frame
    /// </summary>
    Padding = 0x00,

    /// <summary>
    /// PING frame
    /// </summary>
    Ping = 0x01,

    /// <summary>
    /// ACK frame (without ECN)
    /// </summary>
    Ack = 0x02,

    /// <summary>
    /// ACK frame (with ECN)
    /// </summary>
    AckEcn = 0x03,

    /// <summary>
    /// RESET_STREAM frame
    /// </summary>
    ResetStream = 0x04,

    /// <summary>
    /// STOP_SENDING frame
    /// </summary>
    StopSending = 0x05,

    /// <summary>
    /// CRYPTO frame
    /// </summary>
    Crypto = 0x06,

    /// <summary>
    /// NEW_TOKEN frame
    /// </summary>
    NewToken = 0x07,

    /// <summary>
    /// STREAM frame base (bits 0x08-0x0f)
    /// Actual frame type includes FIN, LEN, and OFF bits
    /// </summary>
    Stream = 0x08,
    StreamFin = 0x09,
    StreamLen = 0x0a,
    StreamLenFin = 0x0b,
    StreamOff = 0x0c,
    StreamOffFin = 0x0d,
    StreamOffLen = 0x0e,
    StreamOffLenFin = 0x0f,

    /// <summary>
    /// MAX_DATA frame
    /// </summary>
    MaxData = 0x10,

    /// <summary>
    /// MAX_STREAM_DATA frame
    /// </summary>
    MaxStreamData = 0x11,

    /// <summary>
    /// MAX_STREAMS frame (bidirectional)
    /// </summary>
    MaxStreamsBidi = 0x12,

    /// <summary>
    /// MAX_STREAMS frame (unidirectional)
    /// </summary>
    MaxStreamsUni = 0x13,

    /// <summary>
    /// DATA_BLOCKED frame
    /// </summary>
    DataBlocked = 0x14,

    /// <summary>
    /// STREAM_DATA_BLOCKED frame
    /// </summary>
    StreamDataBlocked = 0x15,

    /// <summary>
    /// STREAMS_BLOCKED frame (bidirectional)
    /// </summary>
    StreamsBlockedBidi = 0x16,

    /// <summary>
    /// STREAMS_BLOCKED frame (unidirectional)
    /// </summary>
    StreamsBlockedUni = 0x17,

    /// <summary>
    /// NEW_CONNECTION_ID frame
    /// </summary>
    NewConnectionId = 0x18,

    /// <summary>
    /// RETIRE_CONNECTION_ID frame
    /// </summary>
    RetireConnectionId = 0x19,

    /// <summary>
    /// PATH_CHALLENGE frame
    /// </summary>
    PathChallenge = 0x1a,

    /// <summary>
    /// PATH_RESPONSE frame
    /// </summary>
    PathResponse = 0x1b,

    /// <summary>
    /// CONNECTION_CLOSE frame (transport error)
    /// </summary>
    ConnectionCloseQuic = 0x1c,

    /// <summary>
    /// CONNECTION_CLOSE frame (application error)
    /// </summary>
    ConnectionCloseApp = 0x1d,

    /// <summary>
    /// HANDSHAKE_DONE frame
    /// </summary>
    HandshakeDone = 0x1e,

    /// <summary>
    /// Extension frame type for DATAGRAM (RFC 9221)
    /// </summary>
    Datagram = 0x30,
    DatagramLen = 0x31
}