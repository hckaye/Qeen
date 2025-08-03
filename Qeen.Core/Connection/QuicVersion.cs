namespace Qeen.Core.Connection;

/// <summary>
/// QUIC protocol version as defined in RFC 9000
/// </summary>
public enum QuicVersion : uint
{
    /// <summary>
    /// Version negotiation packet (0x00000000)
    /// </summary>
    VersionNegotiation = 0x00000000,
    
    /// <summary>
    /// QUIC version 1 (RFC 9000) - 0x00000001
    /// </summary>
    Version1 = 0x00000001,
    
    /// <summary>
    /// QUIC version 2 (RFC 9369) - 0x6b3343cf
    /// </summary>
    Version2 = 0x6b3343cf,
    
    /// <summary>
    /// Draft version 29 - 0xff00001d
    /// </summary>
    Draft29 = 0xff00001d
}