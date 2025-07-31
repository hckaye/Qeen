namespace Qeen.Core.Packet;

/// <summary>
/// QUIC packet types as defined in RFC 9000
/// </summary>
public enum PacketType : byte
{
    /// <summary>
    /// Initial packet type (Long Header)
    /// </summary>
    Initial = 0x00,

    /// <summary>
    /// 0-RTT packet type (Long Header)
    /// </summary>
    ZeroRtt = 0x01,

    /// <summary>
    /// Handshake packet type (Long Header)
    /// </summary>
    Handshake = 0x02,

    /// <summary>
    /// Retry packet type (Long Header)
    /// </summary>
    Retry = 0x03,

    /// <summary>
    /// 1-RTT packet type (Short Header)
    /// Uses the mask 0x40 to identify short header packets
    /// </summary>
    OneRtt = 0x40,

    /// <summary>
    /// Version Negotiation packet (special case, not a regular packet type)
    /// </summary>
    VersionNegotiation = 0xFF
}