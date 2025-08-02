using Qeen.Core.Connection;
using Qeen.Core.Frame;

namespace Qeen.Core.Handshake;

/// <summary>
/// Represents a QUIC Handshake packet.
/// </summary>
public class HandshakePacket
{
    /// <summary>
    /// Gets or sets the destination connection ID.
    /// </summary>
    public ConnectionId DestinationConnectionId { get; set; }
    
    /// <summary>
    /// Gets or sets the source connection ID.
    /// </summary>
    public ConnectionId SourceConnectionId { get; set; }
    
    /// <summary>
    /// Gets or sets the packet number.
    /// </summary>
    public ulong PacketNumber { get; set; }
    
    /// <summary>
    /// Gets or sets the frames in this packet.
    /// </summary>
    public List<IQuicFrame> Frames { get; set; } = new();
    
    /// <summary>
    /// Gets or sets the QUIC version.
    /// </summary>
    public uint Version { get; set; } = 0x00000001; // QUIC v1
}