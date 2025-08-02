using Qeen.Core.Packet;

namespace Qeen.Core.Frame;

/// <summary>
/// Represents a QUIC frame that can be encoded and decoded.
/// </summary>
public interface IQuicFrame
{
    /// <summary>
    /// Gets the type of this frame.
    /// </summary>
    FrameType Type { get; }
    
    /// <summary>
    /// Encodes this frame to the provided writer.
    /// </summary>
    /// <param name="writer">The frame writer to encode to.</param>
    void Encode(ref FrameWriter writer);
    
    /// <summary>
    /// Gets whether this frame type is allowed in the specified packet type.
    /// </summary>
    /// <param name="packetType">The packet type to check.</param>
    /// <returns>True if this frame can be sent in the specified packet type.</returns>
    bool IsAllowedInPacketType(PacketType packetType);
}