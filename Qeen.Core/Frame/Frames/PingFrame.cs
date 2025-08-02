using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// PING frame (type 0x01) - used to keep connections alive and for path validation.
/// </summary>
public readonly struct PingFrame : IQuicFrame
{
    /// <summary>
    /// Singleton instance of PING frame since it has no fields.
    /// </summary>
    public static readonly PingFrame Instance = new();
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.Ping;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.Ping);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // PING is allowed in all packet types except 0-RTT
        return packetType != PacketType.ZeroRtt;
    }
    
    /// <summary>
    /// Decodes a PING frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out PingFrame frame)
    {
        // PING frame has no additional data after the type byte
        frame = Instance;
        return true;
    }
}