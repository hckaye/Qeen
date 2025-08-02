using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// HANDSHAKE_DONE frame (type 0x1e) - signals handshake completion.
/// </summary>
public readonly struct HandshakeDoneFrame : IQuicFrame
{
    /// <summary>
    /// Singleton instance of HANDSHAKE_DONE frame since it has no fields.
    /// </summary>
    public static readonly HandshakeDoneFrame Instance = new();
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.HandshakeDone;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.HandshakeDone);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // HANDSHAKE_DONE frames are only allowed in 1-RTT packets
        return packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a HANDSHAKE_DONE frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out HandshakeDoneFrame frame)
    {
        // HANDSHAKE_DONE frame has no additional data after the type byte
        frame = Instance;
        return true;
    }
}