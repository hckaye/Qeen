using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// STREAMS_BLOCKED frame (types 0x16 and 0x17) - indicates stream limit is blocking stream creation.
/// </summary>
public readonly struct StreamsBlockedFrame : IQuicFrame
{
    /// <summary>
    /// Gets whether this applies to bidirectional streams.
    /// </summary>
    public bool IsBidirectional { get; }
    
    /// <summary>
    /// Gets the stream limit at which blocking occurred.
    /// </summary>
    public ulong StreamLimit { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="StreamsBlockedFrame"/> struct.
    /// </summary>
    /// <param name="isBidirectional">Whether this applies to bidirectional streams.</param>
    /// <param name="streamLimit">The stream limit at which blocking occurred.</param>
    public StreamsBlockedFrame(bool isBidirectional, ulong streamLimit)
    {
        IsBidirectional = isBidirectional;
        StreamLimit = streamLimit;
    }
    
    /// <inheritdoc/>
    public FrameType Type => IsBidirectional ? FrameType.StreamsBlockedBidi : FrameType.StreamsBlockedUni;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)Type);
        writer.WriteVariableLength(StreamLimit);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // STREAMS_BLOCKED frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a STREAMS_BLOCKED frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="isBidirectional">Whether this is for bidirectional streams.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, bool isBidirectional, out StreamsBlockedFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var streamLimit))
            return false;
            
        frame = new StreamsBlockedFrame(isBidirectional, streamLimit);
        return true;
    }
}