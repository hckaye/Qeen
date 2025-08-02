using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// MAX_STREAMS frame (types 0x12 and 0x13) - informs peer of maximum number of streams.
/// </summary>
public readonly struct MaxStreamsFrame : IQuicFrame
{
    /// <summary>
    /// Gets whether this applies to bidirectional streams.
    /// </summary>
    public bool IsBidirectional { get; }
    
    /// <summary>
    /// Gets the maximum number of streams.
    /// </summary>
    public ulong MaximumStreams { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="MaxStreamsFrame"/> struct.
    /// </summary>
    /// <param name="isBidirectional">Whether this applies to bidirectional streams.</param>
    /// <param name="maximumStreams">The maximum number of streams.</param>
    public MaxStreamsFrame(bool isBidirectional, ulong maximumStreams)
    {
        IsBidirectional = isBidirectional;
        MaximumStreams = maximumStreams;
    }
    
    /// <inheritdoc/>
    public FrameType Type => IsBidirectional ? FrameType.MaxStreamsBidi : FrameType.MaxStreamsUni;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)Type);
        writer.WriteVariableLength(MaximumStreams);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // MAX_STREAMS frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a MAX_STREAMS frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="isBidirectional">Whether this is for bidirectional streams.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, bool isBidirectional, out MaxStreamsFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var maxStreams))
            return false;
            
        frame = new MaxStreamsFrame(isBidirectional, maxStreams);
        return true;
    }
}