using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// MAX_STREAM_DATA frame (type 0x11) - informs peer of maximum data it can send on a stream.
/// </summary>
public readonly struct MaxStreamDataFrame : IQuicFrame
{
    /// <summary>
    /// Gets the stream ID.
    /// </summary>
    public ulong StreamId { get; }
    
    /// <summary>
    /// Gets the maximum amount of data that can be sent on the stream.
    /// </summary>
    public ulong MaximumStreamData { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="MaxStreamDataFrame"/> struct.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="maximumStreamData">The maximum stream data limit.</param>
    public MaxStreamDataFrame(ulong streamId, ulong maximumStreamData)
    {
        StreamId = streamId;
        MaximumStreamData = maximumStreamData;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.MaxStreamData;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.MaxStreamData);
        writer.WriteVariableLength(StreamId);
        writer.WriteVariableLength(MaximumStreamData);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // MAX_STREAM_DATA frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a MAX_STREAM_DATA frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out MaxStreamDataFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var streamId))
            return false;
            
        if (!reader.TryReadVariableLength(out var maxStreamData))
            return false;
            
        frame = new MaxStreamDataFrame(streamId, maxStreamData);
        return true;
    }
}