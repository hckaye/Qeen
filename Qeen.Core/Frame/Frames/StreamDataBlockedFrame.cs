using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// STREAM_DATA_BLOCKED frame (type 0x15) - indicates stream-level flow control is blocking transmission.
/// </summary>
public readonly struct StreamDataBlockedFrame : IQuicFrame
{
    /// <summary>
    /// Gets the stream ID.
    /// </summary>
    public ulong StreamId { get; }
    
    /// <summary>
    /// Gets the limit at which blocking occurred.
    /// </summary>
    public ulong StreamDataLimit { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="StreamDataBlockedFrame"/> struct.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="streamDataLimit">The stream data limit at which blocking occurred.</param>
    public StreamDataBlockedFrame(ulong streamId, ulong streamDataLimit)
    {
        StreamId = streamId;
        StreamDataLimit = streamDataLimit;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.StreamDataBlocked;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.StreamDataBlocked);
        writer.WriteVariableLength(StreamId);
        writer.WriteVariableLength(StreamDataLimit);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // STREAM_DATA_BLOCKED frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a STREAM_DATA_BLOCKED frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out StreamDataBlockedFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var streamId))
            return false;
            
        if (!reader.TryReadVariableLength(out var streamDataLimit))
            return false;
            
        frame = new StreamDataBlockedFrame(streamId, streamDataLimit);
        return true;
    }
}