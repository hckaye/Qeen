using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// STREAM frame (types 0x08-0x0f) - carries stream data.
/// </summary>
public readonly struct StreamFrame : IQuicFrame
{
    /// <summary>
    /// Gets the stream ID.
    /// </summary>
    public ulong StreamId { get; }
    
    /// <summary>
    /// Gets the offset of the data in the stream.
    /// </summary>
    public ulong Offset { get; }
    
    /// <summary>
    /// Gets the stream data.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }
    
    /// <summary>
    /// Gets whether this frame marks the end of the stream.
    /// </summary>
    public bool Fin { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="StreamFrame"/> struct.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="offset">The offset of the data.</param>
    /// <param name="data">The stream data.</param>
    /// <param name="fin">Whether this is the final frame.</param>
    public StreamFrame(ulong streamId, ulong offset, ReadOnlyMemory<byte> data, bool fin = false)
    {
        StreamId = streamId;
        Offset = offset;
        Data = data;
        Fin = fin;
    }
    
    /// <inheritdoc/>
    public FrameType Type
    {
        get
        {
            byte type = 0x08;
            if (Fin) type |= 0x01;
            if (Data.Length > 0) type |= 0x02;
            if (Offset > 0) type |= 0x04;
            return (FrameType)type;
        }
    }
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)Type);
        writer.WriteVariableLength(StreamId);
        
        if (Offset > 0)
        {
            writer.WriteVariableLength(Offset);
        }
        
        if (Data.Length > 0)
        {
            writer.WriteVariableLength((ulong)Data.Length);
            writer.WriteBytes(Data.Span);
        }
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // STREAM frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a STREAM frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frameType">The frame type byte.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, byte frameType, out StreamFrame frame)
    {
        frame = default;
        
        // Extract flags from frame type
        bool fin = (frameType & 0x01) != 0;
        bool hasLength = (frameType & 0x02) != 0;
        bool hasOffset = (frameType & 0x04) != 0;
        
        if (!reader.TryReadVariableLength(out var streamId))
            return false;
            
        ulong offset = 0;
        if (hasOffset)
        {
            if (!reader.TryReadVariableLength(out offset))
                return false;
        }
        
        ReadOnlyMemory<byte> data = ReadOnlyMemory<byte>.Empty;
        if (hasLength)
        {
            if (!reader.TryReadVariableLength(out var length))
                return false;
                
            if (length > int.MaxValue || reader.BytesRemaining < (int)length)
                return false;
                
            var bytes = new byte[length];
            reader.ReadBytes((int)length).CopyTo(bytes);
            data = bytes;
        }
        else if (!fin)
        {
            // If no length and not FIN, consume all remaining bytes
            var remaining = reader.BytesRemaining;
            if (remaining > 0)
            {
                var bytes = new byte[remaining];
                reader.ReadBytes(remaining).CopyTo(bytes);
                data = bytes;
            }
        }
        
        frame = new StreamFrame(streamId, offset, data, fin);
        return true;
    }
}