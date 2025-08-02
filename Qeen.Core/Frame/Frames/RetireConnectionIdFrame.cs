using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// RETIRE_CONNECTION_ID frame (type 0x19) - indicates connection ID will no longer be used.
/// </summary>
public readonly struct RetireConnectionIdFrame : IQuicFrame
{
    /// <summary>
    /// Gets the sequence number of the connection ID being retired.
    /// </summary>
    public ulong SequenceNumber { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="RetireConnectionIdFrame"/> struct.
    /// </summary>
    /// <param name="sequenceNumber">The sequence number to retire.</param>
    public RetireConnectionIdFrame(ulong sequenceNumber)
    {
        SequenceNumber = sequenceNumber;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.RetireConnectionId;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.RetireConnectionId);
        writer.WriteVariableLength(SequenceNumber);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // RETIRE_CONNECTION_ID frames are not allowed in 0-RTT packets
        return packetType != PacketType.ZeroRtt;
    }
    
    /// <summary>
    /// Decodes a RETIRE_CONNECTION_ID frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out RetireConnectionIdFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var sequenceNumber))
            return false;
            
        frame = new RetireConnectionIdFrame(sequenceNumber);
        return true;
    }
}