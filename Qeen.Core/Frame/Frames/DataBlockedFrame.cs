using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// DATA_BLOCKED frame (type 0x14) - indicates connection-level flow control is blocking transmission.
/// </summary>
public readonly struct DataBlockedFrame : IQuicFrame
{
    /// <summary>
    /// Gets the limit at which blocking occurred.
    /// </summary>
    public ulong DataLimit { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="DataBlockedFrame"/> struct.
    /// </summary>
    /// <param name="dataLimit">The data limit at which blocking occurred.</param>
    public DataBlockedFrame(ulong dataLimit)
    {
        DataLimit = dataLimit;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.DataBlocked;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.DataBlocked);
        writer.WriteVariableLength(DataLimit);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // DATA_BLOCKED frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a DATA_BLOCKED frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out DataBlockedFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var dataLimit))
            return false;
            
        frame = new DataBlockedFrame(dataLimit);
        return true;
    }
}