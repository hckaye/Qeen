using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// MAX_DATA frame (type 0x10) - informs peer of maximum data it can send on connection.
/// </summary>
public readonly struct MaxDataFrame : IQuicFrame
{
    /// <summary>
    /// Gets the maximum amount of data that can be sent on the connection.
    /// </summary>
    public ulong MaximumData { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="MaxDataFrame"/> struct.
    /// </summary>
    /// <param name="maximumData">The maximum data limit.</param>
    public MaxDataFrame(ulong maximumData)
    {
        MaximumData = maximumData;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.MaxData;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.MaxData);
        writer.WriteVariableLength(MaximumData);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // MAX_DATA frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a MAX_DATA frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out MaxDataFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var maxData))
            return false;
            
        frame = new MaxDataFrame(maxData);
        return true;
    }
}