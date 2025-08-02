using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// ACK frame (type 0x02) - acknowledges received packets.
/// </summary>
public readonly struct AckFrame : IQuicFrame
{
    /// <summary>
    /// Gets the largest acknowledged packet number.
    /// </summary>
    public ulong LargestAcknowledged { get; }
    
    /// <summary>
    /// Gets the ACK delay in microseconds.
    /// </summary>
    public ulong AckDelay { get; }
    
    /// <summary>
    /// Gets the ACK ranges.
    /// </summary>
    public IReadOnlyList<AckRange> AckRanges { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="AckFrame"/> struct.
    /// </summary>
    /// <param name="largestAcknowledged">The largest acknowledged packet number.</param>
    /// <param name="ackDelay">The ACK delay in microseconds.</param>
    /// <param name="ackRanges">The ACK ranges.</param>
    public AckFrame(ulong largestAcknowledged, ulong ackDelay, IReadOnlyList<AckRange> ackRanges)
    {
        if (ackRanges == null || ackRanges.Count == 0)
            throw new ArgumentException("ACK frame must have at least one range", nameof(ackRanges));
            
        LargestAcknowledged = largestAcknowledged;
        AckDelay = ackDelay;
        AckRanges = ackRanges;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.Ack;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.Ack);
        writer.WriteVariableLength(LargestAcknowledged);
        writer.WriteVariableLength(AckDelay);
        writer.WriteVariableLength((ulong)(AckRanges.Count - 1)); // ACK Range Count
        
        // First ACK Range
        writer.WriteVariableLength(AckRanges[0].Length);
        
        // Additional ACK Ranges
        for (int i = 1; i < AckRanges.Count; i++)
        {
            writer.WriteVariableLength(AckRanges[i].Gap);
            writer.WriteVariableLength(AckRanges[i].Length);
        }
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // ACK frames are allowed in all packet types except 0-RTT
        return packetType != PacketType.ZeroRtt;
    }
    
    /// <summary>
    /// Decodes an ACK frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out AckFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var largestAcknowledged))
            return false;
            
        if (!reader.TryReadVariableLength(out var ackDelay))
            return false;
            
        if (!reader.TryReadVariableLength(out var ackRangeCount))
            return false;
            
        if (!reader.TryReadVariableLength(out var firstAckRange))
            return false;
            
        var ranges = new List<AckRange>
        {
            new AckRange(0, firstAckRange)
        };
        
        for (ulong i = 0; i < ackRangeCount; i++)
        {
            if (!reader.TryReadVariableLength(out var gap))
                return false;
                
            if (!reader.TryReadVariableLength(out var length))
                return false;
                
            ranges.Add(new AckRange(gap, length));
        }
        
        frame = new AckFrame(largestAcknowledged, ackDelay, ranges);
        return true;
    }
}

/// <summary>
/// Represents a range of acknowledged packets.
/// </summary>
public readonly struct AckRange
{
    /// <summary>
    /// Gets the gap to the previous range (in packet numbers).
    /// </summary>
    public ulong Gap { get; }
    
    /// <summary>
    /// Gets the length of this range (number of packets).
    /// </summary>
    public ulong Length { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="AckRange"/> struct.
    /// </summary>
    /// <param name="gap">The gap to the previous range.</param>
    /// <param name="length">The length of this range.</param>
    public AckRange(ulong gap, ulong length)
    {
        Gap = gap;
        Length = length;
    }
}