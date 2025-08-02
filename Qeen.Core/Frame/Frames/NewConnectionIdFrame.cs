using Qeen.Core.Connection;
using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// NEW_CONNECTION_ID frame (type 0x18) - provides peer with alternative connection IDs.
/// </summary>
public readonly struct NewConnectionIdFrame : IQuicFrame
{
    /// <summary>
    /// Gets the sequence number assigned to the connection ID.
    /// </summary>
    public ulong SequenceNumber { get; }
    
    /// <summary>
    /// Gets the threshold below which connection IDs should be retired.
    /// </summary>
    public ulong RetirePriorTo { get; }
    
    /// <summary>
    /// Gets the connection ID.
    /// </summary>
    public ConnectionId ConnectionId { get; }
    
    /// <summary>
    /// Gets the stateless reset token.
    /// </summary>
    public ReadOnlyMemory<byte> StatelessResetToken { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="NewConnectionIdFrame"/> struct.
    /// </summary>
    /// <param name="sequenceNumber">The sequence number.</param>
    /// <param name="retirePriorTo">The retire prior to value.</param>
    /// <param name="connectionId">The connection ID.</param>
    /// <param name="statelessResetToken">The stateless reset token (must be 16 bytes).</param>
    public NewConnectionIdFrame(ulong sequenceNumber, ulong retirePriorTo, ConnectionId connectionId, ReadOnlyMemory<byte> statelessResetToken)
    {
        if (statelessResetToken.Length != 16)
            throw new ArgumentException("Stateless reset token must be 16 bytes", nameof(statelessResetToken));
            
        SequenceNumber = sequenceNumber;
        RetirePriorTo = retirePriorTo;
        ConnectionId = connectionId;
        StatelessResetToken = statelessResetToken;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.NewConnectionId;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.NewConnectionId);
        writer.WriteVariableLength(SequenceNumber);
        writer.WriteVariableLength(RetirePriorTo);
        writer.WriteByte((byte)ConnectionId.Length);
        writer.WriteBytes(ConnectionId.ToArray());
        writer.WriteBytes(StatelessResetToken.Span);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // NEW_CONNECTION_ID frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a NEW_CONNECTION_ID frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out NewConnectionIdFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var sequenceNumber))
            return false;
            
        if (!reader.TryReadVariableLength(out var retirePriorTo))
            return false;
            
        if (reader.BytesRemaining < 1)
            return false;
            
        var cidLength = reader.ReadByte();
        if (cidLength > ConnectionId.MaxLength)
            return false;
            
        if (reader.BytesRemaining < cidLength + 16) // CID + reset token
            return false;
            
        var cidBytes = reader.ReadBytes(cidLength);
        var cid = new ConnectionId(cidBytes);
        
        var resetToken = new byte[16];
        reader.ReadBytes(16).CopyTo(resetToken);
        
        frame = new NewConnectionIdFrame(sequenceNumber, retirePriorTo, cid, resetToken);
        return true;
    }
}