using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// STOP_SENDING frame (type 0x05) - requests that a peer stop sending on a stream.
/// </summary>
public readonly struct StopSendingFrame : IQuicFrame
{
    /// <summary>
    /// Gets the stream ID.
    /// </summary>
    public ulong StreamId { get; }
    
    /// <summary>
    /// Gets the application error code.
    /// </summary>
    public ulong ApplicationErrorCode { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="StopSendingFrame"/> struct.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="applicationErrorCode">The application error code.</param>
    public StopSendingFrame(ulong streamId, ulong applicationErrorCode)
    {
        StreamId = streamId;
        ApplicationErrorCode = applicationErrorCode;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.StopSending;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.StopSending);
        writer.WriteVariableLength(StreamId);
        writer.WriteVariableLength(ApplicationErrorCode);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // STOP_SENDING frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a STOP_SENDING frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out StopSendingFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var streamId))
            return false;
            
        if (!reader.TryReadVariableLength(out var errorCode))
            return false;
            
        frame = new StopSendingFrame(streamId, errorCode);
        return true;
    }
}