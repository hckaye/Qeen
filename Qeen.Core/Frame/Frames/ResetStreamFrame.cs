using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// RESET_STREAM frame (type 0x04) - abruptly terminates a stream.
/// </summary>
public readonly struct ResetStreamFrame : IQuicFrame
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
    /// Gets the final size of the stream.
    /// </summary>
    public ulong FinalSize { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="ResetStreamFrame"/> struct.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="applicationErrorCode">The application error code.</param>
    /// <param name="finalSize">The final size of the stream.</param>
    public ResetStreamFrame(ulong streamId, ulong applicationErrorCode, ulong finalSize)
    {
        StreamId = streamId;
        ApplicationErrorCode = applicationErrorCode;
        FinalSize = finalSize;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.ResetStream;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.ResetStream);
        writer.WriteVariableLength(StreamId);
        writer.WriteVariableLength(ApplicationErrorCode);
        writer.WriteVariableLength(FinalSize);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // RESET_STREAM frames are allowed in 0-RTT and 1-RTT packets
        return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a RESET_STREAM frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out ResetStreamFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var streamId))
            return false;
            
        if (!reader.TryReadVariableLength(out var errorCode))
            return false;
            
        if (!reader.TryReadVariableLength(out var finalSize))
            return false;
            
        frame = new ResetStreamFrame(streamId, errorCode, finalSize);
        return true;
    }
}