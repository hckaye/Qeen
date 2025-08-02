using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// PATH_RESPONSE frame (type 0x1b) - sent in response to a PATH_CHALLENGE frame.
/// </summary>
public readonly struct PathResponseFrame : IQuicFrame
{
    /// <summary>
    /// Gets the response data (8 bytes).
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="PathResponseFrame"/> struct.
    /// </summary>
    /// <param name="data">The response data (must be 8 bytes).</param>
    public PathResponseFrame(ReadOnlyMemory<byte> data)
    {
        if (data.Length != 8)
            throw new ArgumentException("Path response data must be 8 bytes", nameof(data));
            
        Data = data;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.PathResponse;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.PathResponse);
        writer.WriteBytes(Data.Span);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // PATH_RESPONSE frames are only allowed in 1-RTT packets
        return packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a PATH_RESPONSE frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out PathResponseFrame frame)
    {
        frame = default;
        
        if (reader.BytesRemaining < 8)
            return false;
            
        var data = new byte[8];
        reader.ReadBytes(8).CopyTo(data);
        
        frame = new PathResponseFrame(data);
        return true;
    }
}