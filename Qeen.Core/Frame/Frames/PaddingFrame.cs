using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// PADDING frame (type 0x00) - used to increase packet size.
/// </summary>
public readonly struct PaddingFrame : IQuicFrame
{
    /// <summary>
    /// Gets the number of padding bytes.
    /// </summary>
    public int Length { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="PaddingFrame"/> struct.
    /// </summary>
    /// <param name="length">The number of padding bytes.</param>
    public PaddingFrame(int length)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Padding length must be positive");
            
        Length = length;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.Padding;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        // PADDING frames are just zero bytes
        for (int i = 0; i < Length; i++)
        {
            writer.WriteByte(0x00);
        }
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // PADDING is allowed in all packet types
        return true;
    }
    
    /// <summary>
    /// Decodes a PADDING frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out PaddingFrame frame)
    {
        // Count consecutive zero bytes
        int length = 1; // We already read one 0x00 byte to identify this as PADDING
        
        while (reader.BytesRemaining > 0 && reader.PeekByte() == 0x00)
        {
            reader.ReadByte();
            length++;
        }
        
        frame = new PaddingFrame(length);
        return true;
    }
}