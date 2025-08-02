using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// CRYPTO frame (type 0x06) - carries cryptographic handshake data.
/// </summary>
public readonly struct CryptoFrame : IQuicFrame
{
    /// <summary>
    /// Gets the offset of the crypto data.
    /// </summary>
    public ulong Offset { get; }
    
    /// <summary>
    /// Gets the crypto data.
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="CryptoFrame"/> struct.
    /// </summary>
    /// <param name="offset">The offset of the crypto data.</param>
    /// <param name="data">The crypto data.</param>
    public CryptoFrame(ulong offset, ReadOnlyMemory<byte> data)
    {
        Offset = offset;
        Data = data;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.Crypto;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.Crypto);
        writer.WriteVariableLength(Offset);
        writer.WriteVariableLength((ulong)Data.Length);
        writer.WriteBytes(Data.Span);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // CRYPTO frames are allowed in Initial, Handshake, and 1-RTT packets
        return packetType == PacketType.Initial || 
               packetType == PacketType.Handshake || 
               packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a CRYPTO frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out CryptoFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var offset))
            return false;
            
        if (!reader.TryReadVariableLength(out var length))
            return false;
            
        if (length > int.MaxValue || reader.BytesRemaining < (int)length)
            return false;
            
        var data = new byte[length];
        reader.ReadBytes((int)length).CopyTo(data);
        
        frame = new CryptoFrame(offset, data);
        return true;
    }
}