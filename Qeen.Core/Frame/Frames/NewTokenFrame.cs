using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// NEW_TOKEN frame (type 0x07) - provides client with token for future connections.
/// </summary>
public readonly struct NewTokenFrame : IQuicFrame
{
    /// <summary>
    /// Gets the token data.
    /// </summary>
    public ReadOnlyMemory<byte> Token { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="NewTokenFrame"/> struct.
    /// </summary>
    /// <param name="token">The token data.</param>
    public NewTokenFrame(ReadOnlyMemory<byte> token)
    {
        if (token.Length == 0)
            throw new ArgumentException("Token cannot be empty", nameof(token));
            
        Token = token;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.NewToken;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.NewToken);
        writer.WriteVariableLength((ulong)Token.Length);
        writer.WriteBytes(Token.Span);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // NEW_TOKEN frames are only allowed in 1-RTT packets
        return packetType == PacketType.OneRtt;
    }
    
    /// <summary>
    /// Decodes a NEW_TOKEN frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out NewTokenFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var tokenLength))
            return false;
            
        if (tokenLength == 0 || tokenLength > int.MaxValue || reader.BytesRemaining < (int)tokenLength)
            return false;
            
        var token = new byte[tokenLength];
        reader.ReadBytes((int)tokenLength).CopyTo(token);
        
        frame = new NewTokenFrame(token);
        return true;
    }
}