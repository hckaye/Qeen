using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// PATH_CHALLENGE frame (type 0x1a) - used to verify reachability to peer.
/// </summary>
public readonly struct PathChallengeFrame : IQuicFrame
{
    /// <summary>
    /// Gets the challenge data (8 bytes).
    /// </summary>
    public ReadOnlyMemory<byte> Data { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="PathChallengeFrame"/> struct.
    /// </summary>
    /// <param name="data">The challenge data (must be 8 bytes).</param>
    public PathChallengeFrame(ReadOnlyMemory<byte> data)
    {
        if (data.Length != 8)
            throw new ArgumentException("Path challenge data must be 8 bytes", nameof(data));
            
        Data = data;
    }
    
    /// <inheritdoc/>
    public FrameType Type => FrameType.PathChallenge;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)FrameType.PathChallenge);
        writer.WriteBytes(Data.Span);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // PATH_CHALLENGE frames are allowed in all packet types except 0-RTT
        return packetType != PacketType.ZeroRtt;
    }
    
    /// <summary>
    /// Decodes a PATH_CHALLENGE frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, out PathChallengeFrame frame)
    {
        frame = default;
        
        if (reader.BytesRemaining < 8)
            return false;
            
        var data = new byte[8];
        reader.ReadBytes(8).CopyTo(data);
        
        frame = new PathChallengeFrame(data);
        return true;
    }
}