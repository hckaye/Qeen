using Qeen.Core.Connection;
using Qeen.Core.Frame;

namespace Qeen.Core.Packet;

/// <summary>
/// Represents a QUIC Initial packet.
/// </summary>
public class InitialPacket
{
    /// <summary>
    /// Gets or sets the destination connection ID.
    /// </summary>
    public ConnectionId DestinationConnectionId { get; set; }
    
    /// <summary>
    /// Gets or sets the source connection ID.
    /// </summary>
    public ConnectionId SourceConnectionId { get; set; }
    
    /// <summary>
    /// Gets or sets the token.
    /// </summary>
    public byte[]? Token { get; set; }
    
    /// <summary>
    /// Gets or sets the packet number.
    /// </summary>
    public ulong PacketNumber { get; set; }
    
    /// <summary>
    /// Gets or sets the frames in this packet.
    /// </summary>
    public List<IQuicFrame> Frames { get; set; } = new();
    
    /// <summary>
    /// Gets or sets the QUIC version.
    /// </summary>
    public uint Version { get; set; } = 0x00000001; // QUIC v1
    
    /// <summary>
    /// Encodes the Initial packet to a buffer.
    /// </summary>
    public int Encode(Span<byte> buffer)
    {
        int offset = 0;
        
        // Write header
        // First byte: 0xC0 for Initial packet with long header
        byte firstByte = 0xC0;
        // Set packet number length (2 bits)
        firstByte |= 0x03; // 4-byte packet number
        buffer[offset++] = firstByte;
        
        // Version (4 bytes, big-endian)
        buffer[offset++] = (byte)(Version >> 24);
        buffer[offset++] = (byte)(Version >> 16);
        buffer[offset++] = (byte)(Version >> 8);
        buffer[offset++] = (byte)Version;
        
        // Destination Connection ID
        buffer[offset++] = (byte)DestinationConnectionId.Length;
        DestinationConnectionId.CopyTo(buffer.Slice(offset));
        offset += DestinationConnectionId.Length;
        
        // Source Connection ID
        buffer[offset++] = (byte)SourceConnectionId.Length;
        SourceConnectionId.CopyTo(buffer.Slice(offset));
        offset += SourceConnectionId.Length;
        
        // Token
        if (Token != null && Token.Length > 0)
        {
            offset += WriteVariableLength(buffer.Slice(offset), (ulong)Token.Length);
            Token.CopyTo(buffer.Slice(offset));
            offset += Token.Length;
        }
        else
        {
            offset += WriteVariableLength(buffer.Slice(offset), 0);
        }
        
        // Calculate payload length (frames + packet number)
        // For simplicity, we'll allocate space for frames
        var frameBuffer = new byte[4096];
        var frameWriter = new FrameWriter(frameBuffer);
        foreach (var frame in Frames)
        {
            frame.Encode(ref frameWriter);
        }
        
        // Length field (includes packet number and payload)
        var payloadLength = frameWriter.BytesWritten + 4; // 4 bytes for packet number
        offset += WriteVariableLength(buffer.Slice(offset), (ulong)payloadLength);
        
        // Packet number (4 bytes, big-endian)
        buffer[offset++] = (byte)(PacketNumber >> 24);
        buffer[offset++] = (byte)(PacketNumber >> 16);
        buffer[offset++] = (byte)(PacketNumber >> 8);
        buffer[offset++] = (byte)PacketNumber;
        
        // Write frames
        frameBuffer.AsSpan(0, frameWriter.BytesWritten).CopyTo(buffer.Slice(offset));
        offset += frameWriter.BytesWritten;
        
        return offset;
    }
    
    /// <summary>
    /// Writes a variable-length integer.
    /// </summary>
    private static int WriteVariableLength(Span<byte> buffer, ulong value)
    {
        if (value < 0x40)
        {
            buffer[0] = (byte)value;
            return 1;
        }
        else if (value < 0x4000)
        {
            buffer[0] = (byte)(0x40 | (value >> 8));
            buffer[1] = (byte)value;
            return 2;
        }
        else if (value < 0x40000000)
        {
            buffer[0] = (byte)(0x80 | (value >> 24));
            buffer[1] = (byte)(value >> 16);
            buffer[2] = (byte)(value >> 8);
            buffer[3] = (byte)value;
            return 4;
        }
        else
        {
            buffer[0] = (byte)(0xC0 | (value >> 56));
            buffer[1] = (byte)(value >> 48);
            buffer[2] = (byte)(value >> 40);
            buffer[3] = (byte)(value >> 32);
            buffer[4] = (byte)(value >> 24);
            buffer[5] = (byte)(value >> 16);
            buffer[6] = (byte)(value >> 8);
            buffer[7] = (byte)value;
            return 8;
        }
    }
    
    /// <summary>
    /// Decodes an Initial packet from a buffer.
    /// </summary>
    public static bool TryDecode(ReadOnlySpan<byte> buffer, out InitialPacket packet)
    {
        packet = new InitialPacket();
        
        if (buffer.Length < 7) // Minimum packet size
            return false;
            
        int offset = 0;
        
        // Read first byte
        var firstByte = buffer[offset++];
        
        // Check if it's an Initial packet
        if ((firstByte & 0xF0) != 0xC0)
            return false;
            
        // Read version (4 bytes, big-endian)
        if (offset + 4 > buffer.Length)
            return false;
        packet.Version = (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | 
                               (buffer[offset + 2] << 8) | buffer[offset + 3]);
        offset += 4;
        
        // Read destination connection ID
        if (offset >= buffer.Length)
            return false;
        var dcidLen = buffer[offset++];
        if (offset + dcidLen > buffer.Length)
            return false;
        packet.DestinationConnectionId = new ConnectionId(buffer.Slice(offset, dcidLen));
        offset += dcidLen;
        
        // Read source connection ID
        if (offset >= buffer.Length)
            return false;
        var scidLen = buffer[offset++];
        if (offset + scidLen > buffer.Length)
            return false;
        packet.SourceConnectionId = new ConnectionId(buffer.Slice(offset, scidLen));
        offset += scidLen;
        
        // Read token (variable length)
        if (!TryReadVariableLength(buffer, ref offset, out var tokenLength))
            return false;
        if (tokenLength > 0)
        {
            if (offset + (int)tokenLength > buffer.Length)
                return false;
            packet.Token = buffer.Slice(offset, (int)tokenLength).ToArray();
            offset += (int)tokenLength;
        }
        
        // Read length
        if (!TryReadVariableLength(buffer, ref offset, out var payloadLength))
            return false;
            
        // Read packet number (simplified - assumes 4 bytes)
        if (offset + 4 > buffer.Length)
            return false;
        packet.PacketNumber = (uint)((buffer[offset] << 24) | (buffer[offset + 1] << 16) | 
                                    (buffer[offset + 2] << 8) | buffer[offset + 3]);
        
        // Read frames (simplified - would need decryption in real implementation)
        // For now, we'll skip frame parsing
        
        return true;
    }
    
    /// <summary>
    /// Tries to read a variable-length integer.
    /// </summary>
    private static bool TryReadVariableLength(ReadOnlySpan<byte> buffer, ref int offset, out ulong value)
    {
        value = 0;
        
        if (offset >= buffer.Length)
            return false;
            
        var firstByte = buffer[offset];
        var lengthBits = (firstByte & 0xC0) >> 6;
        
        switch (lengthBits)
        {
            case 0: // 1 byte
                value = (ulong)(firstByte & 0x3F);
                offset += 1;
                return true;
                
            case 1: // 2 bytes
                if (offset + 2 > buffer.Length)
                    return false;
                value = (ulong)(((firstByte & 0x3F) << 8) | buffer[offset + 1]);
                offset += 2;
                return true;
                
            case 2: // 4 bytes
                if (offset + 4 > buffer.Length)
                    return false;
                value = (ulong)(((firstByte & 0x3F) << 24) | 
                              (buffer[offset + 1] << 16) |
                              (buffer[offset + 2] << 8) |
                              buffer[offset + 3]);
                offset += 4;
                return true;
                
            case 3: // 8 bytes
                if (offset + 8 > buffer.Length)
                    return false;
                value = ((ulong)(firstByte & 0x3F) << 56) |
                       ((ulong)buffer[offset + 1] << 48) |
                       ((ulong)buffer[offset + 2] << 40) |
                       ((ulong)buffer[offset + 3] << 32) |
                       ((ulong)buffer[offset + 4] << 24) |
                       ((ulong)buffer[offset + 5] << 16) |
                       ((ulong)buffer[offset + 6] << 8) |
                       (ulong)buffer[offset + 7];
                offset += 8;
                return true;
                
            default:
                return false;
        }
    }
}