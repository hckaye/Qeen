using System.Runtime.CompilerServices;

namespace Qeen.Core.Packet;

/// <summary>
/// QUIC packet header parser for RFC 9000 compliant packet formats
/// </summary>
public static class QuicPacketHeader
{
    /// <summary>
    /// Parse a QUIC packet header and return the offset where the packet number starts
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryGetPacketNumberOffset(ReadOnlySpan<byte> packet, out int offset, out int pnLength)
    {
        offset = 0;
        pnLength = 0;
        
        if (packet.IsEmpty)
            return false;
            
        var isLongHeader = (packet[0] & 0x80) != 0;
        
        if (isLongHeader)
        {
            return TryGetLongHeaderPacketNumberOffset(packet, out offset, out pnLength);
        }
        else
        {
            return TryGetShortHeaderPacketNumberOffset(packet, out offset, out pnLength);
        }
    }
    
    private static bool TryGetLongHeaderPacketNumberOffset(ReadOnlySpan<byte> packet, out int offset, out int pnLength)
    {
        offset = 0;
        pnLength = 0;
        
        // Minimum long header size: flags(1) + version(4) + dcid_len(1) + scid_len(1) = 7
        if (packet.Length < 7)
            return false;
            
        // Skip flags(1) + version(4)
        offset = 5;
        
        // Destination Connection ID
        var dcidLen = packet[offset];
        offset += 1 + dcidLen;
        
        if (packet.Length <= offset)
            return false;
            
        // Source Connection ID
        var scidLen = packet[offset];
        offset += 1 + scidLen;
        
        if (packet.Length <= offset)
            return false;
            
        // Check packet type for additional fields
        var packetType = (packet[0] & 0x30) >> 4;
        
        switch (packetType)
        {
            case 0: // Initial
                // Token length (variable length)
                if (!PacketProcessor.DecodeVariableLength(packet[offset..], out var tokenLen, out var tokenLenBytes))
                    return false;
                offset += tokenLenBytes + (int)tokenLen;
                break;
            case 1: // 0-RTT
                // No additional fields
                break;
            case 2: // Handshake
                // No additional fields
                break;
            case 3: // Retry
                // Retry packets don't have packet numbers
                return false;
        }
        
        if (packet.Length <= offset)
            return false;
            
        // Payload length (variable length)
        if (!PacketProcessor.DecodeVariableLength(packet[offset..], out _, out var lengthBytes))
            return false;
        offset += lengthBytes;
        
        // Extract packet number length from the original (unprotected) first byte
        pnLength = (packet[0] & 0x03) + 1;
        
        return packet.Length > offset;
    }
    
    private static bool TryGetShortHeaderPacketNumberOffset(ReadOnlySpan<byte> packet, out int offset, out int pnLength)
    {
        offset = 0;
        pnLength = 0;
        
        // Short header: flags(1) + destination_connection_id
        // The DCID length is not encoded in short headers, it must be known from context
        // For now, we'll use a default of 8 bytes (common value)
        const int defaultDcidLength = 8;
        
        if (packet.Length < 1 + defaultDcidLength)
            return false;
            
        offset = 1 + defaultDcidLength;
        
        // Extract packet number length from the original (unprotected) first byte
        pnLength = (packet[0] & 0x03) + 1;
        
        return packet.Length > offset;
    }
    
    /// <summary>
    /// Get the sample offset for header protection
    /// The sample starts 4 bytes after the packet number offset
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryGetHeaderProtectionSampleOffset(ReadOnlySpan<byte> packet, out int sampleOffset)
    {
        sampleOffset = 0;
        
        if (!TryGetPacketNumberOffset(packet, out var pnOffset, out _))
            return false;
            
        // Sample starts 4 bytes after packet number starts
        // (to ensure we're sampling from the encrypted payload)
        sampleOffset = pnOffset + 4;
        
        // Ensure we have enough bytes for a 16-byte sample
        return packet.Length >= sampleOffset + 16;
    }
}