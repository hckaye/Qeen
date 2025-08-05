using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Qeen.Core.Packet;

namespace Qeen.Security.Protection;

public struct AesEcbHeaderProtection : IHeaderProtection
{
    private readonly byte[] _hpKey;
    private readonly Aes _aes;

    public AesEcbHeaderProtection(ReadOnlySpan<byte> hpKey)
    {
        if (hpKey.Length != 16)
        {
            throw new ArgumentException("Header protection key must be 128 bits", nameof(hpKey));
        }

        _hpKey = hpKey.ToArray();
        _aes = Aes.Create();
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
        _aes.Key = _hpKey;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void Apply(Span<byte> packet, int headerLength)
    {
        // RFC 9001: Header protection algorithm
        // Use the provided headerLength as the packet number offset if it's valid
        int pnOffset;
        int pnLength;
        
        if (headerLength > 0 && headerLength < packet.Length)
        {
            // Use provided header length
            pnOffset = headerLength;
            // Determine packet number length from first byte
            var firstByte = packet[0];
            pnLength = (firstByte & 0x03) + 1; // Lower 2 bits encode length - 1
        }
        else
        {
            // Fall back to parsing
            if (!QuicPacketHeader.TryGetPacketNumberOffset(packet, out pnOffset, out pnLength))
            {
                throw new ArgumentException("Invalid QUIC packet format", nameof(packet));
            }
        }

        // 2. Get the sample offset (4 bytes after packet number)
        var sampleOffset = pnOffset + 4;
        if (packet.Length < sampleOffset + 16)
        {
            throw new ArgumentException("Packet is too small for header protection sample", nameof(packet));
        }

        // 3. Extract the 16-byte sample
        var sample = packet.Slice(sampleOffset, 16);
        var mask = new byte[16];
        
        // 4. Generate mask by encrypting the sample
        using var encryptor = _aes.CreateEncryptor();
        encryptor.TransformBlock(sample.ToArray(), 0, 16, mask, 0);

        // 5. Apply protection to the first byte
        var isLongHeader = (packet[0] & 0x80) != 0;
        if (isLongHeader)
        {
            // Long header: protect reserved and packet number length bits (lower 4 bits)
            packet[0] ^= (byte)(mask[0] & 0x0f);
        }
        else
        {
            // Short header: protect reserved, key phase and packet number length bits (lower 5 bits)
            packet[0] ^= (byte)(mask[0] & 0x1f);
        }

        // 6. Apply protection to packet number bytes
        // Note: We use the pnLength from the UNPROTECTED packet, not the protected one
        for (int i = 0; i < pnLength; i++)
        {
            packet[pnOffset + i] ^= mask[1 + i];
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe void Remove(Span<byte> packet, int headerLength)
    {
        // RFC 9001: Header protection removal
        // For removal, we need to first get the sample without knowing the packet number length
        
        // 1. Determine if it's a long or short header
        var isLongHeader = (packet[0] & 0x80) != 0;
        
        // 2. Estimate packet number offset
        int estimatedPnOffset;
        if (headerLength > 0 && headerLength < packet.Length)
        {
            // Use provided header length
            estimatedPnOffset = headerLength;
        }
        else if (isLongHeader)
        {
            if (!TryEstimateLongHeaderPacketNumberOffset(packet, out estimatedPnOffset))
            {
                throw new ArgumentException("Invalid QUIC packet format", nameof(packet));
            }
        }
        else
        {
            estimatedPnOffset = 1 + GetDestinationConnectionIdLength(packet);
        }
        
        // 3. Get the sample (4 bytes after estimated packet number offset)
        var sampleOffset = estimatedPnOffset + 4;
        if (packet.Length < sampleOffset + 16)
        {
            throw new ArgumentException("Packet is too small for header protection sample", nameof(packet));
        }
        
        var sample = packet.Slice(sampleOffset, 16);
        var mask = new byte[16];
        
        // 4. Generate mask
        using var encryptor = _aes.CreateEncryptor();
        encryptor.TransformBlock(sample.ToArray(), 0, 16, mask, 0);
        
        // 5. Remove protection from the first byte to get the actual packet number length
        if (isLongHeader)
        {
            packet[0] ^= (byte)(mask[0] & 0x0f);
        }
        else
        {
            packet[0] ^= (byte)(mask[0] & 0x1f);
        }
        
        // 6. Now we can get the actual packet number length
        var pnLength = (packet[0] & 0x03) + 1;
        
        // 7. Remove protection from packet number bytes
        for (int i = 0; i < pnLength; i++)
        {
            packet[estimatedPnOffset + i] ^= mask[1 + i];
        }
    }
    
    private static bool TryEstimateLongHeaderPacketNumberOffset(ReadOnlySpan<byte> packet, out int offset)
    {
        offset = 0;
        
        // Minimum long header size
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
            
        // For Initial packets, there's a token
        var packetType = (packet[0] & 0x30) >> 4;
        if (packetType == 0) // Initial packet
        {
            // Token length is variable length encoded
            if (!PacketProcessor.DecodeVariableLength(packet[offset..], out var tokenLen, out var tokenLenBytes))
                return false;
            offset += tokenLenBytes + (int)tokenLen;
        }
        
        if (packet.Length <= offset)
            return false;
            
        // Payload length (variable length)
        if (!PacketProcessor.DecodeVariableLength(packet[offset..], out _, out var lengthBytes))
            return false;
        offset += lengthBytes;
        
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetDestinationConnectionIdLength(ReadOnlySpan<byte> packet)
    {
        // In a real implementation, this would be determined by the connection context
        // For now, we'll use a default of 8 bytes (common value)
        return 8;
    }

    public void Dispose()
    {
        _aes?.Dispose();
    }
}