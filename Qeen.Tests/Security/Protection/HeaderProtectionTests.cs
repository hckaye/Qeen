using Qeen.Security.Protection;
using Xunit;

namespace Qeen.Tests.Security.Protection;

public class HeaderProtectionTests
{
    // RFC 9001 Appendix A.5 test vectors for header protection
    
    
    [Fact]
    public void AesEcbHeaderProtection_Remove_RevertsProtection()
    {
        // Arrange
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        
        // Create a valid QUIC packet structure
        var originalPacket = new byte[100];
        // Long header Initial packet with 4-byte packet number
        originalPacket[0] = 0xC3; // Long header, Initial type, 4-byte PN
        // Version
        originalPacket[1] = 0x00;
        originalPacket[2] = 0x00;
        originalPacket[3] = 0x00;
        originalPacket[4] = 0x01;
        // DCID length and DCID
        originalPacket[5] = 0x08;
        Random.Shared.NextBytes(originalPacket.AsSpan(6, 8));
        // SCID length
        originalPacket[14] = 0x00;
        // Token length (variable length integer)
        originalPacket[15] = 0x00;
        // Payload length (variable length integer) - 0x40 = 64 bytes
        originalPacket[16] = 0x40;
        originalPacket[17] = 0x00;
        // Packet number (4 bytes)
        Random.Shared.NextBytes(originalPacket.AsSpan(18, 4));
        // Fill rest with random payload
        Random.Shared.NextBytes(originalPacket.AsSpan(22));
        
        var protectedPacket = originalPacket.ToArray();
        var headerLength = 0; // Let the implementation determine header length
        
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // Act
        protection.Apply(protectedPacket, headerLength);
        var afterProtection = protectedPacket.ToArray();
        protection.Remove(protectedPacket, headerLength);
        
        // Assert
        Assert.NotEqual(originalPacket, afterProtection); // Protection changed the packet
        Assert.Equal(originalPacket, protectedPacket); // Remove restored the packet
    }
    
    [Fact]
    public void AesEcbHeaderProtection_ProtectsCorrectBits_LongHeader()
    {
        // Arrange
        var hpKey = new byte[16];
        var packet = new byte[100];
        packet[0] = 0xC0; // Long header (first bit = 1, second bit = 1)
        var originalFirstByte = packet[0];
        var headerLength = 20;
        
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // Act
        protection.Apply(packet, headerLength);
        
        // Assert
        // For long header, only the lower 4 bits should potentially change
        Assert.Equal(originalFirstByte & 0xF0, packet[0] & 0xF0);
    }
    
    [Fact]
    public void AesEcbHeaderProtection_ProtectsCorrectBits_ShortHeader()
    {
        // Arrange
        var hpKey = new byte[16];
        var packet = new byte[100];
        packet[0] = 0x40; // Short header (first bit = 0, second bit = 1)
        var originalFirstByte = packet[0];
        var headerLength = 20;
        
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // Act
        protection.Apply(packet, headerLength);
        
        // Assert
        // For short header, only the lower 5 bits should potentially change
        Assert.Equal(originalFirstByte & 0xE0, packet[0] & 0xE0);
    }
    
    [Fact]
    public void AesEcbHeaderProtection_ProtectsPacketNumber()
    {
        // Arrange
        var hpKey = new byte[16];
        Random.Shared.NextBytes(hpKey); // Use a random key to ensure mask is not all zeros
        var packet = new byte[100];
        packet[0] = 0xC3; // Long header with 4-byte packet number (pn_length = 3)
        
        // Set up a simple long header
        // Format: flags(1) + version(4) + dcid_len(1) + dcid(8) + scid_len(1) + scid(8) + length(2) + packet_number(4)
        packet[5] = 8;  // DCID length
        packet[14] = 8; // SCID length
        
        // Set some payload data after header
        for (int i = 30; i < 50; i++)
        {
            packet[i] = (byte)(i & 0xFF);
        }
        
        var headerLength = 25; // Total header length before packet number
        var pnOffset = headerLength;
        var pnLength = 4;
        
        // Store original packet number bytes
        var originalPn = packet.AsSpan(pnOffset, pnLength).ToArray();
        
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // Act
        protection.Apply(packet, headerLength);
        
        // Assert
        // Packet number bytes should be modified
        var protectedPn = packet.AsSpan(pnOffset, pnLength);
        Assert.NotEqual(originalPn, protectedPn.ToArray());
    }
    
    [Fact]
    public void AesEcbHeaderProtection_ThrowsOnSmallPacket()
    {
        // Arrange
        var hpKey = new byte[16];
        var packet = new byte[15]; // Too small for header + sample
        var headerLength = 10;
        
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => protection.Apply(packet, headerLength));
    }
}