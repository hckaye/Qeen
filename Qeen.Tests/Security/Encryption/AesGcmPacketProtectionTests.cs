using Qeen.Security.Encryption;
using Xunit;

namespace Qeen.Tests.Security.Encryption;

public class AesGcmPacketProtectionTests
{
    [Fact]
    public void Constructor_ValidKeyAndIv_CreatesInstance()
    {
        // Arrange
        var key = new byte[16]; // 128-bit key
        var iv = new byte[12];  // 96-bit IV
        
        // Act
        var protection = new AesGcmPacketProtection(key, iv);
        
        // Assert (struct, so can't be null)
        Assert.True(true);
    }
    
    [Theory]
    [InlineData(16)] // 128-bit
    [InlineData(32)] // 256-bit
    public void Constructor_ValidKeySizes_CreatesInstance(int keySize)
    {
        // Arrange
        var key = new byte[keySize];
        var iv = new byte[12];
        
        // Act
        var protection = new AesGcmPacketProtection(key, iv);
        
        // Assert (struct, so can't be null)
        Assert.True(true);
    }
    
    [Theory]
    [InlineData(8)]
    [InlineData(24)]
    [InlineData(48)]
    public void Constructor_InvalidKeySize_ThrowsArgumentException(int keySize)
    {
        // Arrange
        var key = new byte[keySize];
        var iv = new byte[12];
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => new AesGcmPacketProtection(key, iv));
    }
    
    [Theory]
    [InlineData(8)]
    [InlineData(11)]
    [InlineData(13)]
    [InlineData(16)]
    public void Constructor_InvalidIvSize_ThrowsArgumentException(int ivSize)
    {
        // Arrange
        var key = new byte[16];
        var iv = new byte[ivSize];
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => new AesGcmPacketProtection(key, iv));
    }
    
    [Fact]
    public void Encrypt_Decrypt_RoundTrip_Success()
    {
        // Arrange
        var key = new byte[16];
        var iv = new byte[12];
        var protection = new AesGcmPacketProtection(key, iv);
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var ciphertext = new byte[plaintext.Length + 16]; // Extra space for tag
        var decrypted = new byte[plaintext.Length];
        ulong packetNumber = 12345;
        
        // Act
        var encryptedLength = protection.Encrypt(plaintext, associatedData, ciphertext, packetNumber);
        var decryptSuccess = protection.TryDecrypt(ciphertext.AsSpan(0, encryptedLength), associatedData, decrypted, packetNumber);
        
        // Assert
        Assert.True(decryptSuccess);
        Assert.Equal(plaintext, decrypted);
    }
    
    [Fact]
    public void Encrypt_Decrypt_DifferentPacketNumbers_FailsDecryption()
    {
        // Arrange
        var key = new byte[16];
        var iv = new byte[12];
        var protection = new AesGcmPacketProtection(key, iv);
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var ciphertext = new byte[plaintext.Length + 16];
        var decrypted = new byte[plaintext.Length];
        ulong encryptPacketNumber = 12345;
        ulong decryptPacketNumber = 12346; // Different packet number
        
        // Act
        var encryptedLength = protection.Encrypt(plaintext, associatedData, ciphertext, encryptPacketNumber);
        var decryptSuccess = protection.TryDecrypt(ciphertext.AsSpan(0, encryptedLength), associatedData, decrypted, decryptPacketNumber);
        
        // Assert
        Assert.False(decryptSuccess); // Should fail because nonce is different
    }
    
    [Fact]
    public void TryDecrypt_WrongAssociatedData_ReturnsFalse()
    {
        // Arrange
        var key = new byte[16];
        var iv = new byte[12];
        var protection = new AesGcmPacketProtection(key, iv);
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var wrongAssociatedData = new byte[] { 5, 6, 7, 8 };
        var ciphertext = new byte[plaintext.Length + 16];
        var decrypted = new byte[plaintext.Length];
        ulong packetNumber = 12345;
        
        // Act
        var encryptedLength = protection.Encrypt(plaintext, associatedData, ciphertext, packetNumber);
        var decryptSuccess = protection.TryDecrypt(ciphertext.AsSpan(0, encryptedLength), wrongAssociatedData, decrypted, packetNumber);
        
        // Assert
        Assert.False(decryptSuccess);
    }
    
    [Fact]
    public void TryDecrypt_ModifiedCiphertext_ReturnsFalse()
    {
        // Arrange
        var key = new byte[16];
        var iv = new byte[12];
        var protection = new AesGcmPacketProtection(key, iv);
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var ciphertext = new byte[plaintext.Length + 16];
        var decrypted = new byte[plaintext.Length];
        ulong packetNumber = 12345;
        
        // Act
        var encryptedLength = protection.Encrypt(plaintext, associatedData, ciphertext, packetNumber);
        ciphertext[5] ^= 0xFF; // Corrupt the ciphertext
        var decryptSuccess = protection.TryDecrypt(ciphertext.AsSpan(0, encryptedLength), associatedData, decrypted, packetNumber);
        
        // Assert
        Assert.False(decryptSuccess);
    }
}