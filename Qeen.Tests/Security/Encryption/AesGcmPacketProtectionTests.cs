using Qeen.Security.Encryption;
using Xunit;

namespace Qeen.Tests.Security.Encryption;

public class AesGcmPacketProtectionTests
{
    [Fact]
    public void Constructor_ValidKey_CreatesInstance()
    {
        // Arrange
        var key = new byte[16]; // 128-bit key
        
        // Act
        var protection = new AesGcmPacketProtection(key);
        
        // Assert
        Assert.NotNull(protection);
    }
    
    [Theory]
    [InlineData(16)] // 128-bit
    [InlineData(32)] // 256-bit
    public void Constructor_ValidKeySizes_CreatesInstance(int keySize)
    {
        // Arrange
        var key = new byte[keySize];
        
        // Act
        var protection = new AesGcmPacketProtection(key);
        
        // Assert
        Assert.NotNull(protection);
    }
    
    [Theory]
    [InlineData(8)]
    [InlineData(24)]
    [InlineData(48)]
    public void Constructor_InvalidKeySize_ThrowsArgumentException(int keySize)
    {
        // Arrange
        var key = new byte[keySize];
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => new AesGcmPacketProtection(key));
    }
    
    [Fact]
    public void Encrypt_Decrypt_RoundTrip_Success()
    {
        // Arrange
        var key = new byte[16];
        var protection = new AesGcmPacketProtection(key);
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var ciphertext = new byte[plaintext.Length + 128]; // Extra space for nonce and tag
        var decrypted = new byte[plaintext.Length];
        
        // Act
        var encryptedLength = protection.Encrypt(plaintext, associatedData, ciphertext);
        var decryptSuccess = protection.TryDecrypt(ciphertext.AsSpan(0, encryptedLength), associatedData, decrypted);
        
        // Assert
        Assert.True(decryptSuccess);
        Assert.Equal(plaintext, decrypted);
    }
    
    [Fact]
    public void TryDecrypt_WrongAssociatedData_ReturnsFalse()
    {
        // Arrange
        var key = new byte[16];
        var protection = new AesGcmPacketProtection(key);
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var wrongAssociatedData = new byte[] { 5, 6, 7, 8 };
        var ciphertext = new byte[plaintext.Length + 128];
        var decrypted = new byte[plaintext.Length];
        
        // Act
        var encryptedLength = protection.Encrypt(plaintext, associatedData, ciphertext);
        var decryptSuccess = protection.TryDecrypt(ciphertext.AsSpan(0, encryptedLength), wrongAssociatedData, decrypted);
        
        // Assert
        Assert.False(decryptSuccess);
    }
    
    [Fact]
    public void TryDecrypt_ModifiedCiphertext_ReturnsFalse()
    {
        // Arrange
        var key = new byte[16];
        var protection = new AesGcmPacketProtection(key);
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var ciphertext = new byte[plaintext.Length + 128];
        var decrypted = new byte[plaintext.Length];
        
        // Act
        var encryptedLength = protection.Encrypt(plaintext, associatedData, ciphertext);
        ciphertext[20] ^= 0xFF; // Corrupt the ciphertext
        var decryptSuccess = protection.TryDecrypt(ciphertext.AsSpan(0, encryptedLength), associatedData, decrypted);
        
        // Assert
        Assert.False(decryptSuccess);
    }
}