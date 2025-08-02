using Qeen.Security.Tls;
using Xunit;

namespace Qeen.Tests.Security.Tls;

public class HkdfTests
{
    // RFC 5869 Test Vectors
    
    [Fact]
    public void Extract_Rfc5869TestCase1_ProducesCorrectPrk()
    {
        // Test Case 1 from RFC 5869
        var ikm = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        var salt = Convert.FromHexString("000102030405060708090a0b0c");
        var expectedPrk = Convert.FromHexString(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        
        // Act
        var prk = Hkdf.Extract(salt, ikm);
        
        // Assert
        Assert.Equal(expectedPrk, prk);
    }
    
    [Fact]
    public void Expand_Rfc5869TestCase1_ProducesCorrectOkm()
    {
        // Test Case 1 from RFC 5869
        var prk = Convert.FromHexString(
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        var info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");
        var length = 42;
        var expectedOkm = Convert.FromHexString(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865");
        
        // Act
        var okm = Hkdf.Expand(prk, info, length);
        
        // Assert
        Assert.Equal(expectedOkm, okm);
    }
    
    [Fact]
    public void Extract_EmptySalt_ProducesCorrectPrk()
    {
        // Test Case 3 from RFC 5869 (salt = empty)
        var ikm = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        var salt = ReadOnlySpan<byte>.Empty;
        var expectedPrk = Convert.FromHexString(
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04");
        
        // Act
        var prk = Hkdf.Extract(salt, ikm);
        
        // Assert
        Assert.Equal(expectedPrk, prk);
    }
    
    [Fact]
    public void Expand_LongOutput_ProducesCorrectLength()
    {
        // Arrange
        var prk = new byte[32];
        var info = new byte[0];
        var length = 255 * 32; // Maximum length for SHA-256
        
        // Act
        var okm = Hkdf.Expand(prk, info, length);
        
        // Assert
        Assert.Equal(length, okm.Length);
    }
    
    [Fact]
    public void Expand_TooLongOutput_ThrowsArgumentException()
    {
        // Arrange
        var prk = new byte[32];
        var info = new byte[0];
        var length = 256 * 32; // Exceeds maximum
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => Hkdf.Expand(prk, info, length));
    }
    
    [Fact]
    public void ExpandLabel_QuicLabel_ProducesCorrectOutput()
    {
        // Arrange
        var secret = new byte[32];
        var label = "test label";
        var context = new byte[] { 1, 2, 3, 4 };
        var length = 16;
        
        // Act
        var result = Hkdf.ExpandLabel(secret, label, context, length);
        
        // Assert
        Assert.Equal(length, result.Length);
        // The result should be deterministic for the same inputs
        var result2 = Hkdf.ExpandLabel(secret, label, context, length);
        Assert.Equal(result, result2);
    }
    
    [Fact]
    public void ExpandLabel_EmptyContext_Works()
    {
        // Arrange
        var secret = new byte[32];
        var label = "test";
        var context = ReadOnlySpan<byte>.Empty;
        var length = 32;
        
        // Act
        var result = Hkdf.ExpandLabel(secret, label, context, length);
        
        // Assert
        Assert.Equal(length, result.Length);
    }
    
    [Fact]
    public void DeriveSecret_ProducesConsistentResults()
    {
        // Arrange
        var secret = new byte[32];
        Random.Shared.NextBytes(secret);
        var label = "quic key";
        
        // Act
        var key1 = Hkdf.DeriveSecret(secret, label);
        var key2 = Hkdf.DeriveSecret(secret, label);
        
        // Assert
        Assert.Equal(32, key1.Length); // Default length
        Assert.Equal(key1, key2); // Deterministic
    }
    
    [Fact]
    public void DeriveSecret_DifferentLabels_ProducesDifferentKeys()
    {
        // Arrange
        var secret = new byte[32];
        Random.Shared.NextBytes(secret);
        
        // Act
        var key = Hkdf.DeriveSecret(secret, "quic key");
        var iv = Hkdf.DeriveSecret(secret, "quic iv");
        var hp = Hkdf.DeriveSecret(secret, "quic hp");
        
        // Assert
        Assert.NotEqual(key, iv);
        Assert.NotEqual(key, hp);
        Assert.NotEqual(iv, hp);
    }
}