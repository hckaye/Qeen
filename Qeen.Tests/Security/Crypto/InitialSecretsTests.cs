using System;
using System.Linq;
using Qeen.Core.Connection;
using Qeen.Security.Crypto;
using Xunit;

namespace Qeen.Tests.Security.Crypto;

/// <summary>
/// Tests for QUIC initial secrets derivation based on RFC 9001 Appendix A
/// </summary>
public class InitialSecretsTests
{
    // RFC 9001 Appendix A test vectors
    private static readonly byte[] TestConnectionId = Convert.FromHexString("8394c8f03e515708");
    private static readonly byte[] InitialSaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    private static readonly byte[] ExpectedInitialSecret = Convert.FromHexString("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
    
    // QUIC v2 test vectors
    private static readonly byte[] InitialSaltV2 = Convert.FromHexString("0dede3def700a6db819381be6e269dcbf9bd2ed9");
    
    // Expected derived secrets from QUICWG test vectors
    private static readonly byte[] ExpectedClientInitialSecret = Convert.FromHexString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    private static readonly byte[] ExpectedServerInitialSecret = Convert.FromHexString("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    
    [Fact]
    public void DeriveInitialSecret_WithRfc9001TestVector_ReturnsExpectedSecret()
    {
        // Arrange
        var connectionId = TestConnectionId;
        var salt = InitialSaltV1;
        
        // Act
        var initialSecret = InitialSecrets.DeriveInitialSecret(connectionId, salt);
        
        // Assert
        Assert.Equal(ExpectedInitialSecret, initialSecret);
    }
    
    [Fact]
    public void DeriveClientInitialSecret_FromInitialSecret_ReturnsExpectedValue()
    {
        // Arrange
        var initialSecret = ExpectedInitialSecret;
        
        // Act
        var clientSecret = InitialSecrets.DeriveClientInitialSecret(initialSecret);
        
        // Assert
        Assert.Equal(ExpectedClientInitialSecret, clientSecret);
    }
    
    [Fact]
    public void DeriveServerInitialSecret_FromInitialSecret_ReturnsExpectedValue()
    {
        // Arrange
        var initialSecret = ExpectedInitialSecret;
        
        // Act
        var serverSecret = InitialSecrets.DeriveServerInitialSecret(initialSecret);
        
        // Assert
        Assert.Equal(ExpectedServerInitialSecret, serverSecret);
    }
    
    [Theory]
    [InlineData("1f369613dd76d5467730efcbe3b1a22d", "client", "key")] // Client AEAD key
    [InlineData("fa044b2f42a3fd3b46fb255c", "client", "iv")] // Client AEAD IV
    [InlineData("9f50449e04a0e810283a1e9933adedd2", "client", "hp")] // Client HP key
    [InlineData("cf3a5331653c364c88f0f379b6067e37", "server", "key")] // Server AEAD key
    [InlineData("0ac1493ca1905853b0bba03e", "server", "iv")] // Server AEAD IV
    [InlineData("c206b8d9b9f0f37644430b490eeaa314", "server", "hp")] // Server HP key
    public void DeriveKeyMaterial_WithQuicWgTestVectors_ReturnsExpectedValues(
        string expectedHex, string side, string label)
    {
        // Arrange
        var expected = Convert.FromHexString(expectedHex);
        var secret = side == "client" ? ExpectedClientInitialSecret : ExpectedServerInitialSecret;
        var fullLabel = $"quic {label}";
        
        // Act
        var length = expected.Length;
        var derived = InitialSecrets.DeriveKeyMaterial(secret, fullLabel, length);
        
        // Assert
        Assert.Equal(expected, derived);
    }
    
    [Fact]
    public void DeriveInitialSecrets_WithEmptyConnectionId_ThrowsArgumentException()
    {
        // Arrange
        var emptyConnectionId = Array.Empty<byte>();
        
        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            InitialSecrets.DeriveInitialSecret(emptyConnectionId, InitialSaltV1));
    }
    
    [Fact]
    public void DeriveInitialSecrets_WithQuicV2_UsesDifferentSalt()
    {
        // Arrange
        var connectionId = TestConnectionId;
        
        // Act
        var secretV1 = InitialSecrets.DeriveInitialSecret(connectionId, QuicVersion.Version1);
        var secretV2 = InitialSecrets.DeriveInitialSecret(connectionId, QuicVersion.Version2);
        
        // Assert
        Assert.NotEqual(secretV1, secretV2);
    }
    
    [Fact]
    public void HkdfExpandLabel_WithTls13Prefix_FormatsCorrectly()
    {
        // The HKDF-Expand-Label function should format as:
        // struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // } HkdfLabel;
        
        // Test that our implementation correctly derives a known value
        var secret = Convert.FromHexString("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
        var key = InitialSecrets.DeriveKey(secret);
        
        // The key derivation uses HKDF-Expand-Label internally with "tls13 quic key"
        // If the formatting is wrong, we wouldn't get the correct RFC test vector
        var expected = Convert.FromHexString("1f369613dd76d5467730efcbe3b1a22d");
        Assert.Equal(expected, key);
    }
    
    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(20)]
    public void DeriveInitialSecret_WithVariousConnectionIdLengths_Succeeds(int length)
    {
        // Arrange
        var connectionId = new byte[length];
        new Random(42).NextBytes(connectionId);
        
        // Act
        var secret = InitialSecrets.DeriveInitialSecret(connectionId, InitialSaltV1);
        
        // Assert
        Assert.NotNull(secret);
        Assert.Equal(32, secret.Length); // SHA-256 output
    }
}