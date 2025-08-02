using System.Text;
using Qeen.Core.Crypto;
using Qeen.Security.Tls;
using Xunit;

namespace Qeen.Tests.Security.Tls;

public class InitialSecretsTests
{
    // RFC 9001 Appendix A.1 test vectors
    private static readonly byte[] TestConnectionId = Convert.FromHexString("8394c8f03e515708");
    private static readonly byte[] ExpectedInitialSecret = Convert.FromHexString(
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
    private static readonly byte[] ExpectedClientInitialSecret = Convert.FromHexString(
        "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea");
    private static readonly byte[] ExpectedServerInitialSecret = Convert.FromHexString(
        "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b");
    
    [Fact]
    public void DeriveInitialSecrets_WithRfc9001TestVector_ProducesCorrectSecrets()
    {
        // Arrange
        var tlsEngine = new QuicTlsEngine(isClient: true, TestConnectionId);
        
        // Act
        var clientWriteSecret = tlsEngine.GetWriteSecret(EncryptionLevel.Initial);
        var clientReadSecret = tlsEngine.GetReadSecret(EncryptionLevel.Initial);
        
        // Assert
        Assert.Equal(ExpectedClientInitialSecret, clientWriteSecret.ToArray());
        Assert.Equal(ExpectedServerInitialSecret, clientReadSecret.ToArray());
    }
    
    [Fact]
    public void DeriveInitialSecrets_ServerRole_ProducesCorrectSecrets()
    {
        // Arrange
        var tlsEngine = new QuicTlsEngine(isClient: false, TestConnectionId);
        
        // Act
        var serverWriteSecret = tlsEngine.GetWriteSecret(EncryptionLevel.Initial);
        var serverReadSecret = tlsEngine.GetReadSecret(EncryptionLevel.Initial);
        
        // Assert
        Assert.Equal(ExpectedServerInitialSecret, serverWriteSecret.ToArray());
        Assert.Equal(ExpectedClientInitialSecret, serverReadSecret.ToArray());
    }
    
    [Fact]
    public void Hkdf_Extract_WithRfc9001TestVector_ProducesCorrectInitialSecret()
    {
        // Arrange
        var salt = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
        
        // Act
        var initialSecret = Hkdf.Extract(salt, TestConnectionId);
        
        // Assert
        Assert.Equal(ExpectedInitialSecret, initialSecret);
    }
    
    [Fact]
    public void Hkdf_ExpandLabel_ClientInitial_ProducesCorrectSecret()
    {
        // Arrange
        var initialSecret = Convert.FromHexString(
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
        
        // Act
        var clientSecret = Hkdf.ExpandLabel(initialSecret, "client in", ReadOnlySpan<byte>.Empty, 32);
        
        // Assert
        Assert.Equal(ExpectedClientInitialSecret, clientSecret);
    }
    
    [Fact]
    public void Hkdf_ExpandLabel_ServerInitial_ProducesCorrectSecret()
    {
        // Arrange
        var initialSecret = Convert.FromHexString(
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44");
        
        // Act
        var serverSecret = Hkdf.ExpandLabel(initialSecret, "server in", ReadOnlySpan<byte>.Empty, 32);
        
        // Assert
        Assert.Equal(ExpectedServerInitialSecret, serverSecret);
    }
    
    // Additional RFC 9001 Appendix A derived keys tests
    [Fact]
    public void DeriveKey_ClientInitial_ProducesCorrectAeadKey()
    {
        // RFC 9001 A.1: client initial key = 1f369613dd76d5467730efcbe3b1a22d
        var expectedKey = Convert.FromHexString("1f369613dd76d5467730efcbe3b1a22d");
        
        // Act
        var key = Hkdf.ExpandLabel(ExpectedClientInitialSecret, "quic key", ReadOnlySpan<byte>.Empty, 16);
        
        // Assert
        Assert.Equal(expectedKey, key);
    }
    
    [Fact]
    public void DeriveIv_ClientInitial_ProducesCorrectIv()
    {
        // RFC 9001 A.1: client initial iv = fa044b2f42a3fd3b46fb255c
        var expectedIv = Convert.FromHexString("fa044b2f42a3fd3b46fb255c");
        
        // Act
        var iv = Hkdf.ExpandLabel(ExpectedClientInitialSecret, "quic iv", ReadOnlySpan<byte>.Empty, 12);
        
        // Assert
        Assert.Equal(expectedIv, iv);
    }
    
    [Fact]
    public void DeriveHp_ClientInitial_ProducesCorrectHpKey()
    {
        // RFC 9001 A.1: client initial hp = 9f50449e04a0e810283a1e9933adedd2
        var expectedHp = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        
        // Act
        var hp = Hkdf.ExpandLabel(ExpectedClientInitialSecret, "quic hp", ReadOnlySpan<byte>.Empty, 16);
        
        // Assert
        Assert.Equal(expectedHp, hp);
    }
    
    [Fact]
    public void DeriveKey_ServerInitial_ProducesCorrectAeadKey()
    {
        // RFC 9001 A.1: server initial key = cf3a5331653c364c88f0f379b6067e37
        var expectedKey = Convert.FromHexString("cf3a5331653c364c88f0f379b6067e37");
        
        // Act
        var key = Hkdf.ExpandLabel(ExpectedServerInitialSecret, "quic key", ReadOnlySpan<byte>.Empty, 16);
        
        // Assert
        Assert.Equal(expectedKey, key);
    }
    
    [Fact]
    public void DeriveIv_ServerInitial_ProducesCorrectIv()
    {
        // RFC 9001 A.1: server initial iv = 0ac1493ca1905853b0bba03e
        var expectedIv = Convert.FromHexString("0ac1493ca1905853b0bba03e");
        
        // Act
        var iv = Hkdf.ExpandLabel(ExpectedServerInitialSecret, "quic iv", ReadOnlySpan<byte>.Empty, 12);
        
        // Assert
        Assert.Equal(expectedIv, iv);
    }
    
    [Fact]
    public void DeriveHp_ServerInitial_ProducesCorrectHpKey()
    {
        // RFC 9001 A.1: server initial hp = c206b8d9b9f0f37644430b490eeaa314
        var expectedHp = Convert.FromHexString("c206b8d9b9f0f37644430b490eeaa314");
        
        // Act
        var hp = Hkdf.ExpandLabel(ExpectedServerInitialSecret, "quic hp", ReadOnlySpan<byte>.Empty, 16);
        
        // Assert
        Assert.Equal(expectedHp, hp);
    }
}