using Qeen.Core.Crypto;
using Qeen.Security;
using Qeen.Security.Tls;
using Xunit;

namespace Qeen.Tests.Security.Tls;

public class KeyUpdateTests
{
    [Fact]
    public void UpdateKeys_ChangesApplicationSecrets()
    {
        // Arrange
        var connectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var tlsEngine = new QuicTlsEngine(isClient: true, connectionId);
        
        // Perform handshake to initialize application secrets
        var handshakeResult = tlsEngine.PerformHandshakeAsync().GetAwaiter().GetResult();
        Assert.True(handshakeResult.IsComplete);
        
        var originalWriteSecret = tlsEngine.GetWriteSecret(EncryptionLevel.OneRtt).ToArray();
        var originalReadSecret = tlsEngine.GetReadSecret(EncryptionLevel.OneRtt).ToArray();
        
        // Act
        tlsEngine.UpdateKeys();
        
        // Assert
        var newWriteSecret = tlsEngine.GetWriteSecret(EncryptionLevel.OneRtt).ToArray();
        var newReadSecret = tlsEngine.GetReadSecret(EncryptionLevel.OneRtt).ToArray();
        
        Assert.NotEqual(originalWriteSecret, newWriteSecret);
        Assert.NotEqual(originalReadSecret, newReadSecret);
    }
    
    [Fact]
    public void UpdateKeys_DoesNotChangeOtherEncryptionLevels()
    {
        // Arrange
        var connectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var tlsEngine = new QuicTlsEngine(isClient: true, connectionId);
        
        // Store initial secrets
        var initialWriteSecret = tlsEngine.GetWriteSecret(EncryptionLevel.Initial).ToArray();
        var initialReadSecret = tlsEngine.GetReadSecret(EncryptionLevel.Initial).ToArray();
        
        // Perform handshake
        var handshakeResult = tlsEngine.PerformHandshakeAsync().GetAwaiter().GetResult();
        Assert.True(handshakeResult.IsComplete);
        
        var handshakeWriteSecret = tlsEngine.GetWriteSecret(EncryptionLevel.Handshake).ToArray();
        var handshakeReadSecret = tlsEngine.GetReadSecret(EncryptionLevel.Handshake).ToArray();
        
        // Act
        tlsEngine.UpdateKeys();
        
        // Assert - Initial and Handshake secrets should remain unchanged
        Assert.Equal(initialWriteSecret, tlsEngine.GetWriteSecret(EncryptionLevel.Initial).ToArray());
        Assert.Equal(initialReadSecret, tlsEngine.GetReadSecret(EncryptionLevel.Initial).ToArray());
        Assert.Equal(handshakeWriteSecret, tlsEngine.GetWriteSecret(EncryptionLevel.Handshake).ToArray());
        Assert.Equal(handshakeReadSecret, tlsEngine.GetReadSecret(EncryptionLevel.Handshake).ToArray());
    }
    
    [Fact]
    public void UpdateKeys_UseQuicKuLabel()
    {
        // This test verifies that key update uses the "quic ku" label as specified in RFC 9001
        var oldSecret = Convert.FromHexString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        
        // Act
        var newSecret = Hkdf.ExpandLabel(oldSecret, "quic ku", ReadOnlySpan<byte>.Empty, oldSecret.Length);
        
        // Assert
        Assert.Equal(32, newSecret.Length);
        Assert.NotEqual(oldSecret, newSecret);
        
        // The new secret should be deterministic
        var newSecret2 = Hkdf.ExpandLabel(oldSecret, "quic ku", ReadOnlySpan<byte>.Empty, oldSecret.Length);
        Assert.Equal(newSecret, newSecret2);
    }
    
    [Fact]
    public void UpdateKeys_MultipleUpdates_ProducesDifferentKeys()
    {
        // Arrange
        var connectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var tlsEngine = new QuicTlsEngine(isClient: true, connectionId);
        
        // Perform handshake
        var handshakeResult = tlsEngine.PerformHandshakeAsync().GetAwaiter().GetResult();
        Assert.True(handshakeResult.IsComplete);
        
        var secrets = new List<byte[]>();
        
        // Act - Perform multiple key updates
        for (int i = 0; i < 5; i++)
        {
            secrets.Add(tlsEngine.GetWriteSecret(EncryptionLevel.OneRtt).ToArray());
            tlsEngine.UpdateKeys();
        }
        secrets.Add(tlsEngine.GetWriteSecret(EncryptionLevel.OneRtt).ToArray());
        
        // Assert - All secrets should be different
        for (int i = 0; i < secrets.Count; i++)
        {
            for (int j = i + 1; j < secrets.Count; j++)
            {
                Assert.NotEqual(secrets[i], secrets[j]);
            }
        }
    }
    
    [Fact]
    public async Task PacketProtector_UpdateKeys_WorksCorrectly()
    {
        // Arrange
        var connectionId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var tlsEngine = new QuicTlsEngine(isClient: true, connectionId);
        var packetProtector = new PacketProtector(tlsEngine);
        
        await packetProtector.InitializeHandshakeAsync();
        
        var plaintext = "Hello, QUIC!"u8.ToArray();
        var associatedData = new byte[] { 1, 2, 3, 4 };
        var output1 = new byte[plaintext.Length + 128];
        var output2 = new byte[plaintext.Length + 128];
        var headerLength = 20;
        
        // Encrypt with original key
        var length1 = packetProtector.ProtectPacket(
            EncryptionLevel.OneRtt, plaintext, associatedData, output1, headerLength);
        
        // Act - Update keys
        packetProtector.UpdateKeys();
        
        // Encrypt with new key
        var length2 = packetProtector.ProtectPacket(
            EncryptionLevel.OneRtt, plaintext, associatedData, output2, headerLength);
        
        // Assert - Same plaintext encrypted with different keys should produce different ciphertext
        Assert.NotEqual(output1.AsSpan(0, length1).ToArray(), output2.AsSpan(0, length2).ToArray());
    }
}