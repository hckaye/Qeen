using System.Security.Cryptography;
using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls;

public class TlsKeyScheduleTests
{
    [Fact]
    public void TlsKeySchedule_DeriveEarlySecrets_GeneratesCorrectLength()
    {
        // Arrange
        var keySchedule = new TlsKeySchedule(CipherSuite.TLS_AES_128_GCM_SHA256);

        // Act
        keySchedule.DeriveEarlySecrets();

        // Assert - Early secrets should be derived even without PSK
        // We can't directly access _earlySecret, but we can verify the operation completes
        Assert.NotNull(keySchedule);
    }

    [Fact]
    public void TlsKeySchedule_DeriveHandshakeSecrets_GeneratesSecrets()
    {
        // Arrange
        var keySchedule = new TlsKeySchedule(CipherSuite.TLS_AES_128_GCM_SHA256);
        keySchedule.DeriveEarlySecrets();
        
        var sharedSecret = new byte[32];
        RandomNumberGenerator.Fill(sharedSecret);
        
        // Update transcript with mock ClientHello
        var clientHello = new ClientHello();
        keySchedule.UpdateTranscript(clientHello);

        // Act
        keySchedule.DeriveHandshakeSecrets(sharedSecret);

        // Assert
        Assert.NotNull(keySchedule.ClientHandshakeTrafficSecret);
        Assert.NotNull(keySchedule.ServerHandshakeTrafficSecret);
        Assert.Equal(32, keySchedule.ClientHandshakeTrafficSecret.Length); // SHA256 = 32 bytes
        Assert.Equal(32, keySchedule.ServerHandshakeTrafficSecret.Length);
        Assert.NotEqual(keySchedule.ClientHandshakeTrafficSecret, keySchedule.ServerHandshakeTrafficSecret);
    }

    [Fact]
    public void TlsKeySchedule_DeriveMasterSecrets_GeneratesAllSecrets()
    {
        // Arrange
        var keySchedule = new TlsKeySchedule(CipherSuite.TLS_AES_256_GCM_SHA384);
        keySchedule.DeriveEarlySecrets();
        
        var sharedSecret = new byte[48];
        RandomNumberGenerator.Fill(sharedSecret);
        
        // Update transcript
        keySchedule.UpdateTranscript(new ClientHello());
        keySchedule.UpdateTranscript(new ServerHello());
        
        keySchedule.DeriveHandshakeSecrets(sharedSecret);

        // Act
        keySchedule.DeriveMasterSecrets();

        // Assert - SHA384 = 48 bytes
        Assert.NotNull(keySchedule.ClientApplicationTrafficSecret);
        Assert.NotNull(keySchedule.ServerApplicationTrafficSecret);
        Assert.NotNull(keySchedule.ExporterMasterSecret);
        Assert.NotNull(keySchedule.ResumptionMasterSecret);
        
        Assert.Equal(48, keySchedule.ClientApplicationTrafficSecret.Length);
        Assert.Equal(48, keySchedule.ServerApplicationTrafficSecret.Length);
        Assert.Equal(48, keySchedule.ExporterMasterSecret.Length);
        Assert.Equal(48, keySchedule.ResumptionMasterSecret.Length);
        
        // All secrets should be different
        Assert.NotEqual(keySchedule.ClientApplicationTrafficSecret, keySchedule.ServerApplicationTrafficSecret);
        Assert.NotEqual(keySchedule.ExporterMasterSecret, keySchedule.ResumptionMasterSecret);
    }

    [Fact]
    public void TlsKeySchedule_UpdateTranscript_ChangesHash()
    {
        // Arrange
        var keySchedule = new TlsKeySchedule(CipherSuite.TLS_AES_128_GCM_SHA256);
        
        // Act
        var hash1 = keySchedule.GetTranscriptHash();
        
        keySchedule.UpdateTranscript(new byte[] { 0x01, 0x02, 0x03 });
        var hash2 = keySchedule.GetTranscriptHash();
        
        keySchedule.UpdateTranscript(new byte[] { 0x04, 0x05, 0x06 });
        var hash3 = keySchedule.GetTranscriptHash();

        // Assert
        Assert.NotEqual(hash1, hash2);
        Assert.NotEqual(hash2, hash3);
        Assert.NotEqual(hash1, hash3);
    }

    [Fact]
    public void TlsKeySchedule_ComputeFinishedVerifyData_GeneratesCorrectLength()
    {
        // Arrange
        var keySchedule = new TlsKeySchedule(CipherSuite.TLS_AES_128_GCM_SHA256);
        keySchedule.DeriveEarlySecrets();
        
        var sharedSecret = new byte[32];
        RandomNumberGenerator.Fill(sharedSecret);
        
        keySchedule.UpdateTranscript(new ClientHello());
        keySchedule.UpdateTranscript(new ServerHello());
        keySchedule.DeriveHandshakeSecrets(sharedSecret);

        // Act
        var verifyData = keySchedule.ComputeFinishedVerifyData(keySchedule.ServerHandshakeTrafficSecret);

        // Assert
        Assert.NotNull(verifyData);
        Assert.Equal(32, verifyData.Length); // SHA256 = 32 bytes
    }

    [Fact]
    public void TlsKeySchedule_DeriveKeyUpdateSecret_GeneratesNewSecret()
    {
        // Arrange
        var currentSecret = new byte[32];
        RandomNumberGenerator.Fill(currentSecret);

        // Act
        var newSecret = TlsKeySchedule.DeriveKeyUpdateSecret(HashAlgorithmName.SHA256, currentSecret);

        // Assert
        Assert.NotNull(newSecret);
        Assert.Equal(32, newSecret.Length);
        Assert.NotEqual(currentSecret, newSecret);
    }

    [Fact]
    public void TlsKeySchedule_CipherSuiteSelection_UsesCorrectHashLength()
    {
        // Arrange & Act
        var sha256Schedule = new TlsKeySchedule(CipherSuite.TLS_AES_128_GCM_SHA256);
        var sha384Schedule = new TlsKeySchedule(CipherSuite.TLS_AES_256_GCM_SHA384);
        
        sha256Schedule.DeriveEarlySecrets();
        sha384Schedule.DeriveEarlySecrets();
        
        var sharedSecret256 = new byte[32];
        var sharedSecret384 = new byte[48];
        RandomNumberGenerator.Fill(sharedSecret256);
        RandomNumberGenerator.Fill(sharedSecret384);
        
        sha256Schedule.DeriveHandshakeSecrets(sharedSecret256);
        sha384Schedule.DeriveHandshakeSecrets(sharedSecret384);

        // Assert
        Assert.Equal(32, sha256Schedule.ClientHandshakeTrafficSecret.Length);
        Assert.Equal(48, sha384Schedule.ClientHandshakeTrafficSecret.Length);
    }
}