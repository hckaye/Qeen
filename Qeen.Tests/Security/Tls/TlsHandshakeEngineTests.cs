using Qeen.Core.Connection;
using Qeen.Core.Crypto;
using Qeen.Security.Tls;
using Xunit;

namespace Qeen.Tests.Security.Tls;

public class TlsHandshakeEngineTests
{
    [Fact]
    public async Task TlsHandshakeEngine_ClientHandshake_CompletesSuccessfully()
    {
        // Arrange
        var connectionId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var transportParams = TransportParameters.GetDefault();
        var engine = new TlsHandshakeEngine(
            isClient: true,
            connectionId,
            transportParams,
            serverName: "example.com",
            alpnProtocol: "h3"
        );

        // Act
        var result = await engine.PerformHandshakeAsync();

        // Assert
        Assert.True(result.IsComplete);
        Assert.NotNull(result.ApplicationSecret);
        Assert.NotNull(result.HandshakeSecret);
        Assert.NotNull(result.InitialSecret);
        Assert.NotEmpty(result.ApplicationSecret);
        Assert.NotEmpty(result.HandshakeSecret);
        Assert.NotEmpty(result.InitialSecret);
    }

    [Fact]
    public async Task TlsHandshakeEngine_ServerHandshake_CompletesSuccessfully()
    {
        // Arrange
        var connectionId = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        var transportParams = TransportParameters.GetDefault();
        var engine = new TlsHandshakeEngine(
            isClient: false,
            connectionId,
            transportParams,
            alpnProtocol: "h3"
        );

        // Act
        var result = await engine.PerformHandshakeAsync();

        // Assert
        Assert.True(result.IsComplete);
        Assert.NotNull(result.ApplicationSecret);
        Assert.NotNull(result.HandshakeSecret);
        Assert.NotNull(result.InitialSecret);
    }

    [Fact]
    public void TlsHandshakeEngine_GetInitialSecrets_DifferentForClientAndServer()
    {
        // Arrange
        var connectionId = new byte[] { 0x09, 0x0A, 0x0B, 0x0C };
        var clientEngine = new TlsHandshakeEngine(isClient: true, connectionId);
        var serverEngine = new TlsHandshakeEngine(isClient: false, connectionId);

        // Act
        var clientWrite = clientEngine.GetWriteSecret(EncryptionLevel.Initial);
        var clientRead = clientEngine.GetReadSecret(EncryptionLevel.Initial);
        var serverWrite = serverEngine.GetWriteSecret(EncryptionLevel.Initial);
        var serverRead = serverEngine.GetReadSecret(EncryptionLevel.Initial);

        // Assert
        Assert.False(clientWrite.IsEmpty);
        Assert.False(clientRead.IsEmpty);
        Assert.False(serverWrite.IsEmpty);
        Assert.False(serverRead.IsEmpty);
        
        // Client write should equal server read and vice versa
        Assert.True(clientWrite.SequenceEqual(serverRead));
        Assert.True(serverWrite.SequenceEqual(clientRead));
        
        // Client write should not equal client read
        Assert.False(clientWrite.SequenceEqual(clientRead));
    }

    [Fact]
    public async Task TlsHandshakeEngine_UpdateKeys_GeneratesNewSecrets()
    {
        // Arrange
        var connectionId = new byte[] { 0x0D, 0x0E, 0x0F, 0x10 };
        var engine = new TlsHandshakeEngine(isClient: true, connectionId);
        
        // Perform handshake to establish application secrets
        var _ = await engine.PerformHandshakeAsync();
        
        var originalWrite = engine.GetWriteSecret(EncryptionLevel.OneRtt).ToArray();
        var originalRead = engine.GetReadSecret(EncryptionLevel.OneRtt).ToArray();

        // Act
        engine.UpdateKeys();
        
        var newWrite = engine.GetWriteSecret(EncryptionLevel.OneRtt).ToArray();
        var newRead = engine.GetReadSecret(EncryptionLevel.OneRtt).ToArray();

        // Assert
        Assert.NotEqual(originalWrite, newWrite);
        Assert.NotEqual(originalRead, newRead);
        Assert.Equal(originalWrite.Length, newWrite.Length);
        Assert.Equal(originalRead.Length, newRead.Length);
    }

    [Fact]
    public async Task TlsHandshakeEngine_WithTransportParameters_IncludesInHandshake()
    {
        // Arrange
        var connectionId = new byte[] { 0x11, 0x12, 0x13, 0x14 };
        var transportParams = new TransportParameters
        {
            MaxIdleTimeout = 30000,
            MaxUdpPayloadSize = 1472,
            InitialMaxData = 10485760,
            InitialMaxStreamDataBidiLocal = 1048576,
            InitialMaxStreamDataBidiRemote = 1048576,
            InitialMaxStreamDataUni = 1048576,
            InitialMaxStreamsBidi = 100,
            InitialMaxStreamsUni = 100
        };
        
        var engine = new TlsHandshakeEngine(
            isClient: true,
            connectionId,
            transportParams
        );

        // Act
        var result = await engine.PerformHandshakeAsync();

        // Assert
        Assert.True(result.IsComplete);
        Assert.NotNull(result.TransportParameters);
        Assert.NotEmpty(result.TransportParameters);
    }

    [Fact]
    public void TlsHandshakeEngine_GetSecretBeforeHandshake_ReturnsInitialOnly()
    {
        // Arrange
        var connectionId = new byte[] { 0x15, 0x16, 0x17, 0x18 };
        var engine = new TlsHandshakeEngine(isClient: true, connectionId);

        // Act
        var initialSecret = engine.GetWriteSecret(EncryptionLevel.Initial);
        var handshakeSecret = engine.GetWriteSecret(EncryptionLevel.Handshake);
        var applicationSecret = engine.GetWriteSecret(EncryptionLevel.OneRtt);

        // Assert
        Assert.False(initialSecret.IsEmpty);
        Assert.True(handshakeSecret.IsEmpty);
        Assert.True(applicationSecret.IsEmpty);
    }
}