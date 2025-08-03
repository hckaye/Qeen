using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls.Messages;

public class ServerHelloTests
{
    [Fact]
    public void ServerHello_EncodeDecode_RoundTrip()
    {
        // Arrange
        var original = new ServerHello
        {
            CipherSuite = CipherSuite.TLS_AES_256_GCM_SHA384,
            LegacySessionIdEcho = new byte[] { 0x01, 0x02, 0x03 }
        };
        original.AddSupportedVersionsExtension();
        original.AddKeyShareExtension(new byte[32], 0x001D);
        original.AddQuicTransportParametersExtension(new byte[] { 0x04, 0x05, 0x06 });

        // Act - Encode
        var buffer = new byte[1024];
        var writer = new TlsWriter(buffer);
        original.Encode(ref writer);
        var encoded = writer.Written.ToArray();

        // Act - Decode
        var reader = new TlsReader(encoded);
        var decoded = ServerHello.Decode(ref reader, TlsMessageType.ServerHello) as ServerHello;

        // Assert
        Assert.NotNull(decoded);
        Assert.Equal(original.LegacyVersion, decoded.LegacyVersion);
        Assert.Equal(original.CipherSuite, decoded.CipherSuite);
        Assert.Equal(original.LegacySessionIdEcho, decoded.LegacySessionIdEcho);
        Assert.Equal(original.Extensions.Count, decoded.Extensions.Count);
        
        // Verify extensions
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.SupportedVersions));
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.KeyShare));
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.QuicTransportParameters));
    }

    [Fact]
    public void ServerHello_IsHelloRetryRequest_DetectsSpecialRandom()
    {
        // Arrange
        var hrrServerHello = new ServerHello
        {
            Random = new byte[]
            {
                0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
                0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
                0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
                0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
            }
        };
        
        var normalServerHello = new ServerHello();

        // Act & Assert
        Assert.True(hrrServerHello.IsHelloRetryRequest());
        Assert.False(normalServerHello.IsHelloRetryRequest());
    }

    [Fact]
    public void ServerHello_SupportedVersionsExtension_EncodesCorrectly()
    {
        // Arrange
        var serverHello = new ServerHello();

        // Act
        serverHello.AddSupportedVersionsExtension();

        // Assert
        Assert.True(serverHello.Extensions.ContainsKey(TlsExtensionType.SupportedVersions));
        var extensionData = serverHello.Extensions[TlsExtensionType.SupportedVersions];
        
        // Verify TLS 1.3 version
        var reader = new TlsReader(extensionData);
        var version = reader.ReadUInt16();
        Assert.Equal(0x0304, version); // TLS 1.3
    }

    [Fact]
    public void ServerHello_KeyShareExtension_EncodesCorrectly()
    {
        // Arrange
        var serverHello = new ServerHello();
        var publicKey = new byte[32];
        for (int i = 0; i < publicKey.Length; i++)
        {
            publicKey[i] = (byte)i;
        }
        ushort group = 0x001D; // X25519

        // Act
        serverHello.AddKeyShareExtension(publicKey, group);

        // Assert
        Assert.True(serverHello.Extensions.ContainsKey(TlsExtensionType.KeyShare));
        var extensionData = serverHello.Extensions[TlsExtensionType.KeyShare];
        
        // Verify key share data
        var reader = new TlsReader(extensionData);
        var decodedGroup = reader.ReadUInt16();
        var decodedKey = reader.ReadVector16();
        
        Assert.Equal(group, decodedGroup);
        Assert.Equal(publicKey, decodedKey.ToArray());
    }

    [Fact]
    public void ServerHello_Random_IsInitialized()
    {
        // Arrange & Act
        var serverHello = new ServerHello();

        // Assert
        Assert.Equal(32, serverHello.Random.Length);
        Assert.NotEqual(new byte[32], serverHello.Random);
    }
}