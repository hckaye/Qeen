using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls.Messages;

public class ClientHelloTests
{
    [Fact]
    public void ClientHello_EncodeDecode_RoundTrip()
    {
        // Arrange
        var original = new ClientHello();
        original.AddSupportedVersionsExtension();
        original.AddServerNameExtension("example.com");
        original.AddAlpnExtension("h3", "h3-29");
        original.AddKeyShareExtension(new byte[32], 0x001D);
        original.AddSupportedGroupsExtension(0x001D, 0x0017, 0x0018);
        original.AddSignatureAlgorithmsExtension(0x0403, 0x0503, 0x0804);
        original.AddQuicTransportParametersExtension(new byte[] { 0x01, 0x02, 0x03 });

        // Act - Encode
        var buffer = new byte[4096];
        var writer = new TlsWriter(buffer);
        original.Encode(ref writer);
        var encoded = writer.Written.ToArray();

        // Act - Decode
        var reader = new TlsReader(encoded);
        var decoded = ClientHello.Decode(ref reader, TlsMessageType.ClientHello) as ClientHello;

        // Assert
        Assert.NotNull(decoded);
        Assert.Equal(original.LegacyVersion, decoded.LegacyVersion);
        Assert.Equal(original.Random.Length, decoded.Random.Length);
        Assert.Equal(original.CipherSuites.Count, decoded.CipherSuites.Count);
        Assert.Equal(original.Extensions.Count, decoded.Extensions.Count);
        
        // Verify extensions are present
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.ServerName));
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.ApplicationLayerProtocolNegotiation));
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.KeyShare));
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.SupportedGroups));
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.SignatureAlgorithms));
        Assert.True(decoded.Extensions.ContainsKey(TlsExtensionType.QuicTransportParameters));
    }

    [Fact]
    public void ClientHello_DefaultCipherSuites_ContainsRequiredSuites()
    {
        // Arrange & Act
        var clientHello = new ClientHello();

        // Assert
        Assert.Contains(CipherSuite.TLS_AES_128_GCM_SHA256, clientHello.CipherSuites);
        Assert.Contains(CipherSuite.TLS_AES_256_GCM_SHA384, clientHello.CipherSuites);
        Assert.Contains(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, clientHello.CipherSuites);
    }

    [Fact]
    public void ClientHello_Random_IsInitialized()
    {
        // Arrange & Act
        var clientHello = new ClientHello();

        // Assert
        Assert.Equal(32, clientHello.Random.Length);
        Assert.NotEqual(new byte[32], clientHello.Random);
    }

    [Fact]
    public void ClientHello_ServerNameExtension_EncodesCorrectly()
    {
        // Arrange
        var clientHello = new ClientHello();
        var serverName = "test.example.com";

        // Act
        clientHello.AddServerNameExtension(serverName);

        // Assert
        Assert.True(clientHello.Extensions.ContainsKey(TlsExtensionType.ServerName));
        var extensionData = clientHello.Extensions[TlsExtensionType.ServerName];
        
        // Verify the extension contains the server name
        var reader = new TlsReader(extensionData);
        var listLength = reader.ReadUInt16();
        Assert.True(listLength > 0);
        
        var nameType = reader.ReadUInt8();
        Assert.Equal(0, nameType); // Host name type
        
        var nameBytes = reader.ReadVector16();
        var decodedName = System.Text.Encoding.UTF8.GetString(nameBytes);
        Assert.Equal(serverName, decodedName);
    }

    [Fact]
    public void ClientHello_AlpnExtension_EncodesMultipleProtocols()
    {
        // Arrange
        var clientHello = new ClientHello();
        var protocols = new[] { "h3", "h3-29", "h2" };

        // Act
        clientHello.AddAlpnExtension(protocols);

        // Assert
        Assert.True(clientHello.Extensions.ContainsKey(TlsExtensionType.ApplicationLayerProtocolNegotiation));
        var extensionData = clientHello.Extensions[TlsExtensionType.ApplicationLayerProtocolNegotiation];
        
        // Verify protocols
        var reader = new TlsReader(extensionData);
        var listLength = reader.ReadUInt16();
        Assert.True(listLength > 0);
        
        var decodedProtocols = new List<string>();
        while (reader.HasData)
        {
            decodedProtocols.Add(reader.ReadString8());
        }
        
        Assert.Equal(protocols.Length, decodedProtocols.Count);
        foreach (var protocol in protocols)
        {
            Assert.Contains(protocol, decodedProtocols);
        }
    }
}