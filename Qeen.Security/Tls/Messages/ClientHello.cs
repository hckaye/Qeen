using System.Security.Cryptography;

namespace Qeen.Security.Tls.Messages;

public class ClientHello : ITlsMessage
{
    public TlsMessageType Type => TlsMessageType.ClientHello;
    
    public ushort LegacyVersion { get; set; } = 0x0303; // TLS 1.2 for compatibility
    public byte[] Random { get; set; } = new byte[32];
    public byte[] LegacySessionId { get; set; } = Array.Empty<byte>();
    public List<CipherSuite> CipherSuites { get; set; } = new();
    public byte[] LegacyCompressionMethods { get; set; } = new byte[] { 0 }; // null compression
    public Dictionary<TlsExtensionType, byte[]> Extensions { get; set; } = new();

    public ClientHello()
    {
        RandomNumberGenerator.Fill(Random);
        
        // Add default cipher suites for QUIC
        CipherSuites.Add(CipherSuite.TLS_AES_128_GCM_SHA256);
        CipherSuites.Add(CipherSuite.TLS_AES_256_GCM_SHA384);
        CipherSuites.Add(CipherSuite.TLS_CHACHA20_POLY1305_SHA256);
    }

    public void Encode(ref TlsWriter writer)
    {
        writer.WriteUInt16(LegacyVersion);
        writer.WriteBytes(Random);
        writer.WriteVector8(LegacySessionId);
        
        // Cipher suites
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            foreach (var suite in CipherSuites)
            {
                w.WriteUInt16((ushort)suite);
            }
        });
        
        // Legacy compression methods
        writer.WriteVector8(LegacyCompressionMethods);
        
        // Extensions
        if (Extensions.Count > 0)
        {
            writer.WriteLengthPrefixed16((ref TlsWriter w) =>
            {
                foreach (var (type, data) in Extensions)
                {
                    w.WriteUInt16((ushort)type);
                    w.WriteVector16(data);
                }
            });
        }
    }

    public static ITlsMessage Decode(ref TlsReader reader, TlsMessageType type)
    {
        var clientHello = new ClientHello();
        clientHello.CipherSuites.Clear(); // Clear default cipher suites
        
        clientHello.LegacyVersion = reader.ReadUInt16();
        clientHello.Random = reader.ReadBytes(32).ToArray();
        clientHello.LegacySessionId = reader.ReadVector8().ToArray();
        
        // Cipher suites
        var cipherSuitesLength = reader.ReadUInt16();
        var cipherSuitesEnd = reader.Position + cipherSuitesLength;
        while (reader.Position < cipherSuitesEnd)
        {
            clientHello.CipherSuites.Add((CipherSuite)reader.ReadUInt16());
        }
        
        // Legacy compression methods
        clientHello.LegacyCompressionMethods = reader.ReadVector8().ToArray();
        
        // Extensions
        if (reader.HasData)
        {
            var extensionsLength = reader.ReadUInt16();
            var extensionsEnd = reader.Position + extensionsLength;
            while (reader.Position < extensionsEnd)
            {
                var extensionType = (TlsExtensionType)reader.ReadUInt16();
                var extensionData = reader.ReadVector16().ToArray();
                clientHello.Extensions[extensionType] = extensionData;
            }
        }
        
        return clientHello;
    }

    public void AddSupportedVersionsExtension()
    {
        var writer = new TlsWriter(new byte[3]);
        writer.WriteUInt8(2); // Length of versions list
        writer.WriteUInt16(0x0304); // TLS 1.3
        Extensions[TlsExtensionType.SupportedVersions] = writer.Written.ToArray();
    }

    public void AddServerNameExtension(string serverName)
    {
        var nameBytes = System.Text.Encoding.UTF8.GetBytes(serverName);
        var buffer = new byte[5 + nameBytes.Length];
        var writer = new TlsWriter(buffer);
        
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            w.WriteUInt8(0); // Host name type
            w.WriteVector16(nameBytes);
        });
        
        Extensions[TlsExtensionType.ServerName] = writer.Written.ToArray();
    }

    public void AddAlpnExtension(params string[] protocols)
    {
        var buffer = new byte[1024];
        var writer = new TlsWriter(buffer);
        
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            foreach (var protocol in protocols)
            {
                w.WriteString8(protocol);
            }
        });
        
        Extensions[TlsExtensionType.ApplicationLayerProtocolNegotiation] = writer.Written.ToArray();
    }

    public void AddKeyShareExtension(byte[] publicKey, ushort group)
    {
        var buffer = new byte[1024];
        var writer = new TlsWriter(buffer);
        
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            w.WriteUInt16(group); // Named group
            w.WriteVector16(publicKey);
        });
        
        Extensions[TlsExtensionType.KeyShare] = writer.Written.ToArray();
    }

    public void AddSupportedGroupsExtension(params ushort[] groups)
    {
        var buffer = new byte[2 + groups.Length * 2];
        var writer = new TlsWriter(buffer);
        
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            foreach (var group in groups)
            {
                w.WriteUInt16(group);
            }
        });
        
        Extensions[TlsExtensionType.SupportedGroups] = writer.Written.ToArray();
    }

    public void AddSignatureAlgorithmsExtension(params ushort[] algorithms)
    {
        var buffer = new byte[2 + algorithms.Length * 2];
        var writer = new TlsWriter(buffer);
        
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            foreach (var algo in algorithms)
            {
                w.WriteUInt16(algo);
            }
        });
        
        Extensions[TlsExtensionType.SignatureAlgorithms] = writer.Written.ToArray();
    }

    public void AddQuicTransportParametersExtension(byte[] parameters)
    {
        Extensions[TlsExtensionType.QuicTransportParameters] = parameters;
    }
}