using System.Security.Cryptography;

namespace Qeen.Security.Tls.Messages;

public class ServerHello : ITlsMessage
{
    public TlsMessageType Type => TlsMessageType.ServerHello;
    
    public ushort LegacyVersion { get; set; } = 0x0303; // TLS 1.2 for compatibility
    public byte[] Random { get; set; } = new byte[32];
    public byte[] LegacySessionIdEcho { get; set; } = Array.Empty<byte>();
    public CipherSuite CipherSuite { get; set; }
    public byte LegacyCompressionMethod { get; set; } = 0; // null compression
    public Dictionary<TlsExtensionType, byte[]> Extensions { get; set; } = new();

    public ServerHello()
    {
        RandomNumberGenerator.Fill(Random);
    }

    public void Encode(ref TlsWriter writer)
    {
        writer.WriteUInt16(LegacyVersion);
        writer.WriteBytes(Random);
        writer.WriteVector8(LegacySessionIdEcho);
        writer.WriteUInt16((ushort)CipherSuite);
        writer.WriteUInt8(LegacyCompressionMethod);
        
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
        var serverHello = new ServerHello
        {
            LegacyVersion = reader.ReadUInt16(),
            Random = reader.ReadBytes(32).ToArray(),
            LegacySessionIdEcho = reader.ReadVector8().ToArray(),
            CipherSuite = (CipherSuite)reader.ReadUInt16(),
            LegacyCompressionMethod = reader.ReadUInt8()
        };
        
        // Extensions
        if (reader.HasData)
        {
            var extensionsLength = reader.ReadUInt16();
            var extensionsEnd = reader.Position + extensionsLength;
            while (reader.Position < extensionsEnd)
            {
                var extensionType = (TlsExtensionType)reader.ReadUInt16();
                var extensionData = reader.ReadVector16().ToArray();
                serverHello.Extensions[extensionType] = extensionData;
            }
        }
        
        return serverHello;
    }

    public void AddSupportedVersionsExtension()
    {
        var writer = new TlsWriter(new byte[2]);
        writer.WriteUInt16(0x0304); // TLS 1.3
        Extensions[TlsExtensionType.SupportedVersions] = writer.Written.ToArray();
    }

    public void AddKeyShareExtension(byte[] publicKey, ushort group)
    {
        var buffer = new byte[4 + publicKey.Length];
        var writer = new TlsWriter(buffer);
        
        writer.WriteUInt16(group); // Named group
        writer.WriteVector16(publicKey);
        
        Extensions[TlsExtensionType.KeyShare] = writer.Written.ToArray();
    }

    public void AddQuicTransportParametersExtension(byte[] parameters)
    {
        Extensions[TlsExtensionType.QuicTransportParameters] = parameters;
    }

    public bool IsHelloRetryRequest()
    {
        // TLS 1.3 HelloRetryRequest uses special random value
        ReadOnlySpan<byte> hrrRandom = new byte[]
        {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
            0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
            0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        };
        
        return Random.AsSpan().SequenceEqual(hrrRandom);
    }
}