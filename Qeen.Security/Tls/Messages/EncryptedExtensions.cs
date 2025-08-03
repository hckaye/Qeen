namespace Qeen.Security.Tls.Messages;

public class EncryptedExtensions : ITlsMessage
{
    public TlsMessageType Type => TlsMessageType.EncryptedExtensions;
    
    public Dictionary<TlsExtensionType, byte[]> Extensions { get; set; } = new();

    public void Encode(ref TlsWriter writer)
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

    public static ITlsMessage Decode(ref TlsReader reader, TlsMessageType type)
    {
        var encryptedExtensions = new EncryptedExtensions();
        
        var extensionsLength = reader.ReadUInt16();
        var extensionsEnd = reader.Position + extensionsLength;
        while (reader.Position < extensionsEnd)
        {
            var extensionType = (TlsExtensionType)reader.ReadUInt16();
            var extensionData = reader.ReadVector16().ToArray();
            encryptedExtensions.Extensions[extensionType] = extensionData;
        }
        
        return encryptedExtensions;
    }

    public void AddAlpnExtension(string protocol)
    {
        var buffer = new byte[256];
        var writer = new TlsWriter(buffer);
        
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            w.WriteString8(protocol);
        });
        
        Extensions[TlsExtensionType.ApplicationLayerProtocolNegotiation] = writer.Written.ToArray();
    }

    public void AddQuicTransportParametersExtension(byte[] parameters)
    {
        Extensions[TlsExtensionType.QuicTransportParameters] = parameters;
    }

    public void AddServerNameExtension()
    {
        // Empty extension to acknowledge SNI
        Extensions[TlsExtensionType.ServerName] = Array.Empty<byte>();
    }
}