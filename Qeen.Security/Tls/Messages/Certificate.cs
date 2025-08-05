using System.Security.Cryptography.X509Certificates;

namespace Qeen.Security.Tls.Messages;

public class Certificate : ITlsMessage
{
    public TlsMessageType Type => TlsMessageType.Certificate;
    
    public byte[] CertificateRequestContext { get; set; } = Array.Empty<byte>();
    public List<CertificateEntry> CertificateList { get; set; } = new();

    public class CertificateEntry
    {
        public byte[] CertData { get; set; } = Array.Empty<byte>();
        public Dictionary<TlsExtensionType, byte[]> Extensions { get; set; } = new();

        public CertificateEntry() { }
        
        public CertificateEntry(X509Certificate2 certificate)
        {
            CertData = certificate.RawData;
        }
    }

    public void Encode(ref TlsWriter writer)
    {
        writer.WriteVector8(CertificateRequestContext);
        
        writer.WriteLengthPrefixed24((ref TlsWriter w) =>
        {
            foreach (var entry in CertificateList)
            {
                w.WriteVector24(entry.CertData);
                
                // Extensions for this certificate
                w.WriteLengthPrefixed16((ref TlsWriter ew) =>
                {
                    foreach (var (type, data) in entry.Extensions)
                    {
                        ew.WriteUInt16((ushort)type);
                        ew.WriteVector16(data);
                    }
                });
            }
        });
    }

    public static ITlsMessage Decode(ref TlsReader reader, TlsMessageType type)
    {
        var certificate = new Certificate
        {
            CertificateRequestContext = reader.ReadVector8().ToArray()
        };
        
        var certListLength = (int)reader.ReadUInt24();
        var certListEnd = reader.Position + certListLength;
        
        while (reader.Position < certListEnd)
        {
            var entry = new CertificateEntry
            {
                CertData = reader.ReadVector24().ToArray()
            };
            
            var extensionsLength = reader.ReadUInt16();
            var extensionsEnd = reader.Position + extensionsLength;
            while (reader.Position < extensionsEnd)
            {
                var extensionType = (TlsExtensionType)reader.ReadUInt16();
                var extensionData = reader.ReadVector16().ToArray();
                entry.Extensions[extensionType] = extensionData;
            }
            
            certificate.CertificateList.Add(entry);
        }
        
        return certificate;
    }

    public void AddCertificateChain(X509Certificate2Collection chain)
    {
        foreach (var cert in chain)
        {
            CertificateList.Add(new CertificateEntry(cert));
        }
    }

    public X509Certificate2Collection GetCertificateChain()
    {
        var collection = new X509Certificate2Collection();
        foreach (var entry in CertificateList)
        {
            if (entry.CertData.Length > 0)
            {
                collection.Add(X509CertificateLoader.LoadCertificate(entry.CertData));
            }
        }
        return collection;
    }
}