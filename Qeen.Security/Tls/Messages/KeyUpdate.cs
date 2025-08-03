namespace Qeen.Security.Tls.Messages;

public class KeyUpdate : ITlsMessage
{
    public TlsMessageType Type => TlsMessageType.KeyUpdate;
    
    public KeyUpdateRequest RequestUpdate { get; set; }

    public void Encode(ref TlsWriter writer)
    {
        writer.WriteUInt8((byte)RequestUpdate);
    }

    public static ITlsMessage Decode(ref TlsReader reader, TlsMessageType type)
    {
        return new KeyUpdate
        {
            RequestUpdate = (KeyUpdateRequest)reader.ReadUInt8()
        };
    }
}

public enum KeyUpdateRequest : byte
{
    UpdateNotRequested = 0,
    UpdateRequested = 1
}