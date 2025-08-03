namespace Qeen.Security.Tls.Messages;

public interface ITlsMessage
{
    TlsMessageType Type { get; }
    void Encode(ref TlsWriter writer);
    static abstract ITlsMessage Decode(ref TlsReader reader, TlsMessageType type);
}