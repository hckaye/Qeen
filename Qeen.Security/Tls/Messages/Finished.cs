namespace Qeen.Security.Tls.Messages;

public class Finished : ITlsMessage
{
    public TlsMessageType Type => TlsMessageType.Finished;
    
    public byte[] VerifyData { get; set; } = Array.Empty<byte>();

    public void Encode(ref TlsWriter writer)
    {
        writer.WriteBytes(VerifyData);
    }

    public static ITlsMessage Decode(ref TlsReader reader, TlsMessageType type)
    {
        return new Finished
        {
            VerifyData = reader.Remaining.ToArray()
        };
    }
}