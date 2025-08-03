namespace Qeen.Security.Tls.KeyExchange;

public interface IKeyExchange
{
    ushort NamedGroup { get; }
    byte[] PublicKey { get; }
    byte[] ComputeSharedSecret(byte[] peerPublicKey);
}