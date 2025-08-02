using Qeen.Core.Crypto;

namespace Qeen.Security.Tls;

public interface IQuicTlsEngine
{
    ValueTask<HandshakeResult> PerformHandshakeAsync(CancellationToken cancellationToken = default);
    void UpdateKeys();
    ReadOnlySpan<byte> GetWriteSecret(EncryptionLevel level);
    ReadOnlySpan<byte> GetReadSecret(EncryptionLevel level);
}