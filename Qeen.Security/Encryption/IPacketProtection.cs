namespace Qeen.Security.Encryption;

public interface IPacketProtection
{
    int Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, ulong packetNumber);
    bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, Span<byte> plaintext, ulong packetNumber);
}