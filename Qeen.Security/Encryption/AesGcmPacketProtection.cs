using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Qeen.Security.Encryption;

public struct AesGcmPacketProtection : IPacketProtection
{
    private readonly byte[] _key;
    private readonly AesGcm _aesGcm;

    public AesGcmPacketProtection(ReadOnlySpan<byte> key)
    {
        if (key.Length != 16 && key.Length != 32)
        {
            throw new ArgumentException("Key must be 128 or 256 bits", nameof(key));
        }

        _key = key.ToArray();
        _aesGcm = new AesGcm(_key, AesGcm.TagByteSizes.MaxSize);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext)
    {
        if (ciphertext.Length < plaintext.Length + AesGcm.TagByteSizes.MaxSize)
        {
            throw new ArgumentException("Ciphertext buffer is too small", nameof(ciphertext));
        }

        Span<byte> nonce = stackalloc byte[AesGcm.NonceByteSizes.MaxSize];
        GenerateNonce(nonce);

        var plaintextSpan = ciphertext[AesGcm.NonceByteSizes.MaxSize..(AesGcm.NonceByteSizes.MaxSize + plaintext.Length)];
        plaintext.CopyTo(plaintextSpan);

        var tag = ciphertext[(AesGcm.NonceByteSizes.MaxSize + plaintext.Length)..];

        _aesGcm.Encrypt(nonce, plaintextSpan, plaintextSpan, tag[..AesGcm.TagByteSizes.MaxSize], associatedData);

        nonce.CopyTo(ciphertext[..AesGcm.NonceByteSizes.MaxSize]);

        return AesGcm.NonceByteSizes.MaxSize + plaintext.Length + AesGcm.TagByteSizes.MaxSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, Span<byte> plaintext)
    {
        if (ciphertext.Length < AesGcm.NonceByteSizes.MaxSize + AesGcm.TagByteSizes.MaxSize)
        {
            return false;
        }

        var nonce = ciphertext[..AesGcm.NonceByteSizes.MaxSize];
        var encryptedData = ciphertext[AesGcm.NonceByteSizes.MaxSize..^AesGcm.TagByteSizes.MaxSize];
        var tag = ciphertext[^AesGcm.TagByteSizes.MaxSize..];

        if (plaintext.Length < encryptedData.Length)
        {
            return false;
        }

        try
        {
            _aesGcm.Decrypt(nonce, encryptedData, tag, plaintext[..encryptedData.Length], associatedData);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GenerateNonce(Span<byte> nonce)
    {
        RandomNumberGenerator.Fill(nonce);
    }

    public void Dispose()
    {
        _aesGcm?.Dispose();
    }
}