using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Qeen.Security.Encryption;

public struct AesGcmPacketProtection : IPacketProtection
{
    private readonly byte[] _key;
    private readonly byte[] _iv;
    private readonly AesGcm _aesGcm;

    public AesGcmPacketProtection(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (key.Length != 16 && key.Length != 32)
        {
            throw new ArgumentException("Key must be 128 or 256 bits", nameof(key));
        }
        
        if (iv.Length != 12)
        {
            throw new ArgumentException("IV must be 96 bits (12 bytes) for AES-GCM", nameof(iv));
        }

        _key = key.ToArray();
        _iv = iv.ToArray();
        _aesGcm = new AesGcm(_key, AesGcm.TagByteSizes.MaxSize);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int Encrypt(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, Span<byte> ciphertext, ulong packetNumber)
    {
        if (ciphertext.Length < plaintext.Length + AesGcm.TagByteSizes.MaxSize)
        {
            throw new ArgumentException("Ciphertext buffer is too small", nameof(ciphertext));
        }

        // RFC 9001 Section 5.3: Construct nonce by XORing IV with packet number
        Span<byte> nonce = stackalloc byte[12]; // AES-GCM uses 96-bit nonce
        ConstructNonce(nonce, packetNumber);

        // Encrypt in place - no need to store nonce in ciphertext for QUIC
        var ciphertextData = ciphertext[..plaintext.Length];
        plaintext.CopyTo(ciphertextData);

        var tag = ciphertext[plaintext.Length..(plaintext.Length + AesGcm.TagByteSizes.MaxSize)];

        _aesGcm.Encrypt(nonce, ciphertextData, ciphertextData, tag, associatedData);

        return plaintext.Length + AesGcm.TagByteSizes.MaxSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryDecrypt(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> associatedData, Span<byte> plaintext, ulong packetNumber)
    {
        if (ciphertext.Length < AesGcm.TagByteSizes.MaxSize)
        {
            return false;
        }

        // RFC 9001 Section 5.3: Construct nonce by XORing IV with packet number
        Span<byte> nonce = stackalloc byte[12]; // AES-GCM uses 96-bit nonce
        ConstructNonce(nonce, packetNumber);

        var encryptedData = ciphertext[..^AesGcm.TagByteSizes.MaxSize];
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

    /// <summary>
    /// Constructs a nonce according to RFC 9001 Section 5.3.
    /// The nonce is formed by XORing the packet protection IV with the packet number.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ConstructNonce(Span<byte> nonce, ulong packetNumber)
    {
        // Copy the IV to the nonce
        _iv.CopyTo(nonce);
        
        // RFC 9001 Section 5.3: The 62 bits of the packet number are left-padded with zeros
        // and XORed with the IV to form the nonce.
        // We encode the packet number in big-endian at the end of the nonce
        
        // Get the offset where we should write the packet number (last 8 bytes of 12-byte nonce)
        int offset = nonce.Length - sizeof(ulong);
        
        // XOR the packet number with the IV (big-endian encoding)
        for (int i = 0; i < sizeof(ulong); i++)
        {
            nonce[offset + i] ^= (byte)(packetNumber >> (56 - (i * 8)));
        }
    }

    public void Dispose()
    {
        _aesGcm?.Dispose();
    }
}