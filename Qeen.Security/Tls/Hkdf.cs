using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Qeen.Security.Tls;

/// <summary>
/// HKDF (HMAC-based Extract-and-Expand Key Derivation Function) implementation
/// as specified in RFC 5869 and used in TLS 1.3 (RFC 8446) and QUIC (RFC 9001)
/// </summary>
public static class Hkdf
{
    private const int Sha256HashSize = 32;
    private const int Sha384HashSize = 48;
    
    /// <summary>
    /// HKDF-Extract(salt, IKM) -> PRK
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] Extract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> ikm)
    {
        using var hmac = salt.Length > 0 
            ? new HMACSHA256(salt.ToArray()) 
            : new HMACSHA256(new byte[Sha256HashSize]); // If salt is empty, use zeros
        
        return hmac.ComputeHash(ikm.ToArray());
    }
    
    /// <summary>
    /// HKDF-Extract with HashAlgorithmName
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] Extract(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt)
    {
        using var hmac = CreateHmac(hashAlgorithm, salt);
        return hmac.ComputeHash(ikm.ToArray());
    }
    
    /// <summary>
    /// HKDF-Expand(PRK, info, L) -> OKM
    /// </summary>
    public static byte[] Expand(ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int length)
    {
        if (length > 255 * Sha256HashSize)
        {
            throw new ArgumentException($"Length too large: {length} > {255 * Sha256HashSize}", nameof(length));
        }
        
        var output = new byte[length];
        var outputSpan = output.AsSpan();
        var prev = ReadOnlySpan<byte>.Empty;
        
        using var hmac = new HMACSHA256(prk.ToArray());
        
        for (int i = 0; i < length; i += Sha256HashSize)
        {
            var counter = (byte)((i / Sha256HashSize) + 1);
            var toHash = new byte[prev.Length + info.Length + 1];
            
            prev.CopyTo(toHash);
            info.CopyTo(toHash.AsSpan(prev.Length));
            toHash[^1] = counter;
            
            var hash = hmac.ComputeHash(toHash);
            var toCopy = Math.Min(Sha256HashSize, length - i);
            hash.AsSpan(0, toCopy).CopyTo(outputSpan[i..]);
            
            prev = hash;
        }
        
        return output;
    }
    
    /// <summary>
    /// HKDF-Expand with HashAlgorithmName
    /// </summary>
    public static byte[] Expand(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> prk, ReadOnlySpan<byte> info, int length)
    {
        var hashSize = GetHashSize(hashAlgorithm);
        if (length > 255 * hashSize)
        {
            throw new ArgumentException($"Length too large: {length} > {255 * hashSize}", nameof(length));
        }
        
        var output = new byte[length];
        var outputSpan = output.AsSpan();
        var prev = ReadOnlySpan<byte>.Empty;
        
        using var hmac = CreateHmac(hashAlgorithm, prk);
        
        for (int i = 0; i < length; i += hashSize)
        {
            var counter = (byte)((i / hashSize) + 1);
            var toHash = new byte[prev.Length + info.Length + 1];
            
            prev.CopyTo(toHash);
            info.CopyTo(toHash.AsSpan(prev.Length));
            toHash[^1] = counter;
            
            var hash = hmac.ComputeHash(toHash);
            var toCopy = Math.Min(hashSize, length - i);
            hash.AsSpan(0, toCopy).CopyTo(outputSpan[i..]);
            
            prev = hash;
        }
        
        return output;
    }
    
    /// <summary>
    /// HKDF-Expand-Label as specified in RFC 8446 Section 7.1
    /// </summary>
    public static byte[] ExpandLabel(ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> context, int length)
    {
        var hkdfLabel = BuildHkdfLabel(label, context, length);
        return Expand(secret, hkdfLabel, length);
    }
    
    /// <summary>
    /// HKDF-Expand-Label with HashAlgorithmName
    /// </summary>
    public static byte[] ExpandLabel(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> secret, string label, ReadOnlySpan<byte> context, int length)
    {
        var hkdfLabel = BuildHkdfLabel(label, context, length);
        return Expand(hashAlgorithm, secret, hkdfLabel, length);
    }
    
    /// <summary>
    /// Build HKDF label structure as per RFC 8446
    /// </summary>
    private static byte[] BuildHkdfLabel(string label, ReadOnlySpan<byte> context, int length)
    {
        // struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // } HkdfLabel;
        
        var tlsLabel = "tls13 " + label;
        var labelBytes = Encoding.ASCII.GetBytes(tlsLabel);
        
        if (labelBytes.Length > 255)
        {
            throw new ArgumentException($"Label too long: {labelBytes.Length} bytes", nameof(label));
        }
        
        if (context.Length > 255)
        {
            throw new ArgumentException($"Context too long: {context.Length} bytes", nameof(context));
        }
        
        using var ms = new MemoryStream();
        
        // uint16 length
        ms.WriteByte((byte)(length >> 8));
        ms.WriteByte((byte)length);
        
        // opaque label<7..255>
        ms.WriteByte((byte)labelBytes.Length);
        ms.Write(labelBytes);
        
        // opaque context<0..255>
        ms.WriteByte((byte)context.Length);
        if (context.Length > 0)
        {
            ms.Write(context.ToArray());
        }
        
        return ms.ToArray();
    }
    
    /// <summary>
    /// Derive secret for specific QUIC usage
    /// </summary>
    public static byte[] DeriveSecret(ReadOnlySpan<byte> secret, string label, int length = Sha256HashSize)
    {
        return ExpandLabel(secret, label, ReadOnlySpan<byte>.Empty, length);
    }
    
    private static HMAC CreateHmac(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> key)
    {
        var keyArray = key.Length > 0 ? key.ToArray() : new byte[GetHashSize(hashAlgorithm)];
        
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return new HMACSHA256(keyArray);
        else if (hashAlgorithm == HashAlgorithmName.SHA384)
            return new HMACSHA384(keyArray);
        else if (hashAlgorithm == HashAlgorithmName.SHA512)
            return new HMACSHA512(keyArray);
        else
            throw new NotSupportedException($"Hash algorithm {hashAlgorithm} is not supported");
    }
    
    private static int GetHashSize(HashAlgorithmName hashAlgorithm)
    {
        if (hashAlgorithm == HashAlgorithmName.SHA256)
            return 32;
        else if (hashAlgorithm == HashAlgorithmName.SHA384)
            return 48;
        else if (hashAlgorithm == HashAlgorithmName.SHA512)
            return 64;
        else
            throw new NotSupportedException($"Hash algorithm {hashAlgorithm} is not supported");
    }
}