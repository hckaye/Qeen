using System.Security.Cryptography;
using Qeen.Core.Connection;
using Qeen.Security.Tls;

namespace Qeen.Security.Crypto;

/// <summary>
/// QUIC initial secrets derivation according to RFC 9001
/// </summary>
public static class InitialSecrets
{
    // RFC 9001 Section 5.2: Initial salt for QUIC v1
    private static readonly byte[] InitialSaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    
    // QUIC v2 initial salt (draft-ietf-quic-v2)
    private static readonly byte[] InitialSaltV2 = Convert.FromHexString("0dede3def700a6db819381be6e269dcbf9bd2ed9");
    
    /// <summary>
    /// Derives the initial secret from connection ID and salt
    /// </summary>
    public static byte[] DeriveInitialSecret(ReadOnlySpan<byte> connectionId, ReadOnlySpan<byte> salt)
    {
        if (connectionId.Length == 0)
            throw new ArgumentException("Connection ID cannot be empty", nameof(connectionId));
            
        // initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
        return Hkdf.Extract(HashAlgorithmName.SHA256, connectionId, salt);
    }
    
    /// <summary>
    /// Derives the initial secret for a specific QUIC version
    /// </summary>
    public static byte[] DeriveInitialSecret(ReadOnlySpan<byte> connectionId, QuicVersion version)
    {
        var salt = version switch
        {
            QuicVersion.Version1 => InitialSaltV1,
            QuicVersion.Version2 => InitialSaltV2,
            _ => InitialSaltV1
        };
        
        return DeriveInitialSecret(connectionId, salt);
    }
    
    /// <summary>
    /// Derives the client initial secret from the initial secret
    /// </summary>
    public static byte[] DeriveClientInitialSecret(ReadOnlySpan<byte> initialSecret)
    {
        // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        return Hkdf.ExpandLabel(HashAlgorithmName.SHA256, initialSecret, "client in", ReadOnlySpan<byte>.Empty, 32);
    }
    
    /// <summary>
    /// Derives the server initial secret from the initial secret
    /// </summary>
    public static byte[] DeriveServerInitialSecret(ReadOnlySpan<byte> initialSecret)
    {
        // server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
        return Hkdf.ExpandLabel(HashAlgorithmName.SHA256, initialSecret, "server in", ReadOnlySpan<byte>.Empty, 32);
    }
    
    /// <summary>
    /// Derives key material (key, IV, or header protection key) from a secret
    /// </summary>
    public static byte[] DeriveKeyMaterial(ReadOnlySpan<byte> secret, string label, int length)
    {
        return Hkdf.ExpandLabel(HashAlgorithmName.SHA256, secret, label, ReadOnlySpan<byte>.Empty, length);
    }
    
    /// <summary>
    /// Derives the AEAD key from a secret
    /// </summary>
    public static byte[] DeriveKey(ReadOnlySpan<byte> secret, int keyLength = 16)
    {
        return DeriveKeyMaterial(secret, "quic key", keyLength);
    }
    
    /// <summary>
    /// Derives the AEAD IV from a secret
    /// </summary>
    public static byte[] DeriveIv(ReadOnlySpan<byte> secret)
    {
        return DeriveKeyMaterial(secret, "quic iv", 12);
    }
    
    /// <summary>
    /// Derives the header protection key from a secret
    /// </summary>
    public static byte[] DeriveHpKey(ReadOnlySpan<byte> secret, int keyLength = 16)
    {
        return DeriveKeyMaterial(secret, "quic hp", keyLength);
    }
    
    /// <summary>
    /// Gets the initial salt for a QUIC version
    /// </summary>
    public static byte[] GetInitialSalt(QuicVersion version)
    {
        return version switch
        {
            QuicVersion.Version1 => InitialSaltV1,
            QuicVersion.Version2 => InitialSaltV2,
            _ => InitialSaltV1
        };
    }
}