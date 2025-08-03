using System.Security.Cryptography;
using Qeen.Security.Tls.Messages;

namespace Qeen.Security.Tls;

public class TlsKeySchedule
{
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly int _hashLength;
    private byte[] _transcript = Array.Empty<byte>();
    private byte[] _earlySecret = Array.Empty<byte>();
    private byte[] _handshakeSecret = Array.Empty<byte>();
    private byte[] _masterSecret = Array.Empty<byte>();
    
    public byte[] ClientHandshakeTrafficSecret { get; private set; } = Array.Empty<byte>();
    public byte[] ServerHandshakeTrafficSecret { get; private set; } = Array.Empty<byte>();
    public byte[] ClientApplicationTrafficSecret { get; private set; } = Array.Empty<byte>();
    public byte[] ServerApplicationTrafficSecret { get; private set; } = Array.Empty<byte>();
    public byte[] ExporterMasterSecret { get; private set; } = Array.Empty<byte>();
    public byte[] ResumptionMasterSecret { get; private set; } = Array.Empty<byte>();

    public TlsKeySchedule(CipherSuite cipherSuite)
    {
        _hashAlgorithm = GetHashAlgorithm(cipherSuite);
        _hashLength = GetHashLength(cipherSuite);
    }

    private static HashAlgorithmName GetHashAlgorithm(CipherSuite cipherSuite)
    {
        return cipherSuite switch
        {
            CipherSuite.TLS_AES_128_GCM_SHA256 => HashAlgorithmName.SHA256,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256 => HashAlgorithmName.SHA256,
            CipherSuite.TLS_AES_128_CCM_SHA256 => HashAlgorithmName.SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA256
        };
    }

    private static int GetHashLength(CipherSuite cipherSuite)
    {
        return cipherSuite switch
        {
            CipherSuite.TLS_AES_128_GCM_SHA256 => 32,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256 => 32,
            CipherSuite.TLS_AES_128_CCM_SHA256 => 32,
            CipherSuite.TLS_AES_256_GCM_SHA384 => 48,
            _ => 32
        };
    }

    public void UpdateTranscript(byte[] messageBytes)
    {
        using var hash = IncrementalHash.CreateHash(_hashAlgorithm);
        hash.AppendData(_transcript);
        hash.AppendData(messageBytes);
        _transcript = hash.GetCurrentHash();
    }

    public void UpdateTranscript(ITlsMessage message)
    {
        var buffer = new byte[65536];
        var writer = new TlsWriter(buffer);
        
        // TLS handshake message format
        writer.WriteUInt8((byte)message.Type);
        writer.WriteLengthPrefixed24((ref TlsWriter w) => message.Encode(ref w));
        
        UpdateTranscript(writer.Written.ToArray());
    }

    public void DeriveEarlySecrets(byte[]? psk = null)
    {
        var ikm = psk ?? new byte[_hashLength];
        var salt = new byte[_hashLength]; // All zeros
        
        _earlySecret = Hkdf.Extract(_hashAlgorithm, ikm, salt);
    }

    public void DeriveHandshakeSecrets(byte[] sharedSecret)
    {
        var derivedSecret = DeriveSecret(_earlySecret, "derived", Array.Empty<byte>());
        _handshakeSecret = Hkdf.Extract(_hashAlgorithm, sharedSecret, derivedSecret);
        
        ClientHandshakeTrafficSecret = DeriveSecret(_handshakeSecret, "c hs traffic", _transcript);
        ServerHandshakeTrafficSecret = DeriveSecret(_handshakeSecret, "s hs traffic", _transcript);
    }

    public void DeriveMasterSecrets()
    {
        var derivedSecret = DeriveSecret(_handshakeSecret, "derived", Array.Empty<byte>());
        var zeroKey = new byte[_hashLength];
        _masterSecret = Hkdf.Extract(_hashAlgorithm, zeroKey, derivedSecret);
        
        ClientApplicationTrafficSecret = DeriveSecret(_masterSecret, "c ap traffic", _transcript);
        ServerApplicationTrafficSecret = DeriveSecret(_masterSecret, "s ap traffic", _transcript);
        ExporterMasterSecret = DeriveSecret(_masterSecret, "exp master", _transcript);
        ResumptionMasterSecret = DeriveSecret(_masterSecret, "res master", _transcript);
    }

    private byte[] DeriveSecret(byte[] secret, string label, byte[] context)
    {
        var contextHash = context.Length > 0 ? context : GetEmptyHash();
        return Hkdf.ExpandLabel(_hashAlgorithm, secret, $"tls13 {label}", contextHash, _hashLength);
    }

    private byte[] GetEmptyHash()
    {
        using var hash = IncrementalHash.CreateHash(_hashAlgorithm);
        return hash.GetCurrentHash();
    }

    public byte[] DeriveFinishedKey(byte[] baseKey)
    {
        return Hkdf.ExpandLabel(_hashAlgorithm, baseKey, "tls13 finished", Array.Empty<byte>(), _hashLength);
    }

    public byte[] ComputeFinishedVerifyData(byte[] baseKey)
    {
        var finishedKey = DeriveFinishedKey(baseKey);
        using var hmac = IncrementalHash.CreateHMAC(_hashAlgorithm, finishedKey);
        hmac.AppendData(_transcript);
        return hmac.GetCurrentHash();
    }

    public byte[] GetTranscriptHash()
    {
        return _transcript;
    }

    public static byte[] DeriveKeyUpdateSecret(HashAlgorithmName hashAlgorithm, byte[] currentSecret)
    {
        var hashLength = hashAlgorithm == HashAlgorithmName.SHA384 ? 48 : 32;
        return Hkdf.ExpandLabel(hashAlgorithm, currentSecret, "tls13 quic ku", Array.Empty<byte>(), hashLength);
    }
}