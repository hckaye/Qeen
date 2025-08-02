using System.Runtime.CompilerServices;
using Qeen.Core.Crypto;
using Qeen.Security.Encryption;
using Qeen.Security.Protection;
using Qeen.Security.Tls;

namespace Qeen.Security;

public sealed class PacketProtector
{
    private readonly IQuicTlsEngine _tlsEngine;
    private readonly Dictionary<EncryptionLevel, IPacketProtection> _packetProtections = new();
    private readonly Dictionary<EncryptionLevel, IHeaderProtection> _headerProtections = new();
    
    public PacketProtector(IQuicTlsEngine tlsEngine)
    {
        _tlsEngine = tlsEngine ?? throw new ArgumentNullException(nameof(tlsEngine));
        InitializeProtections();
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int ProtectPacket(EncryptionLevel level, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, 
        Span<byte> output, int headerLength, ulong packetNumber)
    {
        if (!_packetProtections.TryGetValue(level, out var packetProtection))
        {
            throw new InvalidOperationException($"No packet protection available for encryption level {level}");
        }
        
        if (!_headerProtections.TryGetValue(level, out var headerProtection))
        {
            throw new InvalidOperationException($"No header protection available for encryption level {level}");
        }
        
        // Apply packet protection (AEAD encryption) with packet number for nonce construction
        var encryptedLength = packetProtection.Encrypt(plaintext, associatedData, output[headerLength..], packetNumber);
        var totalLength = headerLength + encryptedLength;
        
        // Apply header protection
        headerProtection.Apply(output[..totalLength], headerLength);
        
        return totalLength;
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool UnprotectPacket(EncryptionLevel level, Span<byte> packet, int headerLength, 
        ReadOnlySpan<byte> associatedData, Span<byte> plaintext, ulong packetNumber)
    {
        if (!_headerProtections.TryGetValue(level, out var headerProtection))
        {
            return false;
        }
        
        if (!_packetProtections.TryGetValue(level, out var packetProtection))
        {
            return false;
        }
        
        // Remove header protection
        headerProtection.Remove(packet, headerLength);
        
        // Remove packet protection (AEAD decryption) with packet number for nonce construction
        var ciphertext = packet[headerLength..];
        return packetProtection.TryDecrypt(ciphertext, associatedData, plaintext, packetNumber);
    }
    
    public void UpdateKeys()
    {
        _tlsEngine.UpdateKeys();
        UpdateProtection(EncryptionLevel.OneRtt);
    }
    
    public async Task InitializeHandshakeAsync(CancellationToken cancellationToken = default)
    {
        var result = await _tlsEngine.PerformHandshakeAsync(cancellationToken);
        
        if (result.IsComplete)
        {
            // Update protections for handshake and application levels
            UpdateProtection(EncryptionLevel.Handshake);
            UpdateProtection(EncryptionLevel.OneRtt);
            
            if (result.EarlyDataAccepted)
            {
                UpdateProtection(EncryptionLevel.ZeroRtt);
            }
        }
    }
    
    private void InitializeProtections()
    {
        // Initialize protection for all encryption levels
        UpdateProtection(EncryptionLevel.Initial);
    }
    
    private void UpdateProtection(EncryptionLevel level)
    {
        var writeSecret = _tlsEngine.GetWriteSecret(level);
        var readSecret = _tlsEngine.GetReadSecret(level);
        
        if (!writeSecret.IsEmpty)
        {
            var (aesKey, iv, hpKey) = DeriveKeysAndIv(writeSecret);
            _packetProtections[level] = new AesGcmPacketProtection(aesKey, iv);
            _headerProtections[level] = new AesEcbHeaderProtection(hpKey);
        }
    }
    
    private static (byte[] aesKey, byte[] iv, byte[] hpKey) DeriveKeysAndIv(ReadOnlySpan<byte> secret)
    {
        // RFC 9001 Section 5.1: Derive AEAD key, IV, and header protection key from secret
        var aesKey = Hkdf.ExpandLabel(secret, "quic key", ReadOnlySpan<byte>.Empty, 16);  // 128-bit key for AES-128-GCM
        var iv = Hkdf.ExpandLabel(secret, "quic iv", ReadOnlySpan<byte>.Empty, 12);       // 96-bit IV for AES-GCM
        var hpKey = Hkdf.ExpandLabel(secret, "quic hp", ReadOnlySpan<byte>.Empty, 16);    // 128-bit key for header protection
        
        return (aesKey, iv, hpKey);
    }
}