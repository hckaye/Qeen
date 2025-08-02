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
        Span<byte> output, int headerLength)
    {
        if (!_packetProtections.TryGetValue(level, out var packetProtection))
        {
            throw new InvalidOperationException($"No packet protection available for encryption level {level}");
        }
        
        if (!_headerProtections.TryGetValue(level, out var headerProtection))
        {
            throw new InvalidOperationException($"No header protection available for encryption level {level}");
        }
        
        // Apply packet protection (AEAD encryption)
        var encryptedLength = packetProtection.Encrypt(plaintext, associatedData, output[headerLength..]);
        var totalLength = headerLength + encryptedLength;
        
        // Apply header protection
        headerProtection.Apply(output[..totalLength], headerLength);
        
        return totalLength;
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool UnprotectPacket(EncryptionLevel level, Span<byte> packet, int headerLength, 
        ReadOnlySpan<byte> associatedData, Span<byte> plaintext)
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
        
        // Remove packet protection (AEAD decryption)
        var ciphertext = packet[headerLength..];
        return packetProtection.TryDecrypt(ciphertext, associatedData, plaintext);
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
            var (aesKey, hpKey) = DeriveKeys(writeSecret);
            _packetProtections[level] = new AesGcmPacketProtection(aesKey);
            _headerProtections[level] = new AesEcbHeaderProtection(hpKey);
        }
    }
    
    private static (byte[] aesKey, byte[] hpKey) DeriveKeys(ReadOnlySpan<byte> secret)
    {
        // Derive AEAD key and header protection key from secret using RFC 9001 labels
        var aesKey = Hkdf.ExpandLabel(secret, "quic key", ReadOnlySpan<byte>.Empty, 16);  // 128-bit key for AES-128-GCM
        var hpKey = Hkdf.ExpandLabel(secret, "quic hp", ReadOnlySpan<byte>.Empty, 16);   // 128-bit key for header protection
        
        return (aesKey, hpKey);
    }
}