using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Qeen.Core.Connection;
using Qeen.Core.Crypto;

namespace Qeen.Security.Tls;

public sealed class QuicTlsEngine : IQuicTlsEngine
{
    private readonly bool _isClient;
    private readonly byte[] _connectionId;
    private readonly TransportParameters _localTransportParams;
    
    private byte[]? _initialSecret;
    private byte[]? _handshakeReadSecret;
    private byte[]? _handshakeWriteSecret;
    private byte[]? _applicationReadSecret;
    private byte[]? _applicationWriteSecret;
    private byte[]? _earlyDataSecret;
    
    private readonly Dictionary<EncryptionLevel, byte[]> _readSecrets = new();
    private readonly Dictionary<EncryptionLevel, byte[]> _writeSecrets = new();
    
    // RFC 9001: Initial salt for QUIC v1
    private static readonly byte[] InitialSaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    
    public QuicTlsEngine(bool isClient, ReadOnlySpan<byte> connectionId, TransportParameters? transportParams = null)
    {
        _isClient = isClient;
        _connectionId = connectionId.ToArray();
        _localTransportParams = transportParams ?? TransportParameters.GetDefault();
        
        // Derive initial secrets
        DeriveInitialSecrets();
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public async ValueTask<HandshakeResult> PerformHandshakeAsync(CancellationToken cancellationToken = default)
    {
        // Simplified TLS 1.3 handshake simulation
        // In a real implementation, this would involve actual TLS 1.3 protocol exchange
        
        await Task.Delay(10, cancellationToken); // Simulate async operation
        
        // Generate handshake secrets
        _handshakeReadSecret = GenerateRandomSecret();
        _handshakeWriteSecret = GenerateRandomSecret();
        _writeSecrets[EncryptionLevel.Handshake] = _handshakeWriteSecret;
        _readSecrets[EncryptionLevel.Handshake] = _handshakeReadSecret;
        
        // Generate application secrets
        _applicationReadSecret = GenerateRandomSecret();
        _applicationWriteSecret = GenerateRandomSecret();
        _writeSecrets[EncryptionLevel.OneRtt] = _applicationWriteSecret;
        _readSecrets[EncryptionLevel.OneRtt] = _applicationReadSecret;
        
        return new HandshakeResult
        {
            IsComplete = true,
            ApplicationSecret = _applicationWriteSecret,
            HandshakeSecret = _handshakeWriteSecret,
            InitialSecret = _initialSecret ?? Array.Empty<byte>(),
            TransportParameters = TransportParametersCodec.Encode(_localTransportParams, !_isClient),
            EarlyDataAccepted = false
        };
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void UpdateKeys()
    {
        // RFC 9001: Key update mechanism
        if (_applicationReadSecret != null)
        {
            _applicationReadSecret = UpdateSecret(_applicationReadSecret);
            _readSecrets[EncryptionLevel.OneRtt] = _applicationReadSecret;
        }
        
        if (_applicationWriteSecret != null)
        {
            _applicationWriteSecret = UpdateSecret(_applicationWriteSecret);
            _writeSecrets[EncryptionLevel.OneRtt] = _applicationWriteSecret;
        }
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> GetWriteSecret(EncryptionLevel level)
    {
        return _writeSecrets.TryGetValue(level, out var secret) ? secret : ReadOnlySpan<byte>.Empty;
    }
    
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> GetReadSecret(EncryptionLevel level)
    {
        return _readSecrets.TryGetValue(level, out var secret) ? secret : ReadOnlySpan<byte>.Empty;
    }
    
    private void DeriveInitialSecrets()
    {
        // RFC 9001: Initial secret derivation
        var initialSecret = Hkdf.Extract(InitialSaltV1, _connectionId);
        
        // Derive client and server initial secrets
        var clientInitialSecret = Hkdf.ExpandLabel(initialSecret, "client in", ReadOnlySpan<byte>.Empty, 32);
        var serverInitialSecret = Hkdf.ExpandLabel(initialSecret, "server in", ReadOnlySpan<byte>.Empty, 32);
        
        if (_isClient)
        {
            _initialSecret = clientInitialSecret;
            _writeSecrets[EncryptionLevel.Initial] = clientInitialSecret;
            _readSecrets[EncryptionLevel.Initial] = serverInitialSecret;
        }
        else
        {
            _initialSecret = serverInitialSecret;
            _writeSecrets[EncryptionLevel.Initial] = serverInitialSecret;
            _readSecrets[EncryptionLevel.Initial] = clientInitialSecret;
        }
    }
    
    private static byte[] UpdateSecret(byte[] oldSecret)
    {
        // RFC 9001: Key update using "quic ku" label
        return Hkdf.ExpandLabel(oldSecret, "quic ku", ReadOnlySpan<byte>.Empty, oldSecret.Length);
    }
    
    private static byte[] GenerateRandomSecret()
    {
        var secret = new byte[32];
        RandomNumberGenerator.Fill(secret);
        return secret;
    }
    
}