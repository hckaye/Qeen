using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Qeen.Core.Connection;
using Qeen.Core.Crypto;
using Qeen.Security.Tls.KeyExchange;
using Qeen.Security.Tls.Messages;

namespace Qeen.Security.Tls;

public class TlsHandshakeEngine : IQuicTlsEngine
{
    private readonly bool _isClient;
    private readonly byte[] _connectionId;
    private readonly TransportParameters _localTransportParams;
    private TlsKeySchedule _keySchedule;
    private readonly List<byte[]> _handshakeMessages = new();
    
    private TlsHandshakeState _state = TlsHandshakeState.Start;
    private IKeyExchange? _keyExchange;
    private CipherSuite _selectedCipherSuite;
    private TransportParameters? _peerTransportParams;
    private X509Certificate2? _localCertificate;
    private X509Certificate2Collection? _peerCertificates;
    private string? _serverName;
    private string? _alpnProtocol;
    
    private readonly Dictionary<EncryptionLevel, byte[]> _readSecrets = new();
    private readonly Dictionary<EncryptionLevel, byte[]> _writeSecrets = new();
    
    // RFC 9001: Initial salt for QUIC v1
    private static readonly byte[] InitialSaltV1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    
    // Supported cipher suites for QUIC
    private static readonly CipherSuite[] SupportedCipherSuites = 
    {
        CipherSuite.TLS_AES_128_GCM_SHA256,
        CipherSuite.TLS_AES_256_GCM_SHA384,
        CipherSuite.TLS_CHACHA20_POLY1305_SHA256
    };
    
    // Supported named groups
    private static readonly ushort[] SupportedGroups = 
    {
        0x001D, // X25519
        0x0017, // secp256r1 
        0x0018, // secp384r1
    };
    
    // Supported signature algorithms
    private static readonly ushort[] SupportedSignatureAlgorithms = 
    {
        (ushort)SignatureScheme.EcdsaSecp256r1Sha256,
        (ushort)SignatureScheme.EcdsaSecp384r1Sha384,
        (ushort)SignatureScheme.RsaPssRsaeSha256,
        (ushort)SignatureScheme.RsaPssRsaeSha384,
        (ushort)SignatureScheme.RsaPssRsaeSha512,
        (ushort)SignatureScheme.Ed25519
    };

    public TlsHandshakeEngine(
        bool isClient, 
        ReadOnlySpan<byte> connectionId, 
        TransportParameters? transportParams = null,
        X509Certificate2? certificate = null,
        string? serverName = null,
        string? alpnProtocol = null)
    {
        _isClient = isClient;
        _connectionId = connectionId.ToArray();
        _localTransportParams = transportParams ?? TransportParameters.GetDefault();
        _localCertificate = certificate;
        _serverName = serverName;
        _alpnProtocol = alpnProtocol;
        
        // Start with default cipher suite
        _selectedCipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256;
        _keySchedule = new TlsKeySchedule(_selectedCipherSuite);
        
        // Derive initial secrets
        DeriveInitialSecrets();
    }

    public async ValueTask<HandshakeResult> PerformHandshakeAsync(CancellationToken cancellationToken = default)
    {
        if (_isClient)
        {
            await PerformClientHandshakeAsync(cancellationToken);
        }
        else
        {
            await PerformServerHandshakeAsync(cancellationToken);
        }
        
        return new HandshakeResult
        {
            IsComplete = _state == TlsHandshakeState.Connected,
            ApplicationSecret = _writeSecrets.GetValueOrDefault(EncryptionLevel.OneRtt, Array.Empty<byte>()),
            HandshakeSecret = _writeSecrets.GetValueOrDefault(EncryptionLevel.Handshake, Array.Empty<byte>()),
            InitialSecret = _writeSecrets.GetValueOrDefault(EncryptionLevel.Initial, Array.Empty<byte>()),
            TransportParameters = TransportParametersCodec.Encode(_peerTransportParams ?? new TransportParameters(), !_isClient),
            EarlyDataAccepted = false
        };
    }

    private async ValueTask PerformClientHandshakeAsync(CancellationToken cancellationToken)
    {
        // Send ClientHello
        var clientHello = CreateClientHello();
        _keySchedule.UpdateTranscript(clientHello);
        _handshakeMessages.Add(SerializeMessage(clientHello));
        
        // Simulate receiving ServerHello (in real implementation, this would come from CRYPTO frames)
        await Task.Delay(10, cancellationToken);
        
        // Process ServerHello
        var serverHello = CreateMockServerHello();
        _keySchedule.UpdateTranscript(serverHello);
        ProcessServerHello(serverHello);
        
        // Derive handshake secrets
        if (_keyExchange != null)
        {
            var sharedSecret = _keyExchange.ComputeSharedSecret(new byte[32]); // Mock peer key
            _keySchedule.DeriveHandshakeSecrets(sharedSecret);
            SetHandshakeSecrets();
        }
        
        // Process EncryptedExtensions
        var encryptedExtensions = CreateMockEncryptedExtensions();
        _keySchedule.UpdateTranscript(encryptedExtensions);
        
        // Process Certificate (optional)
        if (!_isClient || _localCertificate != null)
        {
            var certificate = CreateMockCertificate();
            _keySchedule.UpdateTranscript(certificate);
        }
        
        // Process CertificateVerify (optional)
        // var certificateVerify = CreateMockCertificateVerify();
        // _keySchedule.UpdateTranscript(certificateVerify);
        
        // Process Finished
        var serverFinished = CreateMockFinished(true);
        _keySchedule.UpdateTranscript(serverFinished);
        
        // Derive application secrets
        _keySchedule.DeriveMasterSecrets();
        SetApplicationSecrets();
        
        // Send client Finished
        var clientFinished = CreateMockFinished(false);
        _keySchedule.UpdateTranscript(clientFinished);
        
        _state = TlsHandshakeState.Connected;
    }

    private async ValueTask PerformServerHandshakeAsync(CancellationToken cancellationToken)
    {
        // Simulate receiving ClientHello (in real implementation, this would come from CRYPTO frames)
        await Task.Delay(10, cancellationToken);
        
        var clientHello = CreateMockClientHello();
        _keySchedule.UpdateTranscript(clientHello);
        ProcessClientHello(clientHello);
        
        // Send ServerHello
        var serverHello = CreateServerHello();
        _keySchedule.UpdateTranscript(serverHello);
        _handshakeMessages.Add(SerializeMessage(serverHello));
        
        // Derive handshake secrets
        if (_keyExchange != null)
        {
            var sharedSecret = _keyExchange.ComputeSharedSecret(new byte[32]); // Mock peer key
            _keySchedule.DeriveHandshakeSecrets(sharedSecret);
            SetHandshakeSecrets();
        }
        
        // Send EncryptedExtensions
        var encryptedExtensions = CreateEncryptedExtensions();
        _keySchedule.UpdateTranscript(encryptedExtensions);
        _handshakeMessages.Add(SerializeMessage(encryptedExtensions));
        
        // Send Certificate (optional)
        if (_localCertificate != null)
        {
            var certificate = CreateCertificate();
            _keySchedule.UpdateTranscript(certificate);
            _handshakeMessages.Add(SerializeMessage(certificate));
            
            // Send CertificateVerify
            // var certificateVerify = CreateCertificateVerify();
            // _keySchedule.UpdateTranscript(certificateVerify);
            // _handshakeMessages.Add(SerializeMessage(certificateVerify));
        }
        
        // Send Finished
        var serverFinished = CreateFinished();
        _keySchedule.UpdateTranscript(serverFinished);
        _handshakeMessages.Add(SerializeMessage(serverFinished));
        
        // Derive application secrets
        _keySchedule.DeriveMasterSecrets();
        SetApplicationSecrets();
        
        // Wait for client Finished
        await Task.Delay(10, cancellationToken);
        var clientFinished = CreateMockFinished(false);
        _keySchedule.UpdateTranscript(clientFinished);
        
        _state = TlsHandshakeState.Connected;
    }

    private ClientHello CreateClientHello()
    {
        var clientHello = new ClientHello();
        
        // Add supported versions extension (TLS 1.3)
        clientHello.AddSupportedVersionsExtension();
        
        // Add server name indication
        if (!string.IsNullOrEmpty(_serverName))
        {
            clientHello.AddServerNameExtension(_serverName);
        }
        
        // Add ALPN
        if (!string.IsNullOrEmpty(_alpnProtocol))
        {
            clientHello.AddAlpnExtension(_alpnProtocol);
        }
        
        // Add key share
        _keyExchange = new X25519KeyExchange();
        clientHello.AddKeyShareExtension(_keyExchange.PublicKey, _keyExchange.NamedGroup);
        
        // Add supported groups
        clientHello.AddSupportedGroupsExtension(SupportedGroups);
        
        // Add signature algorithms
        clientHello.AddSignatureAlgorithmsExtension(SupportedSignatureAlgorithms);
        
        // Add QUIC transport parameters
        var tpBytes = TransportParametersCodec.Encode(_localTransportParams, false);
        clientHello.AddQuicTransportParametersExtension(tpBytes);
        
        return clientHello;
    }

    private ServerHello CreateServerHello()
    {
        var serverHello = new ServerHello
        {
            CipherSuite = _selectedCipherSuite
        };
        
        // Add supported version (TLS 1.3)
        serverHello.AddSupportedVersionsExtension();
        
        // Add key share
        if (_keyExchange != null)
        {
            serverHello.AddKeyShareExtension(_keyExchange.PublicKey, _keyExchange.NamedGroup);
        }
        
        return serverHello;
    }

    private EncryptedExtensions CreateEncryptedExtensions()
    {
        var encryptedExtensions = new EncryptedExtensions();
        
        // Add ALPN if negotiated
        if (!string.IsNullOrEmpty(_alpnProtocol))
        {
            encryptedExtensions.AddAlpnExtension(_alpnProtocol);
        }
        
        // Add server name acknowledgment
        if (!string.IsNullOrEmpty(_serverName))
        {
            encryptedExtensions.AddServerNameExtension();
        }
        
        // Add QUIC transport parameters
        var tpBytes = TransportParametersCodec.Encode(_localTransportParams, true);
        encryptedExtensions.AddQuicTransportParametersExtension(tpBytes);
        
        return encryptedExtensions;
    }

    private Certificate CreateCertificate()
    {
        var certificate = new Certificate();
        
        if (_localCertificate != null)
        {
            var chain = new X509Certificate2Collection { _localCertificate };
            certificate.AddCertificateChain(chain);
        }
        
        return certificate;
    }

    private Finished CreateFinished()
    {
        var baseKey = _isClient ? 
            _keySchedule.ClientHandshakeTrafficSecret : 
            _keySchedule.ServerHandshakeTrafficSecret;
            
        return new Finished
        {
            VerifyData = _keySchedule.ComputeFinishedVerifyData(baseKey)
        };
    }

    private void ProcessClientHello(ClientHello clientHello)
    {
        // Select cipher suite
        foreach (var suite in clientHello.CipherSuites)
        {
            if (SupportedCipherSuites.Contains(suite))
            {
                _selectedCipherSuite = suite;
                break;
            }
        }
        
        // Process extensions
        if (clientHello.Extensions.TryGetValue(TlsExtensionType.QuicTransportParameters, out var tpBytes))
        {
            _peerTransportParams = TransportParametersCodec.Decode(tpBytes, false);
        }
        
        // Setup key exchange
        if (clientHello.Extensions.TryGetValue(TlsExtensionType.KeyShare, out var keyShareData))
        {
            // Parse key share and setup matching key exchange
            _keyExchange = new X25519KeyExchange();
        }
    }

    private void ProcessServerHello(ServerHello serverHello)
    {
        _selectedCipherSuite = serverHello.CipherSuite;
        _keySchedule = new TlsKeySchedule(_selectedCipherSuite);
    }

    private void SetHandshakeSecrets()
    {
        _writeSecrets[EncryptionLevel.Handshake] = _isClient ? 
            _keySchedule.ClientHandshakeTrafficSecret :
            _keySchedule.ServerHandshakeTrafficSecret;
            
        _readSecrets[EncryptionLevel.Handshake] = _isClient ?
            _keySchedule.ServerHandshakeTrafficSecret :
            _keySchedule.ClientHandshakeTrafficSecret;
    }

    private void SetApplicationSecrets()
    {
        _writeSecrets[EncryptionLevel.OneRtt] = _isClient ?
            _keySchedule.ClientApplicationTrafficSecret :
            _keySchedule.ServerApplicationTrafficSecret;
            
        _readSecrets[EncryptionLevel.OneRtt] = _isClient ?
            _keySchedule.ServerApplicationTrafficSecret :
            _keySchedule.ClientApplicationTrafficSecret;
    }

    private void DeriveInitialSecrets()
    {
        // RFC 9001: Initial secret derivation
        var initialSecret = Hkdf.Extract(HashAlgorithmName.SHA256, _connectionId, InitialSaltV1);
        
        // Derive client and server initial secrets
        var clientInitialSecret = Hkdf.ExpandLabel(HashAlgorithmName.SHA256, initialSecret, "tls13 client in", Array.Empty<byte>(), 32);
        var serverInitialSecret = Hkdf.ExpandLabel(HashAlgorithmName.SHA256, initialSecret, "tls13 server in", Array.Empty<byte>(), 32);
        
        if (_isClient)
        {
            _writeSecrets[EncryptionLevel.Initial] = clientInitialSecret;
            _readSecrets[EncryptionLevel.Initial] = serverInitialSecret;
        }
        else
        {
            _writeSecrets[EncryptionLevel.Initial] = serverInitialSecret;
            _readSecrets[EncryptionLevel.Initial] = clientInitialSecret;
        }
        
        // Initialize early data secret derivation
        _keySchedule.DeriveEarlySecrets();
    }

    public void UpdateKeys()
    {
        // RFC 9001: Key update mechanism
        var hashAlgorithm = GetHashAlgorithm(_selectedCipherSuite);
        
        if (_readSecrets.TryGetValue(EncryptionLevel.OneRtt, out var readSecret))
        {
            _readSecrets[EncryptionLevel.OneRtt] = TlsKeySchedule.DeriveKeyUpdateSecret(hashAlgorithm, readSecret);
        }
        
        if (_writeSecrets.TryGetValue(EncryptionLevel.OneRtt, out var writeSecret))
        {
            _writeSecrets[EncryptionLevel.OneRtt] = TlsKeySchedule.DeriveKeyUpdateSecret(hashAlgorithm, writeSecret);
        }
    }

    public ReadOnlySpan<byte> GetWriteSecret(EncryptionLevel level)
    {
        return _writeSecrets.TryGetValue(level, out var secret) ? secret : ReadOnlySpan<byte>.Empty;
    }

    public ReadOnlySpan<byte> GetReadSecret(EncryptionLevel level)
    {
        return _readSecrets.TryGetValue(level, out var secret) ? secret : ReadOnlySpan<byte>.Empty;
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

    private static byte[] SerializeMessage(ITlsMessage message)
    {
        var buffer = new byte[65536];
        var writer = new TlsWriter(buffer);
        
        // TLS handshake message format
        writer.WriteUInt8((byte)message.Type);
        writer.WriteLengthPrefixed24((ref TlsWriter w) => message.Encode(ref w));
        
        return writer.Written.ToArray();
    }

    // Mock methods for testing - these would be replaced with actual message processing
    private ClientHello CreateMockClientHello() => new ClientHello();
    private ServerHello CreateMockServerHello() => new ServerHello { CipherSuite = _selectedCipherSuite };
    private EncryptedExtensions CreateMockEncryptedExtensions() => new EncryptedExtensions();
    private Certificate CreateMockCertificate() => new Certificate();
    private Finished CreateMockFinished(bool isServer) => new Finished { VerifyData = new byte[32] };
}