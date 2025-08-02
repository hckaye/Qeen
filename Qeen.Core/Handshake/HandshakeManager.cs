using System.Security.Cryptography;
using Qeen.Core.Connection;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;

namespace Qeen.Core.Handshake;

/// <summary>
/// Manages the QUIC handshake process.
/// </summary>
public class HandshakeManager : IHandshakeManager
{
    private readonly bool _isClient;
    private readonly ConnectionId _localConnectionId;
    private readonly ConnectionId _remoteConnectionId;
    private readonly TransportParameters _localTransportParameters;
    private HandshakeState _state;
    private string? _negotiatedProtocol;
    private ulong _nextPacketNumber;
    
    /// <summary>
    /// Initializes a new instance of the HandshakeManager class.
    /// </summary>
    public HandshakeManager(
        bool isClient,
        ConnectionId localConnectionId,
        TransportParameters localTransportParameters)
    {
        _isClient = isClient;
        _localConnectionId = localConnectionId;
        _remoteConnectionId = ConnectionId.Empty;
        _localTransportParameters = localTransportParameters;
        _state = HandshakeState.Idle;
        _nextPacketNumber = 0;
    }
    
    /// <inheritdoc/>
    public HandshakeState State => _state;
    
    /// <inheritdoc/>
    public string? NegotiatedProtocol => _negotiatedProtocol;
    
    /// <inheritdoc/>
    public bool IsComplete => _state == HandshakeState.Complete;
    
    /// <inheritdoc/>
    public InitialPacket StartClientHandshake(string serverName, List<string>? applicationProtocols = null)
    {
        if (!_isClient)
            throw new InvalidOperationException("This is not a client connection");
            
        if (_state != HandshakeState.Idle)
            throw new InvalidOperationException("Handshake already started");
            
        _state = HandshakeState.Initial;
        
        // Create Initial packet with CRYPTO frame containing ClientHello
        var packet = new InitialPacket
        {
            DestinationConnectionId = ConnectionId.Generate(), // Server's connection ID (random for now)
            SourceConnectionId = _localConnectionId,
            PacketNumber = _nextPacketNumber++,
            Version = 0x00000001 // QUIC v1
        };
        
        // Create ClientHello data (simplified)
        var clientHello = CreateClientHello(serverName, applicationProtocols);
        
        // Add CRYPTO frame with ClientHello
        packet.Frames.Add(new CryptoFrame(0, clientHello));
        
        // Add PADDING frame to meet minimum Initial packet size (1200 bytes)
        var paddingSize = 1200 - 100; // Approximate header size
        if (paddingSize > 0)
        {
            packet.Frames.Add(new PaddingFrame(paddingSize));
        }
        
        return packet;
    }
    
    /// <inheritdoc/>
    public InitialPacket? ProcessServerInitial(InitialPacket packet)
    {
        if (_isClient)
            throw new InvalidOperationException("This is not a server connection");
            
        if (_state != HandshakeState.Idle)
            return null;
            
        _state = HandshakeState.Initial;
        
        // Process ClientHello from CRYPTO frame
        var hasCryptoFrame = false;
        CryptoFrame cryptoFrame = default;
        foreach (var frame in packet.Frames)
        {
            if (frame is CryptoFrame cf)
            {
                cryptoFrame = cf;
                hasCryptoFrame = true;
                break;
            }
        }
        
        if (!hasCryptoFrame)
            return null;
            
        // Create response Initial packet with ServerHello
        var response = new InitialPacket
        {
            DestinationConnectionId = packet.SourceConnectionId,
            SourceConnectionId = _localConnectionId,
            PacketNumber = _nextPacketNumber++,
            Version = 0x00000001 // QUIC v1
        };
        
        // Create ServerHello data (simplified)
        var serverHello = CreateServerHello();
        
        // Add CRYPTO frame with ServerHello
        response.Frames.Add(new CryptoFrame(0, serverHello));
        
        // Add ACK frame
        response.Frames.Add(new AckFrame(packet.PacketNumber, 0, new List<AckRange>()));
        
        _state = HandshakeState.Handshake;
        
        return response;
    }
    
    /// <inheritdoc/>
    public HandshakePacket? ProcessClientInitial(InitialPacket packet)
    {
        if (!_isClient)
            throw new InvalidOperationException("This is not a client connection");
            
        if (_state != HandshakeState.Initial)
            return null;
            
        // Process ServerHello from CRYPTO frame
        var hasCryptoFrame = false;
        CryptoFrame cryptoFrame = default;
        foreach (var frame in packet.Frames)
        {
            if (frame is CryptoFrame cf)
            {
                cryptoFrame = cf;
                hasCryptoFrame = true;
                break;
            }
        }
        
        if (!hasCryptoFrame)
            return null;
            
        _state = HandshakeState.Handshake;
        
        // Create Handshake packet with client Finished
        var handshakePacket = new HandshakePacket
        {
            DestinationConnectionId = packet.SourceConnectionId,
            SourceConnectionId = _localConnectionId,
            PacketNumber = _nextPacketNumber++,
            Version = 0x00000001
        };
        
        // Add CRYPTO frame with Finished message
        var finished = CreateClientFinished();
        handshakePacket.Frames.Add(new CryptoFrame(0, finished));
        
        // Add ACK frame
        handshakePacket.Frames.Add(new AckFrame(packet.PacketNumber, 0, new List<AckRange>()));
        
        return handshakePacket;
    }
    
    /// <inheritdoc/>
    public bool ProcessHandshakePacket(HandshakePacket packet)
    {
        if (_state != HandshakeState.Handshake)
            return false;
            
        // Process Finished message
        foreach (var frame in packet.Frames)
        {
            if (frame is CryptoFrame)
            {
                // Verify Finished message (simplified)
                _state = HandshakeState.Complete;
                return true;
            }
        }
        
        return false;
    }
    
    /// <summary>
    /// Creates a ClientHello message (simplified).
    /// </summary>
    private byte[] CreateClientHello(string serverName, List<string>? applicationProtocols)
    {
        // This is a simplified ClientHello
        // In a real implementation, this would use TLS 1.3 message format
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        
        // TLS version (TLS 1.3)
        writer.Write((ushort)0x0304);
        
        // Random (32 bytes)
        var random = new byte[32];
        RandomNumberGenerator.Fill(random);
        writer.Write(random);
        
        // Session ID (empty)
        writer.Write((byte)0);
        
        // Cipher suites (TLS_AES_128_GCM_SHA256)
        writer.Write((ushort)2);
        writer.Write((ushort)0x1301);
        
        // Compression methods (none)
        writer.Write((byte)1);
        writer.Write((byte)0);
        
        // Extensions would go here (SNI, ALPN, etc.)
        // Simplified for now
        
        return ms.ToArray();
    }
    
    /// <summary>
    /// Creates a ServerHello message (simplified).
    /// </summary>
    private byte[] CreateServerHello()
    {
        // This is a simplified ServerHello
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);
        
        // TLS version (TLS 1.3)
        writer.Write((ushort)0x0304);
        
        // Random (32 bytes)
        var random = new byte[32];
        RandomNumberGenerator.Fill(random);
        writer.Write(random);
        
        // Session ID (empty)
        writer.Write((byte)0);
        
        // Cipher suite (TLS_AES_128_GCM_SHA256)
        writer.Write((ushort)0x1301);
        
        // Compression method (none)
        writer.Write((byte)0);
        
        // Extensions would go here
        
        return ms.ToArray();
    }
    
    /// <summary>
    /// Creates a client Finished message (simplified).
    /// </summary>
    private byte[] CreateClientFinished()
    {
        // This is a simplified Finished message
        // In a real implementation, this would contain a verify_data field
        var finished = new byte[32];
        RandomNumberGenerator.Fill(finished);
        return finished;
    }
}