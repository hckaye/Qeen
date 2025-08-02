using Qeen.Core.Connection;
using Qeen.Core.Frame;
using Qeen.Core.Packet;

namespace Qeen.Core.Handshake;

/// <summary>
/// Interface for managing QUIC handshake.
/// </summary>
public interface IHandshakeManager
{
    /// <summary>
    /// Gets the handshake state.
    /// </summary>
    HandshakeState State { get; }
    
    /// <summary>
    /// Starts the client handshake.
    /// </summary>
    /// <param name="serverName">The server name for SNI.</param>
    /// <param name="applicationProtocols">The application protocols for ALPN.</param>
    /// <returns>The Initial packet to send.</returns>
    InitialPacket StartClientHandshake(string serverName, List<string>? applicationProtocols = null);
    
    /// <summary>
    /// Processes a received Initial packet on the server.
    /// </summary>
    /// <param name="packet">The received Initial packet.</param>
    /// <returns>The response Initial packet, or null if no response is needed.</returns>
    InitialPacket? ProcessServerInitial(InitialPacket packet);
    
    /// <summary>
    /// Processes a received Initial packet on the client.
    /// </summary>
    /// <param name="packet">The received Initial packet.</param>
    /// <returns>The Handshake packet to send, or null if handshake is complete.</returns>
    HandshakePacket? ProcessClientInitial(InitialPacket packet);
    
    /// <summary>
    /// Processes a received Handshake packet.
    /// </summary>
    /// <param name="packet">The received Handshake packet.</param>
    /// <returns>True if the handshake is complete.</returns>
    bool ProcessHandshakePacket(HandshakePacket packet);
    
    /// <summary>
    /// Gets the negotiated application protocol.
    /// </summary>
    string? NegotiatedProtocol { get; }
    
    /// <summary>
    /// Gets whether the handshake is complete.
    /// </summary>
    bool IsComplete { get; }
}

/// <summary>
/// Represents the state of the handshake.
/// </summary>
public enum HandshakeState
{
    /// <summary>
    /// Not started.
    /// </summary>
    Idle,
    
    /// <summary>
    /// Initial sent/received.
    /// </summary>
    Initial,
    
    /// <summary>
    /// Handshake in progress.
    /// </summary>
    Handshake,
    
    /// <summary>
    /// Handshake confirmed.
    /// </summary>
    Confirmed,
    
    /// <summary>
    /// Handshake complete.
    /// </summary>
    Complete,
    
    /// <summary>
    /// Handshake failed.
    /// </summary>
    Failed
}