using System.Security.Cryptography.X509Certificates;
using Qeen.Core.Connection;

namespace Qeen.Server;

/// <summary>
/// Configuration for a QUIC server.
/// </summary>
public class QuicServerConfiguration
{
    /// <summary>
    /// Gets or sets the supported QUIC versions.
    /// </summary>
    public List<QuicVersion> SupportedVersions { get; set; } = new() { QuicVersion.Version1 };
    
    /// <summary>
    /// Gets or sets the transport parameters.
    /// </summary>
    public TransportParameters TransportParameters { get; set; } = new();
    
    /// <summary>
    /// Gets or sets the idle timeout.
    /// </summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromSeconds(30);
    
    /// <summary>
    /// Gets or sets the application protocols (ALPN).
    /// </summary>
    public List<string> ApplicationProtocols { get; set; } = new();
    
    /// <summary>
    /// Gets or sets the server certificate.
    /// </summary>
    public X509Certificate2? ServerCertificate { get; set; }
    
    /// <summary>
    /// Gets or sets whether to require client certificate.
    /// </summary>
    public bool RequireClientCertificate { get; set; } = false;
    
    /// <summary>
    /// Gets or sets the maximum number of concurrent connections.
    /// </summary>
    public int MaxConnections { get; set; } = 1000;
    
    /// <summary>
    /// Gets or sets whether to enable 0-RTT.
    /// </summary>
    public bool Enable0Rtt { get; set; } = false;
    
    /// <summary>
    /// Gets or sets the stateless reset token.
    /// </summary>
    public byte[]? StatelessResetToken { get; set; }
    
    /// <summary>
    /// Gets or sets the initial maximum data for the connection.
    /// </summary>
    public ulong InitialMaxData { get; set; } = 10_000_000; // 10 MB
    
    /// <summary>
    /// Gets or sets the initial maximum stream data for bidirectional streams.
    /// </summary>
    public ulong InitialMaxStreamDataBidiLocal { get; set; } = 1_000_000; // 1 MB
    
    /// <summary>
    /// Gets or sets the initial maximum stream data for bidirectional streams.
    /// </summary>
    public ulong InitialMaxStreamDataBidiRemote { get; set; } = 1_000_000; // 1 MB
    
    /// <summary>
    /// Gets or sets the initial maximum stream data for unidirectional streams.
    /// </summary>
    public ulong InitialMaxStreamDataUni { get; set; } = 1_000_000; // 1 MB
    
    /// <summary>
    /// Gets or sets the initial maximum number of bidirectional streams.
    /// </summary>
    public ulong InitialMaxStreamsBidi { get; set; } = 100;
    
    /// <summary>
    /// Gets or sets the initial maximum number of unidirectional streams.
    /// </summary>
    public ulong InitialMaxStreamsUni { get; set; } = 100;
    
    /// <summary>
    /// Gets or sets the address verification token validity duration.
    /// </summary>
    public TimeSpan AddressTokenValidityDuration { get; set; } = TimeSpan.FromMinutes(5);
    
    /// <summary>
    /// Gets or sets whether to perform address validation.
    /// </summary>
    public bool RequireAddressValidation { get; set; } = true;
}

/// <summary>
/// Represents a QUIC protocol version.
/// </summary>
public enum QuicVersion : uint
{
    /// <summary>
    /// QUIC version 1 (RFC 9000).
    /// </summary>
    Version1 = 0x00000001,
    
    /// <summary>
    /// QUIC version 2.
    /// </summary>
    Version2 = 0x6b3343cf,
    
    /// <summary>
    /// Version negotiation.
    /// </summary>
    VersionNegotiation = 0x00000000,
}