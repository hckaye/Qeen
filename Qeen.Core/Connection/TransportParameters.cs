using System.Runtime.CompilerServices;

namespace Qeen.Core.Connection;

/// <summary>
/// QUIC Transport Parameters as defined in RFC 9000
/// </summary>
public struct TransportParameters
{
    /// <summary>
    /// Maximum idle timeout in milliseconds
    /// </summary>
    public ulong MaxIdleTimeout { get; set; }

    /// <summary>
    /// Maximum UDP payload size
    /// </summary>
    public ulong MaxUdpPayloadSize { get; set; }

    /// <summary>
    /// Initial maximum data for the connection
    /// </summary>
    public ulong InitialMaxData { get; set; }

    /// <summary>
    /// Initial maximum data for locally-initiated bidirectional streams
    /// </summary>
    public ulong InitialMaxStreamDataBidiLocal { get; set; }

    /// <summary>
    /// Initial maximum data for remotely-initiated bidirectional streams
    /// </summary>
    public ulong InitialMaxStreamDataBidiRemote { get; set; }

    /// <summary>
    /// Initial maximum data for unidirectional streams
    /// </summary>
    public ulong InitialMaxStreamDataUni { get; set; }

    /// <summary>
    /// Initial maximum number of bidirectional streams
    /// </summary>
    public ulong InitialMaxStreamsBidi { get; set; }

    /// <summary>
    /// Initial maximum number of unidirectional streams
    /// </summary>
    public ulong InitialMaxStreamsUni { get; set; }

    /// <summary>
    /// ACK delay exponent
    /// </summary>
    public ulong AckDelayExponent { get; set; }

    /// <summary>
    /// Maximum ACK delay in milliseconds
    /// </summary>
    public ulong MaxAckDelay { get; set; }

    /// <summary>
    /// Disable active connection migration
    /// </summary>
    public bool DisableActiveMigration { get; set; }

    /// <summary>
    /// Preferred address (optional)
    /// </summary>
    public PreferredAddress? PreferredAddress { get; set; }

    /// <summary>
    /// Active connection ID limit
    /// </summary>
    public ulong ActiveConnectionIdLimit { get; set; }

    /// <summary>
    /// Initial source connection ID
    /// </summary>
    public ConnectionId? InitialSourceConnectionId { get; set; }

    /// <summary>
    /// Retry source connection ID (only in Retry packets)
    /// </summary>
    public ConnectionId? RetrySourceConnectionId { get; set; }

    /// <summary>
    /// Maximum datagram frame size (0 = not supported)
    /// </summary>
    public ulong MaxDatagramFrameSize { get; set; }

    /// <summary>
    /// Gets default transport parameters
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static TransportParameters GetDefault()
    {
        return new TransportParameters
        {
            MaxIdleTimeout = 30000, // 30 seconds
            MaxUdpPayloadSize = 1200, // Conservative default
            InitialMaxData = 1048576, // 1MB
            InitialMaxStreamDataBidiLocal = 524288, // 512KB
            InitialMaxStreamDataBidiRemote = 524288, // 512KB
            InitialMaxStreamDataUni = 524288, // 512KB
            InitialMaxStreamsBidi = 100,
            InitialMaxStreamsUni = 100,
            AckDelayExponent = 3,
            MaxAckDelay = 25, // 25ms
            DisableActiveMigration = false,
            ActiveConnectionIdLimit = 2,
            MaxDatagramFrameSize = 0 // Disabled by default
        };
    }
}

/// <summary>
/// Represents a preferred address for connection migration
/// </summary>
public struct PreferredAddress
{
    /// <summary>
    /// IPv4 address (optional)
    /// </summary>
    public System.Net.IPEndPoint? IPv4Address { get; set; }

    /// <summary>
    /// IPv6 address (optional)
    /// </summary>
    public System.Net.IPEndPoint? IPv6Address { get; set; }

    /// <summary>
    /// Connection ID to use with the preferred address
    /// </summary>
    public ConnectionId ConnectionId { get; set; }

    /// <summary>
    /// Stateless reset token
    /// </summary>
    public ReadOnlyMemory<byte> StatelessResetToken { get; set; }
}