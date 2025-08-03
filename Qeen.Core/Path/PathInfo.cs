using System.Net;

namespace Qeen.Core.Path;

/// <summary>
/// Information about a network path between client and server
/// </summary>
public class PathInfo
{
    /// <summary>
    /// Local endpoint
    /// </summary>
    public IPEndPoint LocalEndPoint { get; set; }
    
    /// <summary>
    /// Remote endpoint
    /// </summary>
    public IPEndPoint RemoteEndPoint { get; set; }
    
    /// <summary>
    /// Current state of the path
    /// </summary>
    public PathState State { get; set; }
    
    /// <summary>
    /// Connection ID associated with this path
    /// </summary>
    public byte[] ConnectionId { get; set; }
    
    /// <summary>
    /// Maximum Transmission Unit for this path
    /// </summary>
    public int Mtu { get; set; }
    
    /// <summary>
    /// Round-trip time for this path
    /// </summary>
    public TimeSpan Rtt { get; set; }
    
    /// <summary>
    /// Number of bytes sent on this path
    /// </summary>
    public ulong BytesSent { get; set; }
    
    /// <summary>
    /// Number of bytes received on this path
    /// </summary>
    public ulong BytesReceived { get; set; }
    
    /// <summary>
    /// Time when the path was last validated
    /// </summary>
    public DateTime LastValidated { get; set; }
    
    /// <summary>
    /// Time when the path was last used
    /// </summary>
    public DateTime LastUsed { get; set; }
    
    /// <summary>
    /// Number of validation attempts
    /// </summary>
    public int ValidationAttempts { get; set; }
    
    /// <summary>
    /// Challenge data for path validation
    /// </summary>
    public byte[]? ValidationChallenge { get; set; }
    
    /// <summary>
    /// Whether this is the primary path
    /// </summary>
    public bool IsPrimary { get; set; }
    
    public PathInfo(IPEndPoint local, IPEndPoint remote)
    {
        LocalEndPoint = local ?? throw new ArgumentNullException(nameof(local));
        RemoteEndPoint = remote ?? throw new ArgumentNullException(nameof(remote));
        State = PathState.Unknown;
        ConnectionId = Array.Empty<byte>();
        Mtu = 1200; // Default QUIC MTU
        Rtt = TimeSpan.Zero;
        LastUsed = DateTime.UtcNow;
    }
    
    /// <summary>
    /// Creates a unique identifier for this path
    /// </summary>
    public string GetPathId()
    {
        return $"{LocalEndPoint}:{RemoteEndPoint}";
    }
    
    /// <summary>
    /// Checks if the path needs revalidation
    /// </summary>
    public bool NeedsRevalidation(TimeSpan validationTimeout)
    {
        if (State != PathState.Validated)
            return true;
            
        return DateTime.UtcNow - LastValidated > validationTimeout;
    }
}