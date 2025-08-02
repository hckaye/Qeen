namespace Qeen.CongestionControl.Loss;

/// <summary>
/// Statistics for loss detection.
/// </summary>
public readonly struct LossDetectionStats
{
    /// <summary>
    /// The total number of packets sent.
    /// </summary>
    public ulong PacketsSent { get; init; }
    
    /// <summary>
    /// The total number of packets acknowledged.
    /// </summary>
    public ulong PacketsAcked { get; init; }
    
    /// <summary>
    /// The total number of packets detected as lost.
    /// </summary>
    public ulong PacketsLost { get; init; }
    
    /// <summary>
    /// The total number of bytes sent.
    /// </summary>
    public ulong BytesSent { get; init; }
    
    /// <summary>
    /// The total number of bytes acknowledged.
    /// </summary>
    public ulong BytesAcked { get; init; }
    
    /// <summary>
    /// The total number of bytes lost.
    /// </summary>
    public ulong BytesLost { get; init; }
    
    /// <summary>
    /// The number of PTO (Probe Timeout) events.
    /// </summary>
    public uint PtoCount { get; init; }
    
    /// <summary>
    /// The current RTT measurement.
    /// </summary>
    public RttMeasurement RttMeasurement { get; init; }
}