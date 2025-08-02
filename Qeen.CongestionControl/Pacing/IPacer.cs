namespace Qeen.CongestionControl.Pacing;

/// <summary>
/// Interface for packet pacing to smooth out transmission bursts.
/// </summary>
public interface IPacer
{
    /// <summary>
    /// Gets the next time when a packet can be sent.
    /// </summary>
    /// <param name="packetSize">The size of the packet to send.</param>
    /// <returns>The time to wait before sending.</returns>
    TimeSpan GetNextSendTime(int packetSize);
    
    /// <summary>
    /// Updates the sending rate based on congestion window and RTT.
    /// </summary>
    /// <param name="congestionWindow">The current congestion window in bytes.</param>
    /// <param name="smoothedRtt">The smoothed RTT.</param>
    void UpdateSendingRate(int congestionWindow, TimeSpan smoothedRtt);
    
    /// <summary>
    /// Records that a packet was sent.
    /// </summary>
    /// <param name="packetSize">The size of the sent packet.</param>
    void OnPacketSent(int packetSize);
    
    /// <summary>
    /// Checks if a packet can be sent now.
    /// </summary>
    /// <returns>True if a packet can be sent immediately.</returns>
    bool ShouldSendNow();
    
    /// <summary>
    /// Gets the current pacing rate in bytes per second.
    /// </summary>
    /// <returns>The pacing rate.</returns>
    double GetPacingRate();
    
    /// <summary>
    /// Sets the pacing gain for slow start or recovery.
    /// </summary>
    /// <param name="gain">The pacing gain multiplier.</param>
    void SetPacingGain(double gain);
}