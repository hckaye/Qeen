using Qeen.CongestionControl.Loss;

namespace Qeen.CongestionControl;

/// <summary>
/// Interface for congestion control algorithms.
/// </summary>
public interface ICongestionController
{
    /// <summary>
    /// Records that a packet was sent.
    /// </summary>
    /// <param name="packetNumber">The packet number.</param>
    /// <param name="packetSize">The size of the packet in bytes.</param>
    void OnPacketSent(ulong packetNumber, int packetSize);
    
    /// <summary>
    /// Processes an acknowledged packet.
    /// </summary>
    /// <param name="packet">The acknowledged packet.</param>
    void OnPacketAcked(SentPacket packet);
    
    /// <summary>
    /// Processes a lost packet.
    /// </summary>
    /// <param name="packet">The lost packet.</param>
    void OnPacketLost(SentPacket packet);
    
    /// <summary>
    /// Handles a retransmission timeout.
    /// </summary>
    void OnRetransmissionTimeout();
    
    /// <summary>
    /// Gets the current congestion window size in bytes.
    /// </summary>
    /// <returns>The congestion window size.</returns>
    int GetCongestionWindow();
    
    /// <summary>
    /// Gets the current bytes in flight.
    /// </summary>
    /// <returns>The bytes in flight.</returns>
    int GetBytesInFlight();
    
    /// <summary>
    /// Checks if a packet of the given size can be sent.
    /// </summary>
    /// <param name="packetSize">The size of the packet to send.</param>
    /// <returns>True if the packet can be sent.</returns>
    bool CanSend(int packetSize);
    
    /// <summary>
    /// Gets the current congestion control state.
    /// </summary>
    /// <returns>The congestion state.</returns>
    CongestionState GetState();
    
    /// <summary>
    /// Gets the slow start threshold.
    /// </summary>
    /// <returns>The slow start threshold in bytes.</returns>
    int GetSlowStartThreshold();
    
    /// <summary>
    /// Updates the maximum datagram size.
    /// </summary>
    /// <param name="maxDatagramSize">The maximum datagram size.</param>
    void SetMaxDatagramSize(int maxDatagramSize);
}