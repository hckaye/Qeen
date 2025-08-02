using Qeen.Core.Frame.Frames;

namespace Qeen.CongestionControl.Loss;

/// <summary>
/// Interface for QUIC loss detection (RFC 9002).
/// </summary>
public interface ILossDetector
{
    /// <summary>
    /// Records that a packet was sent.
    /// </summary>
    /// <param name="packet">The sent packet information.</param>
    void OnPacketSent(SentPacket packet);
    
    /// <summary>
    /// Processes an acknowledgment frame.
    /// </summary>
    /// <param name="ackFrame">The ACK frame received.</param>
    /// <param name="ackDelay">The acknowledgment delay.</param>
    void OnAckReceived(AckFrame ackFrame, TimeSpan ackDelay);
    
    /// <summary>
    /// Detects packets that should be considered lost.
    /// </summary>
    /// <returns>The packets detected as lost.</returns>
    IEnumerable<SentPacket> DetectLostPackets();
    
    /// <summary>
    /// Gets the Probe Timeout (PTO) duration.
    /// </summary>
    /// <returns>The PTO duration.</returns>
    TimeSpan GetProbeTimeout();
    
    /// <summary>
    /// Handles a retransmission timeout event.
    /// </summary>
    void OnRetransmissionTimeout();
    
    /// <summary>
    /// Gets the current loss detection statistics.
    /// </summary>
    /// <returns>The current statistics.</returns>
    LossDetectionStats GetStats();
    
    /// <summary>
    /// Gets the current RTT measurement.
    /// </summary>
    /// <returns>The RTT measurement.</returns>
    RttMeasurement GetRttMeasurement();
    
    /// <summary>
    /// Checks if a probe packet should be sent.
    /// </summary>
    /// <returns>True if a probe should be sent.</returns>
    bool ShouldSendProbe();
}