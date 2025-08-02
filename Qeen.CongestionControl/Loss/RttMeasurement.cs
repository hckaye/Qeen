namespace Qeen.CongestionControl.Loss;

/// <summary>
/// Represents RTT (Round-Trip Time) measurements for a connection.
/// </summary>
public struct RttMeasurement
{
    /// <summary>
    /// The most recent RTT measurement.
    /// </summary>
    public TimeSpan LatestRtt { get; set; }
    
    /// <summary>
    /// The exponentially-weighted moving average RTT.
    /// </summary>
    public TimeSpan SmoothedRtt { get; set; }
    
    /// <summary>
    /// The variance in the RTT measurements.
    /// </summary>
    public TimeSpan RttVariance { get; set; }
    
    /// <summary>
    /// The minimum RTT observed.
    /// </summary>
    public TimeSpan MinRtt { get; set; }
    
    /// <summary>
    /// The maximum acknowledgment delay reported by the peer.
    /// </summary>
    public TimeSpan MaxAckDelay { get; set; }
    
    /// <summary>
    /// The number of RTT samples collected.
    /// </summary>
    public int SampleCount { get; set; }
    
    /// <summary>
    /// Creates a new RttMeasurement with default values.
    /// </summary>
    public static RttMeasurement Default()
    {
        return new RttMeasurement
        {
            LatestRtt = TimeSpan.Zero,
            SmoothedRtt = TimeSpan.FromMilliseconds(333), // RFC 9002 initial RTT
            RttVariance = TimeSpan.FromMilliseconds(166.5), // SmoothedRtt / 2
            MinRtt = TimeSpan.MaxValue,
            MaxAckDelay = TimeSpan.FromMilliseconds(25), // Default max_ack_delay
            SampleCount = 0
        };
    }
    
    /// <summary>
    /// Updates the RTT measurements with a new sample.
    /// </summary>
    /// <param name="rttSample">The new RTT sample.</param>
    /// <param name="ackDelay">The acknowledgment delay.</param>
    public void UpdateRtt(TimeSpan rttSample, TimeSpan ackDelay)
    {
        LatestRtt = rttSample;
        
        if (rttSample < MinRtt)
            MinRtt = rttSample;
        
        // Adjust for ACK delay if appropriate
        var adjustedRtt = rttSample;
        if (rttSample > MinRtt + ackDelay)
            adjustedRtt = rttSample - ackDelay;
        
        if (SampleCount == 0)
        {
            // First RTT sample
            SmoothedRtt = adjustedRtt;
            RttVariance = TimeSpan.FromTicks(adjustedRtt.Ticks / 2);
        }
        else
        {
            // Update smoothed RTT and variance (RFC 9002 formulas)
            var rttDiff = adjustedRtt > SmoothedRtt 
                ? adjustedRtt - SmoothedRtt 
                : SmoothedRtt - adjustedRtt;
            
            RttVariance = TimeSpan.FromTicks((3 * RttVariance.Ticks + rttDiff.Ticks) / 4);
            SmoothedRtt = TimeSpan.FromTicks((7 * SmoothedRtt.Ticks + adjustedRtt.Ticks) / 8);
        }
        
        SampleCount++;
    }
    
    /// <summary>
    /// Gets the Probe Timeout (PTO) duration.
    /// </summary>
    public TimeSpan GetProbeTimeout()
    {
        // PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
        var kGranularity = TimeSpan.FromMilliseconds(1);
        var fourTimesVariance = TimeSpan.FromTicks(4 * RttVariance.Ticks);
        var varianceComponent = fourTimesVariance > kGranularity ? fourTimesVariance : kGranularity;
        
        return SmoothedRtt + varianceComponent + MaxAckDelay;
    }
}