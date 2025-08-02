namespace Qeen.CongestionControl.Pacing;

/// <summary>
/// Default implementation of packet pacing.
/// </summary>
public class DefaultPacer : IPacer
{
    private readonly object _lock = new();
    private double _pacingRate; // bytes per second
    private DateTime _lastSendTime;
    private double _pacingGain;
    private int _burstAllowance;
    private int _maxBurstPackets;
    
    // Pacing constants
    private const double kDefaultPacingGain = 1.25; // 25% headroom
    private const double kSlowStartPacingGain = 2.0; // Double rate in slow start
    private const int kDefaultMaxBurstPackets = 10;
    private const double kMinPacingRate = 1000.0; // 1 KB/s minimum
    
    /// <summary>
    /// Initializes a new instance of the DefaultPacer class.
    /// </summary>
    public DefaultPacer()
    {
        _pacingRate = kMinPacingRate;
        _lastSendTime = DateTime.UtcNow;
        _pacingGain = kDefaultPacingGain;
        _burstAllowance = kDefaultMaxBurstPackets;
        _maxBurstPackets = kDefaultMaxBurstPackets;
    }
    
    /// <inheritdoc/>
    public TimeSpan GetNextSendTime(int packetSize)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            
            // Allow burst at start or after idle
            if (_burstAllowance > 0)
            {
                return TimeSpan.Zero;
            }
            
            // Calculate time needed to send this packet at current rate
            var sendDuration = TimeSpan.FromSeconds(packetSize / _pacingRate);
            
            // Calculate when we can send next
            var nextSendTime = _lastSendTime + sendDuration;
            
            if (nextSendTime > now)
            {
                return nextSendTime - now;
            }
            
            return TimeSpan.Zero;
        }
    }
    
    /// <inheritdoc/>
    public void UpdateSendingRate(int congestionWindow, TimeSpan smoothedRtt)
    {
        lock (_lock)
        {
            if (smoothedRtt.TotalMilliseconds <= 0)
                return;
            
            // Calculate pacing rate: cwnd / RTT * gain
            var baseRate = congestionWindow / smoothedRtt.TotalSeconds;
            _pacingRate = Math.Max(baseRate * _pacingGain, kMinPacingRate);
            
            // Reset burst allowance when rate changes significantly
            _burstAllowance = _maxBurstPackets;
        }
    }
    
    /// <inheritdoc/>
    public void OnPacketSent(int packetSize)
    {
        lock (_lock)
        {
            _lastSendTime = DateTime.UtcNow;
            
            // Decrease burst allowance
            if (_burstAllowance > 0)
            {
                _burstAllowance--;
            }
        }
    }
    
    /// <inheritdoc/>
    public bool ShouldSendNow()
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            
            // Allow burst
            if (_burstAllowance > 0)
            {
                return true;
            }
            
            // Check if enough time has passed
            var timeSinceLastSend = now - _lastSendTime;
            var minInterval = TimeSpan.FromSeconds(1.0 / (_pacingRate / 1200)); // Assume 1200 byte packets
            
            return timeSinceLastSend >= minInterval;
        }
    }
    
    /// <inheritdoc/>
    public double GetPacingRate()
    {
        lock (_lock)
        {
            return _pacingRate;
        }
    }
    
    /// <inheritdoc/>
    public void SetPacingGain(double gain)
    {
        lock (_lock)
        {
            _pacingGain = Math.Max(gain, 1.0);
        }
    }
    
    /// <summary>
    /// Resets the burst allowance after idle period.
    /// </summary>
    public void ResetBurstAllowance()
    {
        lock (_lock)
        {
            _burstAllowance = _maxBurstPackets;
        }
    }
    
    /// <summary>
    /// Sets the maximum burst size.
    /// </summary>
    /// <param name="maxBurstPackets">The maximum number of packets in a burst.</param>
    public void SetMaxBurstSize(int maxBurstPackets)
    {
        lock (_lock)
        {
            _maxBurstPackets = Math.Max(maxBurstPackets, 1);
            _burstAllowance = Math.Min(_burstAllowance, _maxBurstPackets);
        }
    }
}