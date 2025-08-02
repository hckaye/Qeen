using Qeen.CongestionControl.Loss;

namespace Qeen.CongestionControl;

/// <summary>
/// Implements the NewReno congestion control algorithm for QUIC.
/// </summary>
public class NewRenoCongestionController : ICongestionController
{
    private readonly object _lock = new();
    private int _congestionWindow;
    private int _bytesInFlight;
    private int _slowStartThreshold;
    private CongestionState _state;
    private int _maxDatagramSize;
    private ulong _congestionRecoveryStartTime;
    private int _bytesAckedInRound;
    
    // RFC 9002 constants
    private const int kInitialWindow = 10; // 10 * max_datagram_size
    private const int kMinimumWindow = 2; // 2 * max_datagram_size
    private const double kLossReductionFactor = 0.5;
    
    /// <summary>
    /// Initializes a new instance of the NewRenoCongestionController class.
    /// </summary>
    /// <param name="maxDatagramSize">The maximum datagram size.</param>
    public NewRenoCongestionController(int maxDatagramSize = 1200)
    {
        _maxDatagramSize = maxDatagramSize;
        _congestionWindow = kInitialWindow * maxDatagramSize;
        _slowStartThreshold = int.MaxValue;
        _state = CongestionState.SlowStart;
        _bytesInFlight = 0;
        _congestionRecoveryStartTime = 0;
        _bytesAckedInRound = 0;
    }
    
    /// <inheritdoc/>
    public void OnPacketSent(ulong packetNumber, int packetSize)
    {
        lock (_lock)
        {
            _bytesInFlight += packetSize;
        }
    }
    
    /// <inheritdoc/>
    public void OnPacketAcked(SentPacket packet)
    {
        lock (_lock)
        {
            if (!packet.InFlight)
                return;
            
            _bytesInFlight -= packet.Size;
            
            if (_state == CongestionState.Recovery)
            {
                // Don't increase window during recovery
                return;
            }
            
            if (_state == CongestionState.SlowStart)
            {
                // Slow start: increase window by bytes acknowledged
                _congestionWindow += packet.Size;
                
                // Exit slow start if we've reached the threshold
                if (_congestionWindow >= _slowStartThreshold)
                {
                    _state = CongestionState.CongestionAvoidance;
                    _bytesAckedInRound = 0;
                }
            }
            else if (_state == CongestionState.CongestionAvoidance)
            {
                // Congestion avoidance: increase window more slowly
                _bytesAckedInRound += packet.Size;
                
                // Increase window by 1 MSS per RTT
                if (_bytesAckedInRound >= _congestionWindow)
                {
                    _congestionWindow += _maxDatagramSize;
                    _bytesAckedInRound = 0;
                }
            }
        }
    }
    
    /// <inheritdoc/>
    public void OnPacketLost(SentPacket packet)
    {
        lock (_lock)
        {
            if (!packet.InFlight)
                return;
            
            _bytesInFlight -= packet.Size;
            
            // Check if we should enter recovery
            var packetSentTime = (ulong)packet.SentTime.Ticks;
            if (packetSentTime > _congestionRecoveryStartTime)
            {
                // New congestion event
                _congestionRecoveryStartTime = (ulong)DateTime.UtcNow.Ticks;
                
                // Reduce congestion window
                _congestionWindow = (int)(_congestionWindow * kLossReductionFactor);
                _congestionWindow = Math.Max(_congestionWindow, kMinimumWindow * _maxDatagramSize);
                
                // Update slow start threshold
                _slowStartThreshold = _congestionWindow;
                
                // Enter recovery
                _state = CongestionState.Recovery;
            }
        }
    }
    
    /// <inheritdoc/>
    public void OnRetransmissionTimeout()
    {
        lock (_lock)
        {
            // On RTO, reset to minimum window
            _slowStartThreshold = _congestionWindow / 2;
            _congestionWindow = kMinimumWindow * _maxDatagramSize;
            _state = CongestionState.PersistentCongestion;
        }
    }
    
    /// <inheritdoc/>
    public int GetCongestionWindow()
    {
        lock (_lock)
        {
            return _congestionWindow;
        }
    }
    
    /// <inheritdoc/>
    public int GetBytesInFlight()
    {
        lock (_lock)
        {
            return _bytesInFlight;
        }
    }
    
    /// <inheritdoc/>
    public bool CanSend(int packetSize)
    {
        lock (_lock)
        {
            return _bytesInFlight + packetSize <= _congestionWindow;
        }
    }
    
    /// <inheritdoc/>
    public CongestionState GetState()
    {
        lock (_lock)
        {
            return _state;
        }
    }
    
    /// <inheritdoc/>
    public int GetSlowStartThreshold()
    {
        lock (_lock)
        {
            return _slowStartThreshold;
        }
    }
    
    /// <inheritdoc/>
    public void SetMaxDatagramSize(int maxDatagramSize)
    {
        lock (_lock)
        {
            _maxDatagramSize = maxDatagramSize;
            
            // Adjust minimum window
            var minWindow = kMinimumWindow * maxDatagramSize;
            if (_congestionWindow < minWindow)
            {
                _congestionWindow = minWindow;
            }
        }
    }
    
    /// <summary>
    /// Exits recovery state when enough time has passed.
    /// </summary>
    /// <param name="now">The current time.</param>
    public void MaybeExitRecovery(DateTime now)
    {
        lock (_lock)
        {
            if (_state == CongestionState.Recovery)
            {
                // Check if we can exit recovery
                if ((ulong)now.Ticks > _congestionRecoveryStartTime)
                {
                    _state = CongestionState.CongestionAvoidance;
                    _bytesAckedInRound = 0;
                }
            }
        }
    }
}