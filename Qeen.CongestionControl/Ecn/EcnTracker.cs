using System.Collections.Concurrent;
using Qeen.Core.Ecn;

namespace Qeen.CongestionControl.Ecn;

/// <summary>
/// Tracks ECN state and validates ECN feedback according to RFC 9002
/// </summary>
public class EcnTracker
{
    private readonly object _lock = new();
    private EcnState _state;
    private EcnCounts _sentCounts;
    private EcnCounts _ackedCounts;
    private EcnCounts _lastReportedCounts;
    private readonly ConcurrentDictionary<ulong, EcnCodepoint> _sentPackets;
    private ulong _validationPacketNumber;
    private int _validationAttempts;
    private DateTime _lastCongestionTime;
    
    // Constants from RFC 9002
    private const int MaxValidationAttempts = 10;
    private const int ValidationThreshold = 10;
    
    public EcnTracker()
    {
        _state = EcnState.Testing;
        _sentPackets = new ConcurrentDictionary<ulong, EcnCodepoint>();
        _lastCongestionTime = DateTime.MinValue;
    }
    
    /// <summary>
    /// Gets the current ECN state
    /// </summary>
    public EcnState State
    {
        get { lock (_lock) return _state; }
    }
    
    /// <summary>
    /// Gets whether ECN is enabled and working
    /// </summary>
    public bool IsEnabled => State == EcnState.Capable || State == EcnState.CongestionExperienced;
    
    /// <summary>
    /// Records that a packet was sent with the specified ECN marking
    /// </summary>
    public void OnPacketSent(ulong packetNumber, EcnCodepoint codepoint)
    {
        lock (_lock)
        {
            if (_state == EcnState.Disabled || _state == EcnState.Failed)
                return;
            
            _sentPackets[packetNumber] = codepoint;
            
            switch (codepoint)
            {
                case EcnCodepoint.Ect0:
                    _sentCounts.Ect0Count++;
                    break;
                case EcnCodepoint.Ect1:
                    _sentCounts.Ect1Count++;
                    break;
                case EcnCodepoint.CongestionExperienced:
                    _sentCounts.CeCount++;
                    break;
            }
            
            // Start validation if this is the first ECN packet
            if (_state == EcnState.Testing && _validationPacketNumber == 0)
            {
                _validationPacketNumber = packetNumber;
            }
        }
    }
    
    /// <summary>
    /// Processes ECN counts from an ACK frame
    /// </summary>
    public void OnAckReceived(EcnCounts reportedCounts, ulong largestAcked)
    {
        lock (_lock)
        {
            if (_state == EcnState.Disabled || _state == EcnState.Failed)
                return;
            
            // Check for ECN count decrease (RFC 9002 Section 3.3.2)
            if (reportedCounts.HasDecreasedFrom(_lastReportedCounts))
            {
                // ECN validation failed - counts should never decrease
                _state = EcnState.Failed;
                return;
            }
            
            // Calculate newly acknowledged counts
            var newlyAcked = reportedCounts.Subtract(_lastReportedCounts);
            _ackedCounts.Add(newlyAcked);
            _lastReportedCounts = reportedCounts;
            
            // Check for congestion
            if (newlyAcked.CeCount > 0)
            {
                _state = EcnState.CongestionExperienced;
                _lastCongestionTime = DateTime.UtcNow;
            }
            
            // Validate ECN if in testing state
            if (_state == EcnState.Testing)
            {
                ValidateEcn(largestAcked);
            }
        }
    }
    
    /// <summary>
    /// Validates ECN capability based on acknowledgments
    /// </summary>
    private void ValidateEcn(ulong largestAcked)
    {
        // Check if validation packet has been acknowledged
        if (largestAcked >= _validationPacketNumber)
        {
            // Check if we've received ECN feedback
            if (_ackedCounts.TotalCount > 0)
            {
                // ECN is working
                _state = EcnState.Capable;
            }
            else
            {
                _validationAttempts++;
                
                if (_validationAttempts >= MaxValidationAttempts)
                {
                    // ECN validation failed after maximum attempts
                    _state = EcnState.Failed;
                }
                else
                {
                    // Try again with a new packet
                    _validationPacketNumber = 0;
                }
            }
        }
    }
    
    /// <summary>
    /// Gets the ECN codepoint to use for the next packet
    /// </summary>
    public EcnCodepoint GetNextCodepoint()
    {
        lock (_lock)
        {
            switch (_state)
            {
                case EcnState.Testing:
                case EcnState.Capable:
                    // Use ECT(0) by default (could implement ECT(1) randomization)
                    return EcnCodepoint.Ect0;
                    
                case EcnState.CongestionExperienced:
                    // Continue using ECT after congestion
                    // Reset to Capable state after some time
                    if (DateTime.UtcNow - _lastCongestionTime > TimeSpan.FromSeconds(1))
                    {
                        _state = EcnState.Capable;
                    }
                    return EcnCodepoint.Ect0;
                    
                default:
                    return EcnCodepoint.NotEct;
            }
        }
    }
    
    /// <summary>
    /// Handles packet loss to determine if ECN should be disabled
    /// </summary>
    public void OnPacketLost(ulong packetNumber)
    {
        lock (_lock)
        {
            // Remove from sent packets tracking
            _sentPackets.TryRemove(packetNumber, out _);
            
            // Could implement logic to disable ECN if too many losses occur
            // when ECN marking should have prevented them
        }
    }
    
    /// <summary>
    /// Gets current ECN statistics
    /// </summary>
    public EcnStatistics GetStatistics()
    {
        lock (_lock)
        {
            return new EcnStatistics
            {
                State = _state,
                SentCounts = _sentCounts,
                AckedCounts = _ackedCounts,
                ValidationAttempts = _validationAttempts,
                IsEnabled = IsEnabled
            };
        }
    }
}

/// <summary>
/// ECN statistics for monitoring and debugging
/// </summary>
public struct EcnStatistics
{
    public EcnState State { get; set; }
    public EcnCounts SentCounts { get; set; }
    public EcnCounts AckedCounts { get; set; }
    public int ValidationAttempts { get; set; }
    public bool IsEnabled { get; set; }
}