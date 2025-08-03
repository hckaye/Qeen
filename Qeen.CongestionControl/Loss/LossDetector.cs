using System.Collections.Concurrent;
using Qeen.CongestionControl.Ecn;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;

namespace Qeen.CongestionControl.Loss;

/// <summary>
/// Implements QUIC loss detection according to RFC 9002.
/// </summary>
public class LossDetector : ILossDetector
{
    private readonly ConcurrentDictionary<ulong, SentPacket> _sentPackets;
    private readonly object _lock = new();
    private RttMeasurement _rttMeasurement;
    private DateTime _lastAckElicitingSentTime;
    private ulong _largestAckedPacket;
    private DateTime _lossTime;
    private uint _ptoCount;
    private ulong _packetsSent;
    private ulong _packetsAcked;
    private ulong _packetsLost;
    private ulong _bytesSent;
    private ulong _bytesAcked;
    private ulong _bytesLost;
    
    // ECN support
    private readonly EcnTracker _ecnTracker;
    
    // RFC 9002 constants
    private const int kPacketThreshold = 3;
    private const double kTimeThreshold = 9.0 / 8.0;
    private const int kGranularity = 1; // milliseconds
    
    /// <summary>
    /// Initializes a new instance of the LossDetector class.
    /// </summary>
    public LossDetector()
    {
        _sentPackets = new ConcurrentDictionary<ulong, SentPacket>();
        _rttMeasurement = RttMeasurement.Default();
        _lastAckElicitingSentTime = DateTime.MinValue;
        _lossTime = DateTime.MaxValue;
        _ecnTracker = new EcnTracker();
    }
    
    /// <summary>
    /// Gets the ECN tracker for this connection
    /// </summary>
    public EcnTracker EcnTracker => _ecnTracker;
    
    /// <inheritdoc/>
    public void OnPacketSent(SentPacket packet)
    {
        lock (_lock)
        {
            _sentPackets[packet.PacketNumber] = packet;
            _packetsSent++;
            _bytesSent += (ulong)packet.Size;
            
            if (packet.IsAckEliciting)
            {
                _lastAckElicitingSentTime = packet.SentTime;
            }
        }
    }
    
    /// <inheritdoc/>
    public void OnAckReceived(AckFrame ackFrame, TimeSpan ackDelay)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            var newlyAcked = new List<SentPacket>();
            
            // Process acknowledged packets
            // The first range starts from LargestAcknowledged
            var currentPacket = ackFrame.LargestAcknowledged;
            
            foreach (var range in ackFrame.AckRanges)
            {
                // Process this range
                for (ulong i = 0; i <= range.Length; i++)
                {
                    var pn = currentPacket - i;
                    if (_sentPackets.TryRemove(pn, out var packet))
                    {
                        newlyAcked.Add(packet);
                        _packetsAcked++;
                        _bytesAcked += (ulong)packet.Size;
                    }
                }
                
                // Move to next range (accounting for gap)
                currentPacket = currentPacket - range.Length - range.Gap - 2;
            }
            
            if (newlyAcked.Count == 0)
                return;
            
            // Update largest acknowledged packet
            var largestNewlyAcked = newlyAcked.MaxBy(p => p.PacketNumber);
            if (largestNewlyAcked.PacketNumber > _largestAckedPacket)
            {
                _largestAckedPacket = largestNewlyAcked.PacketNumber;
                
                // Update RTT if this is a newly acknowledged ack-eliciting packet
                if (largestNewlyAcked.IsAckEliciting)
                {
                    var rttSample = now - largestNewlyAcked.SentTime;
                    _rttMeasurement.UpdateRtt(rttSample, ackDelay);
                }
            }
            
            // Detect lost packets
            DetectAndRemoveLostPackets(now);
            
            // Reset PTO count on successful ACK
            _ptoCount = 0;
        }
    }
    
    /// <inheritdoc/>
    public IEnumerable<SentPacket> DetectLostPackets()
    {
        lock (_lock)
        {
            return DetectAndRemoveLostPackets(DateTime.UtcNow);
        }
    }
    
    private List<SentPacket> DetectAndRemoveLostPackets(DateTime now)
    {
        var lostPackets = new List<SentPacket>();
        _lossTime = DateTime.MaxValue;
        
        // Loss detection threshold
        var lossDelay = TimeSpan.FromTicks((long)(kTimeThreshold * 
            Math.Max(_rttMeasurement.LatestRtt.Ticks, _rttMeasurement.SmoothedRtt.Ticks)));
        lossDelay = TimeSpan.FromMilliseconds(Math.Max(lossDelay.TotalMilliseconds, kGranularity));
        
        foreach (var packet in _sentPackets.Values.OrderBy(p => p.PacketNumber))
        {
            // Skip if packet number is too recent
            if (packet.PacketNumber > _largestAckedPacket)
                continue;
            
            // Packet threshold loss detection
            if (_largestAckedPacket >= packet.PacketNumber + kPacketThreshold)
            {
                if (_sentPackets.TryRemove(packet.PacketNumber, out _))
                {
                    lostPackets.Add(packet);
                    _packetsLost++;
                    _bytesLost += (ulong)packet.Size;
                }
                continue;
            }
            
            // Time threshold loss detection
            var timeSinceSent = now - packet.SentTime;
            if (timeSinceSent > lossDelay)
            {
                if (_sentPackets.TryRemove(packet.PacketNumber, out _))
                {
                    lostPackets.Add(packet);
                    _packetsLost++;
                    _bytesLost += (ulong)packet.Size;
                }
            }
            else
            {
                // Update loss time for the earliest packet that might be lost
                var whenLost = packet.SentTime + lossDelay;
                if (whenLost < _lossTime)
                {
                    _lossTime = whenLost;
                }
            }
        }
        
        return lostPackets;
    }
    
    /// <inheritdoc/>
    public TimeSpan GetProbeTimeout()
    {
        lock (_lock)
        {
            var pto = _rttMeasurement.GetProbeTimeout();
            
            // Exponential backoff based on PTO count
            for (uint i = 0; i < _ptoCount; i++)
            {
                pto = TimeSpan.FromTicks(pto.Ticks * 2);
            }
            
            return pto;
        }
    }
    
    /// <inheritdoc/>
    public void OnRetransmissionTimeout()
    {
        lock (_lock)
        {
            _ptoCount++;
        }
    }
    
    /// <inheritdoc/>
    public LossDetectionStats GetStats()
    {
        lock (_lock)
        {
            return new LossDetectionStats
            {
                PacketsSent = _packetsSent,
                PacketsAcked = _packetsAcked,
                PacketsLost = _packetsLost,
                BytesSent = _bytesSent,
                BytesAcked = _bytesAcked,
                BytesLost = _bytesLost,
                PtoCount = _ptoCount,
                RttMeasurement = _rttMeasurement
            };
        }
    }
    
    /// <inheritdoc/>
    public RttMeasurement GetRttMeasurement()
    {
        lock (_lock)
        {
            return _rttMeasurement;
        }
    }
    
    /// <inheritdoc/>
    public bool ShouldSendProbe()
    {
        lock (_lock)
        {
            if (_lastAckElicitingSentTime == DateTime.MinValue)
                return false;
            
            var timeSinceLastAckEliciting = DateTime.UtcNow - _lastAckElicitingSentTime;
            return timeSinceLastAckEliciting >= GetProbeTimeout();
        }
    }
}