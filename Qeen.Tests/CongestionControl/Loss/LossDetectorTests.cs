using Qeen.CongestionControl.Loss;
using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.CongestionControl.Loss;

public class LossDetectorTests
{
    [Fact]
    public void LossDetector_InitialState()
    {
        var detector = new LossDetector();
        var stats = detector.GetStats();
        
        Assert.Equal(0u, stats.PacketsSent);
        Assert.Equal(0u, stats.PacketsAcked);
        Assert.Equal(0u, stats.PacketsLost);
        Assert.False(detector.ShouldSendProbe());
    }
    
    [Fact]
    public void LossDetector_OnPacketSent_UpdatesStats()
    {
        var detector = new LossDetector();
        var packet = CreateTestPacket(1, 1200, true);
        
        detector.OnPacketSent(packet);
        
        var stats = detector.GetStats();
        Assert.Equal(1u, stats.PacketsSent);
        Assert.Equal(1200u, stats.BytesSent);
    }
    
    [Fact]
    public void LossDetector_OnAckReceived_UpdatesRtt()
    {
        var detector = new LossDetector();
        var sentTime = DateTime.UtcNow;
        var packet = new SentPacket
        {
            PacketNumber = 1,
            Size = 1200,
            SentTime = sentTime,
            IsAckEliciting = true,
            InFlight = true,
            EncryptionLevel = EncryptionLevel.Application,
            Frames = new List<IQuicFrame>()
        };
        
        detector.OnPacketSent(packet);
        
        // Simulate RTT of 50ms
        Thread.Sleep(50);
        
        var ackRanges = new List<AckRange> { new AckRange(0, 0) };
        var ackFrame = new AckFrame(1, 0, ackRanges);
        detector.OnAckReceived(ackFrame, TimeSpan.Zero);
        
        var rtt = detector.GetRttMeasurement();
        Assert.True(rtt.LatestRtt.TotalMilliseconds >= 50);
        Assert.True(rtt.SmoothedRtt.TotalMilliseconds > 0);
    }
    
    [Fact]
    public void LossDetector_DetectsPacketLoss_ByThreshold()
    {
        var detector = new LossDetector();
        
        // Send packets 1-5
        for (ulong i = 1; i <= 5; i++)
        {
            detector.OnPacketSent(CreateTestPacket(i, 1200, true));
        }
        
        // Acknowledge packet 5 (triggers loss detection for packet 1)
        var ackRanges = new List<AckRange> { new AckRange(0, 0) };
        var ackFrame = new AckFrame(5, 0, ackRanges);
        detector.OnAckReceived(ackFrame, TimeSpan.Zero);
        
        var stats = detector.GetStats();
        Assert.True(stats.PacketsLost > 0);
    }
    
    [Fact]
    public void LossDetector_GetProbeTimeout_ReturnsValidPto()
    {
        var detector = new LossDetector();
        
        var pto = detector.GetProbeTimeout();
        
        // PTO should be a reasonable value (greater than 0)
        Assert.True(pto > TimeSpan.Zero);
        // PTO should not be unreasonably large (less than 10 seconds)
        Assert.True(pto < TimeSpan.FromSeconds(10));
    }
    
    [Fact]
    public void LossDetector_OnRetransmissionTimeout_IncreasesPto()
    {
        var detector = new LossDetector();
        
        var pto1 = detector.GetProbeTimeout();
        detector.OnRetransmissionTimeout();
        var pto2 = detector.GetProbeTimeout();
        
        // PTO should double after timeout
        Assert.True(pto2.TotalMilliseconds >= pto1.TotalMilliseconds * 2);
    }
    
    private static SentPacket CreateTestPacket(ulong packetNumber, int size, bool ackEliciting)
    {
        return new SentPacket
        {
            PacketNumber = packetNumber,
            Size = size,
            SentTime = DateTime.UtcNow,
            IsAckEliciting = ackEliciting,
            InFlight = true,
            EncryptionLevel = EncryptionLevel.Application,
            Frames = new List<IQuicFrame>()
        };
    }
}