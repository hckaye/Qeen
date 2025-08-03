using Qeen.CongestionControl.Ecn;
using Qeen.Core.Ecn;
using Xunit;

namespace Qeen.Tests.CongestionControl.Ecn;

public class EcnTrackerTests
{
    [Fact]
    public void EcnTracker_InitialState_IsTesting()
    {
        // Arrange & Act
        var tracker = new EcnTracker();
        
        // Assert
        Assert.Equal(EcnState.Testing, tracker.State);
        Assert.False(tracker.IsEnabled);
    }
    
    [Fact]
    public void EcnTracker_OnPacketSent_RecordsCodepoint()
    {
        // Arrange
        var tracker = new EcnTracker();
        ulong packetNumber = 100;
        var codepoint = EcnCodepoint.Ect0;
        
        // Act
        tracker.OnPacketSent(packetNumber, codepoint);
        var stats = tracker.GetStatistics();
        
        // Assert
        Assert.Equal(1ul, stats.SentCounts.Ect0Count);
        Assert.Equal(0ul, stats.SentCounts.Ect1Count);
        Assert.Equal(0ul, stats.SentCounts.CeCount);
    }
    
    [Fact]
    public void EcnTracker_OnAckReceived_ValidatesEcn()
    {
        // Arrange
        var tracker = new EcnTracker();
        tracker.OnPacketSent(1, EcnCodepoint.Ect0);
        tracker.OnPacketSent(2, EcnCodepoint.Ect0);
        
        var ecnCounts = new EcnCounts(2, 0, 0); // 2 ECT(0) packets
        
        // Act
        tracker.OnAckReceived(ecnCounts, 2);
        
        // Assert
        Assert.Equal(EcnState.Capable, tracker.State);
        Assert.True(tracker.IsEnabled);
    }
    
    [Fact]
    public void EcnTracker_OnAckReceived_DetectsCongestion()
    {
        // Arrange
        var tracker = new EcnTracker();
        tracker.OnPacketSent(1, EcnCodepoint.Ect0);
        tracker.OnPacketSent(2, EcnCodepoint.Ect0);
        
        // First ACK to validate ECN
        tracker.OnAckReceived(new EcnCounts(2, 0, 0), 2);
        
        // Second ACK with congestion
        var ecnCountsWithCE = new EcnCounts(2, 0, 1); // 1 CE packet
        
        // Act
        tracker.OnAckReceived(ecnCountsWithCE, 3);
        
        // Assert
        Assert.Equal(EcnState.CongestionExperienced, tracker.State);
        Assert.True(tracker.IsEnabled);
    }
    
    [Fact]
    public void EcnTracker_OnAckReceived_FailsOnDecreasedCounts()
    {
        // Arrange
        var tracker = new EcnTracker();
        tracker.OnPacketSent(1, EcnCodepoint.Ect0);
        
        // First ACK
        tracker.OnAckReceived(new EcnCounts(2, 0, 0), 1);
        
        // Second ACK with decreased counts (invalid)
        var decreasedCounts = new EcnCounts(1, 0, 0);
        
        // Act
        tracker.OnAckReceived(decreasedCounts, 2);
        
        // Assert
        Assert.Equal(EcnState.Failed, tracker.State);
        Assert.False(tracker.IsEnabled);
    }
    
    [Fact]
    public void EcnTracker_GetNextCodepoint_ReturnsCorrectCodepoint()
    {
        // Arrange
        var tracker = new EcnTracker();
        
        // Act & Assert - Testing state
        Assert.Equal(EcnCodepoint.Ect0, tracker.GetNextCodepoint());
        
        // Validate ECN
        tracker.OnPacketSent(1, EcnCodepoint.Ect0);
        tracker.OnAckReceived(new EcnCounts(1, 0, 0), 1);
        
        // Act & Assert - Capable state
        Assert.Equal(EcnCodepoint.Ect0, tracker.GetNextCodepoint());
    }
    
    [Fact]
    public void EcnCounts_HasDecreasedFrom_DetectsDecrease()
    {
        // Arrange
        var previous = new EcnCounts(10, 5, 2);
        var current1 = new EcnCounts(11, 5, 2); // Increased
        var current2 = new EcnCounts(10, 5, 2); // Same
        var current3 = new EcnCounts(9, 5, 2);  // Decreased ECT0
        var current4 = new EcnCounts(10, 4, 2); // Decreased ECT1
        var current5 = new EcnCounts(10, 5, 1); // Decreased CE
        
        // Act & Assert
        Assert.False(current1.HasDecreasedFrom(previous));
        Assert.False(current2.HasDecreasedFrom(previous));
        Assert.True(current3.HasDecreasedFrom(previous));
        Assert.True(current4.HasDecreasedFrom(previous));
        Assert.True(current5.HasDecreasedFrom(previous));
    }
    
    [Fact]
    public void EcnCounts_Subtract_CalculatesCorrectly()
    {
        // Arrange
        var total = new EcnCounts(10, 5, 2);
        var previous = new EcnCounts(7, 3, 1);
        
        // Act
        var diff = total.Subtract(previous);
        
        // Assert
        Assert.Equal(3ul, diff.Ect0Count);
        Assert.Equal(2ul, diff.Ect1Count);
        Assert.Equal(1ul, diff.CeCount);
        Assert.Equal(6ul, diff.TotalCount);
    }
}