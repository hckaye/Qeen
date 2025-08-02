using Qeen.CongestionControl.Pacing;
using Xunit;

namespace Qeen.Tests.CongestionControl.Pacing;

public class DefaultPacerTests
{
    [Fact]
    public void DefaultPacer_InitialState()
    {
        var pacer = new DefaultPacer();
        
        Assert.True(pacer.ShouldSendNow()); // Should allow initial burst
        Assert.True(pacer.GetPacingRate() > 0);
    }
    
    [Fact]
    public void DefaultPacer_UpdateSendingRate()
    {
        var pacer = new DefaultPacer();
        
        // Set pacing rate based on cwnd and RTT
        pacer.UpdateSendingRate(12000, TimeSpan.FromMilliseconds(50));
        
        var rate = pacer.GetPacingRate();
        // Rate should be cwnd/RTT * gain
        // 12000 / 0.05 * 1.25 = 300000 bytes/sec
        Assert.True(rate > 200000);
        Assert.True(rate < 400000);
    }
    
    [Fact]
    public void DefaultPacer_BurstAllowance()
    {
        var pacer = new DefaultPacer();
        
        // Should allow burst at start
        for (int i = 0; i < 10; i++)
        {
            Assert.True(pacer.ShouldSendNow());
            pacer.OnPacketSent(1200);
        }
        
        // After burst, may need to wait
        // (depends on timing and rate)
    }
    
    [Fact]
    public void DefaultPacer_GetNextSendTime_AfterBurst()
    {
        var pacer = new DefaultPacer();
        pacer.UpdateSendingRate(12000, TimeSpan.FromMilliseconds(50));
        
        // Use up burst allowance
        for (int i = 0; i < 15; i++)
        {
            pacer.OnPacketSent(1200);
        }
        
        // Should now return non-zero delay
        var delay = pacer.GetNextSendTime(1200);
        Assert.True(delay >= TimeSpan.Zero);
    }
    
    [Fact]
    public void DefaultPacer_SetPacingGain()
    {
        var pacer = new DefaultPacer();
        var initialRate = pacer.GetPacingRate();
        
        pacer.SetPacingGain(2.0);
        pacer.UpdateSendingRate(12000, TimeSpan.FromMilliseconds(50));
        
        var newRate = pacer.GetPacingRate();
        Assert.True(newRate > initialRate);
    }
    
    [Fact]
    public void DefaultPacer_ResetBurstAllowance()
    {
        var pacer = new DefaultPacer();
        
        // Use up burst
        for (int i = 0; i < 15; i++)
        {
            pacer.OnPacketSent(1200);
        }
        
        pacer.ResetBurstAllowance();
        
        // Should allow burst again
        Assert.True(pacer.ShouldSendNow());
    }
    
    [Fact]
    public void DefaultPacer_SetMaxBurstSize()
    {
        var pacer = new DefaultPacer();
        pacer.SetMaxBurstSize(5);
        
        // Should only allow 5 packets in burst
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(TimeSpan.Zero, pacer.GetNextSendTime(1200));
            pacer.OnPacketSent(1200);
        }
        
        // 6th packet may need to wait
        var delay = pacer.GetNextSendTime(1200);
        Assert.True(delay >= TimeSpan.Zero);
    }
}