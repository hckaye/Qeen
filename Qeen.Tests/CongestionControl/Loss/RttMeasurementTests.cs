using Qeen.CongestionControl.Loss;
using Xunit;

namespace Qeen.Tests.CongestionControl.Loss;

public class RttMeasurementTests
{
    [Fact]
    public void RttMeasurement_Default_HasCorrectValues()
    {
        var rtt = RttMeasurement.Default();
        
        Assert.Equal(TimeSpan.Zero, rtt.LatestRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(333), rtt.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(166.5), rtt.RttVariance);
        Assert.Equal(TimeSpan.MaxValue, rtt.MinRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(25), rtt.MaxAckDelay);
        Assert.Equal(0, rtt.SampleCount);
    }
    
    [Fact]
    public void RttMeasurement_GetProbeTimeout_ReturnsCorrectValue()
    {
        var rtt = RttMeasurement.Default();
        var pto = rtt.GetProbeTimeout();
        
        // PTO = 333ms + max(4*166.5ms, 1ms) + 25ms
        // = 333 + 666 + 25 = 1024ms
        Assert.Equal(1024, pto.TotalMilliseconds, 0.1);
    }
    
    [Fact]
    public void RttMeasurement_UpdateRtt_UpdatesValues()
    {
        var rtt = RttMeasurement.Default();
        
        // First sample
        rtt.UpdateRtt(TimeSpan.FromMilliseconds(100), TimeSpan.Zero);
        
        Assert.Equal(TimeSpan.FromMilliseconds(100), rtt.LatestRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(100), rtt.SmoothedRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(100), rtt.MinRtt);
        Assert.Equal(1, rtt.SampleCount);
    }
    
    [Fact]
    public void RttMeasurement_UpdateRtt_MultipleUpdates()
    {
        var rtt = RttMeasurement.Default();
        
        // Multiple samples
        rtt.UpdateRtt(TimeSpan.FromMilliseconds(100), TimeSpan.Zero);
        rtt.UpdateRtt(TimeSpan.FromMilliseconds(150), TimeSpan.Zero);
        rtt.UpdateRtt(TimeSpan.FromMilliseconds(125), TimeSpan.Zero);
        
        Assert.Equal(3, rtt.SampleCount);
        Assert.Equal(TimeSpan.FromMilliseconds(100), rtt.MinRtt);
        Assert.Equal(TimeSpan.FromMilliseconds(125), rtt.LatestRtt);
        Assert.True(rtt.SmoothedRtt > TimeSpan.Zero);
    }
}