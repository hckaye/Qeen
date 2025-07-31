using Xunit;
using Qeen.Core.Stream;

namespace Qeen.Tests.Core.Stream;

public class StreamEnumTests
{
    [Fact]
    public void StreamType_HasCorrectValues()
    {
        Assert.Equal(0, (int)StreamType.Bidirectional);
        Assert.Equal(1, (int)StreamType.Unidirectional);
    }

    [Fact]
    public void StreamState_HasAllRequiredStates()
    {
        var values = Enum.GetValues<StreamState>();
        
        // Verify all expected states exist
        Assert.Contains(StreamState.Idle, values);
        Assert.Contains(StreamState.Open, values);
        Assert.Contains(StreamState.LocallyClosed, values);
        Assert.Contains(StreamState.RemotelyClosed, values);
        Assert.Contains(StreamState.Closed, values);
        Assert.Contains(StreamState.ResetSent, values);
        Assert.Contains(StreamState.ResetReceived, values);
        Assert.Contains(StreamState.ResetClosed, values);
    }

    [Theory]
    [InlineData(StreamState.Idle, 0)]
    [InlineData(StreamState.Open, 1)]
    [InlineData(StreamState.LocallyClosed, 2)]
    [InlineData(StreamState.RemotelyClosed, 3)]
    [InlineData(StreamState.Closed, 4)]
    [InlineData(StreamState.ResetSent, 5)]
    [InlineData(StreamState.ResetReceived, 6)]
    [InlineData(StreamState.ResetClosed, 7)]
    public void StreamState_HasExpectedValues(StreamState state, int expectedValue)
    {
        Assert.Equal(expectedValue, (int)state);
    }
}