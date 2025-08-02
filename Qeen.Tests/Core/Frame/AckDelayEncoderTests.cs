using Qeen.Core.Frame;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class AckDelayEncoderTests
{
    [Fact]
    public void EncodeAckDelay_WithDefaultExponent_EncodesCorrectly()
    {
        // Arrange
        ulong delayMicroseconds = 8000; // 8ms = 8000 microseconds
        byte exponent = AckDelayEncoder.DefaultAckDelayExponent; // 3
        
        // Act
        var encoded = AckDelayEncoder.EncodeAckDelay(delayMicroseconds, exponent);
        
        // Assert
        // 8000 / (2^3) = 8000 / 8 = 1000
        Assert.Equal(1000UL, encoded);
    }
    
    [Fact]
    public void DecodeAckDelay_WithDefaultExponent_DecodesCorrectly()
    {
        // Arrange
        ulong encodedDelay = 1000;
        byte exponent = AckDelayEncoder.DefaultAckDelayExponent; // 3
        
        // Act
        var decoded = AckDelayEncoder.DecodeAckDelay(encodedDelay, exponent);
        
        // Assert
        // 1000 * (2^3) = 1000 * 8 = 8000
        Assert.Equal(8000UL, decoded);
    }
    
    [Theory]
    [InlineData(0UL, 0, 0UL)]
    [InlineData(100UL, 0, 100UL)]
    [InlineData(256UL, 1, 128UL)]
    [InlineData(1024UL, 2, 256UL)]
    [InlineData(8192UL, 3, 1024UL)]
    [InlineData(65536UL, 4, 4096UL)]
    public void EncodeAckDelay_VariousValues_EncodesCorrectly(ulong microseconds, byte exponent, ulong expected)
    {
        // Act
        var encoded = AckDelayEncoder.EncodeAckDelay(microseconds, exponent);
        
        // Assert
        Assert.Equal(expected, encoded);
    }
    
    [Theory]
    [InlineData(0UL, 0, 0UL)]
    [InlineData(100UL, 0, 100UL)]
    [InlineData(128UL, 1, 256UL)]
    [InlineData(256UL, 2, 1024UL)]
    [InlineData(1024UL, 3, 8192UL)]
    [InlineData(4096UL, 4, 65536UL)]
    public void DecodeAckDelay_VariousValues_DecodesCorrectly(ulong encoded, byte exponent, ulong expected)
    {
        // Act
        var decoded = AckDelayEncoder.DecodeAckDelay(encoded, exponent);
        
        // Assert
        Assert.Equal(expected, decoded);
    }
    
    [Fact]
    public void EncodeDecodeAckDelay_RoundTrip_PreservesValue()
    {
        // Arrange
        byte exponent = 5;
        ulong originalMicroseconds = 64000; // Divisible by 2^5 = 32
        
        // Act
        var encoded = AckDelayEncoder.EncodeAckDelay(originalMicroseconds, exponent);
        var decoded = AckDelayEncoder.DecodeAckDelay(encoded, exponent);
        
        // Assert
        Assert.Equal(originalMicroseconds, decoded);
    }
    
    [Fact]
    public void EncodeAckDelay_WithRounding_LossesPrecision()
    {
        // Arrange
        byte exponent = 3;
        ulong originalMicroseconds = 8005; // Not divisible by 8
        
        // Act
        var encoded = AckDelayEncoder.EncodeAckDelay(originalMicroseconds, exponent);
        var decoded = AckDelayEncoder.DecodeAckDelay(encoded, exponent);
        
        // Assert
        // 8005 / 8 = 1000 (integer division, loses 5 microseconds)
        // 1000 * 8 = 8000
        Assert.Equal(1000UL, encoded);
        Assert.Equal(8000UL, decoded);
        Assert.NotEqual(originalMicroseconds, decoded);
    }
    
    [Theory]
    [InlineData(21)]
    [InlineData(50)]
    [InlineData(255)]
    public void EncodeAckDelay_InvalidExponent_ThrowsException(byte exponent)
    {
        // Arrange
        ulong delayMicroseconds = 1000;
        
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            AckDelayEncoder.EncodeAckDelay(delayMicroseconds, exponent));
    }
    
    [Theory]
    [InlineData(21)]
    [InlineData(50)]
    [InlineData(255)]
    public void DecodeAckDelay_InvalidExponent_ThrowsException(byte exponent)
    {
        // Arrange
        ulong encodedDelay = 1000;
        
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            AckDelayEncoder.DecodeAckDelay(encodedDelay, exponent));
    }
    
    [Fact]
    public void DecodeAckDelay_Overflow_SaturatesToMaxValue()
    {
        // Arrange
        ulong encodedDelay = ulong.MaxValue / 2; // Large value that would overflow
        byte exponent = 10;
        
        // Act
        var decoded = AckDelayEncoder.DecodeAckDelay(encodedDelay, exponent);
        
        // Assert
        Assert.Equal(ulong.MaxValue, decoded);
    }
    
    [Theory]
    [InlineData(1UL, 10L)] // 1 microsecond = 10 ticks
    [InlineData(1000UL, 10000L)] // 1000 microseconds = 10,000 ticks
    [InlineData(1000000UL, 10000000L)] // 1 second = 10,000,000 ticks
    [InlineData(0UL, 0L)]
    public void MicrosecondsToTimeSpan_ConvertsCorrectly(ulong microseconds, long expectedTicks)
    {
        // Act
        var timeSpan = AckDelayEncoder.MicrosecondsToTimeSpan(microseconds);
        
        // Assert
        Assert.Equal(expectedTicks, timeSpan.Ticks);
    }
    
    [Fact]
    public void MicrosecondsToTimeSpan_Overflow_ReturnsMaxValue()
    {
        // Arrange
        ulong microseconds = ulong.MaxValue;
        
        // Act
        var timeSpan = AckDelayEncoder.MicrosecondsToTimeSpan(microseconds);
        
        // Assert
        Assert.Equal(TimeSpan.MaxValue, timeSpan);
    }
    
    [Theory]
    [InlineData(10L, 1UL)] // 10 ticks = 1 microsecond
    [InlineData(10000000L, 1000000UL)] // 10,000,000 ticks = 1 second
    [InlineData(0L, 0UL)]
    public void TimeSpanToMicroseconds_ConvertsCorrectly(long ticks, ulong expectedMicroseconds)
    {
        // Arrange
        var timeSpan = TimeSpan.FromTicks(ticks);
        
        // Act
        var microseconds = AckDelayEncoder.TimeSpanToMicroseconds(timeSpan);
        
        // Assert
        Assert.Equal(expectedMicroseconds, microseconds);
    }
    
    [Fact]
    public void TimeSpanToMicroseconds_NegativeValue_ReturnsZero()
    {
        // Arrange
        var timeSpan = TimeSpan.FromSeconds(-1);
        
        // Act
        var microseconds = AckDelayEncoder.TimeSpanToMicroseconds(timeSpan);
        
        // Assert
        Assert.Equal(0UL, microseconds);
    }
    
    [Theory]
    [InlineData(0, true)]
    [InlineData(3, true)]
    [InlineData(10, true)]
    [InlineData(20, true)]
    [InlineData(21, false)]
    [InlineData(255, false)]
    public void IsValidAckDelayExponent_ReturnsCorrectResult(byte exponent, bool expected)
    {
        // Act
        var isValid = AckDelayEncoder.IsValidAckDelayExponent(exponent);
        
        // Assert
        Assert.Equal(expected, isValid);
    }
    
    [Fact]
    public void MaxAckDelayExponent_HasCorrectValue()
    {
        // Assert - RFC 9000 specifies max value is 20
        Assert.Equal(20, AckDelayEncoder.MaxAckDelayExponent);
    }
    
    [Fact]
    public void DefaultAckDelayExponent_HasCorrectValue()
    {
        // Assert - RFC 9000 specifies default value is 3
        Assert.Equal(3, AckDelayEncoder.DefaultAckDelayExponent);
    }
}