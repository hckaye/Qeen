using Qeen.Core.Constants;
using Xunit;

namespace Qeen.Tests.Core.Constants;

public class QuicLimitsTests
{
    [Fact]
    public void MaxPacketNumber_HasCorrectValue()
    {
        // RFC 9000 Section 17.1: Maximum packet number is 2^62 - 1
        Assert.Equal((1UL << 62) - 1, QuicLimits.MaxPacketNumber);
    }
    
    [Fact]
    public void MaxStreamId_HasCorrectValue()
    {
        // RFC 9000 Section 2.1: Maximum stream ID is 2^62 - 1
        Assert.Equal((1UL << 62) - 1, QuicLimits.MaxStreamId);
    }
    
    [Fact]
    public void MaxVarInt_HasCorrectValue()
    {
        // RFC 9000 Section 16: Maximum variable-length integer is 2^62 - 1
        Assert.Equal((1UL << 62) - 1, QuicLimits.MaxVarInt);
    }
    
    [Theory]
    [InlineData(0, true)]
    [InlineData(100, true)]
    [InlineData((1UL << 62) - 1, true)]
    [InlineData(1UL << 62, false)]
    [InlineData(ulong.MaxValue, false)]
    public void IsValidVarInt_ReturnsCorrectResult(ulong value, bool expected)
    {
        Assert.Equal(expected, QuicLimits.IsValidVarInt(value));
    }
    
    [Theory]
    [InlineData(0, true)]
    [InlineData(1000000, true)]
    [InlineData((1UL << 62) - 1, true)]
    [InlineData(1UL << 62, false)]
    [InlineData(ulong.MaxValue, false)]
    public void IsValidPacketNumber_ReturnsCorrectResult(ulong packetNumber, bool expected)
    {
        Assert.Equal(expected, QuicLimits.IsValidPacketNumber(packetNumber));
    }
    
    [Theory]
    [InlineData(0, true)]
    [InlineData(4, true)]
    [InlineData((1UL << 62) - 1, true)]
    [InlineData(1UL << 62, false)]
    [InlineData(ulong.MaxValue, false)]
    public void IsValidStreamId_ReturnsCorrectResult(ulong streamId, bool expected)
    {
        Assert.Equal(expected, QuicLimits.IsValidStreamId(streamId));
    }
    
    [Theory]
    [InlineData(-1, false)]
    [InlineData(0, true)]
    [InlineData(8, true)]
    [InlineData(20, true)]
    [InlineData(21, false)]
    [InlineData(100, false)]
    public void IsValidConnectionIdLength_ReturnsCorrectResult(int length, bool expected)
    {
        Assert.Equal(expected, QuicLimits.IsValidConnectionIdLength(length));
    }
    
    [Theory]
    [InlineData(0x00, true)]  // NO_ERROR
    [InlineData(0x01, true)]  // INTERNAL_ERROR
    [InlineData(0x02, true)]  // CONNECTION_REFUSED
    [InlineData(0x03, true)]  // FLOW_CONTROL_ERROR
    [InlineData(0x04, true)]  // STREAM_LIMIT_ERROR
    [InlineData(0x05, true)]  // STREAM_STATE_ERROR
    [InlineData(0x06, true)]  // FINAL_SIZE_ERROR
    [InlineData(0x07, true)]  // FRAME_ENCODING_ERROR
    [InlineData(0x08, true)]  // TRANSPORT_PARAMETER_ERROR
    [InlineData(0x09, true)]  // CONNECTION_ID_LIMIT_ERROR
    [InlineData(0x0a, true)]  // PROTOCOL_VIOLATION
    [InlineData(0x0b, true)]  // INVALID_TOKEN
    [InlineData(0x0c, true)]  // APPLICATION_ERROR
    [InlineData(0x0d, true)]  // CRYPTO_BUFFER_EXCEEDED
    [InlineData(0x0e, true)]  // KEY_UPDATE_ERROR
    [InlineData(0x0f, true)]  // AEAD_LIMIT_REACHED
    [InlineData(0x10, false)] // Beyond defined transport errors
    [InlineData(0xff, false)]
    [InlineData(0x0100, true)]  // CRYPTO_ERROR start
    [InlineData(0x0150, true)]  // CRYPTO_ERROR middle
    [InlineData(0x01ff, true)]  // CRYPTO_ERROR end
    [InlineData(0x0200, false)] // Beyond CRYPTO_ERROR range
    public void IsValidTransportErrorCode_ReturnsCorrectResult(ulong errorCode, bool expected)
    {
        Assert.Equal(expected, QuicLimits.IsValidTransportErrorCode(errorCode));
    }
    
    [Fact]
    public void MaxConnectionIdLength_HasCorrectValue()
    {
        // RFC 9000 Section 17.2: Connection IDs can be 0 to 20 bytes
        Assert.Equal(20, QuicLimits.MaxConnectionIdLength);
    }
    
    [Fact]
    public void StatelessResetTokenLength_HasCorrectValue()
    {
        // RFC 9000 Section 10.3: Stateless reset tokens are exactly 16 bytes
        Assert.Equal(16, QuicLimits.StatelessResetTokenLength);
    }
    
    [Fact]
    public void MinInitialPacketSize_HasCorrectValue()
    {
        // RFC 9000 Section 14.1: Initial packets must be at least 1200 bytes
        Assert.Equal(1200, QuicLimits.MinInitialPacketSize);
    }
    
    [Fact]
    public void MaxReasonPhraseLength_IsReasonable()
    {
        // While not specified in RFC, we use a reasonable limit
        Assert.Equal(1024, QuicLimits.MaxReasonPhraseLength);
        Assert.True(QuicLimits.MaxReasonPhraseLength > 0);
        Assert.True(QuicLimits.MaxReasonPhraseLength <= 65535);
    }
    
    [Fact]
    public void MaxAckRanges_IsReasonable()
    {
        // While not specified in RFC, we use a reasonable limit
        Assert.Equal(256UL, QuicLimits.MaxAckRanges);
        Assert.True(QuicLimits.MaxAckRanges > 0);
        Assert.True(QuicLimits.MaxAckRanges <= QuicLimits.MaxVarInt);
    }
}