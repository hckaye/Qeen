using System;
using Xunit;
using Qeen.Core.Packet;

namespace Qeen.Tests.RFC;

/// <summary>
/// Tests for RFC 9000 Section 16: Variable-Length Integer Encoding
/// Reference: https://www.rfc-editor.org/rfc/rfc9000.html#section-16
/// </summary>
public class VariableLengthEncodingTests
{
    /// <summary>
    /// RFC 9000 Section 16: Examples of encoded values
    /// </summary>
    [Theory]
    [InlineData(0x00, new byte[] { 0x00 })]
    [InlineData(0x25, new byte[] { 0x25 })]
    [InlineData(0x3F, new byte[] { 0x3F })]
    [InlineData(0x40, new byte[] { 0x40, 0x40 })]
    [InlineData(0x3FFF, new byte[] { 0x7F, 0xFF })]
    [InlineData(0x4000, new byte[] { 0x80, 0x00, 0x40, 0x00 })]
    [InlineData(0x3FFFFFFF, new byte[] { 0xBF, 0xFF, 0xFF, 0xFF })]
    [InlineData(0x40000000, new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 })]
    [InlineData(0x3FFFFFFFFFFFFFFF, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF })]
    public void EncodeVariableLength_RFC9000_Examples(long value, byte[] expected)
    {
        var buffer = new byte[8];
        
        PacketProcessor.EncodeVariableLength(value, buffer, out int bytesWritten);
        
        Assert.Equal(expected.Length, bytesWritten);
        Assert.Equal(expected, buffer.AsSpan(0, bytesWritten).ToArray());
    }

    /// <summary>
    /// RFC 9000 Section 16: Decoding examples
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C }, 151288809941952652)]
    [InlineData(new byte[] { 0x9D, 0x7F, 0x3E, 0x7D }, 494878333)]
    [InlineData(new byte[] { 0x7B, 0xBD }, 15293)]
    [InlineData(new byte[] { 0x25 }, 37)]
    [InlineData(new byte[] { 0x40, 0x25 }, 37)] // 2-byte encoding of 37
    public void DecodeVariableLength_RFC9000_Examples(byte[] encoded, long expected)
    {
        bool success = PacketProcessor.DecodeVariableLength(encoded, out long value, out int bytesRead);
        
        Assert.True(success);
        Assert.Equal(expected, value);
        Assert.Equal(encoded.Length, bytesRead);
    }

    /// <summary>
    /// RFC 9000 Section 16.1: QUIC packet numbers and lengths are encoded using 
    /// the least significant bits of the encoded value
    /// </summary>
    [Theory]
    [InlineData(0xAA, new byte[] { 0xAA })]
    [InlineData(0x1234, new byte[] { 0x52, 0x34 })]
    [InlineData(0x123456, new byte[] { 0x80, 0x12, 0x34, 0x56 })]
    [InlineData(0x12345678, new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78 })]
    public void EncodeVariableLength_PreservesLeastSignificantBits(long value, byte[] expected)
    {
        var buffer = new byte[8];
        
        PacketProcessor.EncodeVariableLength(value, buffer, out int bytesWritten);
        
        Assert.Equal(expected.Length, bytesWritten);
        Assert.Equal(expected, buffer.AsSpan(0, bytesWritten).ToArray());
    }

    /// <summary>
    /// RFC 9000: Maximum values for each encoding length
    /// </summary>
    [Theory]
    [InlineData(1, 63)]
    [InlineData(2, 16383)]
    [InlineData(4, 1073741823)]
    [InlineData(8, 4611686018427387903)]
    public void GetVariableLengthSize_MaximumValues(int expectedSize, long maxValue)
    {
        int size = PacketProcessor.GetVariableLengthSize(maxValue);
        Assert.Equal(expectedSize, size);
        
        // Verify encoding/decoding works for max values
        var buffer = new byte[8];
        PacketProcessor.EncodeVariableLength(maxValue, buffer, out int bytesWritten);
        Assert.Equal(expectedSize, bytesWritten);
        
        bool success = PacketProcessor.DecodeVariableLength(buffer.AsSpan(0, bytesWritten), out long decoded, out int bytesRead);
        Assert.True(success);
        Assert.Equal(maxValue, decoded);
        Assert.Equal(expectedSize, bytesRead);
    }

    /// <summary>
    /// RFC 9000: Values exceeding maximum should fail
    /// </summary>
    [Fact]
    public void EncodeVariableLength_ExceedsMaximum_Throws()
    {
        long tooLarge = 0x4000000000000000; // 2^62, exceeds maximum
        var buffer = new byte[8];
        
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PacketProcessor.EncodeVariableLength(tooLarge, buffer, out _));
    }

    /// <summary>
    /// RFC 9000: Negative values are not allowed
    /// </summary>
    [Fact]
    public void EncodeVariableLength_NegativeValue_Throws()
    {
        var buffer = new byte[8];
        
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            PacketProcessor.EncodeVariableLength(-1, buffer, out _));
    }

    /// <summary>
    /// RFC 9000: Incomplete encodings should fail to decode
    /// </summary>
    [Theory]
    [InlineData(new byte[] { 0x40 })] // 2-byte encoding, but only 1 byte
    [InlineData(new byte[] { 0x80, 0x00 })] // 4-byte encoding, but only 2 bytes
    [InlineData(new byte[] { 0xC0, 0x00, 0x00, 0x00 })] // 8-byte encoding, but only 4 bytes
    public void DecodeVariableLength_IncompleteEncoding_Fails(byte[] incomplete)
    {
        bool success = PacketProcessor.DecodeVariableLength(incomplete, out _, out _);
        Assert.False(success);
    }

    /// <summary>
    /// Test round-trip encoding/decoding for various values
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(16383)]
    [InlineData(16384)]
    [InlineData(1073741823)]
    [InlineData(1073741824)]
    [InlineData(4611686018427387903)]
    public void VariableLength_RoundTrip(long value)
    {
        var buffer = new byte[8];
        
        // Encode
        PacketProcessor.EncodeVariableLength(value, buffer, out int bytesWritten);
        
        // Decode
        bool success = PacketProcessor.DecodeVariableLength(buffer.AsSpan(0, bytesWritten), out long decoded, out int bytesRead);
        
        Assert.True(success);
        Assert.Equal(value, decoded);
        Assert.Equal(bytesWritten, bytesRead);
    }
}