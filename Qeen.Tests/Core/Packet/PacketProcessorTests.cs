using System;
using Xunit;
using Qeen.Core.Packet;

namespace Qeen.Tests.Core.Packet;

public class PacketProcessorTests
{
    [Theory]
    [InlineData(0, new byte[] { 0x00 }, 1)]
    [InlineData(63, new byte[] { 0x3F }, 1)]
    [InlineData(64, new byte[] { 0x40, 0x40 }, 2)]
    [InlineData(16383, new byte[] { 0x7F, 0xFF }, 2)]
    [InlineData(16384, new byte[] { 0x80, 0x00, 0x40, 0x00 }, 4)]
    [InlineData(1073741823, new byte[] { 0xBF, 0xFF, 0xFF, 0xFF }, 4)]
    [InlineData(1073741824, new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }, 8)]
    public void EncodeVariableLength_EncodesCorrectly(long value, byte[] expected, int expectedLength)
    {
        Span<byte> buffer = stackalloc byte[8];
        
        PacketProcessor.EncodeVariableLength(value, buffer, out int bytesWritten);
        
        Assert.Equal(expectedLength, bytesWritten);
        Assert.True(buffer.Slice(0, bytesWritten).SequenceEqual(expected));
    }

    [Fact]
    public void EncodeVariableLength_WithNegativeValue_ThrowsException()
    {
        var buffer = new byte[8];
        
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            PacketProcessor.EncodeVariableLength(-1, buffer, out _));
    }

    [Fact]
    public void EncodeVariableLength_WithTooLargeValue_ThrowsException()
    {
        var buffer = new byte[8];
        long tooLarge = 0x4000000000000000; // Exceeds 62-bit limit
        
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            PacketProcessor.EncodeVariableLength(tooLarge, buffer, out _));
    }

    [Fact]
    public void EncodeVariableLength_WithSmallBuffer_ThrowsException()
    {
        var buffer = new byte[1];
        
        Assert.Throws<ArgumentException>(() => 
            PacketProcessor.EncodeVariableLength(16384, buffer, out _)); // Needs 4 bytes
    }

    [Theory]
    [InlineData(new byte[] { 0x00 }, 0, 1)]
    [InlineData(new byte[] { 0x3F }, 63, 1)]
    [InlineData(new byte[] { 0x40, 0x40 }, 64, 2)]
    [InlineData(new byte[] { 0x7F, 0xFF }, 16383, 2)]
    [InlineData(new byte[] { 0x80, 0x00, 0x40, 0x00 }, 16384, 4)]
    [InlineData(new byte[] { 0xBF, 0xFF, 0xFF, 0xFF }, 1073741823, 4)]
    [InlineData(new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }, 1073741824, 8)]
    public void DecodeVariableLength_DecodesCorrectly(byte[] encoded, long expectedValue, int expectedBytesRead)
    {
        bool success = PacketProcessor.DecodeVariableLength(encoded, out long value, out int bytesRead);
        
        Assert.True(success);
        Assert.Equal(expectedValue, value);
        Assert.Equal(expectedBytesRead, bytesRead);
    }

    [Fact]
    public void DecodeVariableLength_WithEmptyBuffer_ReturnsFalse()
    {
        bool success = PacketProcessor.DecodeVariableLength(ReadOnlySpan<byte>.Empty, out _, out _);
        
        Assert.False(success);
    }

    [Theory]
    [InlineData(new byte[] { 0x40 })] // 2-byte encoding but only 1 byte
    [InlineData(new byte[] { 0x80, 0x00, 0x00 })] // 4-byte encoding but only 3 bytes
    [InlineData(new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })] // 8-byte encoding but only 7 bytes
    public void DecodeVariableLength_WithIncompleteBuffer_ReturnsFalse(byte[] incomplete)
    {
        bool success = PacketProcessor.DecodeVariableLength(incomplete, out _, out _);
        
        Assert.False(success);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(63, 1)]
    [InlineData(64, 2)]
    [InlineData(16383, 2)]
    [InlineData(16384, 4)]
    [InlineData(1073741823, 4)]
    [InlineData(1073741824, 8)]
    [InlineData(4611686018427387903, 8)]
    public void GetVariableLengthSize_ReturnsCorrectSize(long value, int expectedSize)
    {
        int size = PacketProcessor.GetVariableLengthSize(value);
        
        Assert.Equal(expectedSize, size);
    }

    [Fact]
    public void GetVariableLengthSize_WithNegativeValue_ThrowsException()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => 
            PacketProcessor.GetVariableLengthSize(-1));
    }

    [Theory]
    [InlineData(new byte[] { 0x80 }, true)] // Long header bit set
    [InlineData(new byte[] { 0xC0 }, true)] // Long header bit set
    [InlineData(new byte[] { 0x40 }, false)] // Short header
    [InlineData(new byte[] { 0x00 }, false)] // Short header
    public void IsLongHeaderPacket_DetectsCorrectly(byte[] buffer, bool expected)
    {
        bool isLong = PacketProcessor.IsLongHeaderPacket(buffer);
        
        Assert.Equal(expected, isLong);
    }

    [Fact]
    public void IsLongHeaderPacket_WithEmptyBuffer_ReturnsFalse()
    {
        bool isLong = PacketProcessor.IsLongHeaderPacket(ReadOnlySpan<byte>.Empty);
        
        Assert.False(isLong);
    }

    [Theory]
    [InlineData(new byte[] { 0x40 }, true)] // Short header
    [InlineData(new byte[] { 0x7F }, true)] // Short header
    [InlineData(new byte[] { 0x80 }, false)] // Long header
    [InlineData(new byte[] { 0xFF }, false)] // Long header
    public void IsShortHeaderPacket_DetectsCorrectly(byte[] buffer, bool expected)
    {
        bool isShort = PacketProcessor.IsShortHeaderPacket(buffer);
        
        Assert.Equal(expected, isShort);
    }

    [Theory]
    [InlineData(0x80, PacketType.Initial)] // 10000000 -> type 00
    [InlineData(0x90, PacketType.ZeroRtt)] // 10010000 -> type 01
    [InlineData(0xA0, PacketType.Handshake)] // 10100000 -> type 10
    [InlineData(0xB0, PacketType.Retry)] // 10110000 -> type 11
    public void GetLongHeaderPacketType_ExtractsCorrectType(byte firstByte, PacketType expected)
    {
        PacketType type = PacketProcessor.GetLongHeaderPacketType(firstByte);
        
        Assert.Equal(expected, type);
    }

    [Fact]
    public void GetLongHeaderPacketType_WithShortHeader_ThrowsException()
    {
        Assert.Throws<ArgumentException>(() => 
            PacketProcessor.GetLongHeaderPacketType(0x40)); // Short header
    }

    [Theory]
    [InlineData(100, 50, 1, new byte[] { 100 })]
    [InlineData(500, 100, 2, new byte[] { 0x01, 0xF4 })]
    [InlineData(100000, 50000, 3, new byte[] { 0x01, 0x86, 0xA0 })]
    [InlineData(16777216, 0, 4, new byte[] { 0x01, 0x00, 0x00, 0x00 })]
    public void EncodePacketNumber_EncodesCorrectly(long packetNumber, long largestAcked, int expectedLength, byte[] expectedBytes)
    {
        Span<byte> buffer = stackalloc byte[4];
        
        PacketProcessor.EncodePacketNumber(packetNumber, largestAcked, buffer, out int length);
        
        Assert.Equal(expectedLength, length);
        Assert.True(buffer.Slice(0, length).SequenceEqual(expectedBytes));
    }

    [Theory]
    [InlineData(new byte[] { 0x42 }, 1, 100, 66)] // 0x42 = 66
    [InlineData(new byte[] { 0x01, 0xF4 }, 2, 400, 500)] // 0x01F4 = 500
    [InlineData(new byte[] { 0x01, 0x86, 0xA0 }, 3, 99000, 100000)]
    [InlineData(new byte[] { 0x01, 0x00, 0x00, 0x00 }, 4, 16000000, 16777216)]
    public void DecodePacketNumber_DecodesCorrectly(byte[] encoded, int length, long largestPacketNumber, long expected)
    {
        long decoded = PacketProcessor.DecodePacketNumber(encoded, length, largestPacketNumber);
        
        Assert.Equal(expected, decoded);
    }

    [Fact]
    public void DecodePacketNumber_WithInvalidLength_ThrowsException()
    {
        byte[] encoded = new byte[] { 0x42 };
        
        Assert.Throws<ArgumentException>(() => 
            PacketProcessor.DecodePacketNumber(encoded, 5, 100)); // Invalid length
    }

    [Fact]
    public void VariableLength_RoundTrip()
    {
        long[] testValues = { 0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903 };
        var buffer = new byte[8];
        
        foreach (var value in testValues)
        {
            // Encode
            PacketProcessor.EncodeVariableLength(value, buffer, out int bytesWritten);
            
            // Decode
            bool success = PacketProcessor.DecodeVariableLength(buffer.AsSpan(0, bytesWritten), out long decoded, out int bytesRead);
            
            Assert.True(success);
            Assert.Equal(value, decoded);
            Assert.Equal(bytesWritten, bytesRead);
        }
    }
}