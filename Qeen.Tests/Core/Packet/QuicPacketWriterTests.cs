using System;
using Xunit;
using Qeen.Core.Packet;

namespace Qeen.Tests.Core.Packet;

public class QuicPacketWriterTests
{
    [Fact]
    public void Constructor_InitializesCorrectly()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        Assert.Equal(0, writer.Position);
        Assert.Equal(100, writer.Remaining);
        Assert.True(writer.Written.IsEmpty);
    }

    [Fact]
    public void WriteInitialPacket_WritesCorrectStructure()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        var destConnId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var srcConnId = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        var token = new byte[] { 0xAA, 0xBB };
        
        writer.WriteInitialPacket(destConnId, srcConnId, 0x00000001, 123, token, 10);
        
        var written = writer.Written;
        
        // Verify first byte (long header + fixed bit + Initial type + packet number length)
        // RFC 9000: Long header (1) + Fixed bit (1) = 0xC0
        Assert.Equal(0xC0, written[0] & 0xC0); // Long header bit + fixed bit
        Assert.Equal(0x00, written[0] & 0x30); // Initial type (00)
        
        // Verify version
        Assert.Equal(0x00, written[1]);
        Assert.Equal(0x00, written[2]);
        Assert.Equal(0x00, written[3]);
        Assert.Equal(0x01, written[4]);
        
        // Verify DCID
        Assert.Equal(4, written[5]);
        Assert.Equal(0x01, written[6]);
        Assert.Equal(0x02, written[7]);
        Assert.Equal(0x03, written[8]);
        Assert.Equal(0x04, written[9]);
        
        // Verify SCID
        Assert.Equal(4, written[10]);
        Assert.Equal(0x05, written[11]);
        Assert.Equal(0x06, written[12]);
        Assert.Equal(0x07, written[13]);
        Assert.Equal(0x08, written[14]);
        
        // Token should be present
        int tokenLengthStart = 15;
        Assert.Equal(2, written[tokenLengthStart]); // Token length
        Assert.Equal(0xAA, written[tokenLengthStart + 1]);
        Assert.Equal(0xBB, written[tokenLengthStart + 2]);
    }

    [Fact]
    public void WriteHandshakePacket_WritesCorrectStructure()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        var destConnId = new byte[] { 0x11, 0x22 };
        var srcConnId = new byte[] { 0x33, 0x44, 0x55, 0x66 };
        
        writer.WriteHandshakePacket(destConnId, srcConnId, 0x00000001, 456, 20);
        
        var written = writer.Written;
        
        // Verify first byte (long header + fixed bit + Handshake type)
        // RFC 9000: Long header (1) + Fixed bit (1) + Handshake (10) = 0xE0
        Assert.Equal(0xE0, written[0] & 0xF0); // Long header + fixed bit + Handshake (10)
        
        // Verify connection IDs
        Assert.Equal(2, written[5]); // DCID length
        Assert.Equal(4, written[8]); // SCID length
    }

    [Fact]
    public void WriteShortHeaderPacket_WritesCorrectStructure()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        var destConnId = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
        
        writer.WriteShortHeaderPacket(destConnId, 789, keyPhase: 1);
        
        var written = writer.Written;
        
        // Verify first byte (short header + fixed bit + key phase)
        Assert.Equal(0x40, written[0] & 0xC0); // Short header (0) + fixed bit (1)
        Assert.Equal(0x04, written[0] & 0x04); // Key phase bit
        
        // Verify destination connection ID
        Assert.Equal(0xAA, written[1]);
        Assert.Equal(0xBB, written[2]);
        Assert.Equal(0xCC, written[3]);
        Assert.Equal(0xDD, written[4]);
    }

    [Fact]
    public void WriteRetryPacket_WritesCorrectStructure()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        var destConnId = new byte[] { 0x01, 0x02 };
        var srcConnId = new byte[] { 0x03, 0x04 };
        var originalDestConnId = new byte[] { 0x05, 0x06 };
        var retryToken = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        
        writer.WriteRetryPacket(destConnId, srcConnId, originalDestConnId, 0x00000001, retryToken);
        
        var written = writer.Written;
        
        // Verify first byte (long header + fixed bit + Retry type)
        // RFC 9000: Long header (1) + Fixed bit (1) + Retry (11) = 0xF0
        Assert.Equal(0xF0, written[0] & 0xF0); // Long header + fixed bit + Retry (11)
        
        // Verify token is at the end
        Assert.Equal(0xDE, written[written.Length - 4]);
        Assert.Equal(0xAD, written[written.Length - 3]);
        Assert.Equal(0xBE, written[written.Length - 2]);
        Assert.Equal(0xEF, written[written.Length - 1]);
    }

    [Theory]
    [InlineData(100, 1)]
    [InlineData(500, 2)]
    [InlineData(100000, 3)]
    [InlineData(16777216, 4)]
    public void WritePacketNumber_WritesCorrectBytes(long packetNumber, int length)
    {
        var buffer = new byte[10];
        var writer = new QuicPacketWriter(buffer);
        
        writer.WritePacketNumber(packetNumber, length);
        
        var written = writer.Written;
        
        Assert.Equal(length, written.Length);
        
        // Verify the packet number can be read back
        long decoded = length switch
        {
            1 => written[0],
            2 => ((uint)written[0] << 8) | written[1],
            3 => ((uint)written[0] << 16) | ((uint)written[1] << 8) | written[2],
            4 => ((long)written[0] << 24) | ((uint)written[1] << 16) | ((uint)written[2] << 8) | written[3],
            _ => throw new InvalidOperationException()
        };
        
        // Check lower bits match
        Assert.Equal(packetNumber & ((1L << (length * 8)) - 1), decoded);
    }

    [Fact]
    public void WritePacketNumber_WithInvalidLength_ThrowsException()
    {
        var buffer = new byte[10];
        
        Assert.Throws<ArgumentException>(() => 
        {
            var writer = new QuicPacketWriter(buffer);
            writer.WritePacketNumber(123, 0);
        });
        
        Assert.Throws<ArgumentException>(() => 
        {
            var writer = new QuicPacketWriter(buffer);
            writer.WritePacketNumber(123, 5);
        });
    }

    [Fact]
    public void Reset_ResetsPosition()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        writer.WritePacketNumber(123, 2);
        Assert.Equal(2, writer.Position);
        
        writer.Reset();
        Assert.Equal(0, writer.Position);
        Assert.True(writer.Written.IsEmpty);
    }

    [Fact]
    public void Advance_UpdatesPosition()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        writer.Advance(10);
        Assert.Equal(10, writer.Position);
        Assert.Equal(90, writer.Remaining);
    }

    [Fact]
    public void Advance_WithInvalidCount_ThrowsException()
    {
        var buffer = new byte[100];
        
        Assert.Throws<ArgumentOutOfRangeException>(() => 
        {
            var writer = new QuicPacketWriter(buffer);
            writer.Advance(-1);
        });
        
        Assert.Throws<ArgumentOutOfRangeException>(() => 
        {
            var writer = new QuicPacketWriter(buffer);
            writer.Advance(101);
        });
    }

    [Fact]
    public void GetSpan_ReturnsCorrectSlice()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        writer.WritePacketNumber(123, 1);
        var span = writer.GetSpan(10);
        
        Assert.Equal(10, span.Length);
        
        // Write to the span
        span[0] = 0xFF;
        
        // Advance to include the written data
        writer.Advance(1);
        
        Assert.Equal(0xFF, writer.Written[1]);
    }

    [Fact]
    public void GetSpan_AtEndOfBuffer_ReturnsEmpty()
    {
        var buffer = new byte[10];
        var writer = new QuicPacketWriter(buffer);
        
        writer.Advance(10);
        var span = writer.GetSpan();
        
        Assert.True(span.IsEmpty);
    }

    [Fact]
    public void ConnectionIdTooLong_ThrowsException()
    {
        var buffer = new byte[100];
        
        var tooLongConnId = new byte[21]; // Max is 20
        var validConnId = new byte[8];
        
        Assert.Throws<ArgumentException>(() => 
        {
            var writer = new QuicPacketWriter(buffer);
            writer.WriteInitialPacket(tooLongConnId, validConnId, 1, 123, ReadOnlySpan<byte>.Empty, 10);
        });
        
        Assert.Throws<ArgumentException>(() => 
        {
            var writer = new QuicPacketWriter(buffer);
            writer.WriteInitialPacket(validConnId, tooLongConnId, 1, 123, ReadOnlySpan<byte>.Empty, 10);
        });
    }

    [Fact]
    public void BufferOverflow_ThrowsException()
    {
        var buffer = new byte[10]; // Small buffer
        
        var destConnId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var srcConnId = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        
        // This should overflow the small buffer
        Assert.Throws<InvalidOperationException>(() => 
        {
            var writer = new QuicPacketWriter(buffer);
            writer.WriteInitialPacket(destConnId, srcConnId, 1, 123, ReadOnlySpan<byte>.Empty, 10);
        });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void KeyPhase_EncodedCorrectly(byte keyPhase)
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        var destConnId = new byte[] { 0x11, 0x22, 0x33, 0x44 };
        
        writer.WriteShortHeaderPacket(destConnId, 123, keyPhase);
        
        var written = writer.Written;
        
        // Key phase is bit 2 (0x04)
        if (keyPhase == 1)
        {
            Assert.Equal(0x04, written[0] & 0x04);
        }
        else
        {
            Assert.Equal(0x00, written[0] & 0x04);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void PacketNumberLength_EncodedInFirstByte(int pnLength)
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        var destConnId = new byte[] { 0x01, 0x02 };
        var srcConnId = new byte[] { 0x03, 0x04 };
        
        // For Initial packet, we need to determine the packet number based on pnLength
        long packetNumber = pnLength switch
        {
            1 => 100,
            2 => 500,
            3 => 100000,
            4 => 16777216,
            _ => 0
        };
        
        writer.WriteInitialPacket(destConnId, srcConnId, 1, packetNumber, ReadOnlySpan<byte>.Empty, 10);
        
        var written = writer.Written;
        
        // Packet number length is encoded in bits 0-1 of first byte
        Assert.Equal(pnLength - 1, written[0] & 0x03);
    }
}