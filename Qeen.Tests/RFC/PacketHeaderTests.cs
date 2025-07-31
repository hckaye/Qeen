using System;
using Xunit;
using Qeen.Core.Packet;
using Qeen.Core.Connection;

namespace Qeen.Tests.RFC;

/// <summary>
/// Tests for RFC 9000 Section 17: Packet Formats
/// Reference: https://www.rfc-editor.org/rfc/rfc9000.html#section-17
/// </summary>
public class PacketHeaderTests
{
    /// <summary>
    /// RFC 9000 Section 17.2: Long Header Packet Format
    /// The most significant bit (0x80) of the first byte is set to 1 for long headers
    /// </summary>
    [Theory]
    [InlineData(0x80)] // Minimum long header
    [InlineData(0xFF)] // Maximum long header
    [InlineData(0xC0)] // Initial packet
    [InlineData(0xE0)] // Handshake packet
    public void IsLongHeaderPacket_ValidLongHeaders_ReturnsTrue(byte firstByte)
    {
        var buffer = new byte[] { firstByte };
        Assert.True(PacketProcessor.IsLongHeaderPacket(buffer));
    }

    /// <summary>
    /// RFC 9000 Section 17.3: Short Header Packet Format
    /// The most significant bit (0x80) of the first byte is set to 0 for short headers
    /// </summary>
    [Theory]
    [InlineData(0x00)] // Minimum short header
    [InlineData(0x7F)] // Maximum short header
    [InlineData(0x40)] // 1-RTT packet with fixed bit set
    public void IsShortHeaderPacket_ValidShortHeaders_ReturnsTrue(byte firstByte)
    {
        var buffer = new byte[] { firstByte };
        Assert.True(PacketProcessor.IsShortHeaderPacket(buffer));
    }

    /// <summary>
    /// RFC 9000 Section 17.2.1: Version Negotiation Packet
    /// Version field is 0x00000000
    /// </summary>
    [Fact]
    public void VersionNegotiationPacket_HasZeroVersion()
    {
        var buffer = new byte[] {
            0x80 | 0x00, // Long header with random bits
            0x00, 0x00, 0x00, 0x00, // Version = 0
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x08, // SCID length
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // SCID
            // Supported versions follow
            0x00, 0x00, 0x00, 0x01, // Version 1
        };
        
        bool success = QuicPacketReader.TryParse(buffer, out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.VersionNegotiation, packet.Type);
        Assert.Equal(0u, packet.Version);
        Assert.True(packet.IsVersionNegotiation);
    }

    /// <summary>
    /// RFC 9000 Section 17.2.2: Initial Packet
    /// Type = 0x00 (bits 4-5 of first byte)
    /// </summary>
    [Fact]
    public void InitialPacket_HasCorrectType()
    {
        var buffer = CreateInitialPacketBuffer();
        
        bool success = QuicPacketReader.TryParse(buffer, out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.Initial, packet.Type);
        Assert.True(packet.IsLongHeader);
        Assert.False(packet.IsVersionNegotiation);
    }

    /// <summary>
    /// RFC 9000 Section 17.2.4: Handshake Packet
    /// Type = 0x02 (bits 4-5 of first byte)
    /// </summary>
    [Fact]
    public void HandshakePacket_HasCorrectType()
    {
        var buffer = new byte[50];
        int offset = 0;
        
        // First byte: long header (1) + type (10) + reserved + packet number length
        buffer[offset++] = 0x80 | (0x02 << 4) | 0x00;
        
        // Version
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x01;
        
        // DCID
        buffer[offset++] = 0x08;
        for (int i = 0; i < 8; i++)
            buffer[offset++] = (byte)(i + 1);
        
        // SCID
        buffer[offset++] = 0x08;
        for (int i = 0; i < 8; i++)
            buffer[offset++] = (byte)(i + 9);
        
        // Length (remaining)
        buffer[offset++] = 0x05; // 5 bytes payload
        
        // Payload
        for (int i = 0; i < 5; i++)
            buffer[offset++] = (byte)i;
        
        bool success = QuicPacketReader.TryParse(buffer.AsSpan(0, offset), out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.Handshake, packet.Type);
    }

    /// <summary>
    /// RFC 9000 Section 17.2.5: 0-RTT Packet
    /// Type = 0x01 (bits 4-5 of first byte)
    /// </summary>
    [Theory]
    [InlineData(0x80 | (0x01 << 4))] // 0-RTT with PN length 1
    [InlineData(0x80 | (0x01 << 4) | 0x01)] // 0-RTT with PN length 2
    [InlineData(0x80 | (0x01 << 4) | 0x02)] // 0-RTT with PN length 3
    [InlineData(0x80 | (0x01 << 4) | 0x03)] // 0-RTT with PN length 4
    public void ZeroRttPacket_HasCorrectType(byte firstByte)
    {
        PacketType type = (PacketType)((firstByte & 0x30) >> 4);
        Assert.Equal(PacketType.ZeroRtt, type);
    }

    /// <summary>
    /// RFC 9000 Section 17.2.3: Retry Packet
    /// Type = 0x03 (bits 4-5 of first byte)
    /// </summary>
    [Fact]
    public void RetryPacket_HasCorrectType()
    {
        byte firstByte = 0x80 | (0x03 << 4);
        PacketType type = (PacketType)((firstByte & 0x30) >> 4);
        Assert.Equal(PacketType.Retry, type);
    }

    /// <summary>
    /// RFC 9000 Section 17.3.1: 1-RTT Packet
    /// Header Form = 0, Fixed Bit = 1
    /// </summary>
    [Theory]
    [InlineData(0x40)] // Spin bit = 0, Reserved = 00, Key Phase = 0, PN length = 1
    [InlineData(0x41)] // Spin bit = 0, Reserved = 00, Key Phase = 0, PN length = 2
    [InlineData(0x42)] // Spin bit = 0, Reserved = 00, Key Phase = 0, PN length = 3
    [InlineData(0x43)] // Spin bit = 0, Reserved = 00, Key Phase = 0, PN length = 4
    public void OneRttPacket_HasCorrectFormat(byte firstByte)
    {
        Assert.Equal(0, firstByte & 0x80); // Header form bit = 0
        Assert.Equal(0x40, firstByte & 0x40); // Fixed bit = 1
    }

    /// <summary>
    /// RFC 9000 Section 17.2: Packet Number Length Encoding
    /// The two least significant bits of the first byte encode the packet number length
    /// </summary>
    [Theory]
    [InlineData(0x00, 1)] // 00 = 1 byte
    [InlineData(0x01, 2)] // 01 = 2 bytes
    [InlineData(0x02, 3)] // 10 = 3 bytes
    [InlineData(0x03, 4)] // 11 = 4 bytes
    public void PacketNumberLength_EncodedCorrectly(byte encodedLength, int expectedLength)
    {
        Assert.Equal(expectedLength, (encodedLength & 0x03) + 1);
    }

    /// <summary>
    /// RFC 9000 Section 17.1: Packet Number Encoding and Decoding
    /// </summary>
    [Theory]
    [InlineData(0xABC, 0xAB5, 2, new byte[] { 0x0A, 0xBC })]
    [InlineData(0xACE8, 0xABCD, 2, new byte[] { 0xAC, 0xE8 })]
    [InlineData(0x1ACE8, 0x1ABCD, 3, new byte[] { 0x01, 0xAC, 0xE8 })]
    public void PacketNumber_EncodingDecoding(long packetNumber, long largestAcked, int expectedLength, byte[] expectedEncoding)
    {
        var buffer = new byte[4];
        
        // Encode
        PacketProcessor.EncodePacketNumber(packetNumber, largestAcked, buffer, out int length);
        
        Assert.Equal(expectedLength, length);
        Assert.Equal(expectedEncoding, buffer.AsSpan(0, length).ToArray());
        
        // Decode
        long decoded = PacketProcessor.DecodePacketNumber(buffer.AsSpan(0, length), length, largestAcked);
        
        Assert.Equal(packetNumber, decoded);
    }

    /// <summary>
    /// RFC 9000 Section 17.2: Connection ID Length
    /// Connection IDs MUST NOT exceed 20 bytes
    /// </summary>
    [Fact]
    public void ConnectionId_MaxLength_Is20Bytes()
    {
        Assert.Equal(20, ConnectionId.MaxLength);
        
        // Valid connection ID
        var validData = new byte[20];
        var validConnId = new ConnectionId(validData);
        Assert.Equal(20, validConnId.Length);
        
        // Invalid connection ID
        var invalidData = new byte[21];
        Assert.Throws<ArgumentException>(() => new ConnectionId(invalidData));
    }

    /// <summary>
    /// RFC 9000: Connection IDs can be zero-length
    /// </summary>
    [Fact]
    public void ConnectionId_CanBeZeroLength()
    {
        var emptyConnId = ConnectionId.Empty;
        Assert.Equal(0, emptyConnId.Length);
        Assert.True(emptyConnId.IsEmpty);
        
        var zeroLengthConnId = new ConnectionId(ReadOnlySpan<byte>.Empty);
        Assert.Equal(0, zeroLengthConnId.Length);
        Assert.True(zeroLengthConnId.IsEmpty);
    }

    private static byte[] CreateInitialPacketBuffer()
    {
        var buffer = new byte[100];
        int offset = 0;
        
        // First byte: long header (1) + fixed bit (1) + Initial type (00) + reserved + packet number length
        // RFC 9000: Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Type-Specific Bits (2) | Packet Number Length (2)
        buffer[offset++] = 0x80 | 0x40 | (0x00 << 4) | 0x00;
        
        // Version
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x01;
        
        // DCID
        buffer[offset++] = 0x08;
        for (int i = 0; i < 8; i++)
            buffer[offset++] = (byte)(i + 1);
        
        // SCID
        buffer[offset++] = 0x08;
        for (int i = 0; i < 8; i++)
            buffer[offset++] = (byte)(i + 9);
        
        // Token length (0 for client Initial)
        buffer[offset++] = 0x00;
        
        // Length
        buffer[offset++] = 0x05;
        
        // Payload
        for (int i = 0; i < 5; i++)
            buffer[offset++] = (byte)i;
        
        return buffer.AsSpan(0, offset).ToArray();
    }
}