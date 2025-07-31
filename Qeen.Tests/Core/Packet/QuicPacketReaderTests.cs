using System;
using Xunit;
using Qeen.Core.Packet;
using Qeen.Core.Connection;

namespace Qeen.Tests.Core.Packet;

public class QuicPacketReaderTests
{
    [Fact]
    public void TryParse_WithEmptyBuffer_ReturnsFalse()
    {
        var buffer = ReadOnlySpan<byte>.Empty;
        
        bool success = QuicPacketReader.TryParse(buffer, out _);
        
        Assert.False(success);
    }

    [Fact]
    public void TryParse_WithShortHeaderPacket_ParsesCorrectly()
    {
        // Short header: 0x40 (0100 0000) - fixed bit set, packet number length 1
        var buffer = new byte[] { 0x40, 0x01, 0x02, 0x03, 0x04, 0x05 };
        
        bool success = QuicPacketReader.TryParse(buffer, out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.OneRtt, packet.Type);
        Assert.False(packet.IsLongHeader);
        Assert.Equal(1, packet.PacketNumberLength);
        Assert.Equal(1, packet.Header.Length);
        Assert.Equal(5, packet.Payload.Length);
    }

    [Fact]
    public void TryParse_WithInitialPacket_ParsesCorrectly()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        // Write Initial packet
        var destConnId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var srcConnId = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        var token = new byte[] { 0xAA, 0xBB, 0xCC };
        
        writer.WriteInitialPacket(destConnId, srcConnId, 0x00000001, 123, token, 10);
        // Write packet number (based on GetPacketNumberLength logic)
        writer.WritePacketNumber(123, 1);
        // Write dummy payload
        for (int i = 0; i < 10; i++)
        {
            buffer[writer.Position + i] = (byte)i;
        }
        writer.Advance(10);
        var written = writer.Written.ToArray();
        
        bool success = QuicPacketReader.TryParse(written, out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.Initial, packet.Type);
        Assert.True(packet.IsLongHeader);
        Assert.Equal(0x00000001u, packet.Version);
        Assert.True(packet.DestinationConnectionId.SequenceEqual(destConnId));
        Assert.True(packet.SourceConnectionId.SequenceEqual(srcConnId));
        Assert.True(packet.Token.SequenceEqual(token));
    }

    [Fact]
    public void TryParse_WithHandshakePacket_ParsesCorrectly()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        // Write Handshake packet
        var destConnId = new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        var srcConnId = new byte[] { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
        
        writer.WriteHandshakePacket(destConnId, srcConnId, 0x00000001, 456, 20);
        // Write packet number
        writer.WritePacketNumber(456, 2);
        // Write dummy payload
        for (int i = 0; i < 20; i++)
        {
            buffer[writer.Position + i] = (byte)i;
        }
        writer.Advance(20);
        var written = writer.Written.ToArray();
        
        bool success = QuicPacketReader.TryParse(written, out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.Handshake, packet.Type);
        Assert.True(packet.IsLongHeader);
        Assert.Equal(0x00000001u, packet.Version);
        Assert.True(packet.DestinationConnectionId.SequenceEqual(destConnId));
        Assert.True(packet.SourceConnectionId.SequenceEqual(srcConnId));
        Assert.True(packet.Token.IsEmpty); // Handshake packets don't have tokens
    }

    [Fact]
    public void TryParse_WithVersionNegotiationPacket_ParsesCorrectly()
    {
        // Version Negotiation packet format
        // First byte: 0x80 (long header) with random bits
        // Version: 0x00000000
        // Then connection IDs
        var buffer = new byte[] {
            0x80, // Long header, type bits = 00
            0x00, 0x00, 0x00, 0x00, // Version = 0
            0x04, // DCID length
            0x01, 0x02, 0x03, 0x04, // DCID
            0x04, // SCID length
            0x05, 0x06, 0x07, 0x08, // SCID
            // Supported versions follow
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02
        };
        
        bool success = QuicPacketReader.TryParse(buffer, out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.VersionNegotiation, packet.Type);
        Assert.True(packet.IsVersionNegotiation);
        Assert.Equal(0u, packet.Version);
    }

    [Fact]
    public void TryParse_WithRetryPacket_ParsesCorrectly()
    {
        var buffer = new byte[100];
        var writer = new QuicPacketWriter(buffer);
        
        // Write Retry packet
        var destConnId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var srcConnId = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        var originalDestConnId = new byte[] { 0x09, 0x0A, 0x0B, 0x0C };
        var retryToken = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        
        writer.WriteRetryPacket(destConnId, srcConnId, originalDestConnId, 0x00000001, retryToken);
        
        // Add fake integrity tag (16 bytes)
        var writtenLength = writer.Position;
        for (int i = 0; i < 16; i++)
        {
            buffer[writtenLength + i] = 0xFF;
        }
        
        var fullPacket = buffer.AsSpan(0, writtenLength + 16);
        
        bool success = QuicPacketReader.TryParse(fullPacket, out var packet);
        
        Assert.True(success);
        Assert.Equal(PacketType.Retry, packet.Type);
        Assert.True(packet.IsRetry);
        Assert.Equal(writtenLength, packet.Header.Length); // Header includes everything except integrity tag
        Assert.Equal(fullPacket.Length - writtenLength, packet.Payload.Length); // Just the retry token (without integrity tag)
    }

    [Fact]
    public void TryParse_WithInvalidConnectionIdLength_ReturnsFalse()
    {
        // Create a packet with invalid connection ID length (> 20)
        var buffer = new byte[] {
            0x80, // Long header
            0x00, 0x00, 0x00, 0x01, // Version
            21, // DCID length (invalid - max is 20)
            // Not enough data follows
        };
        
        bool success = QuicPacketReader.TryParse(buffer, out _);
        
        Assert.False(success);
    }

    [Fact]
    public void TryParse_WithIncompletePacket_ReturnsFalse()
    {
        // Start of an Initial packet but incomplete
        var buffer = new byte[] {
            0x80, // Long header, Initial type
            0x00, 0x00, 0x00, 0x01, // Version
            0x04, // DCID length
            // Missing the rest
        };
        
        bool success = QuicPacketReader.TryParse(buffer, out _);
        
        Assert.False(success);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void PacketNumberLength_ParsedCorrectly(int pnLength)
    {
        // For long header: packet number length is in bits 0-1 of first byte
        // Use Handshake packet type (0x02) to avoid token requirement
        byte firstByte = (byte)(0x80 | (0x02 << 4) | ((pnLength - 1) & 0x03));
        
        var buffer = new byte[50];
        buffer[0] = firstByte;
        buffer[1] = 0x00; // Version
        buffer[2] = 0x00;
        buffer[3] = 0x00;
        buffer[4] = 0x01;
        buffer[5] = 0x00; // DCID length (0)
        buffer[6] = 0x00; // SCID length (0)
        buffer[7] = 0x05; // Payload length (5 bytes)
        
        bool success = QuicPacketReader.TryParse(buffer, out var packet);
        
        Assert.True(success);
        Assert.Equal(pnLength, packet.PacketNumberLength);
    }

    [Fact]
    public void EmptyConnectionIds_ParsedCorrectly()
    {
        // Create packet with zero-length connection IDs
        var buffer = new byte[] {
            0x80, // Long header, Initial
            0x00, 0x00, 0x00, 0x01, // Version
            0x00, // DCID length (0)
            0x00, // SCID length (0)
            0x00, // Token length (0)
            0x05, // Payload length
            0x01, 0x02, 0x03, 0x04, 0x05 // Payload
        };
        
        bool success = QuicPacketReader.TryParse(buffer, out var packet);
        
        Assert.True(success);
        Assert.True(packet.DestinationConnectionId.IsEmpty);
        Assert.True(packet.SourceConnectionId.IsEmpty);
    }

    [Fact]
    public void MaxLengthConnectionIds_ParsedCorrectly()
    {
        // Create packet with max-length connection IDs (20 bytes each)
        var buffer = new byte[100];
        int offset = 0;
        
        buffer[offset++] = 0x80; // Long header, Initial
        
        // Version
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x01;
        
        // DCID
        buffer[offset++] = 20; // Max length
        for (int i = 0; i < 20; i++)
        {
            buffer[offset++] = (byte)(i + 1);
        }
        
        // SCID
        buffer[offset++] = 20; // Max length
        for (int i = 0; i < 20; i++)
        {
            buffer[offset++] = (byte)(i + 21);
        }
        
        // Token length (0)
        buffer[offset++] = 0x00;
        
        // Payload length
        buffer[offset++] = 0x05;
        
        // Payload
        for (int i = 0; i < 5; i++)
        {
            buffer[offset++] = (byte)(i + 41);
        }
        
        bool success = QuicPacketReader.TryParse(buffer.AsSpan(0, offset), out var packet);
        
        Assert.True(success);
        Assert.Equal(20, packet.DestinationConnectionId.Length);
        Assert.Equal(20, packet.SourceConnectionId.Length);
    }
}