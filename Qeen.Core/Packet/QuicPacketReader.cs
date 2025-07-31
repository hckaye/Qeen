using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Qeen.Core.Connection;

namespace Qeen.Core.Packet;

/// <summary>
/// High-performance QUIC packet reader using zero-allocation techniques
/// </summary>
public readonly ref struct QuicPacketReader
{
    private readonly ReadOnlySpan<byte> _buffer;

    /// <summary>
    /// Gets the packet type
    /// </summary>
    public PacketType Type { get; }

    /// <summary>
    /// Gets the header bytes
    /// </summary>
    public ReadOnlySpan<byte> Header { get; }

    /// <summary>
    /// Gets the payload bytes (may be encrypted)
    /// </summary>
    public ReadOnlySpan<byte> Payload { get; }

    /// <summary>
    /// Gets the version (for long header packets)
    /// </summary>
    public uint Version { get; }

    /// <summary>
    /// Gets the destination connection ID
    /// </summary>
    public ReadOnlySpan<byte> DestinationConnectionId { get; }

    /// <summary>
    /// Gets the source connection ID
    /// </summary>
    public ReadOnlySpan<byte> SourceConnectionId { get; }

    /// <summary>
    /// Gets the packet number length (encoded length, not actual value)
    /// </summary>
    public int PacketNumberLength { get; }

    /// <summary>
    /// Gets the token (for Initial packets only)
    /// </summary>
    public ReadOnlySpan<byte> Token { get; }

    private QuicPacketReader(
        ReadOnlySpan<byte> buffer,
        PacketType type,
        ReadOnlySpan<byte> header,
        ReadOnlySpan<byte> payload,
        uint version,
        ReadOnlySpan<byte> destConnId,
        ReadOnlySpan<byte> srcConnId,
        int packetNumberLength,
        ReadOnlySpan<byte> token)
    {
        _buffer = buffer;
        Type = type;
        Header = header;
        Payload = payload;
        Version = version;
        DestinationConnectionId = destConnId;
        SourceConnectionId = srcConnId;
        PacketNumberLength = packetNumberLength;
        Token = token;
    }

    /// <summary>
    /// Tries to parse a QUIC packet from the buffer
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool TryParse(ReadOnlySpan<byte> buffer, out QuicPacketReader packet)
    {
        packet = default;

        if (buffer.Length < 1)
            return false;

        byte firstByte = buffer[0];
        bool isLongHeader = (firstByte & 0x80) != 0;

        if (isLongHeader)
        {
            return TryParseLongHeader(buffer, out packet);
        }
        else
        {
            return TryParseShortHeader(buffer, out packet);
        }
    }

    private static bool TryParseLongHeader(ReadOnlySpan<byte> buffer, out QuicPacketReader packet)
    {
        packet = default;

        if (buffer.Length < 7) // Minimum long header size
            return false;

        int offset = 0;
        byte firstByte = buffer[offset++];

        // Read version first to check for version negotiation
        if (buffer.Length < offset + 4)
            return false;
        uint version = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(offset));
        offset += 4;

        // Determine packet type
        PacketType type;
        if (version == 0)
        {
            // Version Negotiation packet
            type = PacketType.VersionNegotiation;
        }
        else
        {
            // Extract packet type from first byte
            type = (PacketType)((firstByte & 0x30) >> 4);
        }

        // Read destination connection ID length
        if (buffer.Length < offset + 1)
            return false;
        byte dcidLen = buffer[offset++];
        if (dcidLen > ConnectionId.MaxLength)
            return false;

        // Read destination connection ID
        if (buffer.Length < offset + dcidLen)
            return false;
        var destConnId = buffer.Slice(offset, dcidLen);
        offset += dcidLen;

        // Read source connection ID length
        if (buffer.Length < offset + 1)
            return false;
        byte scidLen = buffer[offset++];
        if (scidLen > ConnectionId.MaxLength)
            return false;

        // Read source connection ID
        if (buffer.Length < offset + scidLen)
            return false;
        var srcConnId = buffer.Slice(offset, scidLen);
        offset += scidLen;

        ReadOnlySpan<byte> token = ReadOnlySpan<byte>.Empty;
        int packetNumberLength = 0;

        // Handle type-specific fields
        switch (type)
        {
            case PacketType.Initial:
                // Read token length
                if (!PacketProcessor.DecodeVariableLength(buffer.Slice(offset), out long tokenLength, out int tokenLengthBytes))
                    return false;
                offset += tokenLengthBytes;

                // Read token
                if (tokenLength > 0)
                {
                    if (buffer.Length < offset + (int)tokenLength)
                        return false;
                    token = buffer.Slice(offset, (int)tokenLength);
                    offset += (int)tokenLength;
                }
                break;

            case PacketType.Retry:
                // Retry packets have a different format
                if (buffer.Length < offset + 16) // Retry integrity tag
                    return false;
                packet = new QuicPacketReader(
                    buffer,
                    type,
                    buffer.Slice(0, buffer.Length - 16),
                    buffer.Slice(buffer.Length - 16), // The payload is the integrity tag
                    version,
                    destConnId,
                    srcConnId,
                    0,
                    ReadOnlySpan<byte>.Empty
                );
                return true;

            case PacketType.VersionNegotiation:
                // Version negotiation packets don't have protected payloads
                packet = new QuicPacketReader(
                    buffer,
                    type,
                    buffer.Slice(0, offset),
                    buffer.Slice(offset),
                    version,
                    destConnId,
                    srcConnId,
                    0,
                    ReadOnlySpan<byte>.Empty
                );
                return true;
        }

        // Read length for non-special packets
        if (type != PacketType.Retry && type != PacketType.VersionNegotiation)
        {
            if (!PacketProcessor.DecodeVariableLength(buffer.Slice(offset), out long payloadLength, out int lengthBytes))
                return false;
            offset += lengthBytes;

            // Packet number length is encoded in the first byte
            packetNumberLength = (firstByte & 0x03) + 1;

            // The payload includes packet number and payload
            if (buffer.Length < offset + (int)payloadLength)
                return false;

            packet = new QuicPacketReader(
                buffer,
                type,
                buffer.Slice(0, offset),
                buffer.Slice(offset, (int)payloadLength),
                version,
                destConnId,
                srcConnId,
                packetNumberLength,
                token
            );
            return true;
        }

        return false;
    }

    private static bool TryParseShortHeader(ReadOnlySpan<byte> buffer, out QuicPacketReader packet)
    {
        packet = default;

        if (buffer.Length < 2) // Minimum short header size
            return false;

        int offset = 0;
        byte firstByte = buffer[offset++];

        // Extract packet number length
        int packetNumberLength = (firstByte & 0x03) + 1;

        // Short header packets use the connection ID negotiated during handshake
        // For now, we'll assume the destination connection ID immediately follows
        // In practice, this would be determined by the connection context
        
        // For the reader, we'll just mark where the payload starts
        // The actual connection ID extraction would be done by the connection handler
        
        packet = new QuicPacketReader(
            buffer,
            PacketType.OneRtt,
            buffer.Slice(0, 1), // Just the first byte is the "header"
            buffer.Slice(1), // Rest is payload
            0, // No version in short header
            ReadOnlySpan<byte>.Empty, // Connection ID determined by context
            ReadOnlySpan<byte>.Empty, // No source connection ID
            packetNumberLength,
            ReadOnlySpan<byte>.Empty // No token
        );

        return true;
    }

    /// <summary>
    /// Checks if this is a long header packet
    /// </summary>
    public bool IsLongHeader => Type != PacketType.OneRtt;

    /// <summary>
    /// Checks if this is a version negotiation packet
    /// </summary>
    public bool IsVersionNegotiation => Type == PacketType.VersionNegotiation;

    /// <summary>
    /// Checks if this is a retry packet
    /// </summary>
    public bool IsRetry => Type == PacketType.Retry;
}