using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using Qeen.Core.Connection;

namespace Qeen.Core.Packet;

/// <summary>
/// High-performance QUIC packet writer using zero-allocation techniques
/// </summary>
public ref struct QuicPacketWriter
{
    private Span<byte> _buffer;
    private int _position;

    /// <summary>
    /// Gets the current position in the buffer
    /// </summary>
    public readonly int Position => _position;

    /// <summary>
    /// Gets the remaining space in the buffer
    /// </summary>
    public readonly int Remaining => _buffer.Length - _position;

    /// <summary>
    /// Gets the written bytes
    /// </summary>
    public readonly ReadOnlySpan<byte> Written => _buffer.Slice(0, _position);

    /// <summary>
    /// Creates a new QuicPacketWriter
    /// </summary>
    public QuicPacketWriter(Span<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    /// <summary>
    /// Writes an Initial packet
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteInitialPacket(
        ReadOnlySpan<byte> destConnId,
        ReadOnlySpan<byte> srcConnId,
        uint version,
        long packetNumber,
        ReadOnlySpan<byte> token,
        int payloadLength)
    {
        if (destConnId.Length > ConnectionId.MaxLength || srcConnId.Length > ConnectionId.MaxLength)
            throw new ArgumentException("Connection ID too long");

        // Calculate packet number length
        int pnLength = GetPacketNumberLength(packetNumber);

        // First byte: long header (1) + fixed bit (1) + Initial type (00) + reserved (00) + packet number length
        // RFC 9000: Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Type-Specific Bits (2) | Packet Number Length (2)
        byte firstByte = (byte)(0x80 | 0x40 | (0x00 << 4) | ((pnLength - 1) & 0x03));
        WriteByte(firstByte);

        // Version
        WriteUInt32(version);

        // Destination Connection ID
        WriteByte((byte)destConnId.Length);
        WriteBytes(destConnId);

        // Source Connection ID
        WriteByte((byte)srcConnId.Length);
        WriteBytes(srcConnId);

        // Token
        WriteVariableLength(token.Length);
        if (token.Length > 0)
        {
            WriteBytes(token);
        }

        // Length (includes packet number and payload)
        WriteVariableLength(pnLength + payloadLength);

        // Mark where packet number will be written
        // The actual packet number will be written after header protection
    }

    /// <summary>
    /// Writes a Handshake packet
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteHandshakePacket(
        ReadOnlySpan<byte> destConnId,
        ReadOnlySpan<byte> srcConnId,
        uint version,
        long packetNumber,
        int payloadLength)
    {
        if (destConnId.Length > ConnectionId.MaxLength || srcConnId.Length > ConnectionId.MaxLength)
            throw new ArgumentException("Connection ID too long");

        // Calculate packet number length
        int pnLength = GetPacketNumberLength(packetNumber);

        // First byte: long header (1) + fixed bit (1) + Handshake type (10) + reserved (00) + packet number length
        // RFC 9000: Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Type-Specific Bits (2) | Packet Number Length (2)
        byte firstByte = (byte)(0x80 | 0x40 | (0x02 << 4) | ((pnLength - 1) & 0x03));
        WriteByte(firstByte);

        // Version
        WriteUInt32(version);

        // Destination Connection ID
        WriteByte((byte)destConnId.Length);
        WriteBytes(destConnId);

        // Source Connection ID
        WriteByte((byte)srcConnId.Length);
        WriteBytes(srcConnId);

        // Length (includes packet number and payload)
        WriteVariableLength(pnLength + payloadLength);
    }

    /// <summary>
    /// Writes a short header (1-RTT) packet
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteShortHeaderPacket(
        ReadOnlySpan<byte> destConnId,
        long packetNumber,
        byte keyPhase = 0)
    {
        if (destConnId.Length > ConnectionId.MaxLength)
            throw new ArgumentException("Connection ID too long");

        // Calculate packet number length
        int pnLength = GetPacketNumberLength(packetNumber);

        // First byte: short header (0) + fixed bit (1) + spin bit (0) + reserved (00) + key phase + packet number length
        byte firstByte = (byte)(0x40 | ((keyPhase & 0x01) << 2) | ((pnLength - 1) & 0x03));
        WriteByte(firstByte);

        // Destination Connection ID
        WriteBytes(destConnId);

        // Packet number will be written after this
    }

    /// <summary>
    /// Writes a Retry packet
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteRetryPacket(
        ReadOnlySpan<byte> destConnId,
        ReadOnlySpan<byte> srcConnId,
        ReadOnlySpan<byte> originalDestConnId,
        uint version,
        ReadOnlySpan<byte> retryToken,
        ReadOnlySpan<byte> retryIntegrityTag = default)
    {
        if (destConnId.Length > ConnectionId.MaxLength || srcConnId.Length > ConnectionId.MaxLength)
            throw new ArgumentException("Connection ID too long");

        // First byte: long header (1) + fixed bit (1) + Retry type (11) + unused (0000)
        // RFC 9000: Header Form (1) | Fixed Bit (1) | Long Packet Type (2) | Unused (4)
        byte firstByte = (byte)(0x80 | 0x40 | (0x03 << 4));
        WriteByte(firstByte);

        // Version
        WriteUInt32(version);

        // Destination Connection ID (client's source connection ID)
        WriteByte((byte)destConnId.Length);
        WriteBytes(destConnId);

        // Source Connection ID (server's new connection ID)
        WriteByte((byte)srcConnId.Length);
        WriteBytes(srcConnId);

        // Retry Token
        WriteBytes(retryToken);

        // Retry Integrity Tag (if provided)
        if (!retryIntegrityTag.IsEmpty)
        {
            WriteBytes(retryIntegrityTag);
        }
    }

    /// <summary>
    /// Writes packet number with specified length
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WritePacketNumber(long packetNumber, int length)
    {
        switch (length)
        {
            case 1:
                WriteByte((byte)packetNumber);
                break;
            case 2:
                WriteUInt16((ushort)packetNumber);
                break;
            case 3:
                WriteByte((byte)(packetNumber >> 16));
                WriteByte((byte)(packetNumber >> 8));
                WriteByte((byte)packetNumber);
                break;
            case 4:
                WriteUInt32((uint)packetNumber);
                break;
            default:
                throw new ArgumentException("Invalid packet number length");
        }
    }

    /// <summary>
    /// Writes a single byte
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void WriteByte(byte value)
    {
        if (_position >= _buffer.Length)
            throw new InvalidOperationException("Buffer overflow");

        _buffer[_position++] = value;
    }

    /// <summary>
    /// Writes a 16-bit unsigned integer in big-endian
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void WriteUInt16(ushort value)
    {
        if (_position + 2 > _buffer.Length)
            throw new InvalidOperationException("Buffer overflow");

        BinaryPrimitives.WriteUInt16BigEndian(_buffer.Slice(_position), value);
        _position += 2;
    }

    /// <summary>
    /// Writes a 32-bit unsigned integer in big-endian
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void WriteUInt32(uint value)
    {
        if (_position + 4 > _buffer.Length)
            throw new InvalidOperationException("Buffer overflow");

        BinaryPrimitives.WriteUInt32BigEndian(_buffer.Slice(_position), value);
        _position += 4;
    }

    /// <summary>
    /// Writes bytes
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        if (_position + bytes.Length > _buffer.Length)
            throw new InvalidOperationException("Buffer overflow");

        bytes.CopyTo(_buffer.Slice(_position));
        _position += bytes.Length;
    }

    /// <summary>
    /// Writes a variable-length integer
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void WriteVariableLength(long value)
    {
        PacketProcessor.EncodeVariableLength(value, _buffer.Slice(_position), out int bytesWritten);
        _position += bytesWritten;
    }

    /// <summary>
    /// Gets the required packet number length
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetPacketNumberLength(long packetNumber)
    {
        if (packetNumber <= 0xFF) return 1;
        if (packetNumber <= 0xFFFF) return 2;
        if (packetNumber <= 0xFFFFFF) return 3;
        return 4;
    }

    /// <summary>
    /// Resets the writer to the beginning
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset()
    {
        _position = 0;
    }

    /// <summary>
    /// Advances the position
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Advance(int count)
    {
        if (count < 0 || _position + count > _buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(count));

        _position += count;
    }

    /// <summary>
    /// Gets the buffer slice from current position
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Span<byte> GetSpan(int sizeHint = 0)
    {
        if (_position >= _buffer.Length)
            return Span<byte>.Empty;

        int available = _buffer.Length - _position;
        if (sizeHint > 0 && sizeHint <= available)
            return _buffer.Slice(_position, sizeHint);

        return _buffer.Slice(_position);
    }
}