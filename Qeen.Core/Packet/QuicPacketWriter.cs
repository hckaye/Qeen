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

    int pnLength = GetPacketNumberLength(packetNumber);

    // 1: firstByte, 4: version, 1: DCID len, DCID, 1: SCID len, SCID
    int headerLen = 1 + 4 + 1 + destConnId.Length + 1 + srcConnId.Length;
    int tokenLenBytes = PacketProcessor.GetVariableLengthSize(token.Length);
    int payloadLenBytes = PacketProcessor.GetVariableLengthSize(pnLength + payloadLength);
    int totalLen = headerLen + tokenLenBytes + token.Length + payloadLenBytes;

    if (_position + totalLen > _buffer.Length)
        throw new InvalidOperationException("Buffer overflow");

    var span = _buffer.Slice(_position, totalLen);
    int offset = 0;

    span[offset++] = (byte)(0x80 | 0x40 | (0x00 << 4) | ((pnLength - 1) & 0x03));
    BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), version);
    offset += 4;

    span[offset++] = (byte)destConnId.Length;
    destConnId.CopyTo(span.Slice(offset, destConnId.Length));
    offset += destConnId.Length;

    span[offset++] = (byte)srcConnId.Length;
    srcConnId.CopyTo(span.Slice(offset, srcConnId.Length));
    offset += srcConnId.Length;

    PacketProcessor.EncodeVariableLength(token.Length, span.Slice(offset), out int tokenLenWritten);
    offset += tokenLenWritten;
    if (token.Length > 0)
    {
        token.CopyTo(span.Slice(offset, token.Length));
        offset += token.Length;
    }

    PacketProcessor.EncodeVariableLength(pnLength + payloadLength, span.Slice(offset), out int payloadLenWritten);
    offset += payloadLenWritten;

    _position += totalLen;
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

    int pnLength = GetPacketNumberLength(packetNumber);

    int headerLen = 1 + 4 + 1 + destConnId.Length + 1 + srcConnId.Length;
    int payloadLenBytes = PacketProcessor.GetVariableLengthSize(pnLength + payloadLength);
    int totalLen = headerLen + payloadLenBytes;

    if (_position + totalLen > _buffer.Length)
        throw new InvalidOperationException("Buffer overflow");

    var span = _buffer.Slice(_position, totalLen);
    int offset = 0;

    span[offset++] = (byte)(0x80 | 0x40 | (0x02 << 4) | ((pnLength - 1) & 0x03));
    BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), version);
    offset += 4;

    span[offset++] = (byte)destConnId.Length;
    destConnId.CopyTo(span.Slice(offset, destConnId.Length));
    offset += destConnId.Length;

    span[offset++] = (byte)srcConnId.Length;
    srcConnId.CopyTo(span.Slice(offset, srcConnId.Length));
    offset += srcConnId.Length;

    PacketProcessor.EncodeVariableLength(pnLength + payloadLength, span.Slice(offset), out int payloadLenWritten);
    offset += payloadLenWritten;

    _position += totalLen;
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

    int pnLength = GetPacketNumberLength(packetNumber);

    int totalLen = 1 + destConnId.Length;
    if (_position + totalLen > _buffer.Length)
        throw new InvalidOperationException("Buffer overflow");

    var span = _buffer.Slice(_position, totalLen);
    int offset = 0;

    span[offset++] = (byte)(0x40 | ((keyPhase & 0x01) << 2) | ((pnLength - 1) & 0x03));
    destConnId.CopyTo(span.Slice(offset, destConnId.Length));
    offset += destConnId.Length;

    _position += totalLen;
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

    int headerLen = 1 + 4 + 1 + destConnId.Length + 1 + srcConnId.Length + retryToken.Length + retryIntegrityTag.Length;
    if (_position + headerLen > _buffer.Length)
        throw new InvalidOperationException("Buffer overflow");

    var span = _buffer.Slice(_position, headerLen);
    int offset = 0;

    span[offset++] = (byte)(0x80 | 0x40 | (0x03 << 4));
    BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), version);
    offset += 4;

    span[offset++] = (byte)destConnId.Length;
    destConnId.CopyTo(span.Slice(offset, destConnId.Length));
    offset += destConnId.Length;

    span[offset++] = (byte)srcConnId.Length;
    srcConnId.CopyTo(span.Slice(offset, srcConnId.Length));
    offset += srcConnId.Length;

    if (retryToken.Length > 0)
    {
        retryToken.CopyTo(span.Slice(offset, retryToken.Length));
        offset += retryToken.Length;
    }

    if (retryIntegrityTag.Length > 0)
    {
        retryIntegrityTag.CopyTo(span.Slice(offset, retryIntegrityTag.Length));
        offset += retryIntegrityTag.Length;
    }

    _position += headerLen;
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
    {
        Span<byte> span = _buffer.Slice(_position, 1);
        span[0] = (byte)packetNumber;
        _position += 1;
    }
    break;
case 2:
    {
        Span<byte> span = _buffer.Slice(_position, 2);
        span[0] = (byte)(packetNumber >> 8);
        span[1] = (byte)packetNumber;
        _position += 2;
    }
    break;
case 3:
    {
        Span<byte> span = _buffer.Slice(_position, 3);
        span[0] = (byte)(packetNumber >> 16);
        span[1] = (byte)(packetNumber >> 8);
        span[2] = (byte)packetNumber;
        _position += 3;
    }
    break;
case 4:
    {
        Span<byte> span = _buffer.Slice(_position, 4);
        span[0] = (byte)(packetNumber >> 24);
        span[1] = (byte)(packetNumber >> 16);
        span[2] = (byte)(packetNumber >> 8);
        span[3] = (byte)packetNumber;
        _position += 4;
    }
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
