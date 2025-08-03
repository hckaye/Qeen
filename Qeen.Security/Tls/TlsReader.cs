using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace Qeen.Security.Tls;

public ref struct TlsReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _position;

    public TlsReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    public int Position => _position;
    public int BytesRemaining => _buffer.Length - _position;
    public bool HasData => _position < _buffer.Length;
    public ReadOnlySpan<byte> Remaining => _buffer[_position..];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte ReadUInt8()
    {
        return _buffer[_position++];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ushort ReadUInt16()
    {
        var value = BinaryPrimitives.ReadUInt16BigEndian(_buffer[_position..]);
        _position += 2;
        return value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint ReadUInt24()
    {
        var value = (uint)(_buffer[_position] << 16 | _buffer[_position + 1] << 8 | _buffer[_position + 2]);
        _position += 3;
        return value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint ReadUInt32()
    {
        var value = BinaryPrimitives.ReadUInt32BigEndian(_buffer[_position..]);
        _position += 4;
        return value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ulong ReadUInt64()
    {
        var value = BinaryPrimitives.ReadUInt64BigEndian(_buffer[_position..]);
        _position += 8;
        return value;
    }

    public ReadOnlySpan<byte> ReadBytes(int length)
    {
        var result = _buffer.Slice(_position, length);
        _position += length;
        return result;
    }

    public ReadOnlySpan<byte> ReadVector8()
    {
        var length = ReadUInt8();
        return ReadBytes(length);
    }

    public ReadOnlySpan<byte> ReadVector16()
    {
        var length = ReadUInt16();
        return ReadBytes(length);
    }

    public ReadOnlySpan<byte> ReadVector24()
    {
        var length = (int)ReadUInt24();
        return ReadBytes(length);
    }

    public string ReadString8()
    {
        var bytes = ReadVector8();
        return Encoding.UTF8.GetString(bytes);
    }

    public string ReadString16()
    {
        var bytes = ReadVector16();
        return Encoding.UTF8.GetString(bytes);
    }

    public void Advance(int count)
    {
        _position += count;
    }

    public bool TryPeek(out byte value)
    {
        if (HasData)
        {
            value = _buffer[_position];
            return true;
        }
        value = 0;
        return false;
    }

    public TlsReader CreateLimitedReader(int length)
    {
        var data = ReadBytes(length);
        return new TlsReader(data);
    }
}