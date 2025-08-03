using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace Qeen.Security.Tls;

public ref struct TlsWriter
{
    private Span<byte> _buffer;
    private int _position;

    public TlsWriter(Span<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    public int Position => _position;
    public int BytesWritten => _position;
    public Span<byte> Written => _buffer[.._position];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUInt8(byte value)
    {
        _buffer[_position++] = value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUInt16(ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(_buffer[_position..], value);
        _position += 2;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUInt24(uint value)
    {
        _buffer[_position++] = (byte)(value >> 16);
        _buffer[_position++] = (byte)(value >> 8);
        _buffer[_position++] = (byte)value;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUInt32(uint value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(_buffer[_position..], value);
        _position += 4;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void WriteUInt64(ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(_buffer[_position..], value);
        _position += 8;
    }

    public void WriteBytes(ReadOnlySpan<byte> data)
    {
        data.CopyTo(_buffer[_position..]);
        _position += data.Length;
    }

    public void WriteVector8(ReadOnlySpan<byte> data)
    {
        WriteUInt8((byte)data.Length);
        WriteBytes(data);
    }

    public void WriteVector16(ReadOnlySpan<byte> data)
    {
        WriteUInt16((ushort)data.Length);
        WriteBytes(data);
    }

    public void WriteVector24(ReadOnlySpan<byte> data)
    {
        WriteUInt24((uint)data.Length);
        WriteBytes(data);
    }

    public delegate void WriterAction(ref TlsWriter writer);
    
    public void WriteLengthPrefixed16(WriterAction writeContent)
    {
        var lengthPosition = _position;
        _position += 2;
        
        var contentStart = _position;
        var writer = new TlsWriter(_buffer[_position..]);
        writeContent(ref writer);
        _position += writer.BytesWritten;
        
        var length = _position - contentStart;
        BinaryPrimitives.WriteUInt16BigEndian(_buffer[lengthPosition..], (ushort)length);
    }

    public void WriteLengthPrefixed24(WriterAction writeContent)
    {
        var lengthPosition = _position;
        _position += 3;
        
        var contentStart = _position;
        var writer = new TlsWriter(_buffer[_position..]);
        writeContent(ref writer);
        _position += writer.BytesWritten;
        
        var length = (uint)(_position - contentStart);
        _buffer[lengthPosition] = (byte)(length >> 16);
        _buffer[lengthPosition + 1] = (byte)(length >> 8);
        _buffer[lengthPosition + 2] = (byte)length;
    }

    public void WriteString8(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteVector8(bytes);
    }

    public void WriteString16(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteVector16(bytes);
    }

    public void Advance(int count)
    {
        _position += count;
    }

    public Span<byte> GetSpan(int sizeHint)
    {
        return _buffer[_position..];
    }
}