namespace Qeen.Core.Frame;

/// <summary>
/// Provides writing functionality for QUIC frames.
/// </summary>
public ref struct FrameWriter
{
    private Span<byte> _buffer;
    private int _position;
    
    /// <summary>
    /// Gets the number of bytes written.
    /// </summary>
    public readonly int BytesWritten => _position;
    
    /// <summary>
    /// Gets the remaining space in the buffer.
    /// </summary>
    public readonly int BytesRemaining => _buffer.Length - _position;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="FrameWriter"/> struct.
    /// </summary>
    /// <param name="buffer">The buffer to write to.</param>
    public FrameWriter(Span<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }
    
    /// <summary>
    /// Writes a single byte.
    /// </summary>
    /// <param name="value">The byte to write.</param>
    public void WriteByte(byte value)
    {
        if (_position >= _buffer.Length)
            throw new InvalidOperationException("Buffer overflow");
            
        _buffer[_position++] = value;
    }
    
    /// <summary>
    /// Writes a span of bytes.
    /// </summary>
    /// <param name="bytes">The bytes to write.</param>
    public void WriteBytes(ReadOnlySpan<byte> bytes)
    {
        if (_position + bytes.Length > _buffer.Length)
            throw new InvalidOperationException("Buffer overflow");
            
        bytes.CopyTo(_buffer.Slice(_position));
        _position += bytes.Length;
    }
    
    /// <summary>
    /// Writes a variable-length integer.
    /// </summary>
    /// <param name="value">The value to write.</param>
    public void WriteVariableLength(ulong value)
    {
        if (value <= 63)
        {
            WriteByte((byte)value);
        }
        else if (value <= 16383)
        {
            WriteByte((byte)(0x40 | (value >> 8)));
            WriteByte((byte)value);
        }
        else if (value <= 1073741823)
        {
            WriteByte((byte)(0x80 | (value >> 24)));
            WriteByte((byte)(value >> 16));
            WriteByte((byte)(value >> 8));
            WriteByte((byte)value);
        }
        else if (value <= 4611686018427387903)
        {
            WriteByte((byte)(0xC0 | (value >> 56)));
            WriteByte((byte)(value >> 48));
            WriteByte((byte)(value >> 40));
            WriteByte((byte)(value >> 32));
            WriteByte((byte)(value >> 24));
            WriteByte((byte)(value >> 16));
            WriteByte((byte)(value >> 8));
            WriteByte((byte)value);
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Value too large for variable-length encoding");
        }
    }
}