namespace Qeen.Core.Frame;

/// <summary>
/// Provides reading functionality for QUIC frames.
/// </summary>
public ref struct FrameReader
{
    private ReadOnlySpan<byte> _buffer;
    private int _position;
    
    /// <summary>
    /// Gets the number of bytes remaining to read.
    /// </summary>
    public readonly int BytesRemaining => _buffer.Length - _position;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="FrameReader"/> struct.
    /// </summary>
    /// <param name="buffer">The buffer to read from.</param>
    public FrameReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }
    
    /// <summary>
    /// Reads a single byte.
    /// </summary>
    /// <returns>The byte read.</returns>
    public byte ReadByte()
    {
        if (_position >= _buffer.Length)
            throw new InvalidOperationException("End of buffer reached");
            
        return _buffer[_position++];
    }
    
    /// <summary>
    /// Peeks at the next byte without advancing the position.
    /// </summary>
    /// <returns>The next byte.</returns>
    public byte PeekByte()
    {
        if (_position >= _buffer.Length)
            throw new InvalidOperationException("End of buffer reached");
            
        return _buffer[_position];
    }
    
    /// <summary>
    /// Reads a span of bytes.
    /// </summary>
    /// <param name="length">The number of bytes to read.</param>
    /// <returns>The bytes read.</returns>
    public ReadOnlySpan<byte> ReadBytes(int length)
    {
        if (_position + length > _buffer.Length)
            throw new InvalidOperationException("Not enough bytes remaining");
            
        var result = _buffer.Slice(_position, length);
        _position += length;
        return result;
    }
    
    /// <summary>
    /// Tries to read a variable-length integer.
    /// </summary>
    /// <param name="value">The value read.</param>
    /// <returns>True if successful.</returns>
    public bool TryReadVariableLength(out ulong value)
    {
        value = 0;
        
        if (_position >= _buffer.Length)
            return false;
            
        byte firstByte = _buffer[_position];
        int prefix = firstByte >> 6;
        int length = 1 << prefix;
        
        if (_position + length > _buffer.Length)
            return false;
            
        // Read the value
        value = (ulong)(firstByte & 0x3F);
        _position++;
        
        for (int i = 1; i < length; i++)
        {
            value = (value << 8) | _buffer[_position++];
        }
        
        return true;
    }
}