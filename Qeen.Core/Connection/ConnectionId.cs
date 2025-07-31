using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Qeen.Core.Connection;

/// <summary>
/// Represents a QUIC Connection ID as defined in RFC 9000
/// Connection IDs can be 0-20 bytes in length
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct ConnectionId : IEquatable<ConnectionId>
{
    /// <summary>
    /// Maximum length of a Connection ID (20 bytes as per RFC 9000)
    /// </summary>
    public const int MaxLength = 20;

    private readonly byte _length;
    private readonly ulong _data1;
    private readonly ulong _data2;
    private readonly uint _data3;

    /// <summary>
    /// Gets the length of the Connection ID in bytes
    /// </summary>
    public byte Length => _length;

    /// <summary>
    /// Gets an empty Connection ID (zero-length)
    /// </summary>
    public static ConnectionId Empty => default;

    /// <summary>
    /// Creates a new ConnectionId from a byte span
    /// </summary>
    public ConnectionId(ReadOnlySpan<byte> data)
    {
        if (data.Length > MaxLength)
            throw new ArgumentException($"Connection ID length cannot exceed {MaxLength} bytes", nameof(data));

        _length = (byte)data.Length;
        _data1 = 0;
        _data2 = 0;
        _data3 = 0;

        if (data.Length > 0)
        {
            unsafe
            {
                fixed (byte* src = data)
                fixed (ulong* dst1 = &_data1)
                {
                    byte* dst = (byte*)dst1;
                    Buffer.MemoryCopy(src, dst, MaxLength, data.Length);
                }
            }
        }
    }

    /// <summary>
    /// Creates a new random ConnectionId of specified length
    /// </summary>
    public static ConnectionId NewRandom(byte length)
    {
        if (length > MaxLength)
            throw new ArgumentException($"Connection ID length cannot exceed {MaxLength} bytes", nameof(length));

        Span<byte> buffer = stackalloc byte[length];
        System.Security.Cryptography.RandomNumberGenerator.Fill(buffer);
        return new ConnectionId(buffer);
    }

    /// <summary>
    /// Copies the Connection ID bytes to the specified span
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int CopyTo(Span<byte> destination)
    {
        if (destination.Length < _length)
            throw new ArgumentException("Destination span is too small", nameof(destination));

        if (_length > 0)
        {
            unsafe
            {
                fixed (ulong* src1 = &_data1)
                fixed (byte* dst = destination)
                {
                    byte* src = (byte*)src1;
                    Buffer.MemoryCopy(src, dst, destination.Length, _length);
                }
            }
        }

        return _length;
    }

    /// <summary>
    /// Gets the Connection ID as a byte span
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> AsSpan()
    {
        if (_length == 0)
            return ReadOnlySpan<byte>.Empty;

        unsafe
        {
            fixed (ulong* ptr = &_data1)
            {
                return new ReadOnlySpan<byte>(ptr, _length);
            }
        }
    }

    /// <summary>
    /// Determines whether this Connection ID is empty (zero-length)
    /// </summary>
    public bool IsEmpty => _length == 0;

    public override bool Equals(object? obj)
    {
        return obj is ConnectionId other && Equals(other);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool Equals(ConnectionId other)
    {
        if (_length != other._length)
            return false;

        if (_length == 0)
            return true;

        return _data1 == other._data1 && 
               _data2 == other._data2 && 
               _data3 == other._data3;
    }

    public override int GetHashCode()
    {
        if (_length == 0)
            return 0;

        return HashCode.Combine(_length, _data1, _data2, _data3);
    }

    public static bool operator ==(ConnectionId left, ConnectionId right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(ConnectionId left, ConnectionId right)
    {
        return !left.Equals(right);
    }

    public override string ToString()
    {
        if (_length == 0)
            return "Empty";

        return Convert.ToHexString(AsSpan());
    }
}