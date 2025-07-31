using System.Buffers;
using System.Runtime.CompilerServices;

namespace Qeen.Core.Memory;

/// <summary>
/// High-performance buffer pool for QUIC packet processing
/// </summary>
public sealed class QuicBufferPool
{
    private readonly ArrayPool<byte> _pool;
    private readonly int _maxBufferSize;

    /// <summary>
    /// Default buffer size for most QUIC packets
    /// </summary>
    public const int DefaultBufferSize = 1500; // Typical MTU size

    /// <summary>
    /// Large buffer size for jumbo frames or coalesced packets
    /// </summary>
    public const int LargeBufferSize = 65536;

    /// <summary>
    /// Shared instance of the buffer pool
    /// </summary>
    public static QuicBufferPool Shared { get; } = new QuicBufferPool();

    /// <summary>
    /// Creates a new QuicBufferPool
    /// </summary>
    public QuicBufferPool(int maxBufferSize = LargeBufferSize)
    {
        _maxBufferSize = maxBufferSize;
        _pool = ArrayPool<byte>.Create(maxBufferSize, 50);
    }

    /// <summary>
    /// Rents a buffer from the pool
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public byte[] Rent(int minimumSize)
    {
        if (minimumSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(minimumSize));

        if (minimumSize > _maxBufferSize)
            throw new ArgumentOutOfRangeException(nameof(minimumSize), $"Requested size {minimumSize} exceeds maximum buffer size {_maxBufferSize}");

        return _pool.Rent(minimumSize);
    }

    /// <summary>
    /// Rents a buffer and returns it as Memory<byte>
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public RentedBuffer RentMemory(int size)
    {
        var buffer = Rent(size);
        return new RentedBuffer(this, buffer, size);
    }

    /// <summary>
    /// Returns a buffer to the pool
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Return(byte[] buffer, bool clearBuffer = false)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));

        _pool.Return(buffer, clearBuffer);
    }

    /// <summary>
    /// Represents a rented buffer that automatically returns to the pool when disposed
    /// </summary>
    public readonly struct RentedBuffer : IDisposable
    {
        private readonly QuicBufferPool _pool;
        private readonly byte[] _buffer;
        private readonly int _size;

        internal RentedBuffer(QuicBufferPool pool, byte[] buffer, int size)
        {
            _pool = pool;
            _buffer = buffer;
            _size = size;
        }

        /// <summary>
        /// Gets the rented memory
        /// </summary>
        public Memory<byte> Memory => _buffer.AsMemory(0, _size);

        /// <summary>
        /// Gets the rented span
        /// </summary>
        public Span<byte> Span => _buffer.AsSpan(0, _size);

        /// <summary>
        /// Returns the buffer to the pool
        /// </summary>
        public void Dispose()
        {
            _pool.Return(_buffer);
        }
    }
}

/// <summary>
/// Provides zero-copy operations using spans
/// </summary>
public ref struct QuicSpan
{
    private Span<byte> _buffer;
    private int _position;
    private readonly int _length;

    /// <summary>
    /// Creates a new QuicSpan
    /// </summary>
    public QuicSpan(Span<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
        _length = buffer.Length;
    }

    /// <summary>
    /// Gets the current position
    /// </summary>
    public readonly int Position => _position;

    /// <summary>
    /// Gets the remaining bytes
    /// </summary>
    public readonly int Remaining => _length - _position;

    /// <summary>
    /// Gets the total length
    /// </summary>
    public readonly int Length => _length;

    /// <summary>
    /// Advances the position
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Advance(int count)
    {
        if (count < 0 || _position + count > _length)
            throw new ArgumentOutOfRangeException(nameof(count));

        _position += count;
    }

    /// <summary>
    /// Gets a slice from the current position
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Span<byte> GetSpan(int length)
    {
        if (length < 0 || _position + length > _length)
            throw new ArgumentOutOfRangeException(nameof(length));

        return _buffer.Slice(_position, length);
    }

    /// <summary>
    /// Gets the remaining span from current position
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Span<byte> GetRemainingSpan()
    {
        return _buffer.Slice(_position, Remaining);
    }

    /// <summary>
    /// Resets the position to the beginning
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Reset()
    {
        _position = 0;
    }
}