namespace Qeen.Core.Stream;

/// <summary>
/// Represents a QUIC stream.
/// </summary>
public interface IQuicStream
{
    /// <summary>
    /// Gets the stream ID.
    /// </summary>
    ulong StreamId { get; }
    
    /// <summary>
    /// Gets the stream type.
    /// </summary>
    StreamType Type { get; }
    
    /// <summary>
    /// Gets the current stream state.
    /// </summary>
    StreamState State { get; }
    
    /// <summary>
    /// Reads data from the stream.
    /// </summary>
    /// <param name="buffer">The buffer to read into.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The number of bytes read, or 0 if the stream has ended.</returns>
    ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Writes data to the stream.
    /// </summary>
    /// <param name="buffer">The data to write.</param>
    /// <param name="fin">Whether this is the final data on the stream.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, bool fin = false, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Closes the stream for writing.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    ValueTask CloseAsync(CancellationToken cancellationToken = default);
}