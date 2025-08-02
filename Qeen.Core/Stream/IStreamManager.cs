namespace Qeen.Core.Stream;

/// <summary>
/// Manages QUIC streams within a connection.
/// </summary>
public interface IStreamManager
{
    /// <summary>
    /// Creates a new stream of the specified type.
    /// </summary>
    /// <param name="type">The type of stream to create.</param>
    /// <returns>The newly created stream.</returns>
    /// <exception cref="InvalidOperationException">If stream limits are exceeded.</exception>
    IQuicStream CreateStream(StreamType type);
    
    /// <summary>
    /// Tries to get an existing stream by ID.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="stream">The stream if found.</param>
    /// <returns>True if the stream exists; otherwise, false.</returns>
    bool TryGetStream(ulong streamId, out IQuicStream? stream);
    
    /// <summary>
    /// Processes an incoming stream from the peer.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="type">The stream type.</param>
    /// <exception cref="QuicException">If the stream violates protocol rules.</exception>
    void ProcessIncomingStream(ulong streamId, StreamType type);
    
    /// <summary>
    /// Updates the maximum number of streams allowed.
    /// </summary>
    /// <param name="maxStreams">The new maximum number of streams.</param>
    /// <param name="type">The stream type to update limits for.</param>
    void UpdateStreamLimits(ulong maxStreams, StreamType type);
    
    /// <summary>
    /// Gets the next available stream ID for the specified type.
    /// </summary>
    /// <param name="type">The stream type.</param>
    /// <returns>The next available stream ID.</returns>
    ulong GetNextStreamId(StreamType type);
    
    /// <summary>
    /// Closes a stream.
    /// </summary>
    /// <param name="streamId">The stream ID to close.</param>
    /// <param name="errorCode">Optional error code if closing due to error.</param>
    void CloseStream(ulong streamId, ulong? errorCode = null);
    
    /// <summary>
    /// Gets all active streams.
    /// </summary>
    /// <returns>A collection of active streams.</returns>
    IEnumerable<IQuicStream> GetActiveStreams();
}