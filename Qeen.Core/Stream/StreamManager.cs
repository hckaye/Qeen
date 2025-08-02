using System.Collections.Concurrent;
using Qeen.Core.Exceptions;

namespace Qeen.Core.Stream;

/// <summary>
/// Manages QUIC streams within a connection.
/// </summary>
public class StreamManager : IStreamManager
{
    private readonly ConcurrentDictionary<ulong, IQuicStream> _streams;
    private readonly bool _isClient;
    private ulong _nextBidirectionalStreamId;
    private ulong _nextUnidirectionalStreamId;
    private ulong _maxBidirectionalStreams;
    private ulong _maxUnidirectionalStreams;
    private ulong _peerMaxBidirectionalStreams;
    private ulong _peerMaxUnidirectionalStreams;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="StreamManager"/> class.
    /// </summary>
    /// <param name="isClient">Whether this is a client connection.</param>
    /// <param name="maxBidirectionalStreams">Maximum bidirectional streams.</param>
    /// <param name="maxUnidirectionalStreams">Maximum unidirectional streams.</param>
    public StreamManager(bool isClient, ulong maxBidirectionalStreams = 100, ulong maxUnidirectionalStreams = 100)
    {
        _streams = new ConcurrentDictionary<ulong, IQuicStream>();
        _isClient = isClient;
        _maxBidirectionalStreams = maxBidirectionalStreams;
        _maxUnidirectionalStreams = maxUnidirectionalStreams;
        _peerMaxBidirectionalStreams = 100; // Default, updated during handshake
        _peerMaxUnidirectionalStreams = 100; // Default, updated during handshake
        
        // Initialize stream IDs based on role
        if (_isClient)
        {
            _nextBidirectionalStreamId = 0;    // Client bidirectional: 0, 4, 8...
            _nextUnidirectionalStreamId = 2;   // Client unidirectional: 2, 6, 10...
        }
        else
        {
            _nextBidirectionalStreamId = 1;    // Server bidirectional: 1, 5, 9...
            _nextUnidirectionalStreamId = 3;   // Server unidirectional: 3, 7, 11...
        }
    }
    
    /// <inheritdoc/>
    public IQuicStream CreateStream(StreamType type)
    {
        ulong streamId;
        ulong maxStreams;
        
        if (type == StreamType.Bidirectional)
        {
            streamId = _nextBidirectionalStreamId;
            maxStreams = _peerMaxBidirectionalStreams;
            
            // Check if we've reached the limit
            var streamCount = (streamId >> 2) + 1;
            if (streamCount > maxStreams)
                throw new InvalidOperationException("Bidirectional stream limit exceeded");
                
            _nextBidirectionalStreamId += 4;
        }
        else
        {
            streamId = _nextUnidirectionalStreamId;
            maxStreams = _peerMaxUnidirectionalStreams;
            
            // Check if we've reached the limit
            var streamCount = (streamId >> 2) + 1;
            if (streamCount > maxStreams)
                throw new InvalidOperationException("Unidirectional stream limit exceeded");
                
            _nextUnidirectionalStreamId += 4;
        }
        
        var stream = new QuicStream(streamId, type, true, 1024 * 1024); // 1MB initial limit
        if (!_streams.TryAdd(streamId, stream))
            throw new InvalidOperationException("Stream ID collision");
            
        return stream;
    }
    
    /// <inheritdoc/>
    public bool TryGetStream(ulong streamId, out IQuicStream? stream)
    {
        return _streams.TryGetValue(streamId, out stream);
    }
    
    /// <inheritdoc/>
    public void ProcessIncomingStream(ulong streamId, StreamType type)
    {
        // Validate stream ID
        var streamType = GetStreamType(streamId);
        if (streamType != type)
            throw new QuicException($"Stream ID {streamId} type mismatch");
            
        // Check if this is a peer-initiated stream
        bool isPeerInitiated = IsStreamInitiatedByPeer(streamId);
        if (!isPeerInitiated)
            throw new QuicException($"Stream ID {streamId} should be peer-initiated");
            
        // Check stream limits
        var streamCount = (streamId >> 2) + 1;
        if (type == StreamType.Bidirectional && streamCount > _maxBidirectionalStreams)
            throw new QuicException("Peer exceeded bidirectional stream limit");
        if (type == StreamType.Unidirectional && streamCount > _maxUnidirectionalStreams)
            throw new QuicException("Peer exceeded unidirectional stream limit");
            
        // Create the stream if it doesn't exist
        if (!_streams.ContainsKey(streamId))
        {
            var stream = new QuicStream(streamId, type, false, 1024 * 1024);
            _streams.TryAdd(streamId, stream);
        }
    }
    
    /// <inheritdoc/>
    public void UpdateStreamLimits(ulong maxStreams, StreamType type)
    {
        if (type == StreamType.Bidirectional)
        {
            _peerMaxBidirectionalStreams = maxStreams;
        }
        else
        {
            _peerMaxUnidirectionalStreams = maxStreams;
        }
    }
    
    /// <inheritdoc/>
    public ulong GetNextStreamId(StreamType type)
    {
        return type == StreamType.Bidirectional ? _nextBidirectionalStreamId : _nextUnidirectionalStreamId;
    }
    
    /// <inheritdoc/>
    public void CloseStream(ulong streamId, ulong? errorCode = null)
    {
        if (_streams.TryRemove(streamId, out var stream))
        {
            // In a real implementation, we'd handle the close more gracefully
            _ = stream.CloseAsync();
        }
    }
    
    /// <inheritdoc/>
    public IEnumerable<IQuicStream> GetActiveStreams()
    {
        return _streams.Values.Where(s => s.State != StreamState.Closed);
    }
    
    private StreamType GetStreamType(ulong streamId)
    {
        // Bit 1 indicates directionality (0 = bidirectional, 1 = unidirectional)
        return (streamId & 0x2) == 0 ? StreamType.Bidirectional : StreamType.Unidirectional;
    }
    
    private bool IsStreamInitiatedByPeer(ulong streamId)
    {
        // Bit 0 indicates initiator (0 = client, 1 = server)
        bool isServerInitiated = (streamId & 0x1) == 1;
        return _isClient ? isServerInitiated : !isServerInitiated;
    }
}