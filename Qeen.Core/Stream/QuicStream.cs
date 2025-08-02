using System.Threading.Channels;
using Qeen.Core.Exceptions;
using Qeen.Core.FlowControl;

namespace Qeen.Core.Stream;

/// <summary>
/// Represents a QUIC stream.
/// </summary>
public class QuicStream : IQuicStream
{
    private readonly Channel<StreamData> _receiveChannel;
    private readonly SemaphoreSlim _sendSemaphore;
    private readonly IStreamFlowController _flowController;
    private StreamState _state;
    private ulong _sendOffset;
    private ulong _receiveOffset;
    private ulong _maxSendData;
    private bool _finSent;
    private bool _finReceived;
    
    /// <inheritdoc/>
    public ulong StreamId { get; }
    
    /// <inheritdoc/>
    public StreamType Type { get; }
    
    /// <inheritdoc/>
    public StreamState State 
    { 
        get => _state;
        private set => _state = value;
    }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicStream"/> class.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="type">The stream type.</param>
    /// <param name="isLocallyInitiated">Whether this stream was locally initiated.</param>
    /// <param name="maxSendData">Maximum data that can be sent.</param>
    public QuicStream(ulong streamId, StreamType type, bool isLocallyInitiated, ulong maxSendData)
    {
        StreamId = streamId;
        Type = type;
        _maxSendData = maxSendData;
        _flowController = new StreamFlowController(streamId, maxSendData);
        _receiveChannel = Channel.CreateUnbounded<StreamData>();
        _sendSemaphore = new SemaphoreSlim(1, 1);
        
        // Set initial state based on stream type and initiation
        if (type == StreamType.Unidirectional)
        {
            _state = isLocallyInitiated ? StreamState.Open : StreamState.ReceiveOnly;
        }
        else
        {
            _state = StreamState.Open;
        }
    }
    
    /// <inheritdoc/>
    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_state == StreamState.Closed)
            throw new InvalidOperationException("Cannot read from closed stream");
            
        if (Type == StreamType.Unidirectional && IsLocallyInitiated())
            throw new InvalidOperationException("Cannot read from unidirectional send stream");
            
        try
        {
            if (await _receiveChannel.Reader.WaitToReadAsync(cancellationToken))
            {
                if (_receiveChannel.Reader.TryRead(out var data))
                {
                    var bytesToCopy = Math.Min(buffer.Length, data.Data.Length);
                    data.Data.Slice(0, bytesToCopy).CopyTo(buffer);
                    
                    if (data.Fin)
                    {
                        _finReceived = true;
                        UpdateState();
                    }
                    
                    return bytesToCopy;
                }
            }
        }
        catch (ChannelClosedException)
        {
            // Channel closed, return 0 to indicate end of stream
        }
        
        return 0;
    }
    
    /// <inheritdoc/>
    public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, bool fin = false, CancellationToken cancellationToken = default)
    {
        if (_state == StreamState.Closed || _state == StreamState.SendClosed)
            throw new InvalidOperationException("Cannot write to closed stream");
            
        if (Type == StreamType.Unidirectional && !IsLocallyInitiated())
            throw new InvalidOperationException("Cannot write to unidirectional receive stream");
            
        if (_finSent)
            throw new InvalidOperationException("Cannot write after FIN");
            
        await _sendSemaphore.WaitAsync(cancellationToken);
        try
        {
            // RFC 9000 Section 4.1: Enforce stream-level flow control
            var dataLength = (ulong)buffer.Length;
            
            if (!_flowController.CanSend(dataLength))
            {
                throw new QuicException(
                    $"Stream {StreamId} flow control limit exceeded. Available window: {_flowController.AvailableWindow} bytes, " +
                    $"Attempted to send: {dataLength} bytes",
                    QuicErrorCode.FlowControlError);
            }
            
            // Record the data being sent
            _flowController.RecordDataSent(_sendOffset, dataLength);
                
            // In a real implementation, this would queue the data for transmission
            // For now, we'll just update the offset
            _sendOffset += dataLength;
            
            if (fin)
            {
                _finSent = true;
                UpdateState();
            }
        }
        finally
        {
            _sendSemaphore.Release();
        }
    }
    
    /// <inheritdoc/>
    public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        if (_state == StreamState.Closed)
            return;
            
        // Send FIN if not already sent
        if (!_finSent && (Type == StreamType.Bidirectional || IsLocallyInitiated()))
        {
            await WriteAsync(ReadOnlyMemory<byte>.Empty, true, cancellationToken);
        }
        
        // Close receive channel
        _receiveChannel.Writer.TryComplete();
        
        _state = StreamState.Closed;
    }
    
    /// <summary>
    /// Delivers received data to the stream.
    /// </summary>
    /// <param name="offset">The offset of the data.</param>
    /// <param name="data">The data received.</param>
    /// <param name="fin">Whether this is the final data.</param>
    public async Task DeliverData(ulong offset, ReadOnlyMemory<byte> data, bool fin)
    {
        if (_state == StreamState.Closed)
            return;
        
        // RFC 9000 Section 4.1: Validate incoming data against flow control limits
        var dataLength = (ulong)data.Length;
        _flowController.ValidateIncomingData(offset, dataLength);
            
        // In a real implementation, we'd handle out-of-order data
        // For now, assume data arrives in order
        if (offset != _receiveOffset)
            throw new QuicException("Out-of-order stream data not yet supported");
            
        _receiveOffset += (ulong)data.Length;
        
        await _receiveChannel.Writer.WriteAsync(new StreamData(data, fin));
        
        if (fin)
        {
            _finReceived = true;
            _receiveChannel.Writer.TryComplete();
            UpdateState();
        }
    }
    
    /// <summary>
    /// Updates stream flow control limits.
    /// </summary>
    /// <param name="maxData">New maximum data limit.</param>
    internal void UpdateFlowControl(ulong maxData)
    {
        _maxSendData = maxData;
        _flowController.UpdateMaxStreamData(maxData);
    }
    
    /// <summary>
    /// Gets whether the stream is blocked by flow control.
    /// </summary>
    public bool IsFlowControlBlocked => _flowController.IsBlocked();
    
    private bool IsLocallyInitiated()
    {
        // Stream IDs follow a pattern:
        // Client-initiated: 0, 4, 8, 12... (0 mod 4) or 2, 6, 10... (2 mod 4)
        // Server-initiated: 1, 5, 9, 13... (1 mod 4) or 3, 7, 11... (3 mod 4)
        // For now, assume we're always the client
        return (StreamId & 0x1) == 0;
    }
    
    private void UpdateState()
    {
        if (_finSent && _finReceived)
        {
            _state = StreamState.Closed;
        }
        else if (_finSent)
        {
            _state = StreamState.SendClosed;
        }
        else if (_finReceived)
        {
            _state = StreamState.ReceiveClosed;
        }
    }
    
    private readonly struct StreamData
    {
        public ReadOnlyMemory<byte> Data { get; }
        public bool Fin { get; }
        
        public StreamData(ReadOnlyMemory<byte> data, bool fin)
        {
            Data = data;
            Fin = fin;
        }
    }
}