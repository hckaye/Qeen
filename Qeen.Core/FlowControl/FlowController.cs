using System.Threading;
using Qeen.Core.Exceptions;

namespace Qeen.Core.FlowControl;

/// <summary>
/// Manages flow control for QUIC connections and streams according to RFC 9000.
/// </summary>
public class FlowController : IFlowController
{
    private long _maxData;
    private long _dataConsumed;
    private long _dataSent;
    private readonly object _lock = new object();
    
    /// <summary>
    /// Initializes a new instance of the <see cref="FlowController"/> class.
    /// </summary>
    /// <param name="initialMaxData">Initial maximum data limit.</param>
    public FlowController(ulong initialMaxData)
    {
        _maxData = (long)initialMaxData;
        _dataConsumed = 0;
        _dataSent = 0;
    }
    
    /// <inheritdoc/>
    public ulong MaxData => (ulong)Interlocked.Read(ref _maxData);
    
    /// <inheritdoc/>
    public ulong DataConsumed => (ulong)Interlocked.Read(ref _dataConsumed);
    
    /// <inheritdoc/>
    public ulong DataSent => (ulong)Interlocked.Read(ref _dataSent);
    
    /// <inheritdoc/>
    public ulong AvailableWindow
    {
        get
        {
            lock (_lock)
            {
                var max = _maxData;
                var sent = _dataSent;
                return sent >= max ? 0 : (ulong)(max - sent);
            }
        }
    }
    
    /// <inheritdoc/>
    public bool CanSend(ulong dataLength)
    {
        lock (_lock)
        {
            return _dataSent + (long)dataLength <= _maxData;
        }
    }
    
    /// <inheritdoc/>
    public void RecordDataSent(ulong dataLength)
    {
        lock (_lock)
        {
            var newSent = _dataSent + (long)dataLength;
            
            // RFC 9000 Section 4.1: Sending data beyond the limit is a FLOW_CONTROL_ERROR
            if (newSent > _maxData)
            {
                throw new QuicException(
                    $"Flow control violation: Attempting to send {dataLength} bytes would exceed limit. " +
                    $"Current sent: {_dataSent}, Max allowed: {_maxData}",
                    QuicErrorCode.FlowControlError);
            }
            
            _dataSent = newSent;
        }
    }
    
    /// <inheritdoc/>
    public void RecordDataConsumed(ulong dataLength)
    {
        Interlocked.Add(ref _dataConsumed, (long)dataLength);
    }
    
    /// <inheritdoc/>
    public void UpdateMaxData(ulong newMaxData)
    {
        lock (_lock)
        {
            var newMax = (long)newMaxData;
            
            // RFC 9000 Section 4.1: MAX_DATA values only increase
            if (newMax <= _maxData)
            {
                // Ignore values that don't increase the limit
                return;
            }
            
            _maxData = newMax;
        }
    }
    
    /// <inheritdoc/>
    public bool IsBlocked()
    {
        lock (_lock)
        {
            return _dataSent >= _maxData;
        }
    }
    
    /// <inheritdoc/>
    public void ValidateIncomingData(ulong offset, ulong dataLength)
    {
        lock (_lock)
        {
            // RFC 9000 Section 4.1: Receiving data beyond the advertised limit is a FLOW_CONTROL_ERROR
            var endOffset = offset + dataLength;
            if (endOffset > (ulong)_maxData)
            {
                throw new QuicException(
                    $"Flow control violation: Received data beyond advertised limit. " +
                    $"End offset: {endOffset}, Max allowed: {_maxData}",
                    QuicErrorCode.FlowControlError);
            }
        }
    }
    
    /// <inheritdoc/>
    public void Reset()
    {
        lock (_lock)
        {
            _dataConsumed = 0;
            _dataSent = 0;
            // Don't reset _maxData as it should persist
        }
    }
}

/// <summary>
/// Manages per-stream flow control according to RFC 9000.
/// </summary>
public class StreamFlowController : IStreamFlowController
{
    private readonly ulong _streamId;
    private long _maxStreamData;
    private long _dataConsumed;
    private long _dataSent;
    private long _highestOffset;
    private readonly object _lock = new object();
    
    /// <summary>
    /// Initializes a new instance of the <see cref="StreamFlowController"/> class.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="initialMaxStreamData">Initial maximum stream data limit.</param>
    public StreamFlowController(ulong streamId, ulong initialMaxStreamData)
    {
        _streamId = streamId;
        _maxStreamData = (long)initialMaxStreamData;
        _dataConsumed = 0;
        _dataSent = 0;
        _highestOffset = -1;
    }
    
    /// <inheritdoc/>
    public ulong StreamId => _streamId;
    
    /// <inheritdoc/>
    public ulong MaxStreamData => (ulong)Interlocked.Read(ref _maxStreamData);
    
    /// <inheritdoc/>
    public ulong DataConsumed => (ulong)Interlocked.Read(ref _dataConsumed);
    
    /// <inheritdoc/>
    public ulong DataSent => (ulong)Interlocked.Read(ref _dataSent);
    
    /// <inheritdoc/>
    public ulong AvailableWindow
    {
        get
        {
            lock (_lock)
            {
                var max = _maxStreamData;
                var sent = _dataSent;
                return sent >= max ? 0 : (ulong)(max - sent);
            }
        }
    }
    
    /// <inheritdoc/>
    public bool CanSend(ulong dataLength)
    {
        lock (_lock)
        {
            return _dataSent + (long)dataLength <= _maxStreamData;
        }
    }
    
    /// <inheritdoc/>
    public void RecordDataSent(ulong offset, ulong dataLength)
    {
        lock (_lock)
        {
            var endOffset = offset + dataLength;
            
            // RFC 9000 Section 4.1: Sending data beyond the stream limit is a FLOW_CONTROL_ERROR
            if ((long)endOffset > _maxStreamData)
            {
                throw new QuicException(
                    $"Stream {_streamId} flow control violation: Attempting to send data beyond limit. " +
                    $"End offset: {endOffset}, Max allowed: {_maxStreamData}",
                    QuicErrorCode.FlowControlError);
            }
            
            // Update the highest sent offset
            if ((long)endOffset > _dataSent)
            {
                _dataSent = (long)endOffset;
            }
        }
    }
    
    /// <inheritdoc/>
    public void RecordDataConsumed(ulong dataLength)
    {
        Interlocked.Add(ref _dataConsumed, (long)dataLength);
    }
    
    /// <inheritdoc/>
    public void UpdateMaxStreamData(ulong newMaxStreamData)
    {
        lock (_lock)
        {
            var newMax = (long)newMaxStreamData;
            
            // RFC 9000 Section 4.1: MAX_STREAM_DATA values only increase
            if (newMax <= _maxStreamData)
            {
                // Ignore values that don't increase the limit
                return;
            }
            
            _maxStreamData = newMax;
        }
    }
    
    /// <inheritdoc/>
    public bool IsBlocked()
    {
        lock (_lock)
        {
            return _dataSent >= _maxStreamData;
        }
    }
    
    /// <inheritdoc/>
    public void ValidateIncomingData(ulong offset, ulong dataLength)
    {
        lock (_lock)
        {
            var endOffset = offset + dataLength;
            
            // RFC 9000 Section 4.1: Receiving data beyond the advertised stream limit is a FLOW_CONTROL_ERROR
            if ((long)endOffset > _maxStreamData)
            {
                throw new QuicException(
                    $"Stream {_streamId} flow control violation: Received data beyond advertised limit. " +
                    $"End offset: {endOffset}, Max allowed: {_maxStreamData}",
                    QuicErrorCode.FlowControlError);
            }
            
            // Update highest received offset
            if ((long)endOffset > _highestOffset)
            {
                _highestOffset = (long)endOffset;
            }
        }
    }
    
    /// <inheritdoc/>
    public void Reset()
    {
        lock (_lock)
        {
            _dataConsumed = 0;
            _dataSent = 0;
            _highestOffset = -1;
            // Don't reset _maxStreamData as it should persist
        }
    }
}