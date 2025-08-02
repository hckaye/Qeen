namespace Qeen.Core.FlowControl;

/// <summary>
/// Defines the interface for connection-level flow control.
/// </summary>
public interface IFlowController
{
    /// <summary>
    /// Gets the maximum data limit for the connection.
    /// </summary>
    ulong MaxData { get; }
    
    /// <summary>
    /// Gets the total data consumed (received and processed).
    /// </summary>
    ulong DataConsumed { get; }
    
    /// <summary>
    /// Gets the total data sent.
    /// </summary>
    ulong DataSent { get; }
    
    /// <summary>
    /// Gets the available send window.
    /// </summary>
    ulong AvailableWindow { get; }
    
    /// <summary>
    /// Checks if the specified amount of data can be sent without violating flow control.
    /// </summary>
    /// <param name="dataLength">The length of data to send.</param>
    /// <returns>True if the data can be sent; otherwise, false.</returns>
    bool CanSend(ulong dataLength);
    
    /// <summary>
    /// Records data that has been sent.
    /// </summary>
    /// <param name="dataLength">The length of data sent.</param>
    /// <exception cref="QuicException">Thrown if sending would violate flow control limits.</exception>
    void RecordDataSent(ulong dataLength);
    
    /// <summary>
    /// Records data that has been consumed (received and processed).
    /// </summary>
    /// <param name="dataLength">The length of data consumed.</param>
    void RecordDataConsumed(ulong dataLength);
    
    /// <summary>
    /// Updates the maximum data limit.
    /// </summary>
    /// <param name="newMaxData">The new maximum data limit.</param>
    void UpdateMaxData(ulong newMaxData);
    
    /// <summary>
    /// Checks if the connection is blocked by flow control.
    /// </summary>
    /// <returns>True if blocked; otherwise, false.</returns>
    bool IsBlocked();
    
    /// <summary>
    /// Validates incoming data against flow control limits.
    /// </summary>
    /// <param name="offset">The offset of the incoming data.</param>
    /// <param name="dataLength">The length of the incoming data.</param>
    /// <exception cref="QuicException">Thrown if the data violates flow control limits.</exception>
    void ValidateIncomingData(ulong offset, ulong dataLength);
    
    /// <summary>
    /// Resets the flow control state (for connection reset).
    /// </summary>
    void Reset();
}

/// <summary>
/// Defines the interface for stream-level flow control.
/// </summary>
public interface IStreamFlowController
{
    /// <summary>
    /// Gets the stream ID.
    /// </summary>
    ulong StreamId { get; }
    
    /// <summary>
    /// Gets the maximum data limit for the stream.
    /// </summary>
    ulong MaxStreamData { get; }
    
    /// <summary>
    /// Gets the total data consumed on this stream.
    /// </summary>
    ulong DataConsumed { get; }
    
    /// <summary>
    /// Gets the total data sent on this stream.
    /// </summary>
    ulong DataSent { get; }
    
    /// <summary>
    /// Gets the available send window for the stream.
    /// </summary>
    ulong AvailableWindow { get; }
    
    /// <summary>
    /// Checks if the specified amount of data can be sent without violating stream flow control.
    /// </summary>
    /// <param name="dataLength">The length of data to send.</param>
    /// <returns>True if the data can be sent; otherwise, false.</returns>
    bool CanSend(ulong dataLength);
    
    /// <summary>
    /// Records data that has been sent on the stream.
    /// </summary>
    /// <param name="offset">The offset at which the data is sent.</param>
    /// <param name="dataLength">The length of data sent.</param>
    /// <exception cref="QuicException">Thrown if sending would violate flow control limits.</exception>
    void RecordDataSent(ulong offset, ulong dataLength);
    
    /// <summary>
    /// Records data that has been consumed on the stream.
    /// </summary>
    /// <param name="dataLength">The length of data consumed.</param>
    void RecordDataConsumed(ulong dataLength);
    
    /// <summary>
    /// Updates the maximum stream data limit.
    /// </summary>
    /// <param name="newMaxStreamData">The new maximum stream data limit.</param>
    void UpdateMaxStreamData(ulong newMaxStreamData);
    
    /// <summary>
    /// Checks if the stream is blocked by flow control.
    /// </summary>
    /// <returns>True if blocked; otherwise, false.</returns>
    bool IsBlocked();
    
    /// <summary>
    /// Validates incoming stream data against flow control limits.
    /// </summary>
    /// <param name="offset">The offset of the incoming data.</param>
    /// <param name="dataLength">The length of the incoming data.</param>
    /// <exception cref="QuicException">Thrown if the data violates flow control limits.</exception>
    void ValidateIncomingData(ulong offset, ulong dataLength);
    
    /// <summary>
    /// Resets the stream flow control state.
    /// </summary>
    void Reset();
}