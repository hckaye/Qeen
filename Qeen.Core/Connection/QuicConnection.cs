using System.Net;
using System.Threading.Channels;
using Qeen.Core.Exceptions;
using Qeen.Core.FlowControl;
using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Handshake;
using Qeen.Core.Packet;
using Qeen.Core.Stream;

namespace Qeen.Core.Connection;

/// <summary>
/// Represents a QUIC connection.
/// </summary>
public class QuicConnection : IQuicConnection
{
    private readonly IStreamManager _streamManager;
    private readonly IFrameProcessor _frameProcessor;
    private readonly IFlowController _flowController;
    private readonly Channel<IQuicFrame> _outgoingFrames;
    private readonly SemaphoreSlim _stateLock;
    private readonly IHandshakeManager _handshakeManager;
    private ConnectionState _state;
    private EndPoint? _remoteEndPoint;
    private TransportParameters? _remoteTransportParameters;
    private ulong _maxData;
    private ulong _dataConsumed;
    private readonly bool _isClient;
    
    /// <inheritdoc/>
    public ConnectionId LocalConnectionId { get; }
    
    /// <inheritdoc/>
    public ConnectionId RemoteConnectionId { get; private set; }
    
    /// <inheritdoc/>
    public ConnectionState State 
    { 
        get => _state;
        private set => _state = value;
    }
    
    /// <inheritdoc/>
    public TransportParameters LocalTransportParameters { get; }
    
    /// <inheritdoc/>
    public TransportParameters? RemoteTransportParameters => _remoteTransportParameters;
    
    /// <summary>
    /// Initializes a new instance of the <see cref="QuicConnection"/> class.
    /// </summary>
    /// <param name="isClient">Whether this is a client connection.</param>
    /// <param name="localConnectionId">The local connection ID.</param>
    /// <param name="localTransportParameters">The local transport parameters.</param>
    public QuicConnection(bool isClient, ConnectionId localConnectionId, TransportParameters localTransportParameters)
    {
        _isClient = isClient;
        LocalConnectionId = localConnectionId;
        LocalTransportParameters = localTransportParameters;
        RemoteConnectionId = ConnectionId.Empty;
        _state = ConnectionState.Idle;
        _streamManager = new StreamManager(isClient);
        _frameProcessor = new FrameProcessor();
        _flowController = new FlowController(localTransportParameters.InitialMaxData);
        _outgoingFrames = Channel.CreateUnbounded<IQuicFrame>();
        _stateLock = new SemaphoreSlim(1, 1);
        _handshakeManager = new HandshakeManager(isClient, localConnectionId, localTransportParameters);
        _maxData = localTransportParameters.InitialMaxData;
    }
    
    /// <inheritdoc/>
    public async Task ConnectAsync(EndPoint remoteEndpoint, CancellationToken cancellationToken = default)
    {
        await _stateLock.WaitAsync(cancellationToken);
        try
        {
            if (_state != ConnectionState.Idle)
                throw new InvalidOperationException("Connection is not in idle state");
                
            _remoteEndPoint = remoteEndpoint;
            _state = ConnectionState.Connecting;
            
            // In a real implementation, this would initiate the handshake
            // For now, we'll simulate a successful connection
            await Task.Delay(10, cancellationToken); // Simulate handshake
            
            _state = ConnectionState.Connected;
        }
        finally
        {
            _stateLock.Release();
        }
    }
    
    /// <inheritdoc/>
    public IQuicStream OpenStream(StreamType type)
    {
        if (_state != ConnectionState.Connected)
            throw new InvalidOperationException("Connection is not established");
            
        return _streamManager.CreateStream(type);
    }
    
    /// <inheritdoc/>
    public async Task CloseAsync(ulong errorCode, string reason, CancellationToken cancellationToken = default)
    {
        await _stateLock.WaitAsync(cancellationToken);
        try
        {
            if (_state == ConnectionState.Closed)
                return;
                
            _state = ConnectionState.Closing;
            
            // Send CONNECTION_CLOSE frame
            var closeFrame = new ConnectionCloseFrame(errorCode, reason);
            await _outgoingFrames.Writer.WriteAsync(closeFrame, cancellationToken);
            
            // Close all streams
            foreach (var stream in _streamManager.GetActiveStreams())
            {
                await stream.CloseAsync(cancellationToken);
            }
            
            _state = ConnectionState.Closed;
        }
        finally
        {
            _stateLock.Release();
        }
    }
    
    /// <summary>
    /// Processes an incoming frame.
    /// </summary>
    /// <param name="frame">The frame to process.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task ProcessFrameAsync(IQuicFrame frame, CancellationToken cancellationToken = default)
    {
        await _frameProcessor.ProcessFrameAsync(frame, this, cancellationToken);
    }
    
    /// <summary>
    /// Updates the remote connection ID.
    /// </summary>
    /// <param name="connectionId">The new remote connection ID.</param>
    public void UpdateRemoteConnectionId(ConnectionId connectionId)
    {
        RemoteConnectionId = connectionId;
    }
    
    /// <summary>
    /// Updates the remote transport parameters.
    /// </summary>
    /// <param name="parameters">The remote transport parameters.</param>
    public void UpdateRemoteTransportParameters(TransportParameters parameters)
    {
        _remoteTransportParameters = parameters;
        _maxData = parameters.InitialMaxData;
        
        // Update stream limits
        _streamManager.UpdateStreamLimits(parameters.InitialMaxStreamsBidi, StreamType.Bidirectional);
        _streamManager.UpdateStreamLimits(parameters.InitialMaxStreamsUni, StreamType.Unidirectional);
    }
    
    /// <summary>
    /// Updates flow control limits.
    /// </summary>
    /// <param name="maxData">The new maximum data limit.</param>
    internal void UpdateMaxData(ulong maxData)
    {
        _maxData = maxData;
        _flowController.UpdateMaxData(maxData);
    }
    
    /// <summary>
    /// Validates incoming data against connection flow control limits.
    /// </summary>
    /// <param name="streamId">The stream ID.</param>
    /// <param name="offset">The offset of the data.</param>
    /// <param name="dataLength">The length of the data.</param>
    internal void ValidateConnectionFlowControl(ulong streamId, ulong offset, ulong dataLength)
    {
        // RFC 9000 Section 4.1: Connection-level flow control applies to all stream data
        _flowController.ValidateIncomingData(offset, dataLength);
    }
    
    /// <summary>
    /// Records data sent on the connection.
    /// </summary>
    /// <param name="dataLength">The length of data sent.</param>
    internal void RecordDataSent(ulong dataLength)
    {
        _flowController.RecordDataSent(dataLength);
    }
    
    /// <summary>
    /// Gets whether the connection is blocked by flow control.
    /// </summary>
    public bool IsFlowControlBlocked => _flowController.IsBlocked();
    
    /// <summary>
    /// Gets the next frame to send.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The next frame to send, or null if no frames are available.</returns>
    public async Task<IQuicFrame?> GetNextFrameAsync(CancellationToken cancellationToken = default)
    {
        if (await _outgoingFrames.Reader.WaitToReadAsync(cancellationToken))
        {
            if (_outgoingFrames.Reader.TryRead(out var frame))
            {
                return frame;
            }
        }
        
        return null;
    }
    
    /// <summary>
    /// Sends a frame.
    /// </summary>
    /// <param name="frame">The frame to send.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task SendFrameAsync(IQuicFrame frame, CancellationToken cancellationToken = default)
    {
        await _outgoingFrames.Writer.WriteAsync(frame, cancellationToken);
    }
    
    /// <summary>
    /// Gets the handshake manager.
    /// </summary>
    public IHandshakeManager HandshakeManager => _handshakeManager;
    
    /// <summary>
    /// Gets whether this is a client connection.
    /// </summary>
    public bool IsClient => _isClient;
}