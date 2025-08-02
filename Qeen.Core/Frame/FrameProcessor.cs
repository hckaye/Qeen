using Qeen.Core.Connection;
using Qeen.Core.Frame.Frames;
using Qeen.Core.Packet;
using Qeen.Core.Stream;

namespace Qeen.Core.Frame;

/// <summary>
/// Processes QUIC frames.
/// </summary>
public class FrameProcessor : IFrameProcessor
{
    /// <inheritdoc/>
    public async Task ProcessFrameAsync(IQuicFrame frame, IQuicConnection connection, CancellationToken cancellationToken = default)
    {
        if (connection == null)
            throw new ArgumentNullException(nameof(connection));
            
        // Cast to QuicConnection to access internal methods
        var quicConnection = connection as QuicConnection;
        if (quicConnection == null)
            throw new ArgumentException("Invalid connection type", nameof(connection));
            
        switch (frame.Type)
        {
            case FrameType.Padding:
                // PADDING frames are ignored
                break;
                
            case FrameType.Ping:
                // PING frames trigger an ACK
                // In a real implementation, we'd queue an ACK frame
                break;
                
            case FrameType.Ack:
            case FrameType.AckEcn:
                // Process acknowledgments
                // In a real implementation, we'd update packet acknowledgment state
                break;
                
            case FrameType.ResetStream:
                var resetFrame = (ResetStreamFrame)frame;
                // Handle stream reset
                // In a real implementation, we'd notify the stream
                break;
                
            case FrameType.StopSending:
                var stopFrame = (StopSendingFrame)frame;
                // Handle stop sending request
                // In a real implementation, we'd stop sending on the stream
                break;
                
            case FrameType.Crypto:
                var cryptoFrame = (CryptoFrame)frame;
                // Handle crypto data
                // In a real implementation, we'd pass to TLS engine
                break;
                
            case FrameType.NewToken:
                var tokenFrame = (NewTokenFrame)frame;
                // Store token for future use
                break;
                
            case var t when (byte)t >= 0x08 && (byte)t <= 0x0f:
                var streamFrame = (StreamFrame)frame;
                // Handle stream data
                // In a real implementation, we'd deliver to the stream
                break;
                
            case FrameType.MaxData:
                var maxDataFrame = (MaxDataFrame)frame;
                quicConnection.UpdateMaxData(maxDataFrame.MaximumData);
                break;
                
            case FrameType.MaxStreamData:
                var maxStreamDataFrame = (MaxStreamDataFrame)frame;
                // Update stream flow control
                break;
                
            case FrameType.MaxStreamsBidi:
            case FrameType.MaxStreamsUni:
                var maxStreamsFrame = (MaxStreamsFrame)frame;
                // Update stream limits
                break;
                
            case FrameType.DataBlocked:
            case FrameType.StreamDataBlocked:
            case FrameType.StreamsBlockedBidi:
            case FrameType.StreamsBlockedUni:
                // Handle flow control blocked notifications
                // These are informational
                break;
                
            case FrameType.NewConnectionId:
                var newCidFrame = (NewConnectionIdFrame)frame;
                // Store new connection ID
                break;
                
            case FrameType.RetireConnectionId:
                var retireCidFrame = (RetireConnectionIdFrame)frame;
                // Retire connection ID
                break;
                
            case FrameType.PathChallenge:
                var challengeFrame = (PathChallengeFrame)frame;
                // Respond with PATH_RESPONSE
                var responseFrame = new PathResponseFrame(challengeFrame.Data);
                await quicConnection.SendFrameAsync(responseFrame, cancellationToken);
                break;
                
            case FrameType.PathResponse:
                // Validate path response
                break;
                
            case FrameType.ConnectionCloseQuic:
            case FrameType.ConnectionCloseApp:
                var closeFrame = (ConnectionCloseFrame)frame;
                // Handle connection close
                await quicConnection.CloseAsync(closeFrame.ErrorCode, closeFrame.ReasonPhrase, cancellationToken);
                break;
                
            case FrameType.HandshakeDone:
                // Mark handshake as complete
                break;
                
            default:
                // Unknown frame type
                throw new NotSupportedException($"Frame type {frame.Type} is not supported");
        }
    }
    
    /// <inheritdoc/>
    public bool CanProcessInPacketType(FrameType frameType, PacketType packetType)
    {
        // This method checks if a frame type is allowed in a specific packet type
        // Based on RFC 9000 Section 12.4
        
        switch (frameType)
        {
            case FrameType.Padding:
            case FrameType.ConnectionCloseQuic:
            case FrameType.ConnectionCloseApp:
                // Allowed in all packet types
                return true;
                
            case FrameType.Ping:
            case FrameType.Ack:
            case FrameType.AckEcn:
                // Not allowed in 0-RTT
                return packetType != PacketType.ZeroRtt;
                
            case FrameType.Crypto:
                // Allowed in Initial, Handshake, and 1-RTT
                return packetType == PacketType.Initial || 
                       packetType == PacketType.Handshake || 
                       packetType == PacketType.OneRtt;
                       
            case FrameType.NewToken:
            case FrameType.HandshakeDone:
                // Only in 1-RTT
                return packetType == PacketType.OneRtt;
                
            case FrameType.PathResponse:
                // Only in 1-RTT
                return packetType == PacketType.OneRtt;
                
            case FrameType.PathChallenge:
            case FrameType.RetireConnectionId:
                // Not in 0-RTT
                return packetType != PacketType.ZeroRtt;
                
            case var t when (byte)t >= 0x08 && (byte)t <= 0x0f: // STREAM frames
            case FrameType.ResetStream:
            case FrameType.StopSending:
            case FrameType.MaxData:
            case FrameType.MaxStreamData:
            case FrameType.MaxStreamsBidi:
            case FrameType.MaxStreamsUni:
            case FrameType.DataBlocked:
            case FrameType.StreamDataBlocked:
            case FrameType.StreamsBlockedBidi:
            case FrameType.StreamsBlockedUni:
            case FrameType.NewConnectionId:
                // Allowed in 0-RTT and 1-RTT
                return packetType == PacketType.ZeroRtt || packetType == PacketType.OneRtt;
                
            default:
                return false;
        }
    }
}