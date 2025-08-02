using Qeen.Core.Frame.Frames;

namespace Qeen.Core.Frame;

/// <summary>
/// Decodes QUIC frames from packet data.
/// </summary>
public static class FrameDecoder
{
    /// <summary>
    /// Attempts to decode a frame from the reader.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if a frame was successfully decoded.</returns>
    public static bool TryDecodeFrame(FrameReader reader, out IQuicFrame? frame)
    {
        frame = null;
        
        if (reader.BytesRemaining == 0)
            return false;
            
        var typeByte = reader.ReadByte();
        var frameType = (FrameType)typeByte;
        
        switch (frameType)
        {
            case FrameType.Padding:
                if (PaddingFrame.TryDecode(reader, out var paddingFrame))
                {
                    frame = paddingFrame;
                    return true;
                }
                break;
                
            case FrameType.Ping:
                if (PingFrame.TryDecode(reader, out var pingFrame))
                {
                    frame = pingFrame;
                    return true;
                }
                break;
                
            case FrameType.Ack:
                if (AckFrame.TryDecode(reader, out var ackFrame))
                {
                    frame = ackFrame;
                    return true;
                }
                break;
                
            case FrameType.ConnectionCloseQuic:
                if (ConnectionCloseFrame.TryDecode(reader, false, out var closeQuicFrame))
                {
                    frame = closeQuicFrame;
                    return true;
                }
                break;
                
            case FrameType.ConnectionCloseApp:
                if (ConnectionCloseFrame.TryDecode(reader, true, out var closeAppFrame))
                {
                    frame = closeAppFrame;
                    return true;
                }
                break;
                
            case FrameType.ResetStream:
                if (ResetStreamFrame.TryDecode(reader, out var resetStreamFrame))
                {
                    frame = resetStreamFrame;
                    return true;
                }
                break;
                
            case FrameType.StopSending:
                if (StopSendingFrame.TryDecode(reader, out var stopSendingFrame))
                {
                    frame = stopSendingFrame;
                    return true;
                }
                break;
                
            case FrameType.Crypto:
                if (CryptoFrame.TryDecode(reader, out var cryptoFrame))
                {
                    frame = cryptoFrame;
                    return true;
                }
                break;
                
            case FrameType.NewToken:
                if (NewTokenFrame.TryDecode(reader, out var newTokenFrame))
                {
                    frame = newTokenFrame;
                    return true;
                }
                break;
                
            case FrameType.MaxData:
                if (MaxDataFrame.TryDecode(reader, out var maxDataFrame))
                {
                    frame = maxDataFrame;
                    return true;
                }
                break;
                
            case FrameType.MaxStreamData:
                if (MaxStreamDataFrame.TryDecode(reader, out var maxStreamDataFrame))
                {
                    frame = maxStreamDataFrame;
                    return true;
                }
                break;
                
            case FrameType.MaxStreamsBidi:
                if (MaxStreamsFrame.TryDecode(reader, true, out var maxStreamsBidiFrame))
                {
                    frame = maxStreamsBidiFrame;
                    return true;
                }
                break;
                
            case FrameType.MaxStreamsUni:
                if (MaxStreamsFrame.TryDecode(reader, false, out var maxStreamsUniFrame))
                {
                    frame = maxStreamsUniFrame;
                    return true;
                }
                break;
                
            case FrameType.DataBlocked:
                if (DataBlockedFrame.TryDecode(reader, out var dataBlockedFrame))
                {
                    frame = dataBlockedFrame;
                    return true;
                }
                break;
                
            case FrameType.StreamDataBlocked:
                if (StreamDataBlockedFrame.TryDecode(reader, out var streamDataBlockedFrame))
                {
                    frame = streamDataBlockedFrame;
                    return true;
                }
                break;
                
            case FrameType.StreamsBlockedBidi:
                if (StreamsBlockedFrame.TryDecode(reader, true, out var streamsBlockedBidiFrame))
                {
                    frame = streamsBlockedBidiFrame;
                    return true;
                }
                break;
                
            case FrameType.StreamsBlockedUni:
                if (StreamsBlockedFrame.TryDecode(reader, false, out var streamsBlockedUniFrame))
                {
                    frame = streamsBlockedUniFrame;
                    return true;
                }
                break;
                
            case FrameType.NewConnectionId:
                if (NewConnectionIdFrame.TryDecode(reader, out var newConnectionIdFrame))
                {
                    frame = newConnectionIdFrame;
                    return true;
                }
                break;
                
            case FrameType.RetireConnectionId:
                if (RetireConnectionIdFrame.TryDecode(reader, out var retireConnectionIdFrame))
                {
                    frame = retireConnectionIdFrame;
                    return true;
                }
                break;
                
            case FrameType.PathChallenge:
                if (PathChallengeFrame.TryDecode(reader, out var pathChallengeFrame))
                {
                    frame = pathChallengeFrame;
                    return true;
                }
                break;
                
            case FrameType.PathResponse:
                if (PathResponseFrame.TryDecode(reader, out var pathResponseFrame))
                {
                    frame = pathResponseFrame;
                    return true;
                }
                break;
                
            case FrameType.HandshakeDone:
                if (HandshakeDoneFrame.TryDecode(reader, out var handshakeDoneFrame))
                {
                    frame = handshakeDoneFrame;
                    return true;
                }
                break;
                
            default:
                // Check if it's a STREAM frame (0x08-0x0f)
                if ((typeByte & 0xf8) == 0x08)
                {
                    if (StreamFrame.TryDecode(reader, typeByte, out var streamFrame))
                    {
                        frame = streamFrame;
                        return true;
                    }
                }
                
                // Unknown frame type
                return false;
        }
        
        return false;
    }
    
    /// <summary>
    /// Decodes all frames from a packet.
    /// </summary>
    /// <param name="reader">The frame reader.</param>
    /// <returns>A list of decoded frames.</returns>
    public static List<IQuicFrame> DecodeFrames(FrameReader reader)
    {
        var frames = new List<IQuicFrame>();
        
        while (reader.BytesRemaining > 0)
        {
            if (TryDecodeFrame(reader, out var frame) && frame != null)
            {
                frames.Add(frame);
            }
            else
            {
                // Stop on first failed decode
                break;
            }
        }
        
        return frames;
    }
}