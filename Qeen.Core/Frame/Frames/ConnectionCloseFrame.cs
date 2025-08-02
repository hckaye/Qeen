using System.Text;
using Qeen.Core.Packet;

namespace Qeen.Core.Frame.Frames;

/// <summary>
/// CONNECTION_CLOSE frame (types 0x1c and 0x1d) - signals connection termination.
/// </summary>
public readonly struct ConnectionCloseFrame : IQuicFrame
{
    /// <summary>
    /// Gets whether this is an application-level close (0x1d) or transport-level close (0x1c).
    /// </summary>
    public bool IsApplicationClose { get; }
    
    /// <summary>
    /// Gets the error code.
    /// </summary>
    public ulong ErrorCode { get; }
    
    /// <summary>
    /// Gets the frame type that triggered the error (transport errors only).
    /// </summary>
    public ulong? FrameType { get; }
    
    /// <summary>
    /// Gets the human-readable reason phrase.
    /// </summary>
    public string ReasonPhrase { get; }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="ConnectionCloseFrame"/> struct for application errors.
    /// </summary>
    /// <param name="errorCode">The application error code.</param>
    /// <param name="reasonPhrase">The reason phrase.</param>
    public ConnectionCloseFrame(ulong errorCode, string reasonPhrase)
    {
        IsApplicationClose = true;
        ErrorCode = errorCode;
        FrameType = null;
        ReasonPhrase = reasonPhrase ?? string.Empty;
    }
    
    /// <summary>
    /// Initializes a new instance of the <see cref="ConnectionCloseFrame"/> struct for transport errors.
    /// </summary>
    /// <param name="errorCode">The transport error code.</param>
    /// <param name="frameType">The frame type that triggered the error.</param>
    /// <param name="reasonPhrase">The reason phrase.</param>
    public ConnectionCloseFrame(ulong errorCode, ulong frameType, string reasonPhrase)
    {
        IsApplicationClose = false;
        ErrorCode = errorCode;
        FrameType = frameType;
        ReasonPhrase = reasonPhrase ?? string.Empty;
    }
    
    /// <inheritdoc/>
    public Frame.FrameType Type => IsApplicationClose ? Frame.FrameType.ConnectionCloseApp : Frame.FrameType.ConnectionCloseQuic;
    
    /// <inheritdoc/>
    public void Encode(ref FrameWriter writer)
    {
        writer.WriteByte((byte)Type);
        writer.WriteVariableLength(ErrorCode);
        
        if (!IsApplicationClose)
        {
            writer.WriteVariableLength(FrameType ?? 0);
        }
        
        var reasonBytes = Encoding.UTF8.GetBytes(ReasonPhrase);
        writer.WriteVariableLength((ulong)reasonBytes.Length);
        writer.WriteBytes(reasonBytes);
    }
    
    /// <inheritdoc/>
    public bool IsAllowedInPacketType(PacketType packetType)
    {
        // CONNECTION_CLOSE frames are allowed in all packet types
        return true;
    }
    
    /// <summary>
    /// Decodes a CONNECTION_CLOSE frame from the reader.
    /// </summary>
    /// <param name="reader">The packet reader.</param>
    /// <param name="isApplicationClose">Whether this is an application close frame.</param>
    /// <param name="frame">The decoded frame.</param>
    /// <returns>True if decoding succeeded.</returns>
    public static bool TryDecode(FrameReader reader, bool isApplicationClose, out ConnectionCloseFrame frame)
    {
        frame = default;
        
        if (!reader.TryReadVariableLength(out var errorCode))
            return false;
            
        ulong? frameType = null;
        if (!isApplicationClose)
        {
            if (!reader.TryReadVariableLength(out var ft))
                return false;
            frameType = ft;
        }
        
        if (!reader.TryReadVariableLength(out var reasonLength))
            return false;
            
        if (reasonLength > int.MaxValue || reader.BytesRemaining < (int)reasonLength)
            return false;
            
        var reasonBytes = reader.ReadBytes((int)reasonLength);
        var reasonPhrase = Encoding.UTF8.GetString(reasonBytes);
        
        frame = isApplicationClose 
            ? new ConnectionCloseFrame(errorCode, reasonPhrase)
            : new ConnectionCloseFrame(errorCode, frameType!.Value, reasonPhrase);
            
        return true;
    }
}