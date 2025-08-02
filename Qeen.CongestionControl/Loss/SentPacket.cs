using Qeen.Core.Frame;
using Qeen.Core.Packet;

namespace Qeen.CongestionControl.Loss;

/// <summary>
/// Represents information about a sent packet for loss detection and congestion control.
/// </summary>
public readonly struct SentPacket
{
    /// <summary>
    /// The packet number of the sent packet.
    /// </summary>
    public ulong PacketNumber { get; init; }
    
    /// <summary>
    /// The size of the packet in bytes.
    /// </summary>
    public int Size { get; init; }
    
    /// <summary>
    /// The time when the packet was sent.
    /// </summary>
    public DateTime SentTime { get; init; }
    
    /// <summary>
    /// Whether this packet elicits an ACK.
    /// </summary>
    public bool IsAckEliciting { get; init; }
    
    /// <summary>
    /// Whether this packet counts towards bytes in flight.
    /// </summary>
    public bool InFlight { get; init; }
    
    /// <summary>
    /// The encryption level of the packet.
    /// </summary>
    public EncryptionLevel EncryptionLevel { get; init; }
    
    /// <summary>
    /// The frames contained in this packet.
    /// </summary>
    public IReadOnlyList<IQuicFrame> Frames { get; init; }
    
    /// <summary>
    /// Creates a new SentPacket instance.
    /// </summary>
    public SentPacket(
        ulong packetNumber,
        int size,
        DateTime sentTime,
        bool isAckEliciting,
        bool inFlight,
        EncryptionLevel encryptionLevel,
        IReadOnlyList<IQuicFrame> frames)
    {
        PacketNumber = packetNumber;
        Size = size;
        SentTime = sentTime;
        IsAckEliciting = isAckEliciting;
        InFlight = inFlight;
        EncryptionLevel = encryptionLevel;
        Frames = frames ?? Array.Empty<IQuicFrame>();
    }
}