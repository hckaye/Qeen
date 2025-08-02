using Qeen.Core.Connection;

namespace Qeen.Core.Frame;

/// <summary>
/// Processes QUIC frames received from the network.
/// </summary>
public interface IFrameProcessor
{
    /// <summary>
    /// Processes a frame in the context of a connection.
    /// </summary>
    /// <param name="frame">The frame to process.</param>
    /// <param name="connection">The connection context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task ProcessFrameAsync(IQuicFrame frame, IQuicConnection connection, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Checks if a frame type can be processed in a specific packet type.
    /// </summary>
    /// <param name="frameType">The frame type to check.</param>
    /// <param name="packetType">The packet type containing the frame.</param>
    /// <returns>True if the frame type is allowed in the packet type.</returns>
    bool CanProcessInPacketType(FrameType frameType, PacketType packetType);
}