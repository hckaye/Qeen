namespace Qeen.Core.Packet;

/// <summary>
/// Represents the encryption level for QUIC packets.
/// </summary>
public enum EncryptionLevel
{
    /// <summary>
    /// Initial encryption level using Initial secrets.
    /// </summary>
    Initial,
    
    /// <summary>
    /// Handshake encryption level.
    /// </summary>
    Handshake,
    
    /// <summary>
    /// 0-RTT encryption level for early data.
    /// </summary>
    EarlyData,
    
    /// <summary>
    /// Application data encryption level (1-RTT).
    /// </summary>
    Application
}