namespace Qeen.Core.Crypto;

/// <summary>
/// Encryption levels used in QUIC as defined in RFC 9001
/// </summary>
public enum EncryptionLevel
{
    /// <summary>
    /// Initial encryption level using initial secrets
    /// </summary>
    Initial = 0,

    /// <summary>
    /// Handshake encryption level
    /// </summary>
    Handshake = 1,

    /// <summary>
    /// 0-RTT encryption level (early data)
    /// </summary>
    ZeroRtt = 2,

    /// <summary>
    /// 1-RTT encryption level (application data)
    /// </summary>
    OneRtt = 3
}