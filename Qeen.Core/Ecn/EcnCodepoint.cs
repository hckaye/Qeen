namespace Qeen.Core.Ecn;

/// <summary>
/// ECN codepoints as defined in RFC 3168
/// These are the values used in the ECN field of the IP header
/// </summary>
public enum EcnCodepoint : byte
{
    /// <summary>
    /// Not ECN-Capable Transport (Not-ECT)
    /// </summary>
    NotEct = 0b00,
    
    /// <summary>
    /// ECN-Capable Transport (ECT(0))
    /// </summary>
    Ect0 = 0b10,
    
    /// <summary>
    /// ECN-Capable Transport (ECT(1))
    /// </summary>
    Ect1 = 0b01,
    
    /// <summary>
    /// Congestion Experienced (CE)
    /// </summary>
    CongestionExperienced = 0b11
}