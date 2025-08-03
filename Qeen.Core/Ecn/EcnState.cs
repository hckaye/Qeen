namespace Qeen.Core.Ecn;

/// <summary>
/// ECN (Explicit Congestion Notification) state for a QUIC connection
/// as defined in RFC 9002 Section 3 and RFC 3168
/// </summary>
public enum EcnState
{
    /// <summary>
    /// ECN is not enabled or not supported
    /// </summary>
    Disabled,
    
    /// <summary>
    /// ECN capability is being tested
    /// </summary>
    Testing,
    
    /// <summary>
    /// ECN is capable but not experiencing congestion
    /// </summary>
    Capable,
    
    /// <summary>
    /// ECN has detected congestion
    /// </summary>
    CongestionExperienced,
    
    /// <summary>
    /// ECN validation failed
    /// </summary>
    Failed
}