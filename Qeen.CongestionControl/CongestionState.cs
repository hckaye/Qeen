namespace Qeen.CongestionControl;

/// <summary>
/// Represents the state of congestion control.
/// </summary>
public enum CongestionState
{
    /// <summary>
    /// Slow start phase - exponential growth.
    /// </summary>
    SlowStart,
    
    /// <summary>
    /// Congestion avoidance phase - linear growth.
    /// </summary>
    CongestionAvoidance,
    
    /// <summary>
    /// Recovery phase after packet loss.
    /// </summary>
    Recovery,
    
    /// <summary>
    /// Persistent congestion detected.
    /// </summary>
    PersistentCongestion
}