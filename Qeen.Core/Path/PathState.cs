namespace Qeen.Core.Path;

/// <summary>
/// Path validation state as defined in RFC 9000 Section 8.2
/// </summary>
public enum PathState
{
    /// <summary>
    /// Path has not been validated
    /// </summary>
    Unknown,
    
    /// <summary>
    /// Path validation is in progress
    /// </summary>
    Validating,
    
    /// <summary>
    /// Path has been validated and is active
    /// </summary>
    Validated,
    
    /// <summary>
    /// Path validation failed
    /// </summary>
    Failed,
    
    /// <summary>
    /// Path was validated but is now abandoned
    /// </summary>
    Abandoned
}