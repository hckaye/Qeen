namespace Qeen.Core.Stream;

/// <summary>
/// Represents the type of a QUIC stream
/// </summary>
public enum StreamType
{
    /// <summary>
    /// Bidirectional stream - data can flow in both directions
    /// </summary>
    Bidirectional,

    /// <summary>
    /// Unidirectional stream - data flows in one direction only
    /// </summary>
    Unidirectional
}