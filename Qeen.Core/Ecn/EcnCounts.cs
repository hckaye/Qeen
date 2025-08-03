namespace Qeen.Core.Ecn;

/// <summary>
/// ECN counts as reported in ACK frames per RFC 9000 Section 19.3.2
/// </summary>
public struct EcnCounts
{
    /// <summary>
    /// Total number of packets received with ECT(0) codepoint
    /// </summary>
    public ulong Ect0Count { get; set; }
    
    /// <summary>
    /// Total number of packets received with ECT(1) codepoint
    /// </summary>
    public ulong Ect1Count { get; set; }
    
    /// <summary>
    /// Total number of packets received with CE codepoint
    /// </summary>
    public ulong CeCount { get; set; }
    
    /// <summary>
    /// Gets the total count of all ECN-marked packets
    /// </summary>
    public ulong TotalCount => Ect0Count + Ect1Count + CeCount;
    
    /// <summary>
    /// Creates a new instance with the specified counts
    /// </summary>
    public EcnCounts(ulong ect0, ulong ect1, ulong ce)
    {
        Ect0Count = ect0;
        Ect1Count = ect1;
        CeCount = ce;
    }
    
    /// <summary>
    /// Adds the counts from another EcnCounts instance
    /// </summary>
    public void Add(EcnCounts other)
    {
        Ect0Count += other.Ect0Count;
        Ect1Count += other.Ect1Count;
        CeCount += other.CeCount;
    }
    
    /// <summary>
    /// Subtracts the counts from another EcnCounts instance
    /// </summary>
    public EcnCounts Subtract(EcnCounts other)
    {
        return new EcnCounts(
            Ect0Count - other.Ect0Count,
            Ect1Count - other.Ect1Count,
            CeCount - other.CeCount
        );
    }
    
    /// <summary>
    /// Checks if any count has decreased (which would indicate ECN validation failure)
    /// </summary>
    public bool HasDecreasedFrom(EcnCounts previous)
    {
        return Ect0Count < previous.Ect0Count ||
               Ect1Count < previous.Ect1Count ||
               CeCount < previous.CeCount;
    }
}