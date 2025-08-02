namespace Qeen.Security.Tls;

public class HandshakeResult
{
    public bool IsComplete { get; init; }
    public byte[]? ApplicationSecret { get; init; }
    public byte[]? HandshakeSecret { get; init; }
    public byte[]? InitialSecret { get; init; }
    public byte[]? TransportParameters { get; init; }
    public byte[]? EarlyDataSecret { get; init; }
    public bool EarlyDataAccepted { get; init; }
}