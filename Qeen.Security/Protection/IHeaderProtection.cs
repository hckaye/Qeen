namespace Qeen.Security.Protection;

public interface IHeaderProtection
{
    void Apply(Span<byte> packet, int headerLength);
    void Remove(Span<byte> packet, int headerLength);
}