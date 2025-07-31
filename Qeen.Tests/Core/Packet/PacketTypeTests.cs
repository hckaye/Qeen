using Xunit;
using Qeen.Core.Packet;

namespace Qeen.Tests.Core.Packet;

public class PacketTypeTests
{
    [Theory]
    [InlineData(PacketType.Initial, 0x00)]
    [InlineData(PacketType.ZeroRtt, 0x01)]
    [InlineData(PacketType.Handshake, 0x02)]
    [InlineData(PacketType.Retry, 0x03)]
    [InlineData(PacketType.OneRtt, 0x40)]
    [InlineData(PacketType.VersionNegotiation, 0xFF)]
    public void PacketType_HasCorrectValues(PacketType type, byte expectedValue)
    {
        Assert.Equal(expectedValue, (byte)type);
    }

    [Fact]
    public void PacketType_AllValuesAreDefined()
    {
        var values = Enum.GetValues<PacketType>();
        
        Assert.Contains(PacketType.Initial, values);
        Assert.Contains(PacketType.ZeroRtt, values);
        Assert.Contains(PacketType.Handshake, values);
        Assert.Contains(PacketType.Retry, values);
        Assert.Contains(PacketType.OneRtt, values);
        Assert.Contains(PacketType.VersionNegotiation, values);
    }
}