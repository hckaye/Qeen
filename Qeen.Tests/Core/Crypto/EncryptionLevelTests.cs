using Xunit;
using Qeen.Core.Crypto;

namespace Qeen.Tests.Core.Crypto;

public class EncryptionLevelTests
{
    [Theory]
    [InlineData(EncryptionLevel.Initial, 0)]
    [InlineData(EncryptionLevel.Handshake, 1)]
    [InlineData(EncryptionLevel.ZeroRtt, 2)]
    [InlineData(EncryptionLevel.OneRtt, 3)]
    public void EncryptionLevel_HasCorrectValues(EncryptionLevel level, int expectedValue)
    {
        Assert.Equal(expectedValue, (int)level);
    }

    [Fact]
    public void EncryptionLevel_HasAllLevels()
    {
        var values = Enum.GetValues<EncryptionLevel>();
        
        Assert.Equal(4, values.Length);
        Assert.Contains(EncryptionLevel.Initial, values);
        Assert.Contains(EncryptionLevel.Handshake, values);
        Assert.Contains(EncryptionLevel.ZeroRtt, values);
        Assert.Contains(EncryptionLevel.OneRtt, values);
    }

    [Fact]
    public void EncryptionLevel_OrderMatches_RFC9001()
    {
        // According to RFC 9001, encryption levels have a specific order
        Assert.True(EncryptionLevel.Initial < EncryptionLevel.Handshake);
        Assert.True(EncryptionLevel.Handshake < EncryptionLevel.ZeroRtt);
        Assert.True(EncryptionLevel.ZeroRtt < EncryptionLevel.OneRtt);
    }
}