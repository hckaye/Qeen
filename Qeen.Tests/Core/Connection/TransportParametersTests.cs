using System.Net;
using Xunit;
using Qeen.Core.Connection;

namespace Qeen.Tests.Core.Connection;

public class TransportParametersTests
{
    [Fact]
    public void GetDefault_ReturnsValidDefaultParameters()
    {
        var defaults = TransportParameters.GetDefault();

        Assert.Equal(30000u, defaults.MaxIdleTimeout);
        Assert.Equal(1200u, defaults.MaxUdpPayloadSize);
        Assert.Equal(1048576u, defaults.InitialMaxData);
        Assert.Equal(524288u, defaults.InitialMaxStreamDataBidiLocal);
        Assert.Equal(524288u, defaults.InitialMaxStreamDataBidiRemote);
        Assert.Equal(524288u, defaults.InitialMaxStreamDataUni);
        Assert.Equal(100u, defaults.InitialMaxStreamsBidi);
        Assert.Equal(100u, defaults.InitialMaxStreamsUni);
        Assert.Equal(3u, defaults.AckDelayExponent);
        Assert.Equal(25u, defaults.MaxAckDelay);
        Assert.False(defaults.DisableActiveMigration);
        Assert.Equal(2u, defaults.ActiveConnectionIdLimit);
        Assert.Equal(0u, defaults.MaxDatagramFrameSize);
        Assert.Null(defaults.PreferredAddress);
        Assert.Null(defaults.InitialSourceConnectionId);
        Assert.Null(defaults.RetrySourceConnectionId);
    }

    [Fact]
    public void TransportParameters_CanSetAllProperties()
    {
        var connId = ConnectionId.NewRandom(8);
        var preferredAddr = new PreferredAddress
        {
            IPv4Address = new IPEndPoint(IPAddress.Loopback, 443),
            IPv6Address = new IPEndPoint(IPAddress.IPv6Loopback, 443),
            ConnectionId = connId,
            StatelessResetToken = new byte[16]
        };

        var parameters = new TransportParameters
        {
            MaxIdleTimeout = 60000,
            MaxUdpPayloadSize = 1500,
            InitialMaxData = 2097152,
            InitialMaxStreamDataBidiLocal = 1048576,
            InitialMaxStreamDataBidiRemote = 1048576,
            InitialMaxStreamDataUni = 1048576,
            InitialMaxStreamsBidi = 200,
            InitialMaxStreamsUni = 200,
            AckDelayExponent = 4,
            MaxAckDelay = 50,
            DisableActiveMigration = true,
            PreferredAddress = preferredAddr,
            ActiveConnectionIdLimit = 4,
            InitialSourceConnectionId = connId,
            RetrySourceConnectionId = connId,
            MaxDatagramFrameSize = 1200
        };

        Assert.Equal(60000u, parameters.MaxIdleTimeout);
        Assert.Equal(1500u, parameters.MaxUdpPayloadSize);
        Assert.Equal(2097152u, parameters.InitialMaxData);
        Assert.Equal(1048576u, parameters.InitialMaxStreamDataBidiLocal);
        Assert.Equal(1048576u, parameters.InitialMaxStreamDataBidiRemote);
        Assert.Equal(1048576u, parameters.InitialMaxStreamDataUni);
        Assert.Equal(200u, parameters.InitialMaxStreamsBidi);
        Assert.Equal(200u, parameters.InitialMaxStreamsUni);
        Assert.Equal(4u, parameters.AckDelayExponent);
        Assert.Equal(50u, parameters.MaxAckDelay);
        Assert.True(parameters.DisableActiveMigration);
        Assert.Equal(4u, parameters.ActiveConnectionIdLimit);
        Assert.Equal(1200u, parameters.MaxDatagramFrameSize);
        Assert.NotNull(parameters.PreferredAddress);
        Assert.NotNull(parameters.InitialSourceConnectionId);
        Assert.NotNull(parameters.RetrySourceConnectionId);
    }

    [Fact]
    public void PreferredAddress_CanSetProperties()
    {
        var connId = ConnectionId.NewRandom(16);
        var resetToken = new byte[16];
        Random.Shared.NextBytes(resetToken);

        var preferredAddr = new PreferredAddress
        {
            IPv4Address = new IPEndPoint(IPAddress.Parse("192.168.1.1"), 4433),
            IPv6Address = new IPEndPoint(IPAddress.Parse("::1"), 4433),
            ConnectionId = connId,
            StatelessResetToken = resetToken
        };

        Assert.NotNull(preferredAddr.IPv4Address);
        Assert.Equal("192.168.1.1", preferredAddr.IPv4Address.Address.ToString());
        Assert.Equal(4433, preferredAddr.IPv4Address.Port);
        
        Assert.NotNull(preferredAddr.IPv6Address);
        Assert.Equal("::1", preferredAddr.IPv6Address.Address.ToString());
        Assert.Equal(4433, preferredAddr.IPv6Address.Port);
        
        Assert.Equal(connId, preferredAddr.ConnectionId);
        Assert.Equal(16, preferredAddr.StatelessResetToken.Length);
    }
}