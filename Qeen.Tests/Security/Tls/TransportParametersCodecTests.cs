using System;
using Xunit;
using Qeen.Core.Connection;
using Qeen.Security.Tls;

namespace Qeen.Tests.Security.Tls;

public class TransportParametersCodecTests
{
    [Fact]
    public void Encode_Decode_RoundTrip_ClientParameters()
    {
        // Arrange
        var original = new TransportParameters
        {
            MaxIdleTimeout = 30000,
            MaxUdpPayloadSize = 1350,
            InitialMaxData = 1048576,
            InitialMaxStreamDataBidiLocal = 524288,
            InitialMaxStreamDataBidiRemote = 524288,
            InitialMaxStreamDataUni = 262144,
            InitialMaxStreamsBidi = 100,
            InitialMaxStreamsUni = 50,
            AckDelayExponent = 3,
            MaxAckDelay = 25,
            DisableActiveMigration = false,
            ActiveConnectionIdLimit = 4,
            InitialSourceConnectionId = new ConnectionId(new byte[] { 1, 2, 3, 4 })
        };

        // Act
        var encoded = TransportParametersCodec.Encode(original, isServer: false);
        var decoded = TransportParametersCodec.Decode(encoded, isServer: false);

        // Assert
        Assert.Equal(original.MaxIdleTimeout, decoded.MaxIdleTimeout);
        Assert.Equal(original.MaxUdpPayloadSize, decoded.MaxUdpPayloadSize);
        Assert.Equal(original.InitialMaxData, decoded.InitialMaxData);
        Assert.Equal(original.InitialMaxStreamDataBidiLocal, decoded.InitialMaxStreamDataBidiLocal);
        Assert.Equal(original.InitialMaxStreamDataBidiRemote, decoded.InitialMaxStreamDataBidiRemote);
        Assert.Equal(original.InitialMaxStreamDataUni, decoded.InitialMaxStreamDataUni);
        Assert.Equal(original.InitialMaxStreamsBidi, decoded.InitialMaxStreamsBidi);
        Assert.Equal(original.InitialMaxStreamsUni, decoded.InitialMaxStreamsUni);
        Assert.Equal(original.AckDelayExponent, decoded.AckDelayExponent);
        Assert.Equal(original.MaxAckDelay, decoded.MaxAckDelay);
        Assert.Equal(original.DisableActiveMigration, decoded.DisableActiveMigration);
        Assert.Equal(original.ActiveConnectionIdLimit, decoded.ActiveConnectionIdLimit);
        Assert.Equal(original.InitialSourceConnectionId, decoded.InitialSourceConnectionId);
    }

    [Fact]
    public void Encode_Decode_RoundTrip_ServerParameters()
    {
        // Arrange
        var original = new TransportParameters
        {
            MaxIdleTimeout = 60000,
            MaxUdpPayloadSize = 1500,
            InitialMaxData = 2097152,
            InitialMaxStreamDataBidiLocal = 1048576,
            InitialMaxStreamDataBidiRemote = 1048576,
            InitialMaxStreamDataUni = 524288,
            InitialMaxStreamsBidi = 200,
            InitialMaxStreamsUni = 100,
            AckDelayExponent = 4,
            MaxAckDelay = 50,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 8,
            InitialSourceConnectionId = new ConnectionId(new byte[] { 5, 6, 7, 8 }),
            RetrySourceConnectionId = new ConnectionId(new byte[] { 9, 10, 11, 12 }),
            StatelessResetToken = new byte[16] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }
        };

        // Act
        var encoded = TransportParametersCodec.Encode(original, isServer: true);
        var decoded = TransportParametersCodec.Decode(encoded, isServer: true);

        // Assert
        Assert.Equal(original.MaxIdleTimeout, decoded.MaxIdleTimeout);
        Assert.Equal(original.MaxUdpPayloadSize, decoded.MaxUdpPayloadSize);
        Assert.Equal(original.InitialMaxData, decoded.InitialMaxData);
        Assert.Equal(original.InitialMaxStreamDataBidiLocal, decoded.InitialMaxStreamDataBidiLocal);
        Assert.Equal(original.InitialMaxStreamDataBidiRemote, decoded.InitialMaxStreamDataBidiRemote);
        Assert.Equal(original.InitialMaxStreamDataUni, decoded.InitialMaxStreamDataUni);
        Assert.Equal(original.InitialMaxStreamsBidi, decoded.InitialMaxStreamsBidi);
        Assert.Equal(original.InitialMaxStreamsUni, decoded.InitialMaxStreamsUni);
        Assert.Equal(original.AckDelayExponent, decoded.AckDelayExponent);
        Assert.Equal(original.MaxAckDelay, decoded.MaxAckDelay);
        Assert.Equal(original.DisableActiveMigration, decoded.DisableActiveMigration);
        Assert.Equal(original.ActiveConnectionIdLimit, decoded.ActiveConnectionIdLimit);
        Assert.Equal(original.InitialSourceConnectionId, decoded.InitialSourceConnectionId);
        Assert.Equal(original.RetrySourceConnectionId, decoded.RetrySourceConnectionId);
        Assert.Equal(original.StatelessResetToken, decoded.StatelessResetToken);
    }

    [Fact]
    public void Encode_DefaultValues_ProducesMinimalOutput()
    {
        // Arrange
        var parameters = TransportParameters.GetDefault();

        // Act
        var encoded = TransportParametersCodec.Encode(parameters, isServer: false);

        // Assert
        Assert.NotNull(encoded);
        Assert.True(encoded.Length > 0);
        // Default values should result in relatively small encoding
        Assert.True(encoded.Length < 200);
    }

    [Fact]
    public void Decode_EmptyData_ReturnsDefaults()
    {
        // Act
        var decoded = TransportParametersCodec.Decode(Array.Empty<byte>(), isServer: false);

        // Assert
        // Should return a valid TransportParameters with defaults from GetDefault()
        var defaults = TransportParameters.GetDefault();
        Assert.Equal(defaults.MaxIdleTimeout, decoded.MaxIdleTimeout);
    }

    [Fact]
    public void Encode_MaxDatagramFrameSize_OnlyIncludedWhenNonZero()
    {
        // Arrange
        var paramsWithoutDatagram = new TransportParameters
        {
            MaxDatagramFrameSize = 0, // Datagram not supported
            InitialMaxData = 1000
        };

        var paramsWithDatagram = new TransportParameters
        {
            MaxDatagramFrameSize = 1200, // Datagram supported
            InitialMaxData = 1000
        };

        // Act
        var encodedWithout = TransportParametersCodec.Encode(paramsWithoutDatagram, isServer: false);
        var encodedWith = TransportParametersCodec.Encode(paramsWithDatagram, isServer: false);

        // Assert
        Assert.True(encodedWith.Length > encodedWithout.Length);
    }

    [Fact]
    public void TlsExtensionType_IsCorrect()
    {
        // Assert
        Assert.Equal(0xffa5, TransportParametersCodec.TlsExtensionType);
    }

    [Fact]
    public void Encode_DisableActiveMigration_OnlyIncludedWhenTrue()
    {
        // Arrange
        var paramsWithMigration = new TransportParameters
        {
            DisableActiveMigration = false,
            InitialMaxData = 1000
        };

        var paramsWithoutMigration = new TransportParameters
        {
            DisableActiveMigration = true,
            InitialMaxData = 1000
        };

        // Act
        var encodedWith = TransportParametersCodec.Encode(paramsWithMigration, isServer: false);
        var encodedWithout = TransportParametersCodec.Encode(paramsWithoutMigration, isServer: false);

        // Assert
        // When DisableActiveMigration is true, it adds the parameter
        Assert.True(encodedWithout.Length > encodedWith.Length);
    }

    [Fact]
    public void Decode_InvalidVarint_ThrowsException()
    {
        // Arrange
        var invalidData = new byte[] { 0xFF }; // Incomplete varint

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => 
            TransportParametersCodec.Decode(invalidData, isServer: false));
    }

    [Fact]
    public void Encode_ConnectionId_HandledCorrectly()
    {
        // Arrange
        var parameters = new TransportParameters
        {
            InitialSourceConnectionId = new ConnectionId(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD })
        };

        // Act
        var encoded = TransportParametersCodec.Encode(parameters, isServer: false);
        var decoded = TransportParametersCodec.Decode(encoded, isServer: false);

        // Assert
        Assert.NotNull(decoded.InitialSourceConnectionId);
        Assert.Equal(parameters.InitialSourceConnectionId, decoded.InitialSourceConnectionId);
    }
}