using System;
using Xunit;
using Qeen.Core.Connection;

namespace Qeen.Tests.Core.Connection;

public class ConnectionIdTests
{
    [Fact]
    public void Empty_ReturnsZeroLengthConnectionId()
    {
        var empty = ConnectionId.Empty;
        
        Assert.Equal(0, empty.Length);
        Assert.True(empty.IsEmpty);
        Assert.Equal("Empty", empty.ToString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(20)]
    public void Constructor_WithValidLength_CreatesConnectionId(int length)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i++)
        {
            data[i] = (byte)i;
        }

        var connId = new ConnectionId(data);

        Assert.Equal(length, connId.Length);
        Assert.Equal(length == 0, connId.IsEmpty);
    }

    [Fact]
    public void Constructor_WithTooLongData_ThrowsException()
    {
        var data = new byte[21]; // Max is 20

        Assert.Throws<ArgumentException>(() => new ConnectionId(data));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(8)]
    [InlineData(16)]
    [InlineData(20)]
    public void NewRandom_CreatesRandomConnectionId(byte length)
    {
        var connId1 = ConnectionId.NewRandom(length);
        var connId2 = ConnectionId.NewRandom(length);

        Assert.Equal(length, connId1.Length);
        Assert.Equal(length, connId2.Length);

        if (length > 0)
        {
            // Random values should be different (with very high probability)
            Assert.NotEqual(connId1, connId2);
        }
    }

    [Fact]
    public void NewRandom_WithInvalidLength_ThrowsException()
    {
        Assert.Throws<ArgumentException>(() => ConnectionId.NewRandom(21));
    }

    [Fact]
    public void CopyTo_CopiesCorrectBytes()
    {
        var originalData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var connId = new ConnectionId(originalData);
        var destination = new byte[8];

        int copied = connId.CopyTo(destination);

        Assert.Equal(8, copied);
        Assert.Equal(originalData, destination);
    }

    [Fact]
    public void CopyTo_WithSmallDestination_ThrowsException()
    {
        var connId = new ConnectionId(new byte[] { 1, 2, 3, 4 });
        var destination = new byte[3]; // Too small

        Assert.Throws<ArgumentException>(() => connId.CopyTo(destination));
    }

    [Fact]
    public void AsSpan_ReturnsCorrectSpan()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var connId = new ConnectionId(data);

        var span = connId.AsSpan();

        Assert.Equal(5, span.Length);
        Assert.True(span.SequenceEqual(data));
    }

    [Fact]
    public void AsSpan_ForEmptyConnectionId_ReturnsEmptySpan()
    {
        var empty = ConnectionId.Empty;

        var span = empty.AsSpan();

        Assert.True(span.IsEmpty);
    }

    [Fact]
    public void Equals_WithSameData_ReturnsTrue()
    {
        var data = new byte[] { 1, 2, 3, 4, 5 };
        var connId1 = new ConnectionId(data);
        var connId2 = new ConnectionId(data);

        Assert.True(connId1.Equals(connId2));
        Assert.True(connId1 == connId2);
        Assert.False(connId1 != connId2);
        Assert.Equal(connId1.GetHashCode(), connId2.GetHashCode());
    }

    [Fact]
    public void Equals_WithDifferentData_ReturnsFalse()
    {
        var connId1 = new ConnectionId(new byte[] { 1, 2, 3, 4 });
        var connId2 = new ConnectionId(new byte[] { 1, 2, 3, 5 });

        Assert.False(connId1.Equals(connId2));
        Assert.False(connId1 == connId2);
        Assert.True(connId1 != connId2);
    }

    [Fact]
    public void Equals_WithDifferentLength_ReturnsFalse()
    {
        var connId1 = new ConnectionId(new byte[] { 1, 2, 3 });
        var connId2 = new ConnectionId(new byte[] { 1, 2, 3, 4 });

        Assert.False(connId1.Equals(connId2));
    }

    [Fact]
    public void ToString_ReturnsHexString()
    {
        var connId = new ConnectionId(new byte[] { 0x12, 0x34, 0x56, 0x78 });

        var str = connId.ToString();

        Assert.Equal("12345678", str);
    }

    [Fact]
    public void GetHashCode_ForEmptyConnectionId_ReturnsZero()
    {
        var empty = ConnectionId.Empty;

        Assert.Equal(0, empty.GetHashCode());
    }

    [Fact]
    public void ConnectionId_PreservesDataAcrossOperations()
    {
        var originalData = new byte[20];
        for (int i = 0; i < 20; i++)
        {
            originalData[i] = (byte)(i * 13); // Some pattern
        }

        var connId = new ConnectionId(originalData);
        var copiedData = new byte[20];
        connId.CopyTo(copiedData);

        Assert.Equal(originalData, copiedData);
        Assert.True(connId.AsSpan().SequenceEqual(originalData));
    }
}