using System.Reflection;
using System.Threading.Tasks;
using Xunit;
using Qeen.Core.Packet;

namespace Qeen.Tests.Core.Packet;

public class PacketNumberSpaceTests
{
    [Fact]
    public void Constructor_InitializesCorrectly()
    {
        var space = new PacketNumberSpace();
        
        Assert.Equal(-1, space.LargestAcked);
        Assert.Equal(-1, space.LargestReceived);
        Assert.Equal(0, space.NextPacketNumber);
    }

    [Fact]
    public void GetNextPacketNumber_IncrementsSequentially()
    {
        var space = new PacketNumberSpace();
        
        Assert.Equal(0, space.GetNextPacketNumber());
        Assert.Equal(1, space.GetNextPacketNumber());
        Assert.Equal(2, space.GetNextPacketNumber());
        Assert.Equal(3, space.GetNextPacketNumber());
        
        Assert.Equal(4, space.NextPacketNumber);
    }

    [Fact]
    public void UpdateLargestAcked_UpdatesWhenLarger()
    {
        var space = new PacketNumberSpace();
        
        space.UpdateLargestAcked(10);
        Assert.Equal(10, space.LargestAcked);
        
        space.UpdateLargestAcked(20);
        Assert.Equal(20, space.LargestAcked);
        
        // Should not update when smaller
        space.UpdateLargestAcked(15);
        Assert.Equal(20, space.LargestAcked);
        
        // Should not update when equal
        space.UpdateLargestAcked(20);
        Assert.Equal(20, space.LargestAcked);
    }

    [Fact]
    public void UpdateLargestReceived_UpdatesWhenLarger()
    {
        var space = new PacketNumberSpace();
        
        space.UpdateLargestReceived(5);
        Assert.Equal(5, space.LargestReceived);
        
        space.UpdateLargestReceived(15);
        Assert.Equal(15, space.LargestReceived);
        
        // Should not update when smaller
        space.UpdateLargestReceived(10);
        Assert.Equal(15, space.LargestReceived);
    }

    [Fact]
    public void IsValidPacketNumber_ReturnsTrueForNewPackets()
    {
        var space = new PacketNumberSpace();
        space.UpdateLargestReceived(100);
        
        // Packets larger than largest received are valid
        Assert.True(space.IsValidPacketNumber(101));
        Assert.True(space.IsValidPacketNumber(200));
        Assert.True(space.IsValidPacketNumber(1000));
    }

    [Fact]
    public void IsValidPacketNumber_AllowsReorderingWithinThreshold()
    {
        var space = new PacketNumberSpace();
        space.UpdateLargestReceived(1500);
        
        // Within reordering threshold (1000 packets)
        Assert.True(space.IsValidPacketNumber(501));
        Assert.True(space.IsValidPacketNumber(1000));
        Assert.True(space.IsValidPacketNumber(1499));
        
        // Outside reordering threshold
        Assert.False(space.IsValidPacketNumber(499));
        Assert.False(space.IsValidPacketNumber(0));
    }

    [Theory]
    [InlineData(0, 0, 1)]
    [InlineData(100, 50, 1)]
    [InlineData(200, 50, 2)]
    [InlineData(50000, 30000, 2)]
    [InlineData(10000000, 1000000, 4)]
    public void GetPacketNumberLength_ReturnsOptimalLength(long packetNumber, long largestAcked, int expectedLength)
    {
        var space = new PacketNumberSpace();
        space.UpdateLargestAcked(largestAcked);
        
        int length = space.GetPacketNumberLength(packetNumber);
        
        Assert.Equal(expectedLength, length);
    }

    [Fact]
    public void GetPacketNumberLength_WithNoAckedPackets_UsesZero()
    {
        var space = new PacketNumberSpace();
        // LargestAcked is -1, should be treated as 0
        
        Assert.Equal(1, space.GetPacketNumberLength(0));
        Assert.Equal(1, space.GetPacketNumberLength(100));
        Assert.Equal(2, space.GetPacketNumberLength(200));
    }

    [Fact]
    public void Reset_ResetsAllValues()
    {
        var space = new PacketNumberSpace();
        
        // Set some values
        space.UpdateLargestAcked(100);
        space.UpdateLargestReceived(200);
        space.GetNextPacketNumber();
        space.GetNextPacketNumber();
        
        // Reset
        space.Reset();
        
        Assert.Equal(-1, space.LargestAcked);
        Assert.Equal(-1, space.LargestReceived);
        Assert.Equal(0, space.NextPacketNumber);
    }

    [Fact]
    public void GetNextPacketNumber_ThrowsOnOverflow()
    {
        var space = new PacketNumberSpace();
        
        // Use reflection to set the internal counter near the maximum value
        var field = typeof(PacketNumberSpace).GetField("_nextPacketNumber", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(field);
        
        const long maxPacketNumber = (1L << 62) - 1;
        
        // Test 1: Verify we can return exactly MaxPacketNumber
        // When _nextPacketNumber = MaxPacketNumber + 1:
        // - Interlocked.Increment changes it to MaxPacketNumber + 2 and returns MaxPacketNumber + 2
        // - We subtract 1, returning MaxPacketNumber + 1
        // But wait, that's already over the limit!
        
        // Actually, when _nextPacketNumber = MaxPacketNumber:
        // - Interlocked.Increment changes it to MaxPacketNumber + 1 and returns MaxPacketNumber + 1
        // - We subtract 1, returning MaxPacketNumber (exactly at the limit, should be OK)
        field.SetValueDirect(__makeref(space), maxPacketNumber);
        var pn = space.GetNextPacketNumber();
        Assert.Equal(maxPacketNumber, pn);
        
        // Now _nextPacketNumber = MaxPacketNumber + 1
        // The next call should throw
        var ex = Assert.Throws<InvalidOperationException>(() => space.GetNextPacketNumber());
        Assert.Contains("Packet number would exceed maximum value", ex.Message);
        Assert.Contains("AEAD_LIMIT_REACHED", ex.Message);
    }

    [Fact]
    public async Task ConcurrentUpdates_AreThreadSafe()
    {
        var space = new PacketNumberSpace();
        const int iterations = 1000;
        
        // Run multiple tasks updating different values concurrently
        var tasks = new[]
        {
            Task.Run(() =>
            {
                for (int i = 0; i < iterations; i++)
                {
                    space.GetNextPacketNumber();
                }
            }),
            Task.Run(() =>
            {
                for (int i = 0; i < iterations; i++)
                {
                    space.UpdateLargestAcked(i);
                }
            }),
            Task.Run(() =>
            {
                for (int i = 0; i < iterations; i++)
                {
                    space.UpdateLargestReceived(i);
                }
            })
        };
        
        await Task.WhenAll(tasks);
        
        // Verify final state is consistent
        Assert.Equal(iterations, space.NextPacketNumber);
        Assert.Equal(iterations - 1, space.LargestAcked);
        Assert.Equal(iterations - 1, space.LargestReceived);
    }

    [Fact]
    public void PacketNumberSpaceManager_InitializesAllSpaces()
    {
        var manager = new PacketNumberSpaceManager();
        
        // PacketNumberSpace is a value type, no need to check for null
        
        Assert.Equal(-1, manager.Initial.LargestAcked);
        Assert.Equal(-1, manager.Handshake.LargestAcked);
        Assert.Equal(-1, manager.ApplicationData.LargestAcked);
    }

    [Theory]
    [InlineData(PacketType.Initial)]
    [InlineData(PacketType.Retry)]
    public void GetSpace_ReturnsInitialSpace(PacketType type)
    {
        var manager = new PacketNumberSpaceManager();
        
        ref var space = ref manager.GetSpace(type);
        space.UpdateLargestAcked(100);
        
        Assert.Equal(100, manager.Initial.LargestAcked);
        Assert.Equal(-1, manager.Handshake.LargestAcked);
        Assert.Equal(-1, manager.ApplicationData.LargestAcked);
    }

    [Fact]
    public void GetSpace_ReturnsHandshakeSpace()
    {
        var manager = new PacketNumberSpaceManager();
        
        ref var space = ref manager.GetSpace(PacketType.Handshake);
        space.UpdateLargestAcked(200);
        
        Assert.Equal(-1, manager.Initial.LargestAcked);
        Assert.Equal(200, manager.Handshake.LargestAcked);
        Assert.Equal(-1, manager.ApplicationData.LargestAcked);
    }

    [Theory]
    [InlineData(PacketType.ZeroRtt)]
    [InlineData(PacketType.OneRtt)]
    public void GetSpace_ReturnsApplicationDataSpace(PacketType type)
    {
        var manager = new PacketNumberSpaceManager();
        
        ref var space = ref manager.GetSpace(type);
        space.UpdateLargestAcked(300);
        
        Assert.Equal(-1, manager.Initial.LargestAcked);
        Assert.Equal(-1, manager.Handshake.LargestAcked);
        Assert.Equal(300, manager.ApplicationData.LargestAcked);
    }

    [Fact]
    public void GetSpace_WithInvalidType_ThrowsException()
    {
        var manager = new PacketNumberSpaceManager();
        
        Assert.Throws<ArgumentException>(() => 
            manager.GetSpace(PacketType.VersionNegotiation));
    }

    [Fact]
    public void Reset_ResetsAllSpaces()
    {
        var manager = new PacketNumberSpaceManager();
        
        // Set values in all spaces
        manager.Initial.UpdateLargestAcked(100);
        manager.Handshake.UpdateLargestAcked(200);
        manager.ApplicationData.UpdateLargestAcked(300);
        
        manager.Initial.GetNextPacketNumber();
        manager.Handshake.GetNextPacketNumber();
        manager.ApplicationData.GetNextPacketNumber();
        
        // Reset
        manager.Reset();
        
        // Verify all spaces are reset
        Assert.Equal(-1, manager.Initial.LargestAcked);
        Assert.Equal(-1, manager.Handshake.LargestAcked);
        Assert.Equal(-1, manager.ApplicationData.LargestAcked);
        
        Assert.Equal(0, manager.Initial.NextPacketNumber);
        Assert.Equal(0, manager.Handshake.NextPacketNumber);
        Assert.Equal(0, manager.ApplicationData.NextPacketNumber);
    }

    [Fact]
    public void IndependentSpaces_MaintainSeparateState()
    {
        var manager = new PacketNumberSpaceManager();
        
        // Get packet numbers from different spaces
        var initial1 = manager.Initial.GetNextPacketNumber();
        var initial2 = manager.Initial.GetNextPacketNumber();
        
        var handshake1 = manager.Handshake.GetNextPacketNumber();
        var handshake2 = manager.Handshake.GetNextPacketNumber();
        
        var app1 = manager.ApplicationData.GetNextPacketNumber();
        var app2 = manager.ApplicationData.GetNextPacketNumber();
        
        // Each space should maintain its own sequence
        Assert.Equal(0, initial1);
        Assert.Equal(1, initial2);
        
        Assert.Equal(0, handshake1);
        Assert.Equal(1, handshake2);
        
        Assert.Equal(0, app1);
        Assert.Equal(1, app2);
    }
}