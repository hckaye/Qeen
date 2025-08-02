using Qeen.CongestionControl;
using Qeen.CongestionControl.Loss;
using Qeen.Core.Frame;
using Qeen.Core.Packet;
using Xunit;

namespace Qeen.Tests.CongestionControl;

public class NewRenoCongestionControllerTests
{
    [Fact]
    public void NewReno_InitialState()
    {
        var controller = new NewRenoCongestionController(1200);
        
        Assert.Equal(CongestionState.SlowStart, controller.GetState());
        Assert.Equal(12000, controller.GetCongestionWindow()); // 10 * MSS
        Assert.Equal(0, controller.GetBytesInFlight());
        Assert.True(controller.CanSend(1200));
    }
    
    [Fact]
    public void NewReno_OnPacketSent_UpdatesBytesInFlight()
    {
        var controller = new NewRenoCongestionController(1200);
        
        controller.OnPacketSent(1, 1200);
        
        Assert.Equal(1200, controller.GetBytesInFlight());
        Assert.True(controller.CanSend(1200)); // Still room in window
    }
    
    [Fact]
    public void NewReno_SlowStart_DoublesWindow()
    {
        var controller = new NewRenoCongestionController(1200);
        var initialWindow = controller.GetCongestionWindow();
        
        // Send and acknowledge a packet
        controller.OnPacketSent(1, 1200);
        var packet = CreateTestPacket(1, 1200);
        controller.OnPacketAcked(packet);
        
        var newWindow = controller.GetCongestionWindow();
        Assert.Equal(initialWindow + 1200, newWindow);
        Assert.Equal(CongestionState.SlowStart, controller.GetState());
    }
    
    [Fact]
    public void NewReno_OnPacketLost_ReducesWindow()
    {
        var controller = new NewRenoCongestionController(1200);
        var initialWindow = controller.GetCongestionWindow();
        
        // Send and lose a packet
        controller.OnPacketSent(1, 1200);
        var packet = CreateTestPacket(1, 1200);
        controller.OnPacketLost(packet);
        
        var newWindow = controller.GetCongestionWindow();
        Assert.True(newWindow < initialWindow);
        Assert.Equal(CongestionState.Recovery, controller.GetState());
    }
    
    [Fact]
    public void NewReno_OnRetransmissionTimeout_ResetsToMinimum()
    {
        var controller = new NewRenoCongestionController(1200);
        
        // Grow the window
        for (int i = 1; i <= 5; i++)
        {
            controller.OnPacketSent((ulong)i, 1200);
            controller.OnPacketAcked(CreateTestPacket((ulong)i, 1200));
        }
        
        controller.OnRetransmissionTimeout();
        
        Assert.Equal(2400, controller.GetCongestionWindow()); // 2 * MSS
        Assert.Equal(CongestionState.PersistentCongestion, controller.GetState());
    }
    
    [Fact]
    public void NewReno_CanSend_RespectsWindow()
    {
        var controller = new NewRenoCongestionController(1200);
        
        // Fill the congestion window
        var window = controller.GetCongestionWindow();
        var packetsToSend = window / 1200;
        
        for (int i = 0; i < packetsToSend; i++)
        {
            Assert.True(controller.CanSend(1200));
            controller.OnPacketSent((ulong)i, 1200);
        }
        
        // Window should be full
        Assert.False(controller.CanSend(1200));
    }
    
    [Fact]
    public void NewReno_SetMaxDatagramSize_UpdatesWindow()
    {
        var controller = new NewRenoCongestionController(1200);
        
        controller.SetMaxDatagramSize(1500);
        
        // Minimum window should be updated
        controller.OnRetransmissionTimeout();
        Assert.Equal(3000, controller.GetCongestionWindow()); // 2 * 1500
    }
    
    private static SentPacket CreateTestPacket(ulong packetNumber, int size)
    {
        return new SentPacket
        {
            PacketNumber = packetNumber,
            Size = size,
            SentTime = DateTime.UtcNow.AddMilliseconds(-50), // 50ms ago
            IsAckEliciting = true,
            InFlight = true,
            EncryptionLevel = EncryptionLevel.Application,
            Frames = new List<IQuicFrame>()
        };
    }
}