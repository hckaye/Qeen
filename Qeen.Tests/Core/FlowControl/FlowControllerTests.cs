using Qeen.Core.Exceptions;
using Qeen.Core.FlowControl;
using Xunit;

namespace Qeen.Tests.Core.FlowControl;

public class FlowControllerTests
{
    [Fact]
    public void FlowController_InitialState()
    {
        var controller = new FlowController(1000);
        
        Assert.Equal(1000u, controller.MaxData);
        Assert.Equal(0u, controller.DataConsumed);
        Assert.Equal(0u, controller.DataSent);
        Assert.Equal(1000u, controller.AvailableWindow);
        Assert.False(controller.IsBlocked());
    }
    
    [Fact]
    public void FlowController_CanSend_WithinLimit()
    {
        var controller = new FlowController(1000);
        
        Assert.True(controller.CanSend(500));
        Assert.True(controller.CanSend(1000));
        Assert.False(controller.CanSend(1001));
    }
    
    [Fact]
    public void FlowController_RecordDataSent_UpdatesState()
    {
        var controller = new FlowController(1000);
        
        controller.RecordDataSent(300);
        Assert.Equal(300u, controller.DataSent);
        Assert.Equal(700u, controller.AvailableWindow);
        
        controller.RecordDataSent(400);
        Assert.Equal(700u, controller.DataSent);
        Assert.Equal(300u, controller.AvailableWindow);
    }
    
    [Fact]
    public void FlowController_RecordDataSent_ThrowsOnViolation()
    {
        var controller = new FlowController(1000);
        
        controller.RecordDataSent(800);
        
        var ex = Assert.Throws<QuicException>(() => controller.RecordDataSent(300));
        Assert.Equal(QuicErrorCode.FlowControlError, ex.ErrorCode);
        Assert.Contains("Flow control violation", ex.Message);
    }
    
    [Fact]
    public void FlowController_UpdateMaxData_OnlyIncreases()
    {
        var controller = new FlowController(1000);
        
        // Should update to higher value
        controller.UpdateMaxData(2000);
        Assert.Equal(2000u, controller.MaxData);
        
        // Should ignore lower value
        controller.UpdateMaxData(1500);
        Assert.Equal(2000u, controller.MaxData);
        
        // Should ignore equal value
        controller.UpdateMaxData(2000);
        Assert.Equal(2000u, controller.MaxData);
    }
    
    [Fact]
    public void FlowController_IsBlocked_WhenAtLimit()
    {
        var controller = new FlowController(1000);
        
        controller.RecordDataSent(1000);
        Assert.True(controller.IsBlocked());
        Assert.Equal(0u, controller.AvailableWindow);
    }
    
    [Fact]
    public void FlowController_ValidateIncomingData_WithinLimit()
    {
        var controller = new FlowController(1000);
        
        // Should not throw for data within limit
        controller.ValidateIncomingData(0, 500);
        controller.ValidateIncomingData(500, 500);
    }
    
    [Fact]
    public void FlowController_ValidateIncomingData_ThrowsOnViolation()
    {
        var controller = new FlowController(1000);
        
        var ex = Assert.Throws<QuicException>(() => controller.ValidateIncomingData(500, 600));
        Assert.Equal(QuicErrorCode.FlowControlError, ex.ErrorCode);
        Assert.Contains("Flow control violation", ex.Message);
        Assert.Contains("Received data beyond advertised limit", ex.Message);
    }
    
    [Fact]
    public void FlowController_Reset_ClearsCounters()
    {
        var controller = new FlowController(1000);
        
        controller.RecordDataSent(500);
        controller.RecordDataConsumed(300);
        
        controller.Reset();
        
        Assert.Equal(0u, controller.DataSent);
        Assert.Equal(0u, controller.DataConsumed);
        Assert.Equal(1000u, controller.MaxData); // MaxData should persist
        Assert.Equal(1000u, controller.AvailableWindow);
    }
}

public class StreamFlowControllerTests
{
    [Fact]
    public void StreamFlowController_InitialState()
    {
        var controller = new StreamFlowController(123, 1000);
        
        Assert.Equal(123u, controller.StreamId);
        Assert.Equal(1000u, controller.MaxStreamData);
        Assert.Equal(0u, controller.DataConsumed);
        Assert.Equal(0u, controller.DataSent);
        Assert.Equal(1000u, controller.AvailableWindow);
        Assert.False(controller.IsBlocked());
    }
    
    [Fact]
    public void StreamFlowController_RecordDataSent_TracksHighestOffset()
    {
        var controller = new StreamFlowController(123, 1000);
        
        // Send data at offset 0
        controller.RecordDataSent(0, 300);
        Assert.Equal(300u, controller.DataSent);
        
        // Send data at offset 300
        controller.RecordDataSent(300, 200);
        Assert.Equal(500u, controller.DataSent);
        
        // Retransmit data at offset 100 (should not increase DataSent)
        controller.RecordDataSent(100, 100);
        Assert.Equal(500u, controller.DataSent);
    }
    
    [Fact]
    public void StreamFlowController_RecordDataSent_ThrowsOnViolation()
    {
        var controller = new StreamFlowController(123, 1000);
        
        var ex = Assert.Throws<QuicException>(() => controller.RecordDataSent(500, 600));
        Assert.Equal(QuicErrorCode.FlowControlError, ex.ErrorCode);
        Assert.Contains("Stream 123 flow control violation", ex.Message);
    }
    
    [Fact]
    public void StreamFlowController_UpdateMaxStreamData_OnlyIncreases()
    {
        var controller = new StreamFlowController(123, 1000);
        
        // Should update to higher value
        controller.UpdateMaxStreamData(2000);
        Assert.Equal(2000u, controller.MaxStreamData);
        
        // Should ignore lower value
        controller.UpdateMaxStreamData(1500);
        Assert.Equal(2000u, controller.MaxStreamData);
    }
    
    [Fact]
    public void StreamFlowController_ValidateIncomingData_WithinLimit()
    {
        var controller = new StreamFlowController(123, 1000);
        
        // Should not throw for data within limit
        controller.ValidateIncomingData(0, 500);
        controller.ValidateIncomingData(500, 500);
        
        // Out-of-order data should also be validated
        controller.ValidateIncomingData(200, 300);
    }
    
    [Fact]
    public void StreamFlowController_ValidateIncomingData_ThrowsOnViolation()
    {
        var controller = new StreamFlowController(123, 1000);
        
        var ex = Assert.Throws<QuicException>(() => controller.ValidateIncomingData(500, 600));
        Assert.Equal(QuicErrorCode.FlowControlError, ex.ErrorCode);
        Assert.Contains("Stream 123 flow control violation", ex.Message);
        Assert.Contains("Received data beyond advertised limit", ex.Message);
    }
    
    [Fact]
    public void StreamFlowController_IsBlocked_WhenAtLimit()
    {
        var controller = new StreamFlowController(123, 1000);
        
        controller.RecordDataSent(0, 1000);
        Assert.True(controller.IsBlocked());
        Assert.Equal(0u, controller.AvailableWindow);
    }
    
    [Fact]
    public void StreamFlowController_Reset_ClearsCounters()
    {
        var controller = new StreamFlowController(123, 1000);
        
        controller.RecordDataSent(0, 500);
        controller.RecordDataConsumed(300);
        controller.ValidateIncomingData(0, 400);
        
        controller.Reset();
        
        Assert.Equal(0u, controller.DataSent);
        Assert.Equal(0u, controller.DataConsumed);
        Assert.Equal(1000u, controller.MaxStreamData); // MaxStreamData should persist
        Assert.Equal(1000u, controller.AvailableWindow);
    }
}