using Qeen.Core.Frame;
using Qeen.Core.Frame.Frames;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class FrameEncodingTests
{
    [Fact]
    public void PingFrame_DirectEncode_Works()
    {
        var buffer = new byte[10];
        var writer = new FrameWriter(buffer);
        
        PingFrame.Instance.Encode(ref writer);
        
        Assert.Equal(1, writer.BytesWritten);
        Assert.Equal(0x01, buffer[0]);
    }
    
    [Fact]
    public void FrameWriter_PassedAsParameter_MaintainsState()
    {
        var buffer = new byte[10];
        var writer = new FrameWriter(buffer);
        
        WriteByteToWriter(ref writer);
        
        // This should fail if ref struct doesn't maintain state
        Assert.Equal(1, writer.BytesWritten);
    }
    
    private void WriteByteToWriter(ref FrameWriter writer)
    {
        writer.WriteByte(0x42);
    }
}