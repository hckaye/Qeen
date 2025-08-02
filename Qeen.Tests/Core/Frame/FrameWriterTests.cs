using Qeen.Core.Frame;
using Xunit;

namespace Qeen.Tests.Core.Frame;

public class FrameWriterTests
{
    [Fact]
    public void FrameWriter_WriteByte_UpdatesBytesWritten()
    {
        var buffer = new byte[10];
        var writer = new FrameWriter(buffer);
        
        Assert.Equal(0, writer.BytesWritten);
        
        writer.WriteByte(0x42);
        
        Assert.Equal(1, writer.BytesWritten);
        Assert.Equal(0x42, buffer[0]);
    }
    
    [Fact]
    public void FrameWriter_WriteVariableLength_SingleByte()
    {
        var buffer = new byte[10];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(42);
        
        Assert.Equal(1, writer.BytesWritten);
        Assert.Equal(42, buffer[0]);
    }
    
    [Fact]
    public void FrameWriter_WriteVariableLength_TwoBytes()
    {
        var buffer = new byte[10];
        var writer = new FrameWriter(buffer);
        
        writer.WriteVariableLength(16000); // Requires 2 bytes
        
        Assert.Equal(2, writer.BytesWritten);
        Assert.Equal(0x7E, buffer[0]); // 0x40 | (16000 >> 8)
        Assert.Equal(0x80, buffer[1]); // 16000 & 0xFF
    }
}