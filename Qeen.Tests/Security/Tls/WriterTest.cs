using System;
using Qeen.Security.Tls;
using Xunit;

namespace Qeen.Tests.Security.Tls;

public class WriterTest
{
    [Fact]
    public void WriteLengthPrefixed16_Works()
    {
        var buffer = new byte[100];
        var writer = new TlsWriter(buffer);
        
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            w.WriteUInt16(0x1301); // TLS_AES_128_GCM_SHA256
            w.WriteUInt16(0x1302); // TLS_AES_256_GCM_SHA384
            w.WriteUInt16(0x1303); // TLS_CHACHA20_POLY1305_SHA256
        });
        
        var written = writer.Written.ToArray();
        
        // First two bytes should be the length (6 bytes = 3 * 2)
        Assert.Equal(0x00, written[0]);
        Assert.Equal(0x06, written[1]);
        
        // Next 6 bytes should be the cipher suites
        Assert.Equal(0x13, written[2]);
        Assert.Equal(0x01, written[3]);
        Assert.Equal(0x13, written[4]);
        Assert.Equal(0x02, written[5]);
        Assert.Equal(0x13, written[6]);
        Assert.Equal(0x03, written[7]);
        
        Assert.Equal(8, writer.BytesWritten);
    }
    
    [Fact]
    public void TlsWriter_Nested_Writers()
    {
        var buffer = new byte[100];
        var writer = new TlsWriter(buffer);
        
        writer.WriteUInt16(0x0303); // version
        
        var posBefore = writer.Position;
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            // This creates a new writer with a different buffer slice
            w.WriteUInt16(0x1301);
        });
        var posAfter = writer.Position;
        
        Assert.Equal(4, posAfter - posBefore); // 2 bytes length + 2 bytes data
        
        var written = writer.Written.ToArray();
        Assert.Equal(0x03, written[0]);
        Assert.Equal(0x03, written[1]);
        Assert.Equal(0x00, written[2]); // length high byte
        Assert.Equal(0x02, written[3]); // length low byte
        Assert.Equal(0x13, written[4]);
        Assert.Equal(0x01, written[5]);
    }
}