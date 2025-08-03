using System;
using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls;

public class InlineWriterTest
{
    [Fact]
    public void Test_WriteLengthPrefixed16_Inline()
    {
        var buffer = new byte[100];
        var writer = new TlsWriter(buffer);
        
        // Test the exact same code that's in ClientHello.Encode
        var cipherSuites = new List<CipherSuite>
        {
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256
        };
        
        var startPos = writer.Position;
        
        // Manually write length and content
        writer.WriteUInt16(6); // 3 suites * 2 bytes each
        foreach (var suite in cipherSuites)
        {
            writer.WriteUInt16((ushort)suite);
        }
        
        Assert.Equal(8, writer.Position - startPos); // 2 bytes length + 6 bytes data
        
        // Now test with WriteLengthPrefixed16
        var buffer2 = new byte[100];
        var writer2 = new TlsWriter(buffer2);
        
        var startPos2 = writer2.Position;
        int bytesWrittenInside = 0;
        
        writer2.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            foreach (var suite in cipherSuites)
            {
                w.WriteUInt16((ushort)suite);
            }
            bytesWrittenInside = w.BytesWritten;
        });
        
        Assert.Equal(6, bytesWrittenInside);
        Assert.Equal(8, writer2.Position - startPos2);
        
        // Check the actual bytes
        Assert.Equal(0, buffer2[0]);
        Assert.Equal(6, buffer2[1]);
    }
}