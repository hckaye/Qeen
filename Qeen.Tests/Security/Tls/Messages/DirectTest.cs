using System;
using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls.Messages;

public class DirectTest
{
    [Fact]
    public void Direct_Test()
    {
        var hello = new ClientHello();
        var suiteCount = hello.CipherSuites.Count;
        
        // Encode
        var buffer = new byte[1024];
        var writer = new TlsWriter(buffer);
        hello.Encode(ref writer);
        
        // Check the bytes at position 35 (after version + random + sessionId)
        // version = 2, random = 32, sessionId length = 1, sessionId = 0
        // So cipher suites length should be at position 35
        var pos = 35;
        var cipherSuitesLength = (buffer[pos] << 8) | buffer[pos + 1];
        
        Assert.True(cipherSuitesLength > 0, $"CipherSuites length in bytes should be > 0, but was {cipherSuitesLength}");
        Assert.Equal(suiteCount * 2, cipherSuitesLength);
    }
}