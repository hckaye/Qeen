using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls.Messages;

public class CipherSuiteTest
{
    [Fact]
    public void ClientHello_Has_CipherSuites()
    {
        var hello = new ClientHello();
        
        Assert.NotEmpty(hello.CipherSuites);
        Assert.Equal(3, hello.CipherSuites.Count);
        Assert.Contains(CipherSuite.TLS_AES_128_GCM_SHA256, hello.CipherSuites);
        Assert.Contains(CipherSuite.TLS_AES_256_GCM_SHA384, hello.CipherSuites);
        Assert.Contains(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, hello.CipherSuites);
    }
}