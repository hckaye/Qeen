using System;
using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls.Messages;

public class SimpleDebugTest
{
    [Fact]
    public void Simple_ClientHello_Debug()
    {
        // Arrange
        var original = new ClientHello();
        Console.WriteLine($"Original CipherSuites count: {original.CipherSuites.Count}");
        
        // Add some extensions for testing
        original.AddSupportedVersionsExtension();
        Console.WriteLine($"Original Extensions count: {original.Extensions.Count}");

        // Act - Encode
        var buffer = new byte[4096];
        var writer = new TlsWriter(buffer);
        original.Encode(ref writer);
        var encoded = writer.Written.ToArray();
        Console.WriteLine($"Encoded length: {encoded.Length}");

        // Act - Decode
        var reader = new TlsReader(encoded);
        var decoded = ClientHello.Decode(ref reader, TlsMessageType.ClientHello) as ClientHello;

        Console.WriteLine($"Decoded CipherSuites count: {decoded?.CipherSuites.Count}");
        Console.WriteLine($"Decoded Extensions count: {decoded?.Extensions.Count}");
        
        // Let's manually check what we're reading
        var testReader = new TlsReader(encoded);
        var version = testReader.ReadUInt16();
        Console.WriteLine($"Version: {version:X4}");
        var random = testReader.ReadBytes(32);
        Console.WriteLine($"Random length: {random.Length}");
        var sessionId = testReader.ReadVector8();
        Console.WriteLine($"SessionId length: {sessionId.Length}");
        var cipherSuitesLength = testReader.ReadUInt16();
        Console.WriteLine($"CipherSuites length in bytes: {cipherSuitesLength}");
        Console.WriteLine($"CipherSuites count: {cipherSuitesLength / 2}");
        
        Assert.NotNull(decoded);
        Assert.True(decoded.CipherSuites.Count > 0, "CipherSuites should not be empty");
    }
}