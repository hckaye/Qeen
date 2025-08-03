using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;
using Xunit.Abstractions;

namespace Qeen.Tests.Security.Tls.Messages;

public class ClientHelloDebugTest
{
    private readonly ITestOutputHelper _output;

    public ClientHelloDebugTest(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Debug_ClientHello_Encoding()
    {
        // Arrange
        var original = new ClientHello();
        _output.WriteLine($"Original CipherSuites count: {original.CipherSuites.Count}");
        foreach (var suite in original.CipherSuites)
        {
            _output.WriteLine($"  Suite: {(ushort)suite:X4}");
        }

        // Act - Encode
        var buffer = new byte[4096];
        var writer = new TlsWriter(buffer);
        original.Encode(ref writer);
        var encoded = writer.Written.ToArray();
        _output.WriteLine($"Encoded bytes length: {encoded.Length}");
        _output.WriteLine($"Encoded hex: {BitConverter.ToString(encoded).Replace("-", " ")}");

        // Act - Decode
        var reader = new TlsReader(encoded);
        var decoded = ClientHello.Decode(ref reader, TlsMessageType.ClientHello) as ClientHello;

        // Assert
        Assert.NotNull(decoded);
        _output.WriteLine($"Decoded CipherSuites count: {decoded.CipherSuites.Count}");
        foreach (var suite in decoded.CipherSuites)
        {
            _output.WriteLine($"  Suite: {(ushort)suite:X4}");
        }
    }
}