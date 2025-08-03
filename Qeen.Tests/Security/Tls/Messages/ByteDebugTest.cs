using System;
using System.Linq;
using Qeen.Security.Tls;
using Qeen.Security.Tls.Messages;
using Xunit;

namespace Qeen.Tests.Security.Tls.Messages;

public class ByteDebugTest
{
    [Fact]
    public void Debug_Bytes()
    {
        var original = new ClientHello();
        
        var buffer = new byte[4096];
        var writer = new TlsWriter(buffer);
        
        // Write version
        writer.WriteUInt16(original.LegacyVersion);
        Console.WriteLine($"After version, position: {writer.Position}");
        
        // Write random
        writer.WriteBytes(original.Random);
        Console.WriteLine($"After random, position: {writer.Position}");
        
        // Write session ID
        writer.WriteVector8(original.LegacySessionId);
        Console.WriteLine($"After sessionId, position: {writer.Position}");
        
        // Write cipher suites with length prefix
        var suiteCountBefore = original.CipherSuites.Count;
        Console.WriteLine($"CipherSuites count before encoding: {suiteCountBefore}");
        
        var startPos = writer.Position;
        writer.WriteLengthPrefixed16((ref TlsWriter w) =>
        {
            Console.WriteLine($"Inside WriteLengthPrefixed16, writing {original.CipherSuites.Count} suites");
            foreach (var suite in original.CipherSuites)
            {
                w.WriteUInt16((ushort)suite);
                Console.WriteLine($"  Wrote suite: {(ushort)suite:X4}");
            }
        });
        Console.WriteLine($"After cipher suites, position: {writer.Position}, wrote {writer.Position - startPos} bytes");
        
        // Check what was actually written
        var cipherSuitesBytes = buffer.Skip(startPos).Take(writer.Position - startPos).ToArray();
        Console.WriteLine($"CipherSuites bytes: {BitConverter.ToString(cipherSuitesBytes)}");
        
        // Now try to read it back
        var reader = new TlsReader(writer.Written);
        var version = reader.ReadUInt16();
        var random = reader.ReadBytes(32);
        var sessionId = reader.ReadVector8();
        var cipherSuitesLength = reader.ReadUInt16();
        Console.WriteLine($"Read cipherSuitesLength: {cipherSuitesLength} bytes = {cipherSuitesLength/2} suites");
        
        var suiteCount = 0;
        var endPos = reader.Position + cipherSuitesLength;
        while (reader.Position < endPos)
        {
            var suite = reader.ReadUInt16();
            Console.WriteLine($"  Read suite {suiteCount}: {suite:X4}");
            suiteCount++;
        }
        
        Assert.Equal(suiteCountBefore, suiteCount);
    }
}