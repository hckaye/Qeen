using System.Text;
using Qeen.Core.Packet;
using Qeen.Security.Protection;
using Xunit;
using Xunit.Abstractions;

namespace Qeen.Tests.Security.Protection;

public class DebugHeaderProtectionTest
{
    private readonly ITestOutputHelper _output;
    
    public DebugHeaderProtectionTest(ITestOutputHelper output)
    {
        _output = output;
    }
    
    [Fact]
    public void AnalyzeRfc9001ClientInitialPacket()
    {
        // RFC 9001 A.2: Unprotected Client Initial packet
        var unprotectedHex = 
            "c000000001088394c8f03e5157080000" + // Header up to length field
            "449e" + // Payload length (0x449e = 17566 bytes)
            "7b9aec34"; // Packet number (4 bytes)
            
        var unprotected = Convert.FromHexString(unprotectedHex);
        
        _output.WriteLine("=== RFC 9001 A.2 Client Initial Packet Analysis ===");
        _output.WriteLine($"First byte: 0x{unprotected[0]:X2} = {Convert.ToString(unprotected[0], 2).PadLeft(8, '0')}");
        _output.WriteLine($"  Long header: {(unprotected[0] & 0x80) != 0}");
        _output.WriteLine($"  Packet type: {(unprotected[0] & 0x30) >> 4} (0 = Initial)");
        _output.WriteLine($"  Reserved bits: {(unprotected[0] & 0x0C) >> 2}");
        _output.WriteLine($"  Packet number length: {(unprotected[0] & 0x03)} + 1 = {(unprotected[0] & 0x03) + 1}");
        
        _output.WriteLine("\nPacket structure:");
        _output.WriteLine($"  Flags: 0x{unprotected[0]:X2} (offset 0)");
        _output.WriteLine($"  Version: {BitConverter.ToUInt32(unprotected.AsSpan(1, 4).ToArray().Reverse().ToArray())} (offset 1-4)");
        _output.WriteLine($"  DCID len: {unprotected[5]} (offset 5)");
        _output.WriteLine($"  DCID: {Convert.ToHexString(unprotected.AsSpan(6, 8))} (offset 6-13)");
        _output.WriteLine($"  SCID len: {unprotected[14]} (offset 14)");
        _output.WriteLine($"  Token len: {unprotected[15]} (offset 15)");
        _output.WriteLine($"  Payload len: 0x{unprotected[16]:X2}{unprotected[17]:X2} (offset 16-17)");
        _output.WriteLine($"  Packet number: {Convert.ToHexString(unprotected.AsSpan(18, 4))} (offset 18-21)");
        
        // Parse using our implementation
        var success = QuicPacketHeader.TryGetPacketNumberOffset(unprotected, out var pnOffset, out var pnLength);
        _output.WriteLine($"\nOur parser results:");
        _output.WriteLine($"  Success: {success}");
        _output.WriteLine($"  PN offset: {pnOffset} (expected: 18)");
        _output.WriteLine($"  PN length: {pnLength} (expected: 4)");
    }
    
    [Fact]
    public void TestHeaderProtectionSamplePosition()
    {
        // Create a minimal Initial packet
        var packet = new List<byte>();
        
        // Header
        packet.Add(0xC3); // Long header, Initial, PN length = 4
        packet.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x01 }); // Version
        packet.Add(0x08); // DCID length
        packet.AddRange(new byte[8]); // DCID
        packet.Add(0x00); // SCID length
        packet.Add(0x00); // Token length (var int)
        packet.Add(0x40); // Payload length (var int) = 64 bytes
        packet.AddRange(new byte[4]); // Packet number (4 bytes)
        
        // Add payload
        packet.AddRange(new byte[64]);
        
        var packetArray = packet.ToArray();
        
        _output.WriteLine("=== Sample Position Test ===");
        
        // Get packet number offset
        var success = QuicPacketHeader.TryGetPacketNumberOffset(packetArray, out var pnOffset, out var pnLength);
        _output.WriteLine($"PN offset: {pnOffset}");
        _output.WriteLine($"PN length: {pnLength}");
        
        // Sample should be at pnOffset + 4
        var sampleOffset = pnOffset + 4;
        _output.WriteLine($"Sample offset: {sampleOffset}");
        _output.WriteLine($"Sample available: {packetArray.Length >= sampleOffset + 16}");
        
        if (packetArray.Length >= sampleOffset + 16)
        {
            var sample = packetArray.AsSpan(sampleOffset, 16);
            _output.WriteLine($"Sample: {Convert.ToHexString(sample)}");
        }
    }
    
    [Fact]
    public void TestMaskGeneration()
    {
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        var sample = Convert.FromHexString("d1b1c98dd7689fb8ec11d242b123dc9b");
        
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // We need to expose the mask generation for testing
        // For now, we'll create a packet that will use this sample
        var packet = new byte[100];
        packet[0] = 0xC0; // Initial packet
        
        // The sample in RFC 9001 A.5 is at offset 30 (header is 26 bytes + 4 for PN offset)
        // So we need packet number at offset 26
        
        _output.WriteLine("=== Mask Generation Test ===");
        _output.WriteLine($"HP Key: {Convert.ToHexString(hpKey)}");
        _output.WriteLine($"Sample: {Convert.ToHexString(sample)}");
        
        // The mask should be: AES-ECB(hp_key, sample)
        // Expected mask[0] = 0x03 (from RFC analysis)
        // This would XOR with 0xC0 to keep it 0xC0 (since 0xC0 ^ 0x03 = 0xC3, but only lower 4 bits are used)
    }
}