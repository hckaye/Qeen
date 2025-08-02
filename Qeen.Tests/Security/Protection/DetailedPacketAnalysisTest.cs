using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Qeen.Tests.Security.Protection;

/// <summary>
/// Detailed analysis of RFC 9001 A.5 packet structure
/// </summary>
public class DetailedPacketAnalysisTest
{
    private readonly ITestOutputHelper _output;

    public DetailedPacketAnalysisTest(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void AnalyzeRfc9001_A5_PacketStructure()
    {
        // Unprotected packet from RFC 9001 A.2
        var unprotectedHex = 
            "c000000001088394c8f03e5157080000" + // Header
            "449e7b9aec34";                       // Length + PN
            
        // Protected packet from RFC 9001 A.5
        var protectedHex = 
            "c000000001088394c8f03e5157080000" + // Header (unchanged)
            "449e00000002";                       // Length + PN (protected)
            
        var unprotected = Convert.FromHexString(unprotectedHex);
        var protected_ = Convert.FromHexString(protectedHex);
        
        _output.WriteLine("=== RFC 9001 A.5 Packet Structure Analysis ===\n");
        
        // Analyze unprotected packet
        _output.WriteLine("--- Unprotected Packet ---");
        AnalyzePacket(unprotected, "Unprotected");
        
        _output.WriteLine("\n--- Protected Packet ---");
        AnalyzePacket(protected_, "Protected");
        
        _output.WriteLine("\n--- Protection Analysis ---");
        
        // First byte analysis
        _output.WriteLine($"First byte: 0x{unprotected[0]:X2} -> 0x{protected_[0]:X2}");
        if (unprotected[0] == protected_[0])
        {
            _output.WriteLine("  First byte UNCHANGED (this is unexpected based on our implementation)");
        }
        
        // Packet number analysis
        var unprotectedPn = unprotected.AsSpan(18, 4);
        var protectedPn = protected_.AsSpan(18, 4);
        
        _output.WriteLine($"\nPacket number bytes:");
        _output.WriteLine($"  Unprotected: {Convert.ToHexString(unprotectedPn)}");
        _output.WriteLine($"  Protected:   {Convert.ToHexString(protectedPn)}");
        
        // Calculate XOR to find the mask that was applied
        _output.WriteLine($"\nDerived mask (XOR of unprotected and protected):");
        for (int i = 0; i < 4; i++)
        {
            var maskByte = (byte)(unprotectedPn[i] ^ protectedPn[i]);
            _output.WriteLine($"  mask[{i + 1}] = 0x{maskByte:X2}");
        }
        
        // The mask should be: 7b9aec36 (from our AES-ECB calculation)
        // Let's verify
        var expectedMask = new byte[] { 0x7b, 0x9a, 0xec, 0x36 };
        _output.WriteLine($"\nExpected mask from AES-ECB: {Convert.ToHexString(expectedMask)}");
    }
    
    private void AnalyzePacket(byte[] packet, string label)
    {
        var offset = 0;
        
        // First byte
        var firstByte = packet[offset];
        var pnLengthBits = firstByte & 0x03;
        _output.WriteLine($"{label} first byte: 0x{firstByte:X2}");
        _output.WriteLine($"  PN length bits: {pnLengthBits:b2} (=> PN length = {pnLengthBits + 1})");
        offset++;
        
        // Skip to packet number field
        offset = 18; // We know it's at offset 18 from previous analysis
        
        // Packet number (showing all 4 bytes for analysis)
        var pnBytes = packet.AsSpan(offset, 4);
        _output.WriteLine($"{label} packet number: {Convert.ToHexString(pnBytes)}");
        
        // Interpret as 32-bit number
        var pnArray = pnBytes.ToArray();
        var pn = BitConverter.ToUInt32(pnArray, 0);
        if (!BitConverter.IsLittleEndian)
        {
            pn = (uint)System.Net.IPAddress.NetworkToHostOrder((int)pn);
        }
        _output.WriteLine($"  As uint32: {pn}");
    }
    
    [Fact]
    public void VerifyPacketNumberLengthEncoding()
    {
        // The issue might be with packet number length encoding
        // In RFC 9001 A.2, the unprotected packet has:
        // - First byte: 0xC0 (PN length bits = 00)
        // - But the packet number is 4 bytes: 7b9aec34
        
        // This seems inconsistent. Let's check if the first byte in the test vector
        // actually has different PN length bits
        
        var firstByteFromA2 = 0xC0;
        var pnLengthBits = firstByteFromA2 & 0x03;
        _output.WriteLine($"First byte from A.2: 0x{firstByteFromA2:X2}");
        _output.WriteLine($"PN length bits: {pnLengthBits} (implies {pnLengthBits + 1} byte PN)");
        _output.WriteLine("But the actual PN in the test vector is 4 bytes!");
        
        // Let's check what the first byte should be for a 4-byte PN
        var correctFirstByte = (byte)(0xC0 | 0x03); // Set PN length bits to 11
        _output.WriteLine($"\nFirst byte for 4-byte PN should be: 0x{correctFirstByte:X2}");
        
        // Now let's see what happens with protection
        var mask0 = 0x43; // First byte of our AES mask
        var protectedWithMask = (byte)(correctFirstByte ^ (mask0 & 0x0f));
        _output.WriteLine($"After protection with mask[0] & 0x0f = 0x{mask0 & 0x0f:X2}:");
        _output.WriteLine($"  0x{correctFirstByte:X2} ^ 0x{mask0 & 0x0f:X2} = 0x{protectedWithMask:X2}");
        
        // Hmm, this gives us 0xC0, which matches the expected result!
        // So the issue is that the unprotected packet should have 0xC3 as first byte, not 0xC0
    }
}