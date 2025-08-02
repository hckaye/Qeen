using System.Security.Cryptography;
using Qeen.Core.Packet;
using Qeen.Security.Protection;
using Xunit;
using Xunit.Abstractions;

namespace Qeen.Tests.Security.Protection;

/// <summary>
/// Step-by-step debugging of header protection
/// </summary>
public class HeaderProtectionDebugStepByStep
{
    private readonly ITestOutputHelper _output;

    public HeaderProtectionDebugStepByStep(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Debug_HeaderProtection_WithCorrectedFirstByte()
    {
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        
        // Create the unprotected packet with corrected first byte
        var packet = new byte[512];
        var offset = 0;
        
        // Build packet byte by byte
        packet[offset++] = 0xC3; // Long header, Initial type, PN length = 4
        packet[offset++] = 0x00; // Version
        packet[offset++] = 0x00;
        packet[offset++] = 0x00;
        packet[offset++] = 0x01;
        packet[offset++] = 0x08; // DCID length
        packet[offset++] = 0x83; // DCID
        packet[offset++] = 0x94;
        packet[offset++] = 0xC8;
        packet[offset++] = 0xF0;
        packet[offset++] = 0x3E;
        packet[offset++] = 0x51;
        packet[offset++] = 0x57;
        packet[offset++] = 0x08;
        packet[offset++] = 0x00; // SCID length
        packet[offset++] = 0x00; // Token length
        packet[offset++] = 0x44; // Payload length (2 bytes)
        packet[offset++] = 0x9E;
        
        var pnOffset = offset;
        packet[offset++] = 0x7B; // Packet number (4 bytes)
        packet[offset++] = 0x9A;
        packet[offset++] = 0xEC;
        packet[offset++] = 0x34;
        
        // Add sample data starting at offset 22
        var sampleData = Convert.FromHexString("d1b1c98dd7689fb8ec11d242b123dc9b");
        Array.Copy(sampleData, 0, packet, offset, sampleData.Length);
        
        _output.WriteLine("=== Step-by-step Header Protection Debug ===\n");
        
        // Step 1: Parse packet
        var success = QuicPacketHeader.TryGetPacketNumberOffset(packet, out var detectedPnOffset, out var detectedPnLength);
        _output.WriteLine($"Step 1: Parse packet");
        _output.WriteLine($"  Success: {success}");
        _output.WriteLine($"  Detected PN offset: {detectedPnOffset} (expected: {pnOffset})");
        _output.WriteLine($"  Detected PN length: {detectedPnLength} (from first byte)");
        
        // Step 2: Get sample
        var sampleOffset = detectedPnOffset + 4;
        _output.WriteLine($"\nStep 2: Get sample");
        _output.WriteLine($"  Sample offset: {sampleOffset}");
        var sample = packet.AsSpan(sampleOffset, 16);
        _output.WriteLine($"  Sample: {Convert.ToHexString(sample)}");
        
        // Step 3: Generate mask
        _output.WriteLine($"\nStep 3: Generate mask");
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = hpKey;
            
            var mask = new byte[16];
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptor.TransformBlock(sample.ToArray(), 0, 16, mask, 0);
            }
            _output.WriteLine($"  Mask: {Convert.ToHexString(mask)}");
            
            // Step 4: Apply to first byte
            _output.WriteLine($"\nStep 4: Apply to first byte");
            _output.WriteLine($"  Original first byte: 0x{packet[0]:X2}");
            _output.WriteLine($"  Mask[0]: 0x{mask[0]:X2}");
            _output.WriteLine($"  Mask[0] & 0x0F: 0x{mask[0] & 0x0F:X2}");
            var protectedFirstByte = (byte)(packet[0] ^ (mask[0] & 0x0F));
            _output.WriteLine($"  Protected first byte: 0x{protectedFirstByte:X2}");
            
            // Step 5: Get actual PN length from protected first byte
            var actualPnLength = (protectedFirstByte & 0x03) + 1;
            _output.WriteLine($"\nStep 5: Get actual PN length");
            _output.WriteLine($"  PN length from protected first byte: {actualPnLength}");
            
            // Step 6: Apply to packet number
            _output.WriteLine($"\nStep 6: Apply to packet number");
            _output.WriteLine($"  Original PN: {Convert.ToHexString(packet.AsSpan(detectedPnOffset, 4))}");
            for (int i = 0; i < actualPnLength; i++)
            {
                _output.WriteLine($"  PN[{i}]: 0x{packet[detectedPnOffset + i]:X2} ^ mask[{i + 1}]: 0x{mask[i + 1]:X2} = 0x{packet[detectedPnOffset + i] ^ mask[i + 1]:X2}");
            }
        }
        
        // Now apply with actual implementation
        _output.WriteLine($"\n=== Apply with implementation ===");
        var protection = new AesEcbHeaderProtection(hpKey);
        var packetCopy = packet.ToArray();
        protection.Apply(packetCopy, 0);
        
        _output.WriteLine($"Protected first byte: 0x{packetCopy[0]:X2}");
        _output.WriteLine($"Protected PN: {Convert.ToHexString(packetCopy.AsSpan(pnOffset, 4))}");
        
        // Expected values
        _output.WriteLine($"\n=== Expected values ===");
        _output.WriteLine($"Expected first byte: 0xC0");
        _output.WriteLine($"Expected PN: 00000002");
    }
}