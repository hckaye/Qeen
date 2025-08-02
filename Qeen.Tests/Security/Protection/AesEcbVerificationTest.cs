using System.Security.Cryptography;
using Xunit;
using Xunit.Abstractions;

namespace Qeen.Tests.Security.Protection;

/// <summary>
/// Verify AES-ECB implementation against RFC 9001 test vectors
/// </summary>
public class AesEcbVerificationTest
{
    private readonly ITestOutputHelper _output;

    public AesEcbVerificationTest(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void VerifyAesEcb_Rfc9001_A5()
    {
        // From RFC 9001 A.5
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        var sample = Convert.FromHexString("d1b1c98dd7689fb8ec11d242b123dc9b");
        
        // Expected mask from RFC 9001 A.5
        var expectedMask = Convert.FromHexString("437b9aec36");
        
        _output.WriteLine($"HP Key: {Convert.ToHexString(hpKey)}");
        _output.WriteLine($"Sample: {Convert.ToHexString(sample)}");
        
        // Perform AES-ECB encryption
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = hpKey;
            
            var mask = new byte[16];
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptor.TransformBlock(sample, 0, 16, mask, 0);
            }
            
            _output.WriteLine($"Generated mask (full): {Convert.ToHexString(mask)}");
            _output.WriteLine($"Generated mask (first 5 bytes): {Convert.ToHexString(mask.AsSpan(0, 5))}");
            _output.WriteLine($"Expected mask (first 5 bytes): {Convert.ToHexString(expectedMask)}");
            
            // The first 5 bytes should match
            Assert.Equal(expectedMask, mask.AsSpan(0, 5).ToArray());
        }
    }
    
    [Fact]
    public void VerifyHeaderProtection_Rfc9001_A5_Manual()
    {
        // Let's manually apply header protection according to RFC 9001 A.5
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        
        // Original packet first byte and packet number
        byte firstByte = 0xC0;
        var packetNumber = Convert.FromHexString("7b9aec34");
        
        // Sample from the packet
        var sample = Convert.FromHexString("d1b1c98dd7689fb8ec11d242b123dc9b");
        
        // Generate mask
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            aes.Key = hpKey;
            
            var mask = new byte[16];
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptor.TransformBlock(sample, 0, 16, mask, 0);
            }
            
            _output.WriteLine($"Generated mask: {Convert.ToHexString(mask)}");
            
            // Apply protection to first byte (long header, so mask with 0x0f)
            var protectedFirstByte = (byte)(firstByte ^ (mask[0] & 0x0f));
            _output.WriteLine($"Original first byte: 0x{firstByte:X2}");
            _output.WriteLine($"Mask[0] & 0x0f: 0x{(mask[0] & 0x0f):X2}");
            _output.WriteLine($"Protected first byte: 0x{protectedFirstByte:X2}");
            
            // Get packet number length from protected first byte
            var pnLength = (protectedFirstByte & 0x03) + 1;
            _output.WriteLine($"Packet number length: {pnLength}");
            
            // Apply protection to packet number
            var protectedPn = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                protectedPn[i] = (byte)(packetNumber[i] ^ mask[1 + i]);
            }
            
            _output.WriteLine($"Original packet number: {Convert.ToHexString(packetNumber)}");
            _output.WriteLine($"Protected packet number: {Convert.ToHexString(protectedPn)}");
            
            // According to RFC 9001 A.5:
            // - Protected first byte should be 0xC0 (unchanged because mask[0] & 0x0f = 0x03, and 0xC0 ^ 0x03 = 0xC3)
            // - Protected packet number should be 00000002
            
            // But wait, the RFC says the protected first byte should remain 0xC0
            // This means the packet number length bits must be such that after XOR it gives us the same result
            
            // Let's check what the RFC expects
            _output.WriteLine("\n--- RFC 9001 A.5 Expected Values ---");
            _output.WriteLine("Expected protected first byte: 0xC0");
            _output.WriteLine("Expected protected packet number: 00000002");
            
            // Actually, looking at the RFC more carefully:
            // The unprotected packet has PN length bits = 11 (4 bytes)
            // After protection with mask[0] & 0x0f = 0x03, we get:
            // 0xC3 & 0x03 = 0x03, so PN length = 4
            
            // But the RFC shows the protected packet has only changed the packet number bytes
            // Let me re-read the RFC...
        }
    }
}