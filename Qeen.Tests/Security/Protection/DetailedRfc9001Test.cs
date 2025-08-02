using Qeen.Core.Packet;
using Qeen.Security.Protection;
using Xunit;

namespace Qeen.Tests.Security.Protection;

/// <summary>
/// Detailed test following RFC 9001 Appendix A exactly
/// </summary>
public class DetailedRfc9001Test
{
    [Fact]
    public void HeaderProtection_ExactRfc9001ClientInitial()
    {
        // From RFC 9001 A.2: Client Initial
        // The unprotected packet has the first byte 0xc0 (11000000)
        // This indicates:
        // - Long header (1)
        // - Fixed bit (1) 
        // - Packet type Initial (00)
        // - Reserved bits (00)
        // - Packet number length encoded (00) = 1 byte
        
        // But the actual packet number in the test vector is 4 bytes: 7b9aec34
        // This means the packet was constructed with a 4-byte packet number,
        // but the length bits were not set correctly in the test vector.
        
        // Let's create the correct unprotected packet
        var unprotectedPacket = new List<byte>();
        
        // First byte should be 0xc3 for 4-byte packet number
        // 11000011 = 0xC3 (long header, initial type, 4-byte PN)
        unprotectedPacket.Add(0xC3);
        
        // Version (4 bytes)
        unprotectedPacket.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x01 });
        
        // DCID length and DCID
        unprotectedPacket.Add(0x08);
        unprotectedPacket.AddRange(Convert.FromHexString("8394c8f03e515708"));
        
        // SCID length (0)
        unprotectedPacket.Add(0x00);
        
        // Token length (0) - variable length integer
        unprotectedPacket.Add(0x00);
        
        // Payload length (0x449e) - variable length integer (2 bytes)
        unprotectedPacket.Add(0x44);
        unprotectedPacket.Add(0x9e);
        
        // Packet number (4 bytes)
        unprotectedPacket.AddRange(Convert.FromHexString("7b9aec34"));
        
        // Add the encrypted payload (from RFC 9001)
        var encryptedPayload = Convert.FromHexString(
            "d1b1c98dd7689fb8ec11d242b123dc9b" +
            "d8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d" +
            "17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4" +
            "905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b393" +
            "43fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05d" +
            "fffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06" +
            "cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a" +
            "6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc25" +
            "0ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2" +
            "f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d2" +
            "9f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258" +
            "bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565" +
            "636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7483098b6f6ef1" +
            "c65a09e9039fbd8adc412c090ec0f110efa4ce77c8006eb3925ef5e3b4a5bf83" +
            "c42abe5ba91208c7010889c0fec50ee7bc4ec51ef805f24504a6170228b1f0cb" +
            "870b6634cb0d2b8ed59004c0c61746ec7c3cb97327c0378739f8"
        );
        unprotectedPacket.AddRange(encryptedPayload);
        
        var packet = unprotectedPacket.ToArray();
        
        // Header protection key from RFC 9001 A.3
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // Apply protection
        protection.Apply(packet, 0);
        
        // Check the result
        // The first byte should become 0xc0 (from 0xc3)
        // This is because the mask will clear the lower 2 bits
        Assert.Equal(0xC0, packet[0]);
        
        // The packet number should be XORed with the mask
        // Original: 7b9aec34
        // Expected: 00000002 (from RFC 9001 A.5)
        var protectedPn = packet.AsSpan(18, 4);
        var expectedPn = Convert.FromHexString("00000002");
        Assert.Equal(expectedPn, protectedPn.ToArray());
    }
    
    [Fact] 
    public void VerifyMaskCalculation()
    {
        // Let's manually calculate the mask for the RFC 9001 example
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        var sample = Convert.FromHexString("d1b1c98dd7689fb8ec11d242b123dc9b");
        
        // Create AES ECB cipher
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Mode = System.Security.Cryptography.CipherMode.ECB;
        aes.Padding = System.Security.Cryptography.PaddingMode.None;
        aes.Key = hpKey;
        
        var mask = new byte[16];
        using var encryptor = aes.CreateEncryptor();
        encryptor.TransformBlock(sample, 0, 16, mask, 0);
        
        // From reverse engineering the RFC example:
        // mask[0] & 0x0f = 0x03 (to transform 0xc3 -> 0xc0)
        // mask[1..4] = values that transform 7b9aec34 -> 00000002
        
        // Calculate what the mask should be
        var expectedMask1 = (byte)(0x7b ^ 0x00);
        var expectedMask2 = (byte)(0x9a ^ 0x00);
        var expectedMask3 = (byte)(0xec ^ 0x00);
        var expectedMask4 = (byte)(0x34 ^ 0x02);
        
        Assert.Equal(0x03, mask[0] & 0x0f);
        Assert.Equal(expectedMask1, mask[1]);
        Assert.Equal(expectedMask2, mask[2]);
        Assert.Equal(expectedMask3, mask[3]);
        Assert.Equal(expectedMask4, mask[4]);
    }
}