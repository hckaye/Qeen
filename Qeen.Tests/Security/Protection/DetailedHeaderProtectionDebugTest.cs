using System.Text;
using Qeen.Core.Packet;
using Qeen.Security.Protection;
using Xunit;
using Xunit.Abstractions;

namespace Qeen.Tests.Security.Protection;

/// <summary>
/// Detailed debugging test for header protection implementation
/// </summary>
public class DetailedHeaderProtectionDebugTest
{
    private readonly ITestOutputHelper _output;

    public DetailedHeaderProtectionDebugTest(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public void Debug_HeaderProtection_StepByStep()
    {
        // RFC 9001 A.5: Client Initial packet test vector
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        
        // Unprotected packet from RFC 9001 A.2
        // Note: First byte should be 0xC3 to indicate 4-byte packet number
        var unprotectedPacket = Convert.FromHexString(
            "c300000001088394c8f03e5157080000" + // Header up to packet number field (corrected)
            "449e7b9aec34" + // Length (2 bytes) + packet number (4 bytes)
            "d1b1c98dd7689fb8ec11d242b123dc9b" + // Start of encrypted payload
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

        // Expected mask from RFC 9001 A.5
        var expectedMask = Convert.FromHexString("020dbaecf9");
        
        // Expected protected first byte
        var expectedFirstByte = (byte)0xC0; // Should remain 0xC0 for Initial packet
        
        _output.WriteLine("=== RFC 9001 A.5 Header Protection Debug ===");
        _output.WriteLine($"HP Key: {Convert.ToHexString(hpKey)}");
        _output.WriteLine($"Original packet length: {unprotectedPacket.Length} bytes");
        
        // Step 1: Parse packet structure
        _output.WriteLine("\n--- Step 1: Parse packet structure ---");
        LogPacketStructure(unprotectedPacket);
        
        // Step 2: Find packet number offset
        var success = QuicPacketHeader.TryGetPacketNumberOffset(unprotectedPacket, out var pnOffset, out var pnLength);
        _output.WriteLine($"\n--- Step 2: Packet number offset ---");
        _output.WriteLine($"Success: {success}");
        _output.WriteLine($"Packet number offset: {pnOffset}");
        _output.WriteLine($"Packet number length (from flags): {pnLength}");
        
        // Step 3: Calculate sample offset
        var sampleOffset = pnOffset + 4;
        _output.WriteLine($"\n--- Step 3: Sample offset ---");
        _output.WriteLine($"Sample offset: {sampleOffset} (pnOffset + 4)");
        
        // Step 4: Extract sample
        var sample = unprotectedPacket.AsSpan(sampleOffset, 16);
        _output.WriteLine($"\n--- Step 4: Extract sample ---");
        _output.WriteLine($"Sample (16 bytes at offset {sampleOffset}): {Convert.ToHexString(sample)}");
        
        // Step 5: Generate mask using AES-ECB
        _output.WriteLine($"\n--- Step 5: Generate mask ---");
        using (var aes = System.Security.Cryptography.Aes.Create())
        {
            aes.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes.Padding = System.Security.Cryptography.PaddingMode.None;
            aes.Key = hpKey;
            
            var mask = new byte[16];
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptor.TransformBlock(sample.ToArray(), 0, 16, mask, 0);
            }
            
            _output.WriteLine($"Generated mask: {Convert.ToHexString(mask)}");
            _output.WriteLine($"First 5 bytes of mask: {Convert.ToHexString(mask.AsSpan(0, 5))}");
            _output.WriteLine($"Expected mask (from RFC): {Convert.ToHexString(expectedMask)}");
        }
        
        // Step 6: Apply protection
        _output.WriteLine($"\n--- Step 6: Apply protection ---");
        var packet = unprotectedPacket.ToArray();
        var protection = new AesEcbHeaderProtection(hpKey);
        
        _output.WriteLine($"Original first byte: 0x{packet[0]:X2}");
        _output.WriteLine($"Original packet number bytes: {Convert.ToHexString(packet.AsSpan(pnOffset, 4))}");
        
        protection.Apply(packet, 0);
        
        _output.WriteLine($"Protected first byte: 0x{packet[0]:X2}");
        _output.WriteLine($"Protected packet number bytes: {Convert.ToHexString(packet.AsSpan(pnOffset, 4))}");
        
        // Compare with expected
        _output.WriteLine($"\n--- Expected vs Actual ---");
        _output.WriteLine($"Expected first byte: 0xC0");
        _output.WriteLine($"Expected PN bytes: 00000002");
        _output.WriteLine($"Actual first byte: 0x{packet[0]:X2}");
        _output.WriteLine($"Actual PN bytes: {Convert.ToHexString(packet.AsSpan(pnOffset, 4))}");
        
        // The expected protected packet has "00000002" as packet number
        Assert.Equal(0xC0, packet[0]); // First byte should be 0xC0 after protection
        Assert.Equal(0x00, packet[pnOffset]);
        Assert.Equal(0x00, packet[pnOffset + 1]);
        Assert.Equal(0x00, packet[pnOffset + 2]);
        Assert.Equal(0x02, packet[pnOffset + 3]);
    }
    
    private void LogPacketStructure(byte[] packet)
    {
        var offset = 0;
        
        // First byte
        var firstByte = packet[offset];
        var isLongHeader = (firstByte & 0x80) != 0;
        var packetType = (firstByte & 0x30) >> 4;
        var reservedBits = (firstByte & 0x0C) >> 2;
        var pnLengthBits = firstByte & 0x03;
        
        _output.WriteLine($"First byte: 0x{firstByte:X2}");
        _output.WriteLine($"  Long header: {isLongHeader}");
        _output.WriteLine($"  Packet type: {packetType} (0=Initial, 1=0-RTT, 2=Handshake, 3=Retry)");
        _output.WriteLine($"  Reserved bits: {reservedBits:X1}");
        _output.WriteLine($"  PN length bits: {pnLengthBits:b2} (=> PN length = {pnLengthBits + 1})");
        offset++;
        
        // Version
        var version = BitConverter.ToUInt32(packet.AsSpan(offset, 4));
        _output.WriteLine($"Version: 0x{version:X8} (offset {offset})");
        offset += 4;
        
        // DCID
        var dcidLen = packet[offset];
        _output.WriteLine($"DCID length: {dcidLen} (offset {offset})");
        offset++;
        var dcid = packet.AsSpan(offset, dcidLen);
        _output.WriteLine($"DCID: {Convert.ToHexString(dcid)} (offset {offset})");
        offset += dcidLen;
        
        // SCID
        var scidLen = packet[offset];
        _output.WriteLine($"SCID length: {scidLen} (offset {offset})");
        offset++;
        if (scidLen > 0)
        {
            var scid = packet.AsSpan(offset, scidLen);
            _output.WriteLine($"SCID: {Convert.ToHexString(scid)} (offset {offset})");
            offset += scidLen;
        }
        
        // Token (for Initial packets)
        if (packetType == 0)
        {
            var tokenLen = packet[offset]; // Assuming no variable length encoding for simplicity
            _output.WriteLine($"Token length: {tokenLen} (offset {offset})");
            offset++;
            if (tokenLen > 0)
            {
                _output.WriteLine($"Token: {Convert.ToHexString(packet.AsSpan(offset, tokenLen))} (offset {offset})");
                offset += tokenLen;
            }
        }
        
        // Length
        _output.WriteLine($"Length field starts at offset {offset}");
        var lengthBytes = packet.AsSpan(offset, 2);
        _output.WriteLine($"Length bytes: {Convert.ToHexString(lengthBytes)}");
        offset += 2;
        
        // Packet number
        _output.WriteLine($"Packet number starts at offset {offset}");
        var pnBytes = packet.AsSpan(offset, 4);
        _output.WriteLine($"Packet number bytes: {Convert.ToHexString(pnBytes)}");
    }
}