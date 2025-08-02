using Qeen.Security.Protection;
using Xunit;

namespace Qeen.Tests.Security.Protection;

public class CleanRfc9001Test
{
    [Fact]
    public void HeaderProtection_Rfc9001ClientInitial_ExactImplementation()
    {
        // RFC 9001 A.3: client header protection key
        var hpKey = Convert.FromHexString("9f50449e04a0e810283a1e9933adedd2");
        
        // Build unprotected packet with correct first byte (0xC3 for 4-byte PN)
        var unprotectedPacket = Convert.FromHexString(
            "c300000001088394c8f03e5157080000449e7b9aec34" +
            "d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d" +
            "27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d226" +
            "2cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace" +
            "01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a0" +
            "2252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f" +
            "9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11" +
            "a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3f" +
            "af6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60b" +
            "c8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5" +
            "998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a932" +
            "3851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc526" +
            "6ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b" +
            "3dcbc2c7468d54119c7483098b6f6ef1c65a09e9039fbd8adc412c090ec0f110" +
            "efa4ce77c8006eb3925ef5e3b4a5bf83c42abe5ba91208c7010889c0fec50ee7" +
            "bc4ec51ef805f24504a6170228b1f0cb870b6634cb0d2b8ed59004c0c61746ec" +
            "7c3cb97327c0378739f8"
        );
        
        // Expected protected packet from RFC 9001 A.5
        var expectedProtectedPacket = Convert.FromHexString(
            "c000000001088394c8f03e5157080000449e00000002" +
            "d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d" +
            "27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d226" +
            "2cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace" +
            "01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a0" +
            "2252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f" +
            "9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11" +
            "a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3f" +
            "af6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60b" +
            "c8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5" +
            "998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a932" +
            "3851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc526" +
            "6ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b" +
            "3dcbc2c7468d54119c7483098b6f6ef1c65a09e9039fbd8adc412c090ec0f110" +
            "efa4ce77c8006eb3925ef5e3b4a5bf83c42abe5ba91208c7010889c0fec50ee7" +
            "bc4ec51ef805f24504a6170228b1f0cb870b6634cb0d2b8ed59004c0c61746ec" +
            "7c3cb97327c0378739f8"
        );
        
        var packet = unprotectedPacket.ToArray();
        var protection = new AesEcbHeaderProtection(hpKey);
        
        // Apply header protection
        protection.Apply(packet, 0);
        
        // Verify the result matches RFC 9001 expected output
        Assert.Equal(expectedProtectedPacket, packet);
    }
}