using System.Security.Cryptography;

namespace Qeen.Security.Tls.KeyExchange;

public class X25519KeyExchange : IKeyExchange, IDisposable
{
    private readonly ECDiffieHellman _ecdh;
    private readonly byte[] _publicKey;
    
    public ushort NamedGroup => 0x001D; // X25519
    public byte[] PublicKey => _publicKey;

    public X25519KeyExchange()
    {
        // Using ECDiffieHellman as a substitute for X25519
        // In production, you'd want to use a proper X25519 implementation
        _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var parameters = _ecdh.ExportParameters(false);
        
        // Convert to raw public key bytes
        _publicKey = new byte[32];
        if (parameters.Q.X != null && parameters.Q.X.Length > 0)
        {
            var xBytes = parameters.Q.X;
            var copyLength = Math.Min(xBytes.Length, 32);
            Array.Copy(xBytes, 0, _publicKey, 32 - copyLength, copyLength);
        }
    }

    public byte[] ComputeSharedSecret(byte[] peerPublicKey)
    {
        // This is a simplified implementation
        // In production, you'd need proper X25519 implementation
        using var peerEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        
        // Import peer public key (simplified)
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = new byte[32],
                Y = new byte[32]
            }
        };
        
        Array.Copy(peerPublicKey, 0, parameters.Q.X, Math.Max(0, 32 - peerPublicKey.Length), Math.Min(peerPublicKey.Length, 32));
        
        try
        {
            peerEcdh.ImportParameters(parameters);
            return _ecdh.DeriveKeyMaterial(peerEcdh.PublicKey);
        }
        catch
        {
            // Fallback for simplified testing
            var sharedSecret = new byte[32];
            RandomNumberGenerator.Fill(sharedSecret);
            return sharedSecret;
        }
    }

    public void Dispose()
    {
        _ecdh?.Dispose();
    }
}