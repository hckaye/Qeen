using System.Security.Cryptography;

namespace Qeen.Security.Tls.KeyExchange;

public class EllipticCurveKeyExchange : IKeyExchange, IDisposable
{
    private readonly ECDiffieHellman _ecdh;
    private readonly byte[] _publicKey;
    private readonly ushort _namedGroup;
    
    public ushort NamedGroup => _namedGroup;
    public byte[] PublicKey => _publicKey;

    public EllipticCurveKeyExchange(ushort namedGroup)
    {
        _namedGroup = namedGroup;
        var curve = GetCurve(namedGroup);
        _ecdh = ECDiffieHellman.Create(curve);
        
        // Export public key in uncompressed format
        var parameters = _ecdh.ExportParameters(false);
        _publicKey = EncodeUncompressedPoint(parameters.Q);
    }

    private static ECCurve GetCurve(ushort namedGroup)
    {
        return namedGroup switch
        {
            0x0017 => ECCurve.NamedCurves.nistP256, // secp256r1
            0x0018 => ECCurve.NamedCurves.nistP384, // secp384r1
            0x0019 => ECCurve.NamedCurves.nistP521, // secp521r1
            _ => throw new NotSupportedException($"Named group {namedGroup:X4} is not supported")
        };
    }

    private static byte[] EncodeUncompressedPoint(ECPoint point)
    {
        if (point.X == null || point.Y == null)
            throw new InvalidOperationException("Invalid EC point");
            
        var result = new byte[1 + point.X.Length + point.Y.Length];
        result[0] = 0x04; // Uncompressed point
        point.X.CopyTo(result, 1);
        point.Y.CopyTo(result, 1 + point.X.Length);
        return result;
    }

    private static ECPoint DecodeUncompressedPoint(byte[] data, int coordinateLength)
    {
        if (data[0] != 0x04)
            throw new InvalidOperationException("Only uncompressed points are supported");
            
        return new ECPoint
        {
            X = data[1..(1 + coordinateLength)],
            Y = data[(1 + coordinateLength)..(1 + 2 * coordinateLength)]
        };
    }

    public byte[] ComputeSharedSecret(byte[] peerPublicKey)
    {
        var curve = GetCurve(_namedGroup);
        var coordinateLength = _namedGroup switch
        {
            0x0017 => 32, // P-256
            0x0018 => 48, // P-384
            0x0019 => 66, // P-521
            _ => 32
        };
        
        var peerPoint = DecodeUncompressedPoint(peerPublicKey, coordinateLength);
        
        using var peerEcdh = ECDiffieHellman.Create(new ECParameters
        {
            Curve = curve,
            Q = peerPoint
        });
        
        return _ecdh.DeriveKeyMaterial(peerEcdh.PublicKey);
    }

    public void Dispose()
    {
        _ecdh?.Dispose();
    }
}