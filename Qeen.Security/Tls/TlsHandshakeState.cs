namespace Qeen.Security.Tls;

public enum TlsHandshakeState
{
    Start,
    ReceivedClientHello,
    ReceivedServerHello,
    ReceivedEncryptedExtensions,
    ReceivedCertificateRequest,
    ReceivedCertificate,
    ReceivedCertificateVerify,
    ReceivedFinished,
    Connected,
    KeyUpdatePending,
    Closed
}

public enum TlsRole
{
    Client,
    Server
}