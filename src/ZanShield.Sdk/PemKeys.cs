using System;
using System.Security.Cryptography;

namespace ZanShield.Sdk;

/// <summary>Reads the PEM key files ZanShield issues.</summary>
public static class PemKeys
{
    /// <summary>Loads your system's PKCS#8 PEM private key ("-----BEGIN PRIVATE KEY-----").</summary>
    /// <exception cref="ArgumentException">The text isn't a valid RSA private key.</exception>
    public static RSA LoadPrivateKey(string pem) => Load(pem, "private");

    /// <summary>Loads an X.509 PEM public key ("-----BEGIN PUBLIC KEY-----"), such as ZanShield's engine key.</summary>
    /// <exception cref="ArgumentException">The text isn't a valid RSA public key.</exception>
    public static RSA LoadPublicKey(string pem) => Load(pem, "public");

    private static RSA Load(string pem, string kind)
    {
        ArgumentNullException.ThrowIfNull(pem);
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            return rsa;
        }
        catch (Exception e) when (e is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new ArgumentException($"Invalid RSA {kind} key PEM", nameof(pem), e);
        }
    }
}
