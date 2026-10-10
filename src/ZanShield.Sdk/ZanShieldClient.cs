using System;
using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ZanShield.Sdk;

/// <summary>
/// Builds and opens ZanShield tickets: signs and encrypts the tickets you send to ZanShield, and
/// decrypts and verifies the signed acknowledgements it sends back. Thread-safe: create one and share it.
/// </summary>
/// <remarks>
/// Wire format (base64url without padding, of the concatenation): a 4-byte big-endian length of the
/// RSA-OAEP-SHA256-wrapped AES-256 key, the wrapped key, a 12-byte GCM IV, then the AES-GCM
/// ciphertext with its 16-byte tag appended. Inside is <c>{"payload","signature"}</c>: the payload
/// JSON and its SHA256withRSA signature, both base64. The same format as every other ZanShield SDK.
/// </remarks>
/// <example>
/// <code>
/// var client = new ZanShieldClient("PAYROLL01", "EGAZ",
///     PemKeys.LoadPrivateKey(File.ReadAllText("/secure/zanshield-private.pem")),
///     PemKeys.LoadPublicKey(File.ReadAllText("/secure/zanshield-engine-public.pem")));
///
/// // After the user's password is correct:
/// string ticket = client.CreateTicket(user.Id, user.Email, user.FullName, user.Phone);
/// return Redirect(ZanShieldClient.PortalUrl("https://portal.zanshield.devtech.co.tz", ticket));
///
/// // At your redirect URI:
/// TicketPayload ack = client.AcceptAcknowledgement(ticketFromQuery); // throws if it must not sign in
/// </code>
/// </example>
public sealed class ZanShieldClient
{
    private const int GcmIvBytes = 12;
    private const int GcmTagBytes = 16;
    private const int AesKeyBytes = 32;

    // Java writes up to 9 fractional-second digits; .NET parses at most 7.
    private static readonly Regex ExtraFractionDigits = new(@"(\.\d{7})\d+", RegexOptions.Compiled);

    private readonly string _systemCode;
    private readonly string _institutionCode;
    private readonly RSA _myPrivateKey;
    private readonly RSA _enginePublicKey;
    private readonly ITxnIdStore _txnIdStore;
    private readonly TimeSpan _maxAcknowledgementAge;
    private readonly TimeProvider _time;

    /// <param name="systemCode">Your system's code, e.g. "PAYROLL01".</param>
    /// <param name="institutionCode">Your institution's code, e.g. "EGAZ".</param>
    /// <param name="myPrivateKey">The private key issued once when your system was registered.</param>
    /// <param name="enginePublicKey">ZanShield's engine public key, from the Integration page.</param>
    /// <param name="options">Optional settings: replay store, acknowledgement age, clock.</param>
    public ZanShieldClient(string systemCode, string institutionCode, RSA myPrivateKey, RSA enginePublicKey,
        ZanShieldClientOptions? options = null)
    {
        _systemCode = systemCode ?? throw new ArgumentNullException(nameof(systemCode));
        _institutionCode = institutionCode ?? throw new ArgumentNullException(nameof(institutionCode));
        _myPrivateKey = myPrivateKey ?? throw new ArgumentNullException(nameof(myPrivateKey));
        _enginePublicKey = enginePublicKey ?? throw new ArgumentNullException(nameof(enginePublicKey));
        options ??= new ZanShieldClientOptions();
        _time = options.TimeProvider;
        _txnIdStore = options.TxnIdStore ?? new InMemoryTxnIdStore(_time);
        _maxAcknowledgementAge = options.MaxAcknowledgementAge;
    }

    /// <summary>
    /// Builds a signed, sealed ticket asking ZanShield to verify the user. Check the user's
    /// password yourself first: ZanShield only handles the second factor.
    /// </summary>
    /// <param name="userId">Your system's ID for the user.</param>
    /// <param name="email">The user's email address.</param>
    /// <param name="fullName">Optional: lets the portal greet the user by name.</param>
    /// <param name="mobile">Optional, any common format such as "0772 123 456": needed for SMS codes.</param>
    public string CreateTicket(string userId, string email, string? fullName = null, string? mobile = null)
    {
        return CreateTicket(new TicketPayload
        {
            SystemCode = _systemCode,
            InstitutionCode = _institutionCode,
            UserId = userId,
            Email = email,
            FullName = fullName,
            Mobile = mobile,
            DateTime = _time.GetUtcNow().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
        });
    }

    /// <summary>The portal address to redirect the browser to with the ticket.</summary>
    public static string PortalUrl(string portalBaseUrl, string ticket, bool addMethod = false)
    {
        var url = $"{portalBaseUrl.TrimEnd('/')}/ticket?ticket={Uri.EscapeDataString(ticket)}";
        return addMethod ? url + "&add=1" : url;
    }

    /// <summary>
    /// Everything your redirect URI must check before starting a session, in one call: the ticket is
    /// genuine (<see cref="OpenAcknowledgement"/>), the user verified successfully, it is fresh, and
    /// its <c>txnID</c> was never accepted before.
    /// </summary>
    /// <exception cref="AcknowledgementRejectedException">It's genuine but must not sign the user in.</exception>
    /// <exception cref="ZanShieldException">It isn't a valid ZanShield acknowledgement at all.</exception>
    public TicketPayload AcceptAcknowledgement(string ticket)
    {
        var ack = OpenAcknowledgement(ticket);
        if (ack.ResponseCode != ResponseCodes.Success || ack.IsAuthenticated != true)
        {
            throw new AcknowledgementRejectedException(AcknowledgementRejectionReason.NotAuthenticated,
                ack.Message ?? "ZanShield verification was not completed", ack);
        }

        if (string.IsNullOrEmpty(ack.DateTime) || !DateTimeOffset.TryParse(
                ExtraFractionDigits.Replace(ack.DateTime, "$1"), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out var issuedAt))
        {
            throw new AcknowledgementRejectedException(AcknowledgementRejectionReason.Expired,
                "Acknowledgement has no valid dateTime", ack);
        }
        if (issuedAt < _time.GetUtcNow() - _maxAcknowledgementAge)
        {
            throw new AcknowledgementRejectedException(AcknowledgementRejectionReason.Expired,
                "Acknowledgement has expired", ack);
        }

        if (string.IsNullOrEmpty(ack.TxnId) || !_txnIdStore.MarkUsed(ack.TxnId, issuedAt + _maxAcknowledgementAge))
        {
            throw new AcknowledgementRejectedException(AcknowledgementRejectionReason.Replayed,
                "Acknowledgement was already used", ack);
        }
        return ack;
    }

    /// <summary>Lower-level form for when you need fields <see cref="CreateTicket(string, string, string?, string?)"/> doesn't expose.</summary>
    public string CreateTicket(TicketPayload payload)
    {
        try
        {
            var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(payload, ZanShieldJsonContext.Default.TicketPayload);
            var signature = _myPrivateKey.SignData(payloadBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var envelope = new Envelope(Convert.ToBase64String(payloadBytes), Convert.ToBase64String(signature));
            var envelopeBytes = JsonSerializer.SerializeToUtf8Bytes(envelope, ZanShieldJsonContext.Default.Envelope);
            return Base64UrlEncode(Seal(envelopeBytes, _enginePublicKey));
        }
        catch (Exception e) when (e is not ZanShieldException)
        {
            throw new ZanShieldException("Failed to build ZanShield ticket", e);
        }
    }

    /// <summary>
    /// Decrypts the ticket with your key and verifies it was signed by ZanShield's engine key. This
    /// only proves it is genuine; prefer <see cref="AcceptAcknowledgement"/>.
    /// </summary>
    /// <exception cref="ZanShieldException">It isn't a valid ZanShield ticket. Never trust it.</exception>
    public TicketPayload OpenAcknowledgement(string ticket)
    {
        try
        {
            var envelopeBytes = Unseal(Base64UrlDecode(ticket), _myPrivateKey);
            var envelope = JsonSerializer.Deserialize(envelopeBytes, ZanShieldJsonContext.Default.Envelope)
                ?? throw new ZanShieldException("Ticket is empty");
            var payloadBytes = Convert.FromBase64String(envelope.Payload);
            var signature = Convert.FromBase64String(envelope.Signature);

            if (!_enginePublicKey.VerifyData(payloadBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            {
                throw new ZanShieldException("Ticket signature verification failed");
            }
            return JsonSerializer.Deserialize(payloadBytes, ZanShieldJsonContext.Default.TicketPayload)
                ?? throw new ZanShieldException("Ticket payload is empty");
        }
        catch (Exception e) when (e is not ZanShieldException)
        {
            throw new ZanShieldException("Failed to open acknowledgement ticket", e);
        }
    }

    private static byte[] Seal(byte[] plaintext, RSA recipientPublicKey)
    {
        var aesKey = RandomNumberGenerator.GetBytes(AesKeyBytes);
        var iv = RandomNumberGenerator.GetBytes(GcmIvBytes);
        var ciphertextWithTag = new byte[plaintext.Length + GcmTagBytes];
        using (var aes = new AesGcm(aesKey, GcmTagBytes))
        {
            aes.Encrypt(iv, plaintext, ciphertextWithTag.AsSpan(0, plaintext.Length),
                ciphertextWithTag.AsSpan(plaintext.Length));
        }
        var wrappedKey = recipientPublicKey.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
        CryptographicOperations.ZeroMemory(aesKey);

        var sealedBytes = new byte[4 + wrappedKey.Length + GcmIvBytes + ciphertextWithTag.Length];
        BinaryPrimitives.WriteInt32BigEndian(sealedBytes, wrappedKey.Length);
        wrappedKey.CopyTo(sealedBytes, 4);
        iv.CopyTo(sealedBytes, 4 + wrappedKey.Length);
        ciphertextWithTag.CopyTo(sealedBytes, 4 + wrappedKey.Length + GcmIvBytes);
        return sealedBytes;
    }

    private static byte[] Unseal(byte[] sealedBytes, RSA myPrivateKey)
    {
        if (sealedBytes.Length < 4 + GcmIvBytes + GcmTagBytes)
        {
            throw new ZanShieldException("Ticket is too short");
        }
        var wrappedKeyLength = BinaryPrimitives.ReadInt32BigEndian(sealedBytes);
        if (wrappedKeyLength <= 0 || 4 + wrappedKeyLength + GcmIvBytes + GcmTagBytes > sealedBytes.Length)
        {
            throw new ZanShieldException("Ticket is malformed");
        }
        var wrappedKey = sealedBytes.AsSpan(4, wrappedKeyLength).ToArray();
        var iv = sealedBytes.AsSpan(4 + wrappedKeyLength, GcmIvBytes);
        var body = sealedBytes.AsSpan(4 + wrappedKeyLength + GcmIvBytes);
        var ciphertext = body[..^GcmTagBytes];
        var tag = body[^GcmTagBytes..];

        var aesKey = myPrivateKey.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
        try
        {
            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(aesKey, GcmTagBytes);
            aes.Decrypt(iv, ciphertext, tag, plaintext);
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aesKey);
        }
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string text)
    {
        var s = text.Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        return Convert.FromBase64String(s);
    }
}
