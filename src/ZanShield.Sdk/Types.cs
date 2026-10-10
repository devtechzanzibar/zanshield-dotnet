using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Text.Json.Serialization;

namespace ZanShield.Sdk;

/// <summary>The <c>responseCode</c> values ZanShield puts on acknowledgements.</summary>
public static class ResponseCodes
{
    /// <summary>The only code that means the user verified successfully.</summary>
    public const int Success = 9000;
    /// <summary>The ticket could not be decrypted or verified.</summary>
    public const int InvalidTicket = 9031;
    /// <summary>The user entered too many wrong codes.</summary>
    public const int MaxAttemptsReached = 9032;
    /// <summary>The ticket was too old when it reached ZanShield.</summary>
    public const int TicketExpired = 9038;
    /// <summary>The system code is unknown, or the system is deactivated.</summary>
    public const int UnknownClientSystem = 9040;
    /// <summary>The user already has that method.</summary>
    public const int MethodAlreadyRegistered = 9041;
    /// <summary>The user has not set up that method.</summary>
    public const int MethodNotRegistered = 9042;
    /// <summary>The verification code was wrong.</summary>
    public const int InvalidCode = 9043;
    /// <summary>The security key check failed.</summary>
    public const int WebAuthnError = 9044;
    /// <summary>The system does not allow that method.</summary>
    public const int MethodNotAllowed = 9045;
    /// <summary>No mobile number is on record, so SMS codes are unavailable.</summary>
    public const int MobileNotAvailable = 9046;
    /// <summary>The SMS code could not be sent.</summary>
    public const int SmsDeliveryFailed = 9047;
}

/// <summary>
/// The JSON payload carried inside a ticket. The same shape is used for your outbound ticket and
/// for ZanShield's signed acknowledgement; fields that don't apply to a direction are null and
/// left out of the wire JSON.
/// </summary>
public sealed class TicketPayload
{
    /// <summary>Your system's code.</summary>
    [JsonPropertyName("systemCode")] public string? SystemCode { get; set; }
    /// <summary>Your institution's code.</summary>
    [JsonPropertyName("institutionCode")] public string? InstitutionCode { get; set; }
    /// <summary>Your system's ID for the user.</summary>
    [JsonPropertyName("userId")] public string? UserId { get; set; }
    /// <summary>The user's email address.</summary>
    [JsonPropertyName("email")] public string? Email { get; set; }

    /// <summary>Optional: lets the portal greet the user by name.</summary>
    [JsonPropertyName("fullName")] public string? FullName { get; set; }

    /// <summary>Optional: needed for the user to choose SMS codes.</summary>
    [JsonPropertyName("mobile")] public string? Mobile { get; set; }

    /// <summary>On an acknowledgement: the method the user verified with, e.g. "TOTP".</summary>
    [JsonPropertyName("authenticationMethod")] public string? AuthenticationMethod { get; set; }
    /// <summary>When the ticket or acknowledgement was issued (ISO 8601, UTC).</summary>
    [JsonPropertyName("dateTime")] public string? DateTime { get; set; }
    /// <summary>On an acknowledgement: whether the user verified.</summary>
    [JsonPropertyName("isAuthenticated")] public bool? IsAuthenticated { get; set; }
    /// <summary>On an acknowledgement: the user's registered methods.</summary>
    [JsonPropertyName("authenticationMethods")] public string? AuthenticationMethods { get; set; }
    /// <summary>On an acknowledgement: ZanShield's transaction ID, used once.</summary>
    [JsonPropertyName("txnID")] public string? TxnId { get; set; }
    /// <summary>On an acknowledgement: one of the <see cref="ResponseCodes"/>.</summary>
    [JsonPropertyName("responseCode")] public int? ResponseCode { get; set; }
    /// <summary>On an acknowledgement: ZanShield's message for the outcome.</summary>
    [JsonPropertyName("message")] public string? Message { get; set; }
}

/// <summary>Raised for any failure while building or opening a ZanShield ticket. Never trust such a ticket.</summary>
public class ZanShieldException : Exception
{
    /// <summary>Creates the exception with a message.</summary>
    public ZanShieldException(string message) : base(message) { }

    /// <summary>Creates the exception with a message and the underlying cause.</summary>
    public ZanShieldException(string message, Exception innerException) : base(message, innerException) { }
}

/// <summary>Why <see cref="ZanShieldClient.AcceptAcknowledgement"/> refused a genuine acknowledgement.</summary>
public enum AcknowledgementRejectionReason
{
    /// <summary>The user didn't verify (wrong codes, gave up, locked out...).</summary>
    NotAuthenticated,
    /// <summary>The acknowledgement is older than the allowed age.</summary>
    Expired,
    /// <summary>The acknowledgement's <c>txnID</c> was already accepted once.</summary>
    Replayed,
}

/// <summary>
/// Thrown by <see cref="ZanShieldClient.AcceptAcknowledgement"/> when a genuine acknowledgement
/// must still not start a session. <see cref="Acknowledgement"/> has its contents, e.g. ZanShield's message.
/// </summary>
public sealed class AcknowledgementRejectedException : ZanShieldException
{
    /// <summary>Creates the exception for a rejected acknowledgement.</summary>
    public AcknowledgementRejectedException(AcknowledgementRejectionReason reason, string message, TicketPayload acknowledgement)
        : base(message)
    {
        Reason = reason;
        Acknowledgement = acknowledgement;
    }

    /// <summary>Why the acknowledgement was refused.</summary>
    public AcknowledgementRejectionReason Reason { get; }

    /// <summary>The acknowledgement's contents, for logging or to show ZanShield's message.</summary>
    public TicketPayload Acknowledgement { get; }
}

/// <summary>
/// Where <see cref="ZanShieldClient.AcceptAcknowledgement"/> remembers used <c>txnID</c>s, so a
/// leaked callback URL can't be replayed into a second session. With several servers, implement
/// it on shared storage (a database unique key, Redis <c>SET NX</c>, ...).
/// </summary>
public interface ITxnIdStore
{
    /// <summary>Records <paramref name="txnId"/>; returns true the first time it's seen, false if it was already used.</summary>
    bool MarkUsed(string txnId, DateTimeOffset keepUntil);
}

/// <summary>The default <see cref="ITxnIdStore"/>: thread-safe, fine for a single process.</summary>
public sealed class InMemoryTxnIdStore : ITxnIdStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _used = new();
    private readonly TimeProvider _time;

    /// <summary>Creates an empty store.</summary>
    public InMemoryTxnIdStore() : this(TimeProvider.System) { }

    internal InMemoryTxnIdStore(TimeProvider time) => _time = time;

    /// <inheritdoc />
    public bool MarkUsed(string txnId, DateTimeOffset keepUntil)
    {
        var now = _time.GetUtcNow();
        foreach (var expired in _used.Where(e => e.Value < now).Select(e => e.Key).ToList())
        {
            _used.TryRemove(expired, out _);
        }
        return _used.TryAdd(txnId, keepUntil);
    }
}

/// <summary>Settings for <see cref="ZanShieldClient"/>.</summary>
public sealed class ZanShieldClientOptions
{
    /// <summary>Where used <c>txnID</c>s are remembered. Defaults to an <see cref="InMemoryTxnIdStore"/>.</summary>
    public ITxnIdStore? TxnIdStore { get; set; }

    /// <summary>How old an acknowledgement may be when it reaches your redirect URI. Defaults to 3 minutes.</summary>
    public TimeSpan MaxAcknowledgementAge { get; set; } = TimeSpan.FromMinutes(3);

    /// <summary>The clock; replace it in tests. Defaults to <see cref="TimeProvider.System"/>.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}
