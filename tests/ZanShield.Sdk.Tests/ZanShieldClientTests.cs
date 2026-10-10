using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace ZanShield.Sdk.Tests;

/// <summary>
/// Round trips with throwaway keys. "ZanShield" here is a second client holding the engine's key
/// pair, which opens your tickets and seals acknowledgements back, as the real engine does.
/// </summary>
public class ZanShieldClientTests
{
    private static readonly RSA SystemKey = RSA.Create(2048);
    private static readonly RSA EngineKey = RSA.Create(2048);

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 11, 8, 0, 0, TimeSpan.Zero));

    private ZanShieldClient SystemClient(ITxnIdStore? store = null) => new("PAYROLL01", "EGAZ", SystemKey, EngineKey,
        new ZanShieldClientOptions { TimeProvider = _time, TxnIdStore = store });

    // The engine's side: opens tickets addressed to it, and seals acknowledgements to the system.
    private static ZanShieldClient Engine() => new("ENGINE", "EGAZ", EngineKey, SystemKey);

    private string Acknowledgement(int responseCode = ResponseCodes.Success, bool authenticated = true,
        string txnId = "TXN-1", DateTimeOffset? issuedAt = null) =>
        Engine().CreateTicket(new TicketPayload
        {
            SystemCode = "PAYROLL01",
            InstitutionCode = "EGAZ",
            UserId = "u-42",
            Email = "amina@example.go.tz",
            AuthenticationMethod = "TOTP",
            // Java writes up to 9 fractional digits; the SDK must accept that.
            DateTime = (issuedAt ?? _time.GetUtcNow()).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff") + "12Z",
            IsAuthenticated = authenticated,
            TxnId = txnId,
            ResponseCode = responseCode,
            Message = responseCode == ResponseCodes.Success ? "Success" : "Invalid verification code",
        });

    [Fact]
    public void TicketCarriesWhoTheUserIsAndNoRequestType()
    {
        var ticket = SystemClient().CreateTicket("u-42", "amina@example.go.tz", "Amina Juma", "0772 123 456");
        var opened = new ZanShieldClient("ENGINE", "EGAZ", EngineKey, SystemKey).OpenAcknowledgement(ticket);

        Assert.Equal("PAYROLL01", opened.SystemCode);
        Assert.Equal("EGAZ", opened.InstitutionCode);
        Assert.Equal("u-42", opened.UserId);
        Assert.Equal("amina@example.go.tz", opened.Email);
        Assert.Equal("Amina Juma", opened.FullName);
        Assert.Equal("0772 123 456", opened.Mobile);
        Assert.Equal("2026-10-11T08:00:00.000Z", opened.DateTime);
    }

    [Fact]
    public void OptionalFieldsAreLeftOutOfTheWireJson()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(new TicketPayload { UserId = "u-42", Email = "a@b.tz" },
            ZanShieldJsonContext.Default.TicketPayload);
        var node = JsonNode.Parse(json)!.AsObject();

        Assert.Equal(["userId", "email"], node.Select(p => p.Key).ToArray());
    }

    [Fact]
    public void BuildsThePortalUrl()
    {
        Assert.Equal("https://portal.example/ticket?ticket=a%2Bb%2Fc",
            ZanShieldClient.PortalUrl("https://portal.example/", "a+b/c"));
        Assert.EndsWith("&add=1", ZanShieldClient.PortalUrl("https://portal.example", "t", addMethod: true));
    }

    [Fact]
    public void AcceptsAFreshSuccessfulAcknowledgementOnce()
    {
        var client = SystemClient();
        var ack = Acknowledgement();

        var accepted = client.AcceptAcknowledgement(ack);
        Assert.Equal("u-42", accepted.UserId);
        Assert.Equal(ResponseCodes.Success, accepted.ResponseCode);

        var replay = Assert.Throws<AcknowledgementRejectedException>(() => client.AcceptAcknowledgement(ack));
        Assert.Equal(AcknowledgementRejectionReason.Replayed, replay.Reason);
    }

    [Fact]
    public void RejectsAnUnsuccessfulAcknowledgement()
    {
        var e = Assert.Throws<AcknowledgementRejectedException>(() =>
            SystemClient().AcceptAcknowledgement(Acknowledgement(ResponseCodes.InvalidCode, authenticated: false)));

        Assert.Equal(AcknowledgementRejectionReason.NotAuthenticated, e.Reason);
        Assert.Equal("Invalid verification code", e.Message);
        Assert.Equal(ResponseCodes.InvalidCode, e.Acknowledgement.ResponseCode);
    }

    [Fact]
    public void RejectsAnOldAcknowledgement()
    {
        var ack = Acknowledgement(issuedAt: _time.GetUtcNow());
        _time.Advance(TimeSpan.FromMinutes(4));

        var e = Assert.Throws<AcknowledgementRejectedException>(() => SystemClient().AcceptAcknowledgement(ack));
        Assert.Equal(AcknowledgementRejectionReason.Expired, e.Reason);
    }

    [Fact]
    public void UsesTheConfiguredTxnIdStore()
    {
        var store = new RecordingStore();
        SystemClient(store).AcceptAcknowledgement(Acknowledgement(txnId: "TXN-77"));

        Assert.Equal(["TXN-77"], store.Seen);
        Assert.Throws<AcknowledgementRejectedException>(() =>
            SystemClient(store).AcceptAcknowledgement(Acknowledgement(txnId: "TXN-77")));
    }

    [Fact]
    public void RejectsATicketSignedByTheWrongKey()
    {
        using var impostor = RSA.Create(2048);
        var forged = new ZanShieldClient("ENGINE", "EGAZ", impostor, SystemKey).CreateTicket(new TicketPayload
        {
            UserId = "u-42", ResponseCode = ResponseCodes.Success, IsAuthenticated = true, TxnId = "TXN-9",
            DateTime = _time.GetUtcNow().ToString("O"),
        });

        var e = Assert.Throws<ZanShieldException>(() => SystemClient().AcceptAcknowledgement(forged));
        Assert.IsNotType<AcknowledgementRejectedException>(e);
    }

    [Fact]
    public void RejectsATamperedTicket()
    {
        var ack = Acknowledgement();
        var tampered = ack[..^6] + (ack[^6] == 'A' ? 'B' : 'A') + ack[^5..];

        Assert.Throws<ZanShieldException>(() => SystemClient().AcceptAcknowledgement(tampered));
        Assert.Throws<ZanShieldException>(() => SystemClient().AcceptAcknowledgement("not-a-ticket"));
    }

    private sealed class RecordingStore : ITxnIdStore
    {
        public List<string> Seen { get; } = [];

        public bool MarkUsed(string txnId, DateTimeOffset keepUntil)
        {
            if (Seen.Contains(txnId)) return false;
            Seen.Add(txnId);
            return true;
        }
    }
}
