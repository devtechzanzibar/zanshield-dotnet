# ZanShield SDK for .NET

Add ZanShield multi-factor authentication to your system's login. ZanShield is the authentication service run by eGAZ (eGovernment Authority Zanzibar).

Your system checks the user's password as usual, then hands them to ZanShield for the second factor. ZanShield decides everything from there: whether the user sets up their first method or verifies an existing one, and which methods (authenticator app, security key, email, SMS) your system allows. It then sends the user back to you with a signed acknowledgement. This library builds the ticket you send and checks the acknowledgement you get back.

## Install

```bash
dotnet add package ZanShield.Sdk
```

Requires .NET 8 or later. No dependencies beyond .NET itself. Works in trimmed and native-AOT apps.

## Before you start

Your institution admin registers your system in the ZanShield administration console. You get:

- your **system code** (e.g. `PAYROLL01`) and **institution code**
- your system's **private key** (shown once; keep it on your server only, never in a browser or mobile app)
- ZanShield's **engine public key** (the admin console's "Download ZanShield public key" button)
- the **portal address**, e.g. `https://portal.zanshield.devtech.co.tz`

The **redirect URI** you register is where ZanShield sends users back to.

## Usage

Create one `ZanShieldClient` and share it; it is thread-safe. In ASP.NET Core, register it as a singleton:

```csharp
using ZanShield.Sdk;

builder.Services.AddSingleton(new ZanShieldClient(
    "PAYROLL01",
    "EGAZ",
    PemKeys.LoadPrivateKey(File.ReadAllText("/secure/zanshield-private.pem")),
    PemKeys.LoadPublicKey(File.ReadAllText("/secure/zanshield-engine-public.pem"))));
```

```csharp
// 1. After the user's password is correct. fullName and mobile are optional;
//    without a mobile number the user can't choose SMS codes.
string ticket = zanShield.CreateTicket(user.Id, user.Email, user.FullName, user.Phone);
return Redirect(ZanShieldClient.PortalUrl("https://portal.zanshield.devtech.co.tz", ticket));

// 2. At your redirect URI, ZanShield sends the user back with ?ticket=...
try
{
    TicketPayload ack = zanShield.AcceptAcknowledgement(Request.Query["ticket"]!);
    await SignInAsync(ack.UserId!);
}
catch (AcknowledgementRejectedException e)
{
    // Genuine, but must not sign in: e.Reason is NotAuthenticated, Expired or Replayed.
    return ShowError(e.Acknowledgement.Message ?? e.Message);
}
// Any other ZanShieldException means it isn't a valid ZanShield acknowledgement at all.
```

`AcceptAcknowledgement` does every check your callback needs before it starts a session. If any check fails it throws and returns nothing:

1. The ticket decrypts with your key and is signed by ZanShield. If not, it throws `ZanShieldException`, and you must never trust such a ticket.
2. `ResponseCode` is `9000` and `IsAuthenticated` is true.
3. It's fresh: issued less than 3 minutes ago, configurable with `ZanShieldClientOptions.MaxAcknowledgementAge`.
4. Its `TxnId` hasn't been used before, so a leaked callback URL can't be replayed into a second session.

### More than one server

By default, used transaction IDs are remembered in memory, which protects a single process. If your application runs on several servers, implement `ITxnIdStore` on something they share:

```csharp
public sealed class RedisTxnIdStore(IDatabase redis) : ITxnIdStore
{
    public bool MarkUsed(string txnId, DateTimeOffset keepUntil) =>
        redis.StringSet($"zanshield:txn:{txnId}", 1, keepUntil - DateTimeOffset.UtcNow, When.NotExists);
}

var zanShield = new ZanShieldClient(systemCode, institutionCode, privateKey, enginePublicKey,
    new ZanShieldClientOptions { TxnIdStore = new RedisTxnIdStore(redis) });
```

## Response codes

`ResponseCodes` has every code ZanShield uses. On an acknowledgement, only `ResponseCodes.Success` (9000) means the user verified.

## License

Apache-2.0
