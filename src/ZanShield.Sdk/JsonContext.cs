using System.Text.Json.Serialization;

namespace ZanShield.Sdk;

/// <summary>The signed envelope inside a sealed ticket: the payload JSON and its signature, both base64.</summary>
internal sealed record Envelope(
    [property: JsonPropertyName("payload")] string Payload,
    [property: JsonPropertyName("signature")] string Signature);

// JSON code generated at compile time, so the library works in trimmed and native-AOT apps.
[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(TicketPayload))]
[JsonSerializable(typeof(Envelope))]
internal sealed partial class ZanShieldJsonContext : JsonSerializerContext
{
}
