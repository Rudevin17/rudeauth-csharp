using System.Text.Json.Serialization;

namespace RudeAuth;

// Response DTOs, mirroring the server's internal/api/client wire.go. The
// signature is verified over the raw bytes before any of these are parsed.

internal sealed class Envelope
{
    [JsonPropertyName("data")] public string Data { get; set; } = "";
    [JsonPropertyName("signature")] public string Signature { get; set; } = "";
}

// LicenseInfo is what the server reports about the licence at handshake.
public sealed class LicenseInfo
{
    [JsonPropertyName("level")] public int Level { get; set; }
    [JsonPropertyName("expires_at")] public long ExpiresAt { get; set; } // unix seconds; 0 = perpetual
    [JsonPropertyName("devices_used")] public int DevicesUsed { get; set; }
    [JsonPropertyName("max_devices")] public int MaxDevices { get; set; }
}

internal sealed class HandshakePayload
{
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("client_nonce")] public string ClientNonce { get; set; } = "";
    [JsonPropertyName("server_time")] public long ServerTime { get; set; }
    [JsonPropertyName("session_token")] public string SessionToken { get; set; } = "";
    [JsonPropertyName("session_expires_at")] public long SessionExpiresAt { get; set; }
    [JsonPropertyName("session_id")] public string SessionId { get; set; } = "";
    [JsonPropertyName("server_eph_pubkey")] public string ServerEphPubkey { get; set; } = "";
    [JsonPropertyName("license")] public LicenseInfo? License { get; set; }
    [JsonPropertyName("error")] public string Error { get; set; } = "";
}

internal sealed class GatingPayload
{
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("sealed")] public string Sealed { get; set; } = "";
    [JsonPropertyName("version")] public int Version { get; set; }
    [JsonPropertyName("error")] public string Error { get; set; } = "";
}

internal sealed class HeartbeatPayload
{
    [JsonPropertyName("valid")] public bool Valid { get; set; }
    [JsonPropertyName("expires_at")] public long ExpiresAt { get; set; }
    [JsonPropertyName("error")] public string Error { get; set; } = "";
}

internal sealed class WebhookPayload
{
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("body")] public string Body { get; set; } = "";
    [JsonPropertyName("error")] public string Error { get; set; } = "";
}

internal sealed class DeviceResetPayload
{
    [JsonPropertyName("success")] public bool Success { get; set; }
    [JsonPropertyName("error")] public string Error { get; set; } = "";
}
