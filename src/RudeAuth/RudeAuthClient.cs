using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace RudeAuth;

// Options for a RudeAuthClient. The Collect/Label/Handler hooks are internal so
// tests can inject deterministic values and an in-process server.
public sealed class RudeAuthClientOptions
{
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(15);
    public string AppVersion { get; set; } = "1.0.0";

    internal Func<IReadOnlyList<string>>? Collect { get; set; }
    internal Func<string>? Label { get; set; }
    internal HttpMessageHandler? Handler { get; set; }
}

// RudeAuthClient holds the pinned public key and talks to one RudeAuth server.
public sealed class RudeAuthClient : IDisposable
{
    private const long MaxClockSkewSec = 300;
    private const int MinComponents = 2;

    internal static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    private readonly byte[] _pub;
    private readonly string _baseUrl;
    private readonly string _appVersion;
    private readonly HttpClient _http;
    private readonly Func<IReadOnlyList<string>> _collect;
    private readonly Func<string> _label;

    internal string AppId { get; }

    // appId and publicKeyBase64 come from `rudeauth-cli app create`. Both are safe
    // to embed: the public key verifies responses, it cannot forge them.
    public RudeAuthClient(string appId, string publicKeyBase64, string baseUrl, RudeAuthClientOptions? options = null)
    {
        options ??= new RudeAuthClientOptions();
        byte[] pub;
        try { pub = Convert.FromBase64String(publicKeyBase64); }
        catch (FormatException) { throw new RudeAuthException(ErrorCode.Internal, "public key is not valid base64"); }
        if (pub.Length != 32)
        {
            throw new RudeAuthException(ErrorCode.Internal, "public key must be a 32-byte Ed25519 key");
        }

        AppId = appId;
        _pub = pub;
        _baseUrl = baseUrl.TrimEnd('/');
        _appVersion = options.AppVersion;
        _http = options.Handler is null
            ? new HttpClient()
            : new HttpClient(options.Handler, disposeHandler: false);
        _http.Timeout = options.Timeout;
        _collect = options.Collect ?? Fingerprint.Collect;
        _label = options.Label ?? Fingerprint.Label;
    }

    public void Dispose() => _http.Dispose();

    // CallEndpointAsync posts body and returns the VERIFIED payload bytes. There
    // is no path through here that yields unverified data.
    internal async Task<byte[]> CallEndpointAsync(string path, string endpoint, object body, CancellationToken ct)
    {
        byte[] reqBytes = JsonSerializer.SerializeToUtf8Bytes(body, JsonOpts);
        using var content = new ByteArrayContent(reqBytes);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

        HttpResponseMessage resp;
        try
        {
            resp = await _http.PostAsync(_baseUrl + path, content, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new RudeAuthException(ErrorCode.Network, "server unreachable", ex);
        }

        using (resp)
        {
            if (resp.StatusCode != HttpStatusCode.OK)
            {
                // A non-200 carries no signed envelope, so nothing about it can be trusted.
                throw new RudeAuthException(ErrorCode.BadResponse, $"http status {(int)resp.StatusCode}");
            }

            byte[] raw = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            Envelope? env;
            try { env = JsonSerializer.Deserialize<Envelope>(raw, JsonOpts); }
            catch (JsonException) { throw new RudeAuthException(ErrorCode.BadResponse, "envelope did not parse"); }
            if (env is null || env.Data.Length == 0 || env.Signature.Length == 0)
            {
                throw new RudeAuthException(ErrorCode.BadResponse, "envelope fields missing");
            }

            byte[] data, sig;
            try
            {
                data = Convert.FromBase64String(env.Data);
                sig = Convert.FromBase64String(env.Signature);
            }
            catch (FormatException) { throw new RudeAuthException(ErrorCode.BadResponse, "envelope is not base64"); }

            // STEP ONE, before anything is parsed: verify against the pinned key.
            if (!Crypto.Verify(_pub, endpoint, data, sig))
            {
                throw new RudeAuthException(ErrorCode.SignatureInvalid, "response was not signed by this application's key");
            }
            return data;
        }
    }

    // Authenticate performs the handshake and returns a live Session, or throws a
    // RudeAuthException. A rejected licence is a specific ErrorCode, never a bool.
    public Session Authenticate(string licenseKey) => AuthenticateAsync(licenseKey).GetAwaiter().GetResult();

    public async Task<Session> AuthenticateAsync(string licenseKey, CancellationToken ct = default)
    {
        IReadOnlyList<string> components = _collect();
        if (components.Count < MinComponents)
        {
            throw new RudeAuthException(ErrorCode.Internal,
                $"could not read enough hardware components ({components.Count}, need {MinComponents})");
        }

        (byte[] ephPub, byte[] ephPriv) = Crypto.Ephemeral();
        byte[] nonce = Crypto.RandomNonce();
        string nonceB64 = Convert.ToBase64String(nonce);

        var body = new Dictionary<string, object?>
        {
            ["app_id"] = AppId,
            ["app_version"] = _appVersion,
            ["license_key"] = licenseKey,
            ["fingerprint_components"] = components,
            ["fingerprint_label"] = _label(),
            ["client_nonce"] = nonceB64,
            ["eph_pubkey"] = Convert.ToBase64String(ephPub),
            ["sent_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };

        byte[] data = await CallEndpointAsync("/v1/handshake", "handshake", body, ct).ConfigureAwait(false);
        HandshakePayload hs = JsonSerializer.Deserialize<HandshakePayload>(data, JsonOpts)
            ?? throw new RudeAuthException(ErrorCode.BadResponse, "handshake payload did not parse");

        // The echoed nonce proves this response was produced for THIS request.
        if (hs.ClientNonce != nonceB64)
        {
            throw new RudeAuthException(ErrorCode.NonceMismatch, "server did not echo our nonce");
        }
        if (hs.ServerTime > 0)
        {
            long delta = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - hs.ServerTime;
            if (delta > MaxClockSkewSec || delta < -MaxClockSkewSec)
            {
                throw new RudeAuthException(ErrorCode.ClockSkew, "local clock differs from the server's");
            }
        }
        if (!hs.Success)
        {
            throw RudeAuthException.FromWire(hs.Error);
        }

        byte[] serverEph;
        try { serverEph = Convert.FromBase64String(hs.ServerEphPubkey); }
        catch (FormatException) { throw new RudeAuthException(ErrorCode.BadResponse, "server ephemeral key missing"); }

        byte[] key;
        try { key = Crypto.DeriveSessionKey(ephPriv, serverEph, hs.SessionId); }
        catch (Exception ex) { throw new RudeAuthException(ErrorCode.BadResponse, "session key derivation failed", ex); }

        return new Session(this, hs.SessionToken, key, hs.License ?? new LicenseInfo(), hs.SessionExpiresAt);
    }

    // RequestDeviceReset unbinds a licence from its machines so it can be moved.
    // The server bounds this by cooldown and lifetime cap; the client cannot.
    public static void RequestDeviceReset(string appId, string publicKeyBase64, string baseUrl, string licenseKey, RudeAuthClientOptions? options = null)
        => RequestDeviceResetAsync(appId, publicKeyBase64, baseUrl, licenseKey, options).GetAwaiter().GetResult();

    public static async Task RequestDeviceResetAsync(string appId, string publicKeyBase64, string baseUrl, string licenseKey, RudeAuthClientOptions? options = null, CancellationToken ct = default)
    {
        using var c = new RudeAuthClient(appId, publicKeyBase64, baseUrl, options);
        byte[] data = await c.CallEndpointAsync("/v1/device/reset", "device_reset",
            new Dictionary<string, object?> { ["app_id"] = appId, ["license_key"] = licenseKey }, ct).ConfigureAwait(false);
        DeviceResetPayload dr = JsonSerializer.Deserialize<DeviceResetPayload>(data, JsonOpts)
            ?? throw new RudeAuthException(ErrorCode.BadResponse, "device reset did not parse");
        if (!dr.Success)
        {
            throw RudeAuthException.FromWire(dr.Error);
        }
    }
}
