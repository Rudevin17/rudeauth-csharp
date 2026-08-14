using System.Text;
using System.Text.Json;

namespace RudeAuth;

// Session is an authenticated, live connection. It heartbeats on a background
// task from construction. Dispose stops the heartbeat and zeroes the session key.
public sealed class Session : IDisposable
{
    private readonly RudeAuthClient _client;
    private readonly string _token;
    private readonly object _lock = new();
    private readonly byte[] _key;
    private readonly LicenseInfo _info;
    private long _expiresAt;
    private bool _closed;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _beat;

    internal Session(RudeAuthClient client, string token, byte[] key, LicenseInfo info, long expiresAt)
    {
        _client = client;
        _token = token;
        _key = key;
        _info = info;
        _expiresAt = expiresAt;
        _beat = Task.Run(() => BeatLoopAsync(_stop.Token));
    }

    // Info is what the server reported about the licence at handshake.
    public LicenseInfo Info => _info;

    public void Dispose()
    {
        _stop.Cancel();
        lock (_lock)
        {
            _closed = true;
            Array.Clear(_key, 0, _key.Length);
        }
        try { _beat.Wait(TimeSpan.FromSeconds(1)); } catch { /* stopping */ }
        _stop.Dispose();
    }

    // Variable returns a server-side value, fetched fresh. There is no cache: a
    // cached "last known good" value is exactly what an attacker induces by
    // blocking the network.
    public string Variable(string name) => VariableAsync(name).GetAwaiter().GetResult();

    public async Task<string> VariableAsync(string name, CancellationToken ct = default)
    {
        byte[] plain = await SealedCallAsync("/v1/variables", "variables",
            new Dictionary<string, object?> { ["app_id"] = _client.AppId, ["session_token"] = _token },
            Encoding.ASCII.GetBytes("variables"), ct).ConfigureAwait(false);

        Dictionary<string, string>? vars = JsonSerializer.Deserialize<Dictionary<string, string>>(plain, RudeAuthClient.JsonOpts);
        if (vars is null || !vars.TryGetValue(name, out string? v))
        {
            throw new RudeAuthException(ErrorCode.BadResponse, $"no such variable: {name}");
        }
        return v;
    }

    // File returns a decrypted payload that never shipped inside your binary.
    public byte[] File(string name) => FileAsync(name).GetAwaiter().GetResult();

    public Task<byte[]> FileAsync(string name, CancellationToken ct = default) =>
        SealedCallAsync("/v1/files", "files",
            new Dictionary<string, object?> { ["app_id"] = _client.AppId, ["session_token"] = _token, ["name"] = name },
            Encoding.ASCII.GetBytes("files:" + name), ct);

    // Webhook asks the server to call one of your configured endpoints, so the URL
    // never appears in your binary.
    public string Webhook(string name, IReadOnlyDictionary<string, string> parameters) =>
        WebhookAsync(name, parameters).GetAwaiter().GetResult();

    public async Task<string> WebhookAsync(string name, IReadOnlyDictionary<string, string> parameters, CancellationToken ct = default)
    {
        byte[] data = await _client.CallEndpointAsync("/v1/webhook", "webhook",
            new Dictionary<string, object?> { ["app_id"] = _client.AppId, ["session_token"] = _token, ["name"] = name, ["params"] = parameters },
            ct).ConfigureAwait(false);
        WebhookPayload wp = JsonSerializer.Deserialize<WebhookPayload>(data, RudeAuthClient.JsonOpts)
            ?? throw new RudeAuthException(ErrorCode.BadResponse, "webhook did not parse");
        if (!wp.Success)
        {
            throw RudeAuthException.FromWire(wp.Error);
        }
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(wp.Body)); }
        catch (FormatException) { throw new RudeAuthException(ErrorCode.BadResponse, "webhook body is not base64"); }
    }

    private async Task<byte[]> SealedCallAsync(string path, string endpoint, object body, byte[] aad, CancellationToken ct)
    {
        byte[] data = await _client.CallEndpointAsync(path, endpoint, body, ct).ConfigureAwait(false);
        GatingPayload gp = JsonSerializer.Deserialize<GatingPayload>(data, RudeAuthClient.JsonOpts)
            ?? throw new RudeAuthException(ErrorCode.BadResponse, "gating payload did not parse");
        if (!gp.Success)
        {
            throw RudeAuthException.FromWire(gp.Error);
        }
        byte[] sealedBlob;
        try { sealedBlob = Convert.FromBase64String(gp.Sealed); }
        catch (FormatException) { throw new RudeAuthException(ErrorCode.BadResponse, "sealed field is not base64"); }

        lock (_lock)
        {
            if (_closed)
            {
                throw new RudeAuthException(ErrorCode.SessionExpired, "session is closed");
            }
            byte[]? plain = Crypto.OpenSealed(_key, sealedBlob, aad);
            if (plain is null)
            {
                throw new RudeAuthException(ErrorCode.BadResponse, "sealed payload did not open for this session");
            }
            return plain;
        }
    }

    // BeatLoopAsync keeps the session alive. A missed beat is NOT a logout: it
    // retries until the TTL genuinely lapses, so a brief network blip does not
    // drop a paying customer.
    private async Task BeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            long remaining;
            lock (_lock) { remaining = _expiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds(); }
            TimeSpan wait = remaining > 4 ? TimeSpan.FromSeconds(remaining / 2) : TimeSpan.FromSeconds(2);
            try { await Task.Delay(wait, ct).ConfigureAwait(false); }
            catch (TaskCanceledException) { return; }
            await BeatOnceAsync(ct).ConfigureAwait(false);
        }
    }

    private async Task BeatOnceAsync(CancellationToken ct)
    {
        try
        {
            byte[] data = await _client.CallEndpointAsync("/v1/heartbeat", "heartbeat",
                new Dictionary<string, object?> { ["app_id"] = _client.AppId, ["session_token"] = _token }, ct).ConfigureAwait(false);
            HeartbeatPayload? hp = JsonSerializer.Deserialize<HeartbeatPayload>(data, RudeAuthClient.JsonOpts);
            if (hp is null || !hp.Valid)
            {
                return; // let the TTL lapse naturally
            }
            if (hp.ExpiresAt > 0)
            {
                lock (_lock) { _expiresAt = hp.ExpiresAt; }
            }
        }
        catch (RudeAuthException)
        {
            // transient; the TTL still governs
        }
    }
}
