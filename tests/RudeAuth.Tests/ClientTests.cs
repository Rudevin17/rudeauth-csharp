using System.Net;
using System.Text;
using System.Text.Json;
using NSec.Cryptography;

namespace RudeAuth.Tests;

// MockServer is a minimal RudeAuth server that signs and seals exactly as the
// real one does, so the SDK verifies real signatures and opens real payloads. It
// reuses the library's internal crypto and DTOs (via InternalsVisibleTo).
internal sealed class MockServer : HttpMessageHandler
{
    private readonly Key _signKey;
    public byte[] PublicKey { get; }
    public string PublicKeyB64 => Convert.ToBase64String(PublicKey);
    public string? FailCode { get; set; }

    private byte[] _sessionKey = Array.Empty<byte>();
    private static readonly JsonSerializerOptions J = new() { PropertyNameCaseInsensitive = true };

    public MockServer()
    {
        _signKey = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        PublicKey = _signKey.PublicKey.Export(KeyBlobFormat.RawPublicKey);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        string path = request.RequestUri!.AbsolutePath;
        byte[] reqBody = await request.Content!.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        JsonElement req = JsonDocument.Parse(reqBody).RootElement;

        switch (path)
        {
            case "/v1/handshake":
                return Respond("handshake", BuildHandshake(req));
            case "/v1/variables":
                byte[] vars = JsonSerializer.SerializeToUtf8Bytes(
                    new Dictionary<string, string> { ["offset"] = "0x4A1F", ["tier"] = "gold" });
                return Respond("variables", new GatingPayload { Success = true, Sealed = Seal(vars, Encoding.ASCII.GetBytes("variables")) });
            case "/v1/files":
                string name = req.GetProperty("name").GetString()!;
                return Respond("files", new GatingPayload { Success = true, Version = 1, Sealed = Seal(Encoding.UTF8.GetBytes("core-dll-bytes"), Encoding.ASCII.GetBytes("files:" + name)) });
            default:
                return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    private object BuildHandshake(JsonElement req)
    {
        string clientNonce = req.GetProperty("client_nonce").GetString()!;
        if (FailCode is not null)
        {
            return new HandshakePayload { Success = false, ClientNonce = clientNonce, ServerTime = Now(), Error = FailCode };
        }
        byte[] clientEph = Convert.FromBase64String(req.GetProperty("eph_pubkey").GetString()!);
        (byte[] srvPub, byte[] srvPriv) = Crypto.Ephemeral();
        const string sid = "test-session-0001";
        _sessionKey = Crypto.DeriveSessionKey(srvPriv, clientEph, sid);
        return new HandshakePayload
        {
            Success = true,
            ClientNonce = clientNonce,
            ServerTime = Now(),
            SessionToken = "session-token-xyz",
            SessionExpiresAt = Now() + 3600,
            SessionId = sid,
            ServerEphPubkey = Convert.ToBase64String(srvPub),
            License = new LicenseInfo { Level = 1, DevicesUsed = 1, MaxDevices = 1 },
        };
    }

    private string Seal(byte[] plaintext, byte[] aad)
    {
        AeadAlgorithm alg = AeadAlgorithm.XChaCha20Poly1305;
        using Key key = Key.Import(alg, _sessionKey, KeyBlobFormat.RawSymmetricKey);
        byte[] nonce = new byte[alg.NonceSize];
        System.Security.Cryptography.RandomNumberGenerator.Fill(nonce);
        byte[] ciphertext = alg.Encrypt(key, nonce, aad, plaintext);
        byte[] blob = new byte[nonce.Length + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, blob, 0, nonce.Length);
        Buffer.BlockCopy(ciphertext, 0, blob, nonce.Length, ciphertext.Length);
        return Convert.ToBase64String(blob);
    }

    private HttpResponseMessage Respond(string endpoint, object payload)
    {
        byte[] data = JsonSerializer.SerializeToUtf8Bytes(payload, payload.GetType(), J);
        byte[] sig = SignatureAlgorithm.Ed25519.Sign(_signKey, Crypto.SigningInput(endpoint, data));
        var env = new Envelope { Data = Convert.ToBase64String(data), Signature = Convert.ToBase64String(sig) };
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(env, env.GetType(), J);
        return new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
    }

    private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _signKey.Dispose(); }
        base.Dispose(disposing);
    }
}

public class ClientTests
{
    private static RudeAuthClient NewClient(MockServer mock, Func<IReadOnlyList<string>>? collect = null)
    {
        var opts = new RudeAuthClientOptions
        {
            Handler = mock,
            Collect = collect ?? (() => new List<string> { "test:cpu", "test:disk" }),
            Label = () => "test-box",
        };
        return new RudeAuthClient("app-uuid", mock.PublicKeyB64, "https://server.test", opts);
    }

    [Fact]
    public void AuthenticateAndGating()
    {
        using var mock = new MockServer();
        using RudeAuthClient client = NewClient(mock);

        using Session sess = client.Authenticate("RUDE-XXXX");
        Assert.Equal(1, sess.Info.MaxDevices);
        Assert.Equal(1, sess.Info.Level);
        Assert.Equal("0x4A1F", sess.Variable("offset"));
        Assert.Equal("core-dll-bytes", Encoding.UTF8.GetString(sess.File("core.dll")));
    }

    [Fact]
    public void RejectsForgedSignature()
    {
        using var mock = new MockServer();
        using Key other = Key.Create(SignatureAlgorithm.Ed25519,
            new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        string otherPub = Convert.ToBase64String(other.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        var opts = new RudeAuthClientOptions { Handler = mock, Collect = () => new List<string> { "a", "b" } };
        using var client = new RudeAuthClient("app", otherPub, "https://server.test", opts);

        RudeAuthException ex = Assert.Throws<RudeAuthException>(() => client.Authenticate("k"));
        Assert.Equal(ErrorCode.SignatureInvalid, ex.Code);
    }

    [Fact]
    public void MapsLicenceError()
    {
        using var mock = new MockServer { FailCode = "LICENSE_EXPIRED" };
        using RudeAuthClient client = NewClient(mock);

        RudeAuthException ex = Assert.Throws<RudeAuthException>(() => client.Authenticate("k"));
        Assert.Equal(ErrorCode.LicenseExpired, ex.Code);
    }

    [Fact]
    public void RefusesWeakFingerprint()
    {
        using var mock = new MockServer();
        using RudeAuthClient client = NewClient(mock, () => new List<string> { "only-one" });

        Assert.Throws<RudeAuthException>(() => client.Authenticate("k"));
    }
}
