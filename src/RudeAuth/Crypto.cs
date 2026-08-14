using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace RudeAuth;

// Crypto mirrors the server's internal/crypto exactly. These are protocol
// constants and constructions, not tunables: the known-answer vectors catch any
// drift from what the server actually produces.
//
// Only the lowest-common-denominator BCL APIs are used, so the library compiles
// for both net8.0 and netstandard2.0 (the latter reaching .NET Framework and Unity).
internal static class Crypto
{
    private const string SigPrefix = "rudeauth-v1:";
    private static readonly byte[] HkdfSalt = Encoding.ASCII.GetBytes("rudeauth-v1-session");

    // SigningInput builds "rudeauth-v1:<endpoint>:" || sha256(data), the exact
    // message the server signs.
    internal static byte[] SigningInput(string endpoint, byte[] data)
    {
        byte[] sum;
        using (var sha = SHA256.Create())
        {
            sum = sha.ComputeHash(data);
        }
        byte[] prefix = Encoding.ASCII.GetBytes(SigPrefix + endpoint + ":");
        byte[] msg = new byte[prefix.Length + sum.Length];
        Buffer.BlockCopy(prefix, 0, msg, 0, prefix.Length);
        Buffer.BlockCopy(sum, 0, msg, prefix.Length, sum.Length);
        return msg;
    }

    // Verify checks a response signature against the pinned public key, over the
    // exact bytes received. Every response passes this before any field is trusted.
    internal static bool Verify(byte[] pub, string endpoint, byte[] data, byte[] sig)
    {
        if (pub.Length != 32 || sig.Length != 64)
        {
            return false;
        }
        SignatureAlgorithm alg = SignatureAlgorithm.Ed25519;
        PublicKey key;
        try
        {
            key = PublicKey.Import(alg, pub, KeyBlobFormat.RawPublicKey);
        }
        catch (FormatException)
        {
            return false;
        }
        return alg.Verify(key, SigningInput(endpoint, data), sig);
    }

    // DeriveSessionKey performs X25519 then HKDF-SHA256 with the fixed salt and
    // the session id as info, matching the server. X25519 rejects low-order
    // points, which stops an attacker forcing a known all-zero shared secret.
    internal static byte[] DeriveSessionKey(byte[] ourPriv, byte[] theirPub, string sessionId)
    {
        KeyAgreementAlgorithm x = KeyAgreementAlgorithm.X25519;
        using Key priv = Key.Import(x, ourPriv, KeyBlobFormat.RawPrivateKey);
        PublicKey pub = PublicKey.Import(x, theirPub, KeyBlobFormat.RawPublicKey);
        using SharedSecret shared = x.Agree(priv, pub)
            ?? throw new CryptographicException("rudeauth: X25519 agreement failed");
        byte[] info = Encoding.UTF8.GetBytes(sessionId);
        return KeyDerivationAlgorithm.HkdfSha256.DeriveBytes(shared, HkdfSalt, info, 32);
    }

    // OpenSealed reverses the server's XChaCha20-Poly1305 sealing: the 24-byte
    // nonce is prepended, so a sealed blob is nonce || ciphertext || tag. Returns
    // null if authentication fails (wrong key, tampering, or wrong AAD).
    internal static byte[]? OpenSealed(byte[] sessionKey, byte[] blob, byte[] aad)
    {
        AeadAlgorithm alg = AeadAlgorithm.XChaCha20Poly1305;
        int ns = alg.NonceSize; // 24
        if (blob.Length < ns)
        {
            return null;
        }
        using Key key = Key.Import(alg, sessionKey, KeyBlobFormat.RawSymmetricKey);
        var nonce = new ReadOnlySpan<byte>(blob, 0, ns);
        var ciphertext = new ReadOnlySpan<byte>(blob, ns, blob.Length - ns);
        try
        {
            return alg.Decrypt(key, nonce, aad, ciphertext);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    // Ephemeral returns a fresh X25519 keypair for one handshake, as raw bytes.
    internal static (byte[] Pub, byte[] Priv) Ephemeral()
    {
        KeyAgreementAlgorithm x = KeyAgreementAlgorithm.X25519;
        var creation = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        using Key key = Key.Create(x, creation);
        byte[] priv = key.Export(KeyBlobFormat.RawPrivateKey);
        byte[] pub = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        return (pub, priv);
    }

    // RandomNonce returns 32 fresh bytes for a handshake client nonce.
    internal static byte[] RandomNonce()
    {
        byte[] n = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(n);
        }
        return n;
    }
}
