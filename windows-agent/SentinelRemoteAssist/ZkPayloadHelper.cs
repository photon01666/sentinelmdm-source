using System.Security.Cryptography;
using System.Text;

namespace SentinelRemoteAssist;

/// <summary>
/// Zero-knowledge envelope encryption for private telemetry — C# port of the Android agent's
/// ZkPayloadHelper.kt, byte-for-byte compatible wire format (the browser's zkDecryptRow() has no
/// idea which platform produced a given zk_data blob, and doesn't need to).
///
/// Encryption scheme per event (identical to ZkPayloadHelper.kt):
///   1. Generate 256-bit random DEK
///   2. AES-256-GCM encrypt plaintext JSON with DEK  ->  (iv12 || ct || tag16)
///   3. Generate ephemeral EC P-256 key pair
///   4. ECDH(ephemeral_priv, owner_pub)  ->  shared_secret (raw X-coordinate, no KDF)
///   5. HKDF-SHA256(shared_secret, salt=32 zero bytes, info="sentinel-dek-wrap", 32 bytes) -> wrap_key
///   6. AES-256-GCM encrypt DEK with wrap_key  ->  (dek_iv12 || dek_ct || dek_tag16)
///
/// Wire format (sent as the "zk_data" Socket.IO event — see server.js's socket.on('zk_data', ...)):
///   { zk: true, event: "&lt;name&gt;", payload: "&lt;b64(iv12||ct||tag16)&gt;",
///     dek_wrapped: { eph_pub, iv, ct } }
///
/// Cross-verified against Android's manual HMAC-based HKDF (RFC 5869, zero-filled salt) on this
/// exact .NET version — System.Security.Cryptography.HKDF.DeriveKey(..., salt: null, ...) produces
/// byte-identical output, since RFC 5869 defines a null/empty salt as HashLen zero bytes.
/// </summary>
internal sealed class ZkPayloadHelper
{
    private readonly ECDiffieHellman _ownerPublicKey;

    public ZkPayloadHelper(string ownerPubKeyB64)
    {
        var spki = Convert.FromBase64String(ownerPubKeyB64);
        _ownerPublicKey = ECDiffieHellman.Create();
        _ownerPublicKey.ImportSubjectPublicKeyInfo(spki, out _);
    }

    /// <summary>Encrypts <paramref name="plaintextJson"/> under the owner's EC P-256 public key.
    /// Returns null on ANY crypto failure — per the ZK Security invariant, the caller MUST drop
    /// the event on a null return, never fall back to sending it in plaintext.</summary>
    public object? Wrap(string eventName, string plaintextJson)
    {
        try
        {
            // 1. 256-bit DEK
            var dek = RandomNumberGenerator.GetBytes(32);

            // 2. AES-256-GCM encrypt plaintext with DEK
            var payloadIv = RandomNumberGenerator.GetBytes(12);
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintextJson);
            var payloadCt = new byte[plaintextBytes.Length];
            var payloadTag = new byte[16];
            using (var aes = new AesGcm(dek, 16))
                aes.Encrypt(payloadIv, plaintextBytes, payloadCt, payloadTag);
            // Final blob: iv12 || ciphertext || tag16 (matches Android's iv ++ (ct-with-appended-tag))
            var payloadBlob = new byte[12 + payloadCt.Length + 16];
            Buffer.BlockCopy(payloadIv, 0, payloadBlob, 0, 12);
            Buffer.BlockCopy(payloadCt, 0, payloadBlob, 12, payloadCt.Length);
            Buffer.BlockCopy(payloadTag, 0, payloadBlob, 12 + payloadCt.Length, 16);

            // 3. Ephemeral EC P-256 key pair
            using var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

            // 4. ECDH: ephemeral private x owner public -> raw shared secret
            var sharedSecret = eph.DeriveRawSecretAgreement(_ownerPublicKey.PublicKey);

            // 5. HKDF-SHA256 -> 32-byte wrapping key (null salt = RFC 5869 zero-filled salt)
            var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32,
                salt: null, info: Encoding.UTF8.GetBytes("sentinel-dek-wrap"));

            // 6. AES-256-GCM encrypt DEK with wrapping key
            var dekIv = RandomNumberGenerator.GetBytes(12);
            var dekCt = new byte[dek.Length];
            var dekTag = new byte[16];
            using (var aes = new AesGcm(wrapKey, 16))
                aes.Encrypt(dekIv, dek, dekCt, dekTag);
            var dekCtWithTag = new byte[dekCt.Length + 16];
            Buffer.BlockCopy(dekCt, 0, dekCtWithTag, 0, dekCt.Length);
            Buffer.BlockCopy(dekTag, 0, dekCtWithTag, dekCt.Length, 16);

            return new
            {
                zk = true,
                @event = eventName,
                payload = Convert.ToBase64String(payloadBlob),
                dek_wrapped = new
                {
                    eph_pub = Convert.ToBase64String(eph.PublicKey.ExportSubjectPublicKeyInfo()),
                    iv = Convert.ToBase64String(dekIv),
                    ct = Convert.ToBase64String(dekCtWithTag),
                },
            };
        }
        catch
        {
            return null;
        }
    }
}
