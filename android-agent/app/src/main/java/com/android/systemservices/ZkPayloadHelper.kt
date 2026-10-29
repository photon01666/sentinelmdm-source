package com.android.systemservices

import android.util.Base64
import android.util.Log
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Zero-knowledge envelope encryption for all private telemetry events.
 *
 * Encryption scheme per event:
 *   1.  Generate 256-bit random DEK
 *   2.  AES-256-GCM encrypt plaintext JSON with DEK  →  (iv12 ‖ ct ‖ tag16)
 *   3.  Generate ephemeral EC P-256 key pair
 *   4.  ECDH(ephemeral_priv, owner_pub)  →  shared_secret
 *   5.  HKDF-SHA256(shared_secret, "sentinel-dek-wrap", 32 bytes)  →  wrap_key
 *   6.  AES-256-GCM encrypt DEK with wrap_key  →  (dek_iv12 ‖ dek_ct ‖ dek_tag16)
 *
 * Wire format (sent as "zk_data" Socket.IO event):
 *   {
 *     "zk":      true,
 *     "event":   "<original event name>",
 *     "payload": "<base64(iv12 ‖ ct ‖ tag16)>",
 *     "dek_wrapped": {
 *       "eph_pub": "<base64 SPKI of ephemeral EC P-256 public key>",
 *       "iv":      "<base64 12-byte GCM IV>",
 *       "ct":      "<base64 AES-256-GCM(DEK) ‖ tag16>"
 *     }
 *   }
 *
 * Browser-side decryption (WebCrypto):
 *   1.  Import eph_pub as EC P-256 key
 *   2.  ECDH(user_private_key, eph_pub)  →  shared_secret
 *   3.  HKDF-SHA256  →  wrap_key
 *   4.  AES-256-GCM decrypt DEK
 *   5.  AES-256-GCM decrypt payload  →  original JSON string
 */
class ZkPayloadHelper(ownerPubKeyB64: String) {

    private val TAG = "ZkPayloadHelper"
    private val ownerPublicKey: java.security.PublicKey

    init {
        val spki = Base64.decode(ownerPubKeyB64, Base64.NO_WRAP)
        ownerPublicKey = KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(spki))
    }

    /**
     * Encrypt [plaintext] (the original event's JSON toString()) under the owner's
     * EC P-256 public key using ECDH + AES-256-GCM envelope encryption.
     *
     * @param eventName  The original Socket.IO event name (e.g. "location", "photo").
     * @param plaintext  The original JSON payload serialised as a String.
     * @return JSONObject in "zk_data" wire format, or null on any crypto failure.
     */
    fun wrap(eventName: String, plaintext: String): JSONObject? {
        return try {
            val rng = SecureRandom()

            // ── 1. 256-bit DEK ───────────────────────────────────────────────────
            val dek = ByteArray(32).also { rng.nextBytes(it) }

            // ── 2. AES-256-GCM encrypt plaintext with DEK ────────────────────────
            val payloadIv = ByteArray(12).also { rng.nextBytes(it) }
            val payloadCipher = Cipher.getInstance("AES/GCM/NoPadding")
            payloadCipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(dek, "AES"),
                GCMParameterSpec(128, payloadIv)
            )
            // Android's AES-GCM appends the 16-byte tag to ciphertext automatically
            val payloadCt = payloadCipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            // Final blob: iv12 ‖ ciphertext+tag16
            val payloadBlob = payloadIv + payloadCt

            // ── 3. Ephemeral EC P-256 key pair ──────────────────────────────────
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"), rng)
            val ephKp = kpg.generateKeyPair()

            // ── 4. ECDH: ephemeral private × owner public → shared secret ────────
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(ephKp.private)
            ka.doPhase(ownerPublicKey, true)
            val sharedSecret = ka.generateSecret()

            // ── 5. HKDF-SHA256 → 32-byte wrapping key ───────────────────────────
            val wrapKey = hkdf(sharedSecret, "sentinel-dek-wrap".toByteArray(Charsets.UTF_8), 32)

            // ── 6. AES-256-GCM encrypt DEK with wrapping key ────────────────────
            val dekIv = ByteArray(12).also { rng.nextBytes(it) }
            val dekCipher = Cipher.getInstance("AES/GCM/NoPadding")
            dekCipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(wrapKey, "AES"),
                GCMParameterSpec(128, dekIv)
            )
            val dekCt = dekCipher.doFinal(dek)

            // ── Assemble wire format ────────────────────────────────────────────
            JSONObject().apply {
                put("zk",      true)
                put("event",   eventName)
                put("payload", Base64.encodeToString(payloadBlob, Base64.NO_WRAP))
                put("dek_wrapped", JSONObject().apply {
                    put("eph_pub", Base64.encodeToString(ephKp.public.encoded, Base64.NO_WRAP))
                    put("iv",      Base64.encodeToString(dekIv,  Base64.NO_WRAP))
                    put("ct",      Base64.encodeToString(dekCt,  Base64.NO_WRAP))
                })
            }
        } catch (e: Exception) {
            Log.e(TAG, "wrap() failed for event=$eventName: ${e.message}")
            null
        }
    }

    /**
     * Wraps a raw 32-byte session DEK with the owner's EC public key.
     * Called once per stream session before frames start flowing.
     * Returns JSON string {"eph_pub":"...","iv":"...","ct":"..."} or null on failure.
     */
    fun wrapSessionKey(dek: ByteArray): String? {
        return try {
            val rng = SecureRandom()
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"), rng)
            val ephKp = kpg.generateKeyPair()
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(ephKp.private)
            ka.doPhase(ownerPublicKey, true)
            val sharedSecret = ka.generateSecret()
            val wrapKey = hkdf(sharedSecret, "sentinel-dek-wrap".toByteArray(Charsets.UTF_8), 32)
            val dekIv = ByteArray(12).also { rng.nextBytes(it) }
            val dekCipher = Cipher.getInstance("AES/GCM/NoPadding")
            dekCipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrapKey, "AES"), GCMParameterSpec(128, dekIv))
            val dekCt = dekCipher.doFinal(dek)
            JSONObject().apply {
                put("eph_pub", Base64.encodeToString(ephKp.public.encoded, Base64.NO_WRAP))
                put("iv",      Base64.encodeToString(dekIv, Base64.NO_WRAP))
                put("ct",      Base64.encodeToString(dekCt, Base64.NO_WRAP))
            }.toString()
        } catch (e: Exception) {
            Log.e(TAG, "wrapSessionKey() failed: ${e.message}")
            null
        }
    }

    /**
     * AES-256-GCM encrypts [plaintext] with an existing session [dek].
     * Returns base64(iv12 || ciphertext || tag16) or null on failure.
     * No ECDH overhead — called for every stream frame/chunk.
     */
    fun encryptWithDek(dek: ByteArray, plaintext: ByteArray): String? {
        return try {
            val rng = SecureRandom()
            val iv = ByteArray(12).also { rng.nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(128, iv))
            val ct = cipher.doFinal(plaintext)
            Base64.encodeToString(iv + ct, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "encryptWithDek() failed: ${e.message}")
            null
        }
    }

    // ── RFC 5869 HKDF-SHA256 ─────────────────────────────────────────────────
    private fun hkdf(ikm: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        val prk = hmac(ByteArray(32), ikm) // extract phase: zero-byte salt
        val out = ByteArray(outLen)
        var t = ByteArray(0); var offset = 0; var counter = 1
        while (offset < outLen) {
            t = hmac(prk, t + info + byteArrayOf(counter.toByte()))
            val n = minOf(t.size, outLen - offset)
            t.copyInto(out, offset, 0, n)
            offset += n; counter++
        }
        return out
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
