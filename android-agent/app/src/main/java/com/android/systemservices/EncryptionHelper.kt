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

object EncryptionHelper {
    private const val TAG = "EncryptionHelper"

    // Server static EC P-256 public key (base64 DER SPKI).
    // Matches the sentinel_enc_private_key Docker secret on the server.
    private const val SERVER_PUB_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEopTU5SdW9VyKkYZLUU9rtMu3X81D" +
        "+nnkEkzwQHXHU+64I4RuShEn7yi3eXX/E9TQoIsxFb6OIqXjwLV/4KW4AA=="

    @Volatile private var sessionKey: ByteArray? = null
    private var ephemeralPrivKey: java.security.PrivateKey? = null

    // Generates ephemeral EC P-256 key pair. Returns base64 SPKI of public key.
    fun generateEphemeralKey(): String {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        ephemeralPrivKey = kp.private
        return Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
    }

    // ECDH(ephemeral_priv, server_static_pub) → HKDF-SHA256 → 16-byte AES-128 key.
    fun deriveKey(): Boolean {
        val priv = ephemeralPrivKey ?: return false
        return try {
            val serverPub = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(Base64.decode(SERVER_PUB_B64, Base64.NO_WRAP)))
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(priv)
            ka.doPhase(serverPub, true)
            val raw = ka.generateSecret()
            sessionKey = hkdf(raw, "SentinelMDM-v1".toByteArray(Charsets.UTF_8), 16)
            ephemeralPrivKey = null
            true
        } catch (e: Exception) {
            Log.e(TAG, "deriveKey: ${e.message}")
            false
        }
    }

    fun clearSession() {
        sessionKey = null
        ephemeralPrivKey = null
    }

    fun isReady() = sessionKey != null

    // Encrypt {ev, d} → JSONObject { "d": base64(iv12 || ciphertext || tag16) }
    fun encrypt(eventName: String, eventData: JSONObject): JSONObject? {
        val key = sessionKey ?: return null
        return try {
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val plain = JSONObject().apply {
                put("ev", eventName)
                put("d", eventData)
            }.toString().toByteArray(Charsets.UTF_8)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            // doFinal returns ciphertext + 16-byte GCM tag
            val ct = cipher.doFinal(plain)
            JSONObject().apply { put("d", Base64.encodeToString(iv + ct, Base64.NO_WRAP)) }
        } catch (e: Exception) {
            Log.e(TAG, "encrypt: ${e.message}")
            null
        }
    }

    // Decrypt incoming `e` event → Pair(eventName, JSONObject) or null on auth failure.
    fun decrypt(wrapper: JSONObject): Pair<String, JSONObject>? {
        val key = sessionKey ?: return null
        return try {
            val combined = Base64.decode(wrapper.getString("d"), Base64.NO_WRAP)
            if (combined.size < 29) return null   // min: iv(12) + 1 byte + tag(16)
            val iv = combined.sliceArray(0..11)
            val ct = combined.sliceArray(12 until combined.size)  // ciphertext + tag
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            val plain = JSONObject(String(cipher.doFinal(ct), Charsets.UTF_8))
            plain.getString("ev") to plain.getJSONObject("d")
        } catch (e: Exception) {
            Log.e(TAG, "decrypt: ${e.message}")
            null
        }
    }

    // RFC 5869 HKDF-SHA256: zero-byte salt, variable info, outLen bytes output.
    private fun hkdf(ikm: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        val prk = hmac(ByteArray(32), ikm)   // extract: HMAC-SHA256(salt=0x00…, IKM)
        val out = ByteArray(outLen)
        var t = ByteArray(0)
        var offset = 0; var i = 1
        while (offset < outLen) {
            t = hmac(prk, t + info + byteArrayOf(i.toByte()))
            val n = minOf(t.size, outLen - offset)
            t.copyInto(out, offset, 0, n)
            offset += n; i++
        }
        return out
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
