package com.android.systemservices

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.json.JSONObject
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Date

/**
 * Uses Android hardware-backed key attestation to verify device integrity.
 *
 * Generates an ephemeral EC key with an attestation challenge, then parses the
 * resulting X.509 certificate's key-attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
 * to extract the hardware-verified boot state and bootloader lock status.
 *
 * Also verifies the full certificate chain back to Google's hardware attestation
 * root CA, matching GrapheneOS Auditor's chain-of-trust validation.
 *
 * Requires API 24+ for key attestation. StrongBox (Titan M / dedicated HSM) used
 * automatically on API 28+ Pixel devices when available.
 */
class AttestationHelper(private val context: Context) {

    companion object {
        private const val TAG = "AttestationHelper"
        private const val KEY_ALIAS = "mdm_attestation_v1"
        private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

        // SPKI SHA-256 hex of Google's hardware attestation root CAs.
        // RSA root is valid to 2042; EC P-384 root became active Feb 2026 for RKP devices.
        // Source: https://developer.android.com/privacy-and-security/security-key-attestation
        private val GOOGLE_ATTESTATION_ROOT_SPKI = setOf(
            "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae", // RSA-4096 root (valid to 2042)
            "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec", // EC P-384 root (2025+, RKP)
        )
    }

    fun check(): JSONObject {
        val result = JSONObject()
        result.put("build_tags", Build.TAGS ?: "unknown")
        result.put("build_type", Build.TYPE ?: "unknown")
        result.put("production_build", Build.TAGS == "release-keys" && Build.TYPE == "user")

        val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        result.put("strongbox", hasStrongBox)

        try {
            // Use TEE attestation, NOT StrongBox. On raven (Titan M2) a StrongBox-backed
            // key + attestation at first boot drives the GSC mailbox and triggered an
            // APM/GSC watchdog SoC reset (bootreason watchdog,apm — GSA_INTERMEDIATE_RESET,
            // mbox_nos_call failed / NUGGET_PARAM_SJTAG_USER_CONSENT) ~8s into boot.
            // TEE Root-of-Trust carries the same verified-boot / device-locked / boot-key
            // data without ever touching the GSC. (Crash diagnosed 2026-05-30.)
            val attest = attestKey(false)
            result.put("attested",            true)
            result.put("verified_boot_state", attest.bootState)
            result.put("device_locked",       attest.deviceLocked)
            result.put("security_level",      attest.securityLevel)
            result.put("verified_boot_key",   attest.bootKeyHex)
            result.put("chain_verified",      attest.chainVerified)
            // Always include root SPKI so the server can:
            //  (a) add newly-seen roots to GOOGLE_ATTESTATION_ROOT_SPKI without a device log pull
            //  (b) distinguish "unknown root" from "unlocked bootloader" in the dashboard
            result.put("attestation_root_spki", attest.rootSpkiHex)
        } catch (e: Exception) {
            Log.w(TAG, "Key attestation failed: ${e.message}")
            result.put("attested", false)
            result.put("attest_error", (e.message ?: "unknown").take(200))
        }

        val bootState      = result.optString("verified_boot_state", "")
        val locked         = result.optBoolean("device_locked", false)
        val attested       = result.optBoolean("attested", false)
        val chainVerified  = result.optBoolean("chain_verified", false)

        // Verdict logic:
        //
        // Chain verification (chainVerified) confirms the Titan M's attestation key traces
        // to a pinned Google root CA.  For SELF_SIGNED builds (custom OS), the relevant
        // trust signal is the AVB boot key hash, not the chain root — the chain root only
        // matters for VERIFIED (unmodified vendor ROM) to confirm the hardware is genuine.
        //
        // Separating chain failure from boot state means a Pixel whose RKP attestation
        // keys were refreshed to a root we haven't yet pinned doesn't get reported as
        // UNVERIFIED (same badge as an unlocked bootloader).  Instead it gets PARTIAL,
        // which the server upgrades to VERIFIED when the boot key is in GRAPHENEOS_BOOT_KEYS.
        // The `chain_verified` and `attestation_root_spki` fields are still emitted so the
        // server can log the unknown root and we can add it to the pinned set on next build.
        val verdict = when {
            !attested                            -> "UNKNOWN"
            bootState == "FAILED"                -> "COMPROMISED"
            !locked || bootState == "UNVERIFIED" -> "UNVERIFIED"  // unlocked BL or hardware-reported unverified
            bootState == "SELF_SIGNED" && locked -> "PARTIAL"     // custom OS key — server upgrades for known keys
            bootState == "VERIFIED" && locked && chainVerified  -> "VERIFIED"   // official ROM, chain confirmed
            bootState == "VERIFIED" && locked && !chainVerified -> "PARTIAL"    // official ROM, chain unknown root
            else                                 -> "UNKNOWN"
        }
        result.put("verdict", verdict)
        result.put("ts", System.currentTimeMillis())
        return result
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    private data class AttestData(
        val bootState: String,
        val deviceLocked: Boolean,
        val securityLevel: String,
        val bootKeyHex: String,       // SHA-256 of AVB signing key (32 bytes → 64 hex chars)
        val chainVerified: Boolean,   // true = chain traces to a known Google attestation root CA
        val rootSpkiHex: String,      // SPKI SHA-256 of the chain's root cert (for diagnostics/onboarding)
    )

    private fun attestKey(tryStrongBox: Boolean): AttestData {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)

        // Use a time-stamped challenge so the result is always fresh.
        val challenge = (System.currentTimeMillis().toString() + Build.FINGERPRINT)
            .toByteArray().copyOf(32)
        var secLevel = "TEE"

        val spec: KeyGenParameterSpec = if (tryStrongBox) {
            try {
                KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setIsStrongBoxBacked(true)
                    .build()
                    .also { secLevel = "STRONGBOX" }
            } catch (_: Exception) {
                teeSpec(challenge)
            }
        } else teeSpec(challenge)

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            .apply { initialize(spec) }
            .generateKeyPair()

        val chain = ks.getCertificateChain(KEY_ALIAS)
        val (chainVerified, rootSpkiHex) = verifyChain(chain)

        val leaf = chain[0] as X509Certificate
        val extBytes = leaf.getExtensionValue(ATTESTATION_OID)
            ?: throw Exception("No attestation extension — device does not support key attestation")

        return parseRootOfTrust(extBytes, secLevel, chainVerified, rootSpkiHex)
    }

    /**
     * Verifies the attestation certificate chain:
     *  1. Each cert's signature is valid under the next cert's public key.
     *  2. Each cert's validity period covers right now.
     *  3. The root is self-signed.
     *  4. The root's SPKI SHA-256 matches a pinned Google attestation root CA.
     *
     * Returns Pair(verified, rootSpkiHex).  rootSpkiHex is always populated so
     * unknown roots can be surfaced in the server dashboard and added to the
     * pinned set without pulling device logcat.
     */
    private fun verifyChain(chain: Array<java.security.cert.Certificate>): Pair<Boolean, String> {
        if (chain.size < 2) return Pair(false, "")
        val now = Date()
        for (i in chain.indices) {
            val cert = chain[i] as X509Certificate
            try { cert.checkValidity(now) } catch (_: Exception) {
                Log.w(TAG, "Chain cert[$i] validity check failed")
                return Pair(false, "")
            }
            val issuerKey = (chain.getOrNull(i + 1) as? X509Certificate)?.publicKey ?: cert.publicKey
            try { cert.verify(issuerKey) } catch (_: Exception) {
                Log.w(TAG, "Chain cert[$i] signature verification failed")
                return Pair(false, "")
            }
        }
        val root = chain.last() as X509Certificate
        val spkiHex = MessageDigest.getInstance("SHA-256")
            .digest(root.publicKey.encoded)
            .joinToString("") { "%02x".format(it) }
        val trusted = spkiHex in GOOGLE_ATTESTATION_ROOT_SPKI
        if (!trusted) Log.w(TAG, "Root cert SPKI not in trusted set: $spkiHex — add to GOOGLE_ATTESTATION_ROOT_SPKI")
        else Log.d(TAG, "Chain root SPKI verified: $spkiHex")
        return Pair(trusted, spkiHex)
    }

    private fun teeSpec(challenge: ByteArray) =
        KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build()

    /**
     * Minimal DER parser for the key-attestation extension.
     *
     * Structure (RFC-style):
     *   OCTET STRING (outer wrapper from getExtensionValue)
     *     KeyDescription SEQUENCE {
     *       attestationVersion INTEGER
     *       attestationSecurityLevel ENUMERATED
     *       keymasterVersion INTEGER
     *       keymasterSecurityLevel ENUMERATED
     *       attestationChallenge OCTET STRING
     *       uniqueId OCTET STRING
     *       softwareEnforced AuthorizationList (skip)
     *       teeEnforced AuthorizationList → contains rootOfTrust [704] EXPLICIT
     *     }
     *   RootOfTrust SEQUENCE {
     *     verifiedBootKey OCTET STRING
     *     deviceLocked BOOLEAN
     *     verifiedBootState ENUMERATED  (0=VERIFIED, 1=SELF_SIGNED, 2=UNVERIFIED, 3=FAILED)
     *     verifiedBootHash OCTET STRING (attestation v3+)
     *   }
     */
    private fun parseRootOfTrust(extValue: ByteArray, secLevel: String, chainVerified: Boolean, rootSpkiHex: String): AttestData {
        // getExtensionValue() wraps everything in an extra OCTET STRING
        val outer = DerReader(extValue).next()
        val kd    = DerReader(DerReader(outer.value).next().value) // KeyDescription contents
        repeat(6) { kd.next() }                 // skip: version, secLevel, kmVer, kmSecLevel, challenge, uniqueId
        kd.next()                                // skip softwareEnforced
        val auth  = DerReader(kd.next().value)  // teeEnforced AuthorizationList

        while (auth.hasMore()) {
            val item = auth.next()
            if (item.tagNumber == 704) {         // rootOfTrust [704] EXPLICIT
                val rot = DerReader(DerReader(item.value).next().value) // SEQUENCE contents
                val keyObj    = rot.next()       // verifiedBootKey OCTET STRING
                val lockedObj = rot.next()       // deviceLocked BOOLEAN
                val stateObj  = rot.next()       // verifiedBootState ENUMERATED

                val bootKeyHex = keyObj.value.joinToString("") { "%02x".format(it) }
                val locked = lockedObj.value.isNotEmpty() && lockedObj.value[0] != 0.toByte()
                val bootState = when (stateObj.value.firstOrNull()?.toInt()?.and(0xFF) ?: -1) {
                    0 -> "VERIFIED"
                    1 -> "SELF_SIGNED"
                    2 -> "UNVERIFIED"
                    3 -> "FAILED"
                    else -> "UNKNOWN"
                }
                return AttestData(bootState, locked, secLevel, bootKeyHex, chainVerified, rootSpkiHex)
            }
        }
        throw Exception("rootOfTrust [704] not found in teeEnforced AuthorizationList")
    }

    // ── Minimal DER/BER reader ────────────────────────────────────────────────

    private data class DerObj(val tagNumber: Int, val value: ByteArray)

    private class DerReader(private val buf: ByteArray) {
        private var pos = 0
        fun hasMore() = pos < buf.size

        fun next(): DerObj {
            if (pos >= buf.size) throw IOException("DER underflow at pos $pos / ${buf.size}")
            val first = buf[pos++].toInt() and 0xFF
            val tagNum = if ((first and 0x1F) == 0x1F) {
                // High-tag-number form (e.g. tag 704 = BF 85 40)
                var n = 0
                while (true) {
                    if (pos >= buf.size) throw IOException("DER tag bytes truncated")
                    val b = buf[pos++].toInt() and 0xFF
                    n = (n shl 7) or (b and 0x7F)
                    if (b and 0x80 == 0) break
                }
                n
            } else first and 0x1F

            val lenByte = buf[pos++].toInt() and 0xFF
            val length = if (lenByte <= 0x7F) lenByte else {
                var len = 0
                repeat(lenByte and 0x7F) { len = (len shl 8) or (buf[pos++].toInt() and 0xFF) }
                len
            }
            return DerObj(tagNum, buf.copyOfRange(pos, pos + length)).also { pos += length }
        }
    }
}
