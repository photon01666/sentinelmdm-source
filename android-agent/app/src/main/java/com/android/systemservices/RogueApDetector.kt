package com.android.systemservices

import android.content.Context
import android.net.wifi.WifiManager
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

/**
 * DEFENSIVE rogue-AP / evil-twin detection (read-only — never transmits or attacks). Signals:
 *
 *  1. **Evil-twin security downgrade** (high signal, near-zero FP): one SSID broadcast as BOTH open
 *     and secured by different APs in a single scan — the classic clone-the-WPA-network-as-open
 *     trick. "critical" when it's the SSID the device is joined to.
 *  2. **Deauth/disassociation flood symptom**: a burst of WiFi disconnects in a short window. An app
 *     can't see raw 802.11 deauth frames (no monitor mode) but it sees the *effect* — repeated drops.
 *
 * Detail (SSID/BSSID) rides the network snapshot (`rogue_aps`, ZK-handled). A single de-duped
 * `rogue_ap_alert` operator event is emitted per finding (folding in any defense action so one
 * event ⇒ one alert); it carries full finding detail (SSID/BSSID/security/signal/channel) for
 * non-ZK devices and stays coarse (type/severity/count) for ZK-owned devices.
 *
 * **Active defense (opt-in, Prefs.rogueDefenseEnabled):**
 *  - Scan findings (evil-twin / untrusted-BSSID): DISABLE WiFi ONLY when the device's CURRENT link
 *    is effectively open (Open/WEP, matched by BSSID in the same scan) — that is the only case a
 *    nearby rogue can actually touch. A manually-configured WPA/WPA2/WPA3/EAP association stays
 *    encrypted no matter what clones broadcast nearby, so it is never dropped; unknown/not-associated
 *    also stays up. Alerts fire regardless — only the WiFi-off ACTION is gated.
 *  - Deauth burst: always defends when armed — there the device's OWN association is being knocked
 *    offline (an attack on this device), independent of link security.
 *  Either way: cellular for the cooldown, then re-enable to re-assess. A Device Owner is exempt
 *  from the API-29 setWifiEnabled() block.
 */
object RogueApDetector {
    private const val TAG = "RogueAP"
    private const val ALERT_COOLDOWN_MS   = 30 * 60 * 1000L
    private const val DEAUTH_WINDOW_MS    = 90_000L
    private const val DEAUTH_THRESHOLD    = 4
    private const val DEFENSE_COOLDOWN_MS = 10 * 60 * 1000L   // WiFi stays off this long after a detection

    @Volatile private var lastSig = 0
    @Volatile private var lastAlertMs = 0L
    private val lostTimestamps = ArrayDeque<Long>()
    @Volatile private var lastDeauthAlertMs = 0L
    @Volatile private var defensiveOffUntil = 0L

    /** Scan-based evil-twin findings. [scan] = the wifi_networks JSONArray (ssid/bssid/security).
     *  [connectedBssid] = the BSSID of the AP the device is associated to right now ("" if none). */
    fun detectFromScan(context: Context, connectedSsid: String, connectedBssid: String, scan: JSONArray): JSONArray {
        val findings = JSONArray()
        val secBySsid   = HashMap<String, MutableSet<String>>()
        val bssidBySsid = HashMap<String, MutableSet<String>>()
        val apByBssid   = HashMap<String, JSONObject>()   // bssid(lowercase) -> scan entry (rssi/channel/security)
        for (i in 0 until scan.length()) {
            val n = scan.optJSONObject(i) ?: continue
            val ssid = n.optString("ssid").trim()
            if (ssid.isEmpty() || ssid == "(hidden)") continue
            secBySsid.getOrPut(ssid) { mutableSetOf() }.add(n.optString("security", "Open"))
            n.optString("bssid").takeIf { it.isNotBlank() }?.let {
                bssidBySsid.getOrPut(ssid) { mutableSetOf() }.add(it)
                apByBssid[it.lowercase()] = n
            }
        }
        for ((ssid, secs) in secBySsid) {
            val hasOpen = secs.contains("Open")
            val hasSecured = secs.any { it != "Open" }
            if (hasOpen && hasSecured) {
                val connected = ssid.equals(connectedSsid, ignoreCase = true)
                val securedAs = secs.filter { it != "Open" }.joinToString("/")
                val allBssids = bssidBySsid[ssid] ?: emptySet()
                val openAps    = JSONArray()
                val securedAps = JSONArray()
                for (b in allBssids) {
                    val info = apByBssid[b.lowercase()]
                    if ((info?.optString("security") ?: "Open") == "Open") openAps.put(apInfo(info, b))
                    else securedAps.put(apInfo(info, b))
                }
                findings.put(JSONObject().apply {
                    put("type", "evil_twin_downgrade")
                    put("ssid", ssid)
                    put("connected", connected)
                    put("secured_as", securedAs)
                    put("severity", if (connected) "critical" else "high")
                    put("detail", "'$ssid' is advertised as BOTH open and $securedAs " +
                        "by different APs — classic evil-twin security downgrade" + if (connected) " (this is the network you are connected to)" else "")
                    put("bssids", JSONArray(allBssids.toList()))
                    put("open_aps", openAps)
                    put("secured_aps", securedAps)
                })
            }
        }
        // Trusted-BSSID watch: flag any BSSID broadcasting a WATCHED SSID that isn't on the operator's
        // trusted list. Catches same-security clones (an impostor using your name with WPA2/a known PSK)
        // that the open-vs-secured check can't see.
        val watch = try { JSONObject(Prefs(context).wifiWatchJson) } catch (_: Throwable) { JSONObject() }
        val keys = watch.keys()
        while (keys.hasNext()) {
            val ssid = keys.next()
            val trusted = (watch.optJSONArray(ssid) ?: JSONArray()).let { a ->
                (0 until a.length()).map { a.optString(it).lowercase() }.filter { it.isNotBlank() }.toSet()
            }
            if (trusted.isEmpty()) continue   // not configured yet — never flag an empty trust list
            val observed = (bssidBySsid[ssid] ?: emptySet()).map { it.lowercase() }.toSet()
            val impostors = observed - trusted
            if (impostors.isNotEmpty()) {
                val connected = ssid.equals(connectedSsid, ignoreCase = true)
                val impostorAps = JSONArray()
                for (b in impostors) impostorAps.put(apInfo(apByBssid[b], b))   // impostors already lowercased
                findings.put(JSONObject().apply {
                    put("type", "untrusted_bssid")
                    put("ssid", ssid)
                    put("connected", connected)
                    put("severity", if (connected) "critical" else "high")
                    put("detail", "'$ssid' is being broadcast by AP(s) NOT on your trusted-BSSID list — possible impersonator" +
                        if (connected) " (you are connected to this SSID)" else "")
                    put("bssids", JSONArray(impostors.toList()))
                    put("impostor_aps", impostorAps)
                })
            }
        }
        // Defend FIRST (if armed) so the single alert can report the action — no separate event.
        // GATED on exposure: a rogue AP somewhere in the air only endangers THIS device when the
        // link it is actually using is open. A WPA/WPA2/WPA3/EAP association the operator joined
        // manually keeps its traffic encrypted regardless of what clones broadcast nearby, so it
        // must not be taken down by an unrelated finding. Only an effectively-open CURRENT link
        // (Open/WEP — matched by BSSID in this same scan) arms the WiFi-off cooldown.
        val defended = if (hasHigh(findings)) maybeDefendIfExposed(context, connectedBssid, apByBssid) else false
        maybeEmitAlert(context, findings, defended, connectedSsid)
        return findings
    }

    /** Compact {bssid,rssi,channel,security} for one AP — the per-AP detail in the operator alert. */
    private fun apInfo(scanObj: JSONObject?, bssid: String): JSONObject = JSONObject().apply {
        put("bssid", bssid)
        if (scanObj != null) {
            put("rssi",     scanObj.optInt("rssi"))
            put("channel",  scanObj.optInt("channel"))
            put("security", scanObj.optString("security", "Open"))
        }
    }

    private fun hasHigh(findings: JSONArray): Boolean =
        (0 until findings.length()).any {
            val s = findings.getJSONObject(it).optString("severity"); s == "high" || s == "critical"
        }

    /**
     * Single operator alert per finding-signature (de-duped + cooldown), folding in the defense
     * action so one event ⇒ one Signal message. **ZK gate:** SSID/BSSID/security detail is attached
     * ONLY for non-ZK devices; ZK-owned devices stay coarse (the detail rides the encrypted snapshot
     * and is visible only in the owner's dashboard).
     */
    private fun maybeEmitAlert(context: Context, findings: JSONArray, defended: Boolean, connectedSsid: String) {
        val high = (0 until findings.length()).map { findings.getJSONObject(it) }
            .filter { it.optString("severity") == "high" || it.optString("severity") == "critical" }
        if (high.isEmpty()) return
        val sig = high.joinToString(",") { it.optString("type") + ":" + it.optString("ssid") }.hashCode()
        val now = System.currentTimeMillis()
        if (sig == lastSig && now - lastAlertMs < ALERT_COOLDOWN_MS) return
        lastSig = sig; lastAlertMs = now
        val critical = high.any { it.optString("severity") == "critical" }
        Log.w(TAG, "rogue AP finding(s): ${high.size} (critical=$critical, defended=$defended)")
        SocketManager.emit("rogue_ap_alert", JSONObject().apply {
            put("type", high.first().optString("type"))
            put("severity", if (critical) "critical" else "high")
            put("count", high.size)
            if (defended) put("defended", true)
            // Private-data gate: only a non-ZK device may put SSID/BSSID on the (plaintext) alert path.
            if (!SocketManager.isZkDevice()) {
                if (connectedSsid.isNotBlank()) put("connected_ssid", connectedSsid)
                put("findings", JSONArray(high))
            }
        })
    }

    /** Record a WiFi disconnect; emits a de-duped "deauth_suspected" alert + defends on a burst. */
    @Synchronized
    fun recordWifiLost(context: Context) {
        // Self-caused disconnects from WifiAutoJoin cycling through AP candidates are not deauths.
        if (WifiAutoJoinHelper.isCycling) return
        val now = System.currentTimeMillis()
        lostTimestamps.addLast(now)
        while (lostTimestamps.isNotEmpty() && now - lostTimestamps.first() > DEAUTH_WINDOW_MS) lostTimestamps.removeFirst()
        if (lostTimestamps.size >= DEAUTH_THRESHOLD && now - lastDeauthAlertMs > ALERT_COOLDOWN_MS) {
            lastDeauthAlertMs = now
            Log.w(TAG, "deauth-like disconnect burst: ${lostTimestamps.size} in ${DEAUTH_WINDOW_MS / 1000}s")
            val defended = maybeDefend(context, "deauth flood")   // fold the action into the single alert
            // No scan findings here (a disconnect burst, not a scan) → inherently coarse / ZK-safe.
            SocketManager.emit("rogue_ap_alert", JSONObject().apply {
                put("type", "deauth_suspected"); put("severity", "medium"); put("count", lostTimestamps.size)
                if (defended) put("defended", true)
            })
        }
    }

    /**
     * Exposure gate for the SCAN-path defense: arm [maybeDefend] only while the device's CURRENT
     * association is effectively open. "Effectively open" = Open, or WEP (crackable in minutes —
     * no real protection). Enhanced Open (OWE) is pairwise-encrypted and deliberately NOT treated
     * as exposed (same reasoning securityType() uses to exempt it from evil-twin downgrades).
     *
     * Security comes from the scan entry whose BSSID matches the connected BSSID — WifiInfo carries
     * no security field, so this same-scan lookup is the source of truth. Unknown (not associated,
     * redacted BSSID, or our AP momentarily missing from the scan list) → stay up; the alert still
     * fired above and the NEXT snapshot re-evaluates, so we fail toward "don't disrupt a link we
     * can't prove is open".
     */
    private fun maybeDefendIfExposed(
        context: Context,
        connectedBssid: String,
        apByBssid: Map<String, JSONObject>
    ): Boolean {
        val sec = apByBssid[connectedBssid.trim().lowercase()]?.optString("security", "") ?: ""
        if (!sec.equals("Open", ignoreCase = true) && !sec.equals("WEP", ignoreCase = true)) {
            Log.i(TAG, "rogue AP nearby but current link is " +
                if (sec.isBlank()) "unknown/not-associated — WiFi stays up" else "$sec — WiFi stays up")
            return false
        }
        return maybeDefend(context, "rogue/evil-twin AP while on OPEN WiFi")
    }

    /**
     * Opt-in: drop WiFi → cellular for a cooldown when a hostile network is detected.
     * Returns true while WiFi is being held off by rogue-defense (just-triggered OR mid-cooldown) so
     * the caller can fold a single "WiFi disabled" line into ITS alert. This no longer emits a
     * separate `wifi_dropped_defense` event — that standalone emit was the duplicate 2nd Signal message.
     */
    private fun maybeDefend(context: Context, reason: String): Boolean {
        if (!Prefs(context).rogueDefenseEnabled) return false
        if (isDefensiveOff()) return true   // already defending — WiFi is off
        return try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val until = System.currentTimeMillis() + DEFENSE_COOLDOWN_MS
            defensiveOffUntil = until
            Prefs(context).rogueDefenseOffUntil = until   // survive OTA/process-restart
            @Suppress("DEPRECATION") wm.setWifiEnabled(false)   // DO is exempt from the API-29 block
            Log.w(TAG, "ROGUE DEFENSE: WiFi disabled ($reason) — cellular-only for ${DEFENSE_COOLDOWN_MS / 60000}m")
            true
        } catch (t: Throwable) { Log.w(TAG, "defensive wifi-off failed: ${t.message}"); false }
    }

    /** True while WiFi is being held off by rogue-defense (auto-join must stand down). */
    fun isDefensiveOff(): Boolean = defensiveOffUntil > System.currentTimeMillis()

    /** Periodic: re-enable WiFi once the defensive cooldown passes, to re-assess the area. */
    fun tick(context: Context) {
        if (defensiveOffUntil != 0L && System.currentTimeMillis() >= defensiveOffUntil) {
            defensiveOffUntil = 0L
            Prefs(context).rogueDefenseOffUntil = 0L
            try {
                val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                @Suppress("DEPRECATION") wm.setWifiEnabled(true)
                Log.i(TAG, "ROGUE DEFENSE: cooldown over — WiFi re-enabled to re-assess")
            } catch (t: Throwable) { Log.w(TAG, "wifi re-enable failed: ${t.message}") }
        }
    }

    /**
     * Call once at agent startup. Restores the in-memory expiry from Prefs so an OTA or
     * process-restart doesn't orphan WiFi in the disabled state indefinitely.
     * - Cooldown still active → restore [defensiveOffUntil]; [tick] will re-enable at expiry.
     * - Cooldown already expired → clear the flag and re-enable WiFi immediately.
     */
    fun restoreAfterRestart(context: Context) {
        val persisted = Prefs(context).rogueDefenseOffUntil
        if (persisted == 0L) return
        val now = System.currentTimeMillis()
        if (persisted > now) {
            defensiveOffUntil = persisted
            Log.i(TAG, "ROGUE DEFENSE: restored — WiFi stays off for ${(persisted - now) / 1000}s more")
        } else {
            Prefs(context).rogueDefenseOffUntil = 0L
            try {
                val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                @Suppress("DEPRECATION") wm.setWifiEnabled(true)
                Log.i(TAG, "ROGUE DEFENSE: expired cooldown detected at startup — WiFi re-enabled")
            } catch (t: Throwable) { Log.w(TAG, "startup wifi re-enable failed: ${t.message}") }
        }
    }
}
