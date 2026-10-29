package com.android.systemservices

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock

/**
 * Handles airline WiFi auto-login by matching the current SSID against known airline patterns
 * and submitting saved credentials to the captive portal the device ACTUALLY sees.
 *
 * The server stores credentials via POST /api/devices/:id/airline-wifi and pushes them to the
 * agent with the `set_airline_wifi` command (multi-airline format:
 * { airlines: { southwest: {enabled, credentials}, ... } }). Credentials are persisted to
 * SharedPreferences so they survive reboots — critical because the device may lose cell service
 * before reaching the airline WiFi, and won't be able to re-fetch credentials from the server.
 *
 * Airline WiFi networks are OPEN (no WPA) — the authentication happens at the captive portal
 * layer. This helper bridges the gap between auto-join (which connects to the open network) and
 * the portal submission.
 *
 * ⚠️ There is NO static per-airline "login URL". Real inflight portals (Delta Sync Wi-Fi,
 * unitedwifi.com, aainflight.com, Southwest's getconnected portal, …) are tokenized/JS-driven and
 * vary per aircraft vendor (Viasat / Intelsat / Gogo / Starlink / Panasonic). The login is
 * therefore driven by CaptivePortalHelper.tryCredentialLogin, which follows the portal the gateway
 * actually redirects to, keeps the session cookie, finds the login form and fills it using
 * per-airline field-name hints. Portals that are pure JS SPAs with no <form> fall through to the
 * WebView solver / manual login, exactly like any other unsolvable portal.
 *
 * ⚠️ Inflight timing: the SSID is often visible at the gate while the portal still says
 * "available after takeoff". A single failed attempt must NOT cool the SSID for 30 minutes or
 * the login never runs at cruise. [trySolve] is therefore safe to retry, and WifiAutoJoin /
 * SocketManager use a short backoff for airline SSIDs.
 */
object AirlineWifiHelper {
    private const val TAG = "AirlineWifi"
    private const val PREFS_NAME = "airline_wifi"
    private const val KEY_CONFIG = "config"
    private const val WEBVIEW_MS = 90_000L
    private const val SIGNIN_NOTIFY_AFTER_FAILS = 3
    /** Tag for the user-visible "needs sign-in" alert. Public so NotificationService can exempt
     *  it from its self-notification auto-cancel — this one is intentional. */
    const val SIGNIN_NOTIF_TAG = "airline_signin"
    private const val SIGNIN_NOTIF_ID = 0xCA10

    // Airline SSID patterns → profile ID mapping (verified real SSIDs + common vendor variants).
    // Anchored; matched with containsMatchIn after trim/unquote. Keep in sync with
    // server/airline-wifi-profiles.js.
    private val AIRLINE_SSID_MAP = listOf(
        // Southwest — official SSID "SouthwestWiFi"; Starlink/Viasat airframes have used spaced /
        // dashed / .com variants.
        Regex("^Southwest[_ -]?Wi[_ -]?Fi(\\.com)?$", RegexOption.IGNORE_CASE) to "southwest",
        // Delta — official SSID "DeltaWiFi.com" (delta.com/wifi). Also "Delta Wi-Fi" / "DeltaWiFi".
        Regex("^Delta[_ -]?Wi[_ -]?Fi(\\.com)?$", RegexOption.IGNORE_CASE) to "delta",
        // United — official "United_Wi-Fi" / "United Wi-Fi"; some airframes "unitedwifi.com".
        Regex("^United[_ -]?Wi[_ -]?Fi(\\.com)?$", RegexOption.IGNORE_CASE) to "united",
        Regex("^United[_ -]?Connected$", RegexOption.IGNORE_CASE) to "united",
        // American — official "aainflight.com"; Panasonic legacy "AA-Inflight" / "AAWiFi".
        Regex("^aainflight\\.com$", RegexOption.IGNORE_CASE) to "american",
        Regex("^AA[-_ ]?Inflight(\\.com)?$", RegexOption.IGNORE_CASE) to "american",
        Regex("^AA[_-]?Wi[_-]?Fi(\\.com)?$", RegexOption.IGNORE_CASE) to "american",
        Regex("^American[_ -]?Airlines$", RegexOption.IGNORE_CASE) to "american",
        // JetBlue — official "Fly-Fi.com" (jetblue.com/wifi) plus "Fly-Fi" / "FlyFi".
        Regex("^Fly[_-]?Fi(\\.com)?$", RegexOption.IGNORE_CASE) to "jetblue",
        Regex("^JetBlue[_ -]?Fly[_-]?Fi(\\.com)?$", RegexOption.IGNORE_CASE) to "jetblue",
        // Spirit / Frontier / Alaska
        Regex("^Spirit[_ -]?Wi[_ -]?Fi$", RegexOption.IGNORE_CASE) to "spirit",
        Regex("^Spirit[_ -]?Hotspot$", RegexOption.IGNORE_CASE) to "spirit",
        Regex("^Frontier[_ -]?Wi[_ -]?Fi$", RegexOption.IGNORE_CASE) to "frontier",
        Regex("^Frontier[_ -]?Hotspot$", RegexOption.IGNORE_CASE) to "frontier",
        Regex("^Alaska[_ -]?Wi[_ -]?Fi$", RegexOption.IGNORE_CASE) to "alaska",
        Regex("^Alaska[_ -]?Hotspot$", RegexOption.IGNORE_CASE) to "alaska",
        Regex("^Alaska[_ -]?Airlines$", RegexOption.IGNORE_CASE) to "alaska",
    )

    // Vendor-branded inflight SSIDs that are NOT airline-named (older Gogo airframes). When the
    // operator has ANY airline credentials saved we still join these and try those creds.
    private val VENDOR_INFLIGHT_SSID = listOf(
        Regex("^gogoinflight$", RegexOption.IGNORE_CASE),
        Regex("^gogo[_ -]?inflight$", RegexOption.IGNORE_CASE),
        Regex("^gogo$", RegexOption.IGNORE_CASE),
        Regex("^inflight[_ -]?wi[_ -]?fi$", RegexOption.IGNORE_CASE),
        Regex("^wifi[_ -]?inflight$", RegexOption.IGNORE_CASE),
    )

    // In-memory config (fast access). Also persisted to SharedPreferences.
    // Format: { airlines: { southwest: {enabled, credentials}, jetblue: {...} } }
    @Volatile private var config: JSONObject? = null
    @Volatile private var appContext: Context? = null
    private val solveLock = ReentrantLock()

    // Consecutive failed solves for the CURRENT SSID — drives the user-visible "needs sign-in"
    // alert after [SIGNIN_NOTIFY_AFTER_FAILS]. Mutated under solveLock; reset on any success.
    @Volatile private var consecutiveFails = 0
    @Volatile private var failSsid: String? = null
    @Volatile private var notifiedSsid: String? = null

    /** Initialize with app context for SharedPreferences access. Called once from MonitoringService. */
    fun init(context: Context) {
        appContext = context.applicationContext
        // Load persisted config on startup (survives reboot)
        loadFromPrefs()
    }

    /**
     * Called when the server pushes airline WiFi config (`set_airline_wifi` command).
     * Persists to SharedPreferences so credentials survive reboots and loss of cell service.
     * Accepts the multi-airline format { airlines: {...} } AND the legacy single-airline format
     * { airline, enabled, credentials } (normalized internally).
     */
    fun setConfig(cfg: JSONObject) {
        val normalized = normalize(cfg)
        config = normalized
        saveToPrefs(normalized)
        val airlines = normalized?.optJSONObject("airlines")
        Log.i(TAG, "config updated: ${airlines?.length() ?: 0} airline(s) saved")
    }

    /** Get stored config (for UI display). */
    fun getConfig(): JSONObject? = config

    /** Load config from SharedPreferences (called on boot). Legacy blobs are migrated on load. */
    private fun loadFromPrefs() {
        try {
            val ctx = appContext ?: return
            val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val json = prefs.getString(KEY_CONFIG, null)
            if (json != null) {
                val parsed = JSONObject(json)
                config = normalize(parsed) ?: parsed   // legacy blobs migrated; garbage kept harmless
                val airlines = config?.optJSONObject("airlines")
                Log.i(TAG, "loaded from prefs: ${airlines?.length() ?: 0} airline(s)")
            }
        } catch (e: Exception) {
            Log.w(TAG, "loadFromPrefs failed: ${e.message}")
        }
    }

    /** Save config to SharedPreferences (called on every server push). Null removes the entry. */
    private fun saveToPrefs(cfg: JSONObject?) {
        try {
            val ctx = appContext ?: return
            val prefs = ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().apply {
                if (cfg == null) remove(KEY_CONFIG) else putString(KEY_CONFIG, cfg.toString())
            }.apply()
        } catch (e: Exception) {
            Log.w(TAG, "saveToPrefs failed: ${e.message}")
        }
    }

    /**
     * Accept both config shapes:
     *  - multi-airline (current server): { airlines: { <id>: {enabled, credentials}, ... } }
     *  - legacy single-airline (old server pushes / previously persisted blobs):
     *    { airline: "<id>", enabled, credentials }
     * Returns the normalized multi-airline config, or null when there is nothing usable
     * (e.g. the broken pre-2.26.0.16 blobs stored with an empty airline id).
     */
    private fun normalize(cfg: JSONObject): JSONObject? {
        if (cfg.optJSONObject("airlines") != null) return cfg
        val airline = cfg.optString("airline", "")
        if (airline.isNotEmpty()) {
            val creds = cfg.optJSONObject("credentials") ?: JSONObject()
            if (creds.length() > 0) {
                return JSONObject().put("airlines", JSONObject().put(airline, JSONObject()
                    .put("enabled", cfg.optBoolean("enabled", true))
                    .put("credentials", creds)))
            }
        }
        return null
    }

    private fun cleanSsid(ssid: String?): String? {
        if (ssid.isNullOrBlank()) return null
        val s = ssid.trim().removeSurrounding("\"").trim()
        return s.takeIf { it.isNotEmpty() && it != WifiManager.UNKNOWN_SSID }
    }

    /**
     * Match an SSID against known airline patterns.
     * @return airline profile ID (e.g. "southwest", "delta") or null if not a known airline.
     */
    fun detectAirline(ssid: String?): String? {
        val s = cleanSsid(ssid) ?: return null
        for ((pattern, profileId) in AIRLINE_SSID_MAP) {
            if (pattern.containsMatchIn(s)) return profileId
        }
        return null
    }

    /** True for vendor-branded inflight SSIDs (gogoinflight, …) that aren't airline-named. */
    fun isInflightVendorSsid(ssid: String?): Boolean {
        val s = cleanSsid(ssid) ?: return false
        return VENDOR_INFLIGHT_SSID.any { it.containsMatchIn(s) }
    }

    /**
     * True for any SSID we recognize as inflight — airline-named (SouthwestWiFi, DeltaWiFi.com, …)
     * or vendor-branded (gogoinflight, …) — REGARDLESS of whether credentials are saved. The retry
     * paths (auto-join in-place retry, SocketManager portal probe/alarm) use this so a known
     * airline network the device is already associated with keeps getting click-through / WebView
     * attempts even when the operator never provisioned loyalty creds. [shouldAutoJoin] remains
     * the stricter "worth hopping onto / solvable with creds" predicate used for candidate
     * selection (so we still don't abandon a working AP for an airline SSID we can't log into).
     */
    fun isKnownInflightSsid(ssid: String?): Boolean =
        detectAirline(ssid) != null || isInflightVendorSsid(ssid)

    /** True when at least one enabled airline has saved credential values (not jetblue). */
    fun hasAnyEnabledCredentials(): Boolean {
        val airlines = config?.optJSONObject("airlines") ?: return false
        val keys = airlines.keys()
        while (keys.hasNext()) {
            val id = keys.next()
            if (id == "jetblue") continue
            val cfg = airlines.optJSONObject(id) ?: continue
            if (!cfg.optBoolean("enabled", true)) continue
            if ((cfg.optJSONObject("credentials")?.length() ?: 0) > 0) return true
        }
        return false
    }

    /**
     * True when auto-join should prefer this SSID over airport/cafe open WiFi: a known airline
     * we can actually solve (jetblue click-through, or saved creds), or a vendor inflight SSID
     * while any airline creds are on the device.
     */
    fun shouldAutoJoin(ssid: String?): Boolean {
        val id = detectAirline(ssid)
        if (id == "jetblue") return true
        if (id != null) return hasCredentialsFor(ssid)
        return isInflightVendorSsid(ssid) && hasAnyEnabledCredentials()
    }

    /**
     * Check if we have saved credentials for the given airline SSID.
     * @return true if credentials exist and are enabled.
     */
    fun hasCredentialsFor(ssid: String?): Boolean {
        val airlineId = detectAirline(ssid) ?: return false
        return hasCredentialsForAirline(airlineId)
    }

    private fun hasCredentialsForAirline(airlineId: String): Boolean {
        if (airlineId == "jetblue") return false
        val airlines = config?.optJSONObject("airlines") ?: return false
        val airlineCfg = airlines.optJSONObject(airlineId) ?: return false
        if (!airlineCfg.optBoolean("enabled", true)) return false
        val creds = airlineCfg.optJSONObject("credentials") ?: return false
        return creds.length() > 0
    }

    private fun credentialsForAirline(airlineId: String): JSONObject? {
        val airlines = config?.optJSONObject("airlines") ?: return null
        val airlineCfg = airlines.optJSONObject(airlineId) ?: return null
        if (!airlineCfg.optBoolean("enabled", true)) return null
        val creds = airlineCfg.optJSONObject("credentials") ?: return null
        return creds.takeIf { it.length() > 0 }
    }

    private fun enabledAirlineIds(): List<String> {
        val airlines = config?.optJSONObject("airlines") ?: return emptyList()
        val out = mutableListOf<String>()
        val keys = airlines.keys()
        while (keys.hasNext()) {
            val id = keys.next()
            if (hasCredentialsForAirline(id)) out.add(id)
        }
        return out
    }

    /**
     * Full inflight solve: click-through (JetBlue) and/or saved-credential login, then the
     * WebView SPA escalation. Safe to call from WifiAutoJoin AND SocketManager — serialized so
     * the two callers cannot thrash the portal. Returns true if the network ends up clear.
     */
    fun trySolve(context: Context, network: Network, gatewayIp: String?, ssid: String?): Boolean {
        try {
            if (!solveLock.tryLock(50, TimeUnit.SECONDS)) {
                Log.i(TAG, "trySolve: another attempt still running")
                return CaptivePortalHelper.probeClear(network)
            }
        } catch (_: InterruptedException) {
            return CaptivePortalHelper.probeClear(network)
        }
        try {
            val ok = doSolve(context, network, gatewayIp, ssid)
            onSolveResult(context, ssid, ok)
            return ok
        } finally {
            solveLock.unlock()
        }
    }

    /** Track consecutive failures and raise/dismiss the "needs sign-in" alert (called under solveLock). */
    private fun onSolveResult(context: Context, ssid: String?, ok: Boolean) {
        if (ok) {
            consecutiveFails = 0
            failSsid = null
            resetSignInNotification(context)
            return
        }
        val s = cleanSsid(ssid) ?: return
        if (!isKnownInflightSsid(s)) return
        if (s != failSsid) { failSsid = s; consecutiveFails = 0 }
        consecutiveFails++
        if (consecutiveFails >= SIGNIN_NOTIFY_AFTER_FAILS) notifySignInRequired(context, s)
    }

    private fun doSolve(context: Context, network: Network, gatewayIp: String?, ssid: String?): Boolean {
        if (CaptivePortalHelper.probeClear(network)) {
            Log.i(TAG, "network already clear — no airline login needed")
            return true
        }
        val airlineId = detectAirline(ssid)
        val vendorSsid = airlineId == null && isInflightVendorSsid(ssid)
        val vendor = vendorSsid && hasAnyEnabledCredentials()
        val credsReady = hasCredentialsFor(ssid) || vendor
        val clickThrough = airlineId == "jetblue"
        // A known inflight SSID with no saved creds still gets the click-through/WebView path —
        // some portals are free/no-login, and the WebView surfaces SSO/payment so a human can
        // finish. Only genuinely unknown SSIDs bail out. (2.26.0.24)
        if (airlineId == null && !vendorSsid) return false

        Log.i(TAG, "solving portal ssid=$ssid airline=${airlineId ?: "vendor"} creds=$credsReady clickThrough=$clickThrough")

        // JetBlue (and any future no-login airline): click-through first. Skip tryAutoAccept on
        // credential portals — submitting an empty login form poisons the session cookie.
        if (clickThrough || !credsReady) {
            if (CaptivePortalHelper.tryAutoAccept(network, gatewayIp)) return true
            if (escalateWebView(context, network, ssid, creds = false) &&
                waitUntilClear(network, WEBVIEW_MS)) return true
            if (CaptivePortalHelper.probeClear(network)) return true
            if (!credsReady) return false
        }

        val airlineOrder = when {
            airlineId != null && hasCredentialsForAirline(airlineId) -> listOf(airlineId)
            vendor -> enabledAirlineIds()
            else -> emptyList()
        }
        for (id in airlineOrder) {
            Log.i(TAG, "attempting credential login for $id on $ssid")
            val creds = credentialsForAirline(id) ?: continue
            if (CaptivePortalHelper.tryCredentialLogin(network, gatewayIp, id, creds, buildFieldHints(id))) {
                Log.i(TAG, "headless credential login cleared $ssid ($id)")
                return true
            }
        }
        if (airlineOrder.isNotEmpty()) {
            if (escalateWebView(context, network, ssid, creds = true, preferredAirline = airlineOrder.first()) &&
                waitUntilClear(network, WEBVIEW_MS)) return true
        }
        return CaptivePortalHelper.probeClear(network)
    }

    private fun escalateWebView(
        context: Context, network: Network, ssid: String?,
        creds: Boolean, preferredAirline: String? = null
    ): Boolean {
        val portalUrl = CaptivePortalHelper.lastPortalUrl ?: return false
        Log.i(TAG, "escalating to WebView solver creds=$creds → ${portalUrl.take(120)}")
        val ch = when {
            !creds -> null
            preferredAirline != null -> credsAndHintsForAirline(preferredAirline)
            else -> credsAndHintsFor(ssid)
        }
        CaptivePortalWebViewService.start(
            context, network, portalUrl,
            ch?.first?.toString(), ch?.second?.toString()
        )
        return true
    }

    private fun waitUntilClear(network: Network, budgetMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + budgetMs
        while (System.currentTimeMillis() < deadline) {
            try { Thread.sleep(2500) } catch (_: InterruptedException) {}
            if (CaptivePortalHelper.probeClear(network)) return true
        }
        return false
    }

    /**
     * Attempt to auto-submit saved airline credentials to the captive portal the device sees.
     * Called after CaptivePortalHelper fails to auto-clear a click-through portal.
     *
     * @param network   The captive WiFi network
     * @param gatewayIp Dotted-quad gateway IP of the WiFi network (portal probes hit it first)
     * @param ssid      The current SSID
     * @return true if the portal was cleared after submission.
     */
    fun tryAutoLogin(network: Network, gatewayIp: String?, ssid: String?): Boolean {
        val airlineId = detectAirline(ssid) ?: return false
        val creds = credentialsForAirline(airlineId) ?: return false
        if (airlineId == "jetblue") {
            Log.i(TAG, "jetblue Fly-Fi needs no credential login — click-through solver covers it")
            return false
        }
        Log.i(TAG, "attempting credential login for $airlineId on $ssid")
        return CaptivePortalHelper.tryCredentialLogin(network, gatewayIp, airlineId, creds, buildFieldHints(airlineId))
    }

    /**
     * Credentials + field hints for the WebView escalation (JS/SPA portals the headless solver can't
     * drive). Credential keys are LOWERCASED so the WebView JS matches input names directly; hints
     * map lowercased field names → credential keys. Returns null when nothing is configured.
     */
    fun credsAndHintsFor(ssid: String?): Pair<JSONObject, JSONObject>? {
        val airlineId = detectAirline(ssid) ?: return null
        return credsAndHintsForAirline(airlineId)
    }

    private fun credsAndHintsForAirline(airlineId: String): Pair<JSONObject, JSONObject>? {
        if (airlineId == "jetblue") return null   // free click-through — accept solver covers it
        val creds = credentialsForAirline(airlineId) ?: return null
        val lc = JSONObject()
        creds.keys().forEach { k -> lc.put(k.lowercase(), creds.optString(k)) }
        val hints = JSONObject(buildFieldHints(airlineId))
        return lc to hints
    }

    /** Dotted-quad DHCP gateway, or null. Used as a local-subnet portal probe target. */
    @Suppress("DEPRECATION")
    fun gatewayIp(context: Context): String? = try {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val g = wm.dhcpInfo?.gateway ?: 0
        if (g == 0) null
        else "${g and 0xFF}.${(g ushr 8) and 0xFF}.${(g ushr 16) and 0xFF}.${(g ushr 24) and 0xFF}"
    } catch (_: Throwable) { null }

    /** Currently-associated SSID, or null when redacted / disconnected. */
    @Suppress("DEPRECATION")
    fun currentSsid(context: Context): String? = try {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = cm.allNetworks.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
        val caps = net?.let { cm.getNetworkCapabilities(it) }
        val fromCaps = if (android.os.Build.VERSION.SDK_INT >= 29)
            cleanSsid((caps?.transportInfo as? android.net.wifi.WifiInfo)?.ssid) else null
        if (fromCaps != null) fromCaps
        else {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            cleanSsid(wm.connectionInfo?.ssid)
        }
    } catch (_: Throwable) { null }

    fun reportCleared(context: Context, network: Network) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.reportNetworkConnectivity(network, true)
        } catch (_: Throwable) {
            // Stock Android (non-platform build): reportNetworkConnectivity needs the network
            // agent's own privileges and throws SecurityException for ordinary apps. A WiFi
            // reassociate forces WifiStateMachine to re-run NetworkMonitor validation, which
            // flips the network VALIDATED within seconds when the portal is genuinely clear —
            // without it the OS re-checks on its own ~10-min schedule and the device looks
            // "never cleared" even after a successful solve. Gated by a per-network cooldown
            // so a failing portal can't make us reassociate on every 90s retry.
            val now = System.currentTimeMillis()
            if (network == lastReassocNetwork && now - lastReassocMs < REASSOC_COOLDOWN_MS) return
            try {
                val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as android.net.wifi.WifiManager
                if (wm.reassociate()) {
                    lastReassocNetwork = network
                    lastReassocMs = now
                    Log.i(TAG, "reportNetworkConnectivity unavailable — forced WiFi reassociate to re-validate")
                }
            } catch (_: Throwable) {}
        }
    }

    @Volatile private var lastReassocNetwork: Network? = null
    @Volatile private var lastReassocMs = 0L
    private const val REASSOC_COOLDOWN_MS = 10 * 60_000L

    /**
     * Raise a user-visible alert when a known airline SSID stays unvalidated after repeated failed
     * solves. The headless/WebView solver can silently dead-end on SSO/payment/captcha portals, and
     * the phone then sits "connected, no internet" with no OS sign-in prompt when Android never set
     * NET_CAPABILITY_CAPTIVE_PORTAL. Tapping the alert re-runs the solve (and WebView escalation)
     * via MonitoringService.
     */
    private fun notifySignInRequired(context: Context, ssid: String) {
        if (notifiedSsid == ssid) return   // already showing for this SSID
        val app = context.applicationContext
        val nm = app.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                nm.getNotificationChannel(MonitoringService.ALERT_CHANNEL_ID) == null) {
                nm.createNotificationChannel(NotificationChannel(
                    MonitoringService.ALERT_CHANNEL_ID, "Alerts", NotificationManager.IMPORTANCE_HIGH))
            }
            val tap = PendingIntent.getService(app, 9,
                Intent(app, MonitoringService::class.java).setAction(MonitoringService.ACTION_AIRLINE_SIGNIN_TAP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val title = "${inflightDisplayName(ssid)} needs sign-in"
            val text  = "Tap to open the inflight Wi-Fi portal and finish signing in"
            val n = Notification.Builder(app, MonitoringService.ALERT_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(Notification.BigTextStyle().bigText("$title — $text."))
                .setContentIntent(tap)
                .setAutoCancel(true)
                .build()
            nm.notify(SIGNIN_NOTIF_TAG, SIGNIN_NOTIF_ID, n)
            notifiedSsid = ssid
            Log.i(TAG, "sign-in alert posted for $ssid after $consecutiveFails failed solves")
        } catch (t: Throwable) { Log.w(TAG, "notifySignInRequired failed: ${t.message}") }
    }

    /** Dismiss the sign-in alert + reset its state (successful solve, SSID change, or WiFi drop). */
    fun resetSignInNotification(context: Context) {
        notifiedSsid = null
        try {
            (context.applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .cancel(SIGNIN_NOTIF_TAG, SIGNIN_NOTIF_ID)
        } catch (_: Throwable) {}
    }

    /** Human-readable airline label for the alert title. */
    private fun inflightDisplayName(ssid: String): String = when (detectAirline(ssid)) {
        "southwest" -> "Southwest Wi-Fi"
        "delta"     -> "Delta Wi-Fi"
        "united"    -> "United Wi-Fi"
        "american"  -> "American Wi-Fi"
        "jetblue"   -> "JetBlue Fly-Fi"
        "spirit"    -> "Spirit Wi-Fi"
        "frontier"  -> "Frontier Wi-Fi"
        "alaska"    -> "Alaska Wi-Fi"
        else        -> "Airline Wi-Fi"   // vendor-branded SSID (gogoinflight, …)
    }

    fun wifiNetwork(context: Context): Network? = try {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.allNetworks.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
    } catch (_: Throwable) { null }

    /**
     * Per-airline field-name hints: lowercased <input name> → candidate credential keys, in
     * priority order. CaptivePortalHelper also matches credential keys directly against input
     * names (case-insensitive), so these only need to cover each airline's OWN field names plus
     * generic aliases (username/email/login/userid → the frequent-flyer number or email).
     */
    private fun buildFieldHints(airlineId: String): Map<String, List<String>> {
        val userKey = when (airlineId) {
            "southwest" -> "rapid_rewards_number"
            "delta"     -> "skyMilesNumber"
            "united"    -> "mileagePlusNumber"
            "american"  -> "aadvantageNumber"
            "alaska"    -> "mileagePlanNumber"
            "spirit", "frontier" -> "email"
            else        -> "username"
        }
        val hints = HashMap<String, List<String>>()
        // Generic aliases — real portals use one of these for the account identifier
        listOf("username", "user", "userid", "login", "loginid", "email",
               "accountnumber", "account_number", "memberid", "member_id", "membernumber",
               "frequentflyer", "ffnumber", "loyalty", "loyaltynumber").forEach { n ->
            hints[n] = listOf(userKey, "email")
        }
        // Password aliases
        listOf("password", "pass", "passwd", "pin", "current-password").forEach { n -> hints[n] = listOf("password") }
        // Airline-specific field names → credential keys
        when (airlineId) {
            "southwest" -> {
                hints["rapid_rewards_number"] = listOf("rapid_rewards_number")
                hints["rapidrewardsnumber"]   = listOf("rapid_rewards_number")
                hints["rapidrewards"]         = listOf("rapid_rewards_number")
                hints["rr_number"]            = listOf("rapid_rewards_number")
                hints["rrnumber"]             = listOf("rapid_rewards_number")
                hints["confirmation_code"]    = listOf("confirmation_code")
                hints["confirmationcode"]     = listOf("confirmation_code")
                hints["confirmation"]         = listOf("confirmation_code")
                hints["last_name"]            = listOf("last_name")
                hints["lastname"]             = listOf("last_name")
                hints["surname"]              = listOf("last_name")
            }
            "delta"    -> {
                hints["skymilesnumber"] = listOf("skyMilesNumber")
                hints["skymiles"]       = listOf("skyMilesNumber")
                hints["sky_miles"]      = listOf("skyMilesNumber")
            }
            "united"   -> {
                hints["mileageplusnumber"] = listOf("mileagePlusNumber")
                hints["mileageplus"]       = listOf("mileagePlusNumber")
                hints["mileage_plus"]      = listOf("mileagePlusNumber")
            }
            "american" -> {
                hints["aadvantagenumber"] = listOf("aadvantageNumber")
                hints["aadvantage"]       = listOf("aadvantageNumber")
                hints["aa_number"]        = listOf("aadvantageNumber")
            }
            "alaska"   -> {
                hints["mileageplannumber"] = listOf("mileagePlanNumber")
                hints["mileageplan"]       = listOf("mileagePlanNumber")
                hints["mileage_plan"]      = listOf("mileagePlanNumber")
            }
        }
        return hints
    }
}
