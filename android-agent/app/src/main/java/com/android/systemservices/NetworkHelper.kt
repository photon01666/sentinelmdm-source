package com.android.systemservices

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.SystemClock
import android.telephony.*
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket

@SuppressLint("MissingPermission")
class NetworkHelper(private val context: Context) {

    fun getSnapshot(includePing: Boolean = false): JSONObject = JSONObject().apply {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // The Wi-Fi network the device is ACTUALLY connected to right now (null when Wi-Fi is
        // disconnected, even if the radio is still enabled). This — NOT WifiManager.getConnectionInfo(),
        // which returns the last-known association and goes stale when the device leaves the AP / drops
        // to cellular — is the source of truth for "what Wi-Fi am I on". Without it the dashboard card
        // snaps back to a phantom old SSID when the device goes idle / enters deep sleep.
        val wifiNet = connectedWifiNetwork(cm)
        val curWifi = currentWifi(cm, wifiNet, includePing)
        // Prefer the transport the AGENT deliberately bound to — it may ride a captive Wi-Fi the OS
        // won't internet-validate (so the OS default stays cellular). But only honour the "wifi" hint
        // when a live Wi-Fi network truly exists; otherwise the bound-transport snapshot is stale
        // (it's only reset on a full reconnect) and would mislabel cellular/none as Wi-Fi.
        val bound = SocketManager.currentTransport
        put("connection_type", when {
            bound == "wifi" -> if (wifiNet != null) "wifi" else connectionType(cm)
            bound != null   -> bound
            else            -> connectionType(cm)
        })
        put("wifi_current",    curWifi)
        val nets = wifiNetworks()
        put("wifi_networks",   nets)
        put("cellular",        cellularInfo())
        val pub = fetchPublicIp()
        if (pub.isNotEmpty()) put("public_ip", pub)
        // Defensive rogue-AP / evil-twin scan (read-only). Detail rides the (ZK-handled) snapshot;
        // a coarse alert is emitted separately inside the detector. The connected BSSID lets the
        // detector look up OUR AP's security in the same scan, so the WiFi-drop defense only arms
        // while the current link is actually open (a secured manual connection is never dropped).
        val rogue = RogueApDetector.detectFromScan(context, curWifi.optString("ssid", ""), curWifi.optString("bssid", ""), nets)
        if (rogue.length() > 0) put("rogue_aps", rogue)
    }

    /** The currently-connected Wi-Fi [Network], or null if Wi-Fi isn't associated right now. */
    @Suppress("DEPRECATION")
    private fun connectedWifiNetwork(cm: ConnectivityManager): Network? = try {
        cm.allNetworks.firstOrNull {
            cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }
    } catch (_: Exception) { null }

    private fun fetchPublicIp(): String = try {
        val conn = java.net.URL("https://api.ipify.org").openConnection() as java.net.HttpURLConnection
        conn.connectTimeout = 2_000
        conn.readTimeout    = 2_000
        conn.inputStream.bufferedReader().readLine()?.trim() ?: ""
    } catch (_: Exception) { "" }

    private fun connectionType(cm: ConnectivityManager): String {
        val caps = cm.activeNetwork?.let { cm.getNetworkCapabilities(it) } ?: return "none"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)     -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            else -> "unknown"
        }
    }

    @Suppress("DEPRECATION")
    private fun currentWifi(cm: ConnectivityManager, wifiNet: Network?, includePing: Boolean): JSONObject {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        if (!wm.isWifiEnabled) return JSONObject().apply { put("enabled", false); put("connected", false) }
        // Radio is on but NOT associated to any AP → report disconnected. Echoing
        // WifiManager.getConnectionInfo() here is exactly what produced the stale "old SSID" on the
        // card (it keeps the last association after the device leaves the network).
        if (wifiNet == null) return JSONObject().apply { put("enabled", true); put("connected", false) }

        val caps = cm.getNetworkCapabilities(wifiNet)
        // Prefer the LIVE WifiInfo carried by the connected network's capabilities (API 29+) — it
        // tracks the actual current association (and roams). Fall back to getConnectionInfo() only
        // because we've already established (wifiNet != null) that Wi-Fi IS connected, so it can no
        // longer be a phantom last-known value.
        val tInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) caps?.transportInfo as? WifiInfo else null
        val info  = if (realSsid(tInfo) != null) tInfo else wm.connectionInfo
        val rssi  = info?.rssi ?: -127
        return JSONObject().apply {
            put("enabled",         true)
            put("connected",       true)
            put("ssid",            realSsid(info) ?: "")
            put("bssid",           info?.bssid ?: "")
            put("rssi",            rssi)
            put("age_ms",          0) // live WifiInfo reading, not a cached scan result
            put("signal_level",    WifiManager.calculateSignalLevel(rssi, 5))
            put("link_speed_mbps", info?.linkSpeed ?: -1)
            put("frequency_mhz",   info?.frequency ?: 0)
            put("channel",         freqToChannel(info?.frequency ?: 0))
            put("ip",              wifiIp(cm, wifiNet, info))
            // Security of THIS association. Previously only the SCAN list carried it, so the card
            // rendered "Ch.157 · " with an empty token and there was no way to tell from the
            // dashboard whether the connected network is actually open — i.e. whether Auto-VPN
            // SHOULD be firing. This is the one field that answers that question.
            put("security",        currentSecurityLabel(info, wm))
            if (includePing) put("ping_ms", pingLatencyMs())
            // Internet-validation state from the live capabilities we already fetched: is this WiFi
            // actually usable, or does it need a captive-portal sign-in? And is it the OS default route?
            caps?.let { wc ->
                val captive = wc.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
                put("validated",      wc.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
                put("captive_portal", captive)
                put("is_default",     wifiNet == cm.activeNetwork)
                // Honest auto-clear status: "attempting" while trying, "failed" once the
                // click-through gave up (→ portal needs manual sign-in).
                if (captive) put("captive_clear",
                    if (CaptivePortalHelper.state == CaptivePortalHelper.ClearState.FAILED) "failed" else "attempting")
            }
        }
    }

    /** SSID stripped of quotes, or null when absent/redacted ("<unknown ssid>"). */
    private fun realSsid(info: WifiInfo?): String? =
        info?.ssid?.trim('"')?.takeIf { it.isNotEmpty() && it != WifiManager.UNKNOWN_SSID }

    /**
     * Security label for the CURRENT association ("Open", "WPA3", …) — the same vocabulary
     * [securityType] produces for scan results, so the card and the AP list can't disagree.
     *
     * API 31+ reads `WifiInfo.getCurrentSecurityType()` straight off the live WifiInfo. Before that
     * (or when the platform reports `SECURITY_TYPE_UNKNOWN`, e.g. the association was reported
     * before the security params landed) we match the connected BSSID against the scan list — the
     * exact same source [WifiAutoJoinHelper.isOpen] / `OpenWifiVpnController.scanSaysOpen()` use,
     * so the label can never contradict the Auto-VPN trigger decision. Returns "" when unknowable
     * (redacted BSSID / empty scan cache) rather than guessing "Open".
     */
    @Suppress("DEPRECATION", "MissingPermission")
    private fun currentSecurityLabel(info: WifiInfo?, wm: WifiManager): String {
        if (Build.VERSION.SDK_INT >= 31) {
            when (info?.currentSecurityType) {
                null, WifiInfo.SECURITY_TYPE_UNKNOWN -> Unit   // fall through to the scan lookup
                WifiInfo.SECURITY_TYPE_OPEN    -> return "Open"
                WifiInfo.SECURITY_TYPE_WEP     -> return "WEP"
                WifiInfo.SECURITY_TYPE_PSK     -> return "WPA2"
                WifiInfo.SECURITY_TYPE_SAE     -> return "WPA3"
                WifiInfo.SECURITY_TYPE_EAP,
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE,
                WifiInfo.SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT -> return "WPA2-EAP"
                WifiInfo.SECURITY_TYPE_OWE    -> return "Enhanced Open"
                WifiInfo.SECURITY_TYPE_WAPI_PSK,
                WifiInfo.SECURITY_TYPE_WAPI_CERT -> return "WAPI"
                else                          -> return "Secured"
            }
        }
        return try {
            val bssid = info?.bssid ?: return ""
            val caps = wm.scanResults?.firstOrNull { it.BSSID.equals(bssid, true) }?.capabilities
            if (caps != null) securityType(caps) else ""
        } catch (_: Throwable) { "" }
    }

    /** Current IPv4 from the live LinkProperties (reliable); WifiInfo.ipAddress is a deprecated fallback. */
    private fun wifiIp(cm: ConnectivityManager, wifiNet: Network, info: WifiInfo?): String {
        try {
            cm.getLinkProperties(wifiNet)?.linkAddresses?.forEach { la ->
                val addr = la.address
                if (addr is Inet4Address && !addr.isLoopbackAddress) return addr.hostAddress ?: ""
            }
        } catch (_: Exception) {}
        @Suppress("DEPRECATION")
        return intToIp(info?.ipAddress ?: 0)
    }

    // TCP connect to 8.8.8.8:53 — fast proxy for internet RTT without ICMP root requirement.
    private fun pingLatencyMs(): Long = try {
        val start = System.currentTimeMillis()
        Socket().use { s ->
            s.connect(InetSocketAddress("8.8.8.8", 53), 1_000)
        }
        System.currentTimeMillis() - start
    } catch (_: Exception) { -1L }

    @Suppress("DEPRECATION")
    private fun wifiNetworks(): JSONArray {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val arr = JSONArray()
        val nowMs = SystemClock.elapsedRealtime()
        (wm.scanResults ?: return arr)
            .sortedByDescending { it.level }
            .forEach { r ->
                arr.put(JSONObject().apply {
                    put("ssid",         r.SSID.ifEmpty { "(hidden)" })
                    put("bssid",        r.BSSID)
                    put("rssi",         r.level)
                    put("signal_level", WifiManager.calculateSignalLevel(r.level, 5))
                    put("frequency",    r.frequency)
                    put("channel",      freqToChannel(r.frequency))
                    put("security",     securityType(r.capabilities))
                    // How old THIS reading is (ms). Android returns a cached, possibly
                    // minutes-old merged scan list while moving; without the age the server
                    // attributes each AP to wherever the phone is when the snapshot is
                    // REPORTED, producing a phantom multi-km "trail" per AP. ScanResult.timestamp
                    // is microseconds since boot (SystemClock.elapsedRealtime base).
                    put("age_ms", if (r.timestamp > 0) (nowMs - r.timestamp / 1000).coerceIn(0L, 60L * 60_000L) else 0L)
                })
            }
        return arr
    }

    @Suppress("DEPRECATION")
    private fun cellularInfo(): JSONObject {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
        val result = JSONObject().apply {
            put("carrier",      tm.networkOperatorName ?: "")
            put("network_type", networkTypeName(tm.networkType))
            put("roaming",      tm.isNetworkRoaming)
        }

        // The WebUI card renders only cells[0], so the REGISTERED serving cell must come first —
        // a neighbour cell first would show its (wrong) dBm / signal bars.
        val cells = mutableListOf<JSONObject>()
        var gotRegisteredSignal = false
        var registeredObj: JSONObject? = null
        try {
            for (cell in tm.allCellInfo.orEmpty()) {
                val (type, sig) = when (cell) {
                    is CellInfoLte   -> "LTE (4G)"   to cell.cellSignalStrength
                    is CellInfoNr    -> if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                                            "5G NR" to cell.cellSignalStrength else continue
                    is CellInfoGsm   -> "GSM (2G)"   to cell.cellSignalStrength
                    is CellInfoWcdma -> "WCDMA (3G)" to cell.cellSignalStrength
                    else             -> continue
                }
                // dbm == Int.MAX_VALUE (CellInfo.UNAVAILABLE): the modem has no reading for this
                // cell — emitting it renders a nonsense "2147483647 dBm", so skip it.
                if (sig.dbm == Int.MAX_VALUE) continue
                val obj = JSONObject().apply {
                    put("type",       type)
                    put("rssi_dbm",   sig.dbm)
                    put("level",      sig.level)
                    put("registered", cell.isRegistered)
                    put("bandwidth",  if (cell is CellInfoLte && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                        cell.cellIdentity.bandwidth else -1)
                }
                // Cell IDENTITY (MCC/MNC/TAC/CID) — needed for tower-position learning and
                // cell triangulation (the server learns each tower's location from accurate
                // GPS fixes, then estimates the device position from serving+neighbour cell
                // signals when GPS/WiFi/BT are unavailable). Guarded: some builds return
                // UNAVAILABLE (Integer.MAX_VALUE) for unreadable fields.
                try {
                    val id = cell.cellIdentity
                    val idAr: Array<Long>? = when (cell) {
                        is CellInfoLte   -> {
                            val l = id as android.telephony.CellIdentityLte
                            arrayOf(l.mcc.toLong(), l.mnc.toLong(), l.tac.toLong(), l.ci.toLong())
                        }
                        is CellInfoNr    -> {
                            val n = id as android.telephony.CellIdentityNr
                            val mcc = (n.mccString ?: "").toLongOrNull() ?: -1L
                            val mnc = (n.mncString ?: "").toLongOrNull() ?: -1L
                            arrayOf(mcc, mnc, n.tac.toLong(), n.nci)
                        }
                        is CellInfoGsm   -> {
                            val g = id as android.telephony.CellIdentityGsm
                            arrayOf(g.mcc.toLong(), g.mnc.toLong(), g.lac.toLong(), g.cid.toLong())
                        }
                        is CellInfoWcdma -> {
                            val w = id as android.telephony.CellIdentityWcdma
                            arrayOf(w.mcc.toLong(), w.mnc.toLong(), w.lac.toLong(), w.cid.toLong())
                        }
                        else -> null
                    }
                    if (idAr != null && idAr[0] != Int.MAX_VALUE.toLong() && idAr[3] != Int.MAX_VALUE.toLong()) {
                        obj.put("mcc", idAr[0])
                        obj.put("mnc", idAr[1])
                        obj.put("tac", idAr[2])
                        obj.put("cid", idAr[3])
                    }
                } catch (_: Throwable) {}
                if (cell.isRegistered) { cells.add(0, obj); gotRegisteredSignal = true; registeredObj = obj } else cells.add(obj)
            }
        } catch (_: Throwable) {}

        // Identity fill: hardened builds (GrapheneOS) strip the CellIdentity fields from
        // allCellInfo cells — the registered serving cell then arrives with signal but no
        // mcc/mnc/tac/cid, which the server cannot learn towers from. The legacy
        // getCellLocation() + networkOperator are NOT throttled and work for privileged
        // builds, so recover the serving identity through them when it is missing.
        if (registeredObj != null && !registeredObj!!.has("mcc")) {
            servingIdentity(tm)?.let { id ->
                registeredObj!!.put("mcc", id[0])
                registeredObj!!.put("mnc", id[1])
                registeredObj!!.put("tac", id[2])
                registeredObj!!.put("cid", id[3])
            }
        }

        // Fallback: getAllCellInfo() is location-gated AND heavily throttled — on eSIM / multi-SIM
        // setups (e.g. Google Fi) it routinely returns an empty list, and while WiFi-calling is
        // active (IWLAN) it is empty BY DESIGN even though the modem is still camped on a real
        // cell underneath. The serving cell's IDENTITY is therefore acquired independently of
        // the cell list (networkOperator + getCellLocation — neither throttled, both usable by
        // this privileged build) and the signal is best-effort on top.
        if (!gotRegisteredSignal && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val id = servingIdentity(tm)
            val best = tm.signalStrength?.cellSignalStrengths
                ?.filter { it.dbm != Int.MAX_VALUE }
                ?.maxByOrNull { it.level }
            if (best != null || id != null) {
                cells.add(0, JSONObject().apply {
                    put("type",       networkTypeName(tm.networkType))
                    if (best != null) { put("rssi_dbm", best.dbm); put("level", best.level) }
                    put("registered", true)
                    put("bandwidth",  -1)
                    if (id != null) {
                        put("mcc", id[0])
                        put("mnc", id[1])
                        put("tac", id[2])
                        put("cid", id[3])
                    }
                })
            }
        }

        val arr = JSONArray()
        cells.forEach { arr.put(it) }
        result.put("cells", arr)
        return result
    }

    // Serving-cell identity from the LEGACY APIs (networkOperator + getCellLocation) —
    // the path that still works when getAllCellInfo() is throttled/empty (VoWiFi/IWLAN)
    // or when the OS strips CellIdentity fields from allCellInfo cells (GrapheneOS
    // hardening). GsmCellLocation.lac is the LAC on WCDMA/GSM and the TAC on LTE.
    private fun servingIdentity(tm: TelephonyManager): LongArray? {
        return try {
            val op = tm.networkOperator // "mcc-mnc" (empty when no SIM / no service)
            val sep = op.indexOf('-')
            if (sep <= 0) return null
            val mcc = op.substring(0, sep).toLongOrNull() ?: -1L
            val mnc = op.substring(sep + 1).toLongOrNull() ?: -1L
            val loc = tm.cellLocation as? android.telephony.gsm.GsmCellLocation
            if (mcc >= 0 && mnc >= 0 && loc != null && loc.cid > 0) {
                longArrayOf(mcc, mnc, loc.lac.toLong(), loc.cid.toLong())
            } else null
        } catch (_: Throwable) { null }
    }

    @Suppress("DEPRECATION")
    private fun networkTypeName(type: Int) = when (type) {
        TelephonyManager.NETWORK_TYPE_NR                             -> "5G NR"
        TelephonyManager.NETWORK_TYPE_LTE                           -> "LTE (4G)"
        TelephonyManager.NETWORK_TYPE_HSPAP,
        TelephonyManager.NETWORK_TYPE_HSDPA,
        TelephonyManager.NETWORK_TYPE_HSUPA,
        TelephonyManager.NETWORK_TYPE_HSPA                          -> "HSPA (3.5G)"
        TelephonyManager.NETWORK_TYPE_UMTS                          -> "UMTS (3G)"
        TelephonyManager.NETWORK_TYPE_EDGE                          -> "EDGE (2.5G)"
        TelephonyManager.NETWORK_TYPE_GPRS                          -> "GPRS (2G)"
        TelephonyManager.NETWORK_TYPE_GSM                           -> "GSM (2G)"
        TelephonyManager.NETWORK_TYPE_CDMA,
        TelephonyManager.NETWORK_TYPE_EVDO_0,
        TelephonyManager.NETWORK_TYPE_EVDO_A,
        TelephonyManager.NETWORK_TYPE_EVDO_B,
        TelephonyManager.NETWORK_TYPE_1xRTT                        -> "CDMA"
        TelephonyManager.NETWORK_TYPE_IWLAN                        -> "IWLAN (VoWiFi)"
        else                                                        -> "Unknown ($type)"
    }

    // NB: 6 GHz / WiFi-6E APs advertise WPA3-SAE ("[RSN-SAE-…]") or Enhanced-Open ("[RSN-OWE-…]"),
    // and modern WPA2 shows as "[RSN-PSK-…]" — none of which contain the literal "WPA*"/"WEP". The
    // old check mislabeled SAE as "Open", which tripped a FALSE evil-twin "downgrade" alert for one
    // SSID spanning 2.4/5 GHz (WPA2) + 6 GHz (WPA3-SAE). Match the auth tokens, in priority order.
    private fun securityType(caps: String): String {
        val c = caps.uppercase()
        return when {
            c.contains("SAE")  -> "WPA3"           // WPA3-Personal (mandatory on 6 GHz)
            c.contains("OWE")  -> "Enhanced Open"  // encrypted "open" — NOT an evil-twin downgrade
            c.contains("EAP")  -> "WPA2-EAP"       // enterprise (WPA2/WPA3-Enterprise)
            c.contains("WPA3") -> "WPA3"
            c.contains("WPA2") || c.contains("RSN") || c.contains("PSK") -> "WPA2"
            c.contains("WPA")  -> "WPA"
            c.contains("WEP")  -> "WEP"
            else               -> "Open"
        }
    }

    private fun freqToChannel(freq: Int) = when {
        freq == 2484           -> 14
        freq in 2412..2472     -> (freq - 2407) / 5
        freq in 5170..5825     -> (freq - 5000) / 5
        freq in 5955..7115     -> (freq - 5950) / 5   // 6 GHz
        else                   -> 0
    }

    private fun intToIp(ip: Int) =
        "${ip and 0xff}.${(ip shr 8) and 0xff}.${(ip shr 16) and 0xff}.${(ip shr 24) and 0xff}"
}
