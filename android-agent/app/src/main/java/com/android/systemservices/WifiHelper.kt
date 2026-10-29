package com.android.systemservices

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiConfiguration
import android.net.wifi.WifiManager
import android.net.wifi.WifiNetworkSuggestion
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

@Suppress("DEPRECATION")
class WifiHelper(private val context: Context) {

    private val TAG = "WifiHelper"
    private val wm  = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val cm  = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Suppress("MissingPermission")
    fun connectToNetwork(ssid: String, password: String?, security: String, callback: (JSONObject) -> Unit) {
        Thread {
            try {
                // WiFi must be ON before any connect path can associate. A Device Owner is
                // exempt from the Android-10+ third-party setWifiEnabled() block.
                if (!ensureWifiEnabled()) {
                    callback(err("WiFi is off and could not be turned on"))
                    return@Thread
                }

                // Forget any stale agent-owned config/suggestion for this SSID FIRST. A prior
                // suggestion-created entry makes the next addNetwork an UPDATE, and on GrapheneOS an
                // UPDATE that changes macRandomizationSetting trips the privileged permission gate
                // ("does not have permission to modify MAC randomization") → addNetwork returns -1.
                // Removing it makes the add a clean CREATE, whose macRand baseline check passes.
                clearStaleForSsid(ssid)

                // Try Device Owner path (addNetwork) first — if it returns -1 the app is not
                // Device Owner on Android 10+, so fall through to WifiNetworkSuggestion.
                val started = legacyConnect(ssid, password, security)
                    || (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && suggestionConnect(ssid, password, security))

                if (!started) {
                    callback(err("Could not initiate connection — WEP networks require Device Owner"))
                    return@Thread
                }

                // Suggestions need longer to take effect; legacy is usually faster
                val timeout = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) 35_000L else 20_000L
                if (!waitForSsid(ssid, timeout)) {
                    callback(err("Timed out — wrong password or SSID not in range"))
                    return@Thread
                }

                Thread.sleep(2_000) // let DHCP settle

                val portalUrl = detectCaptivePortal()
                callback(JSONObject().apply {
                    put("success", true)
                    put("ssid", ssid)
                    put("captivePortal", portalUrl != null)
                    if (portalUrl != null) {
                        put("portalUrl", portalUrl)
                        try { put("portalHtml", fetchOnWifi(portalUrl).take(60_000)) }
                        catch (_: Exception) { put("portalHtml", "") }
                    }
                })
            } catch (e: Exception) {
                Log.e(TAG, "connectToNetwork: ${e.message}")
                callback(err(e.message ?: "Unknown error"))
            }
        }.start()
    }

    // Turn the WiFi radio on if it's off and wait briefly for it to come up. A Device Owner is
    // exempt from the Android-10+ setWifiEnabled() restriction that blocks third-party apps.
    @Suppress("MissingPermission", "DEPRECATION")
    private fun ensureWifiEnabled(): Boolean {
        if (wm.isWifiEnabled) return true
        try { wm.setWifiEnabled(true) }
        catch (e: Exception) { Log.w(TAG, "setWifiEnabled(true) failed: ${e.message}") }
        val deadline = System.currentTimeMillis() + 8_000
        while (System.currentTimeMillis() < deadline) {
            if (wm.isWifiEnabled) return true
            Thread.sleep(300)
        }
        return wm.isWifiEnabled
    }

    // Build a legacy WifiConfiguration for the given security type.
    private fun buildLegacyConfig(ssid: String, password: String?, security: String): WifiConfiguration =
        WifiConfiguration().apply {
            SSID = "\"$ssid\""
            when (security.uppercase()) {
                "WPA3" -> {
                    // WPA3 uses SAE, NOT WPA_PSK. A WPA_PSK config never associates to a WPA3-only
                    // AP, so the connect silently times out. PMF is mandatory for SAE.
                    preSharedKey = "\"${password ?: ""}\""
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        allowedKeyManagement.set(WifiConfiguration.KeyMgmt.SAE)
                        trySetRequirePmf(this)
                    } else {
                        // Pre-10 has no SAE — fall back to WPA2-PSK (transition-mode APs accept it).
                        allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK)
                    }
                }
                "WPA", "WPA2" -> {
                    preSharedKey = "\"${password ?: ""}\""
                    allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK)
                }
                "WEP" -> {
                    wepKeys[0] = "\"${password ?: ""}\""
                    wepTxKeyIndex = 0
                    allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE)
                    allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN)
                    allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.SHARED)
                }
                else -> allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE)
            }
            neutralizeMacRandomization(this)
        }

    // addNetwork/enableNetwork — works on Android <10 and Android 10+ with Device Owner.
    // Returns false if addNetwork returns -1 (not available), so caller can try suggestions.
    @Suppress("MissingPermission")
    private fun legacyConnect(ssid: String, password: String?, security: String): Boolean {
        var netId = wm.addNetwork(buildLegacyConfig(ssid, password, security))
        if (netId == -1 && security.uppercase() == "WPA3" && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // SAE add still blocked (or rejected). A WPA2/WPA3 *transition* AP (RSN-PSK+SAE, the
            // common case for "WPA3" home/IoT networks) also accepts a plain WPA2-PSK association,
            // so retry as PSK to get a netId for the deterministic, sticky enableNetwork() path.
            Log.w(TAG, "SAE addNetwork failed for $ssid — retrying as WPA2-PSK (transition AP)")
            netId = wm.addNetwork(buildLegacyConfig(ssid, password, "WPA2"))
        }
        if (netId == -1) {
            // Privileged "modify MAC randomization" gate on GrapheneOS or an unsupported security
            // type — returning false lets the caller try the suggestion path.
            Log.w(TAG, "addNetwork returned -1 for $ssid ($security) — falling back to suggestion")
            return false
        }
        wm.disconnect()
        wm.enableNetwork(netId, true)   // disableOthers=true → forces this network AND holds it
        wm.reconnect()                  //   (other saved nets disabled for auto-join → no revert)
        return true
    }

    /**
     * Forget any agent-owned saved config or network suggestion for [ssid] so the next addNetwork is
     * a clean CREATE rather than an UPDATE. On GrapheneOS an UPDATE that changes macRandomization
     * trips a privileged permission gate (addNetwork → -1); a fresh CREATE with the baseline value
     * passes. Only touches the agent's OWN entries (a Device Owner can't remove others' networks).
     */
    @Suppress("MissingPermission", "DEPRECATION")
    private fun clearStaleForSsid(ssid: String) {
        val quoted = "\"$ssid\""
        try {
            wm.configuredNetworks?.filter { it.SSID == quoted }?.forEach {
                try { wm.removeNetwork(it.networkId) } catch (_: Throwable) {}
            }
            wm.saveConfiguration()
        } catch (t: Throwable) { Log.d(TAG, "clearStale configs: ${t.message}") }
        // Drop our prior network suggestions (only WifiHelper adds suggestions); empty list = remove all.
        try { wm.removeNetworkSuggestions(emptyList()) } catch (_: Throwable) {}
    }

    /** `WifiConfiguration.requirePmf` is @hide at compileSdk 34 — set it via reflection so a
     *  SAE/WPA3 config can negotiate Protected Management Frames. */
    private fun trySetRequirePmf(config: WifiConfiguration) {
        try {
            WifiConfiguration::class.java.getField("requirePmf").setBoolean(config, true)
        } catch (_: Throwable) { /* field unavailable — SAE may still associate in transition mode */ }
    }

    /**
     * GrapheneOS rejects `addNetwork()` with "does not have permission to modify MAC randomization
     * Settings" unless the config's `macRandomizationSetting` equals the per-network baseline the
     * OS treats as "unchanged": `RANDOMIZATION_ALWAYS` (100) on GrapheneOS, `RANDOMIZATION_PERSISTENT`
     * on stock Android. An app-built `WifiConfiguration` reaches the system with a different value,
     * so a Device Owner (which can add networks but isn't NETWORK_SETTINGS) trips the gate and
     * addNetwork returns -1. The field is @hide at compileSdk 34, so align it via reflection to the
     * running OS's own baseline constant. No-op on a runtime without these fields.
     */
    private fun neutralizeMacRandomization(config: WifiConfiguration) {
        try {
            val cls = WifiConfiguration::class.java
            val field = cls.getField("macRandomizationSetting")
            val before = field.getInt(config)
            var alwaysVal = Int.MIN_VALUE
            try { alwaysVal = cls.getField("RANDOMIZATION_ALWAYS").getInt(null) }
            catch (e: Throwable) { Log.w(TAG, "no RANDOMIZATION_ALWAYS const: ${e.message}") }
            val baseline = if (alwaysVal != Int.MIN_VALUE) alwaysVal
                           else try { cls.getField("RANDOMIZATION_PERSISTENT").getInt(null) } catch (_: Throwable) { 1 }
            field.setInt(config, baseline)
            // Belt-and-suspenders: also drive the public @SystemApi setter via reflection.
            try { cls.getMethod("setMacRandomizationSetting", Int::class.javaPrimitiveType).invoke(config, baseline) }
            catch (_: Throwable) { }
            Log.d(TAG, "macRand aligned: $before -> ${field.getInt(config)} (baseline=$baseline)")
        } catch (t: Throwable) { Log.d(TAG, "macRand align skipped: ${t.message}") }
    }

    // WifiNetworkSuggestion — works on Android 10+ without Device Owner.
    // Does NOT support WEP (API limitation). Triggers a scan so the OS notices the suggestion immediately.
    @RequiresApi(Build.VERSION_CODES.Q)
    @Suppress("MissingPermission")
    private fun suggestionConnect(ssid: String, password: String?, security: String): Boolean {
        if (security.uppercase() == "WEP") return false
        val builder = WifiNetworkSuggestion.Builder()
            .setSsid(ssid)
        if (!password.isNullOrEmpty()) {
            when (security.uppercase()) {
                "WPA3" -> builder.setWpa3Passphrase(password)
                else   -> builder.setWpa2Passphrase(password)
            }
        }
        val status = wm.addNetworkSuggestions(listOf(builder.build()))
        if (status != WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS &&
            status != WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE) {
            Log.w(TAG, "addNetworkSuggestions returned $status")
            return false
        }
        @Suppress("DEPRECATION")
        wm.startScan() // nudge the OS to scan and pick up the new suggestion
        return true
    }

    @Suppress("MissingPermission")
    private fun waitForSsid(ssid: String, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val info = wm.connectionInfo
            if (info?.ssid?.trim('"') == ssid && info.ipAddress != 0) return true
            Thread.sleep(500)
        }
        return false
    }

    fun detectCaptivePortal(): String? {
        val net = findWifiNetwork() ?: return null
        return try {
            val conn = net.openConnection(URL("http://connectivitycheck.gstatic.com/generate_204")) as HttpURLConnection
            conn.instanceFollowRedirects = false
            conn.connectTimeout = 5_000
            conn.readTimeout    = 5_000
            conn.connect()
            val code = conn.responseCode
            val loc  = conn.getHeaderField("Location")
            conn.disconnect()
            if (code in 300..399 && !loc.isNullOrBlank()) loc else null
        } catch (e: Exception) {
            Log.d(TAG, "captive portal probe: ${e.message}")
            null
        }
    }

    fun submitCaptivePortal(url: String, method: String, body: String, callback: (JSONObject) -> Unit) {
        Thread {
            try {
                val net = findWifiNetwork() ?: run { callback(err("No WiFi network")); return@Thread }
                val conn = openConn(net, url)
                conn.requestMethod  = method.uppercase()
                conn.connectTimeout = 10_000
                conn.readTimeout    = 10_000
                conn.instanceFollowRedirects = true
                if (method.uppercase() == "POST" && body.isNotEmpty()) {
                    conn.doOutput = true
                    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                    conn.outputStream.bufferedWriter().use { it.write(body) }
                }
                conn.connect()
                val code = conn.responseCode
                conn.disconnect()
                Thread.sleep(3_000)
                // Raw-socket generate_204 probe — HttpURLConnection enforces the cleartext policy,
                // which blocks plain http:// probes and made the old checkInternet() always report
                // failure on captive http URLs. CaptivePortalHelper.probeClear bypasses that.
                val ok = CaptivePortalHelper.probeClear(net)
                callback(JSONObject().apply { put("success", ok); put("httpCode", code) })
            } catch (e: Exception) {
                callback(err(e.message ?: "Unknown error"))
            }
        }.start()
    }

    private fun fetchOnWifi(urlStr: String): String {
        val conn = openConn(findWifiNetwork(), urlStr)
        conn.connectTimeout = 10_000
        conn.readTimeout    = 10_000
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android)")
        conn.connect()
        val html = conn.inputStream.bufferedReader().readText()
        conn.disconnect()
        return html
    }

    private fun openConn(net: Network?, urlStr: String): HttpURLConnection =
        if (net != null) net.openConnection(URL(urlStr)) as HttpURLConnection
        else URL(urlStr).openConnection() as HttpURLConnection

    private fun findWifiNetwork(): Network? =
        cm.allNetworks.firstOrNull { net ->
            cm.getNetworkCapabilities(net)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }

    private fun err(msg: String) = JSONObject().apply { put("success", false); put("error", msg) }
}
