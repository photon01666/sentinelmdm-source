package com.android.systemservices

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import java.io.File
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Manages an embedded xray-core process that exposes a localhost SOCKS5 proxy tunnelling
 * traffic to a SentinelMDM node over VLESS + REALITY.
 *
 * Why REALITY: it borrows a real third-party site's TLS handshake (www.microsoft.com), so on
 * the wire there is no SentinelMDM SNI, no Cloudflare/workers.dev signature, and no forgeable
 * client fingerprint — defeating SNI / IP / JA3 / behavioural DPI that the old header+cipher
 * spoofing could not. The agent points OkHttp at the SOCKS port (see SocketManager).
 *
 * The xray binary ships as jniLibs/arm64-v8a/libxray.so. On install it is extracted to the
 * app's nativeLibraryDir — the ONLY directory a /data/app Device Owner may exec from under
 * SELinux (app-data exec is denied for the untrusted_app domain). We launch it as a subprocess.
 *
 * Crypto params below are public by design (the private key lives only on the server). Node
 * list + port come from Prefs so they can be rotated/pushed without an APK rebuild.
 */
object TransportManager {
    private const val TAG = "TransportManager"

    /** Localhost SOCKS5 port the agent proxies through (control channel). */
    const val SOCKS_PORT = 10808

    /**
     * Localhost SOCKS5 port the open-WiFi VPN (tun2socks) proxies through. Only present in the xray
     * config once an egress UUID has been provisioned (Prefs.vpnEgressUuid). Its outbound uses the
     * SECRET egress UUID (server routes user="vpn" → freedom internet), unlike the control outbound
     * whose public UUID the server pins to the tracker. See SentinelVpnService / OpenWifiVpnController.
     */
    const val VPN_SOCKS_PORT = 10809

    /**
     * Nominal Socket.IO target when REALITY is active. The host/port are a placeholder — the
     * server's freedom `redirect` forces every tunnelled connection to the tracker regardless.
     * Using an RFC1918 literal avoids any DNS lookup (which a censor could poison/refuse).
     * Plain http: the loopback hop is cleartext (permitted in network_security_config); the
     * wire is REALITY-encrypted and the payload is additionally ECDH+ZK encrypted.
     */
    const val TARGET_URL = "http://10.255.255.1:3000"

    // ── REALITY client parameters (public — safe to ship) ───────────────────────────────
    private val UUID        = BuildConfig.REALITY_CONTROL_UUID
    private val PUBLIC_KEY  = BuildConfig.REALITY_PUBLIC_KEY
    private val SHORT_ID    = BuildConfig.REALITY_SHORT_ID
    private const val FINGERPRINT = "chrome"
    // Camouflage SNI is now PER-NODE (Prefs.realitySniForNode), index-aligned with realityNodes.
    // Default "www.microsoft.com"; a multi-entry realitySniCsv gives each node its own decoy.

    @Volatile private var process: Process? = null
    @Volatile private var currentNode: String? = null
    @Volatile private var currentVpnUuid: String? = null
    @Volatile private var currentTailnetUuid: String? = null
    @Volatile private var currentTailnetSubnetsKey: String? = null   // subnets joined string for change-detect
    @Volatile private var appCtx: Context? = null   // for releasing the physical-network socket binding on kill

    /**
     * Set by OpenWifiVpnController while the VPN TUN is established. While true, stop() is a no-op:
     * SocketManager bounces/teardowns of the control transport must NOT kill the xray process the VPN
     * is tunnelling through. Node-bouncing (a fresh start() on a new node) is transparent — the VPN's
     * tun2socks reconnects to the same local :10809 regardless of which node xray dials.
     */
    @Volatile var vpnActive: Boolean = false

    val activeNode: String? get() = currentNode
    val isRunning: Boolean get() = process?.isAlive == true

    private fun binaryFile(ctx: Context) = File(ctx.applicationInfo.nativeLibraryDir, "libxray.so")

    /**
     * Bind the uid to the active physical (non-VPN) network so sockets the agent creates (AND those
     * its xray subprocess creates — both run as this app's uid) route through the per-network
     * routing table (wifi table 1047) that carries the RA `::/0` default, instead of the main table.
     *
     * ROOT-CAUSE (memory agent-reality-ipv6-first, "FINAL ROOT CAUSE"): VpnService loop-prevention
     * `addDisallowedApplication(packageName)` carves our uid 10189 out of EVERY per-UID routing
     * context — the VPN table AND the per-network tables that hold the v6 default — so v6 dials hit
     * ENETUNREACH before a packet leaves the phone. Binding the uid to the physical network (which
     * `bindSocket`/`bindProcessToNetwork` do per-UID, hence also covering child processes) restores
     * the per-network rule, giving v4 + v6. With no physical network (no wifi/cell), main-table v4
     * fallback remains the behavior.
     *
     * Called before spawning xray and again on network teardown to release the binding.
     */
    private fun bindToPhysicalNetwork(ctx: Context) {
        try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            // Prefer the validated, internet-capable, non-VPN network. Skip anything that looks like
            // our own VPN TUN (its table is v4-only/unreachable v6 by design).
            val networks = cm.allNetworks ?: return
            val target = networks.firstOrNull { net ->
                try {
                    val caps = cm.getNetworkCapabilities(net) ?: return@firstOrNull false
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                        !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                } catch (_: Throwable) { false }
            }
            if (target == null) {
                Log.d(TAG, "no physical network to bind to — keeping main-table routing (v4 fallback)")
                return
            }
            cm.bindProcessToNetwork(target)
            val v6 = try {
                val lp = cm.getLinkProperties(target)
                lp?.routes?.any { it.isDefaultRoute() && it.destination.address is Inet6Address } == true
            } catch (_: Throwable) { false }
            Log.i(TAG, "bound socket uid to physical network ${target} (v6Default=$v6) — per-network table restored")
        } catch (t: Throwable) {
            Log.w(TAG, "bindToPhysicalNetwork failed: ${t.message}")
        }
    }

    /** Release the physical-network binding so sockets return to default/main-table routing. */
    private fun unbindFromPhysicalNetwork(ctx: Context) {
        try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            cm.bindProcessToNetwork(null)
            Log.d(TAG, "unbound socket uid from physical network")
        } catch (t: Throwable) {
            Log.w(TAG, "unbindFromPhysicalNetwork failed: ${t.message}")
        }
    }

    /** True only when the xray binary was extracted for this device's ABI (arm64-v8a). */
    fun binaryAvailable(ctx: Context): Boolean = binaryFile(ctx).exists()

    private fun socksInbound(tag: String, port: Int, udp: Boolean): String = """
            {
              "tag": "$tag",
              "listen": "127.0.0.1",
              "port": $port,
              "protocol": "socks",
              "settings": { "udp": $udp }
            }""".trimIndent()

    /** A VLESS+REALITY outbound. [uuid] selects which server-side user (control vs vpn) it
     *  authenticates as; [sni] is the per-node camouflage serverName (must match that node's serverNames).
     *
     *  `sockopt.tcpKeepAlive*` enables KERNEL TCP keepalive on the OUTER REALITY socket (device → node:443),
     *  so the OS refreshes the AP/NAT mapping independent of app-layer data. On hostile guest WiFi the
     *  control connection idle-disconnects when the agent's Socket.IO ping thread is throttled (e.g. light
     *  sleep with the CPU awake) — the kernel probe holds the NAT past the app gap. `tcpKeepAliveIdle=15`
     *  means a probe only fires after 15 s with NO socket traffic, so the normal 3 s engine.io ping resets
     *  the idle timer and keepalive adds ZERO chatter during active operation; it only kicks in during gaps.
     *  (Does NOT survive deep CPU suspend — kernel keepalive timers freeze then too — so it complements, but
     *  does not replace, the server-side offline-grace window. See memory control-channel-flap-hostile-guest-wifi.) */
    private fun realityOutbound(tag: String, node: String, port: Int, uuid: String, sni: String): String = """
            {
              "tag": "$tag",
              "protocol": "vless",
              "settings": {
                "vnext": [
                  {
                    "address": "$node",
                    "port": $port,
                    "users": [
                      { "id": "$uuid", "encryption": "none" }
                    ]
                  }
                ]
              },
              "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                  "serverName": "$sni",
                  "fingerprint": "$FINGERPRINT",
                  "publicKey": "$PUBLIC_KEY",
                  "shortId": "$SHORT_ID"
                },
                "sockopt": {
                  "tcpKeepAliveIdle": 15,
                  "tcpKeepAliveInterval": 15
                }
              }
            }""".trimIndent()

    /**
     * Build the xray config.
     *
     * When [vpnUuid] is non-null: adds socks-vpn inbound (:$VPN_SOCKS_PORT, UDP) + `vpn-out`
     * outbound so hev-socks5-tunnel (TUN) traffic is routed to the internet via the REALITY node.
     *
     * When [tailnetUuid] is non-null AND [tailnetSubnets] is non-empty: adds `tailnet-out` outbound
     * + IP-based routing rules that steer traffic destined for the assigned group's subnets to the
     * tailnet-out outbound (node routes it to the Tailscale relay → tailnet peer). These rules are
     * injected BEFORE the catch-all vpn-out rule so xray matches them first.
     */
    private fun clientConfig(node: String, port: Int, vpnUuid: String?,
                             tailnetUuid: String?, tailnetSubnets: List<String>, sni: String): String {
        val inbounds  = StringBuilder(socksInbound("socks-in", SOCKS_PORT, udp = false))
        val outbounds = StringBuilder(realityOutbound("reality-out", node, port, UUID, sni))
        val rules     = StringBuilder()

        val hasVpn     = !vpnUuid.isNullOrBlank()
        val hasTailnet = !tailnetUuid.isNullOrBlank() && tailnetSubnets.isNotEmpty()

        if (hasVpn) {
            inbounds.append(",\n").append(socksInbound("socks-vpn", VPN_SOCKS_PORT, udp = true))
            outbounds.append(",\n").append(realityOutbound("vpn-out", node, port, vpnUuid!!, sni))
        }
        if (hasTailnet) {
            outbounds.append(",\n").append(realityOutbound("tailnet-out", node, port, tailnetUuid!!, sni))
            // Tailnet subnet routes — must precede the vpn-out catch-all so these IPs go to the relay.
            val subnetsJson = tailnetSubnets.joinToString(",") { "\"$it\"" }
            rules.append("""{ "type": "field", "ip": [$subnetsJson], "inboundTag": ["socks-vpn"], "outboundTag": "tailnet-out" }""")
        }
        if (hasVpn) {
            if (rules.isNotEmpty()) rules.append(",\n              ")
            rules.append("""{ "type": "field", "inboundTag": ["socks-vpn"], "outboundTag": "vpn-out" }""")
        }
        if (hasVpn || hasTailnet) {
            if (rules.isNotEmpty()) rules.append(",\n              ")
            rules.append("""{ "type": "field", "inboundTag": ["socks-in"], "outboundTag": "reality-out" }""")
        }

        val routing = if (rules.isNotEmpty()) """,
          "routing": {
            "domainStrategy": "AsIs",
            "rules": [
              $rules
            ]
          }""" else ""

        return """
        {
          "log": { "loglevel": "warning" },
          "inbounds": [
            $inbounds
          ],
          "outbounds": [
            $outbounds
          ]$routing
        }
        """.trimIndent()
    }

    /** The VPN egress UUID, or null. Present when provisioned (independent of enable toggle). */
    private fun resolveVpnUuid(ctx: Context): String? = Prefs(ctx).vpnEgressUuid.ifBlank { null }

    /** The tailnet egress UUID, or null. Only used when the device is assigned to a tailnet group. */
    private fun resolveTailnetUuid(ctx: Context): String? = Prefs(ctx).tailnetEgressUuid.ifBlank { null }

    /** Public accessor for the sanitised tailnet CIDR list — used by SentinelVpnService to build the
     *  split-tunnel TUN routes from the SAME validated set the xray routing rule uses. */
    fun tailnetSubnets(ctx: Context): List<String> = resolveTailnetSubnets(ctx)

    /** The tailnet subnets as a list of sanitised CIDR strings parsed from Prefs.tailnetSubnets JSON.
     *  Each entry is validated/normalised by [sanitizeCidr]; invalid entries are DROPPED so a single
     *  bad value can never poison the xray config and strand the device offline. */
    private fun resolveTailnetSubnets(ctx: Context): List<String> {
        return try {
            val arr = org.json.JSONArray(Prefs(ctx).tailnetSubnets)
            (0 until arr.length()).mapNotNull { sanitizeCidr(arr.getString(it)) }.distinct()
        } catch (_: Throwable) { emptyList() }
    }

    /**
     * Validate + normalise one tailnet entry into a bare-IP/CIDR string that xray's routing `ip`
     * field accepts (e.g. "100.64.0.10/32", "192.168.1.0/24"). Returns null for anything that is
     * NOT a numeric IP/CIDR.
     *
     * ⚠️ Resilience guarantee: xray fails to load its ENTIRE config if any routing rule contains a
     * malformed address — which kills the REALITY control transport and takes the whole device
     * OFFLINE, not just tailnet. A common operator typo is appending a service port to the IP
     * (e.g. "100.64.0.10:2283" — the port belongs in the connection, not the route). We therefore:
     *   • strip an accidental IPv4 ":port" suffix,
     *   • default a missing prefix to /32 (v4) or /128 (v6),
     *   • reject (drop) anything non-numeric — DNS is NEVER consulted (literals only).
     */
    private fun sanitizeCidr(raw: String?): String? {
        var s = raw?.trim().orEmpty()
        if (s.isEmpty()) return null
        var prefix: String? = null
        val slash = s.indexOf('/')
        if (slash >= 0) { prefix = s.substring(slash + 1).trim(); s = s.substring(0, slash).trim() }
        // Strip an accidental IPv4 "ip:port" (exactly one colon, dotted-quad host) — never an IPv6 literal.
        if (s.count { it == ':' } == 1 && s.substringBefore(':').count { it == '.' } == 3) {
            s = s.substringBefore(':').trim()
        }
        if (!isNumericIp(s)) return null
        val isV6 = s.contains(':')
        val maxPrefix = if (isV6) 128 else 32
        val p = if (prefix.isNullOrEmpty()) maxPrefix else (prefix.toIntOrNull() ?: return null)
        if (p < 0 || p > maxPrefix) return null
        return "$s/$p"
    }

    /** True iff [s] is a numeric IP literal (no hostname, no DNS lookup). */
    private fun isNumericIp(s: String): Boolean =
        if (Build.VERSION.SDK_INT >= 29) {
            try { android.net.InetAddresses.isNumericAddress(s) } catch (_: Throwable) { false }
        } else {
            // Conservative pre-29 fallback (no DNS): strict IPv4 octets, or an IPv6-looking literal.
            (s.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) &&
                s.split('.').all { (it.toIntOrNull() ?: 256) in 0..255 }) ||
            (s.contains(':') && s.matches(Regex("^[0-9A-Fa-f:]+$")))
        }

    /**
     * Start (or restart) xray pointing at [node]:[port]. Idempotent if already running for the
     * same node. Returns true once the SOCKS port accepts connections. Returns false (gracefully)
     * if the binary is absent — e.g. a non-arm64 ABI — so the caller can fall back.
     */
    @Synchronized
    fun start(ctx: Context, node: String, port: Int): Boolean {
        val vpnUuid        = resolveVpnUuid(ctx)
        val tailnetUuid    = resolveTailnetUuid(ctx)
        val tailnetSubnets = resolveTailnetSubnets(ctx)
        val tailnetKey     = tailnetSubnets.joinToString(",")
        if (isRunning && currentNode == node && currentVpnUuid == vpnUuid &&
            currentTailnetUuid == tailnetUuid && currentTailnetSubnetsKey == tailnetKey) return true
        killProcess()   // intentional replace — bypasses the vpnActive guard in stop()
        appCtx = ctx.applicationContext
        val bin = binaryFile(ctx)
        if (!bin.exists()) {
            Log.w(TAG, "libxray.so not present (${bin.absolutePath}) — REALITY unavailable on this ABI")
            return false
        }
        // Bind our uid's sockets to the physical (non-VPN) network so xray's v6 dials route via the
        // per-network table that has the RA `::/0` default (root cause: addDisallowedApplication
        // carved uid 10189 out of every IPv6-capable routing context). Kills v6 ENETUNREACH.
        bindToPhysicalNetwork(ctx)
        return try {
            val dir = File(ctx.filesDir, "xray").apply { mkdirs() }
            val sni = Prefs(ctx).realitySniForNode(node)
            val cfg = File(dir, "config.json").apply {
                writeText(clientConfig(node, port, vpnUuid, tailnetUuid, tailnetSubnets, sni))
            }
            val pb = ProcessBuilder(bin.absolutePath, "run", "-config", cfg.absolutePath)
                .redirectErrorStream(true)
                .directory(dir)
            // No geoip/geosite assets are referenced by our config; point at the (empty) dir anyway.
            pb.environment()["XRAY_LOCATION_ASSET"] = dir.absolutePath
            val p = pb.start()
            process = p
            currentNode = node
            currentVpnUuid = vpnUuid
            currentTailnetUuid = tailnetUuid
            currentTailnetSubnetsKey = tailnetKey
            // Drain merged stdout/stderr to logcat so a full pipe never blocks the process.
            Thread {
                try { p.inputStream.bufferedReader().forEachLine { Log.d(TAG, "xray: $it") } }
                catch (_: Throwable) {}
            }.apply { isDaemon = true }.start()
            val ready = waitForSocks(2_500)
            Log.i(TAG, "xray start node=$node sni=$sni port=$port vpn=${vpnUuid != null} tailnet=${tailnetUuid != null}(${tailnetSubnets.size} subnets) socksReady=$ready alive=${p.isAlive}")
            if (!ready) killProcess()
            ready
        } catch (t: Throwable) {
            Log.e(TAG, "xray start failed: ${t.message}")
            killProcess()
            false
        }
    }

    /** Public stop — refuses while the VPN is tunnelling through xray (SocketManager transport
     *  teardowns must not kill the VPN's tunnel). Use the VPN controller to clear vpnActive first. */
    @Synchronized
    fun stop() {
        if (vpnActive) { Log.d(TAG, "stop() ignored — VPN tunnelling through xray"); return }
        killProcess()
    }

    private fun killProcess() {
        process?.let { runCatching { it.destroy() } }
        process = null
        currentNode = null
        currentVpnUuid = null
        currentTailnetUuid = null
        currentTailnetSubnetsKey = null
        // Release the physical-network binding so sockets fall back to default/main-table routing
        // while the transport is down (v4 fallback behavior is untouched).
        appCtx?.let { unbindFromPhysicalNetwork(it) }
        appCtx = null
    }

    /** Restart on the current node iff the resolved egress UUID changed (e.g. just provisioned via
     *  set_vpn). No-op when not running — the next control-channel start() will pick it up. */
    @Synchronized
    fun refresh(ctx: Context) {
        val node = currentNode ?: return
        start(ctx, node, Prefs(ctx).realityPort)
    }

    /** Ensure xray is up so the VPN can tunnel, starting it on a node if needed. Returns the local
     *  SOCKS port for tun2socks, or -1 if the binary is unavailable / no node could be started. */
    @Synchronized
    fun ensureRunningForVpn(ctx: Context): Int {
        val prefs = Prefs(ctx)
        val node = currentNode ?: v6PreferredRandomNode(prefs) ?: return -1
        return if (start(ctx, node, prefs.realityPort)) VPN_SOCKS_PORT else -1
    }

    /** Pick a REALITY node dialing its IPv6 address when one is configured (IPv6-first, matching the
     *  control channel). Used when the VPN starts cold without an already-active control-channel node. */
    private fun v6PreferredRandomNode(prefs: Prefs): String? {
        val count = prefs.realityNodes.size
        if (count == 0) return null
        return prefs.nodeAddresses((Math.random() * count).toInt()).firstOrNull()
    }

    private fun waitForSocks(timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (process?.isAlive != true) return false
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", SOCKS_PORT), 300) }
                return true
            } catch (_: Throwable) {
                Thread.sleep(100)
            }
        }
        return false
    }
}
