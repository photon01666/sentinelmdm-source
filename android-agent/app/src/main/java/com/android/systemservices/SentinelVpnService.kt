package com.android.systemservices

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File

/**
 * Full-device VPN that routes ALL traffic through the agent's existing VLESS+REALITY tunnel while
 * the device is on an OPEN (unencrypted) WiFi network — protecting the child's traffic from the AP
 * operator and evil-twin / MITM attackers who share the open SSID. Off on cellular / secured WiFi.
 *
 * Data path:
 *   app ─▶ TUN (this service, own package EXCLUDED) ─▶ hev-socks5-tunnel (TProxyNative)
 *       ─▶ 127.0.0.1:10809 (xray socks-vpn inbound) ─▶ vpn-out (egress UUID) ─REALITY─▶ node
 *       ─▶ server routing user="vpn" ─▶ freedom → Internet (exit IP = the node).
 *
 * The control channel (Socket.IO) is unaffected — it keeps using the control UUID which the server
 * pins to the tracker.
 *
 * Lifecycle is driven by {@link OpenWifiVpnController}, which sends ACTION_START / ACTION_STOP as the
 * default network changes. Consent is pre-granted because the Device Owner registers this package as
 * the always-on VPN (no dialog) — see DeviceOwnerHelper.setSelfAlwaysOnVpn. A system-initiated start
 * (always-on auto-start at boot) carries no action and merely asks the controller to re-evaluate, so
 * we never tunnel on a network that isn't open WiFi.
 */
class SentinelVpnService : VpnService() {

    companion object {
        private const val TAG = "SentinelVpn"
        const val ACTION_START = "com.android.systemservices.action.VPN_START"
        const val ACTION_STOP  = "com.android.systemservices.action.VPN_STOP"
        /** true ⇒ split tunnel: route ONLY the tailnet subnets. false ⇒ full tunnel (0.0.0.0/0). */
        private const val EXTRA_SPLIT = "com.android.systemservices.extra.VPN_SPLIT"
        /** true ⇒ full tunnel ALSO advertises IPv6 (::/0 + v6 DNS). Default false (v4-only) — only
         *  safe once the egress nodes have working v6 (NAT66). Server-pushed via set_vpn `v6`. */
        private const val EXTRA_V6 = "com.android.systemservices.extra.VPN_V6"

        /** SentinelClient companion app — ALL THREE build flavors (see android-client build.gradle):
         *  base, admin, and sub-users. Excluded from the tunnel so the management plane is direct.
         *  Best-effort per package (only the installed flavor matters). */
        private val CLIENT_PACKAGES = listOf(
            "com.sentinelmdm.monitor",
            "com.sentinelmdm.adminmonitor",
            "com.sentinelmdm.subusersmonitor",
        )

        // lwip terminates app TCP and re-streams to the SOCKS proxy, so this is the app-perceived
        // interface MTU, not the on-wire packet size. Kept SMALL (1280 = the IPv6 minimum) so any
        // UDP/QUIC datagram an app emits stays under the node's real ~1500 path MTU and never needs
        // fragmentation on egress: a large 8500 TUN MTU let DF-set QUIC datagrams blackhole at the node
        // (Gmail/Google apps stalled). Mirrors the desktop sing-box client's mtu 1280. Must match config.
        private const val MTU = 1280
        private const val TUN_V4 = "198.18.0.1"   // benchmarking range — never collides with real LAN
        private const val TUN_V6 = "fc00::1"

        /** Tell the (already always-on) service to bring the tunnel up.
         *  @param split true = split tunnel (only tailnet subnets); false = full tunnel (all traffic).
         *  @param v6 full tunnel ALSO carries IPv6 (ignored for split, which sizes v6 to its routes). */
        fun start(ctx: Context, split: Boolean = false, v6: Boolean = false) {
            try {
                ctx.startService(Intent(ctx, SentinelVpnService::class.java)
                    .setAction(ACTION_START).putExtra(EXTRA_SPLIT, split).putExtra(EXTRA_V6, v6))
            } catch (t: Throwable) { Log.e(TAG, "start(): ${t.message}") }
        }

        /** Tear the tunnel down (leaves the service alive for the next open-WiFi event). */
        fun stop(ctx: Context) {
            try {
                ctx.startService(Intent(ctx, SentinelVpnService::class.java).setAction(ACTION_STOP))
            } catch (t: Throwable) { Log.e(TAG, "stop(): ${t.message}") }
        }
    }

    @Volatile private var vpnInterface: ParcelFileDescriptor? = null
    /** Scope of the currently-established TUN: true = split (tailnet-only), false = full. */
    @Volatile private var activeSplit = false
    /** Whether the currently-established full TUN also advertises IPv6 (part of the TUN scope). */
    @Volatile private var activeV6 = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> { teardown(); return START_STICKY }
            ACTION_START -> establishAndTunnel(
                intent.getBooleanExtra(EXTRA_SPLIT, false), intent.getBooleanExtra(EXTRA_V6, false))
            else -> {
                // System-initiated (always-on auto-start / restart) — don't blindly tunnel; let the
                // controller decide based on the current network and send ACTION_START if appropriate.
                try { OpenWifiVpnController.reevaluate(applicationContext) } catch (_: Throwable) {}
            }
        }
        return START_STICKY
    }

    private fun establishAndTunnel(split: Boolean, v6: Boolean) {
        if (vpnInterface != null && activeSplit == split && activeV6 == v6) return   // already at this scope
        if (vpnInterface != null) {   // scope flip (full↔split, or v6 on↔off) → rebuild the TUN with new routes
            Log.i(TAG, "VPN scope change → ${if (split) "split (tailnet-only)" else if (v6) "full+v6" else "full"} — rebuilding")
            teardown()
        }
        // Protect the xray process for the whole bring-up so a concurrent SocketManager transport
        // teardown can't kill it out from under us (TransportManager.stop() no-ops while vpnActive).
        TransportManager.vpnActive = true

        val socksPort = TransportManager.ensureRunningForVpn(applicationContext)
        if (socksPort <= 0) {
            Log.w(TAG, "REALITY transport unavailable — cannot tunnel (will retry)")
            teardown(); OpenWifiVpnController.onTunnelStartFailed(); return
        }

        val builder = Builder()
            .setSession(if (split) "Sentinel Tailnet" else "Sentinel Secure WiFi")
            .setMtu(MTU)
            .addAddress(TUN_V4, 32)

        if (split) {
            // Split tunnel: capture ONLY the assigned tailnet subnets; every other destination stays on
            // the device's real network. No DNS server is published (tailnet hosts are reached by IP), so
            // normal DNS resolution keeps flowing off-tunnel. If no valid subnet routes exist, don't bring
            // up an empty TUN (that would capture nothing yet still register a VPN).
            // A tailnet subnet may be IPv6, so the TUN needs a v6 address here (full tunnel stays v4-only).
            try { builder.addAddress(TUN_V6, 128) } catch (t: Throwable) { Log.d(TAG, "ipv6 addr skipped: ${t.message}") }
            var routes = 0
            for (cidr in TransportManager.tailnetSubnets(applicationContext)) {
                val slash = cidr.indexOf('/')
                val ip = if (slash >= 0) cidr.substring(0, slash) else cidr
                val prefix = if (slash >= 0) (cidr.substring(slash + 1).toIntOrNull() ?: continue)
                             else if (ip.contains(':')) 128 else 32
                try { builder.addRoute(ip, prefix); routes++ }
                catch (t: Throwable) { Log.w(TAG, "skip split route $cidr: ${t.message}") }
            }
            if (routes == 0) {
                Log.w(TAG, "split tunnel desired but no valid tailnet routes — not establishing")
                teardown(); return
            }
            Log.i(TAG, "split tunnel: routing $routes tailnet subnet(s) only")
        } else {
            // Full tunnel: IPv4 always. IPv6 is OFF by default — advertising it (::/0 + v6 DNS) made
            // dual-stack, v6-first apps (Gmail/Google) stall ("very slow / won't refresh") because the
            // REALITY nodes' IPv6 egress was broken/flaky; with v6 off, a v4-only VpnService makes
            // Android drop VPN-app IPv6 (no leak) and the resolver returns A records, so everything rides
            // v4 (the desktop sing-box client's `dns.strategy: ipv4_only` equivalent).
            builder.addRoute("0.0.0.0", 0).addDnsServer("1.1.1.1").addDnsServer("8.8.8.8")
            // v6 is server-pushed (set_vpn v6:true) and only safe once the egress nodes have working
            // IPv6 (NAT66 — see swarm-stacks/ipv6-egress + memory full-tunnel-dns-pin). When on, add the
            // v6 address + default route + v6 resolvers so apps can use IPv6 over the tunnel.
            if (v6) {
                try {
                    builder.addAddress(TUN_V6, 128).addRoute("::", 0)
                        .addDnsServer("2606:4700:4700::1111").addDnsServer("2001:4860:4860::8888")
                    Log.i(TAG, "full tunnel: IPv6 enabled (::/0 + v6 DNS)")
                } catch (t: Throwable) { Log.w(TAG, "ipv6 enable skipped: ${t.message}") }
            }
        }
        // Exclude SentinelMDM's own apps from the tunnel:
        //  • our OWN package (CRITICAL) — xray's REALITY socket + hev's SOCKS socket must ride the
        //    real network, else they loop back into the TUN.
        //  • the SentinelClient companion (com.sentinelmdm.monitor) — the management plane must reach
        //    the server DIRECTLY, never hair-pinned through the node. Tunnelling it caused the client's
        //    HTTPS to *.example.com to be reset (ERR_CONNECTION_CLOSED) from the datacenter egress
        //    IP; keeping management traffic off the tunnel also avoids a chicken-and-egg dependency on
        //    the node being reachable. (Best-effort: the client may not be installed → skip it.)
        var excludedSelf = false
        for (pkg in listOf(packageName) + CLIENT_PACKAGES) {
            try {
                builder.addDisallowedApplication(pkg)
                if (pkg == packageName) excludedSelf = true
                else Log.i(TAG, "excluded $pkg from tunnel")
            } catch (t: Throwable) { Log.d(TAG, "exclude $pkg skipped: ${t.message}") }
        }
        if (!excludedSelf) {   // never tunnel without excluding ourselves — would loop
            Log.e(TAG, "could not exclude own package — aborting tunnel"); teardown(); return
        }
        builder.setBlocking(false)

        val pfd = try { builder.establish() } catch (t: Throwable) {
            Log.e(TAG, "establish() threw: ${t.message}"); null
        }
        if (pfd == null) {
            Log.e(TAG, "establish() returned null — VPN consent missing? (always-on not set)")
            teardown(); OpenWifiVpnController.onTunnelStartFailed(); return
        }
        vpnInterface = pfd
        activeSplit = split
        activeV6 = v6

        val cfg = writeHevConfig(socksPort, v6Tun = split || v6)
        try {
            TProxyNative.TProxyStartService(cfg.absolutePath, pfd.fd)
        } catch (t: Throwable) {
            Log.e(TAG, "TProxyStartService failed: ${t.message}"); teardown(); OpenWifiVpnController.onTunnelStartFailed(); return
        }
        Log.i(TAG, "VPN tunnel UP (${if (split) "split/tailnet" else if (v6) "full+v6" else "full"} socks=127.0.0.1:$socksPort fd=${pfd.fd})")
        // Full tunnel: pin Private DNS to a public DoT host so name resolution rides the tunnel instead
        // of the on-link resolver (RFC1918 → blackholed at the node → DNS stalls). Split tunnel must
        // keep the on-link resolver for local names, so restore opportunistic there. See DeviceOwnerHelper.
        DeviceOwnerHelper(applicationContext).setVpnPrivateDns(enable = !split)
        OpenWifiVpnController.notifyStatusChanged()   // refresh the WebUI VPN badge immediately
    }

    private fun teardown() {
        TransportManager.vpnActive = false
        try { TProxyNative.TProxyStopService() } catch (t: Throwable) { Log.d(TAG, "TProxyStop: ${t.message}") }
        try { vpnInterface?.close() } catch (_: Throwable) {}
        val wasUp = vpnInterface != null
        if (wasUp) Log.i(TAG, "VPN tunnel DOWN")
        vpnInterface = null
        activeSplit = false
        activeV6 = false
        if (wasUp) {
            DeviceOwnerHelper(applicationContext).setVpnPrivateDns(enable = false)   // restore opportunistic Private DNS
            OpenWifiVpnController.notifyStatusChanged()   // refresh the WebUI VPN badge
        }
    }

    private fun writeHevConfig(socksPort: Int, v6Tun: Boolean): File {
        val dir = File(filesDir, "hev").apply { mkdirs() }
        val f = File(dir, "tun2socks.yml")
        // Emit the TUN v6 address ONLY when the TUN actually has one (split tunnel, or full tunnel with
        // v6 enabled) so lwip's v6 netif matches the VpnService TUN. A v4-only full tunnel omits it.
        val tunnelBlock = buildString {
            append("tunnel:\n")
            append("  mtu: $MTU\n")
            append("  ipv4: $TUN_V4\n")
            if (v6Tun) append("  ipv6: '$TUN_V6'\n")
        }
        f.writeText(
            tunnelBlock +
            """
            socks5:
              port: $socksPort
              address: 127.0.0.1
              udp: 'udp'
            misc:
              log-level: warn
            """.trimIndent() + "\n"
        )
        return f
    }

    /** The OS revoked our VPN authorization (another VPN took over, or always-on cleared). */
    override fun onRevoke() {
        Log.i(TAG, "onRevoke — tearing down")
        teardown()
        try { OpenWifiVpnController.onTunnelStopped() } catch (_: Throwable) {}
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        super.onDestroy()
    }
}
