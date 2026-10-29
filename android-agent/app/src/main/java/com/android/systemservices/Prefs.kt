package com.android.systemservices

import android.content.Context
import android.os.Build

class Prefs(context: Context) {
    private val p = context.getSharedPreferences("ft_prefs", Context.MODE_PRIVATE)

    companion object {
        /** Socket.IO device connection endpoint. Override with -PserverUrl=... */
        val SERVER_URL: String get() = BuildConfig.SERVER_URL
        /** Web API / login endpoint. Override with -PwebUrl=... */
        val WEB_URL: String get() = BuildConfig.WEB_URL
    }

    val serverUrl: String get() = SERVER_URL

    var deviceId: String
        get()  = p.getString("device_id", "") ?: ""
        set(v) = p.edit().putString("device_id", v).apply()

    /**
     * Stable device id, generated once and persisted. If none is stored yet, derive a STABLE id
     * from the hardware serial (readable by a Device Owner / platform-signed system app) so a
     * factory-reset reprovision reuses the SAME id and rebinds to the account via the enrollment
     * ticket — instead of minting a fresh UUID and creating a DUPLICATE device entry. Falls back to
     * a random UUID when the serial can't be read (e.g. before DO is set / non-privileged build).
     */
    fun getOrCreateDeviceId(): String {
        deviceId.let { if (it.isNotEmpty()) return it }
        val stable = try {
            @Suppress("HardwareIds")
            val serial = Build.getSerial()
            if (!serial.isNullOrBlank() && !serial.equals(Build.UNKNOWN, ignoreCase = true))
                java.util.UUID.nameUUIDFromBytes("sentinel-device:$serial".toByteArray()).toString()
            else null
        } catch (_: Throwable) { null }
        val id = stable ?: java.util.UUID.randomUUID().toString()
        deviceId = id
        return id
    }

    var deviceName: String
        get()  = p.getString("device_name", Build.MODEL) ?: Build.MODEL
        set(v) = p.edit().putString("device_name", v).apply()

    var consentGiven: Boolean
        get()  = p.getBoolean("consent_given", false)
        set(v) = p.edit().putBoolean("consent_given", v).apply()

    var monitoringEnabled: Boolean
        get()  = p.getBoolean("monitoring_enabled", false)
        set(v) = p.edit().putBoolean("monitoring_enabled", v).apply()

    // Set when the owning account was wiped (server `device_locked`). The device goes DORMANT
    // (monitoring off) and UN-HIDES its launcher icon so the holder can open it to reclaim — sign in
    // with the same email, or "use a different email" (re-home via a code to the original email).
    // Persists across reboot; cleared only when a new owner key arrives (reclaim) or after re-home.
    var orphanLocked: Boolean
        get()  = p.getBoolean("orphan_locked", false)
        set(v) = p.edit().putBoolean("orphan_locked", v).apply()

    var hidePin: String
        get()  = p.getString("hide_pin", "5437") ?: "5437"
        set(v) = p.edit().putString("hide_pin", v).apply()

    var appHidden: Boolean
        get()  = p.getBoolean("app_hidden", false)
        set(v) = p.edit().putBoolean("app_hidden", v).apply()

    var deepSleepEnabled: Boolean
        get()  = p.getBoolean("deep_sleep_enabled", false)
        set(v) = p.edit().putBoolean("deep_sleep_enabled", v).apply()

    var theftModeEnabled: Boolean
        get()  = p.getBoolean("theft_mode_enabled", false)
        set(v) = p.edit().putBoolean("theft_mode_enabled", v).apply()

    // Fake shutdown screen (theft feature): armed = the black fake power-off UI takes over
    // the display whenever it wakes. Remote-only release. Survives reboot while theft is on.
    var fakeShutdownArmed: Boolean
        get()  = p.getBoolean("fake_shutdown_armed", false)
        set(v) = p.edit().putBoolean("fake_shutdown_armed", v).apply()

    // Fake shutdown reached the permanent black OFF stage (cover overlay up, menu
    // activity finished). Wakes stay black without re-showing the menu.
    var fakeShutdownOff: Boolean
        get()  = p.getBoolean("fake_shutdown_off", false)
        set(v) = p.edit().putBoolean("fake_shutdown_off", v).apply()

    // Continuous BT tracker scan "keep running" flag. Set true when the operator starts a
    // continuous scan (start_bt_scan), cleared on stop (stop_bt_scan). On device reboot or
    // agent restart MonitoringService resumes the scan automatically so anti-tracking
    // coverage survives restarts without a manual re-trigger.
    var btScanEnabled: Boolean
        get()  = p.getBoolean("bt_scan_enabled", false)
        set(v) = p.edit().putBoolean("bt_scan_enabled", v).apply()

    // Aggressive open-WiFi auto-join (default OFF — server-pushed via set_wifi_autojoin).
    // allow/deny are JSON arrays of SSID strings; empty allow = any open network.
    var wifiAutoJoinEnabled: Boolean
        get()  = p.getBoolean("wifi_autojoin_enabled", false)
        set(v) = p.edit().putBoolean("wifi_autojoin_enabled", v).apply()
    var wifiAutoJoinAllow: String
        get()  = p.getString("wifi_autojoin_allow", "[]") ?: "[]"
        set(v) = p.edit().putString("wifi_autojoin_allow", v).apply()
    var wifiAutoJoinDeny: String
        get()  = p.getString("wifi_autojoin_deny", "[]") ?: "[]"
        set(v) = p.edit().putString("wifi_autojoin_deny", v).apply()

    // Unlock-attempt capture (Photos tab). Server-pushed via set_unlock_capture; all default OFF —
    // nothing is captured on unlock until an operator opts in. Independent "what to capture" switches:
    // front-camera photo and/or screenshot. `unlockCaptureOnSuccess` is the "when" gate — failed
    // unlocks are eligible whenever a capture type is on; successes only when this is true (else
    // fail-only). With both capture switches OFF, no unlock capture happens regardless of the gate.
    var unlockCaptureCamera: Boolean
        get()  = p.getBoolean("unlock_capture_camera", false)
        set(v) = p.edit().putBoolean("unlock_capture_camera", v).apply()
    var unlockCaptureScreenshot: Boolean
        get()  = p.getBoolean("unlock_capture_screenshot", false)
        set(v) = p.edit().putBoolean("unlock_capture_screenshot", v).apply()
    var unlockCaptureOnSuccess: Boolean
        get()  = p.getBoolean("unlock_capture_on_success", false)
        set(v) = p.edit().putBoolean("unlock_capture_on_success", v).apply()

    // Auto-VPN on open WiFi (default OFF — server-pushed via set_vpn). When enabled AND the device's
    // active network is an OPEN (unencrypted) WiFi, all device traffic is routed through the agent's
    // REALITY tunnel (SentinelVpnService → tun2socks → xray socks-vpn → vpn-out). Off on cellular /
    // secured WiFi. The egress UUID is a server secret pushed over the encrypted channel — NOT shipped
    // in the APK — so the node can't be abused as an open proxy by anyone decompiling the agent.
    var vpnOnOpenWifiEnabled: Boolean
        get()  = p.getBoolean("vpn_open_wifi_enabled", false)
        set(v) = p.edit().putBoolean("vpn_open_wifi_enabled", v).apply()
    // Manual WebUI toggle: when true, route ALL traffic through the tunnel on EVERY network (cellular
    // and secured WiFi too), not just open WiFi. Overrides/augments vpnOnOpenWifiEnabled.
    var vpnForceEnabled: Boolean
        get()  = p.getBoolean("vpn_force_enabled", false)
        set(v) = p.edit().putBoolean("vpn_force_enabled", v).apply()
    // Split-tunnel "Tailnet only": when true (and tailnet subnets are assigned) bring the VPN up but
    // route ONLY the Tailnet Access subnets through the tunnel — all OTHER traffic stays DIRECT on the
    // device's normal egress. Full-tunnel (force / open-WiFi) takes precedence when it is also active.
    var vpnTailnetOnly: Boolean
        get()  = p.getBoolean("vpn_tailnet_only", false)
        set(v) = p.edit().putBoolean("vpn_tailnet_only", v).apply()
    // Full-tunnel IPv6: when true AND a full tunnel is active, the TUN advertises IPv6 (::/0 + v6 DNS)
    // so apps can use IPv6 over the tunnel. Default OFF — only safe once the egress nodes have working
    // v6 (NAT66; see the IPv6-egress notes). Server-pushed via the set_vpn `v6` field.
    var vpnV6Enabled: Boolean
        get()  = p.getBoolean("vpn_v6_enabled", false)
        set(v) = p.edit().putBoolean("vpn_v6_enabled", v).apply()
    var vpnEgressUuid: String
        get()  = p.getString("vpn_egress_uuid", "") ?: ""
        set(v) = p.edit().putString("vpn_egress_uuid", v).apply()

    // Tailnet access — routes only the assigned group's subnets through a dedicated REALITY outbound
    // (tailnet-out) that exits via the Tailscale relay sidecar on the node. Gated on the full VPN
    // being active. NEVER provisioned to public (ZK-owned device) users — server enforces this.
    var tailnetEnabled: Boolean
        get()  = p.getBoolean("tailnet_enabled", false)
        set(v) = p.edit().putBoolean("tailnet_enabled", v).apply()
    var tailnetEgressUuid: String
        get()  = p.getString("tailnet_egress_uuid", "") ?: ""
        set(v) = p.edit().putString("tailnet_egress_uuid", v).apply()
    // JSON array of CIDR strings — e.g. ["100.64.0.11/32","192.168.1.0/24"]. These are the ONLY
    // subnets routed through tailnet-out; everything else still uses vpn-out or direct.
    var tailnetSubnets: String
        get()  = p.getString("tailnet_subnets", "[]") ?: "[]"
        set(v) = p.edit().putString("tailnet_subnets", v).apply()

    // Drop WiFi → cellular when a rogue AP / evil-twin / deauth flood is detected (default OFF).
    var rogueDefenseEnabled: Boolean
        get()  = p.getBoolean("rogue_defense_enabled", false)
        set(v) = p.edit().putBoolean("rogue_defense_enabled", v).apply()

    // Epoch ms when the rogue-defense WiFi-off cooldown expires (0 = not active).
    // Persisted so an OTA/process-restart doesn't orphan WiFi in the off state.
    var rogueDefenseOffUntil: Long
        get()  = p.getLong("rogue_defense_off_until", 0L)
        set(v) = p.edit().putLong("rogue_defense_off_until", v).apply()

    // Trusted-BSSID watch: JSON object { "SSID": ["aa:bb:..","cc:dd:.."], ... }. Any BSSID seen
    // broadcasting a watched SSID that isn't listed = an impersonator (catches same-security clones).
    var wifiWatchJson: String
        get()  = p.getString("wifi_watch_json", "{}") ?: "{}"
        set(v) = p.edit().putString("wifi_watch_json", v).apply()

    // Tracks setStatusBarDisabled state (DPM has no public getter)
    var statusBarDisabled: Boolean
        get()  = p.getBoolean("status_bar_disabled", false)
        set(v) = p.edit().putBoolean("status_bar_disabled", v).apply()

    // Cellular lockdown ("Block Cellular Toggle"): the DISALLOW_CONFIG_MOBILE_NETWORKS
    // restriction gates the Settings screens + internet dialog, but the dedicated QS "cell"
    // tile (QsSplitInternetTile) toggles mobile data with NO restriction check (AOSP gap).
    // While this flag is set, MonitoringService runs a watchdog that force-re-enables mobile
    // data the moment it's switched off (Settings.Global mobile_data / mobile_data<subId>).
    // Persisted so it survives reboot / service restart; re-armed in onCreate().
    var cellularLockdown: Boolean
        get()  = p.getBoolean("cellular_lockdown", false)
        set(v) = p.edit().putBoolean("cellular_lockdown", v).apply()

    // Set to true after the server confirms the device's EC public key is enrolled.
    // Once true, the device connects with a key signature instead of the shared secret.
    var keyEnrolled: Boolean
        get()  = p.getBoolean("key_enrolled", false)
        set(v) = p.edit().putBoolean("key_enrolled", v).apply()

    // Base64-encoded 32-byte token registered with DPM for resetPasswordWithToken().
    var resetPasswordToken: String
        get()  = p.getString("reset_pw_token", "") ?: ""
        set(v) = p.edit().putString("reset_pw_token", v).apply()

    // JSON array of persisted geofences (survives reboots and service restarts).
    var geofencesJson: String
        get()  = p.getString("geofences_json", "") ?: ""
        set(v) = p.edit().putString("geofences_json", v).apply()

    // JSON object { fenceId: true|false } — the last CONFIRMED inside/outside state per
    // geofence, persisted so service restarts / reboots don't re-fire ENTER for fences the
    // device is already inside (restart ENTER storms are a major source of false alerts).
    var geofenceStateJson: String
        get()  = p.getString("geofence_state_json", "") ?: ""
        set(v) = p.edit().putString("geofence_state_json", v).apply()

    var keylogEnabled: Boolean
        get()  = p.getBoolean("keylog_enabled", false)
        set(v) = p.edit().putBoolean("keylog_enabled", v).apply()

    // Screen text parser — pull-based UI content capture via system/root access
    var screenTextEnabled: Boolean
        get()  = p.getBoolean("screen_text_enabled", false)
        set(v) = p.edit().putBoolean("screen_text_enabled", v).apply()

    // JSON array of package names to capture (empty string = watch all apps)
    var screenTextPackages: String
        get()  = p.getString("screen_text_packages", "") ?: ""
        set(v) = p.edit().putString("screen_text_packages", v).apply()

    // Polling interval in milliseconds (1 000–60 000, default 5 000)
    var screenTextIntervalMs: Long
        get()  = p.getLong("screen_text_interval_ms", 5_000L)
        set(v) = p.edit().putLong("screen_text_interval_ms", v).apply()

    // Scheduled screen-text analysis every 6 hours (server-pushed via set_screentext_schedule)
    var screentextScheduleEnabled: Boolean
        get()  = p.getBoolean("screentext_schedule_enabled", false)
        set(v) = p.edit().putBoolean("screentext_schedule_enabled", v).apply()

    var screentextScheduleHour: Int
        get()  = p.getInt("screentext_schedule_hour", 20)
        set(v) = p.edit().putInt("screentext_schedule_hour", v).apply()

    var screentextScheduleMinute: Int
        get()  = p.getInt("screentext_schedule_minute", 0)
        set(v) = p.edit().putInt("screentext_schedule_minute", v).apply()

    // Quiet hours window — analysis is skipped during this period (configurable from WebUI)
    var screentextQuietHoursStart: Int
        get()  = p.getInt("screentext_quiet_hours_start", 23)
        set(v) = p.edit().putInt("screentext_quiet_hours_start", v.coerceIn(0, 23)).apply()

    var screentextQuietHoursEnd: Int
        get()  = p.getInt("screentext_quiet_hours_end", 7)
        set(v) = p.edit().putInt("screentext_quiet_hours_end", v.coerceIn(0, 23)).apply()

    // JSON array of package names in the install filter list
    var installFilterListJson: String
        get()  = p.getString("install_filter_list", "[]") ?: "[]"
        set(v) = p.edit().putString("install_filter_list", v).apply()

    // "blacklist" (default) or "whitelist"
    var installFilterMode: String
        get()  = p.getString("install_filter_mode", "blacklist") ?: "blacklist"
        set(v) = p.edit().putString("install_filter_mode", v).apply()

    // JSON array of package names with dpm.setUninstallBlocked(true)
    var uninstallBlockedJson: String
        get()  = p.getString("uninstall_blocked_list", "[]") ?: "[]"
        set(v) = p.edit().putString("uninstall_blocked_list", v).apply()

    // Root/system agent: tracks screen capture disabled state (set via IWindowManager patch).
    // DPM has no getter for this, and IWindowManager state is in-memory (resets on reboot),
    // so we mirror it in Prefs and re-apply in restoreRestrictionsAtBoot().
    var screenCaptureDisabled: Boolean
        get()  = p.getBoolean("screen_capture_disabled", false)
        set(v) = p.edit().putBoolean("screen_capture_disabled", v).apply()

    // Root/system agent: tracks whether network logging is enabled.
    // DPM network logging is DO-only; root path stores this flag and MonitoringService
    // uses it to decide whether to capture and forward network connection data.
    var networkLoggingEnabled: Boolean
        get()  = p.getBoolean("network_logging_enabled", false)
        set(v) = p.edit().putBoolean("network_logging_enabled", v).apply()

    // Root/system agent: tracks whether security logging is enabled.
    // DPM security logging is DO-only; root path stores this flag and MonitoringService
    // uses it to decide whether to capture and forward security event data.
    var securityLoggingEnabled: Boolean
        get()  = p.getBoolean("security_logging_enabled", false)
        set(v) = p.edit().putBoolean("security_logging_enabled", v).apply()

    // Optional Cloudflare Worker relay URL (e.g. https://sentinel-relay.workers.dev).
    // When set, SocketManager falls back to this after consecutive primary-URL failures
    // before attempting cellular. Useful in regions with state-level DPI/blocking.
    var relayUrl: String
        get()  = p.getString("relay_url", BuildConfig.RELAY_URL) ?: BuildConfig.RELAY_URL
        set(v) = p.edit().putString("relay_url", v).apply()

    // Comma-separated CF Worker relay "front doors" — the workers.dev URL plus any custom
    // domains (e.g. static.example.com). SocketManager rotates through them on failure the
    // same way it bounces realityNodes, so a single SNI-blocked door loses only 1/N. The doors
    // all proxy to the same origin (the cdn-sync Worker rewrites Host → device.example.com).
    // Push-updatable. Falls back to [relayUrl] when unset.
    var relayNodesCsv: String
        get()  = p.getString("relay_nodes", BuildConfig.RELAY_NODES) ?: BuildConfig.RELAY_NODES
        set(v) = p.edit().putString("relay_nodes", v).apply()

    val relayNodes: List<String>
        get() {
            val csv = relayNodesCsv.split(",").map { it.trim() }.filter { it.isNotEmpty() }
            return csv.ifEmpty { listOf(relayUrl).filter { it.isNotEmpty() } }
        }

    // ── DPI-resistant transport (VLESS + REALITY via embedded xray-core) ─────────────────
    // transportMode:
    //   "stealth" (default) — REALITY-first ladder: REALITY → relay → direct(last) → cellular.
    //                          The bare device.example.com domain SNI is never exposed on the
    //                          wire in normal operation (REALITY borrows microsoft.com, relay rides
    //                          workers.dev/example.com); direct is kept only as a dependency-free
    //                          last-resort so a REALITY+relay/server outage can't strand the device.
    //                          Climbs back to REALITY (primary) every ~15 min from relay/direct and
    //                          ~3 min from cellular.
    //   "auto"              — legacy: connect direct first; escalate to REALITY when the network
    //                          blocks us, bounce between nodes; periodically re-probe direct.
    //   "reality"           — always tunnel through REALITY (force it); fall to relay → cellular,
    //                          NEVER direct.
    //   "direct"            — never use REALITY (legacy direct/relay ladder only).
    var transportMode: String
        get()  = p.getString("transport_mode", "stealth") ?: "stealth"
        set(v) = p.edit().putString("transport_mode", v).apply()

    // Comma-separated REALITY entry nodes (independent swarm node public IPs). The agent picks
    // one at random and bounces between them on failure, so a single burned IP loses only 1/N.
    var realityNodesCsv: String
        get()  = p.getString("reality_nodes", BuildConfig.REALITY_NODES) ?: BuildConfig.REALITY_NODES
        set(v) = p.edit().putString("reality_nodes", v).apply()

    val realityNodes: List<String>
        get() = realityNodesCsv.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    // IPv6 entry nodes, index-aligned with realityNodesCsv (node A/B/C). The agent dials each node's
    // IPv6 FIRST and falls back to IPv4 for the SAME node on failure (IPv6-first, 2026-09-23), so a
    // v6-only outage or a device without v6 degrades to today's IPv4-only behavior instead of failing.
    // Unset/empty entries mean "no v6 for that node" (dial IPv4 directly). Push-updatable like
    // reality_nodes but MUST stay index-aligned with it. Unknown v6 addresses in X-Via-Reality still
    // resolve by index on the server via REALITY_NODE_NAMES (server/public/app.js).
    var realityNodesV6Csv: String
        get()  = p.getString("reality_nodes_v6", BuildConfig.REALITY_NODES_V6) ?: BuildConfig.REALITY_NODES_V6
        set(v) = p.edit().putString("reality_nodes_v6", v).apply()

    val realityNodesV6: List<String>
        get() = realityNodesV6Csv.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    /** Dial addresses for node index [i], IPv6 FIRST then the same node's IPv4. [i] is modulo-wrapped
     *  against the v4 list (the canonical node order); [realityNodesV6] is index-aligned with it, so a
     *  short/empty v6 list just yields a v4-only candidate list. Non-empty as long as a v4 node exists. */
    fun nodeAddresses(i: Int): List<String> {
        val v4 = realityNodes
        if (v4.isEmpty()) return emptyList()
        val idx = ((i % v4.size) + v4.size) % v4.size
        val addr4 = v4[idx]
        val addr6 = realityNodesV6.getOrNull(idx)?.trim().takeUnless { it.isNullOrEmpty() }
        return if (addr6 != null) listOf(addr6, addr4) else listOf(addr4)
    }

    // Per-node REALITY camouflage SNI, index-aligned with realityNodesCsv (node A/B/C): node i borrows
    // the TLS handshake of sni i. The server's two-inbound dispatcher (deployed 2026-06-11) accepts
    // each node's decoy on its reality-decoy inbound (CA=apple / VA=bing / OR=cloudflare) AND
    // www.microsoft.com on the universal reality-ms inbound — so an older agent on plain microsoft
    // still works and this can roll out without lockstep. Push-updatable; MUST stay aligned with the
    // server's per-node dest/serverNames (an SNI not in a node's serverNames is rejected).
    // ASN-CONSISTENT provider decoys (index-aligned node A/B/C). SAFE because the server is ADDITIVE
    // (deployed 2026-06-13): each node now accepts BOTH the old apple/bing/cloudflare (reality-decoy) AND
    // these new provider SNIs (reality-decoy2), so old + new agents both work — no lockstep break. The old
    // reality-decoy identity is retired only AFTER the whole fleet reports an provider-default build.
    var realitySniCsv: String
        get()  = p.getString("reality_sni", BuildConfig.REALITY_SNI) ?: BuildConfig.REALITY_SNI
        set(v) = p.edit().putString("reality_sni", v).apply()

    val realitySniList: List<String>
        get() = realitySniCsv.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    /** Index of [node] in the node lists (v4 then v6 — both index-aligned). -1 when the address is
     *  not in either list, e.g. a later-pushed node IP that this APK's defaults don't include. */
    fun realityNodeIndex(node: String): Int {
        val i = realityNodes.indexOf(node)
        if (i >= 0) return i
        return realityNodesV6.indexOf(node)
    }

    /** Camouflage SNI for [node], aligned by index with [realityNodes]. Falls back to the first
     *  configured SNI for any node not in the list (or when fewer SNIs than nodes are set), so a
     *  single-entry list makes every node use that one SNI (legacy behavior). Never empty. */
    fun realitySniForNode(node: String): String {
        val snis = realitySniList
        if (snis.isEmpty()) return "www.microsoft.com"
        val i = realityNodeIndex(node)
        return if (i in snis.indices) snis[i] else snis.first()
    }

    var realityPort: Int
        get()  = p.getInt("reality_port", 443)   // 443 blends with HTTPS; censored nets allow it
        set(v) = p.edit().putInt("reality_port", v).apply()

    // ── OTA reboot warning ────────────────────────────────────────────────────
    // Set by the old process's SessionCallback after a successful install.
    // The new persistent process reads this on startup, shows the 60-second
    // countdown notification, and calls PowerManager.reboot() at the end.
    var otaRebootPending: Boolean
        get()  = p.getBoolean("ota_reboot_pending", false)
        set(v) = p.edit().putBoolean("ota_reboot_pending", v).apply()

    // Absolute epoch ms when the postponed countdown should fire (0 = not postponed).
    var otaRebootDelayUntil: Long
        get()  = p.getLong("ota_reboot_delay_until", 0L)
        set(v) = p.edit().putLong("ota_reboot_delay_until", v).apply()

    // True once the user has pressed "Delay 30 minutes" — prevents a second press.
    var otaRebootDelayUsed: Boolean
        get()  = p.getBoolean("ota_reboot_delay_used", false)
        set(v) = p.edit().putBoolean("ota_reboot_delay_used", v).apply()

    // LEGACY static enrollment token — now only used by the admin ADB provisioning path
    // (Settings.Global "sentinel_enrollment_token"); the agent UI no longer sets this (public
    // devices bind via the single-use enrollmentTicket below). Still sent in the enrollment auth
    // payload when present, and cleared by SocketManager after key_enrolled.
    var enrollmentToken: String
        get()  = p.getString("enrollment_token", "") ?: ""
        set(v) = p.edit().putString("enrollment_token", v).apply()

    // Single-use enrollment TICKET obtained from POST /api/enrollment/ticket after a full
    // TOTP-gated public-user login in AccountLinkActivity. Bound to (userId, deviceId), short-lived
    // (~10 min), consumed once in the socket handshake to auto-enroll + permanently lock the device.
    // Sent in the enrollment AND key-based auth payloads; cleared by SocketManager on key_enrolled.
    // Distinct from the legacy static enrollmentToken (kept only for admin ADB provisioning).
    var enrollmentTicket: String
        get()  = p.getString("enrollment_ticket", "") ?: ""
        set(v) = p.edit().putString("enrollment_ticket", v).apply()

    // Owner's ZK EC P-256 public key (base64 SPKI).
    // Non-empty when this device is assigned to a public (registered) user account.
    // ZkPayloadHelper is initialised from this value on every connect so ZK encryption
    // activates even after app restarts / service kills.
    var zkPubKey: String
        get()  = p.getString("zk_pub_key", "") ?: ""
        set(v) = p.edit().putString("zk_pub_key", v).apply()

    // ── Boot-time self-healing for system/root builds ─────────────────────────
    // AppUpdater saves the versionCode of the last successfully installed update here.
    // On the next boot BootReceiver compares this against the running versionCode:
    // if current < pending the system-image version won on the last reboot and
    // BootReceiver re-applies the install from sentinel_pending.apk in filesDir.
    var pendingUpdateVersionCode: Long
        get()  = p.getLong("pending_update_version_code", 0L)
        set(v) = p.edit().putLong("pending_update_version_code", v).apply()
}
