package com.android.systemservices

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Real-time Bluetooth / BLE scanner that detects ALL nearby devices and identifies
 * known tracking devices (AirTag, Tile, SmartTag, Chipolo, Nut, Pebblebee, etc.).
 *
 * Two parallel scan paths:
 *  1. BLE scan (BluetoothLeScanner) — captures low-energy advertisements with RSSI,
 *     manufacturer-specific data, service UUIDs, and device names. This is the PRIMARY
 *     path for tracker detection because trackers broadcast via BLE.
 *  2. Classic Bluetooth discovery (startDiscovery) — catches phones, headphones, speakers,
 *     car kits, and any non-BLE device that does a traditional inquiry scan.
 *
 * Results are deduplicated by MAC address and merged. Each scan cycle produces:
 *  - A full device list (all nearby BT devices with RSSI/type/name/address)
 *  - A filtered "detected trackers" list (devices matching known tracker signatures)
 *
 * The tracker signature database covers:
 *  - Apple AirTag / Find My network (manufacturer data 0x004C + type 0x10/0x12)
 *  - Samsung SmartTag / SmartTag2 (Samsung manufacturer data)
 *  - Tile (Mate, Pro, Sticker, Slim) — manufacturer ID 0x0137
 *  - Chipolo (ONE, ONE Point) — manufacturer ID 0x019D / service UUID
 *  - Nut (Nuttag) — service UUID 0xFE95
 *  - Pebblebee (Card, Clip, Finder) — manufacturer ID 0x0171
 *  - Eone (Newton, Bradley) — service UUID patterns
 *  - Smart cell / iTrack / TagIt — generic tracker service UUIDs
 *  - Any device with the⁽⁾ Apple Find My₍₃₎ or Google Find My Device service UUIDs
 */
class BluetoothScanHelper(private val context: Context) {

    companion object {
        private const val TAG = "BTScanHelper"

        // ── Tracker Manufacturer IDs (Bluetooth SIG assigned company identifiers) ─────
        // Only Apple is matched via manufacturer data: the Find My network advertises a
        // well-documented mfg payload (company 0x004C + type byte). Every other ecosystem
        // signals via SERVICE DATA / service UUID, NOT manufacturer data:
        //   • Samsung SmartTag  → service UUID 0xFD5A/0xFD59 (USENIX Sec'24)
        //   • Tile              → service UUID 0xFEED/0xFEEC (Nordic nRF5 SDK / VIGIL)
        //   • Google Find My    → service data 0xFEAA, frame 0x40/0x41 (Google FMDN spec)
        //   • Chipolo/Pebblebee → Find My network (Apple 0x004C/0x12) or name heuristics
        // Company-ID-only matching was the source of the earlier false positives: the old
        // table was wrong (0x019D = CVS Health, 0x0171 = Amazon, 0x0137 ≠ Tile, 0x0157 ≠
        // Google) and company IDs are shared across whole product families anyway
        // (0x0075 = every Samsung device incl. TVs, which embed their MAC in mfg data for
        // remote pairing — Samsung patents US12604351/US11533766).
        private const val APPLE_COMPANY_ID = 0x004C        // Apple Inc.
        private const val APPLE_TYPE_FIND_MY = 0x12        // Find My network payload (registered accessory)
        private const val APPLE_TYPE_UNPAIRED = 0x07       // unpaired AirTag / Find My setup mode

        // ── Tracker Service UUIDs (16-bit, Bluetooth SIG member assignments) ──────────
        // Full 128-bit forms as reported by ScanRecord.getServiceUuids().
        private val TILE_SERVICE_UUIDS = setOf(
            "0000feed-0000-1000-8000-00805f9b34fb",  // Tile — activated mode
            "0000feec-0000-1000-8000-00805f9b34fb"   // Tile — shipping mode
        )
        private val SAMSUNG_SMARTTAG_SERVICE_UUIDS = setOf(
            "0000fd5a-0000-1000-8000-00805f9b34fb",  // SmartTag (registered)
            "0000fd59-0000-1000-8000-00805f9b34fb"   // SmartTag (unregistered/onboarding)
        )
        // Chipolo / Pebblebee (non-Find-My models) advertise their own "offline finding"
        // service UUIDs — taken from AirGuard's detection source (seemoo-lab/AirGuard,
        // Chipolo.kt / PebbleBee.kt), the reference open-source tracker detector.
        private val CHIPOLO_SERVICE_UUIDS = setOf(
            "0000fe33-0000-1000-8000-00805f9b34fb"   // Chipolo offline-finding service
        )
        private val PEBBLEBEE_SERVICE_UUIDS = setOf(
            "0000fa25-0000-1000-8000-00805f9b34fb"   // Pebblebee offline-finding service
        )
        // Google Find My Device network — advertised as SERVICE DATA under this UUID with a
        // frame byte 0x40 (near owner) / 0x41 (separated/anti-stalking). Matched via the
        // raw advertisement (Layer 4), because 0xFEAA is shared with Eddystone beacons.
        private const val GOOGLE_FMDN_UUID_LO = 0xAA.toByte()
        private const val GOOGLE_FMDN_UUID_HI = 0xFE.toByte()
        private const val GOOGLE_FMDN_SERVICE_UUID = "0000feaa-0000-1000-8000-00805f9b34fb"

        // Service UUIDs whose SERVICE DATA we capture into the device record — they carry the
        // tags' stable identities (Samsung privacy ID, Google FMDN EID) used for dedup across
        // MAC rotation.
        private val TRACKER_SERVICE_DATA_IDS = SAMSUNG_SMARTTAG_SERVICE_UUIDS +
            setOf(GOOGLE_FMDN_SERVICE_UUID)

        // ── Apple Find My manufacturer data type bytes ────────────────────────────────
        // Apple's manufacturer data starts with a 1-byte "type" after the company ID:
        // 0x12 = Find My network payload (registered accessory), 0x07 = unpaired/setup.
        // The status byte (battery etc.) lives AFTER the type+length bytes — the earlier
        // code compared the STATUS byte (0x10 = full battery) against the type table,
        // which silently missed medium/low-battery tags.

        // ── Scan timing ───────────────────────────────────────────────────────────────
        private const val SCAN_WINDOW_MS = 12_000L          // 12s scan window
        private const val SCAN_INTERVAL_MS = 3_000L         // 3s pause between scans
        private const val REPORT_AGE_MS = 30_000L           // Forget devices after 30s
        private const val POWER_WATCHDOG_MS = 3_000L        // re-assert BT radio every 3s while scanning
    }

    /** Callback for scan results. */
    interface Callback {
        /** Called with the full device list + detected trackers after each scan cycle. */
        fun onScanComplete(devices: JSONArray, trackers: JSONArray)
    }

    var callback: Callback? = null

    /**
     * Notified whenever the logical scan state flips, so the caller (MonitoringService) can
     * relay it to the server/WebUI. Invoked on scan start (true) and scan stop (false), and
     * on every successful Bluetooth re-enable while a scan is supposed to be running.
     */
    var onScanStateChanged: ((scanning: Boolean) -> Unit)? = null

    private val bluetoothAdapter: BluetoothAdapter? by lazy {
        (context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager)?.adapter
    }

    private val bleScanner get() = bluetoothAdapter?.bluetoothLeScanner

    private val isScanning  = AtomicBoolean(false)
    private val continuous  = AtomicBoolean(false)
    // Monotonic window sequence: bumped at the start of every cycle and every stop.
    // Guards against stale BLE/discovery callbacks or an already-scheduled end-window
    // runnable from a finished cycle firing into a newer cycle (or a stopped scanner).
    private val windowSeq   = AtomicInteger(0)
    // The last window sequence already finalized. Lets each cycle emit results exactly
    // once no matter which completion signal lands first (the end-window timer from
    // endScanWindow vs. the classic ACTION_DISCOVERY_FINISHED broadcast), and prevents
    // a late discovery-finished broadcast from double-reporting (or reporting on top of
    // an already-cleared next cycle).
    private val finalizedSeq = AtomicInteger(0)
    // Which window sequence the currently-running classic discovery belongs to (0 = no
    // discovery in flight). Set just before startDiscovery() and cleared on cancelDiscovery().
    // Guards the ACTION_DISCOVERY_FINISHED broadcast: `cancelDiscovery()` on the OLD window
    // can queue a discovery-finished broadcast that fires AFTER a newer cycle has already
    // started; without this check the stale broadcast would read the live windowSeq and
    // prematurely finalize the brand-new cycle with leftover/partial data.
    private val discoverySeq = AtomicInteger(0)

    // Merged device cache: address → device JSON (deduped across BLE + classic)
    private val deviceCache = ConcurrentHashMap<String, JSONObject>()

    // ── Classic Bluetooth discovery receiver ──────────────────────────────────────────
    private val classicReceiver = object : BroadcastReceiver() {
        @SuppressLint("MissingPermission")
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE)
                    } ?: return
                    val rssi = intent.getShortExtra(BluetoothDevice.EXTRA_RSSI, Short.MIN_VALUE).toInt()
                    val name = try { device.name } catch (_: SecurityException) { null } ?: ""
                    val address = try { device.address } catch (_: SecurityException) { return }
                    val bondState = try { device.bondState } catch (_: SecurityException) { 0 }

                    val typeStr = when (device.type) {
                        BluetoothDevice.DEVICE_TYPE_CLASSIC -> "classic"
                        BluetoothDevice.DEVICE_TYPE_LE      -> "ble"
                        BluetoothDevice.DEVICE_TYPE_DUAL    -> "dual"
                        else -> "unknown"
                    }
                    mergeDevice(address, name, rssi, typeStr, bondState, null, null, null, null)
                }
                BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                    // Only act on the discovery we actually started for the CURRENT window.
                    // A cancelDiscovery() on a previous window can queue this broadcast after
                    // a newer cycle has begun; tying it to discoverySeq prevents it from
                    // prematurely finalizing (and over-riding) a brand-new scan.
                    if (discoverySeq.get() != windowSeq.get()) return
                    Log.d(TAG, "Classic discovery finished — ${deviceCache.size} devices")
                    discoverySeq.set(0)
                    finalizeScanIfNeeded(windowSeq.get())
                }
            }
        }
    }

    // ── Bluetooth power lock ────────────────────────────────────────────────────────
    // Keeps the radio on for the whole scan window. Two mechanisms:
    //   1. A persistent ACTION_STATE_CHANGED receiver that re-enables the radio the moment the
    //      user (or system) turns it OFF mid-scan.
    //   2. A 3s power watchdog that re-asserts adapter.enable() while scanning. The broadcast
    //      alone is not enough — ACTION_STATE_CHANGED can be delayed/coalesced, and on some
    //      builds an app-initiated enable() issued while the user's toggle is still animating
    //      is silently dropped. The poll makes the "stay on while scanning" contract stick.
    private var powerReceiverRegistered = false
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private val powerWatchdog = object : Runnable {
        override fun run() {
            if (!isScanning.get()) return
            val adapter = bluetoothAdapter
            if (adapter != null && !adapter.isEnabled) {
                Log.w(TAG, "Power watchdog: Bluetooth OFF during scan — re-enabling")
                rearmRadio()
            }
            if (isScanning.get()) mainHandler.postDelayed(this, POWER_WATCHDOG_MS)
        }
    }

    private val powerReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            if (intent.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
            // If the user (or system) turned Bluetooth OFF while a scan is active, immediately
            // power it back on and re-assert the logical scan state to the server.
            if (state == BluetoothAdapter.STATE_OFF && isScanning.get()) {
                Log.w(TAG, "Bluetooth turned OFF while scanning — re-enabling")
                rearmRadio()
            }
        }
    }

    private fun registerPowerReceiver() {
        if (powerReceiverRegistered) return
        try {
            context.registerReceiver(powerReceiver, IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED))
            powerReceiverRegistered = true
        } catch (_: Exception) {}
    }

    /**
     * Ensure the Bluetooth radio is powered on. Returns immediately if already on. If it's off
     * (or transitioning), request enable() and register the power receiver + watchdog so we keep
     * it on. The scanner genuinely requires the radio; enabling it here matches the "auto on at
     * scan start" contract.
     */
    private fun ensureBluetoothOn() {
        val adapter = bluetoothAdapter ?: return
        registerPowerReceiver()
        mainHandler.removeCallbacks(powerWatchdog)
        mainHandler.postDelayed(powerWatchdog, POWER_WATCHDOG_MS)
        if (isScanning.get() && !adapter.isEnabled) {
            rearmRadio()
        }
    }

    /** Release the keep-on lock (receiver + watchdog) once scanning stops. */
    private fun stopPowerKeepOn() {
        mainHandler.removeCallbacks(powerWatchdog)
        if (powerReceiverRegistered) {
            try { context.unregisterReceiver(powerReceiver) } catch (_: Exception) {}
            powerReceiverRegistered = false
        }
    }

    private fun rearmRadio() {
        val adapter = bluetoothAdapter ?: return
        try {
            @Suppress("DEPRECATION")
            val ok = adapter.enable()   // deprecated on 33+ but still the correct programmatic path
            Log.i(TAG, if (ok) "Bluetooth enable requested (radio on)" else "Bluetooth enable() returned false")
            onScanStateChanged?.invoke(true)
        } catch (e: Exception) {
            Log.e(TAG, "Bluetooth enable failed: ${e.message}")
        }
    }

    // ── BLE scan callback ─────────────────────────────────────────────────────────────
    private val bleCallback = object : ScanCallback() {
        @SuppressLint("MissingPermission")
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val device = result.device ?: return
            val address = try { device.address } catch (_: SecurityException) { return }
            val name = try { result.scanRecord?.deviceName ?: device.name } catch (_: SecurityException) { null } ?: ""
            val rssi = result.rssi

            val bondState = try { device.bondState } catch (_: SecurityException) { 0 }
            val typeStr = when (device.type) {
                BluetoothDevice.DEVICE_TYPE_CLASSIC -> "classic"
                BluetoothDevice.DEVICE_TYPE_LE      -> "ble"
                BluetoothDevice.DEVICE_TYPE_DUAL    -> "dual"
                else -> "unknown"
            }

            // Extract manufacturer-specific data
            val mfgData = result.scanRecord?.getManufacturerSpecificData()
            val mfgJson = if (mfgData != null && mfgData.size() > 0) {
                val obj = JSONObject()
                for (i in 0 until mfgData.size()) {
                    val key = mfgData.keyAt(i)
                    val value = mfgData.get(key)
                    if (value != null) {
                        obj.put("0x${String.format("%04X", key)}", bytesToHex(value))
                    }
                }
                obj
            } else null

            // Extract advertised service UUIDs
            val serviceUuids = result.scanRecord?.serviceUuids?.map { it.toString().lowercase() }
            val uuidJson = serviceUuids?.let { JSONArray(it) }

            // Extract SERVICE DATA for tracker-relevant UUIDs. This is what carries a tag's
            // STABLE identity — Samsung SmartTag privacy ID (bytes 4-11 of FD5A/FD59 service
            // data), Google FMDN ephemeral ID (after the frame byte of FEAA) — while the
            // advertised MAC rotates (RPAs). Dedup/safelist decisions can then key on the
            // true tag identity instead of the transient address.
            val svcDataJson = result.scanRecord?.getServiceData()?.let { map ->
                JSONObject().apply {
                    for ((puuid, bytes) in map) {
                        val u = puuid.uuid.toString().lowercase()
                        if (u in TRACKER_SERVICE_DATA_IDS) put(u, bytesToHex(bytes))
                    }
                }.takeIf { it.length() > 0 }
            }

            mergeDevice(address, name, rssi, typeStr, bondState, mfgJson, uuidJson, svcDataJson, result.scanRecord?.bytes)
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE scan failed with code $errorCode")
            // Don't tear the whole scan down here: classic discovery may still be running,
            // and the end-window timer (endScanWindow → finalizeScanIfNeeded) will still
            // finalize this cycle. Aborting here previously left one-shot scans without a
            // completion path whenever BLE startScan failed.
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────────────

    /**
     * Start continuous scanning. Each cycle runs BLE + classic discovery in parallel,
     * waits for both to finish, then emits the merged results.
     */
    @SuppressLint("MissingPermission")
    fun startContinuousScan() {
        if (!isScanning.compareAndSet(false, true)) return
        if (!hasPermissions()) {
            Log.w(TAG, "Missing Bluetooth permissions — cannot scan")
            isScanning.set(false)
            return
        }
        continuous.set(true)
        Log.i(TAG, "Starting continuous BT scan")
        ensureBluetoothOn()            // auto-enable + arm the keep-on lock
        onScanStateChanged?.invoke(true)
        startOneScanCycle()
    }

    /** Run a single scan cycle (one BLE scan window + one classic discovery). */
    @SuppressLint("MissingPermission")
    fun scanOnce() {
        if (isScanning.get()) return   // a scan is already running — ignore the one-shot
        if (!hasPermissions()) {
            Log.w(TAG, "Missing Bluetooth permissions — cannot scan")
            return
        }
        continuous.set(false)
        isScanning.set(true)
        Log.i(TAG, "Starting single BT scan")
        ensureBluetoothOn()            // auto-enable + arm the keep-on lock
        onScanStateChanged?.invoke(true)
        startOneScanCycle()
    }

    /** Whether a scan (continuous or one-shot) is currently active. */
    fun isActive(): Boolean = isScanning.get()

    /** Stop all scanning. */
    @SuppressLint("MissingPermission")
    fun stopScanning() {
        if (!isScanning.getAndSet(false)) return
        continuous.set(false)
        windowSeq.incrementAndGet()   // invalidate any in-flight window / pending end-window runnable
        discoverySeq.set(0)
        Log.i(TAG, "Stopping BT scan")
        try { bleScanner?.stopScan(bleCallback) } catch (_: Exception) {}
        try { bluetoothAdapter?.cancelDiscovery() } catch (_: Exception) {}
        try { context.unregisterReceiver(classicReceiver) } catch (_: Exception) {}
        // Release the Bluetooth keep-on lock once scanning stops.
        stopPowerKeepOn()
        onScanStateChanged?.invoke(false)
    }

    // ── Internal scan lifecycle ───────────────────────────────────────────────────────

    @SuppressLint("MissingPermission")
    private fun startOneScanCycle() {
        val seq = windowSeq.incrementAndGet()
        finalizedSeq.set(seq - 1)   // nothing finalized for this window yet
        deviceCache.clear()

        // Register classic discovery receiver
        try {
            context.registerReceiver(classicReceiver, IntentFilter().apply {
                addAction(BluetoothDevice.ACTION_FOUND)
                addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
            })
        } catch (_: IllegalArgumentException) { /* already registered */ }

        // Start classic discovery
        try {
            discoverySeq.set(seq)
            bluetoothAdapter?.startDiscovery()
        } catch (e: Exception) {
            Log.e(TAG, "startDiscovery failed: ${e.message}")
        }

        // Start BLE scan
        val scanSettings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setReportDelay(0)  // immediate callback per result
            .build()

        try {
            bleScanner?.startScan(emptyList(), scanSettings, bleCallback)
        } catch (e: Exception) {
            Log.e(TAG, "BLE startScan failed: ${e.message}")
        }

        // Schedule end of scan window
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
            endScanWindow(seq)
        }, SCAN_WINDOW_MS)
    }

    @SuppressLint("MissingPermission")
    private fun endScanWindow(seq: Int) {
        if (seq != windowSeq.get()) return   // stale window (scanner stopped or already moved on)
        try { bleScanner?.stopScan(bleCallback) } catch (_: Exception) {}
        if (discoverySeq.get() == seq) discoverySeq.set(0)
        try { bluetoothAdapter?.cancelDiscovery() } catch (_: Exception) {}

        finalizeScanIfNeeded(seq)

        // Schedule next cycle if continuous and still scanning
        if (continuous.get() && isScanning.get()) {
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                if (isScanning.get()) startOneScanCycle()
            }, SCAN_INTERVAL_MS)
        }
    }

    /**
     * Finalize the scan results for a given window exactly once. Called from both the
     * end-window timer and the classic ACTION_DISCOVERY_FINISHED broadcast; the
     * [finalizedSeq] guard makes whichever one arrives second a no-op. A one-shot scan
     * (scanOnce) clears [isScanning] after its single cycle so a repeated one-shot is
     * honored and the caller's state stays consistent.
     */
    @SuppressLint("MissingPermission")
    private fun finalizeScanIfNeeded(seq: Int) {
        if (seq != windowSeq.get()) return            // stale completion — ignore entirely
        if (!finalizedSeq.compareAndSet(seq - 1, seq)) return   // already finalized
        finalizeScan()
        if (!continuous.get()) {
            // One-shot (scanOnce) finished — release the Bluetooth keep-on lock and report OFF.
            isScanning.set(false)
            stopPowerKeepOn()
            onScanStateChanged?.invoke(false)
        }
    }

    private fun finalizeScan() {
        val now = System.currentTimeMillis()

        // Prune stale devices
        val stale = deviceCache.entries.filter { now - it.value.optLong("lastSeen", 0) > REPORT_AGE_MS }
        stale.forEach { deviceCache.remove(it.key) }

        // Build output arrays
        val allDevices = JSONArray()
        val trackers = JSONArray()

        for ((_, dev) in deviceCache) {
            allDevices.put(dev)
            if (dev.optBoolean("isTracker", false)) {
                trackers.put(dev)
            }
        }

        Log.i(TAG, "Scan complete: ${allDevices.length()} devices, ${trackers.length()} trackers")

        // Emit results
        callback?.onScanComplete(allDevices, trackers)
    }

    // ── Device merging & tracker detection ────────────────────────────────────────────

    private fun mergeDevice(
        address: String,
        name: String,
        rssi: Int,
        type: String,
        bondState: Int,
        mfgData: JSONObject?,
        serviceUuids: JSONArray?,
        serviceData: JSONObject?,
        rawBytes: ByteArray?
    ) {
        val now = System.currentTimeMillis()
        val existing = deviceCache[address]
        val timestamp = existing?.optLong("firstSeen", now) ?: now
        // BLE devices only advertise their name in the SCAN RESPONSE, which Android delivers on
        // some cycles but not others. Preserve a previously-seen name so the device doesn't flip
        // between "Samsung" and "" (which rendered as "Unknown Tracker" in the WebUI tracker panel).
        val effectiveName = if (name.isNotBlank()) name else (existing?.optString("name", "") ?: "")

        // Run tracker detection
        val trackerInfo = detectTracker(effectiveName, mfgData, serviceUuids, serviceData, rawBytes)
        val isTracker = trackerInfo != null

        val device = JSONObject().apply {
            put("address", address)
            put("name", effectiveName)
            put("rssi", rssi)
            put("type", type)
            put("bondState", bondState)
            put("firstSeen", timestamp)
            put("lastSeen", now)
            if (mfgData != null) put("manufacturerData", mfgData)
            if (serviceUuids != null) put("serviceUuids", serviceUuids)
            if (serviceData != null) put("serviceData", serviceData)
            if (isTracker) {
                put("isTracker", true)
                put("trackerType", trackerInfo!!.type)
                put("trackerBrand", trackerInfo.brand)
                put("trackerSeverity", trackerInfo.severity)
                put("trackerDetail", trackerInfo.detail)
                // Stable tag identity (survives MAC rotation): Samsung privacy ID, Google EID, …
                if (trackerInfo.trackerId != null) put("trackerId", trackerInfo.trackerId)
            }
        }

        deviceCache[address] = device
    }

    // ── Tracker Detection Engine ──────────────────────────────────────────────────────

    data class TrackerInfo(
        val type: String,       // e.g. "airtag", "tile", "smarttag"
        val brand: String,      // e.g. "Apple", "Tile", "Samsung"
        val severity: String,   // "high", "medium", "low"
        val detail: String,     // human-readable description
        val trackerId: String? = null   // stable identity (Samsung privacy ID / Google EID)
    )

    /**
     * Analyze a BLE advertisement to determine if it matches a known tracker.
     * Returns TrackerInfo if matched, null otherwise.
     *
     * Detection is multi-layered:
     *  1. Manufacturer-specific data (most reliable — Apple/Samsung/Tile use unique company IDs)
     *  2. Service UUIDs (some trackers advertise known service UUIDs)
     *  3. Device name heuristics (fallback — less reliable, many false positives)
     */
    private fun detectTracker(
        name: String,
        mfgData: JSONObject?,
        serviceUuids: JSONArray?,
        serviceData: JSONObject?,
        rawBytes: ByteArray?
    ): TrackerInfo? {
        // ── Layer 1: Manufacturer-specific data ───────────────────────────────────
        if (mfgData != null) {
            // Apple: check for 0x004C company ID
            if (mfgData.has("0x004C")) {
                val tracker = detectAppleTracker(mfgData.getString("0x004C"))
                if (tracker != null) return tracker
            }

            // Samsung — DELIBERATELY NOT matched by manufacturer data alone.
            // Company ID 0x0075 is used by EVERY Samsung BLE device (phones, earbuds, watches,
            // TVs). Samsung TVs and their remotes even embed their own MAC in the manufacturer
            // data for the BLE remote-pairing advertisement (Samsung patents US12604351 /
            // US11533766) — the "MAC in manufacturer data" pattern previously misread as a
            // SmartTag fingerprint (confirmed in the field: a Samsung 4K TV broadcast
            // 42 04 01 80 6E <MAC> <derived-ID> …). Real SmartTags are identified by their
            // service UUID 0xFD5A/0xFD59 (Layer 2), NOT by manufacturer data.

            // Tile / Chipolo / Pebblebee / Google / Nut — NOT matched here. Their old
            // company-ID entries were wrong (0x0137 ≠ Tile, 0x019D = CVS Health, 0x0171 =
            // Amazon, 0x0157 ≠ Google, 0xFE95 = Xiaomi) and none of these ecosystems
            // actually signal via manufacturer data — they use service UUIDs / service
            // data (Layers 2-4) or Find My network payloads (Apple 0x004C above).
        }

        // ── Layer 2: Service UUIDs ────────────────────────────────────────────────
        if (serviceUuids != null) {
            val uuids = mutableListOf<String>()
            for (i in 0 until serviceUuids.length()) {
                uuids.add(serviceUuids.optString(i).lowercase())
            }

            for (uuid in uuids) {
                when {
                    uuid in SAMSUNG_SMARTTAG_SERVICE_UUIDS -> TrackerInfo("smarttag", "Samsung", "high",
                        "Samsung SmartTag detected via service UUID (0xFD5A/0xFD59)",
                        samsungPrivacyId(serviceData))
                    uuid in TILE_SERVICE_UUIDS -> return TrackerInfo("tile", "Tile", "high",
                        "Tile tracker detected via service UUID (0xFEED/0xFEEC)")
                    uuid in CHIPOLO_SERVICE_UUIDS -> return TrackerInfo("chipolo", "Chipolo", "high",
                        "Chipolo tracker detected via service UUID (0xFE33)")
                    uuid in PEBBLEBEE_SERVICE_UUIDS -> return TrackerInfo("pebblebee", "Pebblebee", "high",
                        "Pebblebee tracker detected via service UUID (0xFA25)")
                }
            }
        }

        // ── Layer 3: Device name heuristics ───────────────────────────────────────
        val lowerName = name.lowercase().trim()
        if (lowerName.isNotEmpty()) {
            when {
                // Apple AirTag shows as "AirTag" or Apple Find My device
                lowerName.contains("airtag") -> return TrackerInfo("airtag", "Apple", "high",
                    "Apple AirTag detected by name broadcast")
                lowerName.startsWith("find my") || lowerName.contains("apple find") -> return TrackerInfo(
                    "find_my", "Apple", "high", "Apple Find My device detected by name")

                // Tile
                lowerName.matches(Regex("^tile\\s|\\stile\\s|\\stile$")) -> return TrackerInfo(
                    "tile", "Tile", "high", "Tile tracker detected by name broadcast")
                lowerName.contains("tile mate") || lowerName.contains("tile pro") ||
                lowerName.contains("tile slim") || lowerName.contains("tile sticker") -> return TrackerInfo(
                    "tile", "Tile", "high", "Tile tracker detected by name: $lowerName")

                // Samsung SmartTag
                lowerName.contains("smarttag") || lowerName.contains("smart tag") -> return TrackerInfo(
                    "smarttag", "Samsung", "high", "Samsung SmartTag detected by name broadcast")

                // Chipolo
                lowerName.contains("chipolo") -> return TrackerInfo("chipolo", "Chipolo", "high",
                    "Chipolo tracker detected by name broadcast")

                // Nut
                lowerName.contains("nut") && (lowerName.contains("tag") || lowerName.contains("mini") ||
                    lowerName.contains("pet")) -> return TrackerInfo("nut", "Nut/Nuttag", "medium",
                    "Nut/Nuttag tracker detected by name broadcast")

                // Pebblebee
                lowerName.contains("pebblebee") || lowerName.startsWith("pb - ") -> return TrackerInfo(
                    "pebblebee", "Pebblebee", "high", "Pebblebee tracker detected by name broadcast")

                // Eone
                lowerName.contains("eone") || lowerName.contains("newton") || lowerName.contains("bradley") -> return TrackerInfo(
                    "eone", "Eone", "medium", "Eone tracker detected by name broadcast")

                // Generic tracker names
                lowerName.contains("tracker") || lowerName.contains("tracker") -> return TrackerInfo(
                    "generic", "Unknown", "low", "Possible tracker detected by name: $lowerName")

                // iTrack / TagIt
                lowerName.contains("itrack") || lowerName.contains("tagit") -> return TrackerInfo(
                    "generic", "Unknown", "medium", "Possible tracker detected by name: $lowerName")
            }
        }

        // ── Layer 4: Raw advertisement analysis (BLE scan record bytes) ────────────
        // Google Find My Device network beacons advertise SERVICE DATA under UUID 0xFEAA
        // with a frame byte 0x40 (near owner) / 0x41 (separated, anti-stalking) followed by
        // a 20-byte ephemeral ID (Google FMDN accessory spec / GoogleFindMyTools).
        // 0xFEAA is shared with Eddystone beacons, so the frame byte is what distinguishes
        // a tracker — parse the actual AD structures from the raw record.
        if (rawBytes != null && rawBytes.size > 5) {
            if (isGoogleFmdnFrame(rawBytes)) {
                return TrackerInfo("find_my_device", "Google", "high",
                    "Google Find My Device tracker detected — service data 0xFEAA frame 0x40/0x41",
                    googleFmdnEid(serviceData))
            }
        }

        return null
    }

    /**
     * Samsung SmartTag stable identity: the 8-byte privacy ID at bytes 4-11 of the
     * FD5A/FD59 service data (USENIX Security '24 / AirGuard SamsungTracker.kt — the same
     * bytes AirGuard uses as getUniqueIdentifier). The advertised MAC rotates (RPA every
     * ~15 min) but the privacy ID stays stable, so this is the correct dedup/safelist key.
     */
    private fun samsungPrivacyId(serviceData: JSONObject?): String? {
        if (serviceData == null) return null
        for (key in SAMSUNG_SMARTTAG_SERVICE_UUIDS) {
            val hex = serviceData.optString(key, "")
            if (hex.length >= 24) return hex.substring(8, 24).uppercase()   // bytes 4..11
        }
        return null
    }

    /**
     * Google Find My Device Network stable identity: the 20-byte ephemeral ID that follows
     * the 0x40/0x41 frame byte in the 0xFEAA service data. Rotates but is stable per tag.
     */
    private fun googleFmdnEid(serviceData: JSONObject?): String? {
        if (serviceData == null) return null
        val hex = serviceData.optString(GOOGLE_FMDN_SERVICE_UUID, "")
        if (hex.length >= 42) return hex.substring(2, 42).uppercase()   // after the frame byte
        return null
    }

    /**
     * Scan the raw advertisement record for a Google Find My Device Network (FMDN) service-data
     * frame: AD type 0x16 (Service Data — 16-bit UUID), UUID 0xFEAA, followed by a frame byte
     * whose high nibble is 0x4 (0x40 near-owner / 0x41 separated). Returns false for Eddystone
     * (0xFEAA without the 0x4x frame) and anything else.
     */
    private fun isGoogleFmdnFrame(rawBytes: ByteArray): Boolean {
        var i = 0
        while (i + 1 < rawBytes.size) {
            val len = rawBytes[i].toInt() and 0xFF
            if (len == 0) break
            val type = rawBytes[i + 1].toInt() and 0xFF
            if (type == 0x16 && len >= 4 && i + 4 < rawBytes.size) {   // Service Data — 16-bit UUID
                val uuidLo = rawBytes[i + 2].toInt() and 0xFF
                val uuidHi = rawBytes[i + 3].toInt() and 0xFF
                if (uuidLo == (GOOGLE_FMDN_UUID_LO.toInt() and 0xFF) &&
                    uuidHi == (GOOGLE_FMDN_UUID_HI.toInt() and 0xFF)) {
                    val frame = rawBytes[i + 4].toInt() and 0xFF
                    return (frame and 0xF0) == 0x40   // 0x40 / 0x41
                }
            }
            i += len + 1
        }
        return false
    }

    /**
     * Detect Apple Find My network devices from manufacturer data.
     * The value stored here is the payload AFTER the company ID: [type_byte][length][status][key…].
     * The FIRST byte is the type: 0x12 = Find My network payload (registered accessory),
     * 0x07 = unpaired/setup-mode AirTag. (The old code compared the STATUS byte — 0x10 only
     * means "full battery" — against the type table, missing medium/low-battery tags.)
     */
    private fun detectAppleTracker(hexData: String): TrackerInfo? {
        // Remove any separators and parse
        val clean = hexData.replace(Regex("[^0-9a-fA-F]"), "")
        if (clean.length < 4) return null

        val typeHex = clean.substring(0, 2)
        val typeByte = typeHex.toIntOrNull(16) ?: return null

        return when (typeByte) {
            // Registered Find My network accessory (AirTag, Chipolo One Spot, Pebblebee,
            // Moto Tag, etc.) — any of them is a possible tracker. The 23-byte P-224 public
            // key (bytes 3..25 after the company ID: [0x12][0x19][status][key…]) is the tag's
            // STABLE per-day identity — the advertised address rotates (derived from the key),
            // so this is the correct dedup key, exactly like Samsung's privacy ID.
            APPLE_TYPE_FIND_MY -> TrackerInfo("find_my", "Apple", "high",
                "Apple Find My network device detected — manufacturer data type 0x${typeHex}",
                if (clean.length >= 52) clean.substring(6, 52).uppercase() else null)
            // Unpaired AirTag in setup mode (pre-registration) — still a tracker. Unpaired
            // AirTags use a STABLE public address (no rotation), so MAC-based dedup works.
            APPLE_TYPE_UNPAIRED -> TrackerInfo("airtag", "Apple", "high",
                "Unpaired Apple AirTag detected — manufacturer data type 0x${typeHex}")
            // Everything else is an Apple accessory (AirPods, Beats, pairing payloads…),
            // not a tracker signal — matched by type 0x02/0x03 etc. Return null.
            else -> null
        }
    }

    // ── Utility ───────────────────────────────────────────────────────────────────────

    /** Public permission probe — lets the service decide whether a resume attempt can start. */
    fun hasScanPermissions(): Boolean = hasPermissions()

    private fun hasPermissions(): Boolean {
        // ACCESS_FINE_LOCATION is required for BLE scans on ALL supported API levels
        // (26–30) and for scanning on 31+ where it gates RF exposure. On API 31+ the
        // runtime BLUETOOTH_SCAN/CONNECT permissions are also required; on 26–30 those
        // constants don't even exist, and classic discovery is covered by the install-time
        // BLUETOOTH/BLUETOOTH_ADMIN normal permissions instead.
        val loc = context.checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION)
        if (loc != android.content.pm.PackageManager.PERMISSION_GRANTED) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val scan = context.checkSelfPermission(android.Manifest.permission.BLUETOOTH_SCAN)
            if (scan != android.content.pm.PackageManager.PERMISSION_GRANTED) return false
        }
        return true
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(String.format("%02x", b))
        return sb.toString()
    }
}
