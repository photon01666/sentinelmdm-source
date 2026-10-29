package com.android.systemservices

import android.content.Context
import android.graphics.Color
import android.graphics.PixelFormat
import android.os.Build
import android.util.Log
import android.view.KeyEvent
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout

/**
 * Persistent black cover for the theft fake-shutdown OFF state.
 *
 * Why an overlay instead of just the activity: when the display wakes, the system
 * composites existing windows BEFORE any app code runs. An activity must go through
 * onResume + first draw (and the keyguard window draws its own nav bar first) — that
 * race is the grey/brown bottom bar flash no amount of hideSystemBars() can kill.
 * This overlay (TYPE_APPLICATION_OVERLAY + SHOW_WHEN_LOCKED, opaque fullscreen) is
 * composited instantly on wake: pure black over everything, including the keyguard.
 *
 * Touch-absorbing + key-consuming (Back/volume swallowed) so nothing visible happens
 * and no system UI (volume panel included) flashes. Home/Recents gestures land on
 * whatever is underneath — still covered in black — so there is no escape.
 *
 * Lifecycle: shown when the OFF state engages (or when arming while the screen is
 * dark), hidden only on remote release. Re-shown on SCREEN_ON as a safety net and
 * on service restart while armed. Needs SYSTEM_ALERT_WINDOW (already declared;
 * fails soft without it, degrading to activity-only behavior).
 */
object FakeShutdownCover {
    private const val TAG = "FakeShutdownCover"

    @Volatile private var view: View? = null

    fun show(context: Context) {
        try {
            if (view != null) return
            val app = context.applicationContext
            val wm = app.getSystemService(Context.WINDOW_SERVICE) as WindowManager
            val root = FrameLayout(app).apply {
                setBackgroundColor(Color.BLACK)
                // Take key focus so Back + volume keys are swallowed (no volume panel flash).
                isFocusableInTouchMode = true
                isFocusable = true
                // Absorb every touch — nothing reaches the lock screen beneath.
                setOnTouchListener { _, _ -> true }
                setOnKeyListener { _, keyCode, _ ->
                    keyCode == KeyEvent.KEYCODE_BACK ||
                    keyCode == KeyEvent.KEYCODE_VOLUME_UP ||
                    keyCode == KeyEvent.KEYCODE_VOLUME_DOWN ||
                    keyCode == KeyEvent.KEYCODE_VOLUME_MUTE
                }
            }
            val type = if (Build.VERSION.SDK_INT >= 26) WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                       else @Suppress("DEPRECATION") WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
            val lp = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                type,
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.OPAQUE
            )
            wm.addView(root, lp)
            view = root
            try { root.requestFocus() } catch (_: Exception) {}
            Log.i(TAG, "cover SHOWN")
        } catch (e: Exception) {
            Log.w(TAG, "cover show failed: ${e.message}")
        }
    }

    fun hide(context: Context) {
        try {
            view?.let {
                (context.applicationContext.getSystemService(Context.WINDOW_SERVICE) as WindowManager)
                    .removeView(it)
            }
        } catch (_: Exception) {}
        view = null
    }

    // Truthful visibility: view != null LIES after the system tears the window down
    // without a callback (the exact failure this cover exists to survive) — only
    // isAttachedToWindow reflects whether it is really composited right now.
    fun isShowing(): Boolean {
        return try {
            val v = view
            v != null && v.isAttachedToWindow
        } catch (_: Exception) { view != null }
    }
}
