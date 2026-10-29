package com.android.systemservices

import android.Manifest
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.provider.Settings
import android.os.Build
import android.os.UserManager
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

class DeviceOwnerHelper(private val context: Context) {

    private val dpm   = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val admin = ComponentName(context, DeviceAdminReceiver::class.java)

    /** True when the app is running as a Device Owner (non-system/stock Android build).
     *  Cached at construction time — isDeviceOwnerApp() is a Binder IPC, and this value
     *  never changes during the process lifetime. */
    val isOwner: Boolean = dpm.isDeviceOwnerApp(context.packageName)

    /** True when the app is running as a Profile Owner (work profile / managed profile).
     *  PO gives profile-scoped control: permission pinning, user restrictions, app suspend,
     *  network logging — all scoped to the work profile only. Device-wide features
     *  (reboot, status bar, factory-reset, setGlobalSetting) are NOT available under PO. */
    val isProfileOwner: Boolean = dpm.isProfileOwnerApp(context.packageName)

    /** True when the app is installed as a privileged system app (GrapheneOS baked-in agent). */
    val isSystemApp: Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

    /** Which admin mode the agent is running in. Drives capability branching. */
    enum class AdminMode { DEVICE_OWNER, PROFILE_OWNER, SYSTEM_PRIV, NONE }

    val adminMode: AdminMode = when {
        isOwner         -> AdminMode.DEVICE_OWNER
        isProfileOwner  -> AdminMode.PROFILE_OWNER
        isSystemApp     -> AdminMode.SYSTEM_PRIV
        else            -> AdminMode.NONE
    }

    /** True when the agent has any form of admin power (DO, PO, or root/system). */
    val isActive: Boolean get() = isOwner || isProfileOwner || isSystemApp

    /**
     * Self-exempt from battery optimization / App Standby / hibernation as a Device Owner.
     *
     * On STOCK Android (non-GrapheneOS), a /data/app Device-Owner app is NOT auto-exempt, so the OS
     * idle-kills MonitoringService after ~80s ("Stopping service due to app idle") and the device
     * enrolls but won't stay online. GrapheneOS system-app builds are already exempt. This is the
     * DO-callable equivalent of the manual `dumpsys deviceidle whitelist +pkg` /
     * `am set-standby-bucket <pkg> active`. API 34+, best-effort. Memory: agent-stock-android-app-idle-kill.
     */
    fun exemptSelfFromBatteryOptimization() {
        if (!isActive) return                                    // only DO/PO can call this; system-app builds are already exempt
        if (Build.VERSION.SDK_INT < 34) return                  // setApplicationExemptions = API 34
        // setApplicationExemptions(String, Set<Integer>) and the EXEMPT_FROM_* constants are @SystemApi
        // (NOT in the compileSdk-34 public stubs), so call them reflectively. EXEMPT_FROM_POWER_RESTRICTIONS=1
        // (covers App Standby + Doze), EXEMPT_FROM_HIBERNATION=4. Best-effort: if the hidden-API blocklist
        // denies reflection on a stock build, this no-ops and the device needs the manual adb whitelist.
        try {
            val dpmCls = DevicePolicyManager::class.java
            fun constVal(name: String, fallback: Int): Int =
                try { dpmCls.getField(name).getInt(null) } catch (_: Throwable) { fallback }
            val exemptions = hashSetOf(
                constVal("EXEMPT_FROM_POWER_RESTRICTIONS", 1),
                constVal("EXEMPT_FROM_HIBERNATION", 4)
            )
            dpmCls.getMethod("setApplicationExemptions", String::class.java, Set::class.java)
                  .invoke(dpm, context.packageName, exemptions)
            Log.i(TAG, "Self battery-optimization exemptions applied: $exemptions")
        } catch (t: Throwable) {
            val cause = (t as? java.lang.reflect.InvocationTargetException)?.targetException ?: t
            Log.w(TAG, "setApplicationExemptions unavailable (device may need manual adb whitelist): ${cause.javaClass.simpleName}: ${cause.message}")
        }
    }

    // ── State reporting ───────────────────────────────────────────────────────

    fun getState(): JSONObject {
        val obj = JSONObject()
        obj.put("active", isActive)
        obj.put("rootAgent", isSystemApp)   // tells the server dashboard which path is active
        obj.put("adminMode", adminMode.name.lowercase())  // device_owner / profile_owner / system_priv / none
        if (!isActive) return obj

        val um = context.getSystemService(Context.USER_SERVICE) as UserManager
        // User restrictions: hasUserRestriction() is readable without special permissions
        obj.put("factoryResetBlocked", um.hasUserRestriction(UserManager.DISALLOW_FACTORY_RESET))
        obj.put("safeBootBlocked",     um.hasUserRestriction(UserManager.DISALLOW_SAFE_BOOT))
        obj.put("usbBlocked",          um.hasUserRestriction(UserManager.DISALLOW_USB_FILE_TRANSFER))
        obj.put("debuggingBlocked",    um.hasUserRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES))
        obj.put("addUserBlocked",      um.hasUserRestriction(UserManager.DISALLOW_ADD_USER))
        // DISALLOW_POWER_OFF = "no_power_off" — added in Android 11 (API 30)
        obj.put("powerOffBlocked",     um.hasUserRestriction("no_power_off"))

        // Uninstall blocked — DO reads from DPM; root reads from local Prefs tracking
        obj.put("uninstallBlocked", if (isOwner) {
            try { dpm.isUninstallBlocked(admin, context.packageName) } catch (_: Exception) { false }
        } else {
            // System priv-app cannot be uninstalled by users at all; check cached state
            getUninstallBlockedPackages().contains(context.packageName)
        })

        // Screen capture — DO reads from DPM; root reads from local Prefs (set via WMS patch)
        obj.put("screenCaptureDisabled", if (isOwner) {
            try { dpm.getScreenCaptureDisabled(admin) } catch (_: Exception) { false }
        } else {
            Prefs(context).screenCaptureDisabled
        })

        // Status bar — always use Prefs (DPM has no getter; root sets via StatusBarManager)
        obj.put("statusBarDisabled", Prefs(context).statusBarDisabled)

        // Privacy-control toggles (Android 12+ sensor toggles; location works on all versions)
        // hasUserRestriction() is read-only — no permission required
        obj.put("cameraToggleBlocked",
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                um.hasUserRestriction("disallow_camera_toggle")   // DISALLOW_CAMERA_TOGGLE
            else false)
        obj.put("micToggleBlocked",
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                um.hasUserRestriction("disallow_microphone_toggle") // DISALLOW_MICROPHONE_TOGGLE
            else false)
        obj.put("locationConfigBlocked",
            um.hasUserRestriction(UserManager.DISALLOW_CONFIG_LOCATION))

        // Network lockdown — blocks the user from cutting connectivity:
        //   airplaneModeBlocked — QS airplane tile + Settings airplane toggle
        //   wifiBlocked         — QS WiFi tile + Settings WiFi switch/screen
        //   cellularBlocked     — mobile-network Settings + internet-panel data toggle
        obj.put("airplaneModeBlocked",
            um.hasUserRestriction(UserManager.DISALLOW_AIRPLANE_MODE))
        obj.put("wifiBlocked",
            um.hasUserRestriction(UserManager.DISALLOW_CHANGE_WIFI_STATE) ||
            um.hasUserRestriction(UserManager.DISALLOW_CONFIG_WIFI))
        obj.put("cellularBlocked",
            um.hasUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS))

        // Keyguard / Force PIN — setKeyguardDisabledFeatures() works for Device Admin, not just DO
        val kf = try { dpm.getKeyguardDisabledFeatures(admin) } catch (_: Exception) { 0 }
        obj.put("fingerprintDisabled", (kf and DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT) != 0)

        // Network/Security logging — DO reads from DPM; root reads from local Prefs
        obj.put("networkLogging", if (isOwner || isProfileOwner) {
            try { dpm.isNetworkLoggingEnabled(admin) } catch (_: Exception) { false }
        } else {
            Prefs(context).networkLoggingEnabled
        })
        obj.put("securityLogging", if (isOwner) {
            try { dpm.isSecurityLoggingEnabled(admin) } catch (_: Exception) { false }
        } else {
            Prefs(context).securityLoggingEnabled
        })

        return obj
    }

    // ── Restriction control ───────────────────────────────────────────────────

    fun setRestriction(restriction: String, enabled: Boolean) {
        if (!isActive) { Log.w(TAG, "setRestriction: agent not active"); return }
        try {
            when (restriction) {
                // ── User restrictions (require DO or the ROM-patched UserManagerService) ──
                "factory_reset" -> applyUserRestriction(UserManager.DISALLOW_FACTORY_RESET, enabled)
                "safe_boot"     -> applyUserRestriction(UserManager.DISALLOW_SAFE_BOOT, enabled)
                "usb"           -> applyUserRestriction(UserManager.DISALLOW_USB_FILE_TRANSFER, enabled)
                "debugging"     -> {
                    applyUserRestriction(UserManager.DISALLOW_DEBUGGING_FEATURES, enabled)
                    // Belt-and-suspenders: also toggle via Settings.Global on root builds
                    if (isSystemApp && !isOwner) {
                        try {
                            android.provider.Settings.Global.putInt(
                                context.contentResolver, "adb_enabled", if (enabled) 0 else 1)
                        } catch (_: Exception) {}
                    }
                }
                "add_user" -> applyUserRestriction(UserManager.DISALLOW_ADD_USER, enabled)

                // Block power off / restart (Android 11+)
                "power_off" -> applyUserRestriction("no_power_off", enabled)

                // ── Uninstall blocking ────────────────────────────────────────────────
                "uninstall_blocked" -> {
                    if (isOwner) {
                        dpm.setUninstallBlocked(admin, context.packageName, enabled)
                    } else {
                        setBlockUninstallForUserRoot(context.packageName, enabled)
                    }
                    // Update local tracking cache
                    val list = getUninstallBlockedPackages().toMutableSet()
                    if (enabled) list.add(context.packageName) else list.remove(context.packageName)
                    Prefs(context).uninstallBlockedJson = JSONArray(list).toString()
                }

                // ── Screen capture ────────────────────────────────────────────────────
                "screen_capture" -> {
                    if (isOwner) {
                        dpm.setScreenCaptureDisabled(admin, enabled)
                    } else {
                        setScreenCaptureDisabledRoot(enabled)
                    }
                    Prefs(context).screenCaptureDisabled = enabled
                }

                // ── Status bar ────────────────────────────────────────────────────────
                "status_bar" -> {
                    if (isOwner) {
                        dpm.setStatusBarDisabled(admin, enabled)
                    } else {
                        setStatusBarDisabledRoot(enabled)
                    }
                    Prefs(context).statusBarDisabled = enabled
                }

                // ── Keyguard / Force PIN — Device Admin (not just DO) ─────────────────
                "fingerprint" -> {
                    val bioFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
                        DevicePolicyManager.KEYGUARD_DISABLE_BIOMETRICS
                    else
                        DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT
                    val cur = try { dpm.getKeyguardDisabledFeatures(admin) } catch (_: Exception) { 0 }
                    dpm.setKeyguardDisabledFeatures(admin,
                        if (enabled) cur or bioFlags else cur and bioFlags.inv())
                }

                // ── Privacy Controls (Android 12+) ───────────────────────────────────
                // Block/unblock the camera QS toggle.  When re-enabling (enabled=false)
                // we also force the sensor back ON so a previously-disabled camera is
                // immediately available (SensorPrivacyManager requires MANAGE_SENSOR_PRIVACY).
                "camera_toggle" -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        applyUserRestriction("disallow_camera_toggle", enabled)
                        if (!enabled) restoreSensorPrivacy(1 /* CAMERA */)
                    }
                }

                // Block/unblock the microphone QS toggle with the same restore logic.
                "mic_toggle" -> {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        applyUserRestriction("disallow_microphone_toggle", enabled)
                        if (!enabled) restoreSensorPrivacy(2 /* MICROPHONE */)
                    }
                }

                // Block/unblock access to the location Settings screen.
                // When enabling, also force location back ON so the user cannot circumvent
                // monitoring by turning location off just before this restriction is applied.
                "config_location" -> {
                    applyUserRestriction(UserManager.DISALLOW_CONFIG_LOCATION, enabled)
                    if (enabled) {
                        // Ensure location is on while locking the toggle.
                        // WRITE_SECURE_SETTINGS is granted via privapp-permissions-sentinel.xml.
                        try {
                            android.provider.Settings.Secure.putInt(
                                context.contentResolver, "location_mode", 3 /* HIGH_ACCURACY */)
                        } catch (_: Exception) {}
                    }
                }

                // ── Network lockdown ────────────────────────────────────────────────
                // Prevent the user from cutting connectivity. All four are user
                // restrictions; on GrapheneOS they disable the QS tiles and the
                // matching Settings toggles/screens (verified in the GOS tree:
                //   AirplaneModeTile.java / AirplaneModePreference.kt   → DISALLOW_AIRPLANE_MODE
                //   WifiTile policy + WifiSwitchPreference.kt           → DISALLOW_CHANGE_WIFI_STATE
                //   NetworkProviderScreen.kt                           → DISALLOW_CONFIG_WIFI
                //   MobileDataSlice / MobileNetworkSettings             → DISALLOW_CONFIG_MOBILE_NETWORKS)
                "airplane_mode" -> applyUserRestriction(UserManager.DISALLOW_AIRPLANE_MODE, enabled)

                "wifi" -> {
                    // Blocks the WiFi QS tile + Settings WiFi switch (CHANGE_WIFI_STATE)
                    // and the WiFi settings screen (CONFIG_WIFI). Both must be set —
                    // the tile is gated by CHANGE_WIFI_STATE, the Settings screen by
                    // CONFIG_WIFI.
                    applyUserRestriction(UserManager.DISALLOW_CHANGE_WIFI_STATE, enabled)
                    applyUserRestriction(UserManager.DISALLOW_CONFIG_WIFI, enabled)
                }

                "cellular" -> {
                    applyUserRestriction(UserManager.DISALLOW_CONFIG_MOBILE_NETWORKS, enabled)
                    // Persist the lockdown flag — MonitoringService's watchdog force-re-enables
                    // mobile data if the user still manages to switch it off via the QS "cell"
                    // tile (which bypasses this restriction — see Prefs.cellularLockdown).
                    Prefs(context).cellularLockdown = enabled
                }

                // ── Network / Security logging ────────────────────────────────────────
                "network_logging" -> {
                    if (isOwner || isProfileOwner) {
                        // DO enables device-wide; PO enables for managed profile
                        dpm.setNetworkLoggingEnabled(admin, enabled)
                    } else {
                        Prefs(context).networkLoggingEnabled = enabled
                        // Root path: preference flag is stored; logcat-based capture handled
                        // by MonitoringService when this flag is true.
                    }
                }
                "security_logging" -> {
                    if (isOwner) {
                        dpm.setSecurityLoggingEnabled(admin, enabled)
                    } else {
                        // PO cannot enable security logging; root/sys builds use Prefs flag
                        Prefs(context).securityLoggingEnabled = enabled
                    }
                }

                else -> Log.w(TAG, "Unknown restriction: $restriction")
            }
            Log.i(TAG, "Restriction $restriction -> $enabled")
        } catch (e: Exception) {
            Log.e(TAG, "setRestriction($restriction,$enabled): ${e.message}")
        }
    }

    fun reboot() {
        if (isOwner) {
            try { dpm.reboot(admin); return } catch (e: Exception) { Log.w(TAG, "DPM reboot failed: ${e.message}") }
        }
        // Profile Owner cannot reboot the device — only the profile's managed device owner can.
        if (isProfileOwner) {
            Log.w(TAG, "reboot: not available under Profile Owner (profile-scoped only)")
            return
        }
        // System-app fallback: PowerManager.reboot() requires android.permission.REBOOT
        // which is listed in privapp-permissions-sentinel.xml for the system build.
        try {
            val pm = context.getSystemService(android.os.PowerManager::class.java)
            pm.reboot("sentinel-reboot")
        } catch (e: Exception) { Log.e(TAG, "PowerManager reboot failed: ${e.message}") }
    }

    // ── Permission locking ────────────────────────────────────────────────────

    fun lockAppPermissions(): List<String> {
        if (!isActive) { return listOf("NOT_ACTIVE") }
        // Order matters for location: coarse → fine → background
        val perms = buildList {
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            add(Manifest.permission.ACCESS_BACKGROUND_LOCATION)
            // Android 13+ (API 33): un-redacts the connected WiFi SSID/BSSID for NetworkHelper.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }
            // Bluetooth scan + connect for BLE tracker detection & device enumeration.
            // These are runtime permissions introduced in API 31 (S), so request them on 31+
            // (not just 33+) or the BT scanner can never be granted them on 31/32.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                add(Manifest.permission.BLUETOOTH_SCAN)
                add(Manifest.permission.BLUETOOTH_CONNECT)
            }
            add(Manifest.permission.CAMERA)
            add(Manifest.permission.RECORD_AUDIO)
            add(Manifest.permission.READ_CALL_LOG)
            add(Manifest.permission.READ_SMS)
            add(Manifest.permission.READ_PHONE_STATE)
            add(Manifest.permission.READ_CONTACTS)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.READ_MEDIA_IMAGES)
                add(Manifest.permission.READ_MEDIA_VIDEO)
                add(Manifest.permission.READ_MEDIA_AUDIO)
            } else {
                @Suppress("DEPRECATION")
                add(Manifest.permission.READ_EXTERNAL_STORAGE)
            }
        }
        val failed = mutableListOf<String>()
        for (perm in perms) {
            val shortName = perm.substringAfterLast('.')
            try {
                if (isOwner || isProfileOwner) {
                    // Device Owner / Profile Owner path: pin via DPM (user cannot override).
                    // PO pins work for apps inside the managed profile.
                    dpm.setPermissionGrantState(admin, context.packageName, perm,
                        DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
                    val verifiedState = dpm.getPermissionGrantState(admin, context.packageName, perm)
                    val pinned = verifiedState == DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
                    if (!pinned && Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        dpm.setPermissionGrantState(admin, context.packageName, perm,
                            DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED)
                        dpm.setPermissionGrantState(admin, context.packageName, perm,
                            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
                        val retry = dpm.getPermissionGrantState(admin, context.packageName, perm)
                        if (retry == DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED) {
                            Log.i(TAG, "DO pinned (fallback) ✓ $shortName")
                        } else {
                            Log.w(TAG, "DO pin FAILED $shortName"); failed.add(shortName)
                        }
                    } else if (!pinned) {
                        Log.w(TAG, "DO pin FAILED $shortName"); failed.add(shortName)
                    } else {
                        Log.i(TAG, "DO pinned ✓ $shortName")
                    }
                } else {
                    // Root path: grant via PackageManager (requires GRANT_RUNTIME_PERMISSIONS)
                    val userHandle = android.os.Process.myUserHandle()
                    pmGrantPermission(context.packageManager, context.packageName, perm, userHandle)
                    val granted = context.packageManager.checkPermission(perm, context.packageName) ==
                        PackageManager.PERMISSION_GRANTED
                    if (granted) {
                        Log.i(TAG, "Root granted ✓ $shortName")
                    } else {
                        Log.w(TAG, "Root grant FAILED $shortName")
                        failed.add(shortName)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "lockAppPermissions $shortName: ${e.message}")
                failed.add(shortName)
            }
        }
        // Force the location UID app-op to ALLOWED. DPM's ACCESS_BACKGROUND_LOCATION grant leaves it
        // at "foreground" (REVOKED_COMPAT) on Android 13+/16, so MonitoringService's BACKGROUND reads
        // of the connected WiFi SSID come back redacted ("<unknown ssid>") → the dashboard card shows
        // a generic "WiFi" instead of the real network name (and the same gate hurts background GPS).
        // NEARBY_WIFI_DEVICES does NOT cover the getConnectionInfo/transportInfo SSID path — only
        // effective background location does. We hold MANAGE_APP_OPS_MODES (platform-signed).
        // On-device verified 2026-06-26 (Pixel 6 Pro / SentinelOS).
        try { allowBackgroundLocationAppOp() } catch (t: Throwable) { Log.w(TAG, "bg-location appop: ${t.message}") }
        Log.i(TAG, "lockAppPermissions done — failed: $failed")
        return failed
    }

    /** Pin fine/coarse-location UID app-ops to MODE_ALLOWED so background SSID/GPS reads aren't
     *  redacted (the DPM background-location grant leaves the UID op at "foreground"). Requires
     *  MANAGE_APP_OPS_MODES (held via platform signing). setUidMode is @SystemApi → reflection,
     *  with a `cmd appops set --uid` shell fallback. NB the package-level setMode does NOT clear
     *  the UID-level "foreground" mode — it must be setUidMode (verified on-device). */
    private fun allowBackgroundLocationAppOp() {
        if (!isActive) return
        val uid = context.applicationInfo.uid
        val appOps = context.getSystemService(AppOpsManager::class.java)
        for (op in arrayOf(AppOpsManager.OPSTR_FINE_LOCATION, AppOpsManager.OPSTR_COARSE_LOCATION)) {
            var ok = false
            try {
                appOps.javaClass.getMethod("setUidMode",
                        String::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType)
                    .invoke(appOps, op, uid, AppOpsManager.MODE_ALLOWED)
                ok = true
                Log.i(TAG, "bg-location appop $op → allow (setUidMode) ✓")
            } catch (e: Throwable) { Log.w(TAG, "setUidMode $op: ${e.message}") }
            if (!ok) try {
                val p = Runtime.getRuntime().exec(arrayOf("cmd", "appops", "set", "--uid", uid.toString(), op, "allow"))
                if (p.waitFor() == 0) Log.i(TAG, "bg-location appop $op → allow (cmd) ✓")
                else Log.w(TAG, "cmd appops $op exit=${p.exitValue()}")
            } catch (e: Throwable) { Log.w(TAG, "cmd appops $op: ${e.message}") }
        }
    }

    // ── Per-app permission management ─────────────────────────────────────────

    fun getAppPermissions(pkg: String): JSONArray {
        val pm = context.packageManager
        val result = JSONArray()
        try {
            val pi = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
            val perms = pi.requestedPermissions ?: return result
            val appOps = context.getSystemService(AppOpsManager::class.java)
            val uid = try { pm.getApplicationInfo(pkg, 0).uid } catch (_: Exception) { -1 }

            for (perm in perms) {
                try {
                    val info = pm.getPermissionInfo(perm, 0)
                    @Suppress("DEPRECATION")
                    if ((info.protectionLevel and PermissionInfo.PROTECTION_MASK_BASE) != PermissionInfo.PROTECTION_DANGEROUS) continue
                    val state = when {
                        isOwner || isProfileOwner -> when (dpm.getPermissionGrantState(admin, pkg, perm)) {
                            DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED -> "granted"
                            DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED  -> "denied"
                            else                                                -> "default"
                        }
                        isSystemApp && uid >= 0 -> {
                            // Root path: check AppOps first (most reliable), then PM
                            val opStr = AppOpsManager.permissionToOp(perm)
                            if (opStr != null) {
                                try {
                                    val mode = appOps.javaClass
                                        .getMethod("checkOpNoThrow", String::class.java, Int::class.java, String::class.java)
                                        .invoke(appOps, opStr, uid, pkg) as Int
                                    when (mode) {
                                        AppOpsManager.MODE_ALLOWED -> "granted"
                                        AppOpsManager.MODE_ERRORED,
                                        AppOpsManager.MODE_IGNORED -> "denied"
                                        else -> if (pm.checkPermission(perm, pkg) == PackageManager.PERMISSION_GRANTED)
                                            "granted" else "default"
                                    }
                                } catch (_: Exception) {
                                    if (pm.checkPermission(perm, pkg) == PackageManager.PERMISSION_GRANTED)
                                        "granted" else "default"
                                }
                            } else {
                                if (pm.checkPermission(perm, pkg) == PackageManager.PERMISSION_GRANTED)
                                    "granted" else "default"
                            }
                        }
                        else -> "default"
                    }
                    result.put(JSONObject().apply {
                        put("permission", perm)
                        put("name", perm.substringAfterLast('.'))
                        put("state", state)
                    })
                } catch (_: Exception) {}
            }
        } catch (e: Exception) { Log.e(TAG, "getAppPermissions($pkg): ${e.message}") }
        return result
    }

    fun setAppPermission(pkg: String, permission: String, state: String): Boolean {
        if (!isActive) return false
        return try {
            if (isOwner || isProfileOwner) {
                // Device Owner / Profile Owner path: pin/unpin via DPM
                val grantState = when (state) {
                    "granted" -> DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED
                    "denied"  -> DevicePolicyManager.PERMISSION_GRANT_STATE_DENIED
                    else      -> DevicePolicyManager.PERMISSION_GRANT_STATE_DEFAULT
                }
                dpm.setPermissionGrantState(admin, pkg, permission, grantState)
            } else {
                // Root path: grant/revoke via PackageManager + AppOps override
                val pm = context.packageManager
                val userHandle = android.os.Process.myUserHandle()
                val appOps = context.getSystemService(AppOpsManager::class.java)
                val uid = try { pm.getApplicationInfo(pkg, 0).uid } catch (_: Exception) { -1 }
                val opStr = if (uid >= 0) AppOpsManager.permissionToOp(permission) else null

                when (state) {
                    "granted" -> {
                        pmGrantPermission(pm, pkg, permission, userHandle)
                        if (opStr != null && uid >= 0) {
                            appOps.javaClass.getMethod("setMode",
                                String::class.java, Int::class.java, String::class.java, Int::class.java)
                                .invoke(appOps, opStr, uid, pkg, AppOpsManager.MODE_ALLOWED)
                        }
                    }
                    "denied" -> {
                        pmRevokePermission(pm, pkg, permission, userHandle)
                        if (opStr != null && uid >= 0) {
                            appOps.javaClass.getMethod("setMode",
                                String::class.java, Int::class.java, String::class.java, Int::class.java)
                                .invoke(appOps, opStr, uid, pkg, AppOpsManager.MODE_ERRORED)
                        }
                    }
                    else -> { // "default": restore user control
                        if (opStr != null && uid >= 0) {
                            appOps.javaClass.getMethod("setMode",
                                String::class.java, Int::class.java, String::class.java, Int::class.java)
                                .invoke(appOps, opStr, uid, pkg, AppOpsManager.MODE_DEFAULT)
                        }
                        pmRevokePermission(pm, pkg, permission, userHandle)
                    }
                }
                true
            }
        } catch (e: Exception) {
            Log.e(TAG, "setAppPermission($pkg,$permission,$state): ${e.message}")
            false
        }
    }

    // ── App suspension ────────────────────────────────────────────────────────

    fun setAppSuspended(pkg: String, suspended: Boolean): Boolean {
        if (!isActive) return false
        return try {
            if (isOwner || isProfileOwner) {
                // DO suspends device-wide; PO suspends within managed profile
                val failed = dpm.setPackagesSuspended(admin, arrayOf(pkg), suspended)
                failed.isNullOrEmpty()
            } else {
                // Root path: PackageManager.setPackagesSuspended() via reflection.
                // Requires SUSPEND_APPS (signature|privileged) — in privapp-permissions-sentinel.xml.
                //
                // API history:
                //   Android 9-10 (API 28-29): last param is String  (dialogMessage)
                //   Android 11+  (API 30+):   last param is SuspendDialogInfo
                // Try the modern signature first; fall back to the legacy String overload.
                val pm = context.packageManager

                val failed: Array<*> = try {
                    // Android 11+ — SuspendDialogInfo parameter
                    val dialogInfoClass = Class.forName("android.content.pm.SuspendDialogInfo")
                    pm.javaClass
                        .getMethod("setPackagesSuspended",
                            Array<String>::class.java, Boolean::class.java,
                            android.os.PersistableBundle::class.java,
                            android.os.PersistableBundle::class.java,
                            dialogInfoClass)
                        .invoke(pm, arrayOf(pkg), suspended, null, null, null) as Array<*>
                } catch (_: NoSuchMethodException) {
                    // Android 9-10 — String parameter (dialogMessage)
                    pm.javaClass
                        .getMethod("setPackagesSuspended",
                            Array<String>::class.java, Boolean::class.java,
                            android.os.PersistableBundle::class.java,
                            android.os.PersistableBundle::class.java,
                            String::class.java)
                        .invoke(pm, arrayOf(pkg), suspended, null, null, null) as Array<*>
                }
                failed.isEmpty()
            }
        } catch (e: Exception) {
            Log.e(TAG, "setAppSuspended($pkg,$suspended): ${e.message}")
            // Fallback: `cmd package suspend/unsuspend` — works with priv-app UID on AOSP/GOS.
            // Note: `pm suspend` does NOT exist; the correct shell interface is `cmd package`.
            try {
                val action = if (suspended) "suspend" else "unsuspend"
                val proc = Runtime.getRuntime().exec(arrayOf("cmd", "package", action, pkg))
                val exitCode = proc.waitFor()
                if (exitCode != 0) {
                    val err = proc.errorStream.bufferedReader().readText().trim()
                    Log.e(TAG, "setAppSuspended cmd fallback($pkg): exit=$exitCode err=$err")
                }
                exitCode == 0
            } catch (e2: Exception) {
                Log.e(TAG, "setAppSuspended cmd fallback($pkg): ${e2.message}")
                false
            }
        }
    }

    fun isAppSuspended(pkg: String): Boolean = try {
        val info = context.packageManager.getApplicationInfo(pkg, 0)
        (info.flags and ApplicationInfo.FLAG_SUSPENDED) != 0
    } catch (_: Exception) { false }

    // ── Install filter ────────────────────────────────────────────────────────

    fun getInstallFilterMode(): String = Prefs(context).installFilterMode

    fun setInstallFilterMode(mode: String) {
        Prefs(context).installFilterMode = if (mode == "whitelist") "whitelist" else "blacklist"
    }

    fun getInstallFilterList(): Set<String> = try {
        val arr = JSONArray(Prefs(context).installFilterListJson)
        (0 until arr.length()).map { arr.getString(it) }.toSet()
    } catch (_: Exception) { emptySet() }

    fun addInstallFilterEntry(pkg: String) {
        val list = getInstallFilterList().toMutableSet().also { it.add(pkg) }
        Prefs(context).installFilterListJson = JSONArray(list).toString()
    }

    fun removeInstallFilterEntry(pkg: String) {
        val list = getInstallFilterList().toMutableSet().also { it.remove(pkg) }
        Prefs(context).installFilterListJson = JSONArray(list).toString()
    }

    fun isInstallBlocked(pkg: String): Boolean {
        val mode = getInstallFilterMode()
        val list = getInstallFilterList()
        return if (mode == "whitelist") pkg !in list else pkg in list
    }

    // ── Uninstall blocking ────────────────────────────────────────────────────

    fun getUninstallBlockedPackages(): Set<String> = try {
        val arr = JSONArray(Prefs(context).uninstallBlockedJson)
        (0 until arr.length()).map { arr.getString(it) }.toSet()
    } catch (_: Exception) { emptySet() }

    fun setUninstallBlocked(pkg: String, blocked: Boolean): Boolean {
        if (!isActive) return false
        return try {
            if (isOwner || isProfileOwner) {
                dpm.setUninstallBlocked(admin, pkg, blocked)
            } else {
                setBlockUninstallForUserRoot(pkg, blocked)
            }
            // Update local cache regardless of path
            val list = getUninstallBlockedPackages().toMutableSet()
            if (blocked) list.add(pkg) else list.remove(pkg)
            Prefs(context).uninstallBlockedJson = JSONArray(list).toString()
            true
        } catch (e: Exception) {
            Log.e(TAG, "setUninstallBlocked($pkg,$blocked): ${e.message}")
            false
        }
    }

    fun isUninstallBlocked(pkg: String): Boolean = try {
        if (isOwner || isProfileOwner) {
            dpm.isUninstallBlocked(admin, pkg)
        } else {
            // Root: DO is required to read from DPM; use local tracking instead
            getUninstallBlockedPackages().contains(pkg)
        }
    } catch (_: Exception) { getUninstallBlockedPackages().contains(pkg) }

    // ── Always-on VPN (open-WiFi auto-VPN consent) ────────────────────────────
    // Registering the agent as the device's always-on VPN package pre-grants the VpnService consent
    // (no user dialog) and survives reboot. lockdown=false ⇒ connectivity stays up (fail-open) if the
    // tunnel/node is down. The TUN is only ESTABLISHED while on open WiFi (OpenWifiVpnController);
    // always-on here just keeps consent armed + auto-starts SentinelVpnService.
    fun setSelfAlwaysOnVpn(enable: Boolean): Boolean {
        if (!isActive) return false
        return try {
            if (isOwner || isProfileOwner) {
                // DO sets device-wide always-on VPN; PO sets it for the managed profile.
                dpm.setAlwaysOnVpnPackage(admin, if (enable) context.packageName else null, false)
                true
            } else {
                // Root/system priv-app build has no DPM owner; VPN consent would need the OP_ACTIVATE_VPN
                // appop. Out of scope here — the shipping build is the Device Owner.
                false
            }
        } catch (e: Throwable) {
            Log.e(TAG, "setSelfAlwaysOnVpn($enable): ${e.message}")
            false
        }
    }

    // ── Advanced Protection (APM) accessibility allowlist ────────────────────
    /**
     * Declare an explicit enterprise accessibility allowlist containing only ourselves.
     *
     * Android 13+ Advanced Protection can set `DISALLOW_NON_TOOL_ACCESSIBILITY_SERVICE`, which
     * makes `AccessibilityManagerService.getPermittedServicesStrictApm()` permit an accessibility
     * package only if it is a system app OR declares `android:isAccessibilityTool` — and block the
     * whole package outright if it contains any non-tool service. Neither escape applies to us:
     * ScreenshotService must not claim to be an accessibility tool (it would assert to parents and
     * to Play that a surveillance agent is a disability accommodation), and since the 2026-05-29
     * `/data/app` switch `FLAG_SYSTEM` is never set. When APM is on, the bind loop therefore calls
     * `disableAccessibilityServiceLocked()` and screenshots, keylogging, gesture injection,
     * app-watching and screen-text scraping all die silently.
     *
     * `DevicePolicyManager.setPermittedAccessibilityServices()` is the sanctioned override:
     * `getPermittedAccessibilityServicePackages()` returns the legacy path as soon as
     * `adminPermittedServices != null` ("Admin intent overrides AAPM"), skipping the strict filter.
     * It needs only DO/PO status — no signature, no priv-app, no platform build — so this protects
     * GrapheneOS and stock Android identically. The ROM patches cannot: patch-accessibility-do.py
     * only adds ENABLED_ACCESSIBILITY_SERVICES to SECURE_SETTINGS_DEVICEOWNER_ALLOWLIST, and
     * patch-accessibility-force-on.py only rewrites the ENABLED_ACCESSIBILITY_SERVICES setting,
     * which the separate permission gate then overrides regardless.
     *
     * Our own package must be in the list: the call is rejected while an enabled accessibility
     * service belongs to a package that is neither allowlisted nor a system app.
     */
    fun allowlistAccessibilityForApm(): Boolean {
        if (!isOwner && !isProfileOwner) return false
        return try {
            val ok = dpm.setPermittedAccessibilityServices(admin, listOf(context.packageName))
            if (!ok) Log.w(TAG, "setPermittedAccessibilityServices rejected (an enabled non-allowlisted a11y service?)")
            ok
        } catch (e: Throwable) {
            Log.w(TAG, "setPermittedAccessibilityServices failed: ${e.message}")
            false
        }
    }

    /**
     * Whether Advanced Protection Mode is currently on, or null when the platform can't answer.
     *
     * `QUERY_ADVANCED_PROTECTION_MODE` is `protectionLevel="normal"`, so no special permission is
     * needed — a plain sideloaded DO can read it. `AdvancedProtectionManager` is public API on
     * current platforms but absent from android-34's android.jar, and this module compiles against
     * 34, hence reflection (same pattern as the @SystemApi calls elsewhere in this file).
     */
    fun isAdvancedProtectionEnabled(): Boolean? {
        return try {
            val svc = context.getSystemService("advanced_protection")
            svc?.javaClass?.getMethod("isAdvancedProtectionEnabled")?.invoke(svc) as? Boolean
        } catch (_: Throwable) {
            null // API absent (older platform) or hidden-API blocklist denied the call
        }
    }

    // ── Clear app data ────────────────────────────────────────────────────────

    fun clearAppData(pkg: String, onResult: (Boolean) -> Unit) {
        if (!isActive) { onResult(false); return }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) { onResult(false); return }
        if (isOwner || isProfileOwner) {
            try {
                // DO clears device-wide; PO clears profile-scoped apps
                dpm.clearApplicationUserData(admin, pkg, context.mainExecutor) { _, succeeded ->
                    onResult(succeeded)
                }
            } catch (e: Exception) {
                Log.e(TAG, "clearAppData DO/PO ($pkg): ${e.message}")
                onResult(false)
            }
        } else {
            // Root path: use `pm clear` shell command.
            // Runs with our priv-app UID which has CLEAR_APP_USER_DATA permission.
            Thread {
                try {
                    val exitCode = Runtime.getRuntime().exec(arrayOf("pm", "clear", pkg)).waitFor()
                    onResult(exitCode == 0)
                } catch (e: Exception) {
                    Log.e(TAG, "clearAppData root($pkg): ${e.message}")
                    onResult(false)
                }
            }.start()
        }
    }

    fun clearLockScreenInfo() {
        if (!isOwner) return   // DO-only; PO cannot set device-wide lock screen info
        try { dpm.setDeviceOwnerLockScreenInfo(admin, "") } catch (_: Exception) {}
    }

    // dpm.setGlobalSetting() is the correct DO API for writing Settings.Global values —
    // Settings.Global.putString/putInt() requires WRITE_SECURE_SETTINGS which needs
    // 'privileged' flag (priv-app only) and silently fails for /data/app Device Owners.
    fun setGlobalSetting(key: String, value: String) {
        if (!isOwner) return
        try { dpm.setGlobalSetting(admin, key, value) } catch (_: Exception) {}
    }

    // Turn Private DNS OFF while full tunnel is up; restore opportunistic (platform default) otherwise.
    //
    // WHY "off": the device's on-link DoT resolver (e.g. the WiFi gateway, an RFC1918 address) is
    // blackholed at the node, so opportunistic Private DNS keeps probing it OVER the tunnel and STALLS
    // all name resolution. With Private DNS OFF, VPN-scoped apps fall back to the TUN's published
    // plaintext resolvers (1.1.1.1 / 8.8.8.8 — see SentinelVpnService.addDnsServer), whose queries ride
    // the encrypted REALITY tunnel and egress at the node — so DNS resolves and the on-link resolver is
    // never used. ("hostname"/DoT to 1.1.1.1 also resolves correctly; "off" is chosen for simplicity.)
    //
    // NOTE: this only fixes DNS / the native (okhttp) connection. A WebView (chromium) loading a
    // Cloudflare-fronted self-hosted service (e.g. hass.example.com) in full tunnel is a SEPARATE
    // issue — CF resets the browser's TLS from the datacenter node egress IP — fixed CF-side by
    // whitelisting the node egress IPs on the zone, NOT here. See memory full-tunnel-dns-pin.
    //
    // Direct Settings.Global write works because the platform-signed agent holds WRITE_SECURE_SETTINGS;
    // there is no DPM API to force Private DNS fully OFF, so on the (non-fleet) non-platform-signed DO
    // path we fall back to opportunistic, which at least avoids the throwing specified-host API.
    fun setVpnPrivateDns(enable: Boolean) {
        if (!isActive) return
        try {
            Settings.Global.putString(context.contentResolver, "private_dns_mode", if (enable) "off" else "opportunistic")
            Log.i("DeviceOwnerHelper", "setVpnPrivateDns(enable=$enable) via Settings.Global OK")
            return
        } catch (t: Throwable) {
            Log.w("DeviceOwnerHelper", "setVpnPrivateDns Settings.Global failed (${t.message}); trying DPM")
        }
        // Fallback for a non-platform-signed Device Owner without WRITE_SECURE_SETTINGS (no DPM "off").
        if (!isOwner) return
        try {
            dpm.setGlobalPrivateDnsModeOpportunistic(admin)
            Log.i("DeviceOwnerHelper", "setVpnPrivateDns(enable=$enable) via DPM (opportunistic fallback)")
        } catch (t: Throwable) { Log.w("DeviceOwnerHelper", "setVpnPrivateDns DPM failed: ${t.message}") }
    }

    // READ_LOGS has the `development` protection flag — grantable via `pm grant` but not via
    // grantRuntimePermission(). Try setPermissionGrantState anyway (succeeds on some builds);
    // if it fails the user must run: adb shell pm grant <pkg> android.permission.READ_LOGS
    fun tryGrantReadLogs() {
        if (!isOwner && !isProfileOwner) return  // DO/PO can grant; system app uses privapp perms
        if (context.checkSelfPermission("android.permission.READ_LOGS") ==
                android.content.pm.PackageManager.PERMISSION_GRANTED) return
        try {
            dpm.setPermissionGrantState(admin, context.packageName,
                "android.permission.READ_LOGS",
                DevicePolicyManager.PERMISSION_GRANT_STATE_GRANTED)
        } catch (_: Exception) {}
    }

    // ── Boot-time restriction restoration ────────────────────────────────────
    /**
     * Re-applies non-persistent restrictions on root/system builds after reboot.
     * UserManager restrictions and DPM policies survive reboots automatically.
     * StatusBarManager.disable() and IWindowManager.setScreenCaptureDisabled() are
     * in-memory and must be restored from Prefs each time the service starts.
     *
     * Called from MonitoringService.onCreate() on the isSystemApp path.
     */
    fun restoreRestrictionsAtBoot() {
        if (!isSystemApp || isOwner) return
        val prefs = Prefs(context)
        if (prefs.statusBarDisabled) {
            setStatusBarDisabledRoot(true)
            Log.i(TAG, "Restored status bar disable at boot")
        }
        if (prefs.screenCaptureDisabled) {
            setScreenCaptureDisabledRoot(true)
            Log.i(TAG, "Restored screen capture disable at boot")
        }
    }

    // ── Private root-path helpers ─────────────────────────────────────────────

    /**
     * Sets a user restriction using UserManager directly (root/system path).
     * Requires android.permission.MANAGE_USERS (signature|privileged).
     *
     * For Device Owner restrictions (DISALLOW_FACTORY_RESET, DISALLOW_SAFE_BOOT, etc.),
     * Android 14+ accepts MANAGE_PROFILE_AND_DEVICE_OWNERS as an alternative caller.
     * For earlier Android versions, apply the companion ROM patch:
     *   grapheneos/patches/patch-user-restrictions-agent.py
     */
    private fun applyUserRestriction(restriction: String, enabled: Boolean) {
        if (isOwner) {
            // DO path: standard DPM toggle
            if (enabled) dpm.addUserRestriction(admin, restriction)
            else dpm.clearUserRestriction(admin, restriction)
            return
        }
        // Root/system path: call UserManager directly
        // MANAGE_USERS permission is granted via privapp-permissions-sentinel.xml
        val um = context.getSystemService(Context.USER_SERVICE) as UserManager
        um.setUserRestriction(restriction, enabled)
    }

    /**
     * Blocks/unblocks per-package uninstall via IPackageManager.setBlockUninstallForUser().
     * Requires android.permission.DELETE_PACKAGES (granted via privapp-permissions-sentinel.xml).
     *
     * Uses ActivityThread.getPackageManager() to obtain the IPackageManager binder — this is the
     * same cached proxy the framework uses internally, avoiding any potential SELinux/hidden-API
     * issue with calling ServiceManager.getService("package") directly.
     */
    private fun setBlockUninstallForUserRoot(pkg: String, blocked: Boolean) {
        val userId = android.os.Process.myUserHandle().hashCode()
        try {
            // ActivityThread.getPackageManager() is a static method that returns the cached
            // IPackageManager proxy.  More reliable than a raw ServiceManager.getService() call.
            val actThread = Class.forName("android.app.ActivityThread")
            val ipm = actThread.getMethod("getPackageManager").invoke(null)
                ?: throw IllegalStateException("ActivityThread.getPackageManager() returned null")
            ipm.javaClass
                .getMethod("setBlockUninstallForUser",
                    String::class.java, Boolean::class.java, Int::class.java)
                .invoke(ipm, pkg, blocked, userId)
            Log.i(TAG, "Root setBlockUninstallForUser [$pkg=$blocked] via ActivityThread ✓")
            return
        } catch (e: Exception) {
            Log.w(TAG, "setBlockUninstallForUserRoot ActivityThread path ($pkg): ${e.javaClass.simpleName}: ${e.message}")
        }

        // Fallback: classic ServiceManager → IPackageManager path
        try {
            val smClass = Class.forName("android.os.ServiceManager")
            val binder  = smClass.getMethod("getService", String::class.java)
                .invoke(null, "package") as android.os.IBinder
            val ipmStub = Class.forName("android.content.pm.IPackageManager\$Stub")
            val ipm     = ipmStub.getMethod("asInterface", android.os.IBinder::class.java)
                .invoke(null, binder)
            ipm!!.javaClass
                .getMethod("setBlockUninstallForUser",
                    String::class.java, Boolean::class.java, Int::class.java)
                .invoke(ipm, pkg, blocked, userId)
            Log.i(TAG, "Root setBlockUninstallForUser [$pkg=$blocked] via ServiceManager ✓")
        } catch (e: Exception) {
            Log.e(TAG, "setBlockUninstallForUserRoot BOTH PATHS FAILED ($pkg): ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * Disables/enables screen capture system-wide without being Device Owner.
     *
     * Two paths depending on the Android version baked into the ROM:
     *
     * Android 16+ (DPMS path):
     *   The ROM patch (patch-screen-capture-agent.py) relaxes the
     *   MANAGE_DEVICE_POLICY_SCREEN_CAPTURE check in DevicePolicyManagerService to
     *   also accept callers with MANAGE_PROFILE_AND_DEVICE_OWNERS.  After that patch
     *   the public DPM API works directly.
     *
     * Android 13-15 (WMS path):
     *   IWindowManager.setScreenCaptureDisabled() still exists in WMS.  The ROM patch
     *   relaxes its MANAGE_APP_TOKENS check for MANAGE_PROFILE_AND_DEVICE_OWNERS callers.
     *   Called via reflection because the method was removed in Android 16.
     */
    private fun setScreenCaptureDisabledRoot(disabled: Boolean) {
        // ── Android 16+: DPM public API (patched to accept MANAGE_PROFILE_AND_DEVICE_OWNERS) ──
        try {
            dpm.setScreenCaptureDisabled(admin, disabled)
            Log.i(TAG, "Root setScreenCaptureDisabled via DPM (Android 16+): $disabled")
            return
        } catch (e: SecurityException) {
            // ROM patch not applied, or pre-Android-16 where this path doesn't apply
            Log.d(TAG, "setScreenCaptureDisabled DPM path: ${e.message} — trying IWindowManager")
        } catch (e: Exception) {
            Log.d(TAG, "setScreenCaptureDisabled DPM path: ${e.message} — trying IWindowManager")
        }

        // ── Android 13-15: IWindowManager.setScreenCaptureDisabled() via reflection ──
        // (method was removed in Android 16; NoSuchMethodException expected on newer ROMs)
        try {
            val smClass = Class.forName("android.os.ServiceManager")
            val binder  = smClass.getMethod("getService", String::class.java)
                .invoke(null, "window") as android.os.IBinder
            val iwmStub = Class.forName("android.view.IWindowManager\$Stub")
            val iwm     = iwmStub.getMethod("asInterface", android.os.IBinder::class.java)
                .invoke(null, binder)
            val userId  = android.os.Process.myUserHandle().hashCode()
            iwm.javaClass
                .getMethod("setScreenCaptureDisabled", Int::class.java, Boolean::class.java)
                .invoke(iwm, userId, disabled)
            Log.i(TAG, "Root setScreenCaptureDisabled via IWindowManager (Android ≤15): $disabled")
        } catch (e: NoSuchMethodException) {
            Log.d(TAG, "setScreenCaptureDisabledRoot: IWindowManager path not available on this ROM version")
        } catch (e: SecurityException) {
            Log.w(TAG, "setScreenCaptureDisabledRoot: ROM patch required (patch-screen-capture-agent.py) — ${e.message}")
        } catch (e: Exception) {
            Log.e(TAG, "setScreenCaptureDisabledRoot: ${e.message}")
        }
    }

    /**
     * Disables/enables the status bar via StatusBarManager.disable() + disable2().
     *
     * Replicates exactly what DPM.setStatusBarDisabledInternal() does:
     *   disable1 mask: DISABLE_EXPAND | DISABLE_NOTIFICATION_ICONS |
     *                  DISABLE_NOTIFICATION_ALERTS | DISABLE_SEARCH
     *   disable2 mask: DISABLE2_QUICK_SETTINGS
     *
     * Requires android.permission.STATUS_BAR (signature|privileged).
     * Granted via privapp-permissions-sentinel.xml.
     */
    private fun setStatusBarDisabledRoot(disabled: Boolean) {
        try {
            val sbm = context.getSystemService("statusbar") ?: run {
                Log.w(TAG, "StatusBarManager unavailable"); return
            }

            // Numeric values from View.java / StatusBarManager.java in Android 16
            val DISABLE_EXPAND                = 0x00010000
            val DISABLE_NOTIFICATION_ICONS    = 0x00020000
            val DISABLE_NOTIFICATION_ALERTS   = 0x00040000
            val DISABLE_SEARCH                = 0x02000000
            val DISABLE2_QUICK_SETTINGS       = 0x00000001

            val disable1 = if (disabled)
                DISABLE_EXPAND or DISABLE_NOTIFICATION_ICONS or
                DISABLE_NOTIFICATION_ALERTS or DISABLE_SEARCH
            else 0  // StatusBarManager.DISABLE_NONE

            val disable2 = if (disabled) DISABLE2_QUICK_SETTINGS else 0

            sbm.javaClass.getMethod("disable",  Int::class.java).invoke(sbm, disable1)
            sbm.javaClass.getMethod("disable2", Int::class.java).invoke(sbm, disable2)

            Log.i(TAG, "Root setStatusBarDisabled: $disabled " +
                    "(disable1=0x${disable1.toString(16)}, disable2=0x${disable2.toString(16)})")
        } catch (e: Exception) {
            Log.w(TAG, "setStatusBarDisabledRoot: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * Suppresses/restores the long-press power menu (global actions) via
     * StatusBarManager.disable2(). Used by the theft fake-shutdown screen so a thief's
     * long-press shows nothing real — the display wakes into the fake UI instead.
     *
     * Writes ONLY the disable2 mask, OR-ing with the quick-settings bit when the status
     * bar is disabled (theft mode), so the two features never clobber each other:
     *   mask = (statusBarDisabled ? DISABLE2_QUICK_SETTINGS : 0) |
     *          (suppressed        ? DISABLE2_GLOBAL_ACTIONS  : 0)
     *
     * Requires android.permission.STATUS_BAR (signature|privileged).
     * Granted via privapp-permissions-sentinel.xml.
     */
    fun setPowerMenuSuppressed(suppressed: Boolean, statusBarDisabled: Boolean) {
        try {
            val sbm = context.getSystemService("statusbar") ?: run {
                Log.w(TAG, "StatusBarManager unavailable"); return
            }
            // Numeric values from StatusBarManager.java in Android 16; resolve by
            // reflection first so future renumbers don't silently break this.
            val smc = Class.forName("android.app.StatusBarManager")
            fun flag(name: String, fallback: Int): Int = try {
                smc.getField(name).getInt(null)
            } catch (_: Exception) { fallback }
            val DISABLE2_QUICK_SETTINGS = flag("DISABLE2_QUICK_SETTINGS", 0x00000001)
            val DISABLE2_GLOBAL_ACTIONS = flag("DISABLE2_GLOBAL_ACTIONS", 0x00000010)

            var mask = 0
            if (statusBarDisabled) mask = mask or DISABLE2_QUICK_SETTINGS
            if (suppressed)        mask = mask or DISABLE2_GLOBAL_ACTIONS

            sbm.javaClass.getMethod("disable2", Int::class.java).invoke(sbm, mask)
            Log.i(TAG, "setPowerMenuSuppressed: $suppressed (disable2=0x${mask.toString(16)})")
        } catch (e: Exception) {
            Log.w(TAG, "setPowerMenuSuppressed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * Allowlist our own package for lock-task (kiosk) pinning, used by the theft
     * fake-shutdown screen to kill Home/Recents/gesture escapes. Persists until
     * changed — safe to call on every arm. DO only; fails soft otherwise.
     */
    fun setLockTaskAllowed() {
        try {
            if (!isOwner) {
                Log.w(TAG, "setLockTaskAllowed: not device owner, skipping")
                return
            }
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            dpm.setLockTaskPackages(admin, arrayOf(context.packageName))
            Log.i(TAG, "setLockTaskAllowed: ${context.packageName}")
        } catch (e: Exception) {
            Log.w(TAG, "setLockTaskAllowed: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    // Kept for Device Owner path; use applyUserRestriction() for the unified path
    private fun toggle(restriction: String, enabled: Boolean) {
        if (enabled) dpm.addUserRestriction(admin, restriction)
        else dpm.clearUserRestriction(admin, restriction)
    }

    /**
     * Forces a hardware sensor privacy toggle back to "available" (privacy=false) via
     * SensorPrivacyManager.setSensorPrivacy(toggleType, sensor, privacy).
     *
     * Used when DISALLOW_CAMERA_TOGGLE / DISALLOW_MICROPHONE_TOGGLE is being REMOVED —
     * if the user had previously toggled the sensor OFF, we must re-enable it so the
     * MDM's camera/mic access is immediately restored.
     *
     * @param sensorId  1 = CAMERA, 2 = MICROPHONE  (SensorPrivacyManager.Sensors constants)
     *
     * API notes:
     *   setSensorPrivacy(int toggleType, int sensor, boolean privacy) is @SystemApi (API 31+).
     *   toggleType = TOGGLE_TYPE_SOFTWARE = 1
     *   Requires android.permission.MANAGE_SENSOR_PRIVACY (signature|privileged).
     *   Declared in AndroidManifest.xml and whitelisted in privapp-permissions-sentinel.xml.
     */
    private fun restoreSensorPrivacy(sensorId: Int) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        try {
            val spm = context.getSystemService(android.hardware.SensorPrivacyManager::class.java)
                ?: return
            // TOGGLE_TYPE_SOFTWARE = 1, privacy = false → sensor is available/on
            spm.javaClass
                .getMethod("setSensorPrivacy",
                    Int::class.java, Int::class.java, Boolean::class.java)
                .invoke(spm, 1 /* TOGGLE_TYPE_SOFTWARE */, sensorId, false /* available */)
            Log.i(TAG, "restoreSensorPrivacy: sensor=$sensorId forced ON ✓")
        } catch (e: Exception) {
            Log.w(TAG, "restoreSensorPrivacy(sensor=$sensorId): ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /**
     * Reflection wrapper for PackageManager.grantRuntimePermission() which is @SystemApi
     * and therefore not visible at compileSdk 34 against the public SDK.
     * Requires GRANT_RUNTIME_PERMISSIONS (granted via privapp-permissions-sentinel.xml).
     */
    private fun pmGrantPermission(
        pm: PackageManager,
        pkg: String,
        perm: String,
        user: android.os.UserHandle
    ) {
        pm.javaClass
            .getMethod("grantRuntimePermission",
                String::class.java, String::class.java, android.os.UserHandle::class.java)
            .invoke(pm, pkg, perm, user)
    }

    /**
     * Reflection wrapper for PackageManager.revokeRuntimePermission() — same visibility reason.
     * Swallows all exceptions so callers can use it best-effort inside try blocks.
     * Requires REVOKE_RUNTIME_PERMISSIONS (granted via privapp-permissions-sentinel.xml).
     */
    private fun pmRevokePermission(
        pm: PackageManager,
        pkg: String,
        perm: String,
        user: android.os.UserHandle
    ) {
        try {
            pm.javaClass
                .getMethod("revokeRuntimePermission",
                    String::class.java, String::class.java, android.os.UserHandle::class.java)
                .invoke(pm, pkg, perm, user)
        } catch (_: Exception) {}
    }

    /**
     * Wipe-stable hardware identifier for server-side free-trial-abuse dedup (v2).
     * Prefers the enterprise Enrollment-Specific ID (ESID) — a per-(organization, device) value the
     * framework derives from immutable hardware identifiers, available to a Device Owner on API 31+
     * after setOrganizationId(). It SURVIVES a factory reset, so a re-provisioned device (including a
     * BYOD self-DO re-install) reports the SAME id — unlike device_id, which degrades to a random
     * UUID when getSerial() is unreadable. Falls back to the raw serial. Returns "" if neither is
     * available. Best-effort & self-reported (server use is alert-only) — never throws.
     */
    fun stableHardwareId(): String {
        if (isOwner && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                // Idempotent: setting the SAME org id is a no-op; a DIFFERENT value would throw (caught).
                try { dpm.setOrganizationId(ORG_ID) } catch (_: Throwable) {}
                val esid = dpm.enrollmentSpecificId
                if (!esid.isNullOrBlank()) return esid
            } catch (_: Throwable) {}
        }
        return try {
            @Suppress("HardwareIds")
            val serial = Build.getSerial()
            if (!serial.isNullOrBlank() && !serial.equals(Build.UNKNOWN, ignoreCase = true)) serial else ""
        } catch (_: Throwable) { "" }
    }

    companion object {
        private const val TAG = "DeviceOwnerHelper"
        /** Stable enterprise/organization id. Keep CONSTANT — the ESID is derived from it, so changing
         *  it would change every device's reported hardware id and break trial-abuse lineage. */
        const val ORG_ID = "sentinel"
    }
}
