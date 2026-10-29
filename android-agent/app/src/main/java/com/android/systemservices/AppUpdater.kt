package com.android.systemservices

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.os.PowerManager
import android.util.Log
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

class AppUpdater(private val context: Context, private val isSelfUpdate: Boolean = true) {

    // ── Public API ─────────────────────────────────────────────────────────────

    /**
     * Download an APK from [apkUrl], verify its certificate, and install it.
     *
     * On system/root builds (FLAG_SYSTEM) the session is committed with
     * USER_ACTION_NOT_REQUIRED.  This is silent only when the installer holds
     * android.permission.INSTALL_PACKAGES (listed in AndroidManifest.xml and
     * whitelisted by privapp-permissions-sentinel.xml).  Without that permission
     * the PackageInstaller would fall back to STATUS_PENDING_USER_ACTION and show
     * the user a confirmation dialog.
     *
     * After a successful install the APK is also saved to filesDir as a "pending
     * update" record.  BootReceiver reads this on the next boot and re-applies the
     * install if the package manager rolled back to the older system-image version.
     */
    fun download(apkUrl: String) {
        Thread {
            // Doze-proofing: a long slow download (19.3 MB measured at ~30 KB/s ≈ 11 min on the
            // stallion open-Wi-Fi link, 2026-09-25) must keep the CPU/IO awake or the transfer
            // silently stalls when the device sleeps. Time-capped and released in finally; the
            // installSilent() session write happens inside the same window.
            val power = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            val wake = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "sentinel:apk-update")
            try {
                wake.acquire(30 * 60 * 1000L)
                var lastError = "unknown error"
                for (attempt in 1..DOWNLOAD_ATTEMPTS) {
                    lastError = attemptDownload(apkUrl, attempt) ?: return@Thread
                    Log.w(TAG, "APK download attempt $attempt/$DOWNLOAD_ATTEMPTS failed: $lastError")
                    if (attempt < DOWNLOAD_ATTEMPTS) Thread.sleep(10_000)
                }
                Log.e(TAG, "APK update failed after $DOWNLOAD_ATTEMPTS attempts: $lastError")
                emitUpdateEvent("failed", 0, 0, lastError)
            } catch (e: Throwable) {
                Log.e(TAG, "AppUpdater error: ${e.message}")
                emitUpdateEvent("failed", 0, 0, e.message ?: e.javaClass.simpleName)
            } finally {
                try { if (wake.isHeld) wake.release() } catch (_: Throwable) {}
            }
        }.start()
    }

    /**
     * One download → Content-Length check → signature verify → install pass.
     * Returns null when the install session was committed, else a short error string.
     */
    private fun attemptDownload(apkUrl: String, attempt: Int): String? {
        Log.i(TAG, "Downloading APK from $apkUrl (attempt $attempt/$DOWNLOAD_ATTEMPTS)")
        val apkFile = File(context.cacheDir, "update_download.apk")
        try {
            val conn = URL(apkUrl).openConnection() as HttpURLConnection
            conn.connectTimeout = 20_000
            conn.readTimeout    = 90_000
            conn.connect()
            val code = conn.responseCode
            if (code != 200) {
                Log.e(TAG, "APK download failed: HTTP $code")
                return "HTTP $code"
            }
            val total = conn.contentLengthLong
            // Stream the download to a temp FILE — never hold the APK in a ByteArray.
            // The old readBytes() path OOM'd on low-heap devices (Pixel Tablet, 2.9.0.19:
            // "Failed to allocate a 19237192 byte allocation with 17921648 free bytes").
            // A 19MB APK must not live in the app heap: stream → verify-from-file →
            // session-write-from-file keeps memory flat regardless of APK size.
            emitUpdateEvent("downloading", 0, total, null)
            var written = 0L
            var nextReport = PROGRESS_STEP_BYTES
            conn.inputStream.use { input ->
                apkFile.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        written += n
                        if (written >= nextReport) {
                            nextReport += PROGRESS_STEP_BYTES
                            emitUpdateEvent("downloading", written, total, null)
                        }
                    }
                }
            }
            conn.disconnect()
            Log.i(TAG, "APK downloaded to file: $written bytes (attempt $attempt)")
            // Truncated responses are the classic silent failure on flaky links — the old code
            // happily tried to install a short file and only logged "No signing certificate".
            if (total > 0 && written != total) return "short download: $written/$total bytes"

            emitUpdateEvent("verifying", written, total, null)
            if (isSelfUpdate && !verifySignature(apkFile)) {
                Log.e(TAG, "APK signature verification failed — aborting install")
                return "signature verification failed"
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                emitUpdateEvent("installing", written, total, null)
                installSilent(apkFile)
            } else {
                return "silent install requires Android 12+ (API ${Build.VERSION.SDK_INT})"
            }
            return null
        } catch (e: Throwable) {
            Log.e(TAG, "download attempt $attempt error: ${e.message}")
            return e.message ?: e.javaClass.simpleName
        } finally {
            apkFile.delete()   // session copies the bytes during installSilent()
        }
    }

    /**
     * Dashboard/Signal event feed: `app_update` progress phases and `app_update_failed` for a
     * terminal failure. Without this a slow crawl or a dead link was completely silent — the
     * stallion 19 MB / ~30 KB/s download took 10.5 min with no visible progress (2026-09-25).
     */
    private fun emitUpdateEvent(phase: String, bytes: Long, total: Long, error: String?) {
        try {
            val ev = org.json.JSONObject().apply {
                put("type", if (error != null) "app_update_failed" else "app_update")
                put("package", context.packageName)
                put("name", "SentinelMDM agent")
                put("version", BuildConfig.VERSION_NAME)
                put("phase", phase)
                if (bytes > 0) put("bytes", bytes)
                if (total > 0) put("total", total)
                if (!error.isNullOrBlank()) put("error", error.take(300))
            }
            SocketManager.emit("status_event", ev)
        } catch (_: Throwable) {}
    }

    /**
     * Install from a previously saved APK file (called by BootReceiver for
     * self-healing after a system-image rollback).
     */
    fun installFromFile(apkFile: File) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        Thread {
            try {
                if (!verifySignature(apkFile)) {
                    Log.e(TAG, "Pending APK signature check failed — discarding")
                    apkFile.delete()
                    Prefs(context).pendingUpdateVersionCode = 0L
                    return@Thread
                }
                Log.i(TAG, "Re-installing pending update from ${apkFile.name}")
                installSilent(apkFile)
            } catch (e: Throwable) {
                Log.e(TAG, "installFromFile error: ${e.message}")
            }
        }.start()
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private fun verifySignature(apkFile: File): Boolean {
        return try {
            // Signing cert of the APK we're about to install (parsed straight from the file —
            // no byte[] copy needed)
            val newCertBytes: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = context.packageManager.getPackageArchiveInfo(
                    apkFile.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES)
                info?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                val info = context.packageManager.getPackageArchiveInfo(
                    apkFile.absolutePath, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info?.signatures?.firstOrNull()?.toByteArray()
            }
            if (newCertBytes == null) {
                Log.e(TAG, "No signing certificate found in update APK")
                return false
            }

            // Signing cert of the currently installed app (this app)
            val installedCertBytes: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = context.packageManager.getPackageInfo(
                    context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                info?.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
            } else {
                @Suppress("DEPRECATION")
                val info = context.packageManager.getPackageInfo(
                    context.packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info?.signatures?.firstOrNull()?.toByteArray()
            }
            if (installedCertBytes == null) {
                Log.e(TAG, "Could not read installed app certificate")
                return false
            }

            val newFp       = MessageDigest.getInstance("SHA-256").digest(newCertBytes)
                .joinToString("") { "%02X".format(it) }
            val installedFp = MessageDigest.getInstance("SHA-256").digest(installedCertBytes)
                .joinToString("") { "%02X".format(it) }

            // Optional extra allow-list for cross-signed/rotated builds. Empty by default;
            // Android's own same-signer rule (newFp == installedFp) is the baseline.
            val knownCerts = BuildConfig.EXPECTED_SIGNER_SHA256
                .split(",").map { it.trim().uppercase() }.filter { it.isNotEmpty() }.toSet()
            val ok = newFp == installedFp || newFp in knownCerts
            if (!ok) Log.e(TAG, "Certificate mismatch — update APK cert ($newFp) must match " +
                    "installed ($installedFp) or a known release cert")
            else     Log.i(TAG, "Certificate verified: $newFp")
            ok
        } catch (e: Exception) {
            Log.e(TAG, "verifySignature error: ${e.message}")
            false
        }
    }

    private fun installSilent(apkFile: File) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return

        val isSystemBuild = context.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0

        val pi     = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)

        // USER_ACTION_NOT_REQUIRED suppresses the confirmation dialog — but ONLY when the
        // installer holds android.permission.INSTALL_PACKAGES or is a Device Owner.
        // Without INSTALL_PACKAGES in the manifest this flag is silently ignored, the package
        // manager falls back to STATUS_PENDING_USER_ACTION, and the user sees an install prompt.
        // On root/system builds INSTALL_PACKAGES is granted via privapp-permissions-sentinel.xml
        // (declared in AndroidManifest.xml); on Device-Owner builds the DO role satisfies it.
        params.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)

        // Policy-install reason: suppresses "installed by unknown source" warnings in Settings.
        params.setInstallReason(PackageManager.INSTALL_REASON_POLICY)

        // DO NOT setDontKillApp(true) here.
        //
        // setDontKillApp(true) causes dexopt to fail for the new APK because the OLD process
        // remains alive during the install and holds DEX file locks.  dexopt runs under those
        // locks → fails silently → new APK's DexPathList is empty → every restart attempt
        // crashes with ClassNotFoundException before any app code runs → permanent crash loop.
        //
        // Without this flag, PMS kills our process FIRST (clean slate), then runs dexopt
        // on the new APK without lock contention.  AMS sees the persistent process die and
        // immediately re-adds it from the freshly-compiled new APK.  No extra code needed.
        //
        // The OS "reboot" seen in earlier test builds was caused by the PREVIOUS version's
        // PowerManager.reboot() code running while installing the next version — NOT from PMS.

        // ── Persist APK for boot-time self-healing BEFORE commit ─────────────────────
        // Save first so the file exists before the package manager kills our process.
        // BootReceiver reads this on the next boot if packages.xml rolls back to the
        // system-image version (FLAG_UPDATED_SYSTEM_APP lost across a reboot).
        if (isSystemBuild) {
            savePendingApk(apkFile)
        }

        val sessionId = pi.createSession(params)

        // ── In-process completion callback (replaces PendingIntent broadcast) ──────────
        // PendingIntent broadcasts are silently dropped when the app has the "stopped"
        // flag set (e.g. after am force-stop).  SessionCallback runs entirely in-process
        // via a Handler — no broadcast, immune to stopped-state, guaranteed delivery.
        val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
        pi.registerSessionCallback(object : PackageInstaller.SessionCallback() {
            override fun onCreated(sid: Int) {}
            override fun onBadgingChanged(sid: Int) {}
            override fun onActiveChanged(sid: Int, active: Boolean) {}
            override fun onProgressChanged(sid: Int, progress: Float) {}
            override fun onFinished(sid: Int, success: Boolean) {
                if (sid != sessionId) return
                pi.unregisterSessionCallback(this)
                if (success) {
                    if (isSelfUpdate) {
                        Log.i(TAG, "Self-update installed (SessionCallback) — flagging pending OTA reboot")
                        // Clear the boot-time self-healing record: install is confirmed.
                        try {
                            val f = java.io.File(context.filesDir, PENDING_APK_FILENAME)
                            if (f.exists()) f.delete()
                            Prefs(context).pendingUpdateVersionCode = 0L
                        } catch (_: Exception) {}
                        // Set the reboot-pending flag for the NEW process.
                        //
                        // We do NOT call PowerManager.reboot() here because PMS will
                        // force-stop this process within milliseconds of install completion.
                        // A postDelayed() call on this process's Looper would be cancelled
                        // before the delay expires.
                        //
                        // The flag is read by OtaRebootManager.checkAndSchedule() in
                        // MonitoringService.onCreate() of the new process that AMS spawns.
                        // That process shows the live 60-second countdown notification and
                        // calls PowerManager.reboot() when it reaches zero.
                        // Commit flag + start countdown in THIS process.
                        //
                        // DO NOT call Process.killProcess() here.
                        //
                        // killProcess() causes AMS to restart the process using its
                        // CACHED (pre-install) APK path.  Each PackageInstaller install
                        // creates a new randomized /data/app/~~hash==/ directory, so the
                        // old cached path no longer exists → Resources NPE at startup →
                        // permanent crash loop.  Only PMS-initiated kills (forceStopPackage)
                        // correctly refresh AMS's path cache before the restart.
                        //
                        // Instead: commit the flag, start the countdown in this process
                        // (which is still alive), and let pm.reboot(null) at t=0 trigger
                        // a clean OS reboot.  On reboot PMS reads packages.xml fresh →
                        // correct new APK path → service starts on new code.
                        try {
                            context.getSharedPreferences("ft_prefs", android.content.Context.MODE_PRIVATE)
                                .edit()
                                .putBoolean("ota_reboot_pending",    true)
                                .putBoolean("ota_reboot_delay_used", false)
                                .putLong("ota_reboot_delay_until",   0L)
                                .commit()
                            Log.i(TAG, "OTA reboot flag committed — starting countdown")
                        } catch (_: Exception) {}
                        OtaRebootManager.checkAndSchedule(context)
                    } else {
                        // Third-party APK installed by the admin — no reboot needed.
                        // PMS does NOT kill our process for installs of other packages.
                        Log.i(TAG, "Third-party APK installed successfully — no reboot required")
                        SocketManager.emit("install_apk_result", org.json.JSONObject().apply {
                            put("success", true)
                        })
                    }
                } else {
                    Log.e(TAG, "Install failed (SessionCallback)")
                    if (!isSelfUpdate) {
                        SocketManager.emit("install_apk_result", org.json.JSONObject().apply {
                            put("success", false)
                        })
                    }
                }
            }
        }, mainHandler)

        val session = pi.openSession(sessionId)
        try {
            // Stream the APK file into the session — no full byte[] in the app heap.
            session.openWrite("package", 0, apkFile.length()).use { out ->
                apkFile.inputStream().use { input -> input.copyTo(out, 64 * 1024) }
                session.fsync(out)
            }
            // Still commit with a PendingIntent for DO/non-system builds where
            // SessionCallback may not fire.  On system builds the SessionCallback above
            // is the primary completion path.
            val intent = Intent(context, InstallResultReceiver::class.java)
            val pending = PendingIntent.getBroadcast(
                context, sessionId, intent,
                PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            session.commit(pending.intentSender)
            Log.i(TAG, "PackageInstaller session committed (id=$sessionId, system=$isSystemBuild)")
        } finally {
            session.close()
        }
    }

    /**
     * Save [apkFile] to filesDir so BootReceiver can reinstall if the package
     * manager rolls back to the system-image version.  Also stores the APK's
     * versionCode in SharedPrefs so the boot check can compare without parsing.
     */
    fun savePendingApk(apkFile: File) {
        try {
            val pendingFile = File(context.filesDir, PENDING_APK_FILENAME)
            apkFile.copyTo(pendingFile, overwrite = true)

            // Parse the version code from the pending APK directly (no byte[] copy)
            val vCode: Long = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageArchiveInfo(pendingFile.absolutePath, 0)
                    ?.longVersionCode ?: 0L
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageArchiveInfo(pendingFile.absolutePath, 0)
                    ?.versionCode?.toLong() ?: 0L
            }
            Prefs(context).pendingUpdateVersionCode = vCode
            Log.i(TAG, "Pending update saved to filesDir (versionCode=$vCode)")
        } catch (e: Exception) {
            Log.e(TAG, "savePendingApk error: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "AppUpdater"

        /** Filename for the APK saved to filesDir after a successful install. */
        const val PENDING_APK_FILENAME = "sentinel_pending.apk"

        /** Download/install retry count (one retry, 10 s apart) — flaky guest links drop mid-stream. */
        private const val DOWNLOAD_ATTEMPTS = 2
        /** Emit an `app_update` progress event every ~4 MB rather than per-read. */
        private const val PROGRESS_STEP_BYTES = 4L * 1024 * 1024

    }
}
