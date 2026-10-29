package com.sentinelmdm.monitor

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.webkit.CookieManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

// FCM push handler for the SentinelMDM companion app.
//
// The companion app is an Android WebView, which has NO Web Push API — so the
// dashboard's push toggle, when it runs inside this app, drives FCM instead (via
// the `SentinelNative` JS bridge in MainActivity). The server (firebase-admin)
// pushes alerts to whatever tokens get registered here.
//
// ⚠️ ACTIVATION: requires app/google-services.json (see app/build.gradle, which
// applies the google-services plugin conditionally). Without it, FirebaseApp never
// initialises, the OS never invokes this service, and registerTokenWithServer()
// no-ops — the app still builds and runs normally.
class SentinelFirebaseService : FirebaseMessagingService() {

    // FCM issued (or rotated) a registration token — push it to the server.
    override fun onNewToken(token: String) {
        registerToken(token)
    }

    // A push arrived while the app process is alive — render it as a notification.
    // (Notification-only messages with the app backgrounded are drawn by FCM itself.)
    override fun onMessageReceived(message: RemoteMessage) {
        val n = message.notification
        val title = n?.title ?: message.data["title"] ?: applicationContext.getString(R.string.app_name)
        val body  = n?.body  ?: message.data["body"]  ?: ""
        val url   = message.data["url"] ?: "/"
        showNotification(applicationContext, title, body, url)
    }

    companion object {
        val SERVER_URL = BuildConfig.SERVER_URL
        // Must match the server's android.notification.channelId and the WebUI alert copy.
        private const val CHANNEL_ID   = "sentinel_push"
        private const val CHANNEL_NAME = "SentinelMDM Alerts"

        fun createNotificationChannel(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    CHANNEL_ID, CHANNEL_NAME, NotificationManager.IMPORTANCE_HIGH
                ).apply { description = "Real-time device alerts and status updates" }
                context.getSystemService(NotificationManager::class.java)
                    ?.createNotificationChannel(channel)
            }
        }

        fun showNotification(context: Context, title: String, body: String, url: String = "/") {
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
                putExtra("push_url", url)
            }
            val pi = PendingIntent.getActivity(
                context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notif = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .setContentIntent(pi)
                .build()
            try {
                NotificationManagerCompat.from(context)
                    .notify(System.currentTimeMillis().toInt(), notif)
            } catch (_: SecurityException) { /* POST_NOTIFICATIONS not granted */ }
        }

        // Fetch the current FCM token and register it with the server. Safe to call
        // even when FCM is inactive (no google-services.json) — it just no-ops.
        fun registerTokenWithServer() {
            try {
                FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
                    if (!token.isNullOrEmpty()) registerToken(token)
                }
            } catch (_: Throwable) { /* Firebase not initialised */ }
        }

        // Best-effort removal of this device's token from the server (push "off").
        fun unregisterTokenWithServer() {
            try {
                FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
                    if (!token.isNullOrEmpty()) postToken(token, "DELETE")
                }
            } catch (_: Throwable) {}
        }

        private fun registerToken(token: String) = postToken(token, "POST")

        // POST/DELETE the token to the authed endpoint, attaching the WebView's session
        // cookie (from the app-global CookieManager) so the server can tie this device
        // to the logged-in user.
        private fun postToken(token: String, method: String) {
            Thread {
                try {
                    val cookie = try {
                        CookieManager.getInstance().getCookie(SERVER_URL)
                    } catch (_: Throwable) { null }
                    val conn = (java.net.URL("$SERVER_URL/api/push/fcm-token").openConnection()
                            as java.net.HttpURLConnection).apply {
                        requestMethod = method
                        setRequestProperty("Content-Type", "application/json")
                        if (!cookie.isNullOrEmpty()) setRequestProperty("Cookie", cookie)
                        doOutput = true
                        connectTimeout = 15000
                        readTimeout = 15000
                    }
                    conn.outputStream.use { it.write("""{"token":"$token"}""".toByteArray()) }
                    conn.responseCode // trigger the request
                    conn.disconnect()
                } catch (_: Throwable) {}
            }.start()
        }
    }
}

// Application class — holds a static context reference and creates the notification
// channel up-front. Registered via android:name=".SentinelApp" in AndroidManifest.xml.
class SentinelApp : android.app.Application() {
    companion object {
        var instance: SentinelApp? = null
    }
    override fun onCreate() {
        super.onCreate()
        instance = this
        SentinelFirebaseService.createNotificationChannel(this)
    }
}
