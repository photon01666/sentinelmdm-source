package com.android.systemservices

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.util.Log
import com.google.android.gms.location.Geofence
import com.google.android.gms.location.GeofencingClient
import com.google.android.gms.location.GeofencingRequest
import com.google.android.gms.location.LocationServices
import org.json.JSONArray
import org.json.JSONObject

class GeofenceManager(private val context: Context) {
    private val TAG = "GeofenceManager"
    private val client: GeofencingClient = LocationServices.getGeofencingClient(context)

    data class Entry(
        val id: String,
        val name: String,
        val lat: Double,
        val lng: Double,
        val radius: Float,
        // Bitmask matching Android constants: ENTER=1, EXIT=2, DWELL=4
        val transitions: Int
    ) {
        fun toJson(): JSONObject = JSONObject().apply {
            put("id", id)
            put("name", name)
            put("lat", lat)
            put("lng", lng)
            put("radius", radius)
            put("transitions", transitions)
        }
    }

    private fun pendingIntent(): PendingIntent {
        val intent = Intent(context, GeofenceReceiver::class.java)
        return PendingIntent.getBroadcast(
            context, 0, intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    @Suppress("MissingPermission")
    fun add(entry: Entry) {
        val transitionTypes = entry.transitions.coerceAtLeast(1)
        val geofence = Geofence.Builder()
            .setRequestId(entry.id)
            .setCircularRegion(entry.lat, entry.lng, entry.radius)
            .setExpirationDuration(Geofence.NEVER_EXPIRE)
            .setTransitionTypes(transitionTypes)
            .setLoiteringDelay(if (entry.transitions and Geofence.GEOFENCE_TRANSITION_DWELL != 0) 60_000 else 0)
            .build()
        val request = GeofencingRequest.Builder()
            .setInitialTrigger(GeofencingRequest.INITIAL_TRIGGER_ENTER)
            .addGeofence(geofence)
            .build()
        client.addGeofences(request, pendingIntent())
            .addOnSuccessListener {
                persist(entry)
                Log.i(TAG, "Added geofence ${entry.id} r=${entry.radius}m")
            }
            .addOnFailureListener { e -> Log.e(TAG, "Add geofence failed: ${e.message}") }
    }

    fun remove(id: String) {
        client.removeGeofences(listOf(id))
            .addOnSuccessListener {
                delete(id)
                Log.i(TAG, "Removed geofence $id")
            }
            .addOnFailureListener { e -> Log.e(TAG, "Remove geofence failed: ${e.message}") }
    }

    fun clearAll() {
        client.removeGeofences(pendingIntent())
            .addOnSuccessListener {
                Prefs(context).geofencesJson = "[]"
                Log.i(TAG, "All geofences cleared")
            }
            .addOnFailureListener { e -> Log.e(TAG, "Clear geofences failed: ${e.message}") }
    }

    fun getAll(): List<Entry> {
        return try {
            val arr = JSONArray(Prefs(context).geofencesJson.ifEmpty { "[]" })
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                Entry(
                    id          = o.getString("id"),
                    name        = o.optString("name", o.getString("id")),
                    lat         = o.getDouble("lat"),
                    lng         = o.getDouble("lng"),
                    radius      = o.getDouble("radius").toFloat(),
                    transitions = o.optInt("transitions",
                        Geofence.GEOFENCE_TRANSITION_ENTER or Geofence.GEOFENCE_TRANSITION_EXIT)
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "getAll parse error: ${e.message}")
            emptyList()
        }
    }

    @Suppress("MissingPermission")
    fun reloadAll(onFailure: ((Exception) -> Unit)? = null) {
        val entries = getAll()
        if (entries.isEmpty()) return
        val geofences = entries.map { e ->
            Geofence.Builder()
                .setRequestId(e.id)
                .setCircularRegion(e.lat, e.lng, e.radius)
                .setExpirationDuration(Geofence.NEVER_EXPIRE)
                .setTransitionTypes(e.transitions.coerceAtLeast(1))
                .setLoiteringDelay(if (e.transitions and Geofence.GEOFENCE_TRANSITION_DWELL != 0) 60_000 else 0)
                .build()
        }
        val request = GeofencingRequest.Builder()
            // ⚠️ NOT INITIAL_TRIGGER_ENTER: reloadAll() runs on every service start, and an
            // initial ENTER trigger makes GMS re-fire "enter" for every fence the device is
            // already inside — a false enter alert per restart (same flapping bug the AOSP
            // engine's persisted state fixes). Explicit add() keeps INITIAL_TRIGGER_ENTER:
            // that fires once, on a user-initiated action.
            .setInitialTrigger(0)
            .addGeofences(geofences)
            .build()
        client.addGeofences(request, pendingIntent())
            .addOnSuccessListener { Log.i(TAG, "Reloaded ${geofences.size} geofence(s)") }
            .addOnFailureListener { e ->
                Log.e(TAG, "Reload geofences failed: ${e.message}")
                // addGeofences() never throws synchronously — without surfacing the async
                // Task failure to the caller, MonitoringService cannot know GMS is dead and
                // can never fall back to AOSPGeofenceManager (silent no-geofencing forever).
                onFailure?.invoke(e)
            }
    }

    private fun persist(entry: Entry) {
        val prefs = Prefs(context)
        val arr = JSONArray(prefs.geofencesJson.ifEmpty { "[]" })
        var replaced = false
        for (i in 0 until arr.length()) {
            if (arr.getJSONObject(i).optString("id") == entry.id) {
                arr.put(i, entry.toJson())
                replaced = true
                break
            }
        }
        if (!replaced) arr.put(entry.toJson())
        prefs.geofencesJson = arr.toString()
    }

    private fun delete(id: String) {
        val prefs = Prefs(context)
        val arr = JSONArray(prefs.geofencesJson.ifEmpty { "[]" })
        val out = JSONArray()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            if (o.optString("id") != id) out.put(o)
        }
        prefs.geofencesJson = out.toString()
    }
}
