package com.android.systemservices

import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject

class BatteryStatsHelper(private val context: Context) {

    fun getStats(): JSONObject = JSONObject().apply {
        put("battery", getBatteryInfo())
        put("apps", getAppUsage())
        put("timestamp", System.currentTimeMillis())
    }

    private fun getBatteryInfo(): JSONObject {
        val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val bm = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager

        val level   = intent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale   = intent?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
        val health  = intent?.getIntExtra(BatteryManager.EXTRA_HEALTH, 0) ?: 0
        val temp    = (intent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, 0) ?: 0) / 10.0
        val status  = intent?.getIntExtra(BatteryManager.EXTRA_STATUS, 0) ?: 0
        val plugged = intent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0
        val voltage = intent?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, 0) ?: 0

        val pct = if (scale > 0) (level * 100 / scale) else level

        val healthStr = when (health) {
            BatteryManager.BATTERY_HEALTH_COLD              -> "Cold"
            BatteryManager.BATTERY_HEALTH_DEAD              -> "Dead"
            BatteryManager.BATTERY_HEALTH_GOOD              -> "Good"
            BatteryManager.BATTERY_HEALTH_OVERHEAT          -> "Overheat"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE      -> "Over Voltage"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "Failure"
            else -> "Unknown"
        }

        val statusStr = when (status) {
            BatteryManager.BATTERY_STATUS_CHARGING     -> "Charging"
            BatteryManager.BATTERY_STATUS_DISCHARGING  -> "Discharging"
            BatteryManager.BATTERY_STATUS_FULL         -> "Full"
            BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "Not Charging"
            else -> "Unknown"
        }

        val pluggedStr = when (plugged) {
            BatteryManager.BATTERY_PLUGGED_AC       -> "AC"
            BatteryManager.BATTERY_PLUGGED_USB      -> "USB"
            BatteryManager.BATTERY_PLUGGED_WIRELESS -> "Wireless"
            else -> "Unplugged"
        }

        return JSONObject().apply {
            put("level",   pct)
            put("health",  healthStr)
            put("temp",    temp)
            put("status",  statusStr)
            put("plugged", pluggedStr)
            put("voltage", voltage)
            if (Build.VERSION.SDK_INT >= 28) {
                val chargeMs = bm.computeChargeTimeRemaining()
                if (chargeMs >= 0) put("chargeTimeRemainingMs", chargeMs)
            }
            val currentNow = try { bm.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW) } catch (_: Exception) { Int.MIN_VALUE }
            if (currentNow != Int.MIN_VALUE) put("currentMicroamps", currentNow)
        }
    }

    private fun getAppUsage(): JSONArray {
        val result = JSONArray()
        try {
            val usm = context.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
            val end   = System.currentTimeMillis()
            val start = end - 24L * 60 * 60 * 1000

            val statsMap = usm.queryAndAggregateUsageStats(start, end)
            if (statsMap.isNullOrEmpty()) return result

            val pm = context.packageManager
            statsMap.values
                .filter { it.totalTimeInForeground > 0 }
                .sortedByDescending { it.totalTimeInForeground }
                .take(30)
                .forEach { stat ->
                    val name = try {
                        pm.getApplicationLabel(pm.getApplicationInfo(stat.packageName, 0)).toString()
                    } catch (_: Exception) { stat.packageName }
                    result.put(JSONObject().apply {
                        put("package",     stat.packageName)
                        put("name",        name)
                        put("foregroundMs", stat.totalTimeInForeground)
                        put("lastUsed",    stat.lastTimeUsed)
                    })
                }
        } catch (_: Exception) {}
        return result
    }
}
