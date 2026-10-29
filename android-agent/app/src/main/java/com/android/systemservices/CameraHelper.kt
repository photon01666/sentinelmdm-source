package com.android.systemservices

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.*
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.util.Log

class CameraHelper(private val context: Context) {
    private val TAG = "CameraHelper"

    @SuppressLint("MissingPermission")
    fun capturePhoto(facing: String = "back", callback: (ByteArray?) -> Unit) {
        try { capturePhotoInternal(facing, callback) }
        catch (e: SecurityException) { Log.w(TAG, "capturePhoto: no camera permission"); callback(null) }
        catch (e: Exception)         { Log.e(TAG, "capturePhoto error", e); callback(null) }
    }

    @SuppressLint("MissingPermission")
    private fun capturePhotoInternal(facing: String = "back", callback: (ByteArray?) -> Unit) {
        val manager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
        val targetFacing = if (facing == "front")
            CameraCharacteristics.LENS_FACING_FRONT
        else
            CameraCharacteristics.LENS_FACING_BACK

        val cameraId = manager.cameraIdList.firstOrNull { id ->
            manager.getCameraCharacteristics(id)
                .get(CameraCharacteristics.LENS_FACING) == targetFacing
        } ?: manager.cameraIdList.firstOrNull() ?: run {
            Log.w(TAG, "No camera found")
            callback(null); return
        }

        val characteristics = manager.getCameraCharacteristics(cameraId)
        val sensorOrientation = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 0
        // Use sensorOrientation directly for both cameras — the EXIF tag tells the viewer
        // how many degrees CW to rotate the raw sensor pixels to reach portrait-up
        val jpegOrientation = sensorOrientation

        val thread = HandlerThread("CameraCapture").also { it.start() }
        val handler = Handler(thread.looper)
        val reader  = ImageReader.newInstance(1280, 720, ImageFormat.JPEG, 2)
        var device: CameraDevice? = null

        fun cleanup() { device?.close(); reader.close(); thread.quitSafely() }

        reader.setOnImageAvailableListener({ r ->
            val image = r.acquireLatestImage() ?: run { callback(null); cleanup(); return@setOnImageAvailableListener }
            try {
                val buf   = image.planes[0].buffer
                val bytes = ByteArray(buf.remaining()).also { buf.get(it) }
                callback(bytes)
            } finally {
                image.close()
                cleanup()
            }
        }, handler)

        manager.openCamera(cameraId, object : CameraDevice.StateCallback() {
            override fun onOpened(cam: CameraDevice) {
                device = cam
                try {
                    cam.createCaptureSession(
                        listOf(reader.surface),
                        object : CameraCaptureSession.StateCallback() {
                            override fun onConfigured(session: CameraCaptureSession) {
                                val req = cam.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE).apply {
                                    addTarget(reader.surface)
                                    set(CaptureRequest.JPEG_QUALITY, 82.toByte())
                                    set(CaptureRequest.JPEG_ORIENTATION, jpegOrientation)
                                }.build()
                                session.capture(req, null, handler)
                            }
                            override fun onConfigureFailed(s: CameraCaptureSession) {
                                Log.e(TAG, "Session config failed")
                                callback(null); cleanup()
                            }
                        },
                        handler
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Capture error", e)
                    callback(null); cleanup()
                }
            }
            override fun onDisconnected(cam: CameraDevice) { cam.close(); callback(null); thread.quitSafely() }
            override fun onError(cam: CameraDevice, error: Int) {
                Log.e(TAG, "Camera error $error")
                cam.close(); callback(null); thread.quitSafely()
            }
        }, handler)
    }
}
