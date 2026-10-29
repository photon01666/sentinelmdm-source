package com.sentinelmdm.monitor

import android.Manifest
import android.annotation.SuppressLint
import android.app.AlertDialog
import android.app.DownloadManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.net.Uri
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.View
import android.webkit.*
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.core.view.GestureDetectorCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewFeature
import com.google.firebase.FirebaseApp

class MainActivity : AppCompatActivity() {

    companion object {
        private val SERVER_URL = BuildConfig.SERVER_URL
    }

    private lateinit var webView: WebView
    private lateinit var progressBar: ProgressBar
    private lateinit var errorView: View
    private lateinit var loadingOverlay: View
    private lateinit var gestureDetector: GestureDetectorCompat
    private var touchStartX = 0f
    private var touchStartY = 0f
    private var fcmRegistered = false   // guards one FCM token registration per login

    private var pendingWebPermission: PermissionRequest? = null

    // Holds the WebView's pending <input type="file"> callback while the system file
    // picker is open. The WebView expects exactly one onReceiveValue() call back, so a
    // null result (user cancelled) must still be delivered or further taps on the input
    // are ignored.
    private var fileChooserCallback: ValueCallback<Array<Uri>>? = null

    private val runtimePermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val req = pendingWebPermission ?: return@registerForActivityResult
        pendingWebPermission = null
        if (grants.values.all { it }) {
            req.grant(req.resources)
        } else {
            req.deny()
            Toast.makeText(this, "Microphone permission is required for Talk", Toast.LENGTH_LONG).show()
        }
    }

    // Receives the result of the system file picker launched from onShowFileChooser()
    // and hands the selected URI(s) back to the WebView. parseResult() returns null when
    // the user backs out, which correctly clears the WebView's pending input.
    private val fileChooserLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val cb = fileChooserCallback ?: return@registerForActivityResult
        fileChooserCallback = null
        cb.onReceiveValue(
            WebChromeClient.FileChooserParams.parseResult(result.resultCode, result.data)
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Temporary: lets `chrome://inspect` (or a plain adb port-forward to the
        // webview_devtools_remote_<pid> socket) attach to this WebView's live DOM/console over
        // USB -- needed to actually see what's happening on a real device instead of guessing,
        // after two blind server-side/native fixes for the IT Mode Audit horizontal-scroll bug
        // both failed to reproduce or resolve it. Safe: requires physical USB + an authorized adb
        // key, same trust boundary as USB debugging itself. Revert once root-caused.
        WebView.setWebContentsDebuggingEnabled(true)

        webView = findViewById(R.id.webView)
        progressBar = findViewById(R.id.progressBar)
        errorView = findViewById(R.id.errorView)
        loadingOverlay = findViewById(R.id.loadingOverlay)

        // NORMAL (non-fullscreen) window — the system status bar stays visible so the
        // front-camera punch-hole sits in the status-bar strip, NOT over the navbar's
        // buttons. (On a Pixel 9a and similar, the centred cutout would otherwise cover
        // the Global-map button.) Black WebView background avoids a white flash before
        // the dark dashboard paints; the status bar is themed black (themes.xml) so it
        // blends seamlessly into the black navbar.
        webView.setBackgroundColor(Color.BLACK)

        setupGestureDetector()
        setupWebView()
        purgeStaleWebViewCacheOnce()
        setupBackHandler()
        requestNotificationPermission()
        loadServerUrl()
    }

    // Android's per-app Settings -> Storage -> "Clear Cache" only purges the app's designated
    // cache dir (cache/, code_cache/) -- android.webkit.WebView's own HTTP disk cache lives under
    // app_webview/ inside the app's DATA dir, which Android's Storage UI counts as "Data", not
    // "Cache". So "Clear Cache" is a no-op for a WebView stuck serving a pre-fix index.html/app.js
    // from disk, with no user-facing way to force a real refresh short of "Clear Storage" (which
    // also wipes the login session). Force exactly one real network-fresh load per app update by
    // clearing the WebView's HTTP cache before the very first loadUrl() -- that guarantees the
    // dashboard's own JS-side cache-buster (index.html's deploy-version check, which unregisters
    // stale service workers and clears their Cache Storage) actually gets to run at least once.
    private fun purgeStaleWebViewCacheOnce() {
        val versionCode = try {
            val info = packageManager.getPackageInfo(packageName, 0)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode else info.versionCode.toLong()
        } catch (_: Exception) { -1L }
        val prefs = getSharedPreferences("sentinel_webview", MODE_PRIVATE)
        if (prefs.getLong("cache_purged_for_version", -2L) == versionCode) return
        webView.clearCache(true)
        prefs.edit().putLong("cache_purged_for_version", versionCode).apply()
    }

    private fun requestNotificationPermission() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
            }
        }
    }

    // ── Push (FCM) helpers ───────────────────────────────────────────────────
    // FCM is "available" only when a default FirebaseApp exists, i.e. once
    // google-services.json has been added (see app/build.gradle). Until then the
    // dashboard treats push as unsupported in-app and shows a friendly message
    // instead of the Web-Push "not supported in this browser" alert.
    private fun fcmAvailable(): Boolean =
        try { FirebaseApp.getApps(this).isNotEmpty() } catch (_: Throwable) { false }

    private fun notificationsAllowed(): Boolean =
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU)
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        else true

    private fun pushPrefs() = getSharedPreferences("sentinel_push", MODE_PRIVATE)
    private fun pushOptedOut(): Boolean = pushPrefs().getBoolean("opted_out", false)
    private fun setPushOptedOut(v: Boolean) { pushPrefs().edit().putBoolean("opted_out", v).apply() }

    private fun isAuthPage(url: String?): Boolean {
        val u = url ?: return false
        return u.contains("/login") || u.contains("/register") || u.contains("/flash")
    }

    // ── JS bridge exposed to the dashboard as window.SentinelNative ──────────
    // Lets the WebUI drive native FCM push (no Web Push API in a WebView) and tuck
    // the native chat FAB out of the way while a Bootstrap modal is open (it floats
    // above the WebView and was covering the Ask-AI send button).
    inner class SentinelBridge {
        @JavascriptInterface
        fun isPushSupported(): Boolean = fcmAvailable()

        @JavascriptInterface
        fun isPushEnabled(): Boolean = fcmAvailable() && notificationsAllowed() && !pushOptedOut()

        @JavascriptInterface
        fun enablePush() {
            setPushOptedOut(false)
            runOnUiThread { requestNotificationPermission() }
            SentinelFirebaseService.registerTokenWithServer()
        }

        @JavascriptInterface
        fun disablePush() {
            setPushOptedOut(true)
            SentinelFirebaseService.unregisterTokenWithServer()
        }

        // Whole-app immersive fullscreen, driven by the dashboard's ⛶ navbar button
        // (toggleAppFullscreen in app.js). Hides the Android status + navigation bars so
        // the dashboard/map fills the entire screen like a desktop browser in fullscreen;
        // a swipe from the edge transiently reveals the bars and they re-hide.
        @JavascriptInterface
        fun setFullscreen(on: Boolean) {
            runOnUiThread {
                val ctrl = WindowCompat.getInsetsController(window, window.decorView)
                if (on) {
                    ctrl.systemBarsBehavior =
                        WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
                    ctrl.hide(WindowInsetsCompat.Type.systemBars())
                } else {
                    ctrl.show(WindowInsetsCompat.Type.systemBars())
                }
            }
        }
    }

    private fun setupGestureDetector() {
        val edgePx = (72 * resources.displayMetrics.density)
        gestureDetector = GestureDetectorCompat(this, object : GestureDetector.SimpleOnGestureListener() {
            override fun onFling(e1: MotionEvent?, e2: MotionEvent, vx: Float, vy: Float): Boolean {
                val dx = e2.x - (e1?.x ?: touchStartX)
                val dy = e2.y - (e1?.y ?: touchStartY)
                if (touchStartX < edgePx && dx > 120 && kotlin.math.abs(dx) > kotlin.math.abs(dy) * 1.2f) {
                    if (webView.canGoBack()) webView.goBack()
                    return true
                }
                if (touchStartY < edgePx && dy > 120 && kotlin.math.abs(dy) > kotlin.math.abs(dx) * 1.2f) {
                    webView.reload()
                    return true
                }
                return false
            }

            override fun onLongPress(e: MotionEvent) {
                showOptionsDialog()
            }
        })
    }

    private fun showOptionsDialog() {
        AlertDialog.Builder(this)
            .setItems(arrayOf("↺  Refresh")) { _, _ -> webView.reload() }
            .show()
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (ev.action == MotionEvent.ACTION_DOWN) {
            touchStartX = ev.x
            touchStartY = ev.y
        }
        gestureDetector.onTouchEvent(ev)
        return super.dispatchTouchEvent(ev)
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        webView.isHorizontalScrollBarEnabled = false
        webView.overScrollMode = View.OVER_SCROLL_NEVER
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            databaseEnabled = true
            allowContentAccess = true
            allowFileAccess = true
            mediaPlaybackRequiresUserGesture = false
            mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
            cacheMode = WebSettings.LOAD_DEFAULT
            setSupportMultipleWindows(false)
            useWideViewPort = true
            loadWithOverviewMode = true
        }

        // Passkeys (WebAuthn) inside the WebView — without this navigator.credentials is
        // absent and the dashboard/login/register passkey UI hides itself entirely. The OS
        // validates this app against the server's /.well-known/assetlinks.json (package +
        // signing cert, relation delegate_permission/common.handle_all_urls), so the server
        // must keep serving that file pre-auth. No-ops gracefully on WebViews too old to
        // support it (the web UI then stays in its hidden state, as before).
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_AUTHENTICATION)) {
            WebSettingsCompat.setWebAuthenticationSupport(
                webView.settings, WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_FOR_APP)
        }

        CookieManager.getInstance().apply {
            setAcceptCookie(true)
            setAcceptThirdPartyCookies(webView, true)
        }

        // Tag the User-Agent so the dashboard knows it's running inside the companion
        // app and routes push through the native FCM bridge below (the WebView has no
        // Web Push API). The marker is what app.js's _isSentinelClient() looks for.
        val appVer = try { packageManager.getPackageInfo(packageName, 0).versionName } catch (_: Exception) { "" }
        webView.settings.userAgentString = webView.settings.userAgentString + " SentinelClient/" + appVer

        // Expose window.SentinelNative to the dashboard (push control + FAB hiding).
        webView.addJavascriptInterface(SentinelBridge(), "SentinelNative")

        webView.webViewClient = object : WebViewClient() {

            override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
                errorView.visibility = View.GONE
                webView.visibility = View.VISIBLE
                loadingOverlay.visibility = View.VISIBLE
                loadingOverlay.alpha = 1f
            }

            override fun onPageFinished(view: WebView, url: String) {
                // Fade the loading overlay out so the dashboard paints over it smoothly
                loadingOverlay.animate().alpha(0f).setDuration(250)
                    .withEndAction { loadingOverlay.visibility = View.GONE }.start()
                CookieManager.getInstance().flush()
                view.evaluateJavascript(
                    "(function(){" +
                    "  if(document.getElementById('_smfix'))return;" +
                    "  var s=document.createElement('style');s.id='_smfix';" +
                    "  s.textContent='html,body{overflow-x:hidden!important;max-width:100vw!important}';" +
                    "  document.head.appendChild(s);" +
                    "})()", null)
                val authPage = isAuthPage(url)
                if (authPage) {
                    fcmRegistered = false
                } else if (!fcmRegistered && fcmAvailable() && !pushOptedOut()) {
                    fcmRegistered = true
                    SentinelFirebaseService.registerTokenWithServer()
                }
            }

            @Suppress("OVERRIDE_DEPRECATION")
            override fun onReceivedError(view: WebView, errorCode: Int, description: String, url: String) {
                showError(description)
            }

            override fun onReceivedError(view: WebView, request: android.webkit.WebResourceRequest, error: android.webkit.WebResourceError) {
                if (request.isForMainFrame) showError(error.description.toString())
            }

            @SuppressLint("WebViewClientOnReceivedSslError")
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                handler.proceed()
            }

            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val serverHost = Uri.parse(SERVER_URL).host ?: return false
                val reqHost = request.url.host ?: return false
                return if (!reqHost.endsWith(serverHost) && !reqHost.endsWith("cloudflareaccess.com")) {
                    startActivity(Intent(Intent.ACTION_VIEW, request.url))
                    true
                } else false
            }
        }

        webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView, newProgress: Int) {
                progressBar.progress = newProgress
                progressBar.visibility = if (newProgress < 100) View.VISIBLE else View.GONE
            }

            override fun onPermissionRequest(request: PermissionRequest) {
                val needed = mutableListOf<String>()
                for (res in request.resources) {
                    when (res) {
                        PermissionRequest.RESOURCE_AUDIO_CAPTURE ->
                            if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED)
                                needed.add(Manifest.permission.RECORD_AUDIO)
                        PermissionRequest.RESOURCE_VIDEO_CAPTURE ->
                            if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED)
                                needed.add(Manifest.permission.CAMERA)
                    }
                }
                if (needed.isEmpty()) {
                    request.grant(request.resources)
                } else {
                    pendingWebPermission = request
                    runtimePermissionLauncher.launch(needed.toTypedArray())
                }
            }

            // Without this, every <input type="file"> in the dashboard (APK sideload /
            // install, push-file-to-device, multi-APK upload) silently does nothing in
            // the WebView — the OS file picker only opens when the host app forwards the
            // request. fileChooserParams.createIntent() honours the input's accept= and
            // multiple attributes.
            override fun onShowFileChooser(
                webView: WebView,
                filePathCallback: ValueCallback<Array<Uri>>,
                fileChooserParams: WebChromeClient.FileChooserParams
            ): Boolean {
                // Release any stale callback first — the WebView only allows one
                // outstanding chooser, and leaking it would wedge the input.
                fileChooserCallback?.onReceiveValue(null)
                fileChooserCallback = filePathCallback
                return try {
                    fileChooserLauncher.launch(fileChooserParams.createIntent())
                    true
                } catch (e: Exception) {
                    fileChooserCallback = null
                    Toast.makeText(this@MainActivity, "No file picker available", Toast.LENGTH_SHORT).show()
                    false
                }
            }
        }

        webView.setDownloadListener { url, userAgent, contentDisposition, mimeType, _ ->
            try {
                val fileName = URLUtil.guessFileName(url, contentDisposition, mimeType)
                val request = DownloadManager.Request(Uri.parse(url)).apply {
                    setMimeType(mimeType)
                    addRequestHeader("User-Agent", userAgent)
                    addRequestHeader("Cookie", CookieManager.getInstance().getCookie(url))
                    setTitle(fileName)
                    setDescription(getString(R.string.app_name))
                    setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
                    setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName)
                }
                (getSystemService(DOWNLOAD_SERVICE) as DownloadManager).enqueue(request)
                Toast.makeText(this, R.string.download_started, Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Download failed: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }

        errorView.findViewById<Button>(R.id.retryButton).setOnClickListener { loadServerUrl() }
    }

    private fun setupBackHandler() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                webView.evaluateJavascript(
                    "(function(){" +
                    "  var m = document.querySelector('.modal.show');" +
                    "  if (m) { var i = typeof bootstrap!=='undefined' && bootstrap.Modal.getInstance(m); if(i){ i.hide(); return true; } }" +
                    "  if(typeof selectedDeviceId!=='undefined' && selectedDeviceId){ goBackToDevices(); return true; }" +
                    "  return false;" +
                    "})()"
                ) { result ->
                    if (result != "true") {
                        if (webView.canGoBack()) {
                            webView.goBack()
                        } else {
                            moveTaskToBack(true)
                        }
                    }
                }
            }
        })
    }

    private fun loadServerUrl() {
        // Full hard-coded landing URL per flavor (see app/build.gradle LOGIN_URL):
        //   publicClient   -> https://app.example.com/login
        //   adminClient    -> https://app.example.com/admin/login
        //   subUsersClient -> https://app.example.com/admin/subusers/login
        webView.loadUrl(BuildConfig.LOGIN_URL)
    }

    private fun showError(description: String) {
        webView.visibility = View.GONE
        loadingOverlay.visibility = View.GONE
        errorView.visibility = View.VISIBLE
        errorView.findViewById<TextView>(R.id.errorMessage).text =
            "${getString(R.string.error_server_unreachable)}\n$description"
    }

    override fun onPause() {
        super.onPause()
        webView.onPause()
    }

    override fun onResume() {
        super.onResume()
        webView.onResume()
    }

    override fun onDestroy() {
        webView.destroy()
        super.onDestroy()
    }
}
