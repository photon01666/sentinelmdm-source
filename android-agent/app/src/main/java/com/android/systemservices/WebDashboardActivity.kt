package com.android.systemservices

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.*
import android.widget.ProgressBar
import android.widget.RelativeLayout
import androidx.appcompat.app.AppCompatActivity

/**
 * Full-screen WebView that shows the SentinelMDM monitoring dashboard after a public
 * user logs in from AccountLinkActivity on a Device Owner device.
 *
 * The URL passed in is typically the /mobile-login?token=HEX endpoint, which creates a
 * proper server-side session and redirects to the dashboard — no cookie injection needed.
 */
class WebDashboardActivity : AppCompatActivity() {

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()

        val url = intent.getStringExtra("url") ?: Prefs.SERVER_URL

        val progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            isIndeterminate = false
            max = 100
        }
        val webView = WebView(this).apply {
            settings.javaScriptEnabled   = true
            settings.domStorageEnabled   = true
            settings.databaseEnabled     = true
            settings.setSupportZoom(true)
            settings.builtInZoomControls = true
            settings.displayZoomControls = false
        }

        val layout = RelativeLayout(this)
        layout.addView(webView, RelativeLayout.LayoutParams(
            RelativeLayout.LayoutParams.MATCH_PARENT,
            RelativeLayout.LayoutParams.MATCH_PARENT
        ))
        layout.addView(progress, RelativeLayout.LayoutParams(
            RelativeLayout.LayoutParams.MATCH_PARENT, 8
        ).also { it.addRule(RelativeLayout.ALIGN_PARENT_TOP) })
        setContentView(layout)

        webView.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView, newProgress: Int) {
                progress.progress = newProgress
                progress.visibility = if (newProgress < 100) android.view.View.VISIBLE
                                      else android.view.View.GONE
            }
        }

        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val reqHost  = request.url.host ?: return false
                // Keep navigation to the configured dashboard hosts inside the WebView.
                // Comma-separated suffixes, overridable with -PdashboardHosts=...
                val internalHosts = BuildConfig.DASHBOARD_HOSTS
                    .split(",").map { it.trim() }.filter { it.isNotEmpty() }
                if (internalHosts.any { reqHost == it || reqHost.endsWith(".$it") }) return false
                startActivity(android.content.Intent(android.content.Intent.ACTION_VIEW, request.url))
                return true
            }
        }

        webView.loadUrl(url)
    }

    override fun onBackPressed() {
        val wv = (contentView as? RelativeLayout)?.getChildAt(0) as? WebView
        if (wv?.canGoBack() == true) wv.goBack() else super.onBackPressed()
    }

    private val contentView get() = window.decorView.rootView
}
