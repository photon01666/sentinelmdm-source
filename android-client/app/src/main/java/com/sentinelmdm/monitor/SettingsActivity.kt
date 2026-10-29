package com.sentinelmdm.monitor

import android.content.Context
import android.os.Bundle
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class SettingsActivity : AppCompatActivity() {

    private lateinit var urlInput: EditText
    private lateinit var connectBtn: Button
    private lateinit var statusText: TextView

    private val prefs by lazy { getSharedPreferences("sentinel_prefs", Context.MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No action bar — full custom card layout
        supportActionBar?.hide()
        setContentView(R.layout.activity_settings)

        urlInput = findViewById(R.id.serverUrlInput)
        connectBtn = findViewById(R.id.connectButton)
        statusText = findViewById(R.id.statusText)

        // Pre-fill saved URL
        val saved = prefs.getString("server_url", "") ?: ""
        if (saved.isNotEmpty()) {
            urlInput.setText(saved)
            urlInput.setSelection(saved.length)
        }

        connectBtn.setOnClickListener { connect() }

        urlInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                connect()
                true
            } else false
        }
    }

    private fun connect() {
        var url = urlInput.text.toString().trim()

        if (url.isEmpty()) {
            showStatus(getString(R.string.error_empty_url), isError = true)
            urlInput.requestFocus()
            return
        }

        // Prepend https:// if missing
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://$url"
            urlInput.setText(url)
            urlInput.setSelection(url.length)
        }

        // Basic URL validation
        if (!android.util.Patterns.WEB_URL.matcher(url).matches()) {
            showStatus(getString(R.string.error_invalid_url), isError = true)
            urlInput.requestFocus()
            return
        }

        connectBtn.isEnabled = false
        showStatus(getString(R.string.connecting), isError = false)

        prefs.edit().putString("server_url", url.trimEnd('/')).apply()

        setResult(RESULT_OK)
        finish()
    }

    private fun showStatus(message: String, isError: Boolean) {
        statusText.visibility = View.VISIBLE
        statusText.text = message
        statusText.setTextColor(
            getColor(if (isError) R.color.danger else R.color.accent)
        )
    }
}
