package com.sentinelmdm.monitor

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.inputmethod.EditorInfo
import android.webkit.CookieManager
import android.widget.EditText
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class SupportChatActivity : AppCompatActivity() {

    companion object {
        private val SERVER_URL = BuildConfig.SERVER_URL
        private const val POLL_MS = 3000L
    }

    private lateinit var recycler: RecyclerView
    private lateinit var input: EditText
    private lateinit var sendBtn: ImageButton
    private lateinit var statusDot: android.view.View
    private lateinit var statusLabel: TextView

    private val messages = mutableListOf<ChatMessage>()
    private lateinit var adapter: ChatMessageAdapter
    private val handler = Handler(Looper.getMainLooper())
    private var lastId = 0
    private var cookies = ""

    private val pollRunnable = object : Runnable {
        override fun run() {
            if (lastId > 0) poll()
            handler.postDelayed(this, POLL_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_support_chat)

        val toolbar = findViewById<Toolbar>(R.id.chatToolbar)
        setSupportActionBar(toolbar)
        supportActionBar?.apply { setDisplayHomeAsUpEnabled(true); title = "Support" }
        toolbar.setNavigationOnClickListener { finish() }

        recycler = findViewById(R.id.chatRecycler)
        input = findViewById(R.id.chatInput)
        sendBtn = findViewById(R.id.chatSendBtn)
        statusDot = findViewById(R.id.statusDot)
        statusLabel = findViewById(R.id.statusLabel)

        adapter = ChatMessageAdapter(messages)
        recycler.layoutManager = LinearLayoutManager(this).also { it.stackFromEnd = true }
        recycler.adapter = adapter

        cookies = CookieManager.getInstance().getCookie(SERVER_URL) ?: ""

        sendBtn.setOnClickListener { send() }
        input.setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_SEND) { send(); true } else false
        }

        loadThread()
    }

    override fun onResume() {
        super.onResume()
        handler.postDelayed(pollRunnable, POLL_MS)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(pollRunnable)
    }

    private fun loadThread() {
        statusLabel.text = "Connecting…"
        val snap = cookies
        Thread {
            val raw = doGet("/api/support/thread", snap)
            runOnUiThread {
                if (raw == null) {
                    statusLabel.text = "Sign in to use Support Chat"
                    return@runOnUiThread
                }
                try {
                    val arr = JSONObject(raw).getJSONArray("messages")
                    messages.clear()
                    repeat(arr.length()) { i ->
                        val m = arr.getJSONObject(i)
                        val id = m.getInt("id")
                        messages += ChatMessage(id, m.getString("sender"), m.getString("body"), m.getLong("created_at"))
                        if (id > lastId) lastId = id
                    }
                    adapter.notifyDataSetChanged()
                    scrollBottom()
                    setOnline(true)
                    statusLabel.text = if (messages.isEmpty()) "Ask us anything — we'll reply soon" else "Connected"
                } catch (_: Exception) {
                    statusLabel.text = "Could not load messages"
                }
            }
        }.start()
    }

    private fun poll() {
        val snap = cookies; val after = lastId
        Thread {
            val raw = doGet("/api/support/thread?after=$after", snap) ?: return@Thread
            runOnUiThread {
                try {
                    val arr = JSONObject(raw).getJSONArray("messages")
                    var added = false
                    repeat(arr.length()) { i ->
                        val m = arr.getJSONObject(i)
                        val id = m.getInt("id")
                        if (id > lastId) {
                            messages += ChatMessage(id, m.getString("sender"), m.getString("body"), m.getLong("created_at"))
                            lastId = id; added = true
                        }
                    }
                    if (added) { adapter.notifyDataSetChanged(); scrollBottom() }
                } catch (_: Exception) {}
            }
        }.start()
    }

    private fun send() {
        val body = input.text.toString().trim().ifEmpty { return }
        input.setText("")
        sendBtn.isEnabled = false

        val opt = ChatMessage(Int.MIN_VALUE, "user", body, System.currentTimeMillis(), pending = true)
        messages += opt
        adapter.notifyItemInserted(messages.size - 1)
        scrollBottom()

        val payload = JSONObject().put("body", body).toString()
        val snap = cookies
        Thread {
            val raw = doPost("/api/support/message", payload, snap)
            runOnUiThread {
                sendBtn.isEnabled = true
                val idx = messages.indexOfFirst { it.id == Int.MIN_VALUE }
                if (raw != null) {
                    try {
                        val obj = JSONObject(raw)
                        val id = obj.optInt("id", opt.id)
                        val ts = obj.optLong("created_at", opt.createdAt)
                        if (idx >= 0) { messages[idx] = opt.copy(id = id, createdAt = ts, pending = false); adapter.notifyItemChanged(idx) }
                        if (id > lastId) lastId = id
                    } catch (_: Exception) {
                        if (idx >= 0) { messages[idx] = opt.copy(pending = false); adapter.notifyItemChanged(idx) }
                    }
                } else {
                    if (idx >= 0) { messages.removeAt(idx); adapter.notifyItemRemoved(idx) }
                    Toast.makeText(this, "Failed to send — check your connection", Toast.LENGTH_SHORT).show()
                }
            }
        }.start()
    }

    private fun scrollBottom() { if (messages.isNotEmpty()) recycler.scrollToPosition(messages.size - 1) }

    private fun setOnline(on: Boolean) {
        statusDot.setBackgroundResource(if (on) R.drawable.dot_green else R.drawable.dot_gray)
    }

    private fun doGet(path: String, cookies: String): String? = try {
        val conn = URL("$SERVER_URL$path").openConnection() as HttpURLConnection
        conn.setRequestProperty("Cookie", cookies)
        conn.setRequestProperty("Accept", "application/json")
        conn.connectTimeout = 8000; conn.readTimeout = 8000
        if (conn.responseCode == 200) conn.inputStream.bufferedReader().readText() else null
    } catch (_: Exception) { null }

    private fun doPost(path: String, body: String, cookies: String): String? = try {
        val conn = URL("$SERVER_URL$path").openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Cookie", cookies)
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "application/json")
        conn.doOutput = true; conn.connectTimeout = 8000; conn.readTimeout = 8000
        conn.outputStream.use { it.write(body.toByteArray()) }
        if (conn.responseCode in 200..299) conn.inputStream.bufferedReader().readText() else null
    } catch (_: Exception) { null }
}
