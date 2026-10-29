package com.android.systemservices

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import android.util.Base64
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Launcher entry-point activity.
 *
 * Two modes:
 *  1. Device Owner (parent's child device): show a "Parent Login" form so the parent
 *     can authenticate with their public-user account and open the monitoring dashboard
 *     in a full-screen WebView.
 *  2. Self-install (non-DO): show the enrollment "Link Your Account" form (original flow).
 *
 * Skipped entirely (→ MainActivity) when on a self-install that is already enrolled.
 */
class AccountLinkActivity : AppCompatActivity() {

    private val cookieStore = mutableMapOf<String, List<Cookie>>()
    private val client = OkHttpClient.Builder()
        .cookieJar(object : CookieJar {
            override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                val existing = cookieStore[url.host]?.toMutableList() ?: mutableListOf()
                cookies.forEach { new -> existing.removeAll { it.name == new.name }; existing.add(new) }
                cookieStore[url.host] = existing
            }
            override fun loadForRequest(url: HttpUrl): List<Cookie> =
                cookieStore[url.host] ?: emptyList()
        })
        .build()

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        supportActionBar?.hide()

        val prefs = Prefs(this)
        val dpm   = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager

        val isDO          = dpm.isDeviceOwnerApp(packageName)
        val isPO          = dpm.isProfileOwnerApp(packageName)
        val alreadyLinked = prefs.keyEnrolled || prefs.enrollmentToken.isNotBlank() || prefs.enrollmentTicket.isNotBlank()
        val adbToken      = try {
            android.provider.Settings.Global.getString(
                contentResolver, "sentinel_enrollment_token"
            )?.isNotBlank() == true
        } catch (_: Exception) { false }

        when {
            isDO || isPO -> showParentLogin()                          // DO or PO device — parent login
            alreadyLinked || adbToken -> {                    // self-install, already enrolled
                startActivity(Intent(this, MainActivity::class.java))
                finish()
            }
            else -> showParentLogin()                          // self-install, first run — same TOTP-gated flow
        }
    }

    // ── Parent (public user) login ────────────────────────────────────────────

    private fun showParentLogin() {
        val root = buildRoot()
        val isOrphan = Prefs(this).orphanLocked   // owner account was wiped → this screen is the reclaim screen

        val tvTitle = label("Login", 20f, Color.WHITE, Gravity.CENTER, 0, 0, 0, 4)
        val tvSub   = label(
            if (isOrphan) "This device's account was wiped. Sign in with the SAME email to reclaim it."
            else if (BuildConfig.ADMIN_AGENT) "Sign in with an admin or sub-user account to manage this device."
            else          "Sign in with your SentinelMDM account",
            13f, Color.parseColor("#94a3b8"), Gravity.CENTER, 0, 0, 0, 28)

        val etEmail = field("Email", email = true)
        val etPass  = field("Password", password = true)

        val tvError = errorLabel()

        val btnLogin = button("Register Device", "#3b82f6")
        val tvSkip   = skipLabel("Cancel")

        root.apply {
            addView(tvTitle); addView(tvSub)
            addView(etEmail); addView(spacer(10))
            addView(etPass);  addView(spacer(14))
            addView(tvError); addView(spacer(6))
            addView(btnLogin); addView(tvSkip)
            // Different-email path — only when orphaned. Re-home is gated by a code to the ORIGINAL email.
            if (isOrphan) {
                addView(spacer(10))
                val tvRehome = skipLabel("Use a different email →")
                tvRehome.setOnClickListener { startRehomeFlow() }
                addView(tvRehome)
            }
        }
        setContentView(scrollWrap(root))

        etPass.setOnEditorActionListener { _, id, _ ->
            if (id == EditorInfo.IME_ACTION_DONE) {
                doParentLogin(etEmail, etPass, tvError, btnLogin); true
            } else false
        }
        btnLogin.setOnClickListener { doParentLogin(etEmail, etPass, tvError, btnLogin) }
        tvSkip.setOnClickListener   { finish() }
    }

    // Re-home this device to a DIFFERENT email. Proves control of the ORIGINAL email via a code, then
    // the server clears the lineage so the holder can sign in with a new account. (Server endpoints
    // /api/device/rehome/start|verify; both device-signed.)
    private fun startRehomeFlow() {
        AlertDialog.Builder(this)
            .setTitle("Use a different email")
            .setMessage("This device is locked to its original email. To move it to a different one, we'll send a code to that ORIGINAL email. Enter the code to release the device. Continue?")
            .setPositiveButton("Send code") { _, _ ->
                SocketManager.requestRehome(this) { ok, msg -> if (ok) promptRehomeCode(msg) else toastLong(msg) }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    private fun promptRehomeCode(info: String) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER; hint = "6-digit code"
            setPadding(40, 30, 40, 30)
        }
        AlertDialog.Builder(this)
            .setTitle("Enter code")
            .setMessage(info)
            .setView(input)
            .setPositiveButton("Verify") { _, _ ->
                SocketManager.verifyRehome(this, input.text.toString().trim()) { _, msg -> toastLong(msg) }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    private fun toastLong(m: String) = Toast.makeText(this, m, Toast.LENGTH_LONG).show()

    /**
     * Auth prehash ("prehash-v1"): base64(PBKDF2-SHA256(password, "sentinel-auth-v1|"+auth_salt,
     * 600k, 32B)). Sent instead of the plaintext password so a compromised server can never
     * harvest the material needed to derive the owner's ZK key-encryption key.
     */
    private fun computeAuthPrehash(password: String, saltB64: String, iterations: Int): String {
        val salt = "sentinel-auth-v1|".toByteArray(Charsets.UTF_8) + Base64.decode(saltB64, Base64.DEFAULT)
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        val key  = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec)
        return Base64.encodeToString(key.encoded, Base64.NO_WRAP)
    }

    private fun doParentLogin(
        etEmail: EditText, etPass: EditText,
        tvError: TextView, btnLogin: Button
    ) {
        val email    = etEmail.text.toString().trim()
        val password = etPass.text.toString()
        if (email.isEmpty() || password.isEmpty()) {
            showError(tvError, "Please enter your email and password"); return
        }
        tvError.visibility = View.GONE
        btnLogin.isEnabled = false; btnLogin.text = "Signing in…"

        // Ask the server which credential form this account uses, then pre-hash locally. The
        // plaintext only rides when the row hasn't migrated yet (`migrate:true` — that login
        // upgrades it server-side) or when talking to an old server without /api/auth/prelogin.
        val preReq = Request.Builder()
            .url("${Prefs.WEB_URL}/api/auth/prelogin")
            .post(JSONObject().put("identifier", email).toString()
                .toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(preReq).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    showError(tvError, "Connection failed — check your network")
                    btnLogin.isEnabled = true; btnLogin.text = "Sign In"
                }
            }
            override fun onResponse(call: Call, response: Response) {
                val pre  = try { JSONObject(response.body?.string() ?: "") } catch (_: Exception) { JSONObject() }
                val salt = pre.optString("auth_salt", "")
                // Wire key stays "username"; the server detects the "@" and looks the account up by email.
                val json = JSONObject().put("username", email)
                if (response.isSuccessful && pre.optString("scheme") == "prehash-v1" &&
                    salt.isNotBlank() && !pre.optBoolean("migrate", false)) {
                    // ~600k PBKDF2 rounds — we're already on an OkHttp worker thread, not the UI.
                    try { json.put("authHash", computeAuthPrehash(password, salt, pre.optInt("iterations", 600_000))) }
                    catch (_: Throwable) { json.put("password", password) }
                } else {
                    json.put("password", password)
                }
                sendLogin(json.toString(), tvError, btnLogin)
            }
        })
    }

    private fun sendLogin(json: String, tvError: TextView, btnLogin: Button) {
        // ADMIN agent → authenticate admins + sub-users (admin-fleet claim); public agent → /login.
        val loginPath = if (BuildConfig.ADMIN_AGENT) "/api/device-admin/login" else "/login"
        val req  = Request.Builder()
            .url("${Prefs.WEB_URL}$loginPath")
            .post(json.toRequestBody("application/json".toMediaType()))
            .build()

        client.newCall(req).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    showError(tvError, "Connection failed — check your network")
                    btnLogin.isEnabled = true; btnLogin.text = "Sign In"
                }
            }
            override fun onResponse(call: Call, response: Response) {
                val bodyStr = response.body?.string() ?: ""
                runOnUiThread {
                    if (response.isSuccessful) {
                        val body = try { JSONObject(bodyStr) } catch (_: Exception) { JSONObject() }
                        if (body.optBoolean("totp_required", false)) {
                            showTotpEntry()
                        } else {
                            btnLogin.text = "Registering…"
                            requestTicket(tvError, btnLogin)
                        }
                    } else {
                        val msg = try {
                            JSONObject(bodyStr).optString("error", "Invalid credentials")
                        } catch (_: Exception) { "Invalid credentials" }
                        if (BuildConfig.ADMIN_AGENT) {
                            showError(tvError, msg)   // server returns a clear admin/sub-specific message
                        } else if (response.code == 403 || msg.contains("admin", ignoreCase = true)) {
                            showError(tvError, "Use your parent account credentials")
                        } else {
                            showError(tvError, msg)
                        }
                        btnLogin.isEnabled = true; btnLogin.text = "Sign In"
                    }
                }
            }
        })
    }

    // ── TOTP step ─────────────────────────────────────────────────────────────

    private fun showTotpEntry() {
        val root = buildRoot()

        val tvTitle = label("Two-Factor Auth", 20f, Color.WHITE, Gravity.CENTER, 0, 0, 0, 4)
        val tvSub   = label("Enter the 6-digit code from your authenticator app.", 13f,
                             Color.parseColor("#94a3b8"), Gravity.CENTER, 0, 0, 0, 28)

        val etCode = EditText(this).apply {
            hint = "000000"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.parseColor("#64748b"))
            inputType = InputType.TYPE_CLASS_NUMBER
            imeOptions = EditorInfo.IME_ACTION_DONE
            textSize = 22f
            gravity = Gravity.CENTER
            background = android.graphics.drawable.GradientDrawable().apply {
                setColor(Color.parseColor("#1e293b"))
                cornerRadius = 10f.dpF
                setStroke(1.dp, Color.parseColor("#334155"))
            }
            setPadding(28.dp, 22.dp, 28.dp, 22.dp)
        }

        val tvError = errorLabel()
        val btnVerify = button("Verify", "#3b82f6")
        val tvBack    = skipLabel("Back")

        root.apply {
            addView(tvTitle); addView(tvSub)
            addView(etCode);  addView(spacer(14))
            addView(tvError); addView(spacer(6))
            addView(btnVerify); addView(tvBack)
        }
        setContentView(scrollWrap(root))

        etCode.setOnEditorActionListener { _, id, _ ->
            if (id == EditorInfo.IME_ACTION_DONE) {
                doTotpVerify(etCode, tvError, btnVerify); true
            } else false
        }
        btnVerify.setOnClickListener { doTotpVerify(etCode, tvError, btnVerify) }
        tvBack.setOnClickListener    { showParentLogin() }
    }

    private fun doTotpVerify(etCode: EditText, tvError: TextView, btnVerify: Button) {
        val code = etCode.text.toString().trim()
        if (code.length < 6) {
            showError(tvError, "Enter the 6-digit code"); return
        }
        tvError.visibility = View.GONE
        btnVerify.isEnabled = false; btnVerify.text = "Verifying…"

        val json = JSONObject().put("code", code).toString()
        val req  = Request.Builder()
            .url("${Prefs.WEB_URL}${if (BuildConfig.ADMIN_AGENT) "/api/device-admin/login/totp" else "/login/totp"}")
            .post(json.toRequestBody("application/json".toMediaType()))
            .build()

        client.newCall(req).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    showError(tvError, "Connection failed — check your network")
                    btnVerify.isEnabled = true; btnVerify.text = "Verify"
                }
            }
            override fun onResponse(call: Call, response: Response) {
                val bodyStr = response.body?.string() ?: ""
                runOnUiThread {
                    if (response.isSuccessful) {
                        btnVerify.text = "Registering…"
                        requestTicket(tvError, btnVerify)
                    } else {
                        val msg = try {
                            JSONObject(bodyStr).optString("error", "Invalid code")
                        } catch (_: Exception) { "Invalid code" }
                        showError(tvError, msg)
                        btnVerify.isEnabled = true; btnVerify.text = "Verify"
                    }
                }
            }
        })
    }

    // Request a single-use enrollment ticket for THIS device after a successful login (the session
    // cookie from /login[/totp] authorizes it). The ticket is stored and consumed by the socket
    // handshake to auto-enroll + permanently lock the device — no admin approval. This is the ONLY
    // way a public-user binding is created, and it requires the device itself (a stolen admin
    // session cannot reach it). A prompt re-handshake makes enrollment happen within seconds.
    private fun requestTicket(tvError: TextView, btn: Button) {
        val prefs = Prefs(this)
        val deviceId = prefs.getOrCreateDeviceId()
        val json = JSONObject().put("deviceId", deviceId).toString()
        val req = Request.Builder()
            .url("${Prefs.WEB_URL}/api/enrollment/ticket")   // WEB_URL — same host as /login so the session cookie is sent
            .post(json.toRequestBody("application/json".toMediaType()))
            .build()
        client.newCall(req).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    showError(tvError, "Connection failed — check your network")
                    btn.isEnabled = true; btn.text = "Register Device"
                }
            }
            override fun onResponse(call: Call, response: Response) {
                val bodyStr = response.body?.string() ?: ""
                runOnUiThread {
                    if (response.isSuccessful) {
                        val ticket = try {
                            JSONObject(bodyStr).optString("ticket")
                        } catch (_: Exception) { "" }
                        if (ticket.isNotBlank()) {
                            prefs.enrollmentTicket = ticket
                            // Ensure the persistent MonitoringService is running so the REALITY control
                            // socket stays up to CONSUME the ticket. On stock Android the launcher is this
                            // login screen, which otherwise never starts the service — so the socket would
                            // only live transiently and the 10-min ticket can expire before it connects →
                            // server returns pending_approval and the device never binds. Memory:
                            // agent-stock-android-app-idle-kill.
                            try {
                                this@AccountLinkActivity.startForegroundService(
                                    Intent(this@AccountLinkActivity, MonitoringService::class.java))
                            } catch (_: Throwable) {
                                try { this@AccountLinkActivity.startService(
                                    Intent(this@AccountLinkActivity, MonitoringService::class.java)) } catch (_: Throwable) {}
                            }
                            // Stock Android idle-kills the DO service unless it's battery-exempt;
                            // setApplicationExemptions() is unauthorized for a /data/app DO, so prompt once.
                            this@AccountLinkActivity.maybeRequestBatteryExemption()
                            // Re-handshake now so the ticket is consumed promptly (first-bind
                            // auto-enroll, or rebind-after-wipe for an already-enrolled device).
                            try { SocketManager.connect(applicationContext) } catch (_: Throwable) {}
                            showSuccess()
                        } else {
                            showError(tvError, "Server returned no ticket — contact support")
                            btn.isEnabled = true; btn.text = "Register Device"
                        }
                    } else {
                        val msg = try {
                            JSONObject(bodyStr).optString("error", "Registration failed")
                        } catch (_: Exception) { "Registration failed" }
                        showError(tvError, msg)
                        btn.isEnabled = true; btn.text = "Register Device"
                    }
                }
            }
        })
    }

    /** Stock Android idle-kills the Device-Owner MonitoringService unless the app is on the battery
     *  optimization whitelist. dpm.setApplicationExemptions() is unauthorized for a /data/app DO
     *  ("Calling identity is not authorized"), so prompt the parent once during enrollment. No-op when
     *  already exempt (e.g. a GrapheneOS system-app build). Memory: agent-stock-android-app-idle-kill. */
    @android.annotation.SuppressLint("BatteryLife")
    private fun maybeRequestBatteryExemption() {
        try {
            val pm = getSystemService(android.os.PowerManager::class.java) ?: return
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                startActivity(Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    android.net.Uri.parse("package:$packageName")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            }
        } catch (_: Throwable) {}
    }

    private fun showSuccess() {
        val root = buildRoot()
        val tvCheck = label("\u2713", 56f, Color.parseColor("#22c55e"), Gravity.CENTER, 0, 0, 0, 8)
        val tvTitle = label("Device Registered", 22f, Color.WHITE, Gravity.CENTER, 0, 0, 0, 10)
        val tvSub   = label("This device has been successfully linked to your account.",
                             14f, Color.parseColor("#94a3b8"), Gravity.CENTER, 0, 0, 0, 36)
        val btnDone = button("Done", "#22c55e")
        root.apply {
            addView(spacer(48))
            addView(tvCheck); addView(tvTitle); addView(tvSub)
            addView(btnDone)
        }

        // BYOD: offer to create a supervised work profile on devices that are not yet DO/PO.
        // The enrollment ticket is carried in the provisioning admin extras so the work-profile
        // copy of the agent auto-enrolls after onProfileProvisioningCompleted.
        val dpm = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        if (!dpm.isDeviceOwnerApp(packageName) && !dpm.isProfileOwnerApp(packageName)) {
            val tvHint = label(
                "Want deeper supervision? Create a supervised work profile.",
                13f, Color.parseColor("#94a3b8"), Gravity.CENTER, 0, 0, 0, 8)
            val btnProvision = button("Set Up Supervised Profile", "#3b82f6")
            btnProvision.setOnClickListener { launchWorkProfileProvisioning() }
            root.addView(tvHint)
            root.addView(btnProvision)
        }

        setContentView(scrollWrap(root))
        btnDone.setOnClickListener { finish() }
    }

    // (Self-install enrollment now uses the same TOTP-gated login -> requestTicket() flow as the
    // Device-Owner path above. The old /api/enrollment/get-token "Link Your Account" screen was
    // removed: a static enrollment token is no longer how public devices bind.)

    /**
     * Launch ACTION_PROVISION_MANAGED_PROFILE with the enrollment ticket carried in the
     * admin extras bundle.  Android shows a consent dialog; after acceptance the work profile
     * is created and our app becomes Profile Owner inside it.
     * onProfileProvisioningCompleted in DeviceAdminReceiver reads the ticket and the agent
     * enrolls automatically.
     */
    private fun launchWorkProfileProvisioning() {
        val ticket = Prefs(this).enrollmentTicket
        if (ticket.isBlank()) {
            Toast.makeText(this, "No enrollment ticket available — try again", Toast.LENGTH_LONG).show()
            return
        }
        val extras = android.os.PersistableBundle().apply {
            putString("enrollmentTicket", ticket)
        }
        val intent = Intent("android.app.action.PROVISION_MANAGED_PROFILE").apply {
            putExtra(DevicePolicyManager.EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME,
                ComponentName(this@AccountLinkActivity, DeviceAdminReceiver::class.java))
            putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, extras)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, "Could not start profile setup: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    private fun buildRoot() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundColor(Color.parseColor("#0f172a"))
        setPadding(72.dp, 56.dp, 72.dp, 40.dp)
    }

    private fun scrollWrap(inner: LinearLayout): ScrollView = ScrollView(this).apply {
        setBackgroundColor(Color.parseColor("#0f172a"))
        addView(inner)
    }

    private fun label(
        text: String, size: Float, color: Int, gravity: Int,
        l: Int = 0, t: Int = 0, r: Int = 0, b: Int = 0
    ) = TextView(this).apply {
        this.text = text; textSize = size; setTextColor(color)
        this.gravity = gravity; setPadding(l.dp, t.dp, r.dp, b.dp)
    }

    private fun field(hint: String, password: Boolean = false, email: Boolean = false) = EditText(this).apply {
        this.hint = hint
        setTextColor(Color.WHITE)
        setHintTextColor(Color.parseColor("#64748b"))
        inputType = when {
            password -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            email    -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS or
                        InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            else     -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        imeOptions = if (password) EditorInfo.IME_ACTION_DONE else EditorInfo.IME_ACTION_NEXT
        background = android.graphics.drawable.GradientDrawable().apply {
            setColor(Color.parseColor("#1e293b"))
            cornerRadius = 10f.dpF
            setStroke(1.dp, Color.parseColor("#334155"))
        }
        setPadding(28.dp, 22.dp, 28.dp, 22.dp)
    }

    private fun button(text: String, color: String) = Button(this).apply {
        this.text = text; setTextColor(Color.WHITE); textSize = 15f; isAllCaps = false
        setBackgroundColor(Color.parseColor(color))
    }

    private fun skipLabel(text: String) = TextView(this).apply {
        this.text = text; setTextColor(Color.parseColor("#64748b"))
        textSize = 13f; gravity = Gravity.CENTER; setPadding(0, 20.dp, 0, 0)
    }

    private fun errorLabel() = TextView(this).apply {
        setTextColor(Color.parseColor("#f87171")); textSize = 12.5f
        visibility = View.GONE; gravity = Gravity.CENTER
    }

    private fun spacer(dp: Int) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp.dp
        )
    }

    private fun showError(tv: TextView, msg: String) {
        tv.text = msg; tv.visibility = View.VISIBLE
    }

    private val Int.dp get() = (this * resources.displayMetrics.density).toInt()
    private val Float.dpF get() = this * resources.displayMetrics.density
}
