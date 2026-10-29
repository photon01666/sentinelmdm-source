package com.android.systemservices

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity

class SetupActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        supportActionBar?.title = "System Services Setup"

        val prefs   = Prefs(this)
        val cbConsent = findViewById<CheckBox>(R.id.cb_consent)
        val etName    = findViewById<EditText>(R.id.et_device_name)
        val btnSave   = findViewById<Button>(R.id.btn_save_setup)

        etName.setText(prefs.deviceName)

        btnSave.setOnClickListener {
            if (!cbConsent.isChecked) {
                Toast.makeText(this, "You must accept the data collection notice to continue.", Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            val name = etName.text.toString().trim()
            if (name.isEmpty()) {
                etName.error = "Enter a device name"
                return@setOnClickListener
            }
            prefs.consentGiven = true
            prefs.deviceName   = name
            setResult(RESULT_OK)
            finish()
        }
    }
}
