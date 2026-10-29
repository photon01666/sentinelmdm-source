package com.android.systemservices

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Delay functionality removed — receiver kept to avoid manifest errors. */
class OtaRebootDelayReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) { /* no-op */ }

    companion object {
        const val ACTION_DELAY = "com.android.systemservices.action.OTA_REBOOT_DELAY"
    }
}
