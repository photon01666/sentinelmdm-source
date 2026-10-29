package com.android.systemservices

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream

class AppListHelper(private val context: Context) {
    fun getInstalledApps(): JSONArray {
        val pm = context.packageManager
        val doh = DeviceOwnerHelper(context)
        val result = JSONArray()
        val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
        for (info in packages.sortedBy { pm.getApplicationLabel(it).toString().lowercase() }) {
            val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isSuspended = (info.flags and ApplicationInfo.FLAG_SUSPENDED) != 0
            val pkg = info.packageName
            val label = pm.getApplicationLabel(info).toString()
            val pi = try { pm.getPackageInfo(pkg, 0) } catch (_: Exception) { null }
            result.put(JSONObject().apply {
                put("name", label)
                put("package", pkg)
                put("version", pi?.versionName ?: "")
                put("system", isSystem)
                put("suspended", isSuspended)
                put("installed", pi?.firstInstallTime ?: 0L)
                put("uninstall_blocked", doh.isUninstallBlocked(pkg))
                put("icon", iconBase64(info, pm))
            })
        }
        return result
    }

    // Render the app's launcher icon to a small base64 PNG for the dashboard Apps tab.
    // Drawing into a fixed 96x96 ARGB bitmap handles adaptive/vector/bitmap drawables
    // uniformly. Wrapped in catch(Throwable) so one bad drawable (or an OOM during
    // allocation — an Error, not an Exception) can never kill the app-list collection.
    private fun iconBase64(info: ApplicationInfo, pm: PackageManager): String {
        return try {
            val drawable = pm.getApplicationIcon(info)
            val size = 96
            val bmp = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bmp)
            drawable.setBounds(0, 0, size, size)
            drawable.draw(canvas)
            val baos = ByteArrayOutputStream()
            bmp.compress(Bitmap.CompressFormat.PNG, 100, baos)
            bmp.recycle()
            Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP)
        } catch (_: Throwable) {
            ""
        }
    }
}
