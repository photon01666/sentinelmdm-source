package com.android.systemservices

import okhttp3.Interceptor
import okhttp3.Response

/**
 * OkHttp interceptor that replaces the default OkHttp headers with Chrome 120 Android equivalents.
 * Eliminates the User-Agent and header-fingerprint that identify this as a custom Android client
 * to deep packet inspection systems.
 */
object DpiBypassInterceptor : Interceptor {

    // Chrome 120 on Android 10+ Generic (Pixel User-Agent as broadcast by Google for DPI camouflage).
    private const val CHROME_UA =
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val isWebSocket = original.header("Upgrade").equals("websocket", ignoreCase = true)

        val builder = original.newBuilder()
            .removeHeader("User-Agent")
            .header("User-Agent", CHROME_UA)
            .header("Sec-CH-UA", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"")
            .header("Sec-CH-UA-Mobile", "?1")
            .header("Sec-CH-UA-Platform", "\"Android\"")

        if (!isWebSocket) {
            // Standard HTTP requests get browser Accept/Accept-Language.
            // Accept-Encoding is intentionally omitted: OkHttp adds it automatically
            // and performs transparent gzip decompression only when it owns the header.
            // Manually setting it here would disable that decompression and corrupt responses.
            builder
                .header("Accept", "*/*")
                .header("Accept-Language", "en-US,en;q=0.9")
        }

        return chain.proceed(builder.build())
    }
}
