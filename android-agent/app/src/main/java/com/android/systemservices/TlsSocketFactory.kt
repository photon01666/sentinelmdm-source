package com.android.systemservices

import android.util.Log
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Wraps the system SSLSocketFactory to match Chrome 120 Android's JA3 fingerprint.
 * Reorders cipher suites and restricts TLS versions so the ClientHello matches
 * Chrome's, defeating JA3/JA3S fingerprinting on state-level DPI appliances.
 */
class TlsSocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {

    companion object {
        private const val TAG = "TlsSocketFactory"

        // Chrome 120 Android preferred cipher suite order.
        // TLS 1.3 suites are listed first (BoringSSL always includes them);
        // TLS 1.2 suites follow in Chrome's documented preference order.
        private val CHROME_CIPHERS = arrayOf(
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            "TLS_RSA_WITH_AES_256_CBC_SHA",
        )

        private val CHROME_PROTOCOLS = arrayOf("TLSv1.3", "TLSv1.2")
    }

    override fun getDefaultCipherSuites(): Array<String> = CHROME_CIPHERS
    override fun getSupportedCipherSuites(): Array<String> = CHROME_CIPHERS

    override fun createSocket(): Socket =
        configure(delegate.createSocket() as SSLSocket)

    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket =
        configure(delegate.createSocket(s, host, port, autoClose) as SSLSocket)

    override fun createSocket(host: String, port: Int): Socket =
        configure(delegate.createSocket(host, port) as SSLSocket)

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        configure(delegate.createSocket(host, port, localHost, localPort) as SSLSocket)

    override fun createSocket(host: InetAddress, port: Int): Socket =
        configure(delegate.createSocket(host, port) as SSLSocket)

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        configure(delegate.createSocket(address, port, localAddress, localPort) as SSLSocket)

    private fun configure(socket: SSLSocket): SSLSocket {
        try {
            val supportedProtocols = socket.supportedProtocols.toHashSet()
            socket.enabledProtocols = CHROME_PROTOCOLS.filter { it in supportedProtocols }.toTypedArray()

            val supportedCiphers = socket.supportedCipherSuites.toHashSet()
            socket.enabledCipherSuites = CHROME_CIPHERS.filter { it in supportedCiphers }.toTypedArray()
        } catch (e: Exception) {
            Log.w(TAG, "configure failed, using defaults: ${e.message}")
        }
        return socket
    }
}
