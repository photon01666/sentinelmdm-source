// routes/preauth-public.js — Public (pre-auth) browser/agent endpoints: mobile WebView
// session hand-off, marketing-site analytics beacons (/api/pv + /api/pt + /api/analytics/bot),
// the PWA service worker (/sw.js) and the WebAuthn client script. Extracted VERBATIM from
// server.js L3749-L3903.
//
// The APK-download routes directly above (L3695-L3747) were NOT moved: their helper/key
// bindings (PUBLIC_APK_R2_KEY, CLIENT_APK_R2_KEY, get/savePublicApkMeta, get/saveClientApkMeta)
// are also read by the admin APK-upload routes at server.js L12974+ outside this band, so a
// range-delete would remove live bindings. They stay in server.js.
//
// deriveReferrerBucket (L3782) is private to this module -- used only by the /api/pv handler.
// All ctx names below are module-scope bindings defined earlier in server.js.
// NOTE: `path` is shadowed by `const path = req.body?.path` inside the /api/pv handler; the
// module-level `path` is still required by the /sw.js and /webauthn-client.js handlers.

module.exports = ({ app, analyticsRateLimit, botLogRateLimit, cors, crypto, db, express, getDailySalt, kv, parseUA, path, reqClientIp, resolveGeoAndBackfill, getServerGeneration, regenSession }) => {
// ── Mobile WebView session hand-off ─────────────────────────────────────────
// /mobile-login?token=HEX — public route (before requireAuth wall).
// The agent app logs in via OkHttp, then calls /api/mobile-auth-token (authenticated)
// to get a one-time token. It opens this URL in WebDashboardActivity. The token is
// consumed here to create a proper browser session so the WebView lands on the
// dashboard without a second login prompt.
// SECURITY (MEDIUM-2, 2026-10-13): this is a state-changing endpoint served over GET and reached
// by top-level navigation, so it is reachable cross-site. The token is single-use + 2-min TTL, but
// an attacker who lures a victim into loading a crafted URL could still drive a login-CSRF. Two
// defenses: (1) rotate the session ID here (session-fixation), and (2) when the browser sends an
// Origin/Referer, require it to be same-origin before consuming the token. A bare navigation from
// the app's own WebView sends no Origin/Referer and is unaffected.
app.get('/mobile-login', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.redirect('/login');
  const origin = req.headers.origin || req.headers.referer;
  if (origin) {
    let host = null;
    try { host = new URL(origin).host; } catch { host = null; }
    if (!host || host !== req.headers.host) return res.redirect('/login');
  }
  const data = await kv.getdelJSON('mobauth:' + token);  // atomic one-time consume
  if (!data) return res.redirect('/login');
  regenSession(req, {
    authenticated:    data.authenticated,
    serverGeneration: getServerGeneration(),
    username:         data.username,
    role:             data.role,
    userId:           data.userId,
    account_type:     data.account_type,
    permissions:      data.permissions,
    enabled_features: data.enabled_features,
    is_support_delegate: !!data.is_support_delegate,
  }, () => res.redirect('/'));
});

// ── Web Analytics ingest — PUBLIC, marketing-site only ──
// Registered BEFORE app.use(requireAuth) on purpose: the marketing site is anonymous
// and cross-origin (its include.js beacon posts to the configured device endpoint, the same
// backend). The admin/parent dashboard no longer reports its own page views, so this
// panel reflects public marketing traffic exclusively. `type: () => true` accepts the
// CORS-safelisted `text/plain` beacon bodies the site sends (keeps it preflight-free).
// Real traffic-source bucket for the (repurposed) `referrer` column. Only ever called for the
// FIRST pageview of a browsing session (client sends `landing:true` on that request only) — so
// `referrer IS NULL` on a row unambiguously means "mid-session, not an entry point" (excluded
// from source aggregates), while 'direct' means "entry point, no referrer" (typed URL/bookmark).
function deriveReferrerBucket(raw) {
  if (!raw || typeof raw !== 'string') return 'direct';
  try { const h = new URL(raw).hostname.replace(/^www\./, ''); return h || 'direct'; }
  catch { return 'direct'; }
}

// Route note: the canonical path is the blocker-neutral /api/pv — EasyPrivacy ships a bare
// generic filter `/analytics/pageview` that silently kills the old URL in uBlock/Brave/AdGuard
// (diagnosed 2026-07-06: browser beacons never left the client while curl worked). The old
// /api/analytics/* paths stay as aliases for CF-edge-cached copies of the old beacon script
// (≤7-day window). Do NOT put "analytics"/"track"/"collect"/"pageview" in future beacon paths.
app.post(['/api/pv', '/api/analytics/pageview'], analyticsRateLimit, express.json({ limit: '1kb', type: () => true }), async (req, res) => {
  cors(res);
  const path = req.body?.path;
  // Hoisted to function scope (not just the `if` block) so the post-response geo backfill
  // below can reuse them regardless of whether the insert branch ran.
  let ip = null, session_hash = null;
  if (path && typeof path === 'string' && path.length <= 200) {
    const cleanPath = '/' + path.replace(/^\/+/, '').replace(/[^a-zA-Z0-9/_-]/g, '');
    const { browser, os, device_type } = parseUA(req.headers['user-agent']);
    ip = reqClientIp(req);
    session_hash = crypto.createHash('sha256')
      .update((ip || '') + getDailySalt()).digest('hex').slice(0, 16);
    // Only the beacon's FIRST pageview of a browsing session carries these — see analytics.js.
    let referrer = null, utm_source = null, utm_medium = null, utm_campaign = null;
    if (req.body?.landing === true) {
      referrer = deriveReferrerBucket(req.body.referrer);
      const cap = v => (typeof v === 'string' ? v.slice(0, 100) : null);
      utm_source = cap(req.body.utm_source);
      utm_medium = cap(req.body.utm_medium);
      utm_campaign = cap(req.body.utm_campaign);
    }
    try {
      (await db.prepare(`INSERT INTO web_analytics
        (timestamp, session_hash, path, referrer, os, browser, device_type, utm_source, utm_medium, utm_campaign)
        VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
        Date.now(), session_hash, cleanPath, referrer,
        os, browser, device_type, utm_source, utm_medium, utm_campaign
      ));
    } catch {}
  }
  res.status(204).end();
  // Fire strictly after the response so a slow/down 3rd-party geo lookup never adds latency
  // to the beacon or couples its reliability to ip-api.com's uptime.
  resolveGeoAndBackfill(ip, session_hash).catch(() => {});
});

// Duration beacon — updates the most recent unfinished page view for this session.
// /api/pt is canonical (blocker-neutral); /api/analytics/duration is the legacy alias.
app.post(['/api/pt', '/api/analytics/duration'], analyticsRateLimit, express.json({ limit: '1kb', type: () => true }), async (req, res) => {
  cors(res);
  const { duration } = req.body || {};
  if (typeof duration === 'number' && duration >= 0 && duration <= 86400) {
    const ip = reqClientIp(req);
    const session_hash = crypto.createHash('sha256')
      .update((ip || '') + getDailySalt()).digest('hex').slice(0, 16);
    try {
      (await db.prepare(`UPDATE web_analytics SET duration_seconds=?
        WHERE id = (SELECT id FROM web_analytics
                    WHERE session_hash=? AND timestamp > ? AND duration_seconds=0
                    ORDER BY timestamp DESC LIMIT 1)`)
        .run(Math.floor(duration), session_hash, Date.now() - 3_600_000));
    } catch {}
  }
  res.status(204).end();
});

// Bot-traffic ingest (public) — fed by the marketing site's nginx 404-mirror.
// Every scanner hit to a non-existent path on the public site fires a
// fire-and-forget POST here carrying the original IP/host/path/UA in X-Bot-* headers.
// The marketing site and this API run in different containers, so URL-scanning bots
// (which never run the JS pageview beacon) are only ever visible through this path.
app.post('/api/analytics/bot', botLogRateLimit, async (req, res) => {
  cors(res);
  try {
    const h = req.headers;
    const ip     = (h['x-bot-ip']     || reqClientIp(req) || '').toString().slice(0, 64);
    const host   = (h['x-bot-host']   || '').toString().slice(0, 120);
    const ua     = (h['x-bot-ua']     || '').toString().slice(0, 400);
    const method = (h['x-bot-method'] || '').toString().slice(0, 10).replace(/[^A-Za-z]/g, '');
    const path   = (h['x-bot-path']   || '').toString().slice(0, 300);
    if (path) {
      (await db.prepare(`INSERT INTO bot_traffic (timestamp, ip, host, path, ua, method)
        VALUES (?,?,?,?,?,?)`).run(Date.now(), ip, host, path, ua, method));
    }
  } catch {}
  res.status(204).end();
});

// ── Service worker — MUST be served BEFORE requireAuth ───────────────────────
// NOTE: `__dirname` here is server/routes/, so the public dir is one level up --
// path.join(__dirname, 'public', ...) would resolve to the nonexistent
// routes/public/. Same convention as routes/passkeys.js. This is the only edit
// to this block beyond a verbatim copy.
// The browser's service-worker update fetch of /sw.js does NOT reliably carry the
// session cookie. Behind requireAuth this 302-redirects to /login, and the SW spec
// treats a redirected script response as a hard update FAILURE — so an already-
// installed worker can NEVER update. It stays frozen, serving stale cached
// app.js/index.html forever (no cache-clear or ?v= bump dislodges it). sw.js is a
// public PWA mechanism with nothing sensitive in it. Same pre-auth rationale as
// /api/update/apk and /api/install-apk above.
app.get('/sw.js', (_req, res) => {
  // Strip CSP: Firefox enforces the Content-Security-Policy header that comes on the SW
  // *script response* itself (Chrome ignores it). The global middleware above sets a
  // page-level CSP on every response — it's designed for HTML documents, not service-worker
  // scripts. Leaving it causes Firefox to reject the SW during installation (TypeError).
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('Reporting-Endpoints');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('Surrogate-Control', 'no-store');
  res.set('Service-Worker-Allowed', '/');
  res.type('application/javascript');
  res.sendFile(path.join(__dirname, '..', 'public', 'sw.js'));
});

// Pre-auth (before app.use(requireAuth)): the login page loads /webauthn-client.js to render
// the "Sign in with a passkey" button, but the visitor has no session yet — behind requireAuth
// it would 302 to /login and the script would fail to load (button never appears). It's
// non-sensitive client-side WebAuthn ceremony code (no secrets), so serve it openly, like /sw.js.
app.get('/webauthn-client.js', (_req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.type('application/javascript');
  res.sendFile(path.join(__dirname, '..', 'public', 'webauthn-client.js'));
});
};
