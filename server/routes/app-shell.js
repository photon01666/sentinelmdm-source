module.exports = ({ app, crypto, cspWithNonce, indexHtml, kv, path, randomUUID }) => {
// Dashboard HTML responses carry a per-request CSP nonce (see cspWithNonce): the nonce is stamped
// into the 3 inline <script> blocks of index.html AND into this response's script-src-elem, so an
// XSS-injected <script> (which cannot know the nonce) will not execute. The service worker serves
// HTML network-first and caches response headers WITH the body, so the nonce never goes stale
// (online = always fresh; offline = header+body cached as a matched pair).
function sendDashboard(res) {
  const token = randomUUID();
  const nonce = crypto.randomBytes(16).toString('base64');
  kv.setJSON('socktok:' + token, 1, 24 * 60 * 60).catch(() => {});  // 24h, shared across replicas
  res.setHeader('Content-Security-Policy', cspWithNonce(nonce));
  // Never HTTP-cache the HTML — the WebView's HTTP cache was holding stale pages that loaded
  // old app.js URLs, preventing SW updates from reaching the client.
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(
    indexHtml.replace('__SOCKET_TOKEN_VALUE__', token).replaceAll('__CSP_NONCE__', nonce)
  );
}
app.get('/', (_req, res) => { sendDashboard(res); });

// Chat-only entry point — serves the same dashboard HTML; app.js sees the /chat
// pathname and enters chat-only mode (hides chrome, opens only the support chat).
// Used by the standalone "Sentinel Chat" Android app. Behind the global auth wall
// like '/', so an unauthenticated load redirects to /login.
app.get('/chat', (_req, res) => { sendDashboard(res); });

app.get('/admin', (req, res) => {
  if (req.session?.role !== 'admin') return res.redirect('/');
  sendDashboard(res);
});

app.get('/admin/subusers', (req, res) => {
  if (req.session?.role === 'admin') return res.redirect('/admin');
  if (req.session?.account_type === 'public') return res.redirect('/');
  sendDashboard(res);
});

// Serve sw.js with Cache-Control: no-cache so the browser/WebView always revalidates it
// on navigation — without this, the HTTP cache holds the old sw.js and the browser never
// detects the updated service worker (root cause of "nothing changed after deploy").
// NOTE: the authoritative sw.js route is the pre-auth one registered earlier (before
// requireAuth). This duplicate is harmless (Express matches the first route), but kept
// as a fallback reference.
app.get('/sw.js', (_req, res) => {
  res.removeHeader('Content-Security-Policy');
  res.removeHeader('Reporting-Endpoints');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(path.join(__dirname, '..', 'public', 'sw.js'));
});
};
