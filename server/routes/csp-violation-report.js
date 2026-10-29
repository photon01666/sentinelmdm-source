module.exports = ({ app, express, log, makeRateLimit }) => {
// ── CSP violation reports (report-uri target for SECURITY_CSP) ──────────────
// Pre-auth on purpose (the browser posts these WITHOUT the session cookie / before nav auth) and
// deliberately fire-and-forget. Its ONE job here is a safety net for the tightened connect-src:
// if a legitimate Maps (or other) request gets blocked in the wild, it shows up here so we can
// widen the allow-list. Noisy directives that browser extensions trip constantly (script/style/
// img) are dropped; we only log connect-src / object-src / base-uri / frame-ancestors hits. Rate-
// limited + tiny body cap so an anonymous flooder can't spam the logs. type:()=>true parses the
// application/csp-report content-type the global express.json() (application/json only) misses.
const cspReportRateLimit = makeRateLimit(30, 60 * 1000, 'csp-report');
const CSP_REPORT_DIRECTIVES = /^(connect-src|object-src|base-uri|frame-ancestors|frame-src|form-action)\b/;
app.post('/api/csp-report', cspReportRateLimit, express.json({ limit: '8kb', type: () => true }), (req, res) => {
  res.status(204).end();
  try {
    const r = req.body?.['csp-report'] || req.body?.body || req.body;
    const dir = String(r?.['effective-directive'] || r?.['violated-directive'] || '');
    if (!CSP_REPORT_DIRECTIVES.test(dir)) return;                 // skip script/style/img extension noise
    log('warn', 'CSP violation', {
      directive: dir,
      blocked: String(r?.['blocked-uri'] || '').slice(0, 200),
      documentUri: String(r?.['document-uri'] || '').slice(0, 200),
    });
  } catch (_) { /* malformed report — ignore */ }
});
};
