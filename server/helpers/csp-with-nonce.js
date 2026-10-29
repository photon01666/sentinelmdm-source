// helpers/csp-with-nonce.js — CSP header with per-request nonce.
//
// A HELPER module, not a route module: it registers nothing.
//
//   cspWithNonce   export   build a Content-Security-Policy header string with a nonce
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: CSP_NONSCRIPT (binding L516), CSP_SCRIPT_HOSTS (binding L513).  The call must sit at or after L517; the earliest consumer of
// the export is L572, so at or before L571.  L542 satisfies both.
//
// relative requires: none

module.exports = ({ CSP_NONSCRIPT, CSP_SCRIPT_HOSTS }) => {
// Per-request nonce'd CSP for our first-party HTML: the dashboard document (sendDashboard) AND the
// pre-auth login/register/unlock pages (sendAuthPage). Modern browsers (Chrome/Firefox/Safari + the
// evergreen Android-WebView client — the only two WebUI consumers) honor the CSP-L3 script directives;
// the base `script-src` stays as the fallback for any legacy WebView that ignores them:
//   • script-src (fallback) — keeps 'unsafe-inline' (legacy inline scripts + handlers still run) but
//     DROPS 'unsafe-eval' → eval()/Function() are blocked on ALL browsers here (eval is governed by
//     script-src, NOT script-src-elem). Verified: no eval/Function in any first-party page/script.
//   • script-src-elem — 'self' + per-request nonce, NO 'unsafe-inline' → an XSS-injected <script>
//     cannot execute (it can't know the nonce); legit inline blocks carry nonce="__CSP_NONCE__".
//   • script-src-attr 'unsafe-inline' — keeps the ~418 legacy inline on*= handlers working (a nonce
//     can't apply to an event-handler attribute), so no giant handler refactor is required.
function cspWithNonce(nonce) {
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline' ${CSP_SCRIPT_HOSTS}`,
    `script-src-elem 'self' 'nonce-${nonce}' ${CSP_SCRIPT_HOSTS}`,
    "script-src-attr 'unsafe-inline'",
    ...CSP_NONSCRIPT
  ].join('; ');
}

  return {
    cspWithNonce,
  };
};