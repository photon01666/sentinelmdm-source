// helpers/send-auth-page.js — send an auth page with CSP nonce.
//
// A HELPER module, not a route module: it registers nothing.
//
//   sendAuthPage   export   serve an HTML auth page with a CSP nonce injected
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 deps: AUTH_PAGE_HTML (binding L547), cspWithNonce (destructure L542), crypto (binding L15).  The call must sit at or after L548; the earliest consumer of
// the export is L2677, so at or before L2676.  L551 satisfies both.
//
// relative requires: none

module.exports = ({ AUTH_PAGE_HTML, cspWithNonce, crypto }) => {
function sendAuthPage(res, file) {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Content-Security-Policy', cspWithNonce(nonce));
  res.type('html').send((AUTH_PAGE_HTML[file] || '').replaceAll('__CSP_NONCE__', nonce));
}

  return {
    sendAuthPage,
  };
};