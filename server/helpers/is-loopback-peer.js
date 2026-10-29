// helpers/is-loopback-peer.js — check if request peer is loopback.
//
// A HELPER module, not a route module: it registers nothing.
//
//   isLoopbackPeer   export   check if the TCP peer is localhost
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L2907, so at or before L2906.  L2775 satisfies both.
//
// relative requires: none

module.exports = () => {
// True only when the request's ACTUAL TCP peer is loopback — i.e. an in-container/internal probe
// (Docker HEALTHCHECK, route/smoke checks, local tooling). We deliberately use the socket peer, NOT
// X-Forwarded-For, so an external client can't spoof `127.0.0.1` to suppress the alert: proxied
// requests always arrive from the Traefik/cloudflared overlay peer, never loopback.
function isLoopbackPeer(req) {
  const a = req.socket?.remoteAddress || '';
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
}

  return {
    isLoopbackPeer,
  };
};