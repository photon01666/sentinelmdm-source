// helpers/nodered-alert.js - Home Assistant alert for admin-account logins.
//
// A HELPER module, not a route module: it registers nothing.
//
//   NODERED_ALERT_URL, NODERED_ALERT_KEY, notifyAdminLoginNodeRed   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: readSecret, reqClientIp.  The call must sit at or after L37; the earliest consumer of
// the export is L408, so at or before L407.  L377 satisfies both.
//
// relative requires: none

module.exports = ({ readSecret, reqClientIp }) => {
// ── Home Assistant alert (HASS text notify + TTS on Pixel 9a) for admin-account logins ──
// Fires on EVERY /admin/login (+ 2FA) attempt, success AND failure, so the operator hears
// about it even off-network/off-Signal. Fully inert unless the sentinel_nodered_alert_key
// secret is provisioned — never blocks or slows the login flow (fire-and-forget, short timeout).
// The shared key is a Docker secret, ALSO hardcoded into the Node-RED flow's function node
// (flows.json is host runtime state, not in git — see docs/ARCHITECTURE.md), mirroring
// the HONEYPOT_FEED_URL/HONEYPOT_MGMT_KEY pattern above.
const NODERED_ALERT_URL = (process.env.NODERED_ALERT_URL || 'http://node-red-signal-api_nodered-swarm:1880/admin-login-alert').trim();
const NODERED_ALERT_KEY = (readSecret('sentinel_nodered_alert_key', 'NODERED_ALERT_KEY') || '').trim();
function notifyAdminLoginNodeRed(event, username, req) {
  if (!NODERED_ALERT_KEY) return;
  const ip = reqClientIp(req) || 'unknown';
  fetch(NODERED_ALERT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Sentinel-Key': NODERED_ALERT_KEY },
    body: JSON.stringify({ event, username: username || '(unknown)', ip, time: new Date().toLocaleString() }),
    signal: AbortSignal.timeout(5000),
  }).catch(() => {});
}

  return {
    NODERED_ALERT_URL,
    NODERED_ALERT_KEY,
    notifyAdminLoginNodeRed,
  };
};