// services/device-settings.js — per-device feature-toggle CRUD (WiFi auto-join, unlock capture, VPN).
//
// Extracted from server.js. Each is a thin read/write of a `settings['<feature>:<deviceId>']` row
// (raw db.prepare), plus a normalize() guard and, for VPN, the agent command payload. The routes
// that call these stay inline in server.js (they use the wired svc.deviceSettings.* functions).
// XRAY_VPN_UUID stays defined in server.js too (its VPN POST route reads it); the module reads the
// same secret itself for vpnCommand's egress UUID.

const { readSecret } = require('../config');

module.exports = function createDeviceSettings({ db }) {
  const XRAY_VPN_UUID = readSecret('sentinel_xray_vpn_uuid', 'XRAY_VPN_UUID');

  // ── WiFi auto-join ──────────────────────────────────────────────────────────
  function normalizeWifiAutoJoin(b) {
    const list = (x) => (Array.isArray(x) ? x : String(x || '').split(/[\n,]+/))
      .map(s => String(s).trim()).filter(Boolean).slice(0, 50);
    // Trusted-BSSID watch: { "SSID": ["aa:bb:cc:dd:ee:ff", ...] } — sanitized (valid MACs, lowercased).
    const watch = {};
    const w = b && b.watch;
    if (w && typeof w === 'object') {
      for (const ssid of Object.keys(w).slice(0, 20)) {
        const bssids = (Array.isArray(w[ssid]) ? w[ssid] : [])
          .map(s => String(s).trim().toLowerCase())
          .filter(s => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(s)).slice(0, 16);
        if (bssids.length) watch[String(ssid).slice(0, 64)] = bssids;
      }
    }
    return { enabled: !!(b && b.enabled), rogueDefense: !!(b && b.rogueDefense), allow: list(b && b.allow), deny: list(b && b.deny), watch };
  }
  async function getWifiAutoJoin(deviceId) {
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('wifi_autojoin:' + deviceId));
    if (!row) return { enabled: false, rogueDefense: false, allow: [], deny: [], watch: {} };
    try { return normalizeWifiAutoJoin(JSON.parse(row.value)); } catch { return { enabled: false, rogueDefense: false, allow: [], deny: [], watch: {} }; }
  }
  async function setWifiAutoJoin(deviceId, cfg) {
    (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run('wifi_autojoin:' + deviceId, JSON.stringify(cfg)));
  }

  // ── Unlock-attempt capture ──────────────────────────────────────────────────
  function normalizeUnlockCapture(b) {
    return {
      camera:     !!(b && b.camera),
      screenshot: !!(b && b.screenshot),
      onSuccess:  !!(b && b.onSuccess),
    };
  }
  async function getUnlockCapture(deviceId) {
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('unlock_capture:' + deviceId));
    if (!row) return { camera: false, screenshot: false, onSuccess: false };
    try { return normalizeUnlockCapture(JSON.parse(row.value)); } catch { return { camera: false, screenshot: false, onSuccess: false }; }
  }

  // ── Auto-VPN / manual full-tunnel ───────────────────────────────────────────
  function normalizeVpn(b) {
    // enabled = auto full-tunnel on open WiFi; force = manual full-tunnel (all networks);
    // tailnetOnly = split tunnel — route ONLY the device's Tailnet Access subnets, internet stays direct.
    // v6 = full tunnel ALSO advertises IPv6 (default OFF — only safe once the egress nodes have working
    // IPv6 via NAT66; see swarm-stacks/ipv6-egress). v6-first apps (Gmail) stall if it's on prematurely.
    return { enabled: !!(b && b.enabled), force: !!(b && b.force), tailnetOnly: !!(b && b.tailnetOnly), v6: !!(b && b.v6) };
  }
  async function getVpn(deviceId) {
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('vpn:' + deviceId));
    if (!row) return { enabled: false, force: false, tailnetOnly: false, v6: false };
    try { return normalizeVpn(JSON.parse(row.value)); } catch { return { enabled: false, force: false, tailnetOnly: false, v6: false }; }
  }
  async function setVpn(deviceId, cfg) {
    (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run('vpn:' + deviceId, JSON.stringify(cfg)));
  }
  // Agent command payload — folds in the secret egress UUID (never exposed to the browser).
  function vpnCommand(cfg) {
    return { command: 'set_vpn', enabled: cfg.enabled, force: cfg.force, tailnetOnly: cfg.tailnetOnly, v6: cfg.v6, egressUuid: XRAY_VPN_UUID };
  }

  return {
    normalizeWifiAutoJoin, getWifiAutoJoin, setWifiAutoJoin,
    normalizeUnlockCapture, getUnlockCapture,
    normalizeVpn, getVpn, setVpn, vpnCommand,
  };
};
