// helpers/device-feature-flags.js — device feature flag settings (ARP sweep, sentry, screen text).
//
// A HELPER module, not a route module: it registers nothing.
//
//   getArpSweepWatchEnabled, setArpSweepWatchEnabled, getSentryEnabled, setSentryEnabled,
//   getScreenTextEnabled, setScreenTextEnabled   members
//
// RELOCATE: wiring line must sit at/after L626 and at/before L3454 — placed at L3454.
// 1 dep: db (binding L625).
//
// relative requires: none

module.exports = ({ db }) => {
// ARP sweep (velocity) detection — continuous pktmon-based watch, opt-in and independent of the
// scan above (default OFF; heavier background footprint, not live-validated against real sweep
// traffic — see the docs/ARCHITECTURE.md ARP-sweep invariant / arp-scan-network-discovery memory). GET
// returns install/running state + last-heartbeat for the toggle button; POST installs/uninstalls.
// Cheap stored flag mirroring getVpn()/setVpn()'s settings-table pattern -- lets the worker
// poller below know whether it's even worth paying for a LIVE hop2 SSH round trip to drain a
// device's sweep queue, without having to make that round trip just to find out. Kept in sync at
// two points: (1) every explicit enable/disable call sets it directly, (2) the GET status route
// opportunistically backfills it from the live `installed` result every time a human happens to
// open the device's Reverse SSH tab -- self-heals a device that was enabled before this flag
// existed, or one whose Windows-side task state drifted out of sync some other way.
async function getArpSweepWatchEnabled(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('arp_sweep_watch:' + deviceId));
  return !!row && row.value === 'enabled';
}
async function setArpSweepWatchEnabled(deviceId, enabled) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('arp_sweep_watch:' + deviceId, enabled ? 'enabled' : 'disabled'));
}

async function getSentryEnabled(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('sentry_enabled:' + deviceId));
  return !!row && row.value === 'enabled';
}
async function setSentryEnabled(deviceId, enabled) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('sentry_enabled:' + deviceId, enabled ? 'enabled' : 'disabled'));
}

// Screen Text Capture on Windows — same cheap-stored-flag idiom as getSentryEnabled/setSentryEnabled.
async function getScreenTextEnabled(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('screentext_win_enabled:' + deviceId));
  return !!row && row.value === 'enabled';
}
async function setScreenTextEnabled(deviceId, enabled) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('screentext_win_enabled:' + deviceId, enabled ? 'enabled' : 'disabled'));
}

  return {
    getArpSweepWatchEnabled,
    setArpSweepWatchEnabled,
    getSentryEnabled,
    setSentryEnabled,
    getScreenTextEnabled,
    setScreenTextEnabled,
  };
};