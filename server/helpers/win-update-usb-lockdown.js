// helpers/win-update-usb-lockdown.js — Windows Update force and USB lockdown flags.
//
// A HELPER module, not a route module: it registers nothing.
//
//   getWinUpdateForceActive, setWinUpdateForceActive, getUsbLockdownEnabled, setUsbLockdownEnabled   members
//
// RELOCATE: wiring line must sit at/after L626 and at/before L3455 — placed at L3454.
// 1 dep: db (binding L625).
//
// relative requires: none

module.exports = ({ db }) => {
// Force Windows Update Now — same cheap-stored-flag idiom as getSentryEnabled/setSentryEnabled,
// lets the 60s poller below skip a device without a bastion round trip unless a catch-up cycle
// is actually running.
async function getWinUpdateForceActive(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('winupdate_force_active:' + deviceId));
  return !!row && row.value === 'enabled';
}
async function setWinUpdateForceActive(deviceId, active) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('winupdate_force_active:' + deviceId, active ? 'enabled' : 'disabled'));
}

// USB Lockdown — cheap stored flag so the 30s poller can skip a device without a bastion
// round trip unless USB lockdown is actually enabled on that device.
async function getUsbLockdownEnabled(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('usb_lockdown_enabled:' + deviceId));
  return !!row && row.value === 'enabled';
}
async function setUsbLockdownEnabled(deviceId, enabled) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('usb_lockdown_enabled:' + deviceId, enabled ? 'enabled' : 'disabled'));
}

  return {
    getWinUpdateForceActive,
    setWinUpdateForceActive,
    getUsbLockdownEnabled,
    setUsbLockdownEnabled,
  };
};