// helpers/check-trial-lineage-abuse.js — free-trial abuse lineage tracking.
//
// A HELPER module, not a route module: it registers nothing.
//
//   checkTrialLineageAbuse   export   detect and log free-trial re-trial attempts
//
// RELOCATE: wiring line must sit at/after L3143 and at/before L4678 — placed at L3143.
// 6 deps: db (binding L624), decryptText (function L162, hoisted), hwidHmac (function L3034, hoisted),
// log (destructure L399), normIdent (binding L3142), notifyAdmin (binding L658).
//
// relative requires: none

module.exports = ({ db, decryptText, hwidHmac, log, normIdent, notifyAdmin }) => {
// ── Free-trial-abuse lineage tracking ────────────────────────────────────────
// The 30-day public trial is keyed to the USER ROW, not the person, so a fresh account = a fresh
// 30 days by default. Two cheap re-trial vectors: (1) same physical device — device_id is derived
// from the hardware serial (Prefs.getOrCreateDeviceId) and survives a factory wipe, and a
// self-provisioned (BYOD) Device-Owner re-install re-mints the SAME id; (2) same email — emails are
// intentionally non-unique (see /api/register). We append-only log every trial start keyed on the
// device handle + a keyed HMAC of the email; if either already started a trial under a DIFFERENT
// account, alert the admin. Same-EMAIL reuse is already closed elsewhere (wipeUserAccount() stashes
// the original trial start in account_continuity, restored at re-registration). Same-DEVICE reuse is
// now ALSO enforced, not just alerted: the trial-start handler (io.use 'register', ~L9140) looks up
// the earliest trial_starts row for this device_id and reuses THAT as trial_started_at instead of
// Date.now() — so re-flashing + signing into a brand-new email no longer resets the clock, it just
// continues (or immediately re-locks, if the original window already lapsed). We never hard-deny the
// connection itself (a legit parent re-flashing their own phone still gets in — they just don't get
// extra trial days). hwId (v2) is the agent-reported wipe-stable ESID/serial for devices where the
// serial-derived device_id degrades to a fresh random UUID — it stays ALERT-ONLY here (self-reported,
// so not safe to enforce access control on).
async function checkTrialLineageAbuse(userId, deviceId, hwId) {
  try {
    const urow = (await db.prepare('SELECT email FROM users WHERE id=?').get(userId));
    const email = urow ? normIdent(decryptText(urow.email)) : '';
    const emailHmac  = email ? hwidHmac(email) : null;
    const dev        = deviceId || null;
    const serialHmac = (hwId && hwId.trim()) ? hwidHmac(hwId.trim()) : null;

    const priors = (await db.prepare(
      `SELECT user_id, device_id, email_hmac, serial_hmac FROM trial_starts
       WHERE user_id <> ? AND ((device_id  IS NOT NULL AND device_id  = ?)
                            OR (email_hmac  IS NOT NULL AND email_hmac  = ?)
                            OR (serial_hmac IS NOT NULL AND serial_hmac = ?))`
    ).all(userId, dev, emailHmac, serialHmac));

    // Record THIS trial start regardless of outcome (append-only).
    (await db.prepare(
      'INSERT INTO trial_starts (user_id, device_id, email_hmac, serial_hmac, created_at) VALUES (?,?,?,?,?)'
    ).run(userId, dev, emailHmac, serialHmac, Date.now()));

    if (!priors.length) return;
    const byDevice   = priors.filter(p => p.device_id   && p.device_id   === dev).length;
    const byEmail    = priors.filter(p => p.email_hmac  && p.email_hmac  === emailHmac).length;
    const byHardware = priors.filter(p => p.serial_hmac && p.serial_hmac === serialHmac).length;
    const otherAccts = [...new Set(priors.map(p => p.user_id))];
    const sig = [ byDevice ? 'same device (enforced — inherited original start)' : null,
                  byHardware ? 'same hwId (self-reported, alert-only)' : null,
                  byEmail ? 'same email' : null ]
                  .filter(Boolean).join(' + ');
    await notifyAdmin(
      `🚨 Free-trial re-trial attempt\n` +
      `Account #${userId} (${email || 'no email'}) just connected a device for the trial.\n` +
      `Match: ${sig}. This device/email already trialed under ${otherAccts.length} other account(s): #${otherAccts.join(', #')}.\n` +
      `Device: ${dev || 'unknown'}`
    );
    log('warn', 'Trial lineage abuse suspected', { userId, deviceId: dev, priorAccounts: otherAccts, byDevice, byEmail, byHardware });
  } catch (e) { log('warn', 'checkTrialLineageAbuse error', { userId, deviceId, error: e.message }); }
}

  return {
    checkTrialLineageAbuse,
  };
};