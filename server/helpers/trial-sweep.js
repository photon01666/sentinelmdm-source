// helpers/trial-sweep.js - the free-trial lifecycle sweep for public accounts.
//
// A HELPER module, not a route module: it registers nothing. server.js owns the scheduling —
// `scheduleTrialSweep()` and `trialSweepScheduled` below stay put; only the work moves.
//
//   sendTrialEndingEmail   PRIVATE   deadline-approaching / deadline-passed mail
//   runTrialSweep          export    one hourly pass: who is near expiry, who must be wiped
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 of the 12 deps are `function` declarations and hoist (decryptText, log,
// userHasActiveSubscription, plus the ones declared as functions elsewhere). The lowest
// non-hoisted binding is `wipeUserAccount`, destructured from the
// require('./helpers/public-user-wipe') line at L5099 — so the call must sit at or after
// L5100. The earliest consumer of the export is L5952, so at or before L5951. L5879
// satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ DAY_MS, TRACKER_LOGIN_URL, TRIAL_DAYS_ACCOUNT, TRIAL_LEN_MS, TRIAL_WIPE_GRACE_MS, db, decryptText, log, notifyAdminForUser, publicAccountAlertPolicy, sendEmail, userHasActiveSubscription, wipeUserAccount }) => {
// ── Free-trial lifecycle sweep (worker only) ──────────────────────────────────
// Hourly, for public accounts whose 30-day trial has started and who have NOT subscribed:
//   • 1 day before expiry → email the "trial ending + 48h wipe" warning (once)
//   • 48h after expiry     → auto-wipe the account (delete user + data, release device)
// Subscribing at any point exempts the account (userHasActiveSubscription) — no lock, no wipe.
async function sendTrialEndingEmail(userRow, deadline) {
  const email = decryptText(userRow.email) || '';
  if (!email) return false;
  const endStr  = new Date(deadline).toUTCString();
  const wipeStr = new Date(deadline + TRIAL_WIPE_GRACE_MS).toUTCString();
  const html = `
  <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:520px;margin:0 auto;background:#0d1117;color:#e6edf3;border-radius:12px;overflow:hidden;border:1px solid #30363d">
    <div style="background:#161b22;padding:16px 20px;border-bottom:1px solid #30363d">
      <span style="font-weight:700;font-size:16px;color:#fff">SentinelMDM</span>
    </div>
    <div style="padding:20px">
      <div style="font-size:17px;font-weight:600;margin-bottom:10px">Your free trial ends tomorrow</div>
      <p style="font-size:14px;line-height:1.6;color:#c9d1d9;margin:0 0 14px">
        Your ${TRIAL_DAYS_ACCOUNT}-day SentinelMDM free trial ends on <strong>${endStr}</strong>.
        Subscribe before then to keep protecting your family without interruption.
      </p>
      <div style="background:#3d1418;border:1px solid #f85149;border-radius:8px;padding:12px 14px;font-size:14px;line-height:1.6;color:#ffdcd9">
        ⚠️ <strong>Important:</strong> if you don't subscribe, your account and all its data will be
        <strong>permanently deleted 48 hours after the trial ends</strong> (on ${wipeStr}). This can't be undone.
      </div>
      <a href="${TRACKER_LOGIN_URL}" style="display:inline-block;margin-top:16px;background:#1f6feb;color:#fff;text-decoration:none;font-weight:600;font-size:14px;padding:11px 20px;border-radius:8px">Sign in &amp; subscribe &rarr;</a>
    </div>
    <div style="background:#161b22;padding:12px 20px;border-top:1px solid #30363d;font-size:11px;color:#6e7681">
      You're receiving this because you started a SentinelMDM free trial. Subscribe from your dashboard to keep your account.
    </div>
  </div>`;
  return sendEmail(email, 'Your SentinelMDM free trial ends tomorrow — subscribe to keep your account', html);
}
async function runTrialSweep() {
  const now = Date.now();
  const users = (await db.prepare(
    "SELECT id, username, email, trial_enabled, trial_started_at, trial_1d_alerted_at FROM users " +
    "WHERE account_type='public' AND trial_enabled=1 AND trial_started_at IS NOT NULL"
  ).all());
  for (const u of users) {
    try {
      const deadline = u.trial_started_at + TRIAL_LEN_MS;
      const ms = deadline - now;
      if ((await userHasActiveSubscription(u))) continue;            // subscribed/converted → exempt
      // Wipe only if the user was WARNED first (1-day email sent → trial_1d_alerted_at set). This
      // guarantees no account is ever deleted without notice, AND grandfathers any pre-existing
      // already-expired trial (created before this policy): its alert flag is null and it's past the
      // email window, so it can never be flagged → never auto-wiped (it can still subscribe to unlock).
      if (now >= deadline + TRIAL_WIPE_GRACE_MS && u.trial_1d_alerted_at) {   // 48h past expiry, warned → wipe
        // Precompute the alert policy BEFORE the wipe — the users row is deleted below, and a
        // fresh lookup would resolve to null (→ un-suppressed). A lapsed free trial is never
        // hybrid, so this alert is suppressed for public accounts per the alert policy.
        const wipeAlertPolicy = (await publicAccountAlertPolicy(u.id));
        const r = (await wipeUserAccount(u.id));
        if (r.ok) {
          log('warn', 'Trial account auto-wiped (48h post-expiry, no subscription)', { userId: u.id, username: u.username, devicesReleased: r.devicesReleased });
          notifyAdminForUser(`🧹 Trial Account Auto-Wiped\nAccount "${u.username}" (#${u.id}) deleted 48h after free-trial expiry with no subscription. ${r.devicesReleased} device(s) released.`,
            u.id, wipeAlertPolicy).catch(() => {});
        }
        continue;
      }
      if (ms > 0 && ms <= DAY_MS && !u.trial_1d_alerted_at) {        // ≤1 day left → warn once
        const sent = (await sendTrialEndingEmail(u, deadline));
        if (sent) (await db.prepare('UPDATE users SET trial_1d_alerted_at=? WHERE id=?').run(now, u.id));
      }
    } catch (e) { log('warn', 'trial sweep: user error', { userId: u.id, err: e.message }); }
  }
}
  return {
    runTrialSweep,
  };
};
