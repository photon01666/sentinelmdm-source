// helpers/cleanup-and-integrity.js — worker DB-cleanup scheduling + the daily
// Signal integrity summary.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the consumer call sites and the boot timers. Only the two functions move.
//
//   scheduleCleanup            export   one-shot guard + 5min/24h cleanup timers
//   sendDailyIntegrityReport   export   fleet integrity summary via Signal
//
// Wiring line sits IN-PLACE at the old block head (L4011) — every ctx dep is
// initialised above it (runDbCleanup L4003, scheduleTrialSweep L4007), and all
// three consumers of these exports are DEFERRED (the /api/unlock handler body,
// the tryAutoUnlock IIFE's post-await path, and a 15-minute setTimeout), so the
// hoisted-function consumer at L2457 never evaluates the binding before boot's
// synchronous pass completes.
// Window: L4011-L4069 (plan run L4011-L4069).
//
// 7 ctx deps: IS_WORKER, decryptText, log, notifyAdmin, runDbCleanup,
// scheduleTrialSweep, stmts — all STABLE (const/destructure above
// the wiring line, never reassigned). getCleanupScheduled / setCleanupScheduled
// — LIVE read+write pair.
//
// getCleanupScheduled/setCleanupScheduled are a LIVE dep pair:
// cleanupScheduled (L4010) is runtime-reassigned at 1 site (L4014 — the guard
// flip inside scheduleCleanup). A by-value capture would see `false` on every
// call and schedule the cleanup timers twice. The getter reads the top-level
// `let cleanupScheduled` at call time; the setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     scheduleCleanup's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ IS_WORKER, decryptText, getCleanupScheduled, log, notifyAdmin, runDbCleanup, scheduleTrialSweep, setCleanupScheduled, stmts }) => {

function scheduleCleanup() {
  if (getCleanupScheduled()) return;
  if (!IS_WORKER) return;  // web replicas don't run DB cleanup/VACUUM/R2-purge — the worker does
  setCleanupScheduled(true);
  scheduleTrialSweep();    // free-trial lifecycle (1-day email + 48h auto-wipe) runs on the worker too
  setTimeout(() => {
    runDbCleanup().catch(e => log('error', 'DB cleanup error', { err: e.message }));
    setInterval(
      () => runDbCleanup().catch(e => log('error', 'DB cleanup error', { err: e.message })),
      24 * 60 * 60 * 1000
    ).unref();
  }, 5 * 60 * 1000).unref();
}

// ── Daily integrity summary via Signal ────────────────────────────────────────
async function sendDailyIntegrityReport() {
  try {
    // Demo devices are synthetic sample data seeded for public-user onboarding (see the is_demo
    // invariant) — they have no real attestation/verified-boot state and would always report as
    // "Not yet checked", so exclude them from the fleet integrity summary.
    // Only Android devices have integrity/attestation data — Windows/Linux/RA devices have no
    // meaningful boot state to report, so exclude them too.
    const devices = (await stmts.allDevices.all()).filter(d => !d.is_demo && d.platform === 'android');
    if (!devices.length) return;

    const verdictIcon = { VERIFIED: '✅', PARTIAL: '🔵', UNVERIFIED: '⚠️', COMPROMISED: '🚨', UNKNOWN: '❓' };
    const lines = [];
    let issues = 0;

    for (const row of devices) {
      const name  = decryptText(row.name)  || row.id;
      const model = decryptText(row.model) || '';
      const label = model ? `${name} • ${model}` : name;
      const integrity = row.integrity ? (() => { try { return JSON.parse(row.integrity); } catch { return null; } })() : null;

      if (!integrity) {
        lines.push(`❓ ${label} — Not yet checked`);
        continue;
      }

      const v    = integrity.verdict || 'UNKNOWN';
      const icon = verdictIcon[v] || '❓';
      const sec  = integrity.security_level  ? ` · ${integrity.security_level}`  : '';
      const boot = integrity.verified_boot_state ? ` · Boot: ${integrity.verified_boot_state}` : '';
      const lock = integrity.device_locked != null ? ` · ${integrity.device_locked ? 'Locked' : 'Unlocked'}` : '';
      lines.push(`${icon} ${label} — ${v}${sec}${boot}${lock}`);
      if (v === 'COMPROMISED' || v === 'UNVERIFIED') issues++;
    }

    const date    = new Date().toISOString().slice(0, 10);
    const summary = issues > 0 ? `⚠️ ${issues} device(s) need attention.` : '✅ All devices passed.';
    const msg     = `📋 Daily Integrity Report — ${date}\n\n${lines.join('\n')}\n\n${summary}`;
    notifyAdmin(msg).catch(() => {});
    log('info', 'Daily integrity report sent', { devices: devices.length, issues });
  } catch (e) {
    log('error', 'Daily integrity report failed', { err: e.message });
  }
}

return { scheduleCleanup, sendDailyIntegrityReport };

};
