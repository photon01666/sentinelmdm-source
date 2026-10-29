// helpers/learn-mode-core.js — Learn-Mode observation windows + the alert gate.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// arp-scan wiring (learnGate — eager, L2991) and the edr wirings
// (learnNormalizeDetail / learnGate) — all at/after the wiring line.
//
//   learnNormalizeDetail   private  volatile-token normalizer for signatures
//   learnWindowOpen        private  open/query an observation window
//   learnInvalidate        private  drop a device's window cache entry
//   learnGate              export   true = caller MUST suppress its page
//
// Wiring RELOCATED above its earliest eager consumer (arp-scan wiring, L2991)
// via D1b R2 (dep-first: helpers/learn-mode-guards.js) + R1. Deps:
//   * LEARN_LEARNABLE_CATEGORIES / LEARN_WINDOW_CACHE_MS / _learnWindowCache —
//     stable consts from helpers/learn-mode-guards.js, wired above this line.
//   * learnIsCritical — from the learn-is-critical wiring, RELOCATED above this
//     line (its own dep LEARN_CRITICAL now comes from the guards helper).
//   * db travels as the LIVE getter `getDb: () => db` (reads rewritten to
//     `getDb().prepare`); log (L249) by value.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ LEARN_LEARNABLE_CATEGORIES, LEARN_WINDOW_CACHE_MS, _learnWindowCache, getDb, learnIsCritical, log }) => {

// Collapses the per-occurrence noise out of a finding's detail so the SAME recurring finding maps
// to ONE reviewable signature instead of one per firing (a Sentry cred_manager detail ends in a
// wall-clock timestamp; EDR images can carry PIDs/GUIDs). Deliberately surgical — only clearly
// volatile tokens (dates, times, GUIDs, 4+-digit runs) are masked. An earlier draft replaced EVERY
// digit run, which also merged genuinely distinct neighbours like `a1.exe` and `a2.exe`; that would
// let an accepted baseline entry silently cover a lookalike path an attacker chose.
function learnNormalizeDetail(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?/g, '<guid>')
    .replace(/\b\d{1,2}[:/-]\d{1,2}[:/-]\d{2,4}\b/g, '<date>')
    .replace(/\b\d{1,2}:\d{2}(:\d{2})?\b/g, '<time>')
    .replace(/\b\d{4,}\b/g, '<n>')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

async function learnWindowOpen(deviceId) {
  const hit = _learnWindowCache.get(deviceId);
  if (hit && Date.now() - hit.ts < LEARN_WINDOW_CACHE_MS) return hit.open;
  let open = false;
  try {
    const row = (await getDb().prepare(
      'SELECT expires_at FROM learn_mode WHERE device_id=? AND ended_at IS NULL').get(deviceId));
    open = !!row && Number(row.expires_at) > Date.now();
  } catch (e) { log('warn', 'learn window lookup failed', { deviceId, error: e.message }); }
  _learnWindowCache.set(deviceId, { ts: Date.now(), open });
  return open;
}
function learnInvalidate(deviceId) { _learnWindowCache.delete(deviceId); }

/**
 * @returns {Promise<boolean>} true when the caller MUST suppress its page.
 * Never throws — a Learn Mode failure must degrade to "alert normally", never to silence.
 */
async function learnGate(deviceId, category, rule, signature, detail) {
  try {
    if (!deviceId || !LEARN_LEARNABLE_CATEGORIES.has(category)) return false;
    if (learnIsCritical(category, rule)) return false;
    const sig = String(signature || rule || '').slice(0, 300);
    if (!sig) return false;
    const now = Date.now();
    const existing = (await getDb().prepare(
      'SELECT decision FROM learn_observations WHERE device_id=? AND category=? AND signature=?')
      .get(deviceId, category, sig));
    // Accepted baseline — suppress permanently, but keep counting so the review UI can show that
    // a suppressed signature is still actively occurring (and how often).
    if (existing?.decision === 'accepted') {
      (await getDb().prepare('UPDATE learn_observations SET hits=hits+1, last_seen=? WHERE device_id=? AND category=? AND signature=?')
        .run(now, deviceId, category, sig));
      return true;
    }
    // Explicitly rejected at review — the owner asked to keep being told. Alert, don't re-record.
    if (existing?.decision === 'rejected') return false;
    if (!(await learnWindowOpen(deviceId))) return false;
    (await getDb().prepare(`INSERT INTO learn_observations
        (device_id,category,signature,detail,hits,first_seen,last_seen)
      VALUES (?,?,?,?,1,?,?)
      ON CONFLICT(device_id,category,signature)
      DO UPDATE SET hits=learn_observations.hits+1, last_seen=excluded.last_seen`)
      .run(deviceId, category, sig, String(detail || '').slice(0, 400), now, now));
    return true;
  } catch (e) {
    log('warn', 'learnGate failed — alerting normally', { deviceId, category, error: e.message });
    return false;
  }
}

return { learnGate, learnInvalidate, learnNormalizeDetail };

};
