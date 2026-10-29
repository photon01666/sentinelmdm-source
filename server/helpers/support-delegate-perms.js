// helpers/support-delegate-perms.js — live support-delegate permission resolution.
//
// A HELPER module, not a route module: it registers nothing; requireAuth calls it
// per request. Members: applySupportDelegatePerms (export).
//
// IN-PLACE splice at the block position (X = L2462). Resolution (B):
//   * spread dep SUPPORT_DELEGATE_FULL_PERMS (const L3524) is initialised BELOW
//     the block -> LIVE getter `getSupportDelegateFullPerms` (LIVE_READS pair);
//     the body spreads `...getSupportDelegateFullPerms()`.
//   * db travels as the LIVE getter `getDb: () => db` (LIVE_READS pair; the
//     canon rewrites every bare `db` read, so `getDb().prepare(...)`).
// Both getters are called only inside applySupportDelegatePerms's body (request
// time, post-boot) — never at factory scope.
//
// Stable deps by value: _supportDelegateCache (Map L2459 — mutated by reference,
// never reassigned), SUPPORT_DELEGATE_PERMS_TTL_MS (L2460) — above the wiring.
// The earliest consumer (auth-middleware wiring L2504) sits BELOW the wiring
// line, so the const-before-consumer bound is satisfied.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ SUPPORT_DELEGATE_PERMS_TTL_MS, _supportDelegateCache, getDb, getSupportDelegateFullPerms }) => {

async function applySupportDelegatePerms(req) {
  const s = req.session;
  if (s?.account_type !== 'business_sub' || !s.userId) return;
  const hit = _supportDelegateCache.get(s.userId);
  if (hit && Date.now() - hit.ts < SUPPORT_DELEGATE_PERMS_TTL_MS) {
    if (hit.isDelegate) s.permissions = hit.perms;
    if (hit.isDelegate) s.is_support_delegate = true;
    return;
  }
  const row = (await getDb().prepare('SELECT is_support_delegate, parent_owner_id FROM users WHERE id=?').get(s.userId));
  const isDelegate = !!row?.is_support_delegate;
  let perms = null;
  if (isDelegate && row.parent_owner_id) {
    // Same query the grant uses — no is_demo/lineage_kind filter, so this is exactly the map a
    // fresh revoke+re-grant would produce, just always current.
    const devs = (await getDb().prepare('SELECT id FROM devices WHERE owner_user_id=?').all(row.parent_owner_id));
    perms = {};
    for (const d of devs) perms[d.id] = { ...getSupportDelegateFullPerms() };
  }
  _supportDelegateCache.set(s.userId, { ts: Date.now(), isDelegate, perms });
  if (isDelegate && perms) s.permissions = perms;
  if (isDelegate) s.is_support_delegate = true;
  else delete s.is_support_delegate;
}

return { applySupportDelegatePerms };

};
