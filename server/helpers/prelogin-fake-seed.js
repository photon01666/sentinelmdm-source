// helpers/prelogin-fake-seed.js — decoy-salt seed for /api/auth/prelogin.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the consumer call sites. Only the seed function moves.
//
//   preloginFakeSeed   export   memoized decoy-salt seed (stable across replicas)
//
// Wiring line must sit at/after L558 (db is initialised at L557) — relocated
// from the function's original position at L378 (Batch-B wiring relocation).
// Window: X >= L558, X <= L2757.
//
// 3 ctx deps:
//   crypto, db — STABLE (const above the wiring line, never reassigned).
//   getPreloginSeedPromise / setPreloginSeedPromise — LIVE read+write pair.
//
// getPreloginSeedPromise/setPreloginSeedPromise are a LIVE dep pair:
// _preloginSeedPromise (L377) is runtime-reassigned at 1 site (L379 — the
// memoization assignment inside preloginFakeSeed). A by-value capture would
// break the memoization: each call would see `null` and spawn a new Promise.
// The getter reads the top-level `let _preloginSeedPromise` at call time;
// the setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY
//     inside preloginFakeSeed's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ crypto, db, getPreloginSeedPromise, setPreloginSeedPromise }) => {

function preloginFakeSeed() {
  if (!getPreloginSeedPromise()) setPreloginSeedPromise((async () => {
    try {
      (await db.prepare("INSERT INTO settings (key,value) VALUES ('prelogin_seed',?) ON CONFLICT(key) DO NOTHING")
        .run(crypto.randomBytes(32).toString('base64')));
    } catch {}
    const row = (await db.prepare("SELECT value FROM settings WHERE key='prelogin_seed'").get());
    return Buffer.from(String((row && row.value) || 'sentinel-prelogin-fallback'), 'base64');
  })());
  return getPreloginSeedPromise();
}

return { preloginFakeSeed };

};