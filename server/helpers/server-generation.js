// helpers/server-generation.js — load (or first-boot initialise) the persisted
// server generation.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the consumers. Only the loader function moves.
//
//   _loadOrInitServerGeneration   export   load/initialise the persisted generation
//
// ctx is available at this module's own position in server.js — the require line
// sits after L557 (db is initialised at L557) and before the earliest consumer
// (L933). Batch-B wiring relocation: the function was at L946-L968; the require
// line is placed earlier (next to the other helper requires) so the consumers
// (bootstrapDb at L933, the SQLite bootstrap at L977) can destructure it.
//
// 4 ctx deps: db, log — STABLE (const/destructure above the wiring line, never
// reassigned). getServerGeneration / setServerGeneration — LIVE read+write pair.
//
// getServerGeneration/setServerGeneration are a LIVE dep pair:
// serverGeneration (L115) is runtime-reassigned at 2 sites (this block's own
// write at L958, and the rotate-session-generation handler at L2734). A
// by-value capture would stamp sessions with a stale generation after a
// rotation. The getter reads the top-level `let serverGeneration` at call time;
// the setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     _loadOrInitServerGeneration's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ db, getServerGeneration, log, setServerGeneration }) => {

// ── Load (or first-boot initialise) the persisted server generation. ────────
// Routine restarts reuse the value already in the DB → sessions survive.
// On a fresh DB the initial `Date.now()` is stored. Call admin API or bump
// the DB value directly to force a global logout.
//
// Multi-replica safe: a concurrent first boot can race to persist (both replicas
// would otherwise hold different values and bounce each other's sessions). The
// INSERT uses DO NOTHING so the FIRST writer wins, then everyone reads back the
// same authoritative row.
async function _loadOrInitServerGeneration() {
  try {
    // 1) Ensure a row exists — first-writer-wins on a concurrent fresh boot.
    await db.prepare("INSERT INTO settings (key,value) VALUES ('server_generation',?) ON CONFLICT(key) DO NOTHING").run(String(getServerGeneration()));
    // 2) Read back the authoritative value (either ours, or a replica's).
    const row = await db.prepare("SELECT value FROM settings WHERE key='server_generation'").get();
    if (row && row.value !== null && row.value !== undefined) {
      const parsed = parseInt(String(row.value), 10);
      if (Number.isFinite(parsed)) {
        if (parsed !== getServerGeneration()) {
          log('info', 'Restored persisted server_generation (sessions survive restart)', { generation: parsed });
        }
        setServerGeneration(parsed);
      } else {
        log('warn', 'server_generation value not numeric — using fresh generation', { value: row.value });
      }
    } else {
      log('warn', 'server_generation insert/select race left no row — using fresh generation');
    }
  } catch (e) {
    log('warn', 'server_generation load failed — sessions will reset this boot', { err: e.message });
  }
}

return { _loadOrInitServerGeneration };

};