// @ts-check
// server/db.js
// ─────────────────────────────────────────────────────────────────────────────
// Postgres data layer with a better-sqlite3-compatible surface (Phase 2).
//
// Goal: keep the existing call SHAPE — `stmts.X.get/all/run(...)` and
// `db.prepare(sql).get/all/run(...)` — so the SQLite→Postgres migration is mostly a
// mechanical codemod that adds `await` at call sites, not a full hand-rewrite of the
// ~502 prepared statements. pg-promise backs it.
//
// Placeholder translation (once, at prepare() time):
//   '?'  positional  ->  '$1, $2, ...'   (call with positional args: .get(a, b))
//   '@x' named       ->  '${x}'          (call with ONE object arg: .get({ x: v }))   [better-sqlite3 style]
//
// Result mapping:
//   .get(...)  -> oneOrNone  (row | null)
//   .all(...)  -> any        (row[])
//   .run(...)  -> { changes } (rowCount)   ← lastInsertRowid is NOT provided; the ~12
//                 INSERT-then-read sites are hand-converted to `... RETURNING id` + .get().
//
//   db.exec(sql)        -> async; DDL / multi-statement
//   db.transaction(fn)  -> returns an async fn; runs fn() inside a pg-promise tx. Thanks to
//                          AsyncLocalStorage, statements executed INSIDE fn automatically use
//                          the transaction connection, so existing stmts.* calls stay atomic.
//   db.pragma(...)      -> throws; the 3 PRAGMA table_info sites are hand-converted to
//                          information_schema.columns.
//
// When DATABASE_URL is unset, `enabled` is false and `pg` is null (the server still runs on
// better-sqlite3 until the cutover wires this module in).
// ─────────────────────────────────────────────────────────────────────────────

const { AsyncLocalStorage } = require('async_hooks');
const pgPromise = require('pg-promise');

const pgp = pgPromise({ capSQL: true });

// node-postgres returns BIGINT (int8, OID 20) as a STRING to avoid precision loss.
// better-sqlite3 returned INTEGER as a JS number, and all our BIGINT columns hold
// epoch-millis / counters well under Number.MAX_SAFE_INTEGER (9e15), so parse int8
// back to a number. Without this, timestamps arrive as strings → `new Date(ts)` and
// `===`/sort comparisons break in both server logic and the browser.
pgp.pg.types.setTypeParser(20, v => (v === null ? null : parseInt(v, 10)));

const DATABASE_URL = process.env.DATABASE_URL || '';
const enabled = !!DATABASE_URL;
// keepAlive lets the OS surface a half-dead TCP connection instead of it lingering as a silent
// black hole; connectionTimeoutMillis bounds how long acquiring a pooled connection may block
// (vs hanging indefinitely during a Patroni failover / node blip). Pairs with the per-attempt
// timeout in tryAutoUnlock() — see docs/ARCHITECTURE.md.
const pg = enabled
  ? pgp({ connectionString: DATABASE_URL, keepAlive: true, connectionTimeoutMillis: 15000 })
  : null;

/**
 * The pg-promise query surface this layer relies on — shared structurally by the root
 * database object and by transaction tasks (so an als store value satisfies it too).
 * @typedef {{
 *   oneOrNone: (text: string, values?: any) => Promise<any>,
 *   any:       (text: string, values?: any) => Promise<any[]>,
 *   none:      (text: string, values?: any) => Promise<any>,
 *   result:    (text: string, values: any, cb: (r: { rowCount: number }) => any) => Promise<any>,
 * }} PgConn
 */

// Carries the active transaction connection so stmts inside db.transaction(fn) use it.
/** @type {import('async_hooks').AsyncLocalStorage<PgConn>} */
const als = new AsyncLocalStorage();
const conn = () => /** @type {PgConn} */ (als.getStore() || pg);

// better-sqlite3 '?' / '@name' placeholders -> pg-promise '$1' / '${name}'.
/** @param {string} sql */
function translate(sql) {
  if (/@\w/.test(sql)) return { text: sql.replace(/@(\w+)/g, '$${$1}'), named: true };
  if (sql.indexOf('?') !== -1) {
    let i = 0;
    return { text: sql.replace(/\?/g, () => '$' + (++i)), named: false };
  }
  return { text: sql, named: false };
}

// args -> pg-promise values: named statements take ONE object; positional take the arg list.
/** @type {(args: any[], named: boolean) => any} */
const valuesOf = (args, named) => (named ? (args[0] || {}) : args);

/**
 * @param {string} sql
 * @returns {{
 *   text: string,
 *   get: (...a: any[]) => Promise<any>,
 *   all: (...a: any[]) => Promise<any[]>,
 *   run: (...a: any[]) => Promise<{ changes: number }>,
 * }}
 */
function prepare(sql) {
  const { text, named } = translate(sql);
  return {
    text,
    get: async (...a) => conn().oneOrNone(text, valuesOf(a, named)),
    all: async (...a) => conn().any(text, valuesOf(a, named)),
    run: async (...a) => ({ changes: await conn().result(text, valuesOf(a, named), r => r.rowCount) }),
  };
}

const db = {
  prepare,
  exec: async (/** @type {string} */ sql) => { await conn().none(sql); },
  // better-sqlite3: const txn = db.transaction(fn); txn(...args) runs fn atomically, returns fn's result.
  /** @type {(fn: (...a: any[]) => any) => (...args: any[]) => Promise<any>} */
  transaction: (fn) => async (...args) =>
    /** @type {{ tx: (cb: (t: PgConn) => any) => Promise<any> }} */ (pg).tx(t => als.run(t, () => fn(...args))),
  pragma: () => { throw new Error('db.pragma() is unsupported on Postgres — use information_schema'); },
};

module.exports = { enabled, pg, pgp, db, prepare };
