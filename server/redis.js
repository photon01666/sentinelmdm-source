// @ts-check
// server/redis.js
// ─────────────────────────────────────────────────────────────────────────────
// Shared Redis layer that lets the tracker run as multiple replicas.
//
// When REDIS_URL is set (multi-replica Swarm deploy) the raw `redis`/`pubClient`/
// `subClient` clients back the Socket.IO adapter, the session store, and the `kv`
// helpers below.
//
// When REDIS_URL is UNSET (local/offline single instance, e.g. docker-compose.local.yml)
// `enabled` is false, the raw clients are null, and the `kv` helpers transparently
// fall back to an in-process Map (with TTL). That way server.js can use ONE async
// interface regardless of deployment, and a single instance keeps working offline.
//
// NOTE: `kv` is only for JSON-serialisable values (token metadata, presence,
// status snapshots, counters). Non-serialisable per-connection state (timers,
// chunk buffers, live socket refs, the per-socket AES key) MUST stay in plain
// in-memory Maps on the holding replica — see server.js.
// ─────────────────────────────────────────────────────────────────────────────

// Two connection modes (multi-replica):
//   • plain URL  — REDIS_URL=redis://host:6379           (single-node Redis)
//   • Sentinel   — REDIS_SENTINELS="h1:26379,h2:26379,h3:26379" + REDIS_MASTER_NAME
//                  (HA: ioredis discovers the current master via the sentinels and
//                   transparently reconnects to the newly-promoted master on failover)
const REDIS_URL       = process.env.REDIS_URL || '';
const REDIS_SENTINELS = process.env.REDIS_SENTINELS || '';
const REDIS_MASTER    = process.env.REDIS_MASTER_NAME || 'sentinel-redis';
const enabled = !!(REDIS_URL || REDIS_SENTINELS);

// `Redis` is kept loosely typed: the ctor is spread with a union of arg tuples
// (Sentinel vs URL) that doesn't match ioredis's overloads cleanly, and the client
// methods are only ever reached when `enabled` (so no null-guard noise). The VALUE of
// type-checking this file is the `kv` interface params below, used across server.js.
/** @type {any} */
let Redis = null;
let redis = null, pubClient = null, subClient = null;

// ioredis ctor args differ by mode: Sentinel takes one options object, URL takes (url, opts).
function redisArgs() {
  const base = { maxRetriesPerRequest: null };   // keeps the Socket.IO adapter happy across reconnects
  if (REDIS_SENTINELS) {
    const sentinels = REDIS_SENTINELS.split(',').map(s => {
      const [host, port] = s.trim().split(':');
      return { host, port: Number(port) || 26379 };
    });
    return [{ ...base, name: REDIS_MASTER, sentinels }];
  }
  return [REDIS_URL, base];
}

if (enabled) {
  Redis = require('ioredis');
  redis     = new Redis(...redisArgs());
  pubClient = new Redis(...redisArgs());
  subClient = pubClient.duplicate();
  for (const [n, c] of Object.entries({ redis, pubClient, subClient })) {
    c.on('error', (/** @type {Error} */ e) => console.warn(`[redis:${n}] ${e.message}`));
  }
  console.log('[redis] enabled →', REDIS_SENTINELS ? `sentinel(${REDIS_MASTER}) [${REDIS_SENTINELS}]` : REDIS_URL.replace(/\/\/.*@/, '//***@'));
}

// ── In-memory fallback store (used only when REDIS_URL is unset) ─────────────
const _mem = new Map(); // key -> { v, exp }  (exp=0 means no expiry)
/** @param {string} key */
function _memGet(key) {
  const e = _mem.get(key);
  if (!e) return null;
  if (e.exp && e.exp < Date.now()) { _mem.delete(key); return null; }
  return e.v;
}

// ── Uniform async KV helpers (Redis when enabled, else in-memory) ───────────
const kv = {
  /** @param {string} key @param {any} obj @param {number} [ttlSec] */
  async setJSON(key, obj, ttlSec) {
    const v = JSON.stringify(obj);
    if (enabled) { ttlSec ? await redis.set(key, v, 'EX', ttlSec) : await redis.set(key, v); }
    else { _mem.set(key, { v, exp: ttlSec ? Date.now() + ttlSec * 1000 : 0 }); }
  },
  /** @param {string} key */
  async getJSON(key) {
    const v = enabled ? await redis.get(key) : _memGet(key);
    return v ? JSON.parse(v) : null;
  },
  // Atomic one-time read+delete — for single-use tokens.
  /** @param {string} key */
  async getdelJSON(key) {
    let v;
    if (enabled) { v = await redis.getdel(key); }
    else { v = _memGet(key); _mem.delete(key); }
    return v ? JSON.parse(v) : null;
  },
  /** @param {string} key */
  async del(key) { if (enabled) await redis.del(key); else _mem.delete(key); },
  /** @param {string} key */
  async exists(key) { return enabled ? (await redis.exists(key)) === 1 : _memGet(key) !== null; },

  // Fixed-window rate limit — returns the post-increment count.
  /** @param {string} key @param {number} windowSec */
  async incrWindow(key, windowSec) {
    if (enabled) {
      const n = await redis.incr(key);
      if (n === 1) await redis.expire(key, windowSec);
      return n;
    }
    const cur = _memGet(key);
    if (cur == null) { _mem.set(key, { v: 1, exp: Date.now() + windowSec * 1000 }); return 1; }
    const n = cur + 1; _mem.set(key, { v: n, exp: _mem.get(key).exp }); return n;
  },

  // Fixed-window numeric ACCUMULATOR — increments by `amount` (not just +1); the window
  // starts on the first increment (same "n === amount ⇒ just created" trick incrWindow uses
  // with "n === 1"). Used for quotas like "N seconds of X per rolling 24h", not just hit counts.
  /** @param {string} key @param {number} amount @param {number} windowSec */
  async incrByWindow(key, amount, windowSec) {
    if (enabled) {
      const n = await redis.incrby(key, amount);
      if (n === amount) await redis.expire(key, windowSec);
      return n;
    }
    const cur = _memGet(key);
    if (cur == null) { _mem.set(key, { v: amount, exp: Date.now() + windowSec * 1000 }); return amount; }
    const n = cur + amount; _mem.set(key, { v: n, exp: _mem.get(key).exp }); return n;
  },

  // Plain numeric read (no increment) — peek at an incrWindow/incrByWindow counter's current value.
  /** @param {string} key */
  async getNum(key) {
    const v = enabled ? await redis.get(key) : _memGet(key);
    return v == null ? 0 : Number(v);
  },

  // Remaining TTL in seconds for a key: -1 = no expiry, -2 = missing/expired. Mirrors redis TTL
  // semantics so callers can render "resets in Xh Ym" messages for window-based counters above.
  /** @param {string} key */
  async ttl(key) {
    if (enabled) return await redis.ttl(key);
    const e = _mem.get(key);
    if (!e) return -2;
    if (!e.exp) return -1;
    return Math.max(0, Math.ceil((e.exp - Date.now()) / 1000));
  },

  // Set-if-absent with TTL — returns true if newly set (i.e. action allowed).
  /** @param {string} key @param {number} ttlSec */
  async setNX(key, ttlSec) {
    if (enabled) { return (await redis.set(key, '1', 'EX', ttlSec, 'NX')) === 'OK'; }
    if (_memGet(key) !== null) return false;
    _mem.set(key, { v: '1', exp: Date.now() + ttlSec * 1000 }); return true;
  },

  // Presence set (online devices).
  /** @param {string} setKey @param {string} m */
  async sadd(setKey, m)      { if (enabled) await redis.sadd(setKey, m); else { const s = _memGet(setKey) || new Set(); s.add(m); _mem.set(setKey, { v: s, exp: 0 }); } },
  /** @param {string} setKey @param {string} m */
  async srem(setKey, m)      { if (enabled) await redis.srem(setKey, m); else { const s = _memGet(setKey); if (s) s.delete(m); } },
  /** @param {string} setKey */
  async scard(setKey)        { if (enabled) return await redis.scard(setKey); const s = _memGet(setKey); return s ? s.size : 0; },
  /** @param {string} setKey @param {string} m */
  async sismember(setKey, m) { if (enabled) return (await redis.sismember(setKey, m)) === 1; const s = _memGet(setKey); return s ? s.has(m) : false; },
  /** @param {string} setKey */
  async smembers(setKey)     { if (enabled) return await redis.smembers(setKey); const s = _memGet(setKey); return s ? [...s] : []; },
};

module.exports = { enabled, redis, pubClient, subClient, kv };
