// helpers/honeypot-feed.js — honeypot IOC feed consumption + fleet sightings.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the boot block (worker refresh loop + per-replica Redis hydrate).
//
//   isHoneypotKnownBad   private   Set lookup used by honeypotSighting
//   refreshHoneypotFeed  export    worker feed poll -> refresh the two Sets
//   honeypotSighting     export    known-bad-IP fleet hit + honeypot notify
//
// Wiring line belongs at X in [3885, 3897] (after HONEYPOT_FEED_URL L3884,
// before the sockets/connection wiring L3898 which eagerly consumes
// honeypotSighting) — NOT at the block position: the block sits at L5112, below
// that consumer.
// Window: L5112-L5148 — includes `const _honeypotSeen = new Map();` (sole user
// is honeypotSighting; at X<3898 its declaration would be below the wiring
// line, a TDZ fatal for a shorthand ctx value — the Map travels WITH the block).
//
// ctx deps: HONEYPOT_FEED_URL, HONEYPOT_MGMT_KEY, kv, notifyAdmin —
// STABLE (const above the wiring line, never reassigned). getHoneypotBadIps /
// setHoneypotBadIps and getHoneypotBadDomains / setHoneypotBadDomains — LIVE
// read+write pairs.
//
// The two Set pairs are LIVE deps: _honeypotBadIps/_honeypotBadDomains (L5191-
// L5192, decls stay in server.js — phish-lookup.js and publish-c2-block.js read
// them through their own getters) are runtime-reassigned at 2 sites each (the
// refresh swap in refreshHoneypotFeed, the hydrate swap in the boot block). A
// by-value capture would pin the boot-time empty Sets forever. Getters read the
// top-level `let`s at call time; setters write them back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     member bodies, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ HONEYPOT_FEED_URL, HONEYPOT_MGMT_KEY, getHoneypotBadDomains, getHoneypotBadIps, kv, notifyAdmin, setHoneypotBadDomains, setHoneypotBadIps }) => {

const _honeypotSeen = new Map();   // ip -> last-alerted ms (per-process dedup)

function isHoneypotKnownBad(ip) { return !!ip && getHoneypotBadIps().has(ip); }

async function refreshHoneypotFeed() {
  if (!HONEYPOT_FEED_URL) return;
  try {
    const r = await fetch(HONEYPOT_FEED_URL, {
      headers: HONEYPOT_MGMT_KEY ? { 'X-HP-Auth': HONEYPOT_MGMT_KEY } : {},
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return;
    const j = /** @type {any} */ (await r.json());
    setHoneypotBadIps(new Set([...(j.attacker_ips || []), ...(j.c2_ips || [])]));
    // Phase 6 (2026-08-15): also carry the honeypot's observed C2 DOMAINS (sandbox-detonation
    // URL hosts + c2_domains) so the domain tier blocks them fleet-wide — the honeypot banlist
    // (ipset) is IP-only, so domains were previously invisible to every downstream consumer.
    setHoneypotBadDomains(new Set([...(j.c2_domains || [])].map(d => String(d).trim().toLowerCase().replace(/\.+$/, '')).filter(d => d && d.includes('.'))));
    try { await kv.setJSON('honeypot:badips', { ips: [...getHoneypotBadIps()], domains: [...getHoneypotBadDomains()], at: Date.now() }); } catch {}
  } catch { /* honeypot unreachable — stay inert */ }
}

async function honeypotSighting(ip, context) {
  if (!HONEYPOT_FEED_URL || !isHoneypotKnownBad(ip)) return;
  const now = Date.now();
  if (now - (_honeypotSeen.get(ip) || 0) < 6 * 3600 * 1000) return;
  _honeypotSeen.set(ip, now);
  try {
    fetch(HONEYPOT_FEED_URL.replace(/\/feed\/iocs\.json.*$/, '/api/fleet-hit'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(HONEYPOT_MGMT_KEY ? { 'X-HP-Auth': HONEYPOT_MGMT_KEY } : {}) },
      body: JSON.stringify({ ip, context: String(context || '').slice(0, 200) }),
      signal: AbortSignal.timeout(6000),
    }).catch(() => {});
  } catch {}
  notifyAdmin(`🎯 Honeypot-known-bad IP seen against the FLEET\nIP: ${ip}\n${context || ''}`).catch(() => {});
}

return { refreshHoneypotFeed, honeypotSighting };

};
