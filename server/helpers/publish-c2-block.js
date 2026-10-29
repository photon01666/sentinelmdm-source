// helpers/publish-c2-block.js — combined C2 destination blocklist publisher.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the scheduling (IS_WORKER gate). Only the publish function moves.
//
//   publishCombinedC2Block   export   merges phish + honeypot feeds into one
//                                    compact kv publish for node firewalls
//
// ctx is available at this module's own position in server.js (X >= L5629,
// X <= L5761) — nothing had to move (IN-PLACE splice).
//
// 5 ctx deps: _phishIntel, kv, phishNeverDomain (all STABLE — declared above
// the wiring line, never reassigned), and getHoneypotBadIps /
// getHoneypotBadDomains (LIVE getters).
//
// getHoneypotBadIps and getHoneypotBadDomains are LIVE deps (getters):
// _honeypotBadIps (L5554) is runtime-reassigned at 2 sites (honeypot-feed
// refresh L5569, Redis-restore L5602); _honeypotBadDomains (L5555) likewise
// (L5573, L5603). A by-value capture would publish stale sets after every
// feed refresh or restore. The getters read the top-level `let` at call time.
//   — R5: live vs stable documented here; R3: getHoneypotBadIps() and
//     getHoneypotBadDomains() are called ONLY inside publishCombinedC2Block's
//     body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ _phishIntel, getHoneypotBadDomains, getHoneypotBadIps, kv, phishNeverDomain }) => {

async function publishCombinedC2Block() {
  try {
    const ipv4 = new Set();
    const domains = new Set();
    const push = (ip) => { if (ip && ip.indexOf(':') < 0 && !ipv4.has(ip)) ipv4.add(ip); };
    for (const ip of _phishIntel.c2Ips) push(ip);
    for (const ip of getHoneypotBadIps()) push(ip);
    for (const d of _phishIntel.c2Domains) if (!phishNeverDomain(d)) domains.add(d);
    for (const d of getHoneypotBadDomains()) if (!phishNeverDomain(d)) domains.add(d);
    await kv.setJSON('block:c2', {
      ips: [...ipv4], domains: [...domains], at: Date.now(),
    }, 6 * 60 * 60);
  } catch { /* Redis unavailable — nodes fall back to their own last-known list */ }
}

return { publishCombinedC2Block };

};