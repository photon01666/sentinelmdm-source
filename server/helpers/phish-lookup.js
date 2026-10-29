// helpers/phish-lookup.js — threat-intel lookup for a destination IP/domain.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the consumers. Only the lookup function moves.
//
//   phishLookup   export   returns {tier,kind,asn?,name?} for IP/domain or null
//
// ctx is available at this module's own position in server.js (X >= L5629,
// X <= L5911) — nothing had to move (IN-PLACE splice).
//
// 6 ctx deps: _phishIntel, ipv4InCidr, phishDomainLookup, phishNeverDomain
// (all STABLE — declared above the wiring line, never reassigned),
// and getHoneypotBadIps / getHoneypotBadDomains (LIVE getters).
//
// getHoneypotBadIps and getHoneypotBadDomains are LIVE deps (getters):
// _honeypotBadIps (L5554) is runtime-reassigned at 2 sites (honeypot-feed
// refresh L5569, Redis-restore L5602); _honeypotBadDomains (L5555) likewise
// (L5573, L5603). A by-value capture would look up stale sets after every
// feed refresh or restore. The getters read the top-level `let` at call time.
//   — R5: live vs stable documented here; R3: getHoneypotBadIps() and
//     getHoneypotBadDomains() are called ONLY inside phishLookup's body,
//     never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ _phishIntel, getHoneypotBadDomains, getHoneypotBadIps, ipv4InCidr, phishDomainLookup, phishNeverDomain }) => {

// Returns {tier:'c2'|'low', kind:'ip'|'asn'|'domain', asn?, name?} for a destination IP/domain,
// or null.
function phishLookup(ip, domain) {
  if (!ip && !domain) return null;
  if (ip) {
    if (_phishIntel.c2Ips.has(ip)) return { tier: 'c2', kind: 'ip' };
    if (_phishIntel.lowIps.has(ip)) return { tier: 'low', kind: 'ip' };
    // Confirmed-attacker/C2 IPs from the fleet honeypot are every bit as actionable as the C2 feed
    // (they're sandbox/decoy-observed), so they ride the same c2 tier.
    if (getHoneypotBadIps().has(ip)) return { tier: 'c2', kind: 'ip', source: 'honeypot' };
    for (const c of _phishIntel.cidrs) {
      if (ipv4InCidr(ip, c.cidr)) return { tier: c.tier, kind: 'asn', asn: c.asn, name: c.name };
    }
  }
  // Phase 6 domain tier: the agent reports the resolved hostname (Sysmon DestinationHostname);
  // match it against the feed's domain sets with full label-boundary suffix matching so a
  // subdomain of a flagged C2/PhishTank host rides the same tier as its parent. Known-benign
  // platform hosts (GitHub/Cloudflare/Vercel/...) are checked FIRST and can never match, even
  // if a polluted feed entry contains them (see phishNeverDomain — found live 2026-08-15).
  if (domain) {
    if (phishNeverDomain(domain)) return null;
    const t = phishDomainLookup(domain);
    if (t) return t;
    // Honeypot-observed C2 domains (sandbox detonations / decoy URL hosts) ride the SAME c2
    // tier — they're operator-observed attacker infra, every bit as actionable as the abuse.ch
    // feed. Label-boundary suffix match, identical shape to phishDomainLookup.
    if (getHoneypotBadDomains().size > 0) {
      const d = String(domain).trim().toLowerCase().replace(/\.+$/, '');
      if (d && d.includes('.') && !/\s/.test(d)) {
        let at = d;
        for (;;) {
          if (getHoneypotBadDomains().has(at)) return { tier: 'c2', kind: 'domain', domain: at, source: 'honeypot' };
          const i = at.indexOf('.');
          if (i < 0) break;
          at = at.slice(i + 1);
        }
      }
    }
  }
  return null;
}

return { phishLookup };

};