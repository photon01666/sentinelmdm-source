// helpers/phish-intel-lookups.js — reverse DNS, phish-domain matching, CIDR test,
// and the phish-feed refresh poller.
//
// A HELPER module, not a route module: it registers nothing. Consumers:
//   * the phish-lookup wiring (ipv4InCidr + phishDomainLookup — eager, L4491);
//   * the edr-alerts worker wiring (reverseDnsCached — below);
//   * the phish-feed boot block (refreshPhishFeed — below).
//
//   reverseDnsCached    export   cached PTR lookup
//   phishDomainLookup   export   suffix-walk domain match against the feed
//   ipv4InCidr          export   IPv4-in-CIDR test
//   refreshPhishFeed    export   worker feed poll -> refresh _phishIntel + Redis
//
// Wiring RELOCATED above its earliest eager consumer (phish-lookup wiring,
// L4491) via D1b R2 (dep-first: helpers/ptr-cache.js) + R1. Deps:
//   * PHISH_FEED_URL / PHISH_FEED_KEY (L4468) and _phishIntel (L4469) — stable
//     consts above; PTR_CACHE_* / _ptrCache from helpers/ptr-cache.js (wired
//     above); kv (L21) by value.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ PHISH_FEED_KEY, PHISH_FEED_URL, PTR_CACHE_MAX, PTR_CACHE_TTL_MS, _phishIntel, _ptrCache, kv }) => {

async function reverseDnsCached(ip) {
  if (!ip) return null;
  const c = _ptrCache.get(ip);
  if (c && Date.now() - c.at < PTR_CACHE_TTL_MS) return c.name;
  let name = null;
  try {
    name = await Promise.race([
      (await import('node:dns')).promises.reverse(ip).then(r => r[0] || null),
      new Promise((_, rej) => setTimeout(() => rej(new Error('ptr timeout')), 2000)),
    ]);
  } catch (_) { name = null; }
  if (_ptrCache.size >= PTR_CACHE_MAX) _ptrCache.clear();
  _ptrCache.set(ip, { name, at: Date.now() });
  return name;
}

// Label-boundary suffix match: `sub.evil.example` hits a `evil.example` feed entry, but
// `notevil.example` does NOT. Normalizes case + trailing dot.
function phishDomainLookup(domain) {
  const d = String(domain).trim().toLowerCase().replace(/\.+$/, '');
  if (!d || !d.includes('.') || /\s/.test(d)) return null;
  let at = d;
  for (;;) {
    if (_phishIntel.c2Domains.has(at)) return { tier: 'c2', kind: 'domain', domain: at };
    if (_phishIntel.lowDomains.has(at)) return { tier: 'low', kind: 'domain', domain: at };
    const idx = at.indexOf('.');
    if (idx <= 0 || idx === at.length - 1) break;
    at = at.slice(idx + 1);
  }
  return null;
}

function ipv4InCidr(ip, cidr) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(cidr || ''));
  if (!m) return false;
  const bits = Number(m[2]);
  const a = ip.split('.').map(Number), b = m[1].split('.').map(Number);
  if (a.length !== 4 || b.length !== 4 || a.some(Number.isNaN) || b.some(Number.isNaN)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const ipn = ((a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3]) >>> 0;
  const rn = ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
  return (ipn & mask) === (rn & mask);
}

async function refreshPhishFeed() {
  if (!PHISH_FEED_URL) return;
  try {
    const r = await fetch(PHISH_FEED_URL, {
      headers: PHISH_FEED_KEY ? { 'X-Phish-Auth': PHISH_FEED_KEY } : {},
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return;
    const j = /** @type {any} */ (await r.json());
    const next = {
      c2Ips: new Set(Array.isArray(j.c2_ips) ? j.c2_ips : []),
      lowIps: new Set(Array.isArray(j.phishtank_ips) ? j.phishtank_ips : []),
      c2Domains: new Set(Array.isArray(j.c2_domains) ? j.c2_domains : []),
      lowDomains: new Set(Array.isArray(j.phishtank_domains) ? j.phishtank_domains : []),
      cidrs: Array.isArray(j.asns) ? j.asns.flatMap((a) => Array.isArray(a?.cidrs) ? a.cidrs.map((c) => ({
        cidr: c, asn: a.asn, name: a.name, tier: 'c2',
      })) : []) : [],
    };
    Object.assign(_phishIntel, next);
    try { await kv.setJSON('phish:intel', {
      c2Ips: [...next.c2Ips], lowIps: [...next.lowIps], c2Domains: [...next.c2Domains],
      lowDomains: [...next.lowDomains], cidrs: next.cidrs, at: Date.now(),
    }, 6 * 60 * 60); } catch {}
  } catch { /* feed unreachable — stay inert */ }
}

return { ipv4InCidr, phishDomainLookup, refreshPhishFeed, reverseDnsCached };

};
