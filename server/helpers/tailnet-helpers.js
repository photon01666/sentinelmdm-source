// helpers/tailnet-helpers.js — Tailnet subnet sanitisation & tailnet command builder.
//
// A HELPER module, not a route module: it registers nothing.
//
//   sanitizeSubnet    export   Normalise one tailnet entry to bare-IP/CIDR
//   sanitizeSubnets   export   Sanitise an array of tailnet entries
//   tailnetCommand    export   Build the set_tailnet command for a group
//
// ctx deps (2):
//   TAILNET_UUID    binding    server.js L3791
//   db              binding    server.js L699
//
// The require call must sit at or after L3792 (last non-hoisted dep TAILNET_UUID)
// and at or before L4690 (earliest export consumer is L4691).
//
// relative requires: none

module.exports = ({ TAILNET_UUID, db }) => {
  // Normalise one tailnet entry to a bare-IP/CIDR string that the agent's xray routing `ip` field
  // accepts (e.g. "100.64.0.10/32", "192.168.1.0/24"). Returns null for non-numeric input.
function sanitizeSubnet(raw) {
if (typeof raw !== 'string') return null;
let s = raw.trim();
if (!s) return null;
let prefix = null;
const slash = s.indexOf('/');
if (slash >= 0) { prefix = s.slice(slash + 1).trim(); s = s.slice(0, slash).trim(); }
    // Strip an accidental IPv4 "ip:port" (exactly one colon, dotted-quad host) — never an IPv6 literal.
if ((s.match(/:/g) || []).length === 1 && (s.split(':')[0].match(/\./g) || []).length === 3) {
  s = s.split(':')[0].trim();
}
const isV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split('.').every(o => +o >= 0 && +o <= 255);
const isV6 = s.includes(':') && /^[0-9A-Fa-f:]+$/.test(s);
if (!isV4 && !isV6) return null;
const max = isV6 ? 128 : 32;
const p = (prefix === null || prefix === '') ? max : parseInt(prefix, 10);
if (!Number.isInteger(p) || p < 0 || p > max) return null;
return `${s}/${p}`;
}

function sanitizeSubnets(arr) {
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const x of arr) { const v = sanitizeSubnet(x); if (v && !out.includes(v)) out.push(v); }
  return out;
}

async function tailnetCommand(groupId) {
  if (!groupId || !TAILNET_UUID) return { command: 'set_tailnet', enabled: false };
  const group = (await db.prepare('SELECT subnets FROM tailnet_groups WHERE id=?').get(groupId));
    // Sanitise on the way out too, so any already-stored bad value (e.g. an "ip:port") is corrected
    // before it reaches an agent — defence-in-depth against a legacy row knocking a device offline.
  const subnets = sanitizeSubnets(group ? (() => { try { return JSON.parse(group.subnets); } catch { return []; } })() : []);
  return { command: 'set_tailnet', enabled: true, egressUuid: TAILNET_UUID, subnets };
}

  return { sanitizeSubnet, sanitizeSubnets, tailnetCommand };
};
