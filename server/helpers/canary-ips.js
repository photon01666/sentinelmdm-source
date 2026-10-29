// ARP-canary subnet math: CIDR normalisation, host-range picks, IP<->int.
//
// A HELPER module, not a route module: it registers nothing. ipToInt/intToIp
// stay private (only used inside this file); the two pickers are what
// server.js calls. No ctx at all -- these are pure functions of their
// arguments, which is why the factory takes no parameter.

module.exports = () => {
function ipToInt(ip) {
  const parts = String(ip).split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
// Masks a CIDR string to its network address (192.168.1.10/24 -> 192.168.1.0/24), or null for a
// malformed input. Callers must use the NORMALIZED form as the arp_canary_ips `subnet` key: the
// Linux agent reports interface addresses, so a host-form string would mint one key per address
// on the same LAN and pick canaries against each (found live 2026-08-05). Picker math re-masks
// its own input too, so a host-form string can't silently mispick even if a future caller forgets.
function normalizeSubnetCidr(subnetCidr) {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(String(subnetCidr || '').trim());
  if (!m) return null;
  const addrInt = ipToInt(m[1]);
  const prefixLen = parseInt(m[2], 10);
  if (addrInt === null || prefixLen < 0 || prefixLen > 32) return null;
  const netInt = prefixLen === 0 ? 0 : (addrInt >>> (32 - prefixLen)) << (32 - prefixLen);
  return `${intToIp(netInt >>> 0)}/${prefixLen}`;
}
// Picks up to `count` likely-unused IPs from the TOP of a subnet's host range (mirrors the exact
// netInt/hostCount math _ARP_SCAN_PS1 already uses), skipping anything in `excludeIps`. This is a
// HEURISTIC, not a guarantee a DHCP pool won't include the pick — see arp_canary_ips' 3-consecutive
// -scan confirmation gate in ingestArpScanResult() for how a bad pick gets caught and dropped
// before it's ever trusted enough to alert on.
function pickCanaryCandidateIps(subnetCidr, excludeIps, count) {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(String(subnetCidr || '').trim());
  if (!m || count <= 0) return [];
  const addrInt = ipToInt(m[1]);
  const prefixLen = parseInt(m[2], 10);
  if (addrInt === null || prefixLen < 22 || prefixLen > 30) return [];
  // Mask the host bits off the parsed address — the subnet string may legitimately be an
  // INTERFACE address (e.g. the Linux agent reports 192.168.1.10/24), and adding host offsets to
  // a host address lands every pick a subnet away (found live 2026-08-05: the LAN canaries came
  // out as 192.168.1.10-12 from 192.168.1.10/24). Windows agents send proper network CIDRs, which
  // is why this only ever mispicked for Linux boxes.
  const netInt = prefixLen === 0 ? 0 : (addrInt >>> (32 - prefixLen)) << (32 - prefixLen);
  const hostCount = Math.pow(2, 32 - prefixLen) - 2;
  if (hostCount < 1 || hostCount > 512) return [];
  const picks = [];
  for (let h = hostCount; h >= 1 && picks.length < count; h--) {
    const ip = intToIp((netInt + h) >>> 0);
    if (!excludeIps.has(ip)) picks.push(ip);
  }
  return picks;
}
return {
  normalizeSubnetCidr,
  pickCanaryCandidateIps,
};
};
