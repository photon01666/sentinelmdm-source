// helpers/handle-phishing-proxy-hit.js - AiTM/phishing-proxy intel hit escalation.
//
// A HELPER module, not a route module: it registers nothing.
//
//   handlePhishingProxyHit   export   escalate phishing-proxy intel hits into alerts/blocks
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 13 deps: EDR_ALERT_SUPPRESS_MS (destructure L2172), EDR_NEVER_SUPPRESS_RULES (binding L4160),
// _phishBlockQueued (binding L7225), deviceOwnerInfo (function L3142, hoisted),
// getEdrAlertSuppressedUntil (destructure L2172), isAlertAutoAuditSuppressed (function L7450,
// hoisted), learnGate (function L4206, hoisted), learnNormalizeDetail (function L4176, hoisted),
// log (function L423, hoisted), notifySecurityAlert (binding L741), notifyUser (binding L730),
// phishDomainLookup (function L7299, hoisted), setEdrAlertSuppressedUntil (destructure L2172).
// The last non-hoisted dep is _phishBlockQueued at L7225 — so the call must sit at or after L7226;
// the earliest consumer of the export is L7628, so at or before L7627.  L7565 satisfies both.
//
// REBASE note: The block lazily requires ./bastionClient — rebased to ../bastionClient
// (bastionClient.js lives at the server root; verified resolvable from helpers/).

module.exports = ({ EDR_ALERT_SUPPRESS_MS, EDR_NEVER_SUPPRESS_RULES, _phishBlockQueued, deviceOwnerInfo, getEdrAlertSuppressedUntil, isAlertAutoAuditSuppressed, learnGate, learnNormalizeDetail, log, notifySecurityAlert, notifyUser, phishDomainLookup, setEdrAlertSuppressedUntil }) => {
// Phase 6 — AiTM/phishing-proxy intel hit escalation. The agent ships every public-IP outbound
// destination as a LOW `outbound_connection` feed event (never pages on its own); when this
// helper finds a threat-intel match it escalates into a `phishing_proxy_connection` HIGH alert
// through the SAME learnGate/suppression/notify pipeline as any other EDR HIGH rule, and — for
// confirmed-C2 tier ONLY — pushes a Hop-2 block to the device (firewall outbound deny + hosts
// sinkhole + kill established connections to the IP). PhishTank/low-confidence matches page but
// never block. Dedup keyed per-device|IP so each box that contacts the flagged destination gets
// its own block, but the same box/IP pair isn't re-pushed on every 2-min poll.
async function handlePhishingProxyHit(deviceId, deviceName, ownerEmail, ev, hit) {
  // Function-local require — there is NO module-level bastionClient in server.js (all ~60 call
  // sites do this; the AI Auto-Audit 2026-08-04 bug was exactly a missing one).
  const bastionClient = require('../bastionClient');
  const now = Date.now();
  const escRule = 'phishing_proxy_connection';
  const tierLabel = hit.tier === 'c2'
    ? (hit.source === 'honeypot' ? 'confirmed C2 (honeypot-observed)' : 'confirmed C2 (abuse.ch/validated feed)')
    : 'low-confidence (PhishTank)';
  const reason = `Possible AiTM phishing-proxy destination ${ev.destination_domain || ''}${ev.destination_domain && ev.destination_ip ? ' ' : ''}${ev.destination_ip || ''}:${ev.destination_port || ''} (${tierLabel}) from ${ev.image || 'unknown image'}`;
  const neverSuppress = EDR_NEVER_SUPPRESS_RULES.has(escRule);
  // The BLOCK is the protective action and must run regardless of alert gating — a device in
  // Learn Mode, or one whose alert signature was learned/accepted, still needs the firewall
  // deny + hosts sinkhole on a confirmed C2 destination (the alert might be quieted by the
  // owner's own choice; the block is defense, not notification). Placed BEFORE learnGate and
  // the 30-min alert-suppression stamp so neither can starve it. Deduped 6h per device|IP.
  if (hit.tier === 'c2') {
    const domain = ev.destination_domain && (hit.kind === 'domain' || phishDomainLookup(ev.destination_domain)?.tier === 'c2')
      ? String(ev.destination_domain) : '';
    if (ev.destination_ip || domain) {
      const dedupKey = `${deviceId}|${ev.destination_ip || domain}`;
      // Push when the last push for this device|destination is OUTSIDE the 6h window (or never
      // happened). Found live 2026-08-15: this condition was inverted in the 17d061d restructure
      // (`< 6h` → push "if within window"), and since `now` is Date.now() ms (~1.78e12) while
      // the window is 21.6e6 ms, `now - 0 < 6h` is ALWAYS false — the block silently never
      // pushed for ANY c2 hit after that deploy (alert fired, no block; confirmed on the test device's
      // 2026-08-15 github.com false positive: no phish-block.json on the box, no push logged).
      if (now - (_phishBlockQueued.get(dedupKey) || 0) >= 6 * 3600 * 1000) {
        _phishBlockQueued.set(dedupKey, now);
        try {
          const br = (await bastionClient.phishBlock(deviceId, ev.destination_ip, domain));
          log('info', 'phish block pushed', { deviceId, ip: ev.destination_ip, domain, ok: br?.ok });
        } catch (e) { log('warn', 'phish block push failed', { deviceId, ip: ev.destination_ip, domain, err: e.message }); }
      }
    }
  }
  if (!neverSuppress && now < (await getEdrAlertSuppressedUntil(deviceId, escRule))) return;
  // Learn Mode BEFORE the suppression stamp (same rule as the poller below): a learned finding
  // must not consume the window for a genuinely new one. Signature = rule + image + parent image,
  // never the command line or the destination (the destination rotates with every phish wave).
  if (await learnGate(deviceId, 'edr_alert', escRule,
    `${escRule}:${learnNormalizeDetail(`${ev.image || ''}|${ev.parent_image || ''}`)}`,
    `${reason} ${ev.image || ''}`.trim())) return;
  if (!neverSuppress) (await setEdrAlertSuppressedUntil(deviceId, escRule, now + EDR_ALERT_SUPPRESS_MS));
  const { isZk, ownerUserId } = (await deviceOwnerInfo(deviceId));
  const msg = `🚨 EDR alert\nDevice: ${deviceName}${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}\nRule: ${escRule}\n${reason}`;
  if (await isAlertAutoAuditSuppressed('edr_alert', deviceId, msg)) return;
  if (isZk && ownerUserId) {
    (await notifyUser(ownerUserId, msg, { category: 'edr_alert', deviceId }));
    (await notifySecurityAlert(msg, deviceId, { hybridTarget: true }));
  } else {
    (await notifySecurityAlert(msg, deviceId, { hybridTarget: true }));
  }
}

  return {
    handlePhishingProxyHit,
  };
};