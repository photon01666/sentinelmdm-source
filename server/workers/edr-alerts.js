// workers/edr-alerts.js - worker-only EDR alert poller (2-minute cadence).
//
// Watches endpoint-detection telemetry for a Windows/Linux device and, when a detection is
// neither explicitly suppressed nor already known-benign, raises a user alert. Enrichment comes
// from phishLookup() / reverseDnsCached(), and suppressions are honored via
// getEdrAlertSuppressedUntil / EDR_NEVER_SUPPRESS_RULES.
//
// Grouped by CONTIGUITY: the doc comment at L8579 documents this poller, so it travels with it.
// `extraction-plan.py --pollers` computes that — a gap splits a group only when it holds code.
//
// A WORKER module: it registers a timer, not a route, and registers nothing when IS_WORKER is
// unset.
//
// The replacement call sits at the block's OWN first line (L8579), preserving registration
// order against the server.js lines around it.
//
// ctx: 20 deps. 7 are `function` declarations and hoist. The lowest non-hoisted binding is
// EDR_NEVER_SUPPRESS_RULES (L4480), so the call must sit at or after L4481. L8579 does.
// No upper bound: a poller registers a timer and nothing consumes it.
//
// bastionClient is NOT a ctx dep and must not become one — its function-local lazy require
// stays lazy and rebases to '../'.

module.exports = ({ EDR_ALERT_SUPPRESS_MS, EDR_NEVER_SUPPRESS_RULES, IS_WORKER, db, decryptText, deviceOwnerEmail, deviceOwnerInfo, getEdrAlertSuppressedUntil, getEdrEnabled, getEdrLastSeen, handlePhishingProxyHit, isAlertAutoAuditSuppressed, learnGate, learnNormalizeDetail, log, notifySecurityAlert, notifyUser, phishLookup, reverseDnsCached, setEdrAlertSuppressedUntil, setEdrLastSeen }) => {
// ── EDR alert poller (worker only — one instance) ─────────────────────────────────────────────
// Covers EVERY remote_assist Windows device (admin-fleet AND public-owned) — deliberately NOT
// scoped to a public owner join like the ARP-scan/AI-summary loop above (that loop's second job,
// emailing an AI summary, has no admin-fleet equivalent; EDR alerts do — an admin-fleet/unowned
// device just routes to Signal instead of notifyUser, same routing rule surveilNotify() already
// uses for live-monitoring alerts). get_edr_events() is a cheap bastion-cached jsonl read (not a
// live Hop-2 round trip like ARP-sweep-drain), so a faster cadence than the 15-min ARP loop is
// cheap and worthwhile here — a HIGH-severity finding (e.g. an LSASS credential-dump access)
// shouldn't sit unalerted for up to 15 minutes.
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT id, name FROM devices WHERE platform='windows' AND agent_kind='remote_assist'"
    ).all());
  } catch (e) { log('warn', 'EDR poller: device query failed', { err: e.message }); return; }
  for (const dev of devices) {
    const deviceId = dev.id;
    try {
      if (!(await getEdrEnabled(deviceId))) continue;
      // Safe Boot Guard outbox drain first — folds safe_mode_boot/safeboot_registry_tamper/
      // defender_rearm events (written while Safe Mode was active, when the report tunnel was
      // down) into the same edr_events stream the rest of this poll reads. Best-effort: a
      // drain failure must never block the regular event poll.
      try { (await bastionClient.edrSafeBootDrain(deviceId)); } catch (_) {}
      const lastSeen = (await getEdrLastSeen(deviceId));
      // Unit-normalize the watermark: events' `received_at` is SECONDS (bastion jsonl). A
      // milliseconds-era value (13-digit epoch) can leak into settings from an older writer and
      // then `received_at > since` (s vs ms) is never true — the poller silently sees zero
      // events forever (found live 2026-08-14 on the test VM: edr_last_seen held 1786694035138 ms
      // while every other device row was seconds — its whole EDR chain was dead). Tolerate both.
      const lastSeenSec = lastSeen > 1e12 ? lastSeen / 1000 : lastSeen;
      const result = (await bastionClient.edrEvents(deviceId, { since: String(lastSeenSec) }));
      if (!result?.ok || !Array.isArray(result.events) || !result.events.length) continue;
      const deviceName = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || deviceId);
      const ownerEmail = (await deviceOwnerEmail(deviceId));
      let maxSeen = lastSeenSec;
      for (const ev of result.events) {
        maxSeen = Math.max(maxSeen, Number(ev.received_at) || 0);
        // Phase 6 — AiTM/phishing-proxy intel feed. `outbound_connection` (Event 3) and
        // `dns_query` (Event 22, 3.2.3 — the qname leg that catches CDN-fronted phishing pages
        // where the connect event loses the hostname) are LOW feed-only events; they never page
        // on their own. Match the destination against the threat-intel sets; escalate + optionally
        // block only on a hit.
        if ((ev.rule === 'outbound_connection' || ev.rule === 'dns_query') && ev.severity === 'low') {
          let hit = phishLookup(ev.destination_ip, ev.destination_domain);
          // Reverse-DNS fallback for the domain tier: Sysmon often drops the hostname on the
          // connect event (browsers/curl), so a PTR name that IS a flagged feed domain (typical
          // for VPS-hosted C2) still escalates. Only consulted when nothing matched yet.
          if (!hit && ev.destination_ip && !ev.destination_domain) {
            const ptr = (await reverseDnsCached(ev.destination_ip));
            if (ptr) {
              const ptrHit = phishLookup(ev.destination_ip, ptr);
              if (ptrHit) { ev.destination_domain = ptr; hit = ptrHit; }
            }
          }
          if (hit) (await handlePhishingProxyHit(deviceId, deviceName, ownerEmail, ev, hit));
          continue;
        }
        // MEDIUM (e.g. create_remote_thread — hollowing-adjacent, deliberately never wired to a
        // push alert, see EdrWatcher.cs's doc comment) stays feed-only; only HIGH pages the owner.
        if (ev.severity !== 'high') continue;
        const now = Date.now();
        // Safe Boot Guard rules (EDR_NEVER_SUPPRESS_RULES) bypass the 30-min window ENTIRELY —
        // no suppression check, and no suppression stamp written. Each Safe Mode boot is a
        // distinct security event and must page every time it happens.
        const neverSuppress = EDR_NEVER_SUPPRESS_RULES.has(ev.rule);
        if (!neverSuppress && now < (await getEdrAlertSuppressedUntil(deviceId, ev.rule))) continue;
        // Learn Mode BEFORE the 30-min suppression stamp is written: a learned finding must not
        // consume the window for a genuinely new one of the same rule arriving minutes later.
        // Signature = rule + image + parent image (the stable identity of "this automation"),
        // deliberately NOT the command line — that carries per-run base64/GUIDs and would mint a
        // fresh unreviewable signature on every single execution.
        if (await learnGate(deviceId, 'edr_alert', ev.rule,
          `${ev.rule}:${learnNormalizeDetail(`${ev.image || ev.source_image || ''}|${ev.parent_image || ''}`)}`,
          `${ev.reason || ''} ${ev.image || ev.source_image || ''}`.trim())) continue;
        if (!neverSuppress) (await setEdrAlertSuppressedUntil(deviceId, ev.rule, now + EDR_ALERT_SUPPRESS_MS));
        const { isZk, ownerUserId } = (await deviceOwnerInfo(deviceId));
        const msg = `🚨 EDR alert\nDevice: ${deviceName}${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}\nRule: ${ev.rule}\n${ev.reason || ev.image || ev.source_image || ''}`;
        // If this alert's signature is already marked as a false positive in alert_auto_audits,
        // skip the notification entirely — the user already reviewed and dismissed it.
        if (await isAlertAutoAuditSuppressed('edr_alert', deviceId, msg)) continue;
        if (isZk && ownerUserId) {
          (await notifyUser(ownerUserId, msg, { category: 'edr_alert', deviceId }));
          (await notifySecurityAlert(msg, deviceId, { hybridTarget: true }));
        } else {
          (await notifySecurityAlert(msg, deviceId, { hybridTarget: true }));
        }
      }
      if (maxSeen > lastSeenSec) (await setEdrLastSeen(deviceId, maxSeen));
    } catch (e) { log('warn', 'EDR poll failed', { deviceId, err: e.message }); }
  }
}, 2 * 60 * 1000);

  // Nothing to return: registering the interval IS the side effect.
};
