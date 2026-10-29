// helpers/arp-scan.js - ARP roster diffing + canary detection (arp_neighbors / arp_events).
//
// A HELPER module, not a route module: it registers nothing.
//
// _arpFingerprintJson stays PRIVATE - its only callers are inside this file.
// ingestArpScanResult is the export: server.js wires it in as a ctx dep of the
// Remote Assist fleet/feature routes, and the ARP worker poller calls it.
//
// normalizeSubnetCidr / pickCanaryCandidateIps are NOT used anywhere else in
// server.js - they arrive here from helpers/canary-ips.js, and server.js binds
// that module immediately above this one purely to feed this ctx.
//
// learnGate and deviceOwnerInfo are `function` declarations further down
// server.js; they hoist, so binding them here (above their source position) is
// safe. db and notifyUser are module-scope bindings well above.

module.exports = ({ db, decryptText, deviceOwnerInfo, learnGate, log, normalizeSubnetCidr, notifyUser, pickCanaryCandidateIps }) => {
// Diffs a raw {devices:[{ip,mac,hostname}]} scan result against the persisted roster for one
// device and upserts arp_neighbors + appends arp_events. Keyed by MAC (a device's identity
// persists across DHCP-assigned IP changes) — matches ARPwatch's own model. Three distinct signals:
//   • 'ip_changed'        — a KNOWN mac now has a different ip (ordinary DHCP renewal, benign)
//   • 'mac_changed_for_ip' — a KNOWN ip is now claimed by a DIFFERENT mac than last recorded —
//     the actual ARPwatch "flip-flop" signal (classic ARP/MAC-spoofing indicator, though a mundane
//     explanation — an old device leaving and a new one picking up the same leased IP — is common
//     too; recorded as a raw fact here, the AI summary/human is what judges severity).
//   • 'canary_hit'         — a designated dark-space IP (arp_canary_ips, confirmed_at set) just
//     answered. Higher-confidence than mac_changed_for_ip since the IP was deliberately never
//     supposed to be in use — see pickCanaryCandidateIps() and the state machine below.
// Safe to re-run on an unchanged scan (idempotent no-op) — the worker poller doesn't bother
// tracking "already ingested this exact result".
function _arpFingerprintJson(d) {
  // Normalize the fingerprint fields from the raw scan device into DB-storable JSON strings
  // (null when the scanning agent/bastion predates the fingerprinting feature).
  let openPorts = null;
  let webUi = null;
  try {
    const ports = Array.isArray(d?.openPorts) ? d.openPorts.map(p => Number(p)).filter(p => Number.isInteger(p) && p > 0 && p < 65536) : [];
    if (ports.length) openPorts = JSON.stringify(ports.slice(0, 40));
  } catch (_) {}
  try {
    const web = Array.isArray(d?.web) ? d.web : [];
    const cleaned = web.slice(0, 10).map(w => ({
      port: Number(w?.port) || 0,
      url: String(w?.url || '').slice(0, 400),
      status: Number(w?.status) || 0,
      title: String(w?.title || '').slice(0, 300),
      server: String(w?.server || '').slice(0, 200),
    })).filter(w => w.port > 0);
    if (cleaned.length) webUi = JSON.stringify(cleaned);
  } catch (_) {}
  return { openPorts, webUi };
}
async function ingestArpScanResult(deviceId, rawResult) {
  const devices = Array.isArray(rawResult?.devices) ? rawResult.devices : [];
  const now = Date.now();
  // Record this device's own adapter MACs before the early-return below — a scan that found no
  // neighbours still tells us who THIS box is, which is exactly what the sweep-suppression needs.
  // Older agents/bastions don't send selfMacs; absence is fine, suppression just doesn't apply yet.
  for (const raw of (Array.isArray(rawResult?.selfMacs) ? rawResult.selfMacs : [])) {
    const m = String(raw || '').trim().toLowerCase().replace(/-/g, ':');
    if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(m)) continue;
    try {
      (await db.prepare(`INSERT INTO device_self_macs (device_id,mac_address,last_seen) VALUES (?,?,?)
        ON CONFLICT(device_id,mac_address) DO UPDATE SET last_seen=excluded.last_seen`).run(deviceId, m, now));
    } catch (e) { log('warn', 'device_self_macs upsert failed', { deviceId, error: e.message }); }
  }
  if (!devices.length) return { newCount: 0, events: [] };
  const existing = (await db.prepare('SELECT mac_address,ip_address FROM arp_neighbors WHERE device_id=?').all(deviceId));
  const byMac = new Map(existing.map(r => [r.mac_address, r.ip_address]));
  // Dedupes mac_changed_for_ip AND canary_hit against events ALREADY on record for this exact
  // (ip, mac, prior_value) triple — canary_hit's prior_value is always the constant 'dark', so its
  // keys naturally live in a separate namespace from mac_changed_for_ip's (whose prior_value is a
  // real prior MAC address, never the literal string "dark"). Without this, a still-unresolved
  // conflict/hit would otherwise re-"detect" and re-alert on EVERY future scan for as long as it
  // persists — at a 5-min schedule that's an alert every 5 minutes for one finding. Only a
  // GENUINELY new triple (never recorded before) counts as freshly "found" and gets alerted.
  const knownConflicts = new Set(
    (await db.prepare("SELECT ip_address, mac_address, prior_value FROM arp_events WHERE device_id=? AND event_type IN ('mac_changed_for_ip','canary_hit')").all(deviceId))
      .map(r => `${r.ip_address}|${r.mac_address}|${r.prior_value}`)
  );
  const events = [];
  for (const d of devices) {
    const ip = String(d.ip || '').trim();
    const normMac = String(d.mac || '').trim().toLowerCase().replace(/-/g, ':');
    if (!ip || !/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(normMac)) continue;
    const hostname = d.hostname ? String(d.hostname).slice(0, 255) : null;
    const macAtThisIpBefore = existing.find(r => r.ip_address === ip && r.mac_address !== normMac);
    if (macAtThisIpBefore) {
      const conflictKey = `${ip}|${normMac}|${macAtThisIpBefore.mac_address}`;
      if (!knownConflicts.has(conflictKey)) {
        events.push({ event_type: 'mac_changed_for_ip', mac_address: normMac, ip_address: ip, prior_value: macAtThisIpBefore.mac_address });
        knownConflicts.add(conflictKey);   // guards against the same pair repeating within THIS batch too
      }
    }
    if (!byMac.has(normMac)) {
      const fp = _arpFingerprintJson(d);
      (await db.prepare('INSERT INTO arp_neighbors (device_id,mac_address,ip_address,hostname,open_ports,web_ui,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)')
        .run(deviceId, normMac, ip, hostname, fp.openPorts, fp.webUi, now, now));
      events.push({ event_type: 'new_device', mac_address: normMac, ip_address: ip, prior_value: null });
    } else if (byMac.get(normMac) !== ip) {
      const fp = _arpFingerprintJson(d);
      (await db.prepare('UPDATE arp_neighbors SET ip_address=?, hostname=COALESCE(?,hostname), open_ports=?, web_ui=?, last_seen=? WHERE device_id=? AND mac_address=?')
        .run(ip, hostname, fp.openPorts, fp.webUi, now, deviceId, normMac));
      events.push({ event_type: 'ip_changed', mac_address: normMac, ip_address: ip, prior_value: byMac.get(normMac) });
    } else {
      const fp = _arpFingerprintJson(d);
      (await db.prepare('UPDATE arp_neighbors SET hostname=COALESCE(?,hostname), open_ports=?, web_ui=?, last_seen=? WHERE device_id=? AND mac_address=?')
        .run(hostname, fp.openPorts, fp.webUi, now, deviceId, normMac));
    }
  }
  // Canary/dark-space IPs — see arp_canary_ips schema comment (schema.sql) for the full design.
  // State machine per (device, subnet): designate up to 2 candidates from the top of the host
  // range (skipping anything occupied or already tracked) → each scan a candidate is absent from
  // advances consecutive_dark_scans → 3 in a row confirms it → only a CONFIRMED canary answering
  // counts as a genuine hit. A candidate that answers BEFORE confirmation was just a bad pick
  // (something legitimately uses it) and is dropped, never alerted on, never re-picked.
  const subnets = Array.isArray(rawResult?.subnets) ? rawResult.subnets : [];
  if (subnets.length) {
    const occupiedIps = new Set(devices.map(d => String(d.ip || '').trim()).filter(Boolean));
    const CANARY_CONFIRM_STREAK = 3;
    for (const rawSubnet of subnets) {
      // Normalize to the network address BEFORE it becomes the DB key — the Linux agent reports
      // interface addresses (192.168.1.10/24), which would otherwise key each LAN address as its
      // own subnet and cap canaries at 2 per address instead of 2 per actual subnet.
      const subnet = normalizeSubnetCidr(rawSubnet);
      if (!subnet) continue;
      const existingCanaries = (await db.prepare(
        'SELECT ip_address, confirmed_at, consecutive_dark_scans FROM arp_canary_ips WHERE device_id=? AND subnet=?'
      ).all(deviceId, subnet));
      if (existingCanaries.length < 2) {
        const trackedIps = new Set(existingCanaries.map(r => r.ip_address));
        const excludeIps = new Set([...occupiedIps, ...trackedIps]);
        const picks = pickCanaryCandidateIps(subnet, excludeIps, 2 - existingCanaries.length);
        for (const ip of picks) {
          try {
            (await db.prepare(
              'INSERT INTO arp_canary_ips (device_id,subnet,ip_address,candidate_at,confirmed_at,consecutive_dark_scans) VALUES (?,?,?,?,NULL,0)'
            ).run(deviceId, subnet, ip, now));
          } catch (e) { /* race with a concurrent ingest for this device — next scan retries */ }
        }
      }
      for (const row of existingCanaries) {
        const hitDevice = occupiedIps.has(row.ip_address)
          ? devices.find(d => String(d.ip || '').trim() === row.ip_address) : null;
        if (hitDevice) {
          if (row.confirmed_at) {
            const normMac = String(hitDevice.mac || '').trim().toLowerCase().replace(/-/g, ':');
            if (normMac) {
              const conflictKey = `${row.ip_address}|${normMac}|dark`;
              if (!knownConflicts.has(conflictKey)) {
                events.push({ event_type: 'canary_hit', mac_address: normMac, ip_address: row.ip_address, prior_value: 'dark' });
                knownConflicts.add(conflictKey);
              }
            }
          } else {
            // Never confirmed dark — this pick was wrong (something legitimately uses it).
            (await db.prepare('DELETE FROM arp_canary_ips WHERE device_id=? AND ip_address=?').run(deviceId, row.ip_address));
          }
        } else if (!row.confirmed_at) {
          const streak = (row.consecutive_dark_scans || 0) + 1;
          (await db.prepare('UPDATE arp_canary_ips SET consecutive_dark_scans=?, confirmed_at=? WHERE device_id=? AND ip_address=?')
            .run(streak, streak >= CANARY_CONFIRM_STREAK ? now : null, deviceId, row.ip_address));
        }
        // confirmed_at already set and still dark this scan: no-op, stays confirmed.
      }
    }
  }
  for (const e of events) {
    (await db.prepare('INSERT INTO arp_events (device_id,event_type,mac_address,ip_address,prior_value,timestamp) VALUES (?,?,?,?,?,?)')
      .run(deviceId, e.event_type, e.mac_address, e.ip_address, e.prior_value, now));
  }
  // Possible spoofing — notify the owner IMMEDIATELY, not on the daily-rate-limited AI-summary
  // cadence (that's a separate, opt-in, once/day report; this is an instant, opt-out security
  // alert — same 'category' gating as geofence/offline/capture, see USER_ALERT_CATEGORIES).
  const spoofEvents = events.filter(e => e.event_type === 'mac_changed_for_ip');
  if (spoofEvents.length) {
    try {
      const { ownerUserId } = (await deviceOwnerInfo(deviceId));
      if (ownerUserId) {
        const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
        const deviceName = (devRow && decryptText(devRow.name)) || deviceId;
        const lines = spoofEvents.map(e => `${e.ip_address} is now ${e.mac_address} (was ${e.prior_value})`);
        await notifyUser(ownerUserId,
          `⚠️ Possible network spoofing detected\nDevice: ${deviceName}\nTime: ${new Date(now).toLocaleTimeString()}\n\n${lines.join('\n')}`,
          { category: 'arp_spoof', deviceId });
      }
    } catch (e) { log('warn', 'ARP spoof alert failed', { deviceId, err: e.message }); }
  }
  // Canary hit — same instant-alert treatment as spoofing, shared 'arp_recon' category (distinct
  // from 'arp_spoof' per explicit request — these are both "possible unauthorized device" signals
  // but the user wanted them toggle-able separately from the mac-flip-flop spoof alert).
  let canaryHitEvents = events.filter(e => e.event_type === 'canary_hit');
  if (canaryHitEvents.length) {
    try {
      // Learn Mode — keyed by the MAC that answered a monitored dark-space IP. A device that
      // legitimately lives on a canary address (a bad canary pick that survived confirmation)
      // is exactly the kind of standing false positive this is for.
      const keptCanary = [];
      for (const e of canaryHitEvents) {
        if (await learnGate(deviceId, 'arp_recon', 'canary_hit', `canary_hit:${e.mac_address}`,
          `${e.mac_address} answering monitored IP ${e.ip_address}`)) continue;
        keptCanary.push(e);
      }
      canaryHitEvents = keptCanary;
      const { ownerUserId } = (await deviceOwnerInfo(deviceId));
      if (canaryHitEvents.length && ownerUserId) {
        const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
        const deviceName = (devRow && decryptText(devRow.name)) || deviceId;
        const lines = canaryHitEvents.map(e => `${e.ip_address} is now used by ${e.mac_address} — this address is monitored and should never be in use`);
        await notifyUser(ownerUserId,
          `⚠️ Unexpected device on a monitored empty IP address\nDevice: ${deviceName}\nTime: ${new Date(now).toLocaleTimeString()}\n\n${lines.join('\n')}`,
          { category: 'arp_recon', deviceId });
      }
    } catch (e) { log('warn', 'ARP canary alert failed', { deviceId, err: e.message }); }
  }
  return { newCount: events.filter(e => e.event_type === 'new_device').length, events };
}

return {
  ingestArpScanResult,
};
};
