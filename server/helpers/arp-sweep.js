// helpers/arp-sweep.js - ARP sweep event ingestion (drained, not diffed).
//
// A HELPER module, not a route module: it registers nothing.
//
// flattenSweepEvents stays PRIVATE - its only caller is ingestArpSweepEvents
// below it. ingestArpSweepEvents is the export: the sweep worker poller calls it.
//
// ctx is available at this module's own position in server.js -- no binding had
// to move. ARP_SWEEP_ALERT_SUPPRESS_MS is declared on the line immediately above
// the require; db and notifyUser are module-scope bindings far above; and
// decryptText, log, deviceOwnerInfo and learnGate are `function` declarations
// that hoist above their source position.

module.exports = ({ ARP_SWEEP_ALERT_SUPPRESS_MS, db, decryptText, deviceOwnerInfo, learnGate, log, notifyUser }) => {
// The on-box PowerShell 5.1 sweep loop accumulates its queue.json by re-reading + re-serializing,
// and ConvertTo-Json's depth handling can wrap real event objects inside nested {value:[...],Count:N}
// containers (a 5.1 serializer artifact — confirmed live 2026-07-18: the drain returned
// `events:[{value:[...],Count:2}]` with no top-level mac, so every event was silently skipped and
// zero arp_sweep rows were ever ingested despite detection working perfectly on-box). Recursively
// unwrap those containers so the real events (any object carrying a mac + targetCount) are recovered
// regardless of how deeply the on-box serializer buried them. Defense-in-depth alongside the on-box
// loop's own flat-write fix — an already-registered box keeps producing the old nested format until
// its watch is re-registered, so the server must tolerate both shapes.
function flattenSweepEvents(input, out = [], depth = 0) {
  if (depth > 12 || out.length > 1000) return out;
  for (const e of (Array.isArray(input) ? input : [input])) {
    if (!e || typeof e !== 'object') continue;
    if (e.mac && e.targetCount) { out.push(e); continue; }
    if (Array.isArray(e.value)) flattenSweepEvents(e.value, out, depth + 1);
  }
  return out;
}
async function ingestArpSweepEvents(deviceId, sweepEvents) {
  if (!Array.isArray(sweepEvents) || !sweepEvents.length) return;
  sweepEvents = flattenSweepEvents(sweepEvents);
  if (!sweepEvents.length) return;
  const now = Date.now();
  const alertedThisBatch = new Set();
  const toAlert = [];
  for (const e of sweepEvents) {
    const normMac = String(e?.mac || '').trim().toLowerCase().replace(/-/g, ':');
    if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(normMac)) continue;
    const targets = Array.isArray(e.sampleTargets) ? e.sampleTargets.filter(Boolean) : [];
    const targetCount = Number(e.targetCount) || targets.length;
    const firstTarget = targets[0] || '';
    const priorValue = `targets=${targetCount} sample=${targets.slice(0, 8).join(',')}`;
    const ts = Date.parse(e.windowEnd || e.windowStart || '') || now;
    (await db.prepare('INSERT INTO arp_events (device_id,event_type,mac_address,ip_address,prior_value,timestamp) VALUES (?,?,?,?,?,?)')
      .run(deviceId, 'arp_sweep', normMac, firstTarget, priorValue, ts));
    if (alertedThisBatch.has(normMac)) continue;
    const recent = (await db.prepare(
      "SELECT MAX(timestamp) AS t FROM arp_events WHERE device_id=? AND event_type='arp_sweep' AND mac_address=? AND timestamp<?"
    ).get(deviceId, normMac, ts));
    if (recent?.t && (ts - recent.t) < ARP_SWEEP_ALERT_SUPPRESS_MS) continue;
    alertedThisBatch.add(normMac);
    toAlert.push({ mac: normMac, targetCount });
  }
  if (!toAlert.length) return;
  try {
    // "Trust this device" / "Authorized scanner" (arp_neighbors.trusted, set via the roster's
    // toggle) — the arp_events row above is ALWAYS recorded regardless (full audit history,
    // visible in the roster/AI summary), only the notifyUser() page is suppressed here.
    // Owner-scoped: the trust flag is stored in whichever device's roster the MAC actually
    // appeared in (normally the single always-on PC that runs the scheduled scan), while ARP
    // Sweep Detection can run on ANY of the owner's devices — a detection-only PC has no roster
    // of its own, so a device-local lookup would miss the owner's own trusted scanner and keep
    // paging. The lookup therefore pulls trusted MACs from every device under the same
    // owner_user_id; the `an.device_id = ?` clause keeps an unowned/admin-fleet device's own
    // trust working exactly as before when ownerUserId is null (NULL never matches the owner
    // clause, degrading to device-local).
    const { ownerUserId } = (await deviceOwnerInfo(deviceId));
    const trustedRows = (await db.prepare(`SELECT an.mac_address FROM arp_neighbors an
      JOIN devices d ON d.id = an.device_id
      WHERE an.trusted=1 AND (d.owner_user_id = ? OR an.device_id = ?)`).all(ownerUserId ?? null, deviceId));
    const trustedMacs = new Set(trustedRows.map(r => r.mac_address));
    // Suppress the page for a sweep sourced from ANOTHER MANAGED DEVICE in the same account —
    // that is our own Network Discovery scan, not an intruder. A managed sibling's scan and a
    // hostile scan are byte-identical on the wire (both ARP the whole subnet), so identity is the
    // only sound discriminator; raising the ≥15-target threshold would blind the detector to real
    // sweeps instead. Found live 2026-08-03: the test VM flagged its neighbour 192.168.1.21's own
    // scheduled scan as a 246-target sweep — with arp_recon default-ON, every pair of managed
    // devices sharing a LAN would page each other on every scan interval.
    // Deliberately alert-only, exactly like the `trusted` flag above: the arp_events row is still
    // written unconditionally, so the roster/AI summary keep the full audit history.
    // Scoped to the SAME OWNER — a MAC belonging to some other customer's device is not something
    // this owner should be told to ignore.
    // Includes THIS device's own MACs, not just siblings'. pktmon captures the local adapter in
    // both directions, so a box sees its OWN scheduled Network Discovery scan as a ~250-target
    // sweep and pages on itself. The original query said `sm.device_id <> ?`, which excluded
    // exactly that case — confirmed live 2026-08-03: a box reported sweeps from a MAC that never
    // appears in its own arp_neighbors roster (a host never ARPs itself), i.e. its own.
    // Self-suppression is deliberately NOT gated on ownerUserId — an unowned/admin-fleet device's
    // own scan is still its own — so `sm.device_id = ?` stands alone and the same-owner sibling
    // clause is OR'd on top (a null ownerUserId simply never matches, degrading to self-only).
    let siblingMacs = new Set();
    try {
      const rows = (await db.prepare(`SELECT sm.mac_address AS mac FROM device_self_macs sm
        JOIN devices d ON d.id = sm.device_id
        WHERE sm.device_id = ? OR d.owner_user_id = ?`).all(deviceId, ownerUserId ?? null));
      siblingMacs = new Set(rows.map(r => String(r.mac || '').toLowerCase()));
    } catch (e) { log('warn', 'self/sibling MAC lookup failed', { deviceId, error: e.message }); }
    let unsuppressed = toAlert.filter(a => !trustedMacs.has(a.mac) && !siblingMacs.has(a.mac));
    if (toAlert.length !== unsuppressed.length) {
      log('info', 'ARP sweep alert(s) suppressed — source is a managed device or a trusted scanner',
        { deviceId, suppressed: toAlert.length - unsuppressed.length });
    }
    // Learn Mode — keyed by source MAC, so "this scanner is normal here" is exactly what gets
    // learned. Runs AFTER the trusted/sibling filters so the baseline never fills up with
    // signatures those already handle.
    const afterLearn = [];
    for (const a of unsuppressed) {
      if (await learnGate(deviceId, 'arp_recon', 'arp_sweep', `arp_sweep:${a.mac}`,
        `${a.mac} swept ${a.targetCount}+ addresses`)) continue;
      afterLearn.push(a);
    }
    unsuppressed = afterLearn;
    if (!unsuppressed.length) return;
    if (ownerUserId) {
      const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
      const deviceName = (devRow && decryptText(devRow.name)) || deviceId;
      const lines = unsuppressed.map(a => `${a.mac} sent ARP "who has" requests for ${a.targetCount}+ addresses in a few seconds — likely a network scan (e.g. Nmap)`);
      await notifyUser(ownerUserId,
        `⚠️ Possible network scanning detected\nDevice: ${deviceName}\nTime: ${new Date(now).toLocaleTimeString()}\n\n${lines.join('\n')}`,
        { category: 'arp_recon', deviceId });
    }
  } catch (e) { log('warn', 'ARP sweep alert failed', { deviceId, err: e.message }); }
}

return {
  ingestArpSweepEvents,
};
};
