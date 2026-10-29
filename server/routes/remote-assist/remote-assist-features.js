// routes/remote-assist/remote-assist-features.js — Auto-start, status, IT audit, forensics, appcontrol, winupdate, telemetry, sentry, USB lockdown, defender, EDR, arp-scan, boot-iso.
// Extracted from server.js L5443-6166. ~724 lines, ~40 routes.
const express = require('express');
module.exports = ({ app, db, emitToDevice, ingestArpScanResult, log, requireAuth, requireAdmin, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, setSentryEnabled, setScreenTextEnabled, setUsbLockdownEnabled, setWinUpdateForceActive }) => {
const OTA_PUBLIC_URL = process.env.OTA_PUBLIC_URL || '';

app.get('/api/devices/:id/remote-assist/auto', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const row = await db.prepare("SELECT value FROM settings WHERE key=?").get('ra_auto:' + req.params.id);
  res.json({ auto: row?.value === '1' });
});
app.post('/api/devices/:id/remote-assist/auto', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const enabled = req.body?.auto === true || req.body?.auto === '1' || req.body?.auto === 1;
  if (enabled) {
    await db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value").run('ra_auto:' + req.params.id, '1');
  } else {
    await db.prepare("DELETE FROM settings WHERE key=?").run('ra_auto:' + req.params.id);
  }
  log('info', 'Remote-assist auto-start ' + (enabled ? 'enabled' : 'disabled'), { deviceId: req.params.id });
  res.json({ ok: true, auto: enabled });
});

app.get('/api/devices/:id/remote-assist/status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.sessionStatus(req.params.id))); }
  catch (e) { res.status(502).json({ error: 'Failed to reach bastion bridge' }); }
});

// IT Mode Audit (malware/inventory scan) — full detail for the Reverse Tunnel tab. Always a live
// (uncached) bastion read, unlike the /api/devices list's cached enrichment — this route is only
// hit when the tab is actually open, not on every dashboard poll, so there's no hot-path reason to
// serve stale data here.
app.get('/api/devices/:id/remote-assist/it-audit/status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json({ ok: true, ...(await bastionClient.sessionAuditLive(req.params.id)) }); }
  catch (e) { res.status(502).json({ ok: false, error: 'Failed to reach bastion bridge' }); }
});

// Manual "Run Check Now" — starts a fresh audit for THIS device only (never the whole fleet).
// Fire-and-poll: this returns as soon as the bastion has accepted/started the run (or, if the
// audit happens to complete within the request, its immediate result) — the dashboard polls
// it-audit/status same as the AppLocker audit flow to watch it land.
app.post('/api/devices/:id/remote-assist/it-audit/run', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.runAudit(req.params.id))); }
  catch (e) {
    const msg = e.bastionError || e.message || 'Audit trigger failed';
    res.status(502).json({ ok: false, error: msg });
  }
});

app.post('/api/devices/:id/remote-assist/it-audit/invalidate-cache', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  bastionClient.invalidateAuditCache(req.params.id);
  res.json({ ok: true });
});

app.get('/api/devices/:id/remote-assist/it-audit/schedule', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.getAuditSchedule(req.params.id));
    if (result && result.ok && result.minutes !== undefined) {
      // Mirror the schedule locally so the dashboard can read it even if the bastion is down.
      try { (await db.prepare(
        "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).run(`audit_schedule:${req.params.id}`, String(result.minutes))); } catch (_) {}
      try { (await db.prepare(
        "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).run(`audit_schedule_entries:${req.params.id}`, JSON.stringify(result.entries || []))); } catch (_) {}
      try { (await db.prepare(
        "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).run(`audit_schedule_tz:${req.params.id}`, result.tz || 'UTC')); } catch (_) {}
    }
    res.json(result);
  } catch (e) {
    // Bastion unreachable — fall back to the last-known local copy.
    try {
      const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get(`audit_schedule:${req.params.id}`));
      const minutes = row ? parseInt(row.value, 10) || 0 : 0;
      let entries = [];
      try {
        const rowE = (await db.prepare("SELECT value FROM settings WHERE key=?").get(`audit_schedule_entries:${req.params.id}`));
        if (rowE && rowE.value) entries = JSON.parse(rowE.value) || [];
      } catch (_) {}
      const rowT = (await db.prepare("SELECT value FROM settings WHERE key=?").get(`audit_schedule_tz:${req.params.id}`));
      res.json({ ok: true, minutes, hours: Math.floor(minutes / 60), entries, tz: rowT?.value || 'UTC' });
    } catch (_) { res.status(502).json({ ok: false, error: 'Failed to reach bastion bridge' }); }
  }
});

// Two mutually exclusive modes (mirroring the bastion route): exact-times {entries, tz} — entries
// is a list of {time: "HH:MM", days: [0..6]}, 0=Sun..6=Sat, empty days = every day, max 8, tz an
// IANA zone name — or {clear: true} to remove the schedule (manual-only). Legacy {minutes} (0 =
// manual-only, otherwise re-audits every N minutes) still accepted for pre-2026-08 dashboard
// builds; back-compat {hours} also accepted (hours*60). Saving one clears the other.
const AUDIT_TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

function auditScheduleEntriesError(entries) {
  if (!Array.isArray(entries) || !entries.length) return 'schedule must be a non-empty list of times';
  if (entries.length > 8) return 'max 8 scheduled times per device';
  const seen = new Set();
  for (const e of entries) {
    if (!e || typeof e !== 'object' || !AUDIT_TIME_RE.test(String(e.time || ''))) return `invalid time ${JSON.stringify(e?.time)} (expected HH:MM, e.g. 03:00)`;
    const days = e.days === undefined ? [0, 1, 2, 3, 4, 5, 6] : e.days;
    if (!Array.isArray(days) || !days.length || days.some(d => !Number.isInteger(d) || d < 0 || d > 6)) {
      return `invalid days for ${e.time} (must be a list of 0=Sun..6=Sat; empty = every day, 1-7 entries)`;
    }
    seen.add(`${e.time}:${[...days].sort((a, b) => a - b).join(',')}`);
  }
  return null;
}

app.post('/api/devices/:id/remote-assist/it-audit/schedule', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  if (req.body?.clear !== undefined || Array.isArray(req.body?.entries)) {
    const entries = req.body.clear ? [] : req.body.entries;
    const err = entries.length ? auditScheduleEntriesError(entries) : null;
    if (err) return res.status(400).json({ ok: false, error: err });
    const tz = typeof req.body.tz === 'string' ? req.body.tz.slice(0, 64) : '';
    // Persist locally so the schedule survives a bastion restart.
    try { (await db.prepare(
      "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
    ).run(`audit_schedule_entries:${req.params.id}`, JSON.stringify(entries))); } catch (_) {}
    try { (await db.prepare(
      "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
    ).run(`audit_schedule:${req.params.id}`, '0')); } catch (_) {}
    if (tz) {
      try { (await db.prepare(
        "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
      ).run(`audit_schedule_tz:${req.params.id}`, tz)); } catch (_) {}
    } else {
      try { (await db.prepare("DELETE FROM settings WHERE key=?").run(`audit_schedule_tz:${req.params.id}`)); } catch (_) {}
    }
    try { res.json((await bastionClient.setAuditSchedule(req.params.id, { entries, tz }))); }
    catch (e) { res.status(502).json({ ok: false, error: 'Failed to reach bastion bridge' }); }
    return;
  }
  let minutes;
  if (req.body?.minutes !== undefined) {
    minutes = parseInt(req.body.minutes, 10);
  } else {
    const hours = parseFloat(req.body?.hours);
    minutes = Number.isFinite(hours) ? Math.round(hours * 60) : NaN;
  }
  if (!Number.isFinite(minutes) || minutes < 0 || minutes > 10080) {
    return res.status(400).json({ ok: false, error: 'minutes must be between 0 (manual-only) and 10080' });
  }
  // Persist locally so the schedule survives a bastion restart.
  try { (await db.prepare(
    "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).run(`audit_schedule:${req.params.id}`, String(minutes))); } catch (_) {}
  try { (await db.prepare(
    "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value"
  ).run(`audit_schedule_entries:${req.params.id}`, '[]')); } catch (_) {}
  try { (await db.prepare("DELETE FROM settings WHERE key=?").run(`audit_schedule_tz:${req.params.id}`)); } catch (_) {}
  try { res.json((await bastionClient.setAuditSchedule(req.params.id, { minutes }))); }
  catch (e) { res.status(502).json({ ok: false, error: 'Failed to reach bastion bridge' }); }
});

// "Nuke" — act on (and/or mark-safe) a subset of the LAST STORED IT-audit's findings. The browser
// only ever sends back the exact finding TEXT it displayed (never a remediation type/target) —
// the bastion looks up what that finding's own already-validated remediation actually is and acts
// on THAT, so a compromised/buggy browser can at most ask to act on something that was genuinely
// a real finding from the last real audit. See remediate_audit_findings()'s doc comment.
app.post('/api/devices/:id/remote-assist/it-audit/remediate', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const removeTexts = Array.isArray(req.body?.removeTexts) ? req.body.removeTexts.map(String) : [];
  const safeTexts = Array.isArray(req.body?.safeTexts) ? req.body.safeTexts.map(String) : [];
  if (!removeTexts.length && !safeTexts.length) return res.status(400).json({ ok: false, error: 'removeTexts or safeTexts required' });
  try { res.json((await bastionClient.remediateAuditFindings(req.params.id, removeTexts, safeTexts))); }
  catch (e) {
    const msg = e.bastionError || e.message || 'Remediation failed';
    log('warn', 'Remote-assist IT-audit remediate failed', { deviceId: req.params.id, error: msg });
    res.status(502).json({ ok: false, error: msg });
  }
});

// Download-for-inspection — path must be an evidence_file value from the last stored audit's
// findings (re-validated bastion-side); returns base64 content capped at 100MB.
app.post('/api/devices/:id/remote-assist/it-audit/fetch-file', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const path = (req.body?.path || '').toString();
  if (!path) return res.status(400).json({ ok: false, error: 'path required' });
  try { res.json((await bastionClient.fetchAuditFile(req.params.id, path))); }
  catch (e) {
    const msg = e.bastionError || e.message || 'File fetch failed';
    log('warn', 'Remote-assist IT-audit fetch-file failed', { deviceId: req.params.id, error: msg });
    res.status(502).json({ ok: false, error: msg });
  }
});

app.post('/api/devices/:id/remote-assist/forensics', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.runForensics(req.params.id, req.body?.kind || 'all'))); }
  catch (e) {
    const msg = e.bastionError || e.message || 'Forensics collection failed';
    log('warn', 'Remote-assist forensics failed', { deviceId: req.params.id, error: msg });
    res.status(502).json({ error: msg, bastionError: e.bastionError || null, detail: e.message || '' });
  }
});
app.get('/api/devices/:id/remote-assist/forensics-full', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.forensicsFull(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Failed to fetch forensics results' }); }
});
// Cached single-category read (no Hop-2 round trip, no re-collect) — powers the per-category tab
// view showing whatever was last collected the moment its tab is opened, same as the bastion
// WebUI's own forensics explorer. :kind is validated bastion-side against FORENSICS_KINDS.
app.get('/api/devices/:id/remote-assist/forensics/:kind', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.forensicsKind(req.params.id, req.params.kind))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Failed to fetch cached forensics' }); }
});
// Cheap poll target for "Collect All" (kind:"all" on the route above is fire-and-forget bastion-side
// — see bastionClient.forensicsFullMeta's doc comment). 404 (no pack yet) is a normal, expected
// response before the very first collection ever completes — not an error worth logging.
app.get('/api/devices/:id/remote-assist/forensics-full/meta', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.forensicsFullMeta(req.params.id))); }
  catch (e) { res.status(e.status === 404 ? 404 : 502).json({ error: e.bastionError || e.message || 'Failed to fetch pack metadata' }); }
});

// Live view-only screen share for Linux (sentineld) devices — see bastionClient.screenviewStart's
// doc comment. Replaces the old single-shot '/remote-assist/snapshot' route (removed 2026-07-29,
// Windows-only, redundant with Windows' existing interactive Live Desktop stream).
app.post('/api/devices/:id/remote-assist/screenview/start', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.screenviewStart(req.params.id)); }
  catch (e) {
    const msg = e.bastionError || e.message || 'Failed to start live view';
    log('warn', 'Remote-assist screenview start failed', { deviceId: req.params.id, error: msg });
    res.status(502).json({ error: msg, bastionError: e.bastionError || null });
  }
});
app.post('/api/devices/:id/remote-assist/screenview/stop', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.screenviewStop(req.params.id)); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Failed to stop live view' }); }
});
// Long-lived MJPEG (multipart/x-mixed-replace) proxy — piped straight through, never buffered
// (same Readable.fromWeb(...).pipe(res) pattern as /api/remote-assist/download above). Stopping
// the bastion-side Hop-2 process on the request's own 'close' event (browser tab closed, Live
// Desktop tab switched away, page navigated away) is a safety net independent of the dashboard's
// own explicit screenview/stop call — either one alone is enough to avoid an orphaned capture
// process on the remote box.
app.get('/api/devices/:id/remote-assist/screenview/stream', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const bastionRes = await bastionClient.streamScreenviewResponse(req.params.id);
    res.setHeader('Content-Type', bastionRes.headers.get('content-type') || 'multipart/x-mixed-replace');
    res.setHeader('Cache-Control', 'no-store');
    req.on('close', () => { bastionClient.screenviewStop(req.params.id).catch(() => {}); });
    const { Readable } = require('node:stream');
    Readable.fromWeb(bastionRes.body).pipe(res).on('error', (err) => {
      log('warn', 'remote-assist screenview stream error', { err: err.message });
      res.destroy();
    });
  } catch (e) {
    res.status(502).json({ error: e.bastionError || e.message || 'Failed to reach bastion' });
  }
});

app.post('/api/devices/:id/remote-assist/appcontrol/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.appControl(req.params.id, req.params.action, req.body || {}));
    // Same stale -L-forward issue as EDR enable above (TunnelRunner.cs's AppControlConfig is only
    // read when the ssh.exe argv is built) — ask the agent to restart its own tunnel directly so an
    // already-connected device doesn't wait for a natural reconnect. No bastion-side kick exists here
    // (never added for this feature) — this is purely additive, not a replacement.
    if (req.params.action === 'enable' && result?.ok) {
      emitToDevice(req.params.id, 'command', { command: 'restart_ra_tunnel' });
    }
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control action failed' }); }
});
app.get('/api/devices/:id/remote-assist/appcontrol-status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.appControlStatus(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control status fetch failed' }); }
});
app.get('/api/devices/:id/remote-assist/appcontrol-events', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.appControlEvents(req.params.id, req.query || {}))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control events fetch failed' }); }
});

// Linux Application Control (fapolicyd) — see bastionClient.linuxAppControlStatus's doc comment.
// A distinct set of routes from the Windows AppLocker ones above (different underlying mechanism,
// no per-app approval queue) rather than overloading the same :action param.

// ── App Control capability fallback for an out-of-date agent wrapper ────────────────────────────
//
// ⚠️ Why this exists: `appcontrol_supported` only landed in appcontrol-deploy.sh on 2026-09-30,
// and the Linux agent's self-update fetches ONLY the sentineld BINARY — nothing refreshes an
// already-installed wrapper. Without this fallback every pre-existing box reports no verdict
// forever, and the dashboard cannot distinguish "this distro has no fapolicyd package" (Arch)
// from "this agent is too old to say". Those need OPPOSITE handling: hiding on the latter silently
// removes a working feature from every Debian/Ubuntu box in the fleet, while showing on the former
// leaves four buttons that can only fail.
//
// The probe reports FACTS ONLY (distro id + which package managers exist). The verdict is derived
// here by the same rule appcontrol-deploy.sh's detect_appcontrol_support() applies, and that
// wrapper stays authoritative for any box whose agent answers for itself — this only runs when it
// doesn't. Runs over the bastion's pre-existing bash route, so no bastion change is needed.
const APPCONTROL_PROBE_SCRIPT = `pm=none
command -v apt-get >/dev/null 2>&1 && pm=apt
[ "$pm" = none ] && command -v pacman >/dev/null 2>&1 && pm=pacman
[ "$pm" = none ] && command -v dnf >/dev/null 2>&1 && pm=dnf
distro=unknown
if [ -r /etc/os-release ]; then
  distro=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -1 | tr -d '" \\r')
  [ -n "$distro" ] || distro=unknown
fi
printf '{"distro":"%s","pkg_manager":"%s"}\\n' "$distro" "$pm"
`;

const APPCONTROL_UNSUPPORTED_REASON =
  'fapolicyd is not available in any official Arch repository, and this agent will not build it from the AUR automatically. App Control cannot be enabled on this host.';
const APPCONTROL_NO_PM_REASON =
  'No supported package manager for fapolicyd was found on this host (looked for apt-get and dnf).';

// Mirrors detect_appcontrol_support()'s case statement: apt/dnf => installable, everything else
// (pacman-only, or nothing recognisable) => not. Deliberately fails to "unsupported" so an
// unidentifiable host gets no buttons rather than buttons that would only error.
function appControlVerdictFromFacts(pm) {
  if (pm === 'apt' || pm === 'dnf') return { appcontrol_supported: true, appcontrol_reason: '' };
  if (pm === 'pacman') {
    return { appcontrol_supported: false, appcontrol_reason: APPCONTROL_UNSUPPORTED_REASON };
  }
  return { appcontrol_supported: false, appcontrol_reason: APPCONTROL_NO_PM_REASON };
}

// Cached because a box genuinely mid-first-run ("starting", building its trust DB) is polled every
// 5s by the dashboard, and an uncached fallback would double those Hop-2 round trips for minutes.
const _appControlCapabilityCache = new Map();   // deviceId -> { at, patch }
const APPCONTROL_CAPABILITY_TTL_MS = 5 * 60 * 1000;

async function appControlStatusWithFallback(bastionClient, deviceId) {
  const status = await bastionClient.linuxAppControlStatus(deviceId);
  // A wrapper that answers for itself always wins — never second-guess the agent.
  if (!status || typeof status !== 'object' || !status.ok) return status;
  if ('appcontrol_supported' in status) return status;

  const hit = _appControlCapabilityCache.get(deviceId);
  if (hit && Date.now() - hit.at < APPCONTROL_CAPABILITY_TTL_MS) {
    return { ...status, ...hit.patch };
  }

  try {
    const probe = await bastionClient.sessionBash(deviceId, APPCONTROL_PROBE_SCRIPT, 20);
    const line = String(probe?.stdout || '')
      .split('\n').map(l => l.trim()).filter(l => l.startsWith('{')).pop();
    if (probe?.ok && line) {
      const facts = JSON.parse(line);
      if (facts && typeof facts.pkg_manager === 'string') {
        const patch = {
          distro: typeof facts.distro === 'string' ? facts.distro : 'unknown',
          pkg_manager: facts.pkg_manager,
          ...appControlVerdictFromFacts(facts.pkg_manager),
          appcontrol_probe: 'server-fallback',   // distinguishable from the wrapper's own answer
        };
        _appControlCapabilityCache.set(deviceId, { at: Date.now(), patch });
        log('info', 'App Control capability resolved by server fallback (agent wrapper predates the field)',
          { deviceId, pkgManager: facts.pkg_manager, distro: patch.distro });
        return { ...status, ...patch };
      }
    }
  } catch (e) {
    // Non-fatal by design: the dashboard resolves an un-enriched response to its explicit 'stale'
    // state (tab kept, enable buttons disabled). Never let a probe failure break the status route.
    log('warn', 'App Control capability fallback probe failed', { deviceId, error: e.message });
  }
  return status;
}

app.get('/api/devices/:id/remote-assist/appcontrol-linux/status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await appControlStatusWithFallback(bastionClient, req.params.id)); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control status fetch failed' }); }
});
app.post('/api/devices/:id/remote-assist/appcontrol-linux/enable', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.linuxAppControlEnable(req.params.id, req.body?.mode)); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control enable failed' }); }
});
app.post('/api/devices/:id/remote-assist/appcontrol-linux/disable', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.linuxAppControlDisable(req.params.id)); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control disable failed' }); }
});
app.get('/api/devices/:id/remote-assist/appcontrol-linux/events', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const n = parseInt(String(req.query?.n || '200'), 10) || 200;
  try { res.json(await bastionClient.linuxAppControlEvents(req.params.id, n)); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control events fetch failed' }); }
});
app.post('/api/devices/:id/remote-assist/appcontrol-linux/approve', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.linuxAppControlApprove(req.params.id, String(req.body?.path || ''))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control approve failed' }); }
});
app.post('/api/devices/:id/remote-assist/appcontrol-linux/approve-many', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const paths = Array.isArray(req.body?.paths) ? req.body.paths.map(p => String(p)) : [];
  try { res.json(await bastionClient.linuxAppControlApproveMany(req.params.id, paths)); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control bulk approve failed' }); }
});

// ⚠️ These three were MISSING entirely — the dashboard (app.js raAppControlLinuxExcludeFolder /
// RefreshExcludedFolders / RemoveFolder), bastionClient.js, and the bastion router itself
// (bastion-web.py appcontrol-linux/{exclude-folder,excluded-folders,remove-folder}) all existed,
// but no Express route forwarded them, so Express fell through to its catch-all 404 handler.
// Symptom: clicking "Exclude Folder" rendered a bare literal "HTTP 404" next to the Disable
// button — that red text lands in #ra-appcontrol-linux-op-status, the SHARED status span sitting
// in the same flex row as the Disable button (index.html ~L3194), which is why the error looked
// like it belonged to Disable. The message is bare "HTTP 404" with no server text because
// apiFetchJSON() only surfaces a server error body when the response is JSON; Express's default
// 404 body is HTML, so it falls back to `HTTP ${r.status}`.
// Note longRunning: true is already set inside bastionClient.linuxAppControlExcludeFolder (the
// exclude walk can hash a whole directory tree, well past the default undici timeout) — the
// route must NOT override it.
app.post('/api/devices/:id/remote-assist/appcontrol-linux/exclude-folder', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.linuxAppControlExcludeFolder(req.params.id, String(req.body?.path || ''))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control exclude folder failed' }); }
});
app.get('/api/devices/:id/remote-assist/appcontrol-linux/excluded-folders', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.linuxAppControlExcludedFolders(req.params.id)); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control excluded-folders fetch failed' }); }
});
app.post('/api/devices/:id/remote-assist/appcontrol-linux/remove-folder', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json(await bastionClient.linuxAppControlRemoveFolder(req.params.id, String(req.body?.path || ''))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'App-control remove folder failed' }); }
});

app.post('/api/devices/:id/remote-assist/winupdate/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.winUpdate(req.params.id, req.params.action, req.body || {}));
    // Same stale -L-forward issue as EDR/AppControl enable above (TunnelRunner.cs's WinUpdateConfig
    // is only read when the ssh.exe argv is built) — 'enable' here is the managed scan/approve
    // feature, distinct from the block/unblock total-disable kill-switch which needs no tunnel
    // restart (pure Hop-2 PS, no report channel).
    if (req.params.action === 'enable' && result?.ok) {
      emitToDevice(req.params.id, 'command', { command: 'restart_ra_tunnel' });
    }
    // Force-Update-Now catch-up cycle — track active state so the 60s poller below only pays
    // for a bastion round trip on devices that actually have a cycle running. The scheduled
    // security cycle ("security-schedule") arms the poller on set / disarms on clear, since its
    // on-device runs never ride a POST.
    if (req.params.action === 'force-start' && result?.ok) (await setWinUpdateForceActive(req.params.id, true));
    if (req.params.action === 'security-start' && result?.ok) (await setWinUpdateForceActive(req.params.id, true));
    if (req.params.action === 'security-schedule' && result?.ok) (await setWinUpdateForceActive(req.params.id, !(req.body || {}).clear));
    if (req.params.action === 'force-cancel' && result?.ok) (await setWinUpdateForceActive(req.params.id, false));
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Windows-Update action failed' }); }
});
app.get('/api/devices/:id/remote-assist/winupdate-status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.winUpdateStatus(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Windows-Update status fetch failed' }); }
});
app.get('/api/devices/:id/remote-assist/winupdate-force-status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.winUpdateForceStatus(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Windows-Update force-status fetch failed' }); }
});
app.get('/api/devices/:id/remote-assist/winupdate-security-status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.winUpdateSecurityStatus(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Windows-Update security-status fetch failed' }); }
});
app.get('/api/devices/:id/remote-assist/winupdate-list', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.winUpdateList(req.params.id, req.query || {}))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Windows-Update list fetch failed' }); }
});

// Telemetry kill-switch (block/unblock/block-status) — action passthrough, same shape as the
// winupdate route above.
app.post('/api/devices/:id/remote-assist/telemetry/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.blockTelemetry(req.params.id, req.params.action, req.body || {}))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Telemetry action failed' }); }
});

// Sentry Mode — endpoint honeypot (enable / disable / status). Action passthrough.
app.post('/api/devices/:id/remote-assist/sentry/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const action = req.params.action;
    if (action === 'enable') {
      const result = (await bastionClient.sentryEnable(req.params.id, req.body || {}));
      if (result?.ok) (await setSentryEnabled(req.params.id, true));
      res.json(result);
    } else if (action === 'disable') {
      const result = (await bastionClient.sentryDisable(req.params.id));
      if (result?.ok) (await setSentryEnabled(req.params.id, false));
      res.json(result);
    } else if (action === 'status') {
      res.json((await bastionClient.sentryStatus(req.params.id)));
    } else {
      res.status(400).json({ error: 'Unknown sentry action' });
    }
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Sentry action failed' }); }
});

// Screen Text Capture — UI Automation text extraction on Windows (enable / disable / status). Action passthrough.
app.post('/api/devices/:id/remote-assist/screentext/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const action = req.params.action;
    if (action === 'enable') {
      const result = (await bastionClient.screenTextEnable(req.params.id));
      if (result?.ok) (await setScreenTextEnabled(req.params.id, true));
      res.json(result);
    } else if (action === 'disable') {
      const result = (await bastionClient.screenTextDisable(req.params.id));
      if (result?.ok) (await setScreenTextEnabled(req.params.id, false));
      res.json(result);
    } else if (action === 'status') {
      res.json((await bastionClient.screenTextStatus(req.params.id)));
    } else {
      res.status(400).json({ error: 'Unknown screentext action' });
    }
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Screen text action failed' }); }
});

// USB Lockdown — USBGuard-style USB device control (enable / disable / status). Action passthrough.
app.post('/api/devices/:id/remote-assist/usblock/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const action = req.params.action;
    if (action === 'enable') {
      const result = (await bastionClient.usbLockdownEnable(req.params.id, req.body || {}));
      if (result?.ok) (await setUsbLockdownEnabled(req.params.id, true));
      res.json(result);
    } else if (action === 'disable') {
      const result = (await bastionClient.usbLockdownDisable(req.params.id));
      if (result?.ok) (await setUsbLockdownEnabled(req.params.id, false));
      res.json(result);
    } else if (action === 'status') {
      res.json((await bastionClient.usbLockdownStatus(req.params.id)));
    } else if (action === 'approve') {
      const instanceId = (req.body || {}).instanceId || '';
      const result = (await bastionClient.usbLockdownApprove(req.params.id, instanceId));
      if (result?.ok) {
        try {
          // vidPid comes back from the Linux agent (approved.txt key); Windows approves return it
          // as null — fine, the Linux-only Remove button matches on vid_pid.
          (await db.prepare('INSERT INTO usblock_approvals (device_id,instance_id,friendly_name,class,approved_at,vid_pid) VALUES (?,?,?,?,?,?)')
            .run(req.params.id, instanceId, (req.body || {}).friendlyName || null, (req.body || {}).deviceClass || null, Date.now(), result.vidPid || null));
        } catch (_) {}
      }
      res.json(result);
    } else if (action === 'blocked') {
      res.json((await bastionClient.usbLockdownBlocked(req.params.id)));
    } else if (action === 'approved') {
      // Linux-only: the persisted vid:pid approvals (approved.txt) — the actual allowlist source.
      res.json((await bastionClient.usbLockdownApproved(req.params.id)));
    } else if (action === 'remove') {
      // Linux-only: revoke a persisted approval by vid:pid — agent-side (approved.txt + rules) and
      // the matching server-side history rows (instance ids renumber on replug, vid_pid does not).
      const vidPid = (req.body || {}).vidPid || '';
      const result = (await bastionClient.usbLockdownRemove(req.params.id, vidPid));
      if (result?.ok && vidPid) {
        try { (await db.prepare('DELETE FROM usblock_approvals WHERE device_id=? AND vid_pid=?').run(req.params.id, vidPid)); } catch (_) {}
      }
      res.json(result);
    } else if (action === 'reprobe') {
      // Linux-only: software replug for an approved device whose drivers never bound.
      const instanceId = (req.body || {}).instanceId || '';
      res.json((await bastionClient.usbLockdownReprobe(req.params.id, instanceId)));
    } else {
      res.status(400).json({ error: 'Unknown usblock action' });
    }
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'USB lockdown action failed' }); }
});

// USB Lockdown — durable approval history (persisted in usblock_approvals, survives page refreshes).
app.get('/api/devices/:id/remote-assist/usblock/history', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  try {
    const rows = (await db.prepare('SELECT instance_id,friendly_name,class,approved_at,vid_pid FROM usblock_approvals WHERE device_id=? ORDER BY approved_at DESC LIMIT 100').all(req.params.id));
    res.json({ ok: true, approvals: rows });
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'USB lockdown history failed' }); }
});

// Defender exclusion — add/remove SentinelRemoteAssist folder from Windows Defender path
// exclusions + toggle automatic sample submission. Action passthrough, same shape as the
// telemetry route above.
app.post('/api/devices/:id/remote-assist/defender-exclusion/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.defenderExclusion(req.params.id, req.params.action, req.body || {}))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Defender exclusion action failed' }); }
});

// ── EDR (continuous behavioral telemetry) ─────────────────────────────────────
// Enable/disable the Sysmon-backed --edr-watch SYSTEM task (see enable_edr()/disable_edr() in
// bastion-web.py) + read accumulated rule-hit events. Cheap stored flag mirrors
// getArpSweepWatchEnabled()/setArpSweepWatchEnabled()'s pattern — lets the worker poller below
// skip a device without paying for a bastion round trip just to find out it's off.
async function getEdrEnabled(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('edr_enabled:' + deviceId));
  return !!row && row.value === 'enabled';
}
async function setEdrEnabled(deviceId, enabled) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('edr_enabled:' + deviceId, enabled ? 'enabled' : 'disabled'));
}
// Same cheap-local-flag idiom, for isolation status specifically. Unlike edr_enabled (which has
// TWO reliable sources — this flag AND bastion's own local edr_state.json file read), isolate
// status has NO reliable local source at all — edr_isolate_status() requires a LIVE Hop-2
// Get-NetFirewallProfile round trip every single call. Found live 2026-07-19: any hiccup in that
// round trip (bastion redeploy mid-request, transient network blip, Cloudflare proxy hiccup) was
// silently swallowed by the WebUI's .catch(()=>{}), leaving the button showing its default
// "not isolated" appearance — actively misleading if the device is REALLY still isolated. This
// flag is the fallback the status route now returns when the live check fails, instead of letting
// a transient failure look identical to "successfully confirmed not isolated."
async function getEdrIsolated(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('edr_isolated:' + deviceId));
  return !!row && row.value === 'isolated';
}
async function setEdrIsolated(deviceId, isolated) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('edr_isolated:' + deviceId, isolated ? 'isolated' : 'restored'));
}
// Per-device watermark (max `received_at` already alerted-on) so the poller below never re-fires
// an alert for an event it already processed on a prior tick — same watermark idiom used elsewhere
// in this file (e.g. ai_report_email_state's last_*_at columns) rather than re-deriving "new since
// last time" from a timestamp comparison at alert-time.
async function getEdrLastSeen(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('edr_last_seen:' + deviceId));
  return row ? (parseFloat(row.value) || 0) : 0;
}
async function setEdrLastSeen(deviceId, ts) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('edr_last_seen:' + deviceId, String(ts)));
}
// Alert-suppression window per (deviceId, rule) — same "one real finding = one page, not spam"
// principle as ARP_SWEEP_ALERT_SUPPRESS_MS: the FIRST high-severity finding of a given rule on a
// device pages immediately; further findings of the SAME rule within the window still land in the
// feed (nothing here touches ingestion) but don't re-page. Necessary because a single triggering
// action commonly produces multiple discrete Sysmon events for the same underlying condition
// (e.g. a nested PowerShell invocation logs a lineage hit at each level) — found live 2026-07-19
// when a handful of manual test invocations paged Signal once per event with zero suppression.
const EDR_ALERT_SUPPRESS_MS = 30 * 60 * 1000;
async function getEdrAlertSuppressedUntil(deviceId, rule) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get(`edr_alert_suppress:${deviceId}:${rule}`));
  return row ? (parseFloat(row.value) || 0) : 0;
}
async function setEdrAlertSuppressedUntil(deviceId, rule, until) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run(`edr_alert_suppress:${deviceId}:${rule}`, String(until)));
}

// bastion's POST .../edr/enable route is backgrounded — it acks {ok:true, status:'installing'}
// immediately, before the Sysmon deploy/provisioning (two chained Hop-2 scp+ssh round trips) even
// starts. Firing restart_ra_tunnel on THAT ack (as this route used to) kills the very Hop-1 tunnel
// the background deploy is scp'ing the Sysmon/provision scripts over, mid-transfer — surfaces on
// the dashboard as "could not deploy script: ssh: connect to host localhost port <N>: Connection
// refused / scp: Connection closed" and looks like clicking Enable EDR itself resets the tunnel
// (it does — just too early). Found live 2026-07-22. Fix: poll edr/events (which read_edr_state()
// rides along, see get_edr_events()'s doc comment) for enable_status actually reaching 'enabled'
// before restarting the tunnel.
async function pollAndRestartRaTunnelAfterEdrEnable(deviceId) {
  const bastionClient = require('../../bastionClient');
  // Sysmon deploy (90s budget) + provisioning (45s budget) + slack.
  const deadline = Date.now() + 150000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 3000));
    let ev;
    try { ev = (await bastionClient.edrEvents(deviceId, {})); } catch (e) {
      log('warn', 'EDR enable-poll failed', { deviceId, err: e.message });
      continue;
    }
    if (ev?.enable_status === 'enabled') {
      emitToDevice(deviceId, 'command', { command: 'restart_ra_tunnel' });
      return;
    }
    if (ev?.enable_status === 'failed') return; // enable failed — nothing to restart the tunnel for
  }
  log('warn', 'EDR enable-poll timed out waiting for enable_status=enabled', { deviceId });
}
app.post('/api/devices/:id/remote-assist/edr/enable', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.edrEnable(req.params.id, !!req.body?.force));
    if (result?.ok) {
      (await setEdrEnabled(req.params.id, true));
      // EDR's -L bastion-report forward is only decided when the Hop-1 ssh.exe argv is built, so an
      // already-connected tunnel needs a restart to pick up the fresh endpoint-config.json. This
      // REPLACES a bastion-side kill-ssh.exe-and-hope kick (bastion-web.py's enable_edr(), removed
      // 2026-07-22 after it left a device's tunnel down for 2+ minutes with no self-heal, live on
      // the test Windows host). Server.js holds the live control-channel socket, so it can ask the agent to
      // restart its own tunnel directly and reliably instead — see AccountLinkedSession.
      // TunnelRestartRequested's doc comment (client). No new key material, xray/control channel
      // untouched. Best-effort: a failure here does not fail the enable call (EDR is already
      // correctly running; reporting still self-heals on the next natural reconnect).
      pollAndRestartRaTunnelAfterEdrEnable(req.params.id);
    }
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR enable failed' }); }
});
app.post('/api/devices/:id/remote-assist/edr/disable', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.edrDisable(req.params.id));
    if (result?.ok) (await setEdrEnabled(req.params.id, false));
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR disable failed' }); }
});
app.get('/api/devices/:id/remote-assist/edr/events', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const data = (await bastionClient.edrEvents(req.params.id, req.query || {}));
    // Annotate admin-dismissed ("mark safe") events — server-side persistence keyed by the
    // bastion event id + rule, so the WebUI can hide them from the default feed (toggle to show).
    if (data?.ok && Array.isArray(data.events) && data.events.length) {
      try {
        const safeRows = (await db.prepare('SELECT event_id,rule FROM edr_safe_events WHERE device_id=?').all(req.params.id));
        const safeSet = new Set(safeRows.map(r => r.event_id + '|' + (r.rule || '')));
        data.events.forEach(e => { if (safeSet.has(e.id + '|' + (e.rule || ''))) e.safe = true; });
        data.safe_count = safeRows.length;
      } catch (_) {}
    }
    res.json(data);
  }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR events fetch failed' }); }
});
// EDR — mark an individual finding safe (dismissed, hidden from the default feed) / undo.
app.post('/api/devices/:id/remote-assist/edr/safe', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const eventId = parseInt(req.body?.eventId, 10);
  if (!Number.isFinite(eventId) || eventId <= 0) return res.status(400).json({ ok: false, error: 'valid eventId required' });
  try {
    // Postgres dialect — db.js's pg shim passes SQL through verbatim, so the SQLite-only
    // "INSERT OR IGNORE" form threw a syntax error here on every click (silent 502 + suppressed
    // danger toast). The UNIQUE(device_id,event_id,rule) constraint makes ON CONFLICT DO NOTHING
    // the exact Postgres equivalent. Found live 2026-08-01: "Mark safe" appeared to do nothing.
    (await db.prepare('INSERT INTO edr_safe_events (device_id,event_id,rule,reason,image,time,marked_at) VALUES (?,?,?,?,?,?,?) ON CONFLICT (device_id,event_id,rule) DO NOTHING')
      .run(req.params.id, eventId, req.body?.rule || null, req.body?.reason || null, req.body?.image || null, req.body?.time || null, Date.now()));
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR mark-safe failed' }); }
});
app.post('/api/devices/:id/remote-assist/edr/unsafe', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const eventId = parseInt(req.body?.eventId, 10);
  if (!Number.isFinite(eventId) || eventId <= 0) return res.status(400).json({ ok: false, error: 'valid eventId required' });
  try {
    (await db.prepare('DELETE FROM edr_safe_events WHERE device_id=? AND event_id=?').run(req.params.id, eventId));
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR unmark failed' }); }
});
app.post('/api/devices/:id/remote-assist/edr/denylist/:action', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const process = req.body?.process || '';
    if (req.params.action === 'add') res.json((await bastionClient.edrDenylistAdd(req.params.id, process)));
    else if (req.params.action === 'remove') res.json((await bastionClient.edrDenylistRemove(req.params.id, process)));
    else res.status(400).json({ error: 'Unknown denylist action' });
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR denylist action failed' }); }
});
// EDR — wipe the accumulated findings feed ("Clear history"). Deletes the bastion-side events.jsonl
// AND the local edr_safe_events rows for this device: clearing resets the per-session event ids to 1
// (bastion counts lines), so a stale (event_id,rule) "safe" row would silently auto-hide an unrelated
// future finding. Denylist/alert-suppression config is deliberately kept (it's config, not history).
app.post('/api/devices/:id/remote-assist/edr/clear', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.edrClear(req.params.id));
    if (result?.ok) {
      try { (await db.prepare('DELETE FROM edr_safe_events WHERE device_id=?').run(req.params.id)); } catch (_) {}
    }
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR clear failed' }); }
});
// Cheap local read (no bastion round trip) — lets the WebUI show current on/off state on tab
// load without needing to hit bastion just to render two buttons correctly.
app.get('/api/devices/:id/remote-assist/edr/status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  res.json({ ok: true, enabled: (await getEdrEnabled(req.params.id)) });
});

// ── EDR Phase 2 — Remote Process Intervention + Dynamic Host Isolation ───────────────────────
app.get('/api/devices/:id/remote-assist/edr/process-list', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.edrProcessList(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR process list failed' }); }
});
app.post('/api/devices/:id/remote-assist/edr/process-kill', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const pid = parseInt(req.body?.pid, 10);
  if (!Number.isFinite(pid) || pid <= 0) return res.status(400).json({ ok: false, error: 'valid pid required' });
  try {
    const result = (await bastionClient.edrProcessKill(req.params.id, pid));
    log('info', 'EDR process kill', { deviceId: req.params.id, pid });
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR process kill failed' }); }
});
// Phase 4 — freezes/unfreezes every thread of a PID, a lighter-weight alternative to Kill for
// inspecting a suspicious process without losing its state. See edr_process_suspend()/
// edr_process_resume() in bastion-web.py.
app.post('/api/devices/:id/remote-assist/edr/process-suspend', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const pid = parseInt(req.body?.pid, 10);
  if (!Number.isFinite(pid) || pid <= 0) return res.status(400).json({ ok: false, error: 'valid pid required' });
  try {
    const result = (await bastionClient.edrProcessSuspend(req.params.id, pid));
    log('info', 'EDR process suspend', { deviceId: req.params.id, pid });
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR process suspend failed' }); }
});
app.post('/api/devices/:id/remote-assist/edr/process-resume', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const pid = parseInt(req.body?.pid, 10);
  if (!Number.isFinite(pid) || pid <= 0) return res.status(400).json({ ok: false, error: 'valid pid required' });
  try {
    const result = (await bastionClient.edrProcessResume(req.params.id, pid));
    log('info', 'EDR process resume', { deviceId: req.params.id, pid });
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR process resume failed' }); }
});
// eventId must be a finding already returned by GET .../edr/events — the actual file path is
// looked up bastion-side FROM that stored finding (delete_edr_file()'s own safety pattern), never
// taken as free text here. See the EDR feature plan's Phase 2 design.
app.post('/api/devices/:id/remote-assist/edr/file-delete', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const eventId = parseInt(req.body?.eventId, 10);
  if (!Number.isFinite(eventId) || eventId <= 0) return res.status(400).json({ ok: false, error: 'valid eventId required' });
  try {
    const result = (await bastionClient.edrFileDelete(req.params.id, eventId));
    log('info', 'EDR file delete', { deviceId: req.params.id, eventId });
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR file delete failed' }); }
});
app.post('/api/devices/:id/remote-assist/edr/isolate/block', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.edrIsolateBlock(req.params.id));
    if (result?.ok) (await setEdrIsolated(req.params.id, true));
    log('info', 'EDR host isolation ENABLED', { deviceId: req.params.id });
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR isolate failed' }); }
});
app.post('/api/devices/:id/remote-assist/edr/isolate/unblock', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.edrIsolateUnblock(req.params.id));
    if (result?.ok) (await setEdrIsolated(req.params.id, false));
    log('info', 'EDR host isolation disabled', { deviceId: req.params.id });
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'EDR unisolate failed' }); }
});
// Live-checks bastion (a real Get-NetFirewallProfile Hop-2 round trip) but NEVER lets a failed
// round trip render as "not isolated" — falls back to the last known local flag instead (set by
// the block/unblock routes above). See getEdrIsolated()'s doc comment for why this exists: a
// transient bastion/network hiccup must not look identical to "confirmed not isolated" when the
// device could genuinely still be cut off.
app.get('/api/devices/:id/remote-assist/edr/isolate-status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const localIsolated = (await getEdrIsolated(req.params.id));
  try {
    const result = (await bastionClient.edrIsolateStatus(req.params.id));
    if (result?.ok) {
      const liveIsolated = !!result.isolated;
      if (liveIsolated !== localIsolated) (await setEdrIsolated(req.params.id, liveIsolated));
      return res.json(result);
    }
    res.json({ ok: true, isolated: localIsolated, stale: true });
  } catch (e) {
    res.json({ ok: true, isolated: localIsolated, stale: true });
  }
});

// ── ARP scan / network discovery ("ARPwatch"-style) ──────────────────────────
// Trigger runs the scan bastion-side then immediately ingests the raw result into the persisted
// roster (arp_neighbors/arp_events) — the dashboard doesn't have to wait for the next poll tick
// to see the device it just asked for. GET returns OUR persisted, diffed view (roster + recent
// events + latest AI summary), never the bastion's raw cache directly — see ingestArpScanResult().
app.post('/api/devices/:id/remote-assist/arp-scan', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.arpScan(req.params.id));
    if (result?.ok) (await ingestArpScanResult(req.params.id, result));
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'ARP scan failed' }); }
});
app.get('/api/devices/:id/remote-assist/arp-scan', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const deviceId = req.params.id;
  const roster = (await db.prepare('SELECT mac_address,ip_address,hostname,open_ports,web_ui,first_seen,last_seen,trusted FROM arp_neighbors WHERE device_id=? ORDER BY last_seen DESC').all(deviceId));
  const events = (await db.prepare('SELECT event_type,mac_address,ip_address,prior_value,timestamp FROM arp_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 100').all(deviceId));
  const summaryRow = (await db.prepare('SELECT summary,generated_at FROM arp_ai_summaries WHERE device_id=? ORDER BY generated_at DESC LIMIT 1').get(deviceId));
  const canaries = (await db.prepare('SELECT ip_address,subnet,confirmed_at,consecutive_dark_scans FROM arp_canary_ips WHERE device_id=? ORDER BY ip_address').all(deviceId));
  res.json({
    ok: true,
    roster: roster.map(r => ({
      ...r, trusted: !!r.trusted,
      openPorts: r.open_ports ? (() => { try { return JSON.parse(r.open_ports); } catch { return []; } })() : [],
      webUi: r.web_ui ? (() => { try { return JSON.parse(r.web_ui); } catch { return []; } })() : [],
    })),
    events, latestSummary: summaryRow || null, canaries,
  });
});

// "Trust this device" / "Authorized scanner" — suppresses arp_sweep (recon/velocity) alerts for
// this MAC across EVERY device under the same owner (see ingestArpSweepEvents()'s owner-scoped
// trusted-MAC check — sweep detection can run on devices that never scan and thus have no roster
// of their own, so the flag set here on the scanning PC must silence detection-only siblings too).
// Deliberately does NOT touch arp_spoof (mac_changed_for_ip) detection — that's about IP/MAC
// binding integrity, not about whether a device's own scanning behavior is expected; a trusted
// scanner's MAC turning up on an IP that previously belonged to a DIFFERENT MAC is still worth
// flagging. Row must already exist in the roster (a device only ever gets marked trusted after
// having been actually seen).
app.post('/api/devices/:id/remote-assist/arp-scan/trust', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const mac = String(req.body?.mac || '').trim().toLowerCase();
  const trusted = req.body?.trusted ? 1 : 0;
  if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac)) return res.status(400).json({ error: 'Invalid MAC address' });
  const result = (await db.prepare('UPDATE arp_neighbors SET trusted=? WHERE device_id=? AND mac_address=?').run(trusted, req.params.id, mac));
  if (!result.changes) return res.status(404).json({ error: 'Unknown MAC — it must appear in the roster first' });
  log('info', 'ARP scanner trust toggled', { deviceId: req.params.id, mac, trusted: !!trusted });
  res.json({ ok: true, mac, trusted: !!trusted });
});
app.get('/api/devices/:id/remote-assist/arp-scan-schedule', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.getArpScanSchedule(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'ARP scan schedule fetch failed' }); }
});
app.post('/api/devices/:id/remote-assist/arp-scan-schedule', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const minutes = Number(req.body?.minutes);
  if (!Number.isFinite(minutes) || minutes < 0 || minutes > 10080) return res.status(400).json({ error: 'minutes must be between 0 (off) and 10080 (weekly)' });
  try { res.json((await bastionClient.setArpScanSchedule(req.params.id, minutes))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'ARP scan schedule update failed' }); }
});

// ── ARP scan VLANs — manually-added VLAN subnets ─────────────────────────────
// Allows the user to specify additional subnets the device should scan beyond its own local
// interfaces. Stored bastion-side in per-session JSON; the server passes them through to the
// bastion on each scan. CRUD operations for the per-device VLAN list.
app.get('/api/devices/:id/remote-assist/arp-vlans', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.listArpVlans(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'ARP VLAN list fetch failed' }); }
});
app.post('/api/devices/:id/remote-assist/arp-vlans', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const action = String(req.body?.action || 'add').trim().toLowerCase();
  try {
    if (action === 'add') {
      const vlanLabel = String(req.body?.label || '').trim();
      const subnet = String(req.body?.subnet || '').trim();
      const vlanId = req.body?.vlanId != null ? Number(req.body.vlanId) : null;
      if (!subnet) return res.status(400).json({ error: 'subnet is required' });
      res.json((await bastionClient.addArpVlan(req.params.id, vlanLabel, subnet, vlanId)));
    } else if (action === 'remove') {
      const subnet = String(req.body?.subnet || '').trim();
      if (!subnet) return res.status(400).json({ error: 'subnet is required' });
      res.json((await bastionClient.removeArpVlan(req.params.id, subnet)));
    } else {
      res.status(400).json({ error: "action must be 'add' or 'remove'" });
    }
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'ARP VLAN update failed' }); }
});

// ── Boot ISO — boot a Windows RA box into a curated ISO (GRUB on the ESP) ─────
// Full flow: bastion-web.py's _BOOT_ISO_STAGE_PS1 downloads the ISO directly on the
// box (public OTA URL — never through the tunnel), verifies SHA-256
// when the catalog knows it, installs a standalone GRUB on the EFI System Partition,
// and points the Boot Manager at it (bcdedit {bootmgr} path). The GRUB menu ALWAYS
// keeps a Windows fallback entry (fallback=1) so a failed ISO boot returns to Windows;
// Restore removes GRUB entirely (EFI\sentinel dir + ISO + bcdedit path back to
// bootmgfw.efi).
//
// The catalog is DISCOVERY-BASED **and PER-ACCOUNT-GATED** (2026-08-16): every *.iso
// under the VIEWER'S OWN `boot-iso/<account-email>/` folder in sentinelmdm-ota is
// listed automatically, plus bucket-root *.iso files for admins only. Uploads (multipart)
// land in `boot-iso/<viewerEmail>/` — so an ISO is only ever visible to (and deletable
// by) the account that uploaded it. Dropping an ISO into your own R2 folder makes it
// immediately available in the WebUI with no registration step. Admin uploads add
// enriched entries (display name + kernel/initrd + sha256 + ownerEmail) persisted in
// settings['boot_iso_catalog']; discovered entries get a derived id (iso:<key>) and
// null kernel/initrd/sha256 — the bastion auto-detects the kernel/initrd names inside
// the ISO (Mount-DiskImage) and skips the SHA-256 verify (size check only) when the
// catalog has no hash. config.js BOOT_ISO_CATALOG_DEFAULTS is deliberately empty.
const { BOOT_ISO_CATALOG_DEFAULTS, OTA_R2_BUCKET, BOOT_ISO_R2_PREFIX, otaR2 } = require('../../config');
const { CreateMultipartUploadCommand, UploadPartCommand, CompleteMultipartUploadCommand, AbortMultipartUploadCommand, DeleteObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const { randomUUID } = require('crypto');
const crypto = require('crypto');

// Per-account folder identity — an OPAQUE 20-hex hash of the account email, NOT the
// raw email. The sentinelmdm-ota bucket is PUBLIC (that's how the box downloads the
// ISO with a plain curl), so an email-derived folder name would leak the account's
// email to anyone listing the bucket or guessing URLs (found 2026-08-16). The hash is
// one-way and deterministic: same email → same folder, so re-uploads land in the same
// place and the WebUI catalog scopes to the same folder on every request. Only the
// server ever sees the email→folder mapping (users table lookup at request time).
function bootIsoFolderId(email) {
  return crypto.createHash('sha256').update(String(email || '').toLowerCase().trim()).digest('hex').slice(0, 20);
}

// The viewer's identity for per-account catalog/upload gating: the users table email
// (fallback username). An empty string means "no authenticated identity" — the catalog
// then has nothing to scope to and returns [].
async function bootIsoViewerEmail(req) {
  try {
    const u = (await db.prepare('SELECT email, username FROM users WHERE id=?').get(req.session?.userId));
    return String((u?.email || u?.username) || '').trim().toLowerCase();
  } catch { return ''; }
}
function bootIsoIsAdminViewer(req) {
  return req.session?.role === 'admin' && req.session?.account_type !== 'public';
}

function bootIsoEntryFromKey(key) {
  const fileName = String(key || '').split('/').pop();
  if (!fileName || !/\.iso$/i.test(fileName)) return null;
  return {
    id: 'iso:' + key,
    name: fileName.replace(/\.iso$/i, ''),
    url: OTA_PUBLIC_URL + '/' + key,
    isoFile: fileName,
    size: null,
    sha256: null,
    kernel: null,
    initrd: null,
    discovered: true,
    r2Key: key,
  };
}

async function getBootIsoCatalog(viewerEmail, isAdminViewer) {
  let extra = [];
  try {
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('boot_iso_catalog'));
    if (row) { const arr = JSON.parse(row.value); if (Array.isArray(arr)) extra = arr; }
  } catch {}
  const seen = new Set();
  const list = [];
  for (const e of [...extra, ...BOOT_ISO_CATALOG_DEFAULTS]) {
    if (!e || seen.has(e.id)) continue;
    // Per-account gating: an entry is visible only to its owner (ownerEmail), or to
    // admins when it carries no owner (legacy/root operator ISOs).
    if (e.ownerEmail) { if (e.ownerEmail !== viewerEmail) continue; }
    else if (!isAdminViewer) continue;
    seen.add(e.id);
    list.push(e);
  }
  // Bucket discovery scoped to the viewer: their OWN boot-iso/<folderId>/ directory
  // (folderId = opaque hash of the account email — never the raw email in the public
  // bucket), plus bucket-root *.iso files (operator-managed) for admins only. Anything
  // in another account's folder never shows up here regardless of filename.
  const viewerFolderId = bootIsoFolderId(viewerEmail);
  if (otaR2 && viewerEmail) {
    try {
      let token;
      do {
        const resp = await otaR2.send(new ListObjectsV2Command({
          Bucket: OTA_R2_BUCKET, ContinuationToken: token, MaxKeys: 1000,
        }));
        for (const obj of (resp.Contents || [])) {
          const key = obj.Key || '';
          if (!/\.iso$/i.test(key)) continue;
          const isRoot = !key.includes('/');
          const ownFolder = key.startsWith(`${BOOT_ISO_R2_PREFIX}${viewerFolderId}/`);
          if (!ownFolder && !(isRoot && isAdminViewer)) continue;
          const existing = list.find(e => e.r2Key === key || e.isoFile === key.split('/').pop());
          if (existing) { if (existing.size === null && obj.Size) existing.size = obj.Size; continue; }
          const entry = bootIsoEntryFromKey(key);
          if (entry) {
            if (obj.Size) entry.size = obj.Size;
            list.push(entry);
            seen.add(entry.id);
          }
        }
        token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
      } while (token);
    } catch (e) {
      log('warn', 'Boot ISO bucket discovery failed', { error: e.message });
    }
  }
  return list;
}
async function saveBootIsoCatalog(list) {
  // Persist only enriched entries (uploads) — discovered entries regenerate from the
  // bucket on every fetch, so storing them would just go stale.
  const persistent = list.filter(e => !e.discovered && !BOOT_ISO_CATALOG_DEFAULTS.some(d => d.id === e.id));
  await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('boot_iso_catalog', JSON.stringify(persistent));
}

app.get('/api/devices/:id/remote-assist/boot-iso/catalog', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  try {
    const viewerEmail = await bootIsoViewerEmail(req);
    const isAdminViewer = bootIsoIsAdminViewer(req);
    res.json({ ok: true, catalog: (await getBootIsoCatalog(viewerEmail, isAdminViewer)) });
  }
  catch (e) { res.status(502).json({ error: e.message || 'Boot ISO catalog failed' }); }
});

app.post('/api/devices/:id/remote-assist/boot-iso/set', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const isoId = String(req.body?.isoId || '').trim();
  const viewerEmail = await bootIsoViewerEmail(req);
  const isAdminViewer = bootIsoIsAdminViewer(req);
  const entry = (await getBootIsoCatalog(viewerEmail, isAdminViewer)).find(e => e.id === isoId);
  if (!entry) return res.status(400).json({ error: 'Unknown ISO in catalog' });
  try {
    const result = (await bastionClient.bootIsoSet(req.params.id, entry));
    if (result?.ok) {
      await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .run('boot_iso_status:' + req.params.id, JSON.stringify({ isoId, isoFile: entry.isoFile, step: result.status || 'started', updatedAt: Date.now() }));
    }
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Boot ISO set failed' }); }
});

app.post('/api/devices/:id/remote-assist/boot-iso/reboot', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.bootIsoReboot(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Boot ISO reboot failed' }); }
});

// Full removal: bcdedit back to bootmgfw.efi + delete EFI\sentinel + delete the ISO.
app.post('/api/devices/:id/remote-assist/boot-iso/restore', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.bootIsoRestore(req.params.id));
    if (result?.ok) {
      await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .run('boot_iso_status:' + req.params.id, JSON.stringify({ step: 'restored', updatedAt: Date.now() }));
    }
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Boot ISO restore failed' }); }
});

// Live status with durable last-known snapshot (survives device offline, same pattern
// as bitlocker_status:<id>).
app.get('/api/devices/:id/remote-assist/boot-iso/status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  let result;
  try { result = (await bastionClient.bootIsoStatus(req.params.id)); } catch (e) { result = { ok: false, error: e.message }; }
  if (result?.ok) {
    await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run('boot_iso_status:' + req.params.id, JSON.stringify({ ...result, updatedAt: Date.now() }));
    return res.json({ ok: true, live: true, ...result });
  }
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('boot_iso_status:' + req.params.id));
  if (row) { try { return res.json({ ok: true, live: false, error: result?.error, ...JSON.parse(row.value) }); } catch {} }
  res.json({ ok: false, live: false, error: result?.error || 'No status available yet' });
});

// ── Boot ISO — per-account upload of a custom ISO (chunked -> R2 multipart) ─────
// Any authenticated user (admin OR public owner) uploads into THEIR OWN
// `boot-iso/<account-email>/` folder — the upload is only ever visible to (and
// deletable by) the account that uploaded it. The key is derived server-side from
// the session's users.email, never from the client. Chunks ride express.raw
// (octet-stream) so a global JSON limit never truncates them; each chunk is one R2
// UploadPart. The browser computes the final SHA-256 (crypto.subtle) and sends it on
// complete — the REAL integrity gate is the box-side Get-FileHash verification in
// _BOOT_ISO_STAGE_PS1, which refuses to boot a mismatched ISO.
const BOOT_ISO_CHUNK_MB = 16;
const BOOT_ISO_FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.iso$/i;
app.post('/api/admin/boot-iso/upload/start', requireUnlocked, requireAuth, express.json(), async (req, res) => {
  try {
    const fileName = String(req.body?.fileName || '').trim();
    if (!BOOT_ISO_FILENAME_RE.test(fileName)) return res.status(400).json({ error: 'fileName must be a plain .iso filename (letters, digits, . _ -)' });
    const viewerEmail = await bootIsoViewerEmail(req);
    if (!viewerEmail) return res.status(400).json({ error: 'Could not resolve your account identity for the upload folder' });
    if (!otaR2) return res.status(503).json({ error: 'OTA R2 upload client not configured' });
    // Opaque per-account folder (sha256 of the email), never the raw email — the
    // bucket is public, so an email folder name would leak the account's address.
    const key = `${BOOT_ISO_R2_PREFIX}${bootIsoFolderId(viewerEmail)}/${fileName}`;
    const created = await otaR2.send(new CreateMultipartUploadCommand({ Bucket: OTA_R2_BUCKET, Key: key, ContentType: 'application/octet-stream' }));
    const uploadId = randomUUID();
    await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run('boot_iso_upload:' + uploadId, JSON.stringify({ fileName, key, ownerEmail: viewerEmail, r2UploadId: created.UploadId, parts: [], receivedBytes: 0, createdAt: Date.now() }));
    res.json({ ok: true, uploadId, chunkSize: BOOT_ISO_CHUNK_MB * 1024 * 1024 });
  } catch (e) { res.status(502).json({ error: e.message || 'Upload start failed' }); }
});

app.post('/api/admin/boot-iso/upload/chunk', requireUnlocked, requireAuth, express.raw({ type: () => true, limit: (BOOT_ISO_CHUNK_MB + 1) + 'mb' }), async (req, res) => {
  try {
    const uploadId = String(req.query.uploadId || '');
    const index = Number(req.query.index);
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('boot_iso_upload:' + uploadId));
    if (!row) return res.status(404).json({ error: 'Unknown upload' });
    const st = JSON.parse(row.value);
    if (st.ownerEmail !== (await bootIsoViewerEmail(req))) return res.status(403).json({ error: 'Not your upload' });
    if (!Number.isInteger(index) || index < 0 || index !== st.parts.length) return res.status(400).json({ error: `Expected chunk index ${st.parts.length}, got ${index}` });
    const body = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body || '');
    if (!body.length || body.length > BOOT_ISO_CHUNK_MB * 1024 * 1024) return res.status(400).json({ error: 'Empty or oversized chunk' });
    const part = await otaR2.send(new UploadPartCommand({
      Bucket: OTA_R2_BUCKET, Key: st.key, UploadId: st.r2UploadId, PartNumber: index + 1, Body: body,
    }));
    st.parts.push({ PartNumber: index + 1, ETag: part.ETag });
    st.receivedBytes += body.length;
    await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
      .run('boot_iso_upload:' + uploadId, JSON.stringify(st));
    res.json({ ok: true, index, receivedBytes: st.receivedBytes });
  } catch (e) { res.status(502).json({ error: e.message || 'Chunk upload failed' }); }
});

app.post('/api/admin/boot-iso/upload/complete', requireUnlocked, requireAuth, express.json(), async (req, res) => {
  try {
    const uploadId = String(req.body?.uploadId || '');
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('boot_iso_upload:' + uploadId));
    if (!row) return res.status(404).json({ error: 'Unknown upload' });
    const st = JSON.parse(row.value);
    if (st.ownerEmail !== (await bootIsoViewerEmail(req))) return res.status(403).json({ error: 'Not your upload' });
    if (!st.parts.length) return res.status(400).json({ error: 'No chunks uploaded' });
    const sha256 = String(req.body?.sha256 || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(sha256)) return res.status(400).json({ error: 'sha256 must be a 64-char hex digest' });
    const completed = await otaR2.send(new CompleteMultipartUploadCommand({
      Bucket: OTA_R2_BUCKET, Key: st.key, UploadId: st.r2UploadId,
      MultipartUpload: { Parts: st.parts.sort((a, b) => a.PartNumber - b.PartNumber) },
    }));
    const entry = {
      id: 'upload-' + st.fileName.replace(/\.iso$/i, '').replace(/[^A-Za-z0-9._-]/g, '-'),
      name: String(req.body?.name || st.fileName).trim().slice(0, 80),
      url: OTA_PUBLIC_URL + '/' + st.key,
      size: st.receivedBytes,
      sha256,
      isoFile: st.fileName,
      kernel: String(req.body?.kernel || '').trim() || null,
      initrd: String(req.body?.initrd || '').trim() || null,
      uploaded: true,
      ownerEmail: st.ownerEmail,
      r2Key: st.key,
    };
    const viewerEmail = st.ownerEmail;
    const isAdminViewer = bootIsoIsAdminViewer(req);
    const list = await getBootIsoCatalog(viewerEmail, isAdminViewer);
    list.push(entry);
    await saveBootIsoCatalog(list);
    await db.prepare("DELETE FROM settings WHERE key=?").run('boot_iso_upload:' + uploadId);
    log('info', 'Boot ISO uploaded', { fileName: st.fileName, size: st.receivedBytes, ownerEmail: st.ownerEmail });
    res.json({ ok: true, entry });
  } catch (e) { res.status(502).json({ error: e.message || 'Upload complete failed' }); }
});

app.post('/api/admin/boot-iso/upload/abort', requireUnlocked, requireAuth, express.json(), async (req, res) => {
  try {
    const uploadId = String(req.body?.uploadId || '');
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('boot_iso_upload:' + uploadId));
    if (row) {
      const st = JSON.parse(row.value);
      if (st.ownerEmail !== (await bootIsoViewerEmail(req))) return res.status(403).json({ error: 'Not your upload' });
      try { await otaR2.send(new AbortMultipartUploadCommand({ Bucket: OTA_R2_BUCKET, Key: st.key, UploadId: st.r2UploadId })); } catch {}
      await db.prepare("DELETE FROM settings WHERE key=?").run('boot_iso_upload:' + uploadId);
    }
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: e.message || 'Upload abort failed' }); }
});

// Delete: owner-only via the scoped catalog (requireAuth — a public owner deletes
// only THEIR OWN uploads; admins additionally see/delete root operator ISOs).
app.delete('/api/admin/boot-iso/catalog/:isoId', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const isoId = String(req.params.isoId || '');
    const viewerEmail = await bootIsoViewerEmail(req);
    const isAdminViewer = bootIsoIsAdminViewer(req);
    const list = await getBootIsoCatalog(viewerEmail, isAdminViewer);
    const entry = list.find(e => e.id === isoId);
    if (!entry) return res.status(404).json({ error: 'ISO not found' });
    // Never let a user delete an object outside their own scoped catalog (e.g. another
    // account's folder) even if they guess the isoId — the scoped list already excludes
    // it, so reaching here means it's theirs (or an admin-visible root ISO).
    const r2Key = entry.r2Key || `${BOOT_ISO_R2_PREFIX}${entry.isoFile}`;
    try { await otaR2.send(new DeleteObjectCommand({ Bucket: OTA_R2_BUCKET, Key: r2Key })); } catch (e) { log('warn', 'Boot ISO R2 delete failed', { r2Key, error: e.message }); }
    // Drop any enriched DB row (uploaded entries) so it doesn't reappear as discovered.
    await saveBootIsoCatalog(list.filter(e => e.id !== isoId && e.isoFile !== entry.isoFile));
    await db.prepare("DELETE FROM settings WHERE key IN (?,?)").run('boot_iso_upload:' + isoId, 'boot_iso_upload:upload-' + isoId);
    log('info', 'Boot ISO deleted', { isoId, fileName: entry.isoFile, r2Key });
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ error: e.message || 'Boot ISO delete failed' }); }
});

};
