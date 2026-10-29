// Server-to-bastion bridge — thin fetch wrapper the tracker/worker use to reach the support service's
// session/forensics/appcontrol/winupdate API for SentinelRemoteAssist ("remote_assist") devices.
//
// the support service itself stays untouched in its existing (Tailscale-only, human-operator, ad hoc
// no-account) responsibilities — this module is purely an ADDITIVE swarm-internal caller. It
// authenticates with a new service-to-service secret (sentinel_bastion_internal_key) that turns on
// the support service's already-present-but-currently-unset BASTION_UI_KEY check for the first time,
// scoped to these calls only; the human-operator Tailscale WebUI keeps its existing access path.
//
// ⚠️ This module never touches an SSH private key. There is no in-browser terminal and no relay —
// interactive access is a plain copy-paste `ssh -J` command the user runs in their OWN terminal
// (see server.js's /remote-assist/hop2-command route and grantJumpAccess() below). See the
// "ZK Security" access-control design in docs/ARCHITECTURE.md and server.js's requireDeviceController() reuse
// on the /remote-assist/* routes: for a ZK-owned (public-user-claimed) device, the SSH keypair
// that actually authenticates is generated in the owning user's browser and never reaches this
// process at all — only its PUBLIC half ever does, exactly like any other SSH pubkey auth setup.

const BASTION_INTERNAL_URL = process.env.BASTION_INTERNAL_URL || 'http://bastion:9098';
const BASTION_INTERNAL_KEY = (() => {
  try { return require('fs').readFileSync('/run/secrets/sentinel_bastion_internal_key', 'utf8').trim(); }
  catch { return process.env.BASTION_INTERNAL_KEY || ''; }
})();

function configured() { return !!BASTION_INTERNAL_KEY; }

// Node's global fetch (undici) defaults to a 300s headersTimeout/bodyTimeout on its Agent — fine
// for forensics/audit/powershell (already routinely 1-3 min per runPowerShell()'s doc comment,
// bastion's own httpd.timeout=1800 was never the bottleneck) but found live 2026-07-22 to break
// File Backup: a real profile's SCP pull + tar + encrypt + rclone upload legitimately runs well
// past 5 minutes, and the request died with a bare "fetch failed" at ~300.5-300.7s on TWO
// different devices/backups — undici's default ceiling, not a Cloudflare timeout (this hop is
// swarm-internal, no CF involved) and not bastion's own socket timeout (1800s, unhit). A longer
// AbortSignal alone would NOT have fixed this — undici's Agent-level headersTimeout/bodyTimeout is
// a separate, lower-level ceiling that fires regardless of the caller's own abort deadline.
// Cast through `any` — the separately npm-installed `undici` package's Dispatcher type structurally
// conflicts with @types/node's bundled `undici-types` (two distinct type definitions for the same
// runtime class), even though the actual object works fine as a `dispatcher` at runtime (verified
// live against node:20-alpine, matching the production image).
const LONG_RUN_DISPATCHER = /** @type {any} */ (new (require('undici').Agent)({ headersTimeout: 0, bodyTimeout: 0 }));

async function bastionFetch(path, opts = {}) {
  if (!BASTION_INTERNAL_KEY) throw new Error('bastion bridge not configured (missing sentinel_bastion_internal_key secret)');
  const { longRunning, ...restOpts } = opts;
  const res = await fetch(`${BASTION_INTERNAL_URL}${path}`, /** @type {any} */ ({
    ...restOpts,
    ...(longRunning ? { dispatcher: LONG_RUN_DISPATCHER } : {}),
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': BASTION_INTERNAL_KEY, ...(opts.headers || {}) },
  }));
  const text = await res.text();
  let body; try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text }; }
  if (!res.ok) {
    // 2.0.4: nuke/PS1-type routes return the transport dict {ok, exitCode, stdout, stderr} with
    // no `error` field — swallow the body and the UI only ever sees "Nuke failed" with the real
    // reason (e.g. "Connection closed by 127.0.0.1 port 43110") stuck in stderr. Surface it.
    const detail = body?.error
      || (body?.stderr ? `stderr: ${body.stderr}` : '')
      || (body?.stdout ? `stdout: ${body.stdout}` : '');
    const msg = detail || `bastion ${path} → HTTP ${res.status}`;
    const e = /** @type {any} */ (new Error(msg));
    e.status = res.status; e.body = body; e.bastionError = body?.error || null;
    throw e;
  }
  return body;
}

async function bastionGet(path) {
  if (!BASTION_INTERNAL_KEY) throw new Error('bastion bridge not configured (missing sentinel_bastion_internal_key secret)');
  const res = await fetch(`${BASTION_INTERNAL_URL}${path}`, {
    headers: { 'X-Api-Key': BASTION_INTERNAL_KEY },
  });
  const text = await res.text();
  let body; try { body = text ? JSON.parse(text) : {}; } catch { body = { raw: text }; }
  if (!res.ok) {
    const msg = body?.error || `bastion ${path} → HTTP ${res.status}`;
    const e = /** @type {any} */ (new Error(msg));
    e.status = res.status; e.body = body; e.bastionError = body?.error || null;
    throw e;
  }
  return body;
}

// Deterministic per-device bastion session label so repeat start/stop reuse the same slot
// (mirrors the existing permanent-port-registry concept for repeat SentinelRemoteAssist customers).
function labelForDevice(deviceId) {
  // Linux sentineld sessions use the raw device ID as the bastion label (it already starts
  // with "ra-"). Windows sessions are created with a hashed label via create_session/provision.
  // If the deviceId is already a valid ra-XX...XX label (16 hex chars after "ra-"), use it directly.
  if (/^ra-[0-9a-f]{16}$/i.test(deviceId)) return deviceId;
  return 'ra-' + require('crypto').createHash('sha256').update(deviceId).digest('hex').slice(0, 16);
}

async function adminSupportPubKey() {
  const body = await bastionGet('/api/admin-support-pubkey');
  return body.pubkey;
}

// Provision/remint the bastion-side Hop-1 session (reverse-tunnel identity + forwarded port) for
// this device. This layer has NOTHING to do with who can reach the ephemeral local admin account
// ON the Windows box (Hop-2) — that's Config.AdminHopTwoPublicKey territory, entirely a
// Windows-agent-side concern (see server.js's remote_assist_ssh_key push, which goes straight to
// the device over the control socket, never through here).
//
// hop1PublicKey is THIS DEVICE's own Hop-1 keypair (Hop1Identity.cs, sent up on every "register"
// and read back from devices.hop1_public_key by the caller) — required. Previously this looked up
// one shared keypair per accountId instead (rotate_account_hop1_key()); that broke the instant a
// second device shared the same account, since sshd's authorized_keys matching can only ever honor
// the FIRST line for a given key — see docs/ARCHITECTURE.md. accountId
// is kept only for bookkeeping (which SentinelMDM account this session belongs to), not for key
// lookup any more.
async function provisionSession(deviceId, accountId, hop1PublicKey, agentPlatform) {
  if (!hop1PublicKey) throw new Error('provisionSession: hop1PublicKey required (device has not sent one yet — no prior register?)');
  const label = labelForDevice(deviceId);
  const sessionBody = {
    label, force_replace: true, replace: true,
    remote_assist_device_id: deviceId, remote_assist_account_id: String(accountId),
    hop1_public_key: hop1PublicKey,
  };
  if (agentPlatform === 'linux') sessionBody.agent_platform = 'linux';
  const body = await bastionFetch('/api/sessions', {
    method: 'POST',
    body: JSON.stringify(sessionBody),
  });
  return { label, port: body.port, downloadUrl: body.download_url };
}

// Pushes the current SentinelMDM device name so the bastion shows it instead of the raw
// "ra-<hash>" label everywhere a human sees it (session cards, Signal alert text) — see
// the support service's display_name_for() doc comment. Called on rename (server.js's
// pushDeviceDisplayNameToBastion) and opportunistically after every provisionSession() call
// (session create/reconnect) for self-healing, so a session that missed a rename push still
// picks up the current name the next time the device connects.
async function setDisplayName(deviceId, name) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/display-name`, {
    method: 'POST', body: JSON.stringify({ displayName: name }),
  });
}

async function endSession(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/remote-assist/end`, { method: 'POST' });
}

// Full teardown — authorized_keys line, live tunnel, session dir, any built account-linked exe.
// Unlike endSession() above (dashboard-tracking-only, never touches the bastion session), this is
// the actual cleanup call for a device that's being deleted/released — see DELETE /api/devices/:id.
// Safe to call on a device that never had a bastion session at all (bastion-side revoke_session()
// is a no-op-but-ok in that case); callers should still treat this as best-effort (try/catch) since
// a bastion outage must never block the device removal itself.
async function revokeSession(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/remote-assist/purge`, { method: 'POST' });
}

async function sessionStatus(deviceId) {
  const label = labelForDevice(deviceId);
  try { return await bastionFetch(`/api/sessions/${encodeURIComponent(label)}`); }
  // 404 = bastion has never provisioned a session row for this device at all (no key ever pushed)
  // — distinct from "provisioned but currently disconnected". neverProvisioned drives the
  // dashboard's Regen Private Key -> "Initiate SSH Tunnel" first-run relabeling (see
  // _raRefreshConnectedState() in app.js).
  catch (e) { if (e.status === 404) return { connected: false, neverProvisioned: true }; throw e; }
}

// "Latest available" Windows agent version — see the support service's get_latest_agent_version() doc
// comment (bastion-side 5-min cache; this call is cheap). Also surfaced per-device on every
// sessionStatus() row (agent_update_available/latest_agent_version) — this standalone getter is
// for the admin panel's page-level "what's the newest build" display, not per-device polling.
async function getLatestAgentVersion(force = false) {
  return bastionGet(`/api/agent/latest-version${force ? '?force=1' : ''}`);
}

// Pushes+cuts over the agent on ONE device — see the support service's agent_self_update() doc comment
// for the SCP-push mechanism. accountId/adminAgent are supplied by the CALLER (server.js already
// knows the owning account + its type from devices/users) rather than looked up bastion-side.
// Fleet-wide "Update Agent" reuses this same per-device call via server.js's existing
// fleetFanOut() (Promise.allSettled across the caller's controllable devices) — the same pattern
// every other fleet action already uses — rather than a separate bastion-side bulk endpoint.
async function agentUpdate(deviceId, accountId, adminAgent) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/agent-update`, {
    method: 'POST', body: JSON.stringify({ account_id: String(accountId), admin_agent: !!adminAgent }),
  });
}

// ── IT Mode Audit (malware/inventory scan) ──────────────────────────────────
// Bastion-side fields (audit_verdict/audit_summary/...) come back on the same per-session row
// sessionStatus() already reads; this just reshapes them + adds caching for the hot list path.
const _auditStatusCache = new Map(); // deviceId -> { data, fetchedAt }
const AUDIT_CACHE_TTL_MS = 60_000; // the underlying data only changes when a (multi-minute) audit
// actually completes, so up to a minute of staleness here is a non-issue -- but /api/devices is
// the single most-hit endpoint in the app, so it must never pay a live bastion round-trip on
// every poll for every request.

function _auditFieldsFromSessionRow(st) {
  return {
    verdict: st.audit_verdict || 'PENDING',
    summary: st.audit_summary || '',
    risk: st.audit_overall_risk || 'low',
    criticalCount: st.audit_critical_count || 0,
    warningCount: st.audit_warning_count || 0,
    collectedAtCdt: st.audit_collected_at_cdt || '',
    collectedAtEpoch: st.audit_collected_at_epoch || 0,
    findings: st.audit_findings || [],
    scheduleMinutes: st.audit_schedule_minutes ?? (st.audit_schedule_hours || 0) * 60,
    scheduleHours: st.audit_schedule_hours || 0,
  };
}

// Cached, best-effort read for the hot /api/devices list path. NEVER let a slow/unreachable
// bastion block the whole devices list -- short timeout, and any failure just means the card
// shows PENDING instead of a real verdict, not a broken dashboard.
async function sessionAuditCached(deviceId) {
  const cached = _auditStatusCache.get(deviceId);
  if (cached && (Date.now() - cached.fetchedAt) < AUDIT_CACHE_TTL_MS) return cached.data;
  const st = await Promise.race([
    sessionStatus(deviceId),
    new Promise((_, reject) => setTimeout(() => reject(new Error('bastion audit status timeout')), 2500)),
  ]);
  const data = _auditFieldsFromSessionRow(st || {});
  _auditStatusCache.set(deviceId, { data, fetchedAt: Date.now() });
  return data;
}

// Uncached, direct read -- used by the Reverse Tunnel tab's own detail view and its post-"Run
// Check Now" poll loop, where the whole point is to see live progress, not a minute-old cache.
async function sessionAuditLive(deviceId) {
  const st = await sessionStatus(deviceId);
  return _auditFieldsFromSessionRow(st || {});
}

function invalidateAuditCache(deviceId) {
  _auditStatusCache.delete(deviceId);
}

// Manual "Run Check Now" trigger -- backgrounded bastion-side (/api/sessions/<label>/it-audit/run),
// NOT the synchronous /api/audit/run the bastion's own internal WebUI uses. That one blocks for
// the whole multi-minute audit; fine direct-over-Tailscale, but this dashboard route goes through
// Cloudflare, which has already hit this exact class of timeout once before (see the forensics
// kind=all fix). Returns immediately; the dashboard polls sessionAuditLive() and watches
// collectedAtEpoch advance to know when the real result has landed.
async function runAudit(deviceId) {
  const label = labelForDevice(deviceId);
  invalidateAuditCache(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/it-audit/run`, { method: 'POST' });
}

async function getAuditSchedule(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/audit-schedule`);
}

// Schedule payload is either the legacy {minutes} cadence (0 = manual-only, never auto-runs) or
// the exact-times form {entries, tz} where entries is a list of {"time":"HH:MM","days":[0..6]}
// (0=Sun..6=Sat, empty days = every day, max 8) and tz is the operator's IANA timezone name.
// entries take precedence over minutes; saving one clears the other (see run_due_session_audits()
// bastion-side, ticked every 15 min by entrypoint.sh's cron).
async function setAuditSchedule(deviceId, payload) {
  const label = labelForDevice(deviceId);
  invalidateAuditCache(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/audit-schedule`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}

async function runForensics(deviceId, kind = 'all') {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/forensics`, {
    method: 'POST', body: JSON.stringify({ kind }),
  });
}

async function forensicsFull(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/forensics-full`);
}

async function forensicsKind(deviceId, kind) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/forensics/${encodeURIComponent(kind)}`);
}

// Lightweight poll target for "Collect all" — kind:"all" on the /forensics POST route is
// fire-and-forget (bastion returns {status:"collecting"} immediately and does the real 14-category
// sweep in a background thread, same reason it-audit/run needs its own status-poll loop). This
// returns just the pack's mtime/summary/kinds_ok/kinds_failed, not the full multi-MB row payload,
// so it's cheap to poll every few seconds until mtime advances past whatever it was before the click.
async function forensicsFullMeta(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/forensics-full/meta`);
}

async function appControl(deviceId, action, payload = {}) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/appcontrol/${encodeURIComponent(action)}`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}

async function appControlStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/appcontrol/op-status`);
}

async function appControlEvents(deviceId, params = {}) {
  const label = labelForDevice(deviceId);
  const qs = new URLSearchParams(params).toString();
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/appcontrol/events${qs ? '?' + qs : ''}`);
}

// Linux Application Control (fapolicyd) — see the support service's own doc comment on
// linux_appcontrol_status()/linux_appcontrol_enable() for why this is a separate, simpler API
// than the Windows AppLocker one above (fapolicyd's allowlist is the package database itself,
// not a hand-approved per-app list).
async function linuxAppControlStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/status`);
}

// Generic Linux bash-over-Hop-2. The bastion route (POST /api/sessions/<label>/bash) already
// existed and is already behind the same internal-key auth as every other bridge call, so wiring
// it up here exposes nothing new. Base64-encoded server-side by the bastion (_run_bash_over_hop2),
// so the script text can't be mangled by Hop-2 argv/quoting.
async function sessionBash(deviceId, script, timeoutSec = 20) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/bash`, {
    method: 'POST', body: JSON.stringify({ script, timeoutSec }),
  });
}

async function linuxAppControlEnable(deviceId, mode) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/enable`, {
    method: 'POST', body: JSON.stringify({ mode: mode === 'enforce' ? 'enforce' : 'audit' }),
  });
}

async function linuxAppControlDisable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/disable`, { method: 'POST', body: '{}' });
}

async function linuxAppControlEvents(deviceId, n = 200) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/events?n=${encodeURIComponent(String(n))}`);
}

async function linuxAppControlApprove(deviceId, path) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/approve`, {
    method: 'POST', body: JSON.stringify({ path }),
  });
}

async function linuxAppControlApproveMany(deviceId, paths) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/approve-many`, {
    method: 'POST', body: JSON.stringify({ paths }),
  });
}

async function linuxAppControlExcludeFolder(deviceId, path) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/exclude-folder`, {
    method: 'POST', body: JSON.stringify({ path }), longRunning: true,
  });
}

async function linuxAppControlExcludedFolders(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/excluded-folders`);
}

async function linuxAppControlRemoveFolder(deviceId, path) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/appcontrol-linux/remove-folder`, {
    method: 'POST', body: JSON.stringify({ path }),
  });
}

async function winUpdate(deviceId, action, payload = {}) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/winupdate/${encodeURIComponent(action)}`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}

async function winUpdateStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/winupdate/scan-status`);
}

async function winUpdateList(deviceId, params = {}) {
  const label = labelForDevice(deviceId);
  const qs = new URLSearchParams(params).toString();
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/winupdate/updates${qs ? '?' + qs : ''}`);
}

// Force Windows Update Now — status GET can't ride the generic winUpdate() POST passthrough
// above; force-start/force-cancel themselves DO ride it (bastion routes them under the same
// /winupdate/<action> prefix). winupdate/force-status also returns the merged scheduled-security
// cycle state + schedule entries when one exists.
async function winUpdateForceStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/winupdate/force-status`);
}

// Security-only schedule ("Force Security Update Now" schedule) — status GET. Set/clear ride the
// generic winUpdate() POST passthrough under /winupdate/security-schedule, and the one-shot
// manual cycle rides /winupdate/security-start (both forward the body untouched).
async function winUpdateSecurityStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/winupdate/security-status`);
}

// Telemetry kill-switch (block/unblock/block-status) — same shape as winUpdate() above; action
// is passed straight through, bastion-side is the actual gate (see telemetry_block() in
// the support service).
async function blockTelemetry(deviceId, action, payload = {}) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/telemetry/${encodeURIComponent(action)}`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}

// Sentry Mode — endpoint honeypot (enable / disable / status / drain-outbox).
// See _SENTRY_PROVISION_PS1 / sentry_enable() / sentry_disable() / sentry_status() /
// sentry_drain() in the support service.
async function sentryEnable(deviceId, payload = {}) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/sentry/enable`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}
async function sentryDisable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/sentry/disable`, {
    method: 'POST', body: '{}',
  });
}
async function sentryStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/sentry/status`, {
    method: 'POST', body: '{}',
  });
}
async function sentryDrain(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/sentry/drain`, {
    method: 'POST', body: '{}',
  });
}

// Screen Text Capture -- UI Automation text extraction on Windows (enable / disable / status / drain-outbox).
// See _SCREENTEXT_PROVISION_PS1 / screentext_enable() / screentext_disable() / screentext_status() /
// screentext_drain() in the support service.
async function screenTextEnable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/screentext/enable`, {
    method: 'POST', body: '{}',
  });
}
async function screenTextDisable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/screentext/disable`, {
    method: 'POST', body: '{}',
  });
}
async function screenTextStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/screentext/status`, {
    method: 'POST', body: '{}',
  });
}
async function screenTextDrain(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/screentext/drain`, {
    method: 'POST', body: '{}',
  });
}

// USB Lockdown — USBGuard-style device control for Windows (enable / disable / status / drain-outbox).
// See _USB_LOCKDOWN_PS1 / usb_lockdown_block() / usb_lockdown_status() / usb_lockdown_drain() in the support service.
async function usbLockdownEnable(deviceId, payload = {}) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/enable`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}
async function usbLockdownDisable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/disable`, {
    method: 'POST', body: '{}',
  });
}
async function usbLockdownStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/status`, {
    method: 'POST', body: '{}',
  });
}
async function usbLockdownDrain(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/drain`, {
    method: 'POST', body: '{}',
  });
}
async function usbLockdownApprove(deviceId, instanceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/approve`, {
    method: 'POST', body: JSON.stringify({ instanceId }),
  });
}
async function usbLockdownBlocked(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/blocked`, {
    method: 'POST', body: '{}',
  });
}
// Linux-only: software replug for an approved device whose drivers never bound (USBGuard quirk).
async function usbLockdownReprobe(deviceId, instanceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/reprobe`, {
    method: 'POST', body: JSON.stringify({ instanceId }),
  });
}
// Linux-only: the persisted vid:pid approvals (approved.txt) — the actual allowlist source on the
// agent; the server-side Approval History is bookkeeping in comparison.
async function usbLockdownApproved(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/approved`, {
    method: 'POST', body: '{}',
  });
}
// Linux-only: revoke a persisted approval by vid:pid (drops approved.txt + rules.conf + live rules).
async function usbLockdownRemove(deviceId, vidPid) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/usblock/remove`, {
    method: 'POST', body: JSON.stringify({ vidPid }),
  });
}

// Defender exclusion — add/remove SentinelRemoteAssist folder from Windows Defender path
// exclusions + toggle automatic sample submission. Action passthrough pattern (same shape as
// blockTelemetry/winUpdate above).
async function defenderExclusion(deviceId, action, payload = {}) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/defender-exclusion/${encodeURIComponent(action)}`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}

// BitLocker — remote enable + live status. Both calls are one-shot (no bastion-side caching, no
// persisted script on the box — see bitlocker_enable()/bitlocker_status() in the support service);
// server.js is what persists any RecoveryPassword key protectors returned into its own encrypted
// bitlocker_keys table and the durable per-device status blob.
async function bitlockerEnable(deviceId, mountPoint) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/bitlocker/enable`, { method: 'POST', body: JSON.stringify({ mountPoint: mountPoint || 'C:' }) });
}
async function bitlockerStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/bitlocker/status`, { method: 'POST', body: '{}' });
}

// Boot ISO — stage (download + GRUB install + bcdedit), reboot into it, live status,
// and full restore (Windows boot manager back to normal, GRUB + ISO removed). See
// boot_iso_set()/boot_iso_reboot()/boot_iso_status()/boot_iso_restore() in the support service.
// The `entry` is the FULL catalog entry (id/name/url/size/sha256/isoFile/kernel/initrd) —
// the server validated it against the catalog before it ever reaches here.
async function bootIsoSet(deviceId, entry) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/bootiso/set`, {
    method: 'POST', body: JSON.stringify({ entry }),
  });
}
async function bootIsoReboot(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/bootiso/reboot`, { method: 'POST', body: '{}' });
}
async function bootIsoStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/bootiso/status`, { method: 'POST', body: '{}' });
}
async function bootIsoRestore(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/bootiso/restore`, { method: 'POST', body: '{}' });
}

// ARP scan (network discovery) — trigger a scan now, read the cached latest result, or
// get/set the per-device auto-scan interval. See arp_scan()/arp_scan_status()/
// get_arp_scan_schedule()/set_arp_scan_schedule() in the support service. Raw only — server.js is
// what turns a raw {ip,mac,hostname} list into persisted roster rows + spoof-detection events.
async function arpScan(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/arp-scan`, { method: 'POST', body: '{}' });
}
async function arpScanStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/arp-scan-status`);
}
async function getArpScanSchedule(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/arp-scan-schedule`);
}
async function setArpScanSchedule(deviceId, minutes) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/arp-scan-schedule`, {
    method: 'POST', body: JSON.stringify({ minutes }),
  });
}

// ARP sweep (velocity) detection — continuous pktmon-based watch, opt-in and separate from the
// scan above. See arp_sweep_watch_enable()/_disable()/_status()/drain_events() in the support service.
async function arpSweepWatchEnable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/arp-sweep-watch`, {
    method: 'POST', body: JSON.stringify({ enable: true }),
  });
}
async function arpSweepWatchDisable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/arp-sweep-watch`, {
    method: 'POST', body: JSON.stringify({ enable: false }),
  });
}
async function arpSweepWatchStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/arp-sweep-watch-status`);
}
async function arpSweepDrainEvents(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/arp-sweep-drain`, { method: 'POST', body: '{}' });
}

// ARP scan VLANs — manually-added VLAN subnets the user wants scanned alongside auto-detected
// local interfaces. CRUD operations passed through to the support service's /arp-vlans routes.
async function listArpVlans(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/arp-vlans`);
}
async function addArpVlan(deviceId, vlanLabel, subnet, vlanId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/arp-vlans`, {
    method: 'POST', body: JSON.stringify({ action: 'add', label: vlanLabel, subnet, vlanId: vlanId || null }),
  });
}
async function removeArpVlan(deviceId, subnet) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/arp-vlans`, {
    method: 'POST', body: JSON.stringify({ action: 'remove', subnet }),
  });
}

// EDR (continuous behavioral telemetry) — enable/disable the Sysmon-backed --edr-watch SYSTEM
// task, and read the accumulated rule-hit events. See enable_edr()/disable_edr()/get_edr_events()
// in the support service. Same shape as the ARP-sweep pair above (enable/disable, separate poll-side
// events read) — no "drain" step here, unlike ARP sweep, since get_edr_events() reads a jsonl file
// bastion already owns rather than something that has to be pulled+cleared over Hop-2 each time.
async function edrEnable(deviceId, force = false) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/enable`, {
    method: 'POST', body: JSON.stringify({ force }),
  });
}
async function edrDisable(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/disable`, { method: 'POST', body: '{}' });
}
// Wipe the accumulated findings feed ("Clear history" in the WebUI EDR panel). Bastion-side only —
// truncates the session's events.jsonl under the shared session-ops lock; suppression config
// (denylist, alert-suppression timers) is deliberately kept. See clear_edr_events() in the support service.
async function edrClear(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/clear`, { method: 'POST', body: '{}' });
}
async function edrEvents(deviceId, params = {}) {
  const label = labelForDevice(deviceId);
  const qs = new URLSearchParams(params).toString();
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/edr/events${qs ? '?' + qs : ''}`);
}
// Safe Boot Guard outbox drain — pulls the on-device safeboot-events.jsonl over Hop-2 and folds
// it into the regular EDR event stream. No-op (empty) when the box has never booted Safe Mode.
async function edrSafeBootDrain(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/safeboot-drain`, { method: 'POST', body: '{}' });
}
async function edrDenylistAdd(deviceId, process) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/denylist/add`, {
    method: 'POST', body: JSON.stringify({ process }),
  });
}
async function edrDenylistRemove(deviceId, process) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/denylist/remove`, {
    method: 'POST', body: JSON.stringify({ process }),
  });
}

// Phase 6 — AiTM/phishing-proxy confirmed-C2 block push. Bastion runs _PHISH_BLOCK_PS1 over Hop-2:
// Windows Firewall outbound deny rule for the IP + hosts-file sinkhole + KILL established
// connections to it. Called by the EDR poller's handlePhishingProxyHit() for c2-tier matches only.
// `domain` (optional) rides along for the hosts sinkhole half of the block.
async function phishBlock(deviceId, ip, domain) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/phish/block`, {
    method: 'POST', body: JSON.stringify({ ip: ip || '', domain: domain || '' }),
  });
}

// EDR Phase 2 — Remote Process Intervention + Dynamic Host Isolation. See edr_process_list()/
// edr_process_kill()/delete_edr_file()/edr_isolate_block()/edr_isolate_unblock()/
// edr_isolate_status() in the support service.
async function edrProcessList(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/edr/process-list`);
}
async function edrProcessKill(deviceId, pid) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/process-kill`, {
    method: 'POST', body: JSON.stringify({ pid }),
  });
}
// Phase 4 — see edr_process_suspend()/edr_process_resume() in the support service.
async function edrProcessSuspend(deviceId, pid) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/process-suspend`, {
    method: 'POST', body: JSON.stringify({ pid }),
  });
}
async function edrProcessResume(deviceId, pid) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/process-resume`, {
    method: 'POST', body: JSON.stringify({ pid }),
  });
}
async function edrFileDelete(deviceId, eventId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/file-delete`, {
    method: 'POST', body: JSON.stringify({ eventId }),
  });
}
async function edrIsolateBlock(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/isolate/block`, { method: 'POST', body: '{}' });
}
async function edrIsolateUnblock(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/edr/isolate/unblock`, { method: 'POST', body: '{}' });
}
async function edrIsolateStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/edr/isolate-status`);
}

// Streams the account-linked release exe for one (variant, account) pair — per-account since each
// account has its own Hop-1 keypair baked in; see build_account_linked_release()'s doc comment.
// Returns the raw fetch Response so server.js can pipe res.body straight through to the browser
// instead of fully buffering (the old downloadRelease() below awaited the ENTIRE ~150-200MB file
// into a Buffer before server.js could send a single byte on to the client — two full sequential
// transfers stacked back to back, found live 2026-07-19 as the main cause of the 20-30s dead wait
// before a download even starts to appear). the support service's route is internal-authed only (not
// the general API_KEY gate), matching this bridge's other calls.
async function streamReleaseResponse(variant, accountId) {
  const url = `${BASTION_INTERNAL_URL}/api/remote-assist-release/${encodeURIComponent(variant)}?account_id=${encodeURIComponent(String(accountId))}`;
  const res = await fetch(url, { headers: { 'X-Api-Key': BASTION_INTERNAL_KEY } });
  if (!res.ok) { const e = /** @type {any} */ (new Error(`bastion release download → HTTP ${res.status}`)); e.status = res.status; throw e; }
  return res;
}

// Old fully-buffered variant — kept in case a future caller genuinely needs the whole file in
// memory (e.g. to re-serve it multiple times without re-fetching); the download route above no
// longer uses this.
async function downloadRelease(variant, accountId) {
  const url = `${BASTION_INTERNAL_URL}/api/remote-assist-release/${encodeURIComponent(variant)}?account_id=${encodeURIComponent(String(accountId))}`;
  const res = await fetch(url, { headers: { 'X-Api-Key': BASTION_INTERNAL_KEY } });
  if (!res.ok) { const e = /** @type {any} */ (new Error(`bastion release download → HTTP ${res.status}`)); e.status = res.status; throw e; }
  return Buffer.from(await res.arrayBuffer());
}

// Triggers a (re)build of the account-linked release exe for one (variant, account) pair. Nothing
// account-specific is embedded any more — each device generates its own Hop-1 keypair at runtime
// (see provisionSession()'s doc comment) — so this is purely "compile the current agent source for
// this variant," not a per-account artifact.
async function buildRelease(variant, accountId) {
  return bastionFetch(`/api/remote-assist-release/${encodeURIComponent(variant)}/build`, {
    method: 'POST',
    body: JSON.stringify({ account_id: String(accountId) }),
  });
}

// Auto-provisioning installer variant (agent 2.0.3) — per-account exe with the account's multi-use
// bind-any enrollment ticket + server URL + ToS version baked in (see the support service's
// build_installer_release() + build_server.py's build_installer_exe()). The ticket is minted by
// server.js (POST /api/ra/installer-agent) and consumed by the device's first socket handshake —
// no login on the target PC.
async function buildInstallerRelease(accountId, webUrl, enrollmentTicket, tosVersion) {
  return bastionFetch('/api/remote-assist-release/installer/build', {
    method: 'POST',
    body: JSON.stringify({
      account_id: String(accountId),
      web_url: webUrl,
      enrollment_ticket: enrollmentTicket,
      tos_version: tosVersion,
    }),
  });
}

// Streams the auto-provisioning installer exe for one account — per-account since each download
// carries that account's own enrollment ticket baked in.
async function streamInstallerRelease(accountId) {
  const url = `${BASTION_INTERNAL_URL}/api/remote-assist-release/installer?account_id=${encodeURIComponent(String(accountId))}`;
  const res = await fetch(url, { headers: { 'X-Api-Key': BASTION_INTERNAL_KEY } });
  if (!res.ok) { const e = /** @type {any} */ (new Error(`bastion installer download → HTTP ${res.status}`)); e.status = res.status; throw e; }
  return res;
}

// Grants a standard OpenSSH ProxyJump entry on the bastion's dedicated jump account for this
// session's browser-generated public key, restricted (via authorized_keys' permitopen) to ONLY
// that session's Hop-1-forwarded port — no shell, no other port reachable through it. This is what
// makes `ssh -J jump-user@... target-user@127.0.0.1:<port>` work as a single portable command: the jump
// hop and the final hop both authenticate with the SAME session key, and the jump hop can reach
// nothing except this one device's forwarded port.
async function grantJumpAccess(deviceId, sshPublicKey, forwardPort) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/remote-assist/jump-access`, {
    method: 'POST', body: JSON.stringify({ sshPublicKey, forwardPort }),
  });
}

// TOTAL agent nuke (2.0.3) — reverts every PowerShell-level feature on the box, then kicks a
// SYSTEM --nuke task that removes the agent + everything it placed on the box. The box's sshd
// dies seconds later; ok only means the nuke was dispatched, so the caller unbinds the device
// immediately (server.js /api/devices/:id/remote-assist/nuke).
async function nukeAgent(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/nuke`, {
    method: 'POST', body: '{}',
  });
}

async function srpAudit(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/srp/audit`, {
    method: 'POST',
  });
}

async function srpAuditStatus(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/srp/audit-status`);
}

async function srpDeploy(deviceId, payload = {}) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/srp/deploy`, {
    method: 'POST', body: JSON.stringify(payload),
  });
}

// What actually ran (AppLocker event 8003, "would have been blocked") since Install Mode was
// last turned on — read-only, no side effects. See collect_applocker_install_mode_events()'s
// doc comment for why this is more precise than re-scanning installed programs.
async function srpInstallModeEvents(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/srp/install-mode-events`);
}

// Live Enforce-mode AppLocker activity — actual blocks (event 8004) + non-system allowed runs
// (event 8002) read straight from the event log, no Install Mode toggle and no full filesystem
// scan needed. See collect_applocker_activity()'s doc comment bastion-side.
async function srpActivity(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionGet(`/api/sessions/${encodeURIComponent(label)}/srp/activity`);
}

// Pulls the actual binary of an AppLocker-blocked path. Raw-fetch, NOT bastionFetch()/bastionGet()
// — those always JSON-parse the body, but a success response here is a raw octet-stream (see
// bastion's fetch_blocked_file_to_disk()/the fetch-blocked route's doc comment for why: base64'ing
// a file up to hundreds of MB into JSON is both slow and memory-heavy for no benefit). Returns
// { ok:true, buffer } on success or { ok:false, error, size?, needsForce? } parsed from bastion's
// JSON failure body — callers must branch on `ok`, never assume a Buffer is present.
async function fetchBlockedFile(deviceId, path, maxBytes, force) {
  if (!BASTION_INTERNAL_KEY) throw new Error('bastion bridge not configured (missing sentinel_bastion_internal_key secret)');
  const label = labelForDevice(deviceId);
  const res = await fetch(`${BASTION_INTERNAL_URL}/api/sessions/${encodeURIComponent(label)}/applocker/fetch-blocked`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': BASTION_INTERNAL_KEY },
    body: JSON.stringify({ path, maxBytes, force: !!force }),
  });
  if (!res.ok) {
    const body = /** @type {any} */ (await res.json().catch(() => ({})));
    return { ok: false, error: body.error || `HTTP ${res.status}`, size: body.size, needsForce: !!body.needs_force };
  }
  const arrayBuf = await res.arrayBuffer();
  return { ok: true, buffer: Buffer.from(arrayBuf) };
}

// File Backup — s3 is the decrypted config object server.js builds fresh from `settings` on every
// call (endpoint, bucket, accessKey, secretKey, region, encryptionPassword, bandwidthMbps); never
// cached bastion-side, mirroring the fetch_blocked_file/agent-update secret-handling pattern.
// folders (optional) is the admin's wellKnown/customPaths selection — see server.js's
// getFileBackupFolders()/setFileBackupFolders() and the support service's run_file_backup() doc
// comment. Omitted = bastion-side default (all 6 well-known folders, no custom paths).
async function fileBackupRun(deviceId, s3, folders, kind) {
  const label = labelForDevice(deviceId);
  const body = { s3 };
  if (folders) body.folders = folders;
  if (kind === 'incremental') body.kind = 'incremental';
  // longRunning: a real profile's SCP+tar+encrypt+rclone-upload routinely exceeds undici's default
  // 300s Agent timeout — see LONG_RUN_DISPATCHER's doc comment above.
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/file-backup/run`, {
    method: 'POST', body: JSON.stringify(body), longRunning: true,
  });
}
// Folder-picker modal — live remote directory listing (path='' lists every local drive letter)
// and a one-shot recursive size lookup for the folder the admin is about to confirm.
async function fileBackupBrowse(deviceId, path) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/file-backup/browse`, {
    method: 'POST', body: JSON.stringify({ path: path || '' }),
  });
}
async function fileBackupPathSize(deviceId, path) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/file-backup/path-size`, {
    method: 'POST', body: JSON.stringify({ path: path || '' }),
  });
}
async function fileBackupList(deviceId, s3) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/file-backup/list`, {
    method: 'POST', body: JSON.stringify({ s3 }),
  });
}
async function fileBackupRestore(deviceId, s3, backupKey, destPath) {
  const label = labelForDevice(deviceId);
  // longRunning — same reasoning as fileBackupRun() above (rclone download + decrypt + tar extract
  // + scp push is at least as long-running, often longer for a full chain replay).
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/file-backup/restore`, {
    method: 'POST', body: JSON.stringify({ s3, backupKey, destPath: destPath || undefined }), longRunning: true,
  });
}

// "Download" builds ONE complete, already-decrypted zip instead of the raw single .tar.enc object
// (an incremental backupKey pulls its base full backup plus every incremental up to itself, same
// chain-replay bastion's restore already does) — see the support service's build_stitched_backup_
// archive() doc comment. longRunning for the same reason fileBackupRestore is: rclone download +
// decrypt + tar extract (repeated per chain entry) + zip routinely exceeds undici's default
// timeout. The actual bytes are fetched separately (server.js streams them directly from bastion's
// GET .../file-backup/download-fetch, not through this JSON-returning helper) once this resolves ok.
async function fileBackupPrepareDownload(deviceId, s3, backupKey, runId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/file-backup/download-prepare`, {
    method: 'POST', body: JSON.stringify({ s3, backupKey, runId }), longRunning: true,
  });
}

// Not device/label-scoped — pure S3 delete, works even for an offline device (retention pruning
// must not depend on the device being reachable).
async function fileBackupDelete(s3, key) {
  return bastionFetch('/api/file-backup/delete', { method: 'POST', body: JSON.stringify({ s3, key }) });
}

// Derives AppLocker's own Publisher/ProductName/BinaryName identity for one exe (via
// Get-AppLockerFileInformation on the box) — the "Approve by Publisher" action. Scoped to that
// exact product+binary, never a bare publisher match; see _APPLOCKER_PUBLISHER_INFO_PS1's doc
// comment in the support service for why a raw Authenticode Subject string can't be used directly here.
async function srpPublisherInfo(deviceId, path) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/srp/publisher-info`, {
    method: 'POST', body: JSON.stringify({ path }),
  });
}

// Windows Fleet menu — arbitrary caller-supplied PowerShell on one device. Script content never
// touches a shell string bastion-side (base64 -EncodedCommand — see _run_powershell_over_hop2()'s
// doc comment); this call itself is a plain JSON POST, so ordinary body-based transport is fine.
// timeoutSec is clamped bastion-side to [5,300]; the request itself has no separate client-side
// timeout, matching runForensics()/runAudit() (already routinely take 1-3 minutes over this path).
async function runPowerShell(deviceId, script, opts) {
  const timeoutSec = (opts || {}).timeoutSec;
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/powershell`, {
    method: 'POST', body: JSON.stringify({ script, timeoutSec }),
  });
}

// "Nuke" — act on (and/or mark-safe) a subset of the LAST STORED IT-audit's findings, matched by
// exact finding text server-side against remediate_audit_findings()'s own record of what that
// audit actually found (never a client-supplied remediation object) — see that function's doc
// comment in the support service. Invalidate the cached audit-status read so the dashboard's next poll
// picks up the post-remediation finding list rather than a stale pre-Nuke cache entry.
async function remediateAuditFindings(deviceId, removeTexts = [], safeTexts = []) {
  const label = labelForDevice(deviceId);
  invalidateAuditCache(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/it-audit/remediate`, {
    method: 'POST', body: JSON.stringify({ removeTexts, safeTexts }),
  });
}

// Fetches a specific file flagged as evidence by the last IT audit, base64-encoded in the JSON
// response (bastion-side caps it at 100MB) — for download/further inspection (e.g. VirusTotal).
// path must exactly match an evidence_file value from that same last audit (validated
// bastion-side in fetch_audit_evidence_file()), never an arbitrary path.
async function fetchAuditFile(deviceId, path) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/it-audit/fetch-file`, {
    method: 'POST', body: JSON.stringify({ path }),
  });
}

// ── Persistent Hop-2 key — session-scoped, never rotates without explicit Regen ──────────
// The bastion mints a per-session ed25519 keypair (hop2_ed25519) for Hop-2 access.
// The server calls this to get the PRIVATE key material so it can persist it encrypted.
// INTERNAL_KEY-authed on the bastion — this is the trusted server bridge, not an operator call.
async function getSessionHop2Key(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/hop2-key`, { method: 'GET' });
}

async function regenSessionHop2Key(deviceId) {
  const label = labelForDevice(deviceId);
  return bastionFetch(`/api/sessions/${encodeURIComponent(label)}/hop2-key/regen`, { method: 'POST' });
}

module.exports = {
  configured, labelForDevice, adminSupportPubKey, provisionSession, setDisplayName, endSession, revokeSession, sessionStatus,
  getLatestAgentVersion, agentUpdate,
  runForensics, forensicsFull, forensicsKind, forensicsFullMeta, appControl, appControlStatus, appControlEvents,
  winUpdate, winUpdateStatus, winUpdateList, winUpdateForceStatus, winUpdateSecurityStatus, blockTelemetry, defenderExclusion, grantJumpAccess,
  linuxAppControlStatus, linuxAppControlEnable, linuxAppControlDisable, linuxAppControlEvents, linuxAppControlApprove, linuxAppControlApproveMany, linuxAppControlExcludeFolder, linuxAppControlExcludedFolders, linuxAppControlRemoveFolder,
  sessionBash,
  bitlockerEnable, bitlockerStatus, bootIsoSet, bootIsoReboot, bootIsoStatus, bootIsoRestore,
  arpScan, arpScanStatus, getArpScanSchedule, setArpScanSchedule,
  arpSweepWatchEnable, arpSweepWatchDisable, arpSweepWatchStatus, arpSweepDrainEvents,
  listArpVlans, addArpVlan, removeArpVlan,
  edrEnable, edrDisable, edrClear, edrEvents, edrSafeBootDrain, edrDenylistAdd, edrDenylistRemove,
  phishBlock,
  edrProcessList, edrProcessKill, edrProcessSuspend, edrProcessResume, edrFileDelete, edrIsolateBlock, edrIsolateUnblock, edrIsolateStatus,
  srpAudit, srpAuditStatus, srpDeploy, srpInstallModeEvents, srpActivity, srpPublisherInfo, fetchBlockedFile,
  fileBackupRun, fileBackupList, fileBackupRestore, fileBackupDelete, fileBackupPrepareDownload,
  fileBackupBrowse, fileBackupPathSize,
  downloadRelease, streamReleaseResponse, buildRelease, buildInstallerRelease, streamInstallerRelease,
  nukeAgent,
  sessionAuditCached, sessionAuditLive, invalidateAuditCache, runAudit, getAuditSchedule, setAuditSchedule,
  remediateAuditFindings, fetchAuditFile, runPowerShell,
  sentryEnable, sentryDisable, sentryStatus, sentryDrain,
  screenTextEnable, screenTextDisable, screenTextStatus, screenTextDrain,
  usbLockdownEnable, usbLockdownDisable, usbLockdownStatus, usbLockdownDrain, usbLockdownApprove, usbLockdownBlocked, usbLockdownReprobe,
  usbLockdownApproved, usbLockdownRemove,
  getSessionHop2Key, regenSessionHop2Key,
};
