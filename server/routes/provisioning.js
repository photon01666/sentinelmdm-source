// routes/provisioning.js — APK downloads, Windows/RA agent provisioning, license trial.
const { GetObjectCommand } = require('@aws-sdk/client-s3');
module.exports = ({ R2_BUCKET, SERVER_ORIGIN, app, crypto, db, decryptBuffer,
                    getActiveApkBuild, kv, log, makeRateLimit, r2, r2Del, r2Get,
                    requireAuth, requireUnlocked, stmts, session }) => {
app.get('/api/update/apk', requireUnlocked, async (req, res) => {
  const dlToken = req.query.token;
  const tok = dlToken ? await kv.getdelJSON('apkdl:' + dlToken) : null;  // atomic one-time consume
  const tokenValid = !!tok;
  if (!tokenValid && !req.session?.authenticated)
    return res.status(401).json({ error: 'Unauthorized' });
  // A token download serves the exact build it was minted for; an authenticated
  // admin without a token gets the active build.
  let r2Key, name;
  if (tokenValid) {
    r2Key = tok.r2Key; name = tok.name;
  } else {
    const b = (await getActiveApkBuild());
    if (!b) return res.status(404).json({ error: 'No APK uploaded' });
    r2Key = b.r2Key; name = b.name;
  }
  try {
    const buf = await r2Get(r2Key);
    if (!buf) return res.status(404).json({ error: 'APK file not found in storage' });
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    res.setHeader('Content-Length', buf.length);
    res.send(buf);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Sideload APK download — before auth wall so devices can fetch with a one-time token
app.get('/api/install-apk', requireUnlocked, async (req, res) => {
  const dlToken = req.query.token;
  let r2Key = null;
  if (dlToken) {
    const entry = await kv.getdelJSON('installapk:' + dlToken);  // atomic one-time consume
    if (entry) r2Key = entry.r2Key;
  }
  if (!r2Key && !req.session?.authenticated)
    return res.status(401).json({ error: 'Unauthorized' });
  if (!r2Key) return res.status(400).json({ error: 'Valid token required' });
  try {
    const encBuf = await r2Get(r2Key);
    if (!encBuf) return res.status(404).json({ error: 'APK not found in storage' });
    const buf = decryptBuffer(encBuf);
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    res.setHeader('Content-Disposition', 'attachment; filename="app.apk"');
    res.setHeader('Content-Length', buf.length);
    res.send(buf);
    // Delete from R2 after serving — one-time-use, no need to keep it
    r2Del(r2Key).catch(() => {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// SentinelRemoteAssist account-linked installer download — pre-auth (before app.use(requireAuth))
// mirroring /api/update/apk's pattern. PER-ACCOUNT: every account (public or admin/sub-user) only
// ever downloads its OWN built copy — scoped to req.session.userId, never a shared file (see
// bastionClient.downloadRelease()'s doc comment). The admin variant is still restricted to
// admin/admin_created accounts — a public user has no legitimate reason to run the admin-fleet
// build, but otherwise this is now self-service for public accounts too (must POST
// /api/remote-assist/build at least once first — see below).
app.get('/api/remote-assist/download', requireUnlocked, async (req, res) => {
  if (!req.session?.authenticated) return res.status(401).json({ error: 'Unauthorized' });
  const variant = req.query.variant === 'admin' ? 'admin' : 'public';
  if (variant === 'admin' && req.session.role !== 'admin' && req.session.account_type !== 'admin_created')
    return res.status(403).json({ error: 'Admin/sub-user accounts only' });
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion bridge not configured on the server' });
  try {
    // Pipe bastion's response straight through rather than buffering the whole ~150-200MB file
    // first (the old downloadRelease() awaited the ENTIRE file into memory before a single byte
    // reached the browser — two full sequential transfers back to back, the main cause of a
    // reported 20-30s dead wait before anything visibly happened). See
    // bastionClient.streamReleaseResponse()'s doc comment.
    const bastionRes = (await bastionClient.streamReleaseResponse(variant, req.session.userId));
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="Windows_Agent.exe"');
    const len = bastionRes.headers.get('content-length');
    if (len) res.setHeader('Content-Length', len);
    const { Readable } = require('node:stream');
    Readable.fromWeb(bastionRes.body).pipe(res).on('error', (err) => {
      log('warn', 'remote-assist download stream error', { err: err.message });
      res.destroy();
    });
  } catch (e) {
    const status = e.status === 404 ? 404 : 502;
    res.status(status).json({ error: status === 404 ? 'Not built yet — click Build/Rebuild agent first' : 'Failed to reach bastion bridge' });
  }
});

// SentinelRemoteAssist account-linked release build trigger — self-service for ANY logged-in
// account (public users included, see the "regenerate agent with a new key" feature). Always
// scoped to the CALLER's own account — there is no target-user param, a public user can only ever
// rebuild their own copy. Nothing account-specific is embedded at build time any more — each
// device generates its own Hop-1 keypair at runtime (Hop1Identity.cs) — so "rebuild" here is only
// ever useful for picking up newer agent code, never for invalidating a device's access; use the
// per-device Revoke on the bastion for that instead.
app.post('/api/remote-assist/build', requireUnlocked, requireAuth, async (req, res) => {
  const isAdminAccount = req.session.role === 'admin' || req.session.account_type === 'admin_created';
  const variant = (isAdminAccount && req.body?.variant === 'admin') ? 'admin' : 'public';
  const accountId = req.session.userId;
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion bridge not configured on the server' });
  try {
    const result = (await bastionClient.buildRelease(variant, accountId));
    log('info', 'Remote-assist release build triggered', { variant, accountId, result: result.ok ? 'ok' : 'failed' });
    res.json(result);
  } catch (e) {
    log('error', 'Remote-assist release build failed', { variant, accountId, error: e.message });
    res.status(502).json({ error: 'Build failed', detail: e.message });
  }
});

// ── Auto-provisioning Windows agent (installer variant, agent 2.0.3) ───────────
// A per-account exe (bastion /build-installer) bakes the account's multi-use bind-any enrollment
// ticket + server URL + ToS version. On the target PC: ToS/MSA dialog (fetched here, versioned) ->
// UAC elevated install with persistence -> ticket enrollment over the socket handshake — no login.
// These routes are PRE-AUTH on purpose: the agent fetches the ToS and records consent BEFORE it
// has any session (the device id is generated locally at first run).
// ⚠️ terms_url MUST point at the PUBLIC site (PUBLIC_SITE_URL/legal/*), never at
// SERVER_ORIGIN. `${SERVER_ORIGIN}/terms` was a dead link: no /terms route exists on the app
// server, so it fell through to `app.use(requireAuth)` and 302'd to /login — the consent dialog's
// "View full terms" link landed the user on a sign-in page instead of the agreement. Asking
// someone to accept documents they demonstrably cannot open is the clearest way to lose a
// clickwrap, so the URLs here must stay unauthenticated and must be verified to return 200.
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || 'http://localhost:3000';
const RA_TOS_VERSION = '2';
const RA_TOS_TERMS_URL = `${PUBLIC_SITE_URL}/legal/terms`;
const RA_TOS_MSA_URL   = `${PUBLIC_SITE_URL}/legal/msa`;
const RA_TOS_TITLE = 'Sentinel Terms of Service && Master Service Agreement';
// Both URLs are repeated in the body text because the dialog only renders ONE clickable link
// (ConsentDialog.cs `linkUrl`); in the body they are at least visible and copyable for the
// document the link doesn't cover. Give the agent a second LinkLabel and this can be trimmed.
const RA_TOS_BODY = [
  'Sentinel Remote Assist will be installed on this computer and will maintain secure remote access on behalf of the account that requested it. The account holder is responsible for this device.',
  '',
  'By accepting, you agree to the Sentinel Master Service Agreement and the Terms of Service. You can read them here:',
  `  Master Service Agreement — ${RA_TOS_MSA_URL}`,
  `  Terms of Service — ${RA_TOS_TERMS_URL}`,
  '',
  'This grants remote administrative access to this computer: authorized support personnel can run commands, install and remove software, change security settings, access files and restart the machine. Remote sessions are recorded, and access is limited to personnel acting on behalf of the account that owns this device.',
  '',
  'Security controls applied to this computer may block unapproved applications, restrict USB storage, manage Windows Update and restart the machine to apply updates. Restarts show an on-screen warning first, but unsaved work may still be lost.',
  '',
  'You may remove the agent at any time from the SentinelMDM dashboard (NUKE Agent — remove everything), or by running the installer again.',
].join('\r\n');

app.get('/api/ra/tos', requireUnlocked, (_req, res) => {
  res.json({
    version: RA_TOS_VERSION, title: RA_TOS_TITLE, body: RA_TOS_BODY,
    terms_url: RA_TOS_TERMS_URL,
    msa_url:   RA_TOS_MSA_URL,   // newer agents can render a second link; older ones ignore it
  });
});

// Consent record from the agent after the user accepts the dialog on the target PC. Pre-auth and
// unauthenticated-by-design (the device has no session yet). Metadata only: deviceId + version +
// timestamp — the audit trail proving consent for remote access. Cheap rate limit so an anonymous
// flooder can't spam the table.
const raConsentRateLimit = makeRateLimit(30, 60 * 1000, 'ra-consent');
app.post('/api/ra/consent', requireUnlocked, raConsentRateLimit, async (req, res) => {
  const deviceId = String(req.body?.deviceId || '').trim().slice(0, 128);
  const tosVersion = String(req.body?.tosVersion || '').trim().slice(0, 32);
  const accepted = req.body?.accepted === true;
  if (!deviceId || !tosVersion) return res.status(400).json({ error: 'deviceId and tosVersion required' });
  try {
    (await db.prepare('INSERT INTO ra_consents (device_id, tos_version, accepted, created_at) VALUES (?,?,?,?)')
      .run(deviceId, tosVersion, accepted ? 1 : 0, Date.now()));
    res.json({ ok: true });
  } catch (e) {
    log('warn', 'ra consent record failed', { deviceId, error: e.message });
    res.status(500).json({ error: 'record failed' });
  }
});

// Mint an auto-provisioning installer agent for an account: creates the multi-use bind-any ticket
// and triggers the bastion build that bakes it into the per-account exe. The ACCOUNT HOLDER calls
// it from their own session (public / business_sub); an admin may mint on behalf of any RA-eligible
// account by passing accountId. The ticket is revocable (POST .../revoke) and self-expires (30d).
app.post('/api/ra/installer-agent', requireUnlocked, requireAuth, async (req, res) => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion bridge not configured on the server' });
  try {
    const isAdmin = req.session.role === 'admin' || req.session.account_type === 'admin_created';
    let targetUserId = req.session.userId;
    if (isAdmin && req.body?.accountId) {
      const acct = String(req.body.accountId).trim();
      const row = (/^\d+$/.test(acct)
        ? (await db.prepare('SELECT id, account_type, status FROM users WHERE id=?').get(Number(acct)))
        : (await db.prepare('SELECT id, account_type, status FROM users WHERE lower(email)=lower(?)').get(acct)));
      if (!row) return res.status(404).json({ error: 'Target account not found' });
      targetUserId = row.id;
      if (row.account_type !== 'public' && row.account_type !== 'business_sub')
        return res.status(400).json({ error: 'Target account type cannot own remote-assist agents' });
    }
    const me = (await db.prepare('SELECT id, email, username, account_type, status FROM users WHERE id=?').get(targetUserId));
    if (!me || me.status !== 'active') return res.status(403).json({ error: 'Account not active' });
    if (me.account_type !== 'public' && me.account_type !== 'business_sub')
      return res.status(403).json({ error: 'This account type cannot mint installer agents' });

    // 2026-08-17: cap raised 25 -> 500 for the fleet-maintenance boot-ISO model — a single
    // shared live ISO bakes ONE ticket and every booted machine consumes one use (fresh identity
    // per boot), so a 25-cap forced a rebuild+re-upload every 25 maintenance sessions. The cap
    // is a defense-in-depth guard against a fat-fingered huge number, not a security boundary;
    // the ticket itself is revocable and self-expiring regardless of quota.
    const uses = Math.min(Math.max(Number(req.body?.uses) || 5, 1), 500);
    const ticket = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + 30 * 24 * 60 * 60 * 1000; // 30 days
    (await stmts.insertInstallerTicket.run(ticket, me.id, '', 'installer', uses, expiresAt, now, 'windows'));

    // bastionFetch THROWS on non-2xx (not just returns !ok) — either failure mode must revoke the
    // just-minted ticket, or a failed build leaves a live, never-baked installer ticket dangling
    // (found live 2026-08-03: the pre-bastion-redeploy 404 left one active).
    let result;
    try {
      result = (await bastionClient.buildInstallerRelease(me.id, SERVER_ORIGIN, ticket, RA_TOS_VERSION));
    } catch (e) {
      result = { ok: false, error: e.message };
    }
    if (!result.ok) {
      // Build failed — don't leave a dangling ticket minted for nothing. Zero uses_remaining too
      // (consumed_at alone is the revoked marker but leaving the quota non-zero would keep the
      // ticket visible in the outstanding-installers list).
      (await stmts.revokeEnrollTicket.run(Date.now(), ticket, 'installer'));
      (await db.prepare("UPDATE enrollment_tickets SET uses_remaining=0 WHERE ticket=?").run(ticket));
      log('error', 'Installer agent build failed', { accountId: me.id, error: result.error, detail: result.detail });
      return res.status(502).json({ error: 'Agent build failed — try again in a moment', detail: result.error });
    }
    log('info', 'Installer agent minted', { accountId: me.id, uses, ticket: ticket.slice(0, 8) });
    res.json({ ok: true, ticket, uses, expires_at: expiresAt, tos_version: RA_TOS_VERSION });
  } catch (e) {
    log('error', 'Installer agent mint error', { error: e.message });
    res.status(502).json({ error: 'Failed to create installer agent', detail: e.message });
  }
});

// Mint an auto-provisioning installer agent for the LINUX agent (sentineld) — the Linux
// counterpart of POST /api/ra/installer-agent, minus the bastion exe build: the per-account
// install command the WebUI copies carries the ticket in its URL, and GET
// /api/remote-assist/linux/install.sh?ticket=<t> bakes it into the served script (the Linux
// equivalent of baking it into the exe). The device then enrolls with NO login — `sentineld
// enroll --ticket <t>` — and the server binds it on the first socket handshake via the same
// kind='installer' multi-use consume path as the Windows exe. No bastion round-trip: nothing
// platform-specific is compiled per account, so minting is instant and never fails on a bastion
// bridge outage. Ticket self-expires (30d) and is revocable via the shared installer-ticket
// revoke route (it lists in /api/ra/installer-agents?platform=linux).
app.post('/api/ra/linux-installer-agent', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const isAdmin = req.session.role === 'admin' || req.session.account_type === 'admin_created';
    let targetUserId = req.session.userId;
    if (isAdmin && req.body?.accountId) {
      const acct = String(req.body.accountId).trim();
      const row = (/^\d+$/.test(acct)
        ? (await db.prepare('SELECT id, account_type, status FROM users WHERE id=?').get(Number(acct)))
        : (await db.prepare('SELECT id, account_type, status FROM users WHERE lower(email)=lower(?)').get(acct)));
      if (!row) return res.status(404).json({ error: 'Target account not found' });
      targetUserId = row.id;
      if (row.account_type !== 'public' && row.account_type !== 'business_sub')
        return res.status(400).json({ error: 'Target account type cannot own remote-assist agents' });
    }
    const me = (await db.prepare('SELECT id, email, username, account_type, status FROM users WHERE id=?').get(targetUserId));
    if (!me || me.status !== 'active') return res.status(403).json({ error: 'Account not active' });
    if (me.account_type !== 'public' && me.account_type !== 'business_sub')
      return res.status(403).json({ error: 'This account type cannot mint installer agents' });

    // 2026-08-17: cap raised 25 -> 500 for the fleet-maintenance boot-ISO model (see the
    // Windows route above for the rationale).
    const uses = Math.min(Math.max(Number(req.body?.uses) || 5, 1), 500);
    const ticket = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const expiresAt = now + 30 * 24 * 60 * 60 * 1000; // 30 days
    (await stmts.insertInstallerTicket.run(ticket, me.id, '', 'installer', uses, expiresAt, now, 'linux'));

    const installUrl = `${SERVER_ORIGIN}/api/remote-assist/linux/install.sh?ticket=${ticket}`;
    const installCommand = `curl -fsSL "${installUrl}" | sudo bash`;
    log('info', 'Linux installer agent minted', { accountId: me.id, uses, ticket: ticket.slice(0, 8) });
    res.json({ ok: true, ticket, uses, expires_at: expiresAt, install_command: installCommand });
  } catch (e) {
    log('error', 'Linux installer agent mint error', { error: e.message });
    res.status(502).json({ error: 'Failed to create Linux installer agent', detail: e.message });
  }
});

// List outstanding (unconsumed) installer tickets — scoped to the caller's own account unless admin.
// ?platform=windows|linux filters by the installer's target platform (the WebUI keeps the Windows
// and Linux dropdown lists separate); omitted = all platforms.
app.get('/api/ra/installer-agents', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const isAdmin = req.session.role === 'admin' || req.session.account_type === 'admin_created';
    const platform = String(req.query.platform || '').trim() || null;
    const rows = (await stmts.listInstallerTickets.all(Date.now(), platform, platform))
      .filter(r => isAdmin || r.user_id === req.session.userId)
      .map(r => ({ ticket: r.ticket, uses_remaining: r.uses_remaining, expires_at: r.expires_at, created_at: r.created_at, platform: r.platform }));
    res.json({ agents: rows });
  } catch (e) {
    log('error', 'Installer agents list error', { error: e.message });
    res.status(500).json({ error: 'list failed' });
  }
});

// Revoke an outstanding installer ticket — the baked exe stops enrolling devices immediately.
app.post('/api/ra/installer-agents/:ticket/revoke', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const t = String(req.params.ticket || '').trim();
    const row = (await stmts.getEnrollTicket.get(t));
    if (!row || row.kind !== 'installer') return res.status(404).json({ error: 'Ticket not found' });
    const isAdmin = req.session.role === 'admin' || req.session.account_type === 'admin_created';
    if (!isAdmin && row.user_id !== req.session.userId) return res.status(403).json({ error: 'Not your ticket' });
    (await stmts.revokeEnrollTicket.run(Date.now(), t, 'installer'));
    // Also zero uses_remaining so the ticket disappears from the list
    (await db.prepare("UPDATE enrollment_tickets SET uses_remaining=0 WHERE ticket=?").run(t));
    log('info', 'Installer agent ticket revoked', { accountId: row.user_id, ticket: t.slice(0, 8) });
    res.json({ ok: true });
  } catch (e) {
    log('error', 'Installer agent revoke error', { error: e.message });
    res.status(500).json({ error: 'revoke failed' });
  }
});

// Bulk revoke all outstanding installer tickets (admin only)
app.post('/api/ra/installer-agents/revoke-all', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const isAdmin = req.session.role === 'admin' || req.session.account_type === 'admin_created';
    if (!isAdmin) return res.status(403).json({ error: 'Admins only' });
    const { changes } = await db.prepare("UPDATE enrollment_tickets SET consumed_at=? WHERE kind='installer' AND consumed_at IS NULL").run(Date.now());
    log('info', 'Bulk revoked installer tickets', { count: changes });
    res.json({ ok: true, revoked: changes });
  } catch (e) {
    log('error', 'Bulk revoke error', { error: e.message });
    res.status(500).json({ error: 'bulk revoke failed' });
  }
});

// Download the auto-provisioning installer exe — session-scoped to the caller's own account
// (admins may pass ?accountId= for an account they minted on behalf of). Mirrors the account-linked
// release download's stream-through behavior (never buffer the whole ~200MB file server-side).
app.get('/api/ra/installer-agent/download', requireUnlocked, async (req, res) => {
  if (!req.session?.authenticated) return res.status(401).json({ error: 'Unauthorized' });
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion bridge not configured on the server' });
  let accountId = req.session.userId;
  if (req.query.accountId) {
    const isAdmin = req.session.role === 'admin' || req.session.account_type === 'admin_created';
    if (!isAdmin) return res.status(403).json({ error: 'Admins only' });
    accountId = String(req.query.accountId).trim();
  }
  try {
    const bastionRes = (await bastionClient.streamInstallerRelease(accountId));
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="SentinelRemoteAssist-Install.exe"');
    const len = bastionRes.headers.get('content-length');
    if (len) res.setHeader('Content-Length', len);
    const { Readable } = require('node:stream');
    Readable.fromWeb(bastionRes.body).pipe(res).on('error', () => res.destroy());
  } catch (e) {
    res.status(e.status === 404 ? 404 : 502).json({ error: e.status === 404 ? 'Not built yet — create an installer agent first' : 'Failed to reach bastion bridge' });
  }
});

// ── SentinelRemoteAssist Linux agent (sentineld) — public, unauthenticated download ────────────
// Deliberately NOT session/account-gated, unlike the Windows exe download above: the installer
// script and the sentineld binary are generic across accounts (matches this Linux port's "push
// secrets post-enrollment, never bake them" design) — the ACCOUNT-SPECIFIC bit is the optional
// ?ticket= query param, which bakes the caller's multi-use enrollment ticket into the served
// script (the Linux equivalent of the Windows builder baking it into the exe). With a valid
// ticket the target server enrolls with NO login; without one the script falls back to the
// interactive `sentineld enroll` sign-in, so a leaked/revoked URL degrades safely instead of
// failing. The ticket itself is the credential (32-byte random, revocable, 30d expiry) — the
// same unauthenticated-download posture as the Windows exe download.
// Both objects live in R2 bucket sentinel-db under the remote-assist/linux/ prefix — confirmed
// distinct from the apks/ (plural) prefix runDbCleanup()'s 30-day purge targets, and distinct
// from apk/ (singular, used by the public/client APK routes above) — safe from both.
const REMOTE_ASSIST_LINUX_R2_PREFIX = 'remote-assist/linux/';

// The literal marker build-standalone-install.sh embeds in the generated installer for the
// server to substitute a real ticket into. MUST appear exactly once in the served script — the
// same exact-once discipline as the Windows builder's __EXTRA_PUBKEY__ token (a twice-replaced
// marker is how a multi-line value silently corrupted a generated artifact there).
const LINUX_INSTALL_TICKET_MARKER = '__LINUX_INSTALL_TICKET__';

app.get('/api/remote-assist/linux/install.sh', async (req, res) => {
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: `${REMOTE_ASSIST_LINUX_R2_PREFIX}install.sh` }));
    let body = await obj.Body.transformToString();
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="install.sh"');
    res.setHeader('Cache-Control', 'no-cache'); // installer may be updated independently of any version bump a curl caller would know to bust

    const ticket = String(req.query.ticket || '').trim();
    if (ticket) {
      const t = (await stmts.getEnrollTicket.get(ticket));
      const valid = t && t.kind === 'installer' && t.platform === 'linux' &&
        !t.consumed_at && t.uses_remaining > 0 && t.expires_at > Date.now();
      if (!valid) {
        // Revoked/exhausted/expired/unknown ticket — serve the plain installer (interactive
        // enroll fallback). Never fail the install over a stale URL.
        log('warn', 'Linux install.sh requested with invalid installer ticket — serving plain installer', { ticket: ticket.slice(0, 8) });
      } else {
        const occurrences = body.split(LINUX_INSTALL_TICKET_MARKER).length - 1;
        if (occurrences !== 1) {
          log('error', 'Linux install.sh ticket marker count mismatch — refusing to bake ticket', { occurrences });
          return res.status(500).send('# installer ticket marker missing — re-run build-standalone-install.sh and re-upload\n');
        }
        body = body.replace(LINUX_INSTALL_TICKET_MARKER, ticket);
        log('info', 'Linux install.sh served with baked installer ticket', { ticket: ticket.slice(0, 8) });
      }
    }
    res.send(body);
  } catch (e) {
    res.status(404).type('text/plain').send('# Linux agent installer not published yet\n');
  }
});

// Same one-off manual-apply posture, for the self-update.sh systemd-run restart fix (2026-07-29 —
// the old nohup/disown deferred restart didn't reliably survive the Hop-2 session tearing down).
app.get('/api/remote-assist/linux/self-update.sh', async (req, res) => {
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: `${REMOTE_ASSIST_LINUX_R2_PREFIX}self-update.sh` }));
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="self-update.sh"');
    res.setHeader('Cache-Control', 'no-cache');
    (/** @type {any} */ (obj.Body)).pipe(res);
  } catch (e) {
    res.status(404).type('text/plain').send('# self-update.sh not published yet\n');
  }
});
// Same one-off manual-apply posture, for the new Application Control (fapolicyd) feature
// (2026-07-29) — appcontrol-deploy.sh + the sudoers snippet below it need to reach an
// already-installed box without a full install.sh re-run.
app.get('/api/remote-assist/linux/appcontrol-deploy.sh', async (req, res) => {
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: `${REMOTE_ASSIST_LINUX_R2_PREFIX}appcontrol-deploy.sh` }));
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="appcontrol-deploy.sh"');
    res.setHeader('Cache-Control', 'no-cache');
    (/** @type {any} */ (obj.Body)).pipe(res);
  } catch (e) {
    res.status(404).type('text/plain').send('# appcontrol-deploy.sh not published yet\n');
  }
});
// Same one-off manual-apply posture, for the new ARP scan + ARP-sweep detection feature
// (2026-08-05) — arpsweep-deploy.sh + the sudoers grant it needs must reach an already-installed
// box without a full install.sh re-run (the binary half rides the normal sentineld self-update).
app.get('/api/remote-assist/linux/arpsweep-deploy.sh', async (req, res) => {
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: `${REMOTE_ASSIST_LINUX_R2_PREFIX}arpsweep-deploy.sh` }));
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="arpsweep-deploy.sh"');
    res.setHeader('Cache-Control', 'no-cache');
    (/** @type {any} */ (obj.Body)).pipe(res);
  } catch (e) {
    res.status(404).type('text/plain').send('# arpsweep-deploy.sh not published yet\n');
  }
});
// Same one-off manual-apply posture, for the USB Lockdown persisted-approval fix
// (2026-08-05) — usblock-deploy.sh must reach an already-installed box without a full
// install.sh re-run (which ends in a fresh interactive `sentineld enroll`).
app.get('/api/remote-assist/linux/usblock-deploy.sh', async (req, res) => {
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: `${REMOTE_ASSIST_LINUX_R2_PREFIX}usblock-deploy.sh` }));
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="usblock-deploy.sh"');
    res.setHeader('Cache-Control', 'no-cache');
    (/** @type {any} */ (obj.Body)).pipe(res);
  } catch (e) {
    res.status(404).type('text/plain').send('# usblock-deploy.sh not published yet\n');
  }
});
app.get('/api/remote-assist/linux/sentinel-remote-assist.sudoers', async (req, res) => {
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: `${REMOTE_ASSIST_LINUX_R2_PREFIX}sentinel-remote-assist.sudoers` }));
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'inline; filename="sentinel-remote-assist.sudoers"');
    res.setHeader('Cache-Control', 'no-cache');
    (/** @type {any} */ (obj.Body)).pipe(res);
  } catch (e) {
    res.status(404).type('text/plain').send('# sudoers snippet not published yet\n');
  }
});

app.get('/api/remote-assist/linux/sentineld', async (req, res) => {
  const arch = req.query.arch === 'arm64' ? 'arm64' : 'amd64';
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: `${REMOTE_ASSIST_LINUX_R2_PREFIX}sentineld-${arch}` }));
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="sentineld"');
    const len = obj.ContentLength;
    if (len) res.setHeader('Content-Length', len);
    (/** @type {any} */ (obj.Body)).pipe(res).on('error', (err) => {
      log('warn', 'remote-assist linux binary stream error', { err: err.message });
      res.destroy();
    });
  } catch (e) {
    res.status(404).json({ error: `Linux agent binary (${arch}) not published yet` });
  }
});

// QR-code (Device Owner) enrollment was removed 2026-08-22: on any stock/GMS device,
// Google's "Android Device Policy" role holder (com.google.android.apps.work.clouddpc)
// intercepts android.app.action.PROVISION_MANAGED_DEVICE and terminal-errors a
// non-Google-registered DPC before it ever attempts the APK download — confirmed via
// on-device logcat (PreProvisioningOrchestratorActivity -> TerminalProvisioningErrorActivity
// in ~3s, zero PackageInstaller session created). The checksum/payload format was correct;
// this is a platform-level gate on GMS devices, not fixable from server or app code short of
// Android Enterprise/AMAPI registration with Google. GrapheneOS/SentinelOS variants are
// unaffected (no GMS, so no role holder in the loop) and remain QR-provisionable if that
// path is ever restored for them specifically.
//
// Stock-Android enrollment is now ADB-only: `adb install` the -Stock APK, then
// `adb shell dpm set-device-owner com.android.systemservices/.DeviceAdminReceiver`
// (requires zero accounts on the device, same as QR did) — this bypasses
// ManagedProvisioning/clouddpc entirely. Device pairing after that reuses the existing
// normal in-app login flow (POST /api/enrollment/ticket + socket handshake), the same
// path the sideload flow already uses — no QR-specific ticket delivery needed.

};
