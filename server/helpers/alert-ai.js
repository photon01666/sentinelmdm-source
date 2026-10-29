// helpers/alert-ai.js - security-alert auto-audit pipeline + the AI memory records it writes.
//
// A HELPER module, not a route module: it registers nothing.
//
//   isAlertUnprocessed    PRIVATE  in-memory + DB double-processing guard for the auto-audit
//   analyzeAlertWithAI    PRIVATE  the bastion forensics dump + OpenCode verdict prompt
//   recordDeviceAiMemory  export   INSERT into device_ai_memory (per-device)
//   generateAccountAiMemory export  rolls per-device rows up into the per-user account memory
//   triggerAutoAuditForAlert export the orchestrator; the 30s alert poll calls this per row
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// Every one of the 16 deps is initialised above L8937: _alertSeenCacheConfig (L8925),
// _alertRetryMap (L8929), markAlertProcessed (L8930), isAlertAutoAuditSuppressed (L8882),
// isDeviceAutoAuditEligible (L8823), suppressSig (L8858), opencodeApiKey (L4233),
// postOpencode (L4250), AUTO_AUDIT_REPORT_TAG (L8920), AUDIT_STALE_MS (L8898),
// OPENCODE_MODEL (L4224), notifySecurityAlert (L765), notifyUser (L754), db (L723);
// and decryptText (L166) + log (L438) are `function` declarations, which hoist.
//
// bastionClient is NOT a ctx dep and must NOT become one. This module keeps the
// established pattern of a function-local lazy require inside each function that needs
// it -- see "The require rebase" below.

module.exports = ({ AUDIT_STALE_MS, AUTO_AUDIT_REPORT_TAG, OPENCODE_FALLBACK_MODELS, OPENCODE_MODEL, _alertRetryMap, _alertSeenCacheConfig, db, decryptText, isAlertAutoAuditSuppressed, isDeviceAutoAuditEligible, log, markAlertProcessed, notifySecurityAlert, notifyUser, opencodeApiKey, postOpencode, suppressSig }) => {
// Is this alert still awaiting its auto-audit? Guards against double-processing (both across the
// 30s poll ticks and across the 3 tracker replicas) WITHOUT letting a half-finished audit block
// the alert forever.
//
// ⚠️ Both layers must honor AUDIT_STALE_MS or an orphan is permanent:
//   - the in-memory cache is set at the START of processing (it doubles as the in-flight guard),
//     so a process that dies mid-audit leaves a DB row behind; a cache entry with no expiry would
//     then keep re-blocking the alert even after that row is reaped.
//   - the DB row is the cross-replica guard, but ANY existing row used to count as "processed",
//     including a 'running' one that would never complete.
// Found live 2026-08-04: 8 alerts sat orphaned for up to 6.5h (3 of them from ordinary redeploys)
// and were silently never analyzed — no error anywhere, they simply vanished from the pipeline.
async function isAlertUnprocessed(alertRow) {
  const seenAt = _alertSeenCacheConfig.ids.get(alertRow.id);
  if (seenAt !== undefined && (Date.now() - seenAt) < AUDIT_STALE_MS) return false;
  try {
    const existing = (await db.prepare(
      "SELECT id, status, created_at FROM alert_auto_audits WHERE alert_id=? ORDER BY id DESC LIMIT 1"
    ).get(alertRow.id));
    if (!existing) return true;
    const ageMs = Date.now() - Number(existing.created_at || 0);
    if (existing.status !== 'running' || ageMs < AUDIT_STALE_MS) {
      markAlertProcessed(alertRow.id);
      return false;
    }
    // Orphaned mid-audit row — drop it so this alert becomes eligible again. Deleting (rather than
    // marking it terminal) is what lets the alert actually get its analysis, which is the whole
    // point of the feature; triggerAutoAuditForAlert() inserts a fresh row on the next tick.
    (await db.prepare("DELETE FROM alert_auto_audits WHERE id=?").run(existing.id));
    _alertSeenCacheConfig.ids.delete(alertRow.id);
    log('warn', 'Auto-audit: reaped orphaned running row', {
      alertId: alertRow.id, rowId: existing.id, ageMin: Math.round(ageMs / 60000),
    });
    return true;
  } catch (e) {
    // Fail CLOSED — on a DB error, treat the alert as already handled rather than risk
    // re-auditing (and re-paging) on every 30s tick while the DB is unhealthy.
    log('warn', 'isAlertUnprocessed failed', { alertId: alertRow.id, err: e.message });
    return false;
  }
}

// Call OpenCode DeepSeek with alert context + forensics results.
async function analyzeAlertWithAI(alertRow, deviceId, auditResult) {
  const apiKey = opencodeApiKey();
  if (!apiKey) return null;
  // ⚠️ There is NO module-level `bastionClient` in this file — every call site does its own
  // function-local require (see triggerAutoAuditForAlert). This one was missing, so the line
  // below threw `ReferenceError: bastionClient is not defined` on EVERY auto-audit, the caller's
  // catch swallowed it, and every single report rendered as "INCONCLUSIVE / Could not determine /
  // Confidence: ?%" — plus, since `suppress` never got set, nothing was ever suppressed and each
  // repeat detection re-audited and re-alerted forever. Note `typeof bastionClient?.x` does NOT
  // guard this: optional chaining still evaluates the base identifier, so it throws exactly like
  // a bare reference (only a bare `typeof bastionClient` is ReferenceError-safe). Found live
  // 2026-08-04, immediately after the ZK-sanitizer fix let audits reach this step at all.
  const bastionClient = require('../bastionClient');
  const label = typeof bastionClient?.labelForDevice === 'function'
    ? bastionClient.labelForDevice(deviceId) : deviceId;
  const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
  const deviceName = (devRow && decryptText(devRow.name)) || deviceId;
  const verdictText = auditResult?.verdict || 'PENDING';
  const summaryText = auditResult?.summary || '(no audit summary available)';

  const systemPrompt = [
    'You are a security analyst for SentinelMDM, a remote device management platform.',
    'You are investigating a SECURITY ALERT that was just triggered for a managed device.',
    'Your job: determine whether this is a REAL THREAT or a FALSE POSITIVE, and why.',
    '',
    'You have TWO sources of information:',
    '1. The ALERT itself (what happened, when, which rule triggered it).',
    '2. A full IT Mode Audit (14-category forensics) that was automatically run on the device RIGHT NOW — processes, services, scheduled tasks, autoruns, network connections, users, installed software, security state, drivers, hosts file, code-signing, WMI persistence, browser extensions, and recent security events.',
    '',
    'Your response must be a valid JSON object with these keys:',
    '  - "verdict": one of "REAL_THREAT", "FALSE_POSITIVE", "INCONCLUSIVE"',
    '  - "root_cause": one short sentence explaining what actually caused this alert (e.g. "A legitimate Discord update triggered the AppLocker block", "An unknown device joined the LAN — real ARP spoofing threat")',
    '  - "confidence": a number 0-100',
    '  - "suppress": true if this is a known-benign pattern that should never alert again for this device, false otherwise. NEVER set suppress=true for applocker_audit alerts — these are visibility events, not threats.',
    '  - "severity": "critical" | "high" | "medium" | "low" | "none"',
    '  - "action_needed": one short sentence describing what (if anything) should be done',
    '  - "summary": a 2-3 sentence plain-language summary for the device owner and admin',
    '',
     'IMPORTANT RULES:',
     '- If the alert AND the forensics both look normal/expected (no suspicious processes, no unexplained network connections, no persistence mechanisms, no unknown users), it IS a false positive — say so clearly.',
     '- Only mark REAL_THREAT if the forensics CONFIRM something genuinely suspicious that cannot be explained by normal system operations.',
     '- When suppress=true, a sha256 fingerprint will prevent this exact cause from re-alerting on this device.',
     '- Be concise. The summary will be sent as a push notification.',
     '- DO NOT format your answer with markdown backticks. Return ONLY the JSON object.',
     '',
     'THREAT-INTEL FEED-CONFIRMED ALERTS (phishing_proxy_connection):',
     'When the alert message contains "Rule: phishing_proxy_connection" and "confirmed C2", the',
     'destination IP/domain was matched against a VALIDATED threat-intel feed (abuse.ch/operator-',
     'validated C2 set) — that match IS the ground truth and the alert is a REAL THREAT by',
     'definition. The on-device IT audit CANNOT refute it and a clean audit is EXPECTED: the',
     'connection was transient (often a single short request) and is typically gone by the time',
     'the audit runs, and the block is pushed over Hop-2 immediately at detection. Therefore:',
     '  - Verdict MUST be "REAL_THREAT" — never FALSE_POSITIVE — for these alerts, regardless of',
     '    how clean the audit looks. Found live 2026-08-14: the AI dismissed a real connection to',
     '    a validated C2 IP (203.0.113.10) as "transient or misattributed event" purely because',
     '    the audit was clean — exactly backwards for this rule.',
     '  - suppress MUST be false.',
     '  - action_needed should confirm the block was/will be pushed (firewall rule + hosts sinkhole)',
     '    and that the device should be checked for follow-on activity.',
     '',
    'INSTALLER CLUSTER ANALYSIS (use the "tasks" and "processes" category rows + the alert path):',
    'When the alert path points to a temp-folder executable (e.g. AppData\\Local\\Temp\\*, Desktop\\*Installer.exe),',
    'this is almost always a legitimate software installer that drops multiple files:',
    '  - The parent installer (e.g. "Firefox Installer.exe" on Desktop)',
    '  - A download helper (e.g. "download.exe" in a temp subfolder)',
    '  - An extraction stub (e.g. "setup-stub.exe" or "setup.exe" from a 7z/NSIS archive)',
    'These are ALL part of the same installation event — a single program spreading its components.',
    'Check the forensics for evidence of the INSTALLED product (e.g. "Mozilla Firefox" in the software list,',
    'a scheduled task or startup entry for the product, a running process with the product name).',
    'If the installed product is a known legitimate application, ALL related temp-folder executables',
    'from the same installation window are FALSE POSITIVE. Consolidate your verdict to cover the',
    'entire cluster, not just the single file in the alert. In the summary, mention ALL related files',
    'so the admin can see the full picture in one glance. When a "FULL EXECUTABLE CLUSTER" list is',
    'provided in the prompt, your summary MUST enumerate EVERY path in that list by name — do not',
    'summarize only the trigger path. This is mandatory: each enumerated path may be rendered on a',
    'separate alert card that has no other AI content, so an omitted path looks unanalyzed.',
    '',
    'NETWORK CONNECTION ANALYSIS (use the "net" category rows):',
    'Scrutinize every TCP/UDP row. Suspicious indicators include:',
    '  - Unknown or unusual processes (not chrome, firefox, svchost, teams, discord, steam, office apps) with ESTABLISHED connections to public IPs on high ports (>1024)',
    '  - Listening sockets on non-standard ports (not 80, 443, 22, 3389, 53, 8080, 8443, or common app ports)',
    '  - Connections to known-shelly ports: 4444, 5555, 1337, 6666, 31337, 12345, 54321',
    '  - Multiple different processes all connecting to the same unusual external IP (C2 beacon pattern)',
    '  - Processes with names mimicking system binaries (e.g. "svchost" with a typo, "scvhost", "csrss" in a non-system path)',
    '  - svchost.exe or other system processes with unexpected remote endpoints beyond the usual Windows Update / telemetry IPs',
    'Benign patterns (do NOT flag these):',
    '  - Chrome/Firefox/Edge with many ESTABLISHED connections to port 443 (normal browsing)',
    '  - Teams/Slack/Discord with persistent connections on standard ports',
    '  - Steam, Epic, Battle.net with connections on their known port ranges',
    '  - Office apps ( Outlook, Teams) connecting to Microsoft 365 endpoints',
    '  - Localhost/127.0.0.1 connections (inter-process communication)',
    '  - UDP listeners on port 53 (DNS), 123 (NTP), 1900 (SSDP), 5353 (mDNS)',
  ].join('\n');

  const userPrompt = [
    `DEVICE: ${deviceName} (${label})`,
    `CATEGORY: ${alertRow.category || 'unknown'}`,
    `ALERT MESSAGE:`,
    alertRow.message || '(empty)',
    '',
  ].join('\n');

  // For applocker_audit alerts, include recent related alerts from the same device so the AI
  // can see the full installer cluster (e.g. Firefox Installer.exe + setup.exe + download.exe)
  // and consolidate into one verdict instead of analyzing each file in isolation.
  let relatedContext = '';
  if (alertRow.category === 'applocker_audit') {
    try {
      const related = (await db.prepare(
        "SELECT message, created_at FROM user_alerts WHERE device_id=? AND category='applocker_audit' AND id != ? AND created_at > ? ORDER BY created_at DESC LIMIT 10"
      ).all(deviceId, alertRow.id, Date.now() - 5 * 60 * 1000));
      // Always include the CURRENT alert's own path as the head of the list, so the cluster
      // enumeration is complete even when the trigger alert is the only one so far. The AI is
      // required (system prompt + this block) to enumerate EVERY path in its summary, because
      // that summary is what gets attached to all the sibling alert cards (see the sibling
      // audit_result attach in triggerAutoAuditForAlert) — a summary naming only the trigger
      // path would leave every other card in the burst looking unanalyzed.
      const ownPathMatch = String(alertRow.message || '').match(/Path: (.+)/);
      let clusterPaths = [];
      if (ownPathMatch) clusterPaths.push(ownPathMatch[1].trim());
      for (const r of related) {
        const pathMatch = String(r.message || '').match(/Path: (.+)/);
        if (pathMatch) clusterPaths.push(pathMatch[1].trim());
      }
      if (clusterPaths.length > 0) {
        relatedContext = '\nFULL EXECUTABLE CLUSTER (every flagged path from this installation/program — analyze as ONE event):\n';
        for (const cp of clusterPaths) relatedContext += `- ${cp}\n`;
        relatedContext += '\nYour summary MUST name EVERY path listed above explicitly (all ' + clusterPaths.length +
          ' of them), never only the first one. Enumerate them so the admin sees the full cluster in one glance.\n';
      }
    } catch (_) {}
  }

  const fullPrompt = userPrompt + relatedContext + [
    `IT AUDIT VERDICT: ${verdictText}`,
    `AUDIT SUMMARY:`,
    summaryText.slice(0, 4000),
  ].join('\n');

  // Two intermittent failure modes were seen live 2026-08-04, both degrading to a content-free
  // "INCONCLUSIVE / Could not determine / Confidence: ?%" report that still pages the owner:
  //   (a) `AI alert analysis not valid JSON | preview=""` — the API returned an EMPTY content
  //       string. ⚠️ Root cause NOT confirmed: an A/B against this exact prompt shape showed
  //       max_tokens:1200 was already sufficient (finish=stop, tokens_out=309, 3.0s), so the old
  //       budget was NOT the ceiling it first looked like. Suspect a transient API hiccup or
  //       concurrency (several audits fire back-to-back). The RETRY below is the actual
  //       mitigation; the larger budget is only defensive headroom.
  //   (b) `The operation was aborted due to timeout` — the old 60s AbortSignal firing under
  //       those same back-to-back audits (a healthy call is ~3s).
  // max_tokens/timeout now match the bastion's own long-proven call against this SAME model
  // (`_call_opencode_analysis`, bastion-web.py: 8192 / 300s). Do NOT lower either, and do not
  // drop the retry — check the finish_reason/tokensOut logged below before changing any of it.
  // Same A/B-logged shape as the bastion (8192/300s against the same model class). The outer
  // loop is the retry; the inner loop walks the model fallback chain so a provider-side model
  // outage (deepseek-v4-flash "Model is unavailable", 2026-08-08) degrades to the next model
  // instead of a content-free INCONCLUSIVE. Do NOT lower max_tokens/timeout.
  const models = [OPENCODE_MODEL, ...OPENCODE_FALLBACK_MODELS.filter(m => m !== OPENCODE_MODEL)];
  for (let attempt = 1; attempt <= 2; attempt++) {
    for (const model of models) {
      try {
        const resp = await postOpencode({
          model,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: fullPrompt },
          ],
          temperature: 0.3,
          max_tokens: 8192,
        }, 180000);
        if (!resp.ok) { log('warn', 'AI alert analysis HTTP error', { status: resp.status, model, attempt }); continue; }
        const j = /** @type {any} */ (await resp.json());
        // Mirrors the bastion's own opencode log line — an empty `content` is otherwise
        // indistinguishable from a malformed one, and finish_reason is what tells them apart.
        log('info', 'AI alert analysis response', {
          finish: j?.choices?.[0]?.finish_reason || '?',
          tokensOut: j?.usage?.completion_tokens ?? '?',
          model,
          attempt,
        });
        const content = j?.choices?.[0]?.message?.content || '';
        try { return JSON.parse(content.trim()); } catch {
          // Try to extract JSON from the response
          const m = content.match(/\{[\s\S]*\}/);
          if (m) { try { return JSON.parse(m[0]); } catch {} }
          log('warn', 'AI alert analysis not valid JSON', { preview: content.slice(0, 200), model, attempt });
        }
      } catch (e) { log('warn', 'AI alert analysis failed', { err: e.message, model, attempt }); }
    }
  }
  return null;
}

// Persist the AI memory record (per-device).
async function recordDeviceAiMemory(deviceId, userId, eventType, summary, aiVerdict, rootCause, actionTaken, rawAnalysis) {
  try {
    return (await db.prepare(
      `INSERT INTO device_ai_memory (device_id, user_id, event_type, summary, ai_verdict, root_cause, action_taken, raw_analysis, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).run(deviceId, String(userId), eventType, String(summary || '').slice(0, 2000),
      aiVerdict || null, rootCause || null, actionTaken || null, String(rawAnalysis || '').slice(0, 8000), Date.now()));
  } catch (e) { log('warn', 'recordDeviceAiMemory failed', { deviceId, err: e.message }); }
}

// Persist account-level AI overview (generated periodically or on demand).
async function generateAccountAiMemory(userId) {
  try {
    const rows = (await db.prepare(
      "SELECT device_id, ai_verdict, root_cause, summary, created_at FROM device_ai_memory WHERE user_id=? ORDER BY created_at DESC LIMIT 50"
    ).all(String(userId)));
    if (!rows.length) return;
    const totals = { REAL_THREAT: 0, FALSE_POSITIVE: 0, INCONCLUSIVE: 0 };
    for (const r of rows) if (r.ai_verdict && totals[r.ai_verdict] !== undefined) totals[r.ai_verdict]++;
    const latest = rows.slice(0, 5).map(r => `- ${new Date(r.created_at).toLocaleDateString()}: ${r.ai_verdict || '?'} — ${(r.summary || '').slice(0, 120)}`).join('\n');
    const summary = `Account AI overview (${rows.length} audits across ${new Set(rows.map(r => r.device_id)).size} devices):\nReal threats: ${totals.REAL_THREAT}\nFalse positives: ${totals.FALSE_POSITIVE}\nInconclusive: ${totals.INCONCLUSIVE}\n\nLatest findings:\n${latest}`;
    // Upsert latest account summary
    (await db.prepare("DELETE FROM account_ai_memory WHERE user_id=?").run(String(userId)));
    (await db.prepare("INSERT INTO account_ai_memory (user_id, summary, created_at) VALUES (?,?,?)")
      .run(String(userId), summary, Date.now()));
  } catch (e) { log('warn', 'generateAccountAiMemory failed', { userId, err: e.message }); }
}

// ── Core orchestration: trigger a full auto-audit for one alert ──
async function triggerAutoAuditForAlert(alertRow) {
  const { id: alertId, device_id: deviceId, user_id: userId, category, message } = alertRow;
  if (!deviceId || !userId) return;
  if (category === 'ra_agent_update') return;
  // Belt-and-braces against the feedback loop (see AUTO_AUDIT_REPORT_TAG). The poller's SQL
  // already filters these out, but that protects only the poller — this guard covers EVERY entry
  // point (the manual /ai-investigate and /ai-remediate routes, and any future caller), so the
  // loop cannot be reintroduced by adding a new call site that forgets the filter.
  if (String(message || '').includes(AUTO_AUDIT_REPORT_TAG)) return;
  if (!(await isAlertUnprocessed(alertRow))) return;
  if (!(await isDeviceAutoAuditEligible(deviceId))) return;
  if (await isAlertAutoAuditSuppressed(category, deviceId, message)) {
    markAlertProcessed(alertId);
    try {
      (await db.prepare(
        `INSERT INTO alert_auto_audits (alert_id, device_id, user_id, status, false_positive, suppression_signature, created_at)
         VALUES (?,?,?,'suppressed',1,?,?)`
      ).run(alertId, deviceId, String(userId), suppressSig(category, deviceId, message), Date.now()));
    } catch (_) {}
    // Write a short audit_result so the alert card shows why it was suppressed.
    try {
      const suppressResult = JSON.stringify({ verdict: 'FALSE_POSITIVE', suppressed: true, reason: 'Known false positive — same signature as a previously reviewed alert.', confidence: 100 });
      (await db.prepare('UPDATE user_alerts SET audit_result=? WHERE id=?').run(suppressResult, alertId));
    } catch (_) {}
    return;
  }

  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  markAlertProcessed(alertId);

  // Per-device cooldown: if this device has a recent audit (running OR completed) within the
  // last 30 minutes, skip this alert. The first alert in a burst triggers the audit; subsequent
  // alerts from the same device (e.g. 4 temp executables from one Firefox installer) are already
  // covered by the first alert's AI analysis, which sees all related paths via the installer
  // cluster prompt. No need to burn N API calls for N files from the same installation event.
  const AUDIT_COOLDOWN_MS = 30 * 60 * 1000;
  let auditResult = null;
  try {
    const recentAudit = (await db.prepare(
      "SELECT id FROM alert_auto_audits WHERE device_id=? AND status IN ('running','completed') AND created_at > ? ORDER BY created_at DESC LIMIT 1"
    ).get(deviceId, Date.now() - AUDIT_COOLDOWN_MS));
    if (recentAudit) {
      if (recentAudit.status === 'completed') {
        // Reuse the cached audit — fetch the result from bastion (it's still fresh)
        try {
          auditResult = (await bastionClient.sessionAuditLive(deviceId));
          if (auditResult?.verdict) {
            log('info', 'Auto-audit: reusing recent audit for device', { alertId, deviceId, recentAuditId: recentAudit.id });
          } else {
            auditResult = null; // cached result expired or missing — fall through to fresh audit
          }
        } catch (_) { auditResult = null; }
      } else {
        // Audit is still running — skip this alert entirely (the running audit will cover it)
        log('info', 'Auto-audit: skipping alert, audit already running for device', { alertId, deviceId, runningAuditId: recentAudit.id });
        return;
      }
    }
  } catch (_) {}

  // 1) Create the pending audit row
  const now = Date.now();
  try {
    (await db.prepare(
      `INSERT INTO alert_auto_audits (alert_id, device_id, user_id, status, started_at, created_at)
       VALUES (?,?,?,'running',?,?)`
    ).run(alertId, deviceId, String(userId), now, now));
  } catch (e) { log('warn', 'Auto-audit: insert pending row failed', { alertId, err: e.message }); return; }

  // 2) If no cached result from cooldown, trigger a fresh bastion IT audit
  if (!auditResult) {
    let beforeEpoch = 0;
    try {
      const cached = (await bastionClient.sessionAuditCached(deviceId));
      beforeEpoch = cached?.collectedAtEpoch || 0;
    } catch (_) {}

    // 3) Trigger a fresh bastion IT audit. The bastion handler is fire-and-forget — it
    // spawns a background thread and returns {ok:true, status:"collecting"} immediately.
    // We poll sessionAuditLive until collectedAtEpoch advances past beforeEpoch (max 5 min).
    try {
      bastionClient.invalidateAuditCache(deviceId);
      (await bastionClient.runAudit(deviceId));
    } catch (e) {
      log('warn', 'Auto-audit: bastion audit trigger failed', { alertId, deviceId, err: e.message });
    }

    // 4) Poll until a genuinely NEW collection lands (collectedAtEpoch must advance).
    const pollStarted = Date.now();
    const MAX_POLL_MS = 5 * 60 * 1000; // 5 min — forensics + AI analysis can take a while
  for (let i = 0; i < 60; i++) {
    if (Date.now() - pollStarted > MAX_POLL_MS) break;
    await new Promise(r => setTimeout(r, 5000));
    try {
      const live = (await bastionClient.sessionAuditLive(deviceId));
      if (live?.collectedAtEpoch && live.collectedAtEpoch > beforeEpoch) {
        auditResult = live;
        break;
      }
    } catch (_) { /* bastion temporarily unreachable — keep polling */ }
  }
  } // end if (!auditResult) — fresh audit path

  // 5) STALE-DATA GUARD: if we couldn't confirm genuinely new data, retry a few
  // times (the bastion tunnel may be transiently down), then give up and alert.
  if (!auditResult) {
    const MAX_RETRIES = 3;
    const retries = (_alertRetryMap.get(alertId) || 0) + 1;
    _alertRetryMap.set(alertId, retries);
    // Clean up the failed audit row so isAlertUnprocessed() lets this alert through
    // again on the next poll tick.
    try { (await db.prepare("DELETE FROM alert_auto_audits WHERE alert_id=?").run(alertId)); } catch (_) {}
    _alertSeenCacheConfig.ids.delete(alertId);
    if (retries >= MAX_RETRIES) {
      _alertRetryMap.delete(alertId);
      const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
      const deviceName = (devRow && decryptText(devRow.name)) || deviceId;
      const staleMsg = `\u26A0\uFE0F ${AUTO_AUDIT_REPORT_TAG}: Failed to collect fresh data after ${MAX_RETRIES} attempts\nDevice: ${deviceName}\nAlert: ${category || 'unknown'}\n\nThe device may be offline or the bastion tunnel is down. Re-run the audit manually from the dashboard when the device is back online.`;
      try { if (userId) (await notifyUser(userId, staleMsg, { category: 'sentry', deviceId })); } catch (_) {}
      try { (await notifySecurityAlert(staleMsg, deviceId)); } catch (_) {}
      try { (await db.prepare(
        "INSERT INTO alert_auto_audits (alert_id, device_id, user_id, status, completed_at, created_at) VALUES (?,?,?,'failed',?,?)"
      ).run(alertId, deviceId, String(userId), Date.now(), Date.now())); } catch (_) {}
    }
    return;
  }
  // Clear any stale-data retry tracking — we got fresh data, the retry loop is done.
  _alertRetryMap.delete(alertId);

  // The epoch advanced but the audit may have failed silently (forensics collection
  // error on the bastion side). When verdict is PENDING with a short summary, the
  // bastion wrote a failure-marker epoch — no real forensics data to feed to AI.
  if (auditResult.verdict === 'PENDING' && auditResult.summary && (
    auditResult.summary.startsWith('Forensics collection failed') ||
    auditResult.summary.startsWith('forensics collection failed') ||
    auditResult.summary === 'audit already in progress for this session')) {
    const devRow2 = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
    const deviceName2 = (devRow2 && decryptText(devRow2.name)) || deviceId;
    const errMsg = `\u26A0\uFE0F ${AUTO_AUDIT_REPORT_TAG}: Audit ran but forensics collection failed\nDevice: ${deviceName2}\nCause: ${auditResult.summary}\n\nThe device may be reachable at Hop-1 but the Hop-2 tunnel to the Windows/Linux box is failing. Check bastion logs.`;
    try { if (userId) (await notifyUser(userId, errMsg, { category: 'sentry', deviceId })); } catch (_) {}
    try { (await notifySecurityAlert(errMsg, deviceId)); } catch (_) {}
    try { (await db.prepare(
      "UPDATE alert_auto_audits SET status='failed_hops', ai_analysis=?, completed_at=? WHERE alert_id=?"
    ).run(JSON.stringify({ error: 'forensics_failed', reason: auditResult.summary }), Date.now(), alertId)); } catch (_) {}
    return;
  }

  // 5) We have confirmed-fresh data — feed to AI
  const completedAt = Date.now();
  let aiResult = null;
  try {
    aiResult = (await analyzeAlertWithAI(alertRow, deviceId, auditResult));
  } catch (e) { log('warn', 'Auto-audit: AI analysis failed', { alertId, err: e.message }); }

  // 4) Build the report message
  const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
  const deviceName = (devRow && decryptText(devRow.name)) || deviceId;
  const auditVerdict = auditResult?.verdict || 'PENDING';
  const aiVerdict = aiResult?.verdict || 'INCONCLUSIVE';
  const severity = aiResult?.severity || 'medium';
  const emoji = aiVerdict === 'REAL_THREAT' ? '🚨' : aiVerdict === 'FALSE_POSITIVE' ? '✅' : '🔍';
  const reportMsg = [
    `${emoji} ${AUTO_AUDIT_REPORT_TAG}: ${aiVerdict.replace(/_/g, ' ')}`,
    `Device: ${deviceName}`,
    `Alert: ${category || 'unknown'} | Severity: ${severity} | Confidence: ${aiResult?.confidence ?? '?'}%`,
    `Root cause: ${aiResult?.root_cause || 'Could not determine'}`,
    `Action: ${aiResult?.action_needed || 'No action needed'}`,
    `Audit verdict: ${auditVerdict}`,
    aiResult?.summary ? `\n${aiResult.summary}` : '',
  ].join('\n');

  // 4.1) Inline the audit result on the ORIGINAL alert row so the WebUI All Alerts panel
  // can render a colored glow + verdict/summary directly in the alert card. The separate
  // notification (below) still pages the owner — this just makes the alert card show the
  // AI verdict inline on every subsequent panel load/open.
  const auditResultJson = JSON.stringify({
    verdict: aiVerdict,
    severity,
    confidence: aiResult?.confidence ?? null,
    root_cause: aiResult?.root_cause || null,
    action: aiResult?.action_needed || null,
    summary: aiResult?.summary || null,
    emoji,
    audited_at: completedAt,
  });
  try { (await db.prepare(
    "UPDATE user_alerts SET audit_result=? WHERE id=?"
  ).run(auditResultJson, alertId)); } catch (e) { log('warn', 'Auto-audit: failed to write audit_result to user_alerts', { alertId, err: e.message }); }

  // 4.2) Attach the SAME verdict to sibling alert cards from this burst, so every alert in the
  // cluster shows the shared AI analysis instead of leaving the non-trigger cards blank.
  // The per-device cooldown (AUDIT_COOLDOWN_MS above) deliberately collapses a burst of related
  // alerts (e.g. 7 Steam binaries from one launch) into a SINGLE AI audit of the first one to
  // reach the poller — but without this step the other 6 alert cards would render with no
  // audit_result at all, looking unanalyzed even though their files were covered by the cluster
  // prompt. Sibling = same device, same category, within the cooldown window of this alert's
  // creation, not yet audited. The same window the cooldown used to swallow them is the window
  // we re-surface them in. audit_result is only ever set by this completion path (one row write
  // per alert id), so a row that already has one was audited separately — skip those.
  try {
    (await db.prepare(
      "UPDATE user_alerts SET audit_result=? WHERE device_id=? AND category=? AND id != ? " +
      "AND audit_result IS NULL AND created_at > ? AND created_at <= ?"
    ).run(auditResultJson, deviceId, category, alertId,
      alertRow.created_at - AUDIT_COOLDOWN_MS, alertRow.created_at + AUDIT_COOLDOWN_MS));
  } catch (e) { log('warn', 'Auto-audit: sibling audit_result attach failed', { alertId, deviceId, err: e.message }); }

  // 5) Notify admin + record memory. The owner sees the audit result INLINE on the
  // original alert card (audit_result field set above), so a separate notifyUser()
  // notification would be a duplicate. Only fire notifySecurityAlert for admin Signal.
  if (aiVerdict === 'FALSE_POSITIVE' || aiResult?.suppress) {
    const sig = suppressSig(category, deviceId, message);
    try { (await notifySecurityAlert(reportMsg, deviceId)); } catch (_) {}
    try { (await db.prepare(
      "UPDATE alert_auto_audits SET status='completed', audit_verdict=?, ai_analysis=?, false_positive=1, suppression_signature=?, alert_handled=1, completed_at=? WHERE alert_id=?"
    ).run(auditVerdict, JSON.stringify(aiResult), sig, completedAt, alertId)); } catch (_) {}
    try { (await recordDeviceAiMemory(deviceId, userId, 'alert_audit', aiResult?.summary || reportMsg, 'FALSE_POSITIVE', aiResult?.root_cause, null, JSON.stringify(aiResult))); } catch (_) {}
    try { (await generateAccountAiMemory(userId)); } catch (_) {}
  } else {
    try { (await notifySecurityAlert(reportMsg, deviceId)); } catch (_) {}
    try { (await db.prepare(
      "UPDATE alert_auto_audits SET status='completed', audit_verdict=?, ai_analysis=?, alert_handled=1, completed_at=? WHERE alert_id=?"
    ).run(auditVerdict, JSON.stringify(aiResult), completedAt, alertId)); } catch (_) {}
    try { (await recordDeviceAiMemory(deviceId, userId, 'alert_audit', aiResult?.summary || reportMsg, aiResult?.verdict, aiResult?.root_cause, null, JSON.stringify(aiResult))); } catch (_) {}
    try { (await generateAccountAiMemory(userId)); } catch (_) {}
  }
}

  return {
    generateAccountAiMemory,
    recordDeviceAiMemory,
    triggerAutoAuditForAlert,
  };
};
