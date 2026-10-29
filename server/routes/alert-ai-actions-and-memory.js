// routes/alert-ai-actions-and-memory.js - User-instructed AI actions from the All Alerts
// panel (investigate / remediate / approve / reject) + per-device & per-account AI memory
// views. Extracted verbatim from server.js (see git log for that commit). The only transform
// applied is require('./bastionClient') -> require('../bastionClient') at both in-route sites:
// that specifier must resolve to server/bastionClient.js from one directory deeper (same rule
// as routes/passkeys.js). The ctx below is the COMPLETE module-scope dependency set for this
// block; completeness is machine-checked by dev-tools/check-ctx.py.
module.exports = ({ app, OPENCODE_MODEL, alertScopeUserId, db, decryptText, generateAccountAiMemory, io, isDeviceAutoAuditEligible, log, notifySecurityAlert, notifyUser, opencodeApiKey, postOpencode, recordDeviceAiMemory, requireAuth, requireDeviceAccess, triggerAutoAuditForAlert }) => {
// ── User-instructed AI actions from the All Alerts panel ──

// POST /api/alerts/:id/ai-investigate — trigger a manual AI investigation of this alert.
// Same pipeline as the auto poller above, but forced (ignores suppression) and reports back inline.
app.post('/api/alerts/:id/ai-investigate', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  try {
    const alert = (await db.prepare(
      'SELECT id, device_id, user_id, category, message, created_at FROM user_alerts WHERE id=? AND user_id=?'
    ).get(req.params.id, String(uid)));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    if (!alert.device_id) return res.status(400).json({ error: 'This alert is not linked to a device' });
    if (!(await isDeviceAutoAuditEligible(alert.device_id))) {
      return res.status(400).json({ error: 'Device is not online or not eligible for auto-audit' });
    }
    // Don't re-investigate if already audited (the poller guard in triggerAutoAuditForAlert
    // would skip it anyway, but returning early here gives the user a clear message).
    const existingAudit = (await db.prepare(
      "SELECT id FROM alert_auto_audits WHERE alert_id=? AND status IN ('completed','suppressed') ORDER BY id DESC LIMIT 1"
    ).get(alert.id));
    if (existingAudit) {
      // Recovery: if audit_result is still NULL (the write failed silently), backfill it now.
      const row = (await db.prepare("SELECT audit_result FROM user_alerts WHERE id=?").get(alert.id));
      if (!row || !row.audit_result) {
        const aa = (await db.prepare("SELECT ai_analysis FROM alert_auto_audits WHERE alert_id=? AND status='completed' ORDER BY id DESC LIMIT 1").get(alert.id));
        if (aa && aa.ai_analysis) {
          try { (await db.prepare("UPDATE user_alerts SET audit_result=? WHERE id=?").run(aa.ai_analysis, alert.id)); } catch (e) { log('warn', 'AI investigate: failed to backfill audit_result', { alertId: alert.id, err: e.message }); }
        }
      }
      return res.json({ status: 'already_investigated', alertId: alert.id });
    }
    res.json({ status: 'investigation_started', alertId: alert.id });

    // Run in background
    try {
      (await triggerAutoAuditForAlert(alert));
    } catch (e) { log('warn', 'Manual AI investigate failed', { alertId: alert.id, err: e.message }); }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/alerts/:id/ai-remediate — generate a fix proposal for review before execution.
// Investigates the device, asks the AI for a remediation script, then stores the proposed fix
// on the alert for the operator to approve or reject. The script is NOT executed until approved.
app.post('/api/alerts/:id/ai-remediate', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  try {
    const alert = (await db.prepare(
      'SELECT id, device_id, user_id, category, message FROM user_alerts WHERE id=? AND user_id=?'
    ).get(req.params.id, String(uid)));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    if (!alert.device_id) return res.status(400).json({ error: 'This alert is not linked to a device' });
    if (!(await isDeviceAutoAuditEligible(alert.device_id))) {
      return res.status(400).json({ error: 'Device is not online or not eligible' });
    }

    const bastionClient = require('../bastionClient');
    if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion not available' });

    // If there's already a pending proposed fix, return it instead of generating a new one
    const existing = (await db.prepare('SELECT proposed_fix FROM user_alerts WHERE id=?').get(alert.id));
    if (existing?.proposed_fix) {
      try {
        const pf = JSON.parse(existing.proposed_fix);
        if (pf.status === 'pending') return res.json({ status: 'proposal_ready', alertId: alert.id, proposedFix: pf });
      } catch (_) {}
    }

    res.json({ status: 'remediation_started', alertId: alert.id });

    // Background: run audit, then use AI to generate a fix proposal (NOT executed yet)
    (async () => {
      try {
        // 1) Run IT audit
        (await bastionClient.runAudit(alert.device_id));
        let auditResult = null;
        for (let i = 0; i < 48; i++) {
          await new Promise(r => setTimeout(r, 5000));
          try {
            const live = (await bastionClient.sessionAuditLive(alert.device_id));
            if (live?.collectedAtEpoch && live.collectedAtEpoch > 0) { auditResult = live; break; }
          } catch (_) {}
        }
        if (!auditResult) { try { auditResult = (await bastionClient.sessionAuditCached(alert.device_id)); } catch (_) {} }

        // 2) Ask AI for a remediation script
        const apiKey = opencodeApiKey();
        if (!apiKey) { log('warn', 'AI remediate: no opencode key'); return; }
        const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(alert.device_id));
        const deviceName = (devRow && decryptText(devRow.name)) || alert.device_id;

        const fixPrompt = [
          'You are a Windows systems engineer. A security alert on a managed device needs remediation.',
          `DEVICE: ${deviceName}`,
          `ALERT: ${alert.category} — ${(alert.message || '').slice(0, 500)}`,
          `AUDIT VERDICT: ${auditResult?.verdict || 'PENDING'}`,
          `AUDIT SUMMARY: ${(auditResult?.summary || '').slice(0, 2000)}`,
          '',
          'Write a PowerShell script that fixes the root cause. The script will run as SYSTEM.',
          'Return ONLY a valid JSON object with:',
          '  - "script": the PowerShell code to fix the issue',
          '  - "explanation": one sentence describing what this will do (shown to the owner)',
          '  - "safe": true if this is a safe/reversible fix',
          'If the issue does NOT need any fix, return {"script":null,"explanation":"No fix needed — this appears to be a false positive","safe":true}.',
        ].join('\n');

        let fixResult = null;
        try {
          const resp = await postOpencode({
            model: OPENCODE_MODEL,
            messages: [
              { role: 'system', content: 'You are a technical systems administrator. Return ONLY valid JSON.' },
              { role: 'user', content: fixPrompt },
            ],
            temperature: 0.2, max_tokens: 2500,
          }, 60000);
          if (resp.ok) {
            const j = (await resp.json());
            const content = j?.choices?.[0]?.message?.content || '';
            log('info', 'AI remediate: raw response', { alertId: alert.id, content: content.slice(0, 500), model: j?.model, finish_reason: j?.choices?.[0]?.finish_reason, response_keys: Object.keys(j || {}) });
            try { fixResult = JSON.parse(content.trim()); } catch {
              const m = content.match(/\{[\s\S]*\}/);
              if (m) { try { fixResult = JSON.parse(m[0]); } catch {} }
            }
          } else {
            const body = await resp.text().catch(() => '');
            log('warn', 'AI remediate: fix-script API returned non-OK', { alertId: alert.id, status: resp.status, body: body.slice(0, 300) });
          }
        } catch (e) { log('warn', 'AI remediate: fix-script generation failed', { alertId: alert.id, err: e.message }); }

        // 3) Store the proposed fix for operator review (NOT executed yet)
        const proposedFix = {
          script:     fixResult?.script || null,
          explanation: fixResult?.explanation || 'No proposal generated',
          safe:       !!fixResult?.safe,
          auditVerdict: auditResult?.verdict || 'UNKNOWN',
          auditSummary: (auditResult?.summary || '').slice(0, 1000),
          deviceName,
          category:   alert.category,
          status:     'pending',
          created_at: Date.now(),
        };

        try {
          await db.prepare('UPDATE user_alerts SET proposed_fix=? WHERE id=?')
            .run(JSON.stringify(proposedFix), alert.id);
        } catch (e) { log('warn', 'AI remediate: failed to store proposed fix', { alertId: alert.id, err: e.message }); }

        // 4) Push to the operator via Socket.IO so the approval modal appears live
        try {
          io.to('monitors').emit('proposed_fix_ready', {
            alertId:     alert.id,
            deviceId:    alert.device_id,
            proposedFix,
          });
        } catch (_) {}

        // 5) Record the audit (alert not handled yet — pending approval)
        try {
          (await db.prepare(
            "INSERT INTO alert_auto_audits (alert_id, device_id, user_id, status, ai_analysis, alert_handled, started_at, completed_at, created_at) VALUES (?,?,?,'completed',?,0,?,?,?)"
          ).run(alert.id, alert.device_id, String(alert.user_id), JSON.stringify({ fixResult: proposedFix }), Date.now(), Date.now(), Date.now()));
        } catch (_) {}
      } catch (e) { log('warn', 'AI remediate background task failed', { alertId: alert.id, err: e.message }); }
    })();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/alerts/:id/ai-approve — execute a previously proposed fix after operator review.
app.post('/api/alerts/:id/ai-approve', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  try {
    const alert = (await db.prepare(
      'SELECT id, device_id, user_id, category, message, proposed_fix FROM user_alerts WHERE id=? AND user_id=?'
    ).get(req.params.id, String(uid)));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    if (!alert.proposed_fix) return res.status(400).json({ error: 'No proposed fix to approve' });
    let pf;
    try { pf = JSON.parse(alert.proposed_fix); } catch { return res.status(400).json({ error: 'Corrupted proposed fix' }); }
    if (pf.status !== 'pending') return res.status(400).json({ error: `Fix already ${pf.status}` });
    if (!pf.script) return res.status(400).json({ error: 'No script to execute — this proposal recommends no action' });

    const bastionClient = require('../bastionClient');
    if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion not available' });

    // Mark as approved (optimistic — will be updated to executed/failed below)
    pf.status = 'approved';
    pf.approved_at = Date.now();
    try { await db.prepare('UPDATE user_alerts SET proposed_fix=? WHERE id=?').run(JSON.stringify(pf), alert.id); } catch (_) {}

    res.json({ status: 'executing', alertId: alert.id });

    // Execute in background
    (async () => {
      let execResult = null;
      try {
        execResult = (await bastionClient.runPowerShell(alert.device_id, pf.script));
      } catch (e) { execResult = { error: e.message }; }

      // Update proposed fix with execution result
      pf.status = execResult?.error ? 'failed' : 'executed';
      pf.executed_at = Date.now();
      pf.execResult = execResult;
      try { await db.prepare('UPDATE user_alerts SET proposed_fix=? WHERE id=?').run(JSON.stringify(pf), alert.id); } catch (_) {}

      const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(alert.device_id));
      const deviceName = (devRow && decryptText(devRow.name)) || alert.device_id;
      const actionTaken = pf.explanation;
      const resultSummary = execResult?.error
        ? `Remediation FAILED: ${execResult.error}`
        : `Remediation completed: ${JSON.stringify(execResult).slice(0, 300)}`;

      const repMsg = [
        `🛠️ AI Remediation on ${deviceName}`,
        `Alert: ${alert.category}`,
        `Action: ${actionTaken}`,
        `Result: ${resultSummary}`,
      ].join('\n');

      try { if (alert.user_id) (await notifyUser(alert.user_id, repMsg, { category: 'sentry', deviceId: alert.device_id })); } catch (_) {}
      try { (await notifySecurityAlert(repMsg, alert.device_id)); } catch (_) {}
      try {
        (await recordDeviceAiMemory(alert.device_id, alert.user_id, 'remediation',
          resultSummary, execResult?.error ? 'FAILED' : 'RESOLVED',
          pf.explanation || null, actionTaken, JSON.stringify({ fixResult: pf, execResult })));
        (await generateAccountAiMemory(alert.user_id));
      } catch (_) {}
      try {
        (await db.prepare(
          "UPDATE alert_auto_audits SET alert_handled=1 WHERE alert_id=? AND status='completed' ORDER BY id DESC LIMIT 1"
        ).run(alert.id));
      } catch (_) {}

      // Push execution result to operator
      try {
        io.to('monitors').emit('proposed_fix_ready', {
          alertId: alert.id, deviceId: alert.device_id, proposedFix: pf,
        });
      } catch (_) {}
    })();
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/alerts/:id/ai-reject — dismiss a proposed fix without executing.
app.post('/api/alerts/:id/ai-reject', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  try {
    const alert = (await db.prepare(
      'SELECT id, device_id, user_id, proposed_fix FROM user_alerts WHERE id=? AND user_id=?'
    ).get(req.params.id, String(uid)));
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    if (!alert.proposed_fix) return res.status(400).json({ error: 'No proposed fix to reject' });
    let pf;
    try { pf = JSON.parse(alert.proposed_fix); } catch { return res.status(400).json({ error: 'Corrupted proposed fix' }); }
    if (pf.status !== 'pending') return res.status(400).json({ error: `Fix already ${pf.status}` });

    pf.status = 'rejected';
    pf.rejected_at = Date.now();
    try {
      await db.prepare('UPDATE user_alerts SET proposed_fix=? WHERE id=?').run(JSON.stringify(pf), alert.id);
    } catch (_) {}

    // Push rejection to operator
    try {
      io.to('monitors').emit('proposed_fix_ready', {
        alertId: alert.id, deviceId: alert.device_id, proposedFix: pf,
      });
    } catch (_) {}

    res.json({ status: 'rejected', alertId: alert.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/devices/:id/ai-memory — per-device AI investigation history
app.get('/api/devices/:id/ai-memory', requireDeviceAccess, async (req, res) => {
  try {
    const rows = (await db.prepare(
      "SELECT id, event_type, summary, ai_verdict, root_cause, action_taken, created_at FROM device_ai_memory WHERE device_id=? ORDER BY created_at DESC LIMIT 100"
    ).all(req.params.id));
    res.json({ memory: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/users/me/ai-memory — per-account AI overview
app.get('/api/users/me/ai-memory', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  try {
    const rows = (await db.prepare(
      "SELECT id, summary, created_at FROM account_ai_memory WHERE user_id=? ORDER BY created_at DESC LIMIT 20"
    ).all(String(uid)));
    res.json({ memory: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
};
