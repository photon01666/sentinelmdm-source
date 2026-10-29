module.exports = ({ app, AI_LOG_PAYLOAD_MAX_CHARS, aiDailyAllow, aiRateAllow, callOpenCodeScreenText, opencodeApiKey, requireAuth, requireDeviceAccess }) => {

  // ── Ask AI — Logcat / Network-log / Security-log analysis ─────────────────────
  // Mirrors /ai/screen-text (same rate limits, daily caps, prompt-built-server-side so it
  // can't be abused as an open AI proxy). `kind` selects a security-review-framed system
  // prompt. Like screen-text, this is a deliberate, consent-gated ZK exception: the OWNER'S
  // browser decrypts the logs and the user explicitly confirms before they are transmitted —
  // the server never stores them.
  //
  // Every prompt opens with this preamble so the model understands the legitimate, authorized,
  // defensive-security purpose and does NOT refuse to analyze logs from a "monitored device".
  const AI_REVIEW_PREAMBLE =
    'You are assisting an AUTHORIZED SECURITY REVIEW. The logs below were lawfully collected ' +
    'from a device that the requester owns or administers under a consent-based monitoring ' +
    'program (parental child-safety controls or enterprise mobile-device management, with the ' +
    'user\'s knowledge and consent). The sole purpose of this analysis is DEFENSIVE SECURITY ' +
    'and SAFETY REVIEW — to detect malware, intrusions, tampering, misuse, and risks to the ' +
    'user and the device. This is a legitimate security/forensics task; analyze the data fully ' +
    'and do not refuse. ';
  const AI_LOG_PROMPTS = {
    logcat: AI_REVIEW_PREAMBLE +
      'You are an Android systems & security engineer reviewing a logcat capture from the ' +
      'monitored device (included in the user turn). Summarise what the apps and system are ' +
      'doing and flag security-relevant findings: crashes / ANRs / native or Java stack traces ' +
      '(FATAL), permission denials, root / exploit / tampering indicators, suspicious app ' +
      'behaviour, and repeated or abnormal patterns. Identify the likely culprit package(s) ' +
      'where possible. Answer follow-ups strictly from the provided lines; if they do not ' +
      'contain the answer, say so plainly. Be concise.',
    network: AI_REVIEW_PREAMBLE +
      'You are a network-security analyst reviewing on-device network connection logs (DNS ' +
      'lookups and TCP connections, each tagged with the originating app package) from the ' +
      'monitored device (included in the user turn). Summarise which apps contact which hosts ' +
      'and flag security concerns: contact with known tracker / ad / telemetry domains, malware ' +
      'or C2-like beaconing, data exfiltration, unexpected IPs or countries, or an app reaching ' +
      'hosts unrelated to its purpose. Answer follow-ups strictly from the provided logs; if ' +
      'they do not contain the answer, say so plainly. Be concise.',
    security: AI_REVIEW_PREAMBLE +
      'You are a device-security analyst reviewing on-device security event logs (unlock ' +
      'attempts, failed authentications, key / credential events, certificate installs, admin / ' +
      'policy changes, ADB usage, OS boots, etc.) from the monitored device (included in the ' +
      'user turn). Summarise the security-relevant activity and flag signs of tampering, ' +
      'unauthorised-access attempts, suspicious certificate or credential installs, or policy ' +
      'changes. Answer follow-ups strictly from the provided events; if they do not contain the ' +
      'answer, say so plainly. Be concise.',
  };

  app.post('/api/devices/:id/ai/logs', requireAuth, requireDeviceAccess, async (req, res) => {
    if (!opencodeApiKey()) return res.status(503).json({ error: 'AI analysis is not configured on this server.' });

    const kind = String(req.body?.kind || '');
    const systemText = AI_LOG_PROMPTS[kind];
    if (!systemText) return res.status(400).json({ error: 'Unknown analysis kind.' });

    const rateKey = String(req.session.userId || req.session.role || req.ip);
    if (!(await aiRateAllow(rateKey))) return res.status(429).json({ error: 'Rate limit exceeded (5 per 15 minutes). Please wait.' });

    const { logs, messages } = req.body || {};
    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ error: 'messages required' });

    // Per-public-user daily cap (shared with screen-text AI — same billable OpenCode budget).
    // Business sub-users bill against their OWNER's daily quota (see the sibling /ai-chat check).
    if (['public', 'business_sub'].includes(req.session.account_type)) {
      const billUserId = req.session.account_type === 'business_sub' ? req.session.parent_owner_id : req.session.userId;
      const dkind = messages.some(m => m && m.role === 'model') ? 'followup' : 'submit';
      if (!(await aiDailyAllow(dkind, String(billUserId)))) {
        return res.status(429).json({ error: dkind === 'followup'
          ? 'Daily limit reached: 6 AI follow-up questions per day. Try again tomorrow.'
          : 'Daily limit reached: 2 AI analyses per day. Try again tomorrow.' });
      }
    }

    // Server builds the prompt (not an arbitrary forwarded body). Logs ride the LATEST user
    // turn (the system message is fixed per conversation, so it can't carry refreshed data).
    // Backstop the size from the END (most recent) — the client row-caps each submission so
    // this rarely triggers, but it guards against a huge backlog. See AI_LOG_PAYLOAD_MAX_CHARS.
    const logsText = typeof logs === 'string' ? logs.slice(-AI_LOG_PAYLOAD_MAX_CHARS) : '';
    const contents = messages.slice(-40).map(m => ({
      role: m.role === 'model' ? 'model' : 'user',
      parts: [{ text: String(m.text || '').slice(0, 100000) }],
    }));
    if (logsText) {
      const label = kind === 'logcat' ? 'LOGCAT' : kind === 'network' ? 'NETWORK CONNECTION' : 'SECURITY EVENT';
      const lastUser = [...contents].reverse().find(c => c.role === 'user');
      if (lastUser) lastUser.parts.push({ text: `\n\n=== ${label} LOGS (for security review) ===\n${logsText}` });
    }

    try {
      const reply = await callOpenCodeScreenText(systemText, contents, { temperature: 0.4, maxTokens: 8192 });
      if (!reply) return res.status(502).json({ error: 'AI provider returned no content.' });
      res.json({ ok: true, reply });
    } catch (e) {
      console.warn(`[ai/logs:${kind}] proxy error:`, e.message);   // message only, never the payload
      res.status(502).json({ error: 'Failed to reach AI provider.' });
    }
  });

};
