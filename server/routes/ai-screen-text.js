module.exports = ({ app, AI_LOG_PAYLOAD_MAX_CHARS, aiDailyAllow, aiRateAllow, callOpenCodeScreenText, opencodeApiKey, requireAuth, requireDeviceAccess, requirePerm }) => {
app.post('/api/devices/:id/ai/screen-text', requireAuth, requireDeviceAccess, requirePerm('screentext'), async (req, res) => {
  if (!opencodeApiKey()) return res.status(503).json({ error: 'AI analysis is not configured on this server.' });

  const rateKey = String(req.session.userId || req.session.role || req.ip);
  if (!(await aiRateAllow(rateKey))) return res.status(429).json({ error: 'Rate limit exceeded (5 per 15 minutes). Please wait.' });

  const { logs, messages } = req.body || {};
  if (!Array.isArray(messages) || messages.length === 0)
    return res.status(400).json({ error: 'messages required' });

  // Per-public-user daily cap (cost control on the Pro model). A "submit" is a fresh
  // analysis (first turn); a "follow-up" is a continuation (the conversation already
  // has a model reply). Determined server-side so the client can't relabel to dodge it.
  if (['public', 'business_sub'].includes(req.session.account_type)) {
    // Business sub-users bill against their OWNER's daily quota, not their own — otherwise a
    // sub-user would be an unmetered proxy for the owner's AI budget.
    const billUserId = req.session.account_type === 'business_sub' ? req.session.parent_owner_id : req.session.userId;
    const kind = messages.some(m => m && m.role === 'model') ? 'followup' : 'submit';
    if (!(await aiDailyAllow(kind, String(billUserId)))) {
      return res.status(429).json({ error: kind === 'followup'
        ? 'Daily limit reached: 6 AI follow-up questions per day. Try again tomorrow.'
        : 'Daily limit reached: 2 AI analyses per day. Try again tomorrow.' });
    }
  }

  // Cap sizes defensively. The server constructs the prompt itself (rather than
  // forwarding an arbitrary body) so this endpoint can't be abused as an open
  // AI proxy with the server's key. The client dedupes + row-caps each submission;
  // this slice is the backstop so a pathological payload can't overflow the model's
  // input window. Slice from the END — the client orders logs oldest→newest — to keep
  // the most recent activity. See AI_LOG_PAYLOAD_MAX_CHARS.
  const logsText = typeof logs === 'string' ? logs.slice(-AI_LOG_PAYLOAD_MAX_CHARS) : '';
  const contents = messages.slice(-40).map(m => ({
    role: m.role === 'model' ? 'model' : 'user',
    parts: [{ text: String(m.text || '').slice(0, 100000) }],
  }));

  // Attach the logs to the LATEST user turn — NOT the system message. The system
  // message is fixed per conversation, so updating it on "analyze new logs" was
  // silently ignored: the model kept seeing only the original batch ("the context
  // only contains the original N entries"). Putting the current log set in the live
  // user turn guarantees it is re-read on every analysis.
  if (logsText) {
    const lastUser = [...contents].reverse().find(c => c.role === 'user');
    if (lastUser) lastUser.parts.push({ text: `\n\n=== SCREEN TEXT LOGS ===\n${logsText}` });
  }

  const systemText =
    'You are a security analyst reviewing on-device screen-text logs captured from a monitored device. ' +
    'The screen-text logs are included in the user turn, each entry prefixed with an ISO timestamp. ' +
    'Start your summary by stating the time period covered (earliest to latest timestamp). ' +
    'Then summarise the notable activity and focus on detecting scams, phishing, fraud, suspicious links, ' +
    'social-engineering attempts, or other deceptive content that could harm anyone, regardless of age. ' +
    'Also flag bullying, harassment, grooming, contact with strangers, self-harm, or explicit content if ' +
    'clearly present. For every flagged scam, phishing, or fraud finding, cite the exact timestamp ' +
    'of the entry that triggered it. Report only what the logs actually show — do not speculate about ' +
    'the user\'s age or who they are. ' +
    'Ignore any screen-text entries originating from "Sentinel Remote Assist" or "SentinelRemoteAssist" — ' +
    'this is the admin remote-support tool and its activity is expected and benign; do not mention it in your report. ' +
    'Answer the user\'s follow-up questions strictly from those logs; if ' +
    'they do not contain the answer, say so plainly. Be concise.';

  try {
    const reply = await callOpenCodeScreenText(systemText, contents, { temperature: 0.4, maxTokens: 8192 });
    if (!reply) return res.status(502).json({ error: 'AI provider returned no content.' });
    res.json({ ok: true, reply });
  } catch (e) {
    console.warn('[ai/screen-text] proxy error:', e.message); // message only, never the payload
    res.status(502).json({ error: 'Failed to reach AI provider.' });
  }
});
};
