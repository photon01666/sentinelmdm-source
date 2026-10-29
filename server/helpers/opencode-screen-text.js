// helpers/opencode-screen-text.js - route screen-text analysis through the OpenCode proxy
// (DeepSeek) instead of the AI provider — same OpenAI-compatible chat/completions contract.
// Converts provider-style {role, parts[]} turns into OpenAI messages, tries OPENCODE_MODEL
// then the fallback chain, and returns the trimmed text reply (or null).
//
// A HELPER module, not a route module: it registers nothing.
//
//   callOpenCodeScreenText   export   analyse screen text via OpenCode proxy
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 5 deps: OPENCODE_MODEL (binding L3904), crypto (Node.js built-in, injected — hidden from
// extraction-plan by JS_GLOBALS), log (function L423, hoisted), opencodeApiKey (function
// L3913, hoisted), postOpencode (function L3930, hoisted).  The last non-hoisted tool-dep
// is OPENCODE_MODEL at L3904 — so the call must sit at or after L3905; the earliest consumer
// of the export is L6032, so at or before L6031.  L5842 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ OPENCODE_FALLBACK_MODELS, OPENCODE_MODEL, crypto, log, opencodeApiKey, postOpencode }) => {
// Route screen-text analysis through the OpenCode proxy (DeepSeek) instead of the
// AI provider — same OpenAI-compatible chat/completions contract as the ARP summary.
// Converts the provider-style {role, parts[]} turn shape into OpenAI messages, tries
// OPENCODE_MODEL then the fallback chain, and returns the trimmed text reply (or null).
async function callOpenCodeScreenText(systemText, contents, { temperature = 0.4, maxTokens = 8192 } = {}) {
  const apiKey = opencodeApiKey();
  if (!apiKey) return null;
  const messages = [{ role: 'system', content: systemText }];
  for (const c of contents || []) {
    const text = (c.parts || []).map(p => p.text || '').join('');
    messages.push({ role: c.role === 'model' ? 'assistant' : 'user', content: text });
  }
  // One session id per analysis conversation — OpenCode Go requires x-opencode-session
  // (a per-conversation stable id so it can route + prompt-cache); shared across the
  // key/model retries below.
  const sessionId = crypto.randomUUID();
  const models = [OPENCODE_MODEL, ...OPENCODE_FALLBACK_MODELS.filter(m => m !== OPENCODE_MODEL)];
  for (const model of models) {
    try {
      // 240s — scheduled payloads can be ~1M chars; mimo-v2.5 needs room on big prompts.
      const resp = await postOpencode({ model, messages, temperature, max_tokens: maxTokens }, 240000, sessionId);
      if (!resp.ok) { log('warn', 'screen-text OpenCode HTTP error', { status: resp.status, model }); continue; }
      const body = /** @type {any} */ (await resp.json());
      const reply = ((body?.choices || [{}])[0]?.message?.content || '').trim();
      if (!reply) { log('warn', 'screen-text: empty OpenCode response', { model }); continue; }
      return reply;
    } catch (e) {
      log('warn', 'screen-text OpenCode call failed', { model, err: e.message });
    }
  }
  return null;
}

  return {
    callOpenCodeScreenText,
  };
};