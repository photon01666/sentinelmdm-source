// helpers/opencode-keys.js — OpenCode API key management.
//
// A HELPER module, not a route module: it registers nothing.
//
//   OPENCODE_FALLBACK_MODELS, opencodePrimaryKey, opencodeFallbackKey, opencodeApiKey   members
//
// RELOCATE: wiring line must sit at/after L37 and at/before L653 — placed at L653.
// 1 dep: readSecret (destructure L36).
//
// relative requires: none

module.exports = ({ readSecret }) => {
// ⚠️ OpenCode Go keys use the /zen/go/ Console-Go route (NOT /zen/v1 — that's the Zen-balance
// route and rejects Go models with "Model not supported"). The Go route REQUIRES the
// x-opencode-session header (added by postOpencode below); without it every call 400s
// "MissingSessionID". This is the documented endpoint for all Go models (docs/go/).
const OPENCODE_FALLBACK_MODELS = (process.env.OPENCODE_FALLBACK_MODELS || 'mimo-v2.5')
  .split(',').map(m => m.trim()).filter(Boolean);
function opencodePrimaryKey()  { return readSecret('opencode_api_key', 'OPENCODE_API_KEY') || ''; }
function opencodeFallbackKey() { return readSecret('opencode_api_fallback_key', 'OPENCODE_API_FALLBACK_KEY') || ''; }
function opencodeApiKey() {
  return opencodePrimaryKey() || opencodeFallbackKey();
}

  return {
    OPENCODE_FALLBACK_MODELS,
    opencodePrimaryKey,
    opencodeFallbackKey,
    opencodeApiKey,
  };
};