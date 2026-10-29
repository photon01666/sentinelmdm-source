// helpers/read-secret.js - read a Docker secret or fall back to env var.
//
// A HELPER module, not a route module: it registers nothing.
//
//   readSecret   export   read a Docker Swarm secret with env-var fallback
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: fs (binding L14).  The call must sit at or after L15; the earliest consumer of
// the export is L45, so at or before L44.  L36 satisfies both.
//
// relative requires: none

module.exports = ({ fs }) => {
// ── Docker Secrets helper ─────────────────────────────────────────────────────
// Reads from /run/secrets/<name> first (Docker Swarm secrets), falls back to env var.
function readSecret(secretName, envKey, defaultVal = '') {
  try { return fs.readFileSync(`/run/secrets/${secretName}`, 'utf8').trim(); } catch {}
  return process.env[envKey] || defaultVal;
}

  return {
    readSecret,
  };
};