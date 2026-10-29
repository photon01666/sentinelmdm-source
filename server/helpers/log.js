// helpers/log.js — structured logging helper.
//
// A HELPER module, not a route module: it registers nothing.
//
//   log   export   structured logging with timestamp, level, and key=value extras
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L468, so at or before L467.  L399 satisfies both.
//
// relative requires: none

module.exports = () => {
// ── Logging ────────────────────────────────────────────────────────────────
function log(level, msg, extra = {}) {
  const ts = new Date().toISOString();
  const parts = [`[${ts}] [${level.toUpperCase()}] ${msg}`];
  const keys = Object.keys(extra);
  if (keys.length) parts.push(' | ' + keys.map(k => `${k}=${JSON.stringify(extra[k])}`).join(' '));
  console.log(parts.join(''));
}

  return {
    log,
  };
};