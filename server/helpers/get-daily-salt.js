// helpers/get-daily-salt.js — deterministic daily analytics salt.
//
// A HELPER module, not a route module: it registers nothing.
//
//   getDailySalt   export   HMAC-based daily salt for analytics
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: _analyticsSaltBase (binding L1967), crypto (binding L15).  The call must sit at or after L1968; the earliest consumer of
// the export is L3154, so at or before L3153.  L1968 satisfies both.
//
// relative requires: none

module.exports = ({ _analyticsSaltBase, crypto }) => {
function getDailySalt() {
  const day = new Date().toISOString().slice(0, 10);
  return crypto.createHmac('sha256', _analyticsSaltBase).update('analytics-' + day).digest('hex');
}

  return {
    getDailySalt,
  };
};