// helpers/classify-bot-ua.js — classify bot User-Agent as crawler or scanner.
//
// A HELPER module, not a route module: it registers nothing.
//
//   classifyBotUA   export   classify a User-Agent string as crawler or scanner
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: CRAWLER_UA_SUBSTRINGS (binding L1974).  The call must sit at or after L1975; the earliest consumer of
// the export is L3236, so at or before L3235.  L1976 satisfies both.
//
// relative requires: none

module.exports = ({ CRAWLER_UA_SUBSTRINGS }) => {
function classifyBotUA(ua) {
  const u = (ua || '').toLowerCase();
  return CRAWLER_UA_SUBSTRINGS.some(s => u.includes(s)) ? 'crawler' : 'scanner';
}

  return {
    classifyBotUA,
  };
};