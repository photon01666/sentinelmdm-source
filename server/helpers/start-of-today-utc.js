// helpers/start-of-today-utc.js — start of today UTC timestamp.
//
// A HELPER module, not a route module: it registers nothing.
//
//   startOfTodayUtcTs   export   get the UTC timestamp for the start of today
//
// RELOCATE: wiring line must sit at/after L1 and at/before L4338 — placed at L4338.
// 0 deps.
//
// relative requires: none

module.exports = () => {
function startOfTodayUtcTs() {
  const d = new Date();
  d.setUTCHours(0, 0, 0, 0);
  return d.getTime();
}

  return {
    startOfTodayUtcTs,
  };
};