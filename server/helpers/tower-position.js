// helpers/tower-position.js — effective tower position resolution.
//
// A HELPER module, not a route module: it registers nothing.
//
//   towerPosition   export   resolve effective tower position (manual > learned > OCID)
//
// RELOCATE: wiring line must sit at/after L5623 and at/before L5790 — placed at L5790.
// 1 dep: LEARNED_MIN_SAMPLES_USE (binding L5622).
//
// relative requires: none

module.exports = ({ LEARNED_MIN_SAMPLES_USE }) => {
// Effective tower position: operator-placed manual truth first, fleet-learned when
// ripe, else the OCID estimate. Returns { lat, lng, posSource, disagreeM } —
// disagreeM is the OCID↔learned split (0 when only one exists, or when the operator
// has spoken); the fix uncertainty must cover it, not hide it.
function towerPosition(t) {
  if (t && t.manual_lat != null && t.manual_lng != null)
    return { lat: t.manual_lat, lng: t.manual_lng, posSource: 'manual', disagreeM: 0, learnedSamples: t.learned_samples || 0, snapped: false };
  const learnedOk = t && t.learned_lat != null && t.learned_lng != null &&
    (t.learned_samples || 0) >= LEARNED_MIN_SAMPLES_USE;
  if (learnedOk) {
    let disagreeM = 0;
    if (t.lat != null && t.lng != null) {
      const dx = (t.learned_lat - t.lat) * 111320, dy = (t.learned_lng - t.lng) * 111320 * Math.cos(t.learned_lat * Math.PI / 180);
      disagreeM = Math.round(Math.sqrt(dx * dx + dy * dy));
    }
    return { lat: t.learned_lat, lng: t.learned_lng, posSource: 'learned', disagreeM, learnedSamples: t.learned_samples, snapped: !!t.learned_snapped };
  }
  if (t) return { lat: t.lat, lng: t.lng, posSource: t.source === 'ocid' ? 'ocid' : (t.source || 'unknown'), disagreeM: 0, learnedSamples: t.learned_samples || 0, snapped: false };
  return null;
}

  return {
    towerPosition,
  };
};