// helpers/learn-mode-guards.js — Learn-Mode rule sets + observation-window cache.
//
// A HELPER module, not a route module: it registers nothing. Extracted DEP-FIRST
// (D1b R2) so its bindings can be created ABOVE the learn run's eager consumer
// (the arp-scan wiring, L2991) — the originals sat at L3025-L3049, below it.
//
//   LEARN_LEARNABLE_CATEGORIES   export   categories a window may learn
//   LEARN_CRITICAL               export   rules that are NEVER suppressible
//   EDR_NEVER_SUPPRESS_RULES     export   never rate-limited EDR rules (rode along
//                                         verbatim: it sat between the deps; its
//                                         consumers are the edr wirings below)
//   LEARN_WINDOW_CACHE_MS        export   observation-window cache TTL
//   _learnWindowCache            export   Map (deviceId -> { ts, open }), mutated
//                                         by reference from helpers/learn-mode-core
//
// No ctx deps. No relative require to rebase.

module.exports = () => {

const LEARN_LEARNABLE_CATEGORIES = new Set(['arp_recon', 'edr_alert', 'sentry']);
const LEARN_CRITICAL = new Set([
  // Ransomware: damage is done or imminent and cannot be undone by a later alert.
  'edr_alert:shadow_copy_attack', 'edr_alert:canary_file_touch', 'edr_alert:mass_file_modification',
  // Defense evasion / blinding the sensor — the precondition for everything else going unseen.
  'edr_alert:defender_disabled', 'edr_alert:process_tamper', 'edr_alert:sysmon_sensor_down',
  // Safe Boot Guard (Akira/Huntress Safe-Mode-blinds-EDR class): booting into Safe Mode itself is
  // the evasion act, a SafeBoot-registry entry is AnyDesk-style persistence, and Defender found OFF
  // at boot is the sensor already blinded — all three are never suppressible, every occurrence pages.
  'edr_alert:safe_mode_boot', 'edr_alert:safeboot_registry_tamper', 'edr_alert:defender_rearm',
  // Phase 4/5 Event 5 (ProcessTerminate): our own tooling was killed — the same sensor-blinding
  // class as process_tamper. A permanent "accepted" baseline must never mute this.
  'edr_alert:agent_process_killed',
]);
// Safe Boot Guard rules are never rate-limited. Each firing is a DISTINCT security event (a real
// Safe Mode boot attempt, a SafeBoot-persistence entry found, Defender found off at boot) — not
// Sysmon lineage noise where one action produces many discrete events for the same condition, which
// is what the 30-min EDR_ALERT_SUPPRESS_MS window exists to collapse. Suppressing a second Safe
// Mode boot inside 30 minutes would let an attacker blind the sensor twice and only get paged once
// — the exact "boot into Safe Mode, kill EDR, boot back" dance this guard exists to surface.
const EDR_NEVER_SUPPRESS_RULES = new Set(['safe_mode_boot', 'safeboot_registry_tamper', 'defender_rearm', 'phishing_proxy_connection']);
// arp_spoof is absent from LEARN_LEARNABLE_CATEGORIES on purpose: IP/MAC binding integrity is not
// a behavioural habit a device can "normally" have, so there is nothing legitimate to learn.
const LEARN_WINDOW_CACHE_MS = 30 * 1000;
const _learnWindowCache = new Map();   // deviceId -> { ts, open }

return { EDR_NEVER_SUPPRESS_RULES, LEARN_CRITICAL, LEARN_LEARNABLE_CATEGORIES, LEARN_WINDOW_CACHE_MS, _learnWindowCache };

};
