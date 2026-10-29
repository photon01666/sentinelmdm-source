// helpers/phish-feed.js — phishing-proxy threat-intel feed config.
//
// A HELPER module, not a route module: it registers nothing.
//
//   PHISH_FEED_URL, PHISH_FEED_KEY   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: readSecret (destructure L36).  The call must sit at or after L37; the earliest consumer of
// the export is L6711, so at or before L6710.  L6570 satisfies both.
//
// relative requires: none

module.exports = ({ readSecret }) => {
// ── Phishing-proxy (AiTM) threat-intel feed — EvilProxy/Tycoon/VoidProxy (env-gated) ──────────
// Mirrors the honeypot feed pattern above: a configured PHISH_FEED_URL is polled by the WORKER
// every 5 min; the result (confirmed-C2 tier + low-confidence tier + ASN-tagged CIDR ranges) is
// cached in Redis `phish:intel`; every replica hydrates a local copy. FULLY INERT (zero network
// calls) until PHISH_FEED_URL is set.
// Tier semantics (this gating is what makes auto-block safe): `c2` = operator/abuse.ch-validated
// C2 infra (URLhaus/ThreatFox) → alert + BLOCK + KILL established connections; `low` = crowd-
// sourced (PhishTank) → ALERT ONLY, never blocks. Confirmed-C2 feeds have genuinely low FP rates;
// the crowd-sourced tier does not, so it must not be able to sever live traffic.
const PHISH_FEED_URL = (process.env.PHISH_FEED_URL || '').trim();
const PHISH_FEED_KEY = (readSecret('sentinel_phish_mgmt_key', 'PHISH_MGMT_KEY') || '').trim();

  return {
    PHISH_FEED_URL,
    PHISH_FEED_KEY,
  };
};