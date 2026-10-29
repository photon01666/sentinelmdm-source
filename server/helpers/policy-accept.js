// helpers/policy-accept.js - record policy / ToS acceptance rows (append-only,
// SHA-256-hashed text for chargeback defense).
//
// A HELPER module, not a route module: it registers nothing.
//
//   recordPolicyAcceptances   export   record one row per known policy key
//   recordTosAcceptance       export   append-only ToS acceptance with SHA-256
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 5 deps: POLICY_TEXTS (binding L2137), crypto (Node.js built-in, injected — hidden from
// extraction-plan by JS_GLOBALS subtraction), db (binding L699), log (function L423,
// hoisted), reqClientIp (function L2117, hoisted).  The last non-hoisted tool-dep is
// POLICY_TEXTS at L2137 — so the call must sit at or after L2138; the earliest consumer
// of the exports is L3285, so at or before L3284.  L2161 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ POLICY_TEXTS, crypto, db, log, reqClientIp }) => {
// Record one append-only row per policy key. Unknown keys are dropped rather than recorded with a
// null hash — an unidentifiable row is not evidence, and silently storing one hides a client bug.
// Returns the number of rows written.
async function recordPolicyAcceptances(req, keys, { userId = null, orderId = null, email = null } = {}) {
  let written = 0;
  for (const key of (Array.isArray(keys) ? keys : [])) {
    const policy = POLICY_TEXTS[String(key)];
    if (!policy) { log('warn', 'unknown policy key at acceptance', { key: String(key).slice(0, 64) }); continue; }
    if (await recordTosAcceptance(req, {
      userId, orderId, email,
      policyKey: String(key), policyVersion: policy.version, policyText: policy.text,
    })) written++;
  }
  return written;
}

// Append-only ToS acceptance (chargeback defense). policyText = exact text shown;
// we store its SHA-256 so the record proves what was agreed without bloating it.
async function recordTosAcceptance(req, { userId = null, orderId = null, email = null,
                                    policyKey, policyVersion, policyText = null }) {
  try {
    const sha = policyText
      ? crypto.createHash('sha256').update(String(policyText)).digest('hex') : null;
    (await db.prepare(`INSERT INTO tos_acceptances
      (user_id, order_id, email, policy_key, policy_version, policy_sha256, accepted_at, ip_address, user_agent)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(
      userId, orderId, email, policyKey, policyVersion, sha,
      Date.now(), reqClientIp(req), String(req.headers['user-agent'] || '').slice(0, 400)));
    return true;
  } catch (e) { log('warn', 'recordTosAcceptance failed', { err: e.message }); return false; }
}

  return {
    recordPolicyAcceptances,
    recordTosAcceptance,
  };
};