// @ts-check
// server/webauthn.js
// ─────────────────────────────────────────────────────────────────────────────
// WebAuthn / passkey ceremony helpers (login replacement for username+password+OTP).
//
// @simplewebauthn/server v13 ships a CommonJS entry ("require": "./script/index.js"),
// so a plain require() works from this CJS codebase — no dynamic import needed.
//
// RP config derives from SERVER_ORIGIN (production host / dev localhost) and is
// overridable via WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN (the latter may be a comma-separated
// list of accepted origins, e.g. for localhost dev + prod).
//
// PRF note: the WebAuthn PRF extension (CTAP2 hmac-secret) is evaluated CLIENT-side to
// derive a stable KEK for the zero-knowledge key. The server only passes the `prf` hint in
// the options and stores the browser-produced ciphertext (zk_wrapped_priv) per credential —
// it never sees the PRF secret or the plaintext ZK key. A FIXED app-wide PRF salt is used so
// a usernameless (discoverable) login can request the same eval without first knowing which
// credential will answer. See PRF_SALT below — it MUST match the client constant in app.js.
// ─────────────────────────────────────────────────────────────────────────────
'use strict';

const swa = require('@simplewebauthn/server');

const SERVER_ORIGIN = process.env.SERVER_ORIGIN || 'http://localhost:3000';
/** @type {string} */
let RP_ID;
try { RP_ID = process.env.WEBAUTHN_RP_ID || new URL(SERVER_ORIGIN).hostname; }
catch { RP_ID = 'localhost'; }
// expectedOrigin may be a single origin or a list (dev localhost + prod, behind CF, etc.)
const EXPECTED_ORIGIN = (process.env.WEBAUTHN_ORIGIN || SERVER_ORIGIN)
  .split(',').map(s => s.trim()).filter(Boolean);
const RP_NAME = 'SentinelMDM';

// Fixed PRF salt → stable per-credential secret across logins. MUST equal app.js _PRF_SALT.
const PRF_SALT = 'sentinelmdm-zk-prf-v1';

const b64u = {
  /** @param {any} buf */
  enc: (buf) => Buffer.from(buf).toString('base64url'),
  /** @param {string} s */
  dec: (s)  => Buffer.from(s, 'base64url'),
};

// ── Registration (enroll a passkey while signed in) ──────────────────────────
/**
 * @param {{ id: number|string, email?: string, username?: string }} user
 * @param {string[]} [existingCredIDs]
 */
async function regOptions(user, existingCredIDs = []) {
  return swa.generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: Buffer.from('u' + user.id),                 // stable, opaque user handle
    userName: user.email || user.username || ('user-' + user.id),
    userDisplayName: user.username || user.email || ('User ' + user.id),
    attestationType: 'none',                            // privacy: no attestation tracking
    excludeCredentials: existingCredIDs.map(id => ({ id })),  // block double-enroll on same authenticator
    authenticatorSelection: {
      residentKey: 'required',                          // discoverable → usernameless login
      requireResidentKey: true,
      userVerification: 'required',                     // biometric/PIN → replaces password+OTP
    },
    // PRF is not in @simplewebauthn's AuthenticationExtensionsClientInputs type, but the
    // client relies on it to derive the ZK KEK (see header note). Cast to pass it through.
    extensions: /** @type {any} */ ({ prf: {} }),       // advertise PRF (public users derive ZK KEK)
    supportedAlgorithmIDs: [-7, -257],                  // ES256, RS256
  });
}

/**
 * @param {any} response
 * @param {string} expectedChallenge
 */
async function verifyReg(response, expectedChallenge) {
  return swa.verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: EXPECTED_ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
  });
}

// ── Authentication (usernameless / discoverable login) ───────────────────────
async function authOptions() {
  return swa.generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: [],                               // empty → let the platform pick the resident credential
  });
}

/**
 * @param {any} response
 * @param {string} expectedChallenge
 * @param {{ id: string, public_key: string, counter: number|string, transports?: string }} credentialRow
 */
async function verifyAuth(response, expectedChallenge, credentialRow) {
  return swa.verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: EXPECTED_ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
    credential: {
      id: credentialRow.id,                             // base64url string
      publicKey: b64u.dec(credentialRow.public_key),
      counter: Number(credentialRow.counter) || 0,
      transports: credentialRow.transports ? safeJson(credentialRow.transports) : undefined,
    },
  });
}

/** @param {string} s */
function safeJson(s) { try { return JSON.parse(s); } catch { return undefined; } }

module.exports = { RP_ID, RP_NAME, EXPECTED_ORIGIN, PRF_SALT, b64u, regOptions, verifyReg, authOptions, verifyAuth };
