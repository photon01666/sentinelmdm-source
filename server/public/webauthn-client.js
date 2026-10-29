// public/webauthn-client.js
// ─────────────────────────────────────────────────────────────────────────────
// Shared passkey (WebAuthn) ceremony + PRF→ZK helpers, loaded by login.html (sign-in)
// and app.js (enroll / manage). Uses the RAW navigator.credentials API (not a wrapper) so
// we have direct access to the PRF extension results needed for zero-knowledge.
//
// For PUBLIC users the login password doubles as the ZK data-encryption key, so a passkey
// can't simply replace it — instead the WebAuthn PRF extension (CTAP2 hmac-secret) yields a
// stable per-credential secret that we HKDF into a KEK and use to wrap/unwrap the ZK private
// key. The server only ever stores that ciphertext (zk_wrapped_priv). PRF_SALT_STR MUST match
// server/webauthn.js PRF_SALT, and the wrapped-key byte format (iv‖ct, base64) MUST match
// login.html deriveAndStoreZkKey so app.js's existing decrypt path keeps working unchanged.
// ─────────────────────────────────────────────────────────────────────────────
(function (global) {
  'use strict';
  const PRF_SALT = new TextEncoder().encode('sentinelmdm-zk-prf-v1'); // == server webauthn.js PRF_SALT

  // ── encodings ────────────────────────────────────────────────────────────
  const b64uToBuf = (s) => { s = s.replace(/-/g, '+').replace(/_/g, '/'); const pad = s.length % 4 ? '='.repeat(4 - s.length % 4) : ''; const bin = atob(s + pad); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b.buffer; };
  const bufToB64u = (buf) => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const b64ToBuf  = (s) => { const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b.buffer; };
  const bufToB64  = (buf) => { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };

  function supported() { return !!(global.PublicKeyCredential && navigator.credentials && navigator.credentials.create); }

  // ── PRF secret → AES-GCM KEK (HKDF-SHA256, domain-separated) ──────────────
  async function prfKek(prfSecret) {
    const ikm = await crypto.subtle.importKey('raw', prfSecret, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('sentinel-passkey-zk-kek-v1') },
      ikm, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function wrapZk(kek, rawPrivBuf) {           // → base64(iv12 ‖ ct)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, rawPrivBuf);
    const out = new Uint8Array(12 + ct.byteLength); out.set(iv, 0); out.set(new Uint8Array(ct), 12);
    return bufToB64(out.buffer);
  }
  async function unwrapZk(kek, blobB64) {            // base64(iv12 ‖ ct) → raw priv ArrayBuffer
    const all = new Uint8Array(b64ToBuf(blobB64));
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(0, 12) }, kek, all.slice(12));
  }

  // ── option JSON ↔ navigator.credentials shapes ────────────────────────────
  const toCreate = (o) => ({ ...o, challenge: b64uToBuf(o.challenge), user: { ...o.user, id: b64uToBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
    extensions: { ...(o.extensions || {}), prf: { eval: { first: PRF_SALT } } } });
  const toGet = (o) => ({ ...o, challenge: b64uToBuf(o.challenge),
    allowCredentials: (o.allowCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
    extensions: { ...(o.extensions || {}), prf: { eval: { first: PRF_SALT } } } });
  const regToJSON = (c) => ({ id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
    response: { clientDataJSON: bufToB64u(c.response.clientDataJSON), attestationObject: bufToB64u(c.response.attestationObject),
      transports: c.response.getTransports ? c.response.getTransports() : [] },
    clientExtensionResults: c.getClientExtensionResults() });
  const authToJSON = (c) => ({ id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
    response: { clientDataJSON: bufToB64u(c.response.clientDataJSON), authenticatorData: bufToB64u(c.response.authenticatorData),
      signature: bufToB64u(c.response.signature), userHandle: c.response.userHandle ? bufToB64u(c.response.userHandle) : null },
    clientExtensionResults: c.getClientExtensionResults() });

  const postJSON = async (url, body) => { const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) }); const d = await r.json().catch(() => ({})); if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status)); return d; };

  // ── ENROLL a passkey ──────────────────────────────────────────────────────
  // Default endpoints require a signed-in session (dashboard). register.html overrides
  // optionsUrl/verifyUrl with the /api/register/passkey/* pair (bound to its pending-
  // registration session) and passes zkPrivB64 directly (the key was just generated on
  // that page and is not in sessionStorage).
  // isPublic → PRF-wrap the ZK priv key so this passkey can decrypt the user's data.
  // onStatus(msg) → optional caller hook for progress messages (the PRF retrieval below
  // fires a SECOND authenticator prompt that looks redundant without an explanation).
  async function enroll({ name, isPublic, optionsUrl, verifyUrl, zkPrivB64, onStatus } = {}) {
    const say = (m) => { try { if (onStatus) onStatus(m); } catch {} };
    const STRANDED = ' Note: the entry just saved to your password manager will never work here — you can delete it.';
    if (isPublic) {
      // The ZK key must be in hand BEFORE the authenticator creates anything, else a
      // useless credential is stranded in the user's password manager.
      const raw = zkPrivB64 || sessionStorage.getItem('zk_priv_key');
      if (!raw) throw new Error('Encryption key not loaded — sign in with your password once, then add a passkey.');
      // Same reason: where the browser can tell us up front that PRF can never work, bail
      // before create(). (Capability probe is new-ish; absence of the API proves nothing.)
      if (global.PublicKeyCredential && PublicKeyCredential.getClientCapabilities) {
        let caps = null;
        try { caps = await PublicKeyCredential.getClientCapabilities(); } catch {}
        if (caps && caps['extension:prf'] === false)
          throw new Error('This browser doesn’t support passkey encryption (PRF), which your end-to-end-encrypted account requires. Use a current Chrome/Edge/Safari or this device’s built-in passkey, or keep using your password.');
      }
    }
    const opts = await postJSON(optionsUrl || '/api/webauthn/register/options');
    const cred = await navigator.credentials.create({ publicKey: toCreate(opts) });
    const createExt = cred.getClientExtensionResults() || {};
    let prf = createExt.prf && createExt.prf.results && createExt.prf.results.first;
    if (isPublic && !prf) {
      // Most authenticators (incl. Bitwarden & most platform providers) only release the
      // PRF secret on a follow-up assertion, not at create(). enabled:false however means
      // the provider says it never will — don't bother prompting again.
      if (createExt.prf && createExt.prf.enabled === false)
        throw new Error('This passkey provider doesn’t support encryption (PRF), which your end-to-end-encrypted account requires. Try this device’s built-in passkey (fingerprint/face) instead.' + STRANDED);
      say('Passkey saved — one more confirmation is needed to bind your encryption key. Approve the next prompt.');
      const aOpts = await postJSON('/api/webauthn/auth/options');
      let g;
      try {
        g = await navigator.credentials.get({ publicKey: { ...toGet(aOpts), allowCredentials: [{ id: cred.rawId, type: 'public-key' }] } });
      } catch (e) {
        throw new Error('The encryption-key confirmation was cancelled, so the passkey was NOT registered.' + STRANDED + ' Then try again and approve both prompts.');
      }
      prf = g.getClientExtensionResults()?.prf?.results?.first;
    }
    let zkWrapped = null;
    if (isPublic) {
      if (!prf) throw new Error('This passkey provider doesn’t support encryption (PRF), which your end-to-end-encrypted account requires. Try this device’s built-in passkey (fingerprint/face), or keep using your password.' + STRANDED);
      const raw = zkPrivB64 || sessionStorage.getItem('zk_priv_key');
      zkWrapped = await wrapZk(await prfKek(prf), b64ToBuf(raw));
    }
    say('Registering passkey…');
    await postJSON(verifyUrl || '/api/webauthn/register/verify', { response: regToJSON(cred), name: name || null, zk_wrapped_priv: zkWrapped });
    return true;
  }

  // ── LOGIN with a passkey (usernameless) → returns { redirect, account_type, … } ──
  async function login() {
    const opts = await postJSON('/api/webauthn/auth/options');
    const cred = await navigator.credentials.get({ publicKey: toGet(opts) });
    const prf  = cred.getClientExtensionResults()?.prf?.results?.first;
    const data = await postJSON('/api/webauthn/auth/verify', { response: authToJSON(cred) });
    if (data.zk_wrapped_priv) {  // unlock the ZK key (public data key, OR staff E2E-Conversations key)
      if (!prf) {
        // Public users' data REQUIRES the key → fatal. Staff use it only for E2E Conversations and can
        // still password-login for that, so a PRF-less device must NOT break their sign-in.
        if (data.account_type === 'public') throw new Error('This device couldn’t unlock your encrypted data (no PRF support). Sign in with your password instead.');
      } else {
        const raw = await unwrapZk(await prfKek(prf), data.zk_wrapped_priv);
        try { sessionStorage.setItem('zk_priv_key', bufToB64(raw)); } catch {}
      }
    }
    return data;
  }

  // ── Bind the personal ZK key to an EXISTING passkey (staff E2E link, or recovery re-bind) ──
  // Requires the ZK key already loaded (i.e. a prior PASSWORD login). Does a PRF assertion on the
  // chosen credential, wraps the loaded key under that credential's PRF KEK, and stores the opaque
  // ciphertext server-side so future passkey logins unlock encrypted Conversations without a password.
  // credId (base64url) constrains the prompt to one specific passkey; the bind targets whichever
  // credential actually answers.
  async function bindZk(credId) {
    const rawZk = sessionStorage.getItem('zk_priv_key');
    if (!rawZk) throw new Error('Your encryption key isn’t loaded — sign in with your password first, then link the passkey.');
    const opts = await postJSON('/api/webauthn/auth/options');
    const getOpts = toGet(opts);
    if (credId) getOpts.allowCredentials = [{ id: b64uToBuf(credId), type: 'public-key' }];
    const cred = await navigator.credentials.get({ publicKey: getOpts });
    const prf  = cred.getClientExtensionResults()?.prf?.results?.first;
    if (!prf) throw new Error('This passkey didn’t return an encryption secret (PRF) in this browser. Firefox and many synced/provider passkeys have limited PRF support — open the dashboard in Chrome, Edge, or Safari and try “Link E2E” again, ideally with this device’s built-in fingerprint/face passkey. (Password login always unlocks Conversations.)');
    const zkWrapped = await wrapZk(await prfKek(prf), b64ToBuf(rawZk));
    await postJSON('/api/webauthn/credentials/' + encodeURIComponent(bufToB64u(cred.rawId)) + '/zk-bind', { zk_wrapped_priv: zkWrapped });
    return true;
  }

  async function list()   { const r = await fetch('/api/webauthn/credentials'); return (await r.json().catch(() => ({}))).credentials || []; }
  async function remove(id) { await fetch('/api/webauthn/credentials/' + encodeURIComponent(id), { method: 'DELETE' }); }

  global.SentinelPasskey = { supported, enroll, login, bindZk, list, remove };
})(window);
