// helpers/encryption.js — AES-256-GCM at-rest encryption primitives.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the scheduling/consumption. Only the crypto core moves.
//
//   deriveKey       export   PBKDF2 key derivation
//   tryUnlock       export   verify passphrase against stored sentinel
//   encryptText     export   encrypt plaintext string to ENC:… envelope
//   decryptText     export   decrypt ENC:… envelope back to string
//   encryptBuffer   export   encrypt Buffer to ENC_MAGIC||iv||tag||ciphertext
//   decryptBuffer   export   decrypt ENC_MAGIC-prefixed Buffer
//   decryptDevice   export   decrypt device name/model/version fields
//
// ctx is available at this module's own position in server.js (X >= L130,
// X <= L1039) — nothing had to move (IN-PLACE splice).
//
// 2 ctx deps: ENC_MAGIC (STABLE — const L129, never reassigned),
//             getENC_KEY (LIVE getter).
//
// getENC_KEY is a LIVE dep (getter): ENC_KEY (L106) is runtime-reassigned at
// 5 sites (unlock-store L2534, rekey L2543/L2638, Phase-2 bootstrap L6092/
// L6101). A by-value capture would decrypt with the OLD key after every
// rotation. The getter reads the top-level `let ENC_KEY` at call time.
//   — R5: live vs stable documented here; R3: getENC_KEY() is called ONLY
//     inside function bodies, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

const crypto = require('crypto');

module.exports = ({ ENC_MAGIC, getENC_KEY }) => {

// storedSalt is a base64 string from the settings table (null for legacy deployments).
// iterations: 600k for new databases, 100k for existing (backward compat — can't change without re-encrypting all data).
function deriveKey(passphrase, storedSalt, iterations = 100_000) {
  const salt = storedSalt ? Buffer.from(storedSalt, 'base64') : Buffer.from('SentinelMDM-v1-salt');
  return crypto.pbkdf2Sync(passphrase, salt, iterations, 32, 'sha256');
}

// Verify passphrase against the stored sentinel (or accept any on first run).
// Returns { key, firstRun? } on success, null on failure.
function tryUnlock(passphrase, sentinel, storedSalt, iterations) {
  const key = deriveKey(passphrase, storedSalt, iterations);
  if (!sentinel) return { key, firstRun: true };
  if (!sentinel.startsWith('ENC:')) return null;
  const parts = sentinel.slice(4).split(':');
  if (parts.length !== 3) return null;
  try {
    const dec = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parts[0], 'base64'));
    dec.setAuthTag(Buffer.from(parts[1], 'base64'));
    const plain = Buffer.concat([dec.update(Buffer.from(parts[2], 'base64')), dec.final()]).toString('utf8');
    return plain === 'SentinelMDM-unlock-v1' ? { key } : null;
  } catch { return null; }
}

function encryptText(plain) {
  if (!plain) return plain;
  if (!getENC_KEY()) throw new Error('Server not unlocked');
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getENC_KEY(), iv);
  const enc    = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return 'ENC:' + iv.toString('base64') + ':' + cipher.getAuthTag().toString('base64') + ':' + enc.toString('base64');
}

function decryptText(value) {
  if (typeof value !== 'string' || !value.startsWith('ENC:')) return value;
  if (!getENC_KEY()) return value;
  const parts = value.slice(4).split(':');
  if (parts.length !== 3) return value;
  try {
    const dec = crypto.createDecipheriv('aes-256-gcm', getENC_KEY(), Buffer.from(parts[0], 'base64'));
    dec.setAuthTag(Buffer.from(parts[1], 'base64'));
    return Buffer.concat([dec.update(Buffer.from(parts[2], 'base64')), dec.final()]).toString('utf8');
  } catch { return value; }
}

function encryptBuffer(buf) {
  if (!getENC_KEY()) throw new Error('Server not unlocked');
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getENC_KEY(), iv);
  const enc    = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([ENC_MAGIC, iv, cipher.getAuthTag(), enc]);
}

function decryptBuffer(buf) {
  if (buf.length < 32 || !buf.slice(0, 4).equals(ENC_MAGIC)) return buf;
  if (!getENC_KEY()) return buf;
  try {
    const dec = crypto.createDecipheriv('aes-256-gcm', getENC_KEY(), buf.slice(4, 16));
    dec.setAuthTag(buf.slice(16, 32));
    return Buffer.concat([dec.update(buf.slice(32)), dec.final()]);
  } catch { return buf; }
}

function decryptDevice(d) {
  if (!d) return d;
  return {
    ...d,
    name: decryptText(d.name),
    model: decryptText(d.model),
    android_version: decryptText(d.android_version),
  };
}

return { deriveKey, tryUnlock, encryptText, decryptText, encryptBuffer, decryptBuffer, decryptDevice };

};