// crypto.js — At-rest encryption (AES-256-GCM), key derivation, unlock verification.
// Depends on: state.js (ENC_KEY, ENC_MAGIC)

const crypto = require('crypto');
const state  = require('./state');

// storedSalt is a base64 string from the settings table (null for legacy deployments).
// iterations: 600k for new databases, 100k for existing (backward compat).
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
  if (!state.ENC_KEY) throw new Error('Server not unlocked');
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', state.ENC_KEY, iv);
  const enc    = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return 'ENC:' + iv.toString('base64') + ':' + cipher.getAuthTag().toString('base64') + ':' + enc.toString('base64');
}

function decryptText(value) {
  if (typeof value !== 'string' || !value.startsWith('ENC:')) return value;
  if (!state.ENC_KEY) return value;
  const parts = value.slice(4).split(':');
  if (parts.length !== 3) return value;
  try {
    const dec = crypto.createDecipheriv('aes-256-gcm', state.ENC_KEY, Buffer.from(parts[0], 'base64'));
    dec.setAuthTag(Buffer.from(parts[1], 'base64'));
    return Buffer.concat([dec.update(Buffer.from(parts[2], 'base64')), dec.final()]).toString('utf8');
  } catch { return value; }
}

function encryptBuffer(buf) {
  if (!state.ENC_KEY) throw new Error('Server not unlocked');
  const iv     = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', state.ENC_KEY, iv);
  const enc    = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([state.ENC_MAGIC, iv, cipher.getAuthTag(), enc]);
}

function decryptBuffer(buf) {
  if (buf.length < 32 || !buf.slice(0, 4).equals(state.ENC_MAGIC)) return buf;
  if (!state.ENC_KEY) return buf;
  try {
    const dec = crypto.createDecipheriv('aes-256-gcm', state.ENC_KEY, buf.slice(4, 16));
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

module.exports = {
  deriveKey,
  tryUnlock,
  encryptText,
  decryptText,
  encryptBuffer,
  decryptBuffer,
  decryptDevice,
};
