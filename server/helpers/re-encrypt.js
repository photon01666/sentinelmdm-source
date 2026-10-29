// helpers/re-encrypt.js - re-encrypt text and buffer values with a new key
// (used during encryption passphrase rotation).
//
// A HELPER module, not a route module: it registers nothing.
//
//   _reEncryptBuffer   export   re-encrypt a Buffer with a new key (ENC_MAGIC-prefixed)
//   _reEncryptText     export   re-encrypt an 'ENC:...' string with a new key
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: ENC_MAGIC (binding L133), crypto (Node.js built-in, injected — hidden from
// extraction-plan by JS_GLOBALS).  The last non-hoisted tool-dep is ENC_MAGIC at L133 —
// so the call must sit at or after L134; the earliest consumer of the exports is L2930,
// so at or before L2929.  L2869 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ ENC_MAGIC, crypto }) => {
function _reEncryptText(value, oldKey, newKey) {
  if (typeof value !== 'string' || !value.startsWith('ENC:')) return value;
  const parts = value.slice(4).split(':');
  if (parts.length !== 3) return value;
  try {
    const dec = crypto.createDecipheriv('aes-256-gcm', oldKey, Buffer.from(parts[0], 'base64'));
    dec.setAuthTag(Buffer.from(parts[1], 'base64'));
    const plain = Buffer.concat([dec.update(Buffer.from(parts[2], 'base64')), dec.final()]).toString('utf8');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', newKey, iv);
    const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    return 'ENC:' + iv.toString('base64') + ':' + cipher.getAuthTag().toString('base64') + ':' + enc.toString('base64');
  } catch { return value; }
}

function _reEncryptBuffer(buf, oldKey, newKey) {
  if (!Buffer.isBuffer(buf) || buf.length < 32 || !buf.slice(0, 4).equals(ENC_MAGIC)) return buf;
  try {
    const dec = crypto.createDecipheriv('aes-256-gcm', oldKey, buf.slice(4, 16));
    dec.setAuthTag(buf.slice(16, 32));
    const plain = Buffer.concat([dec.update(buf.slice(32)), dec.final()]);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', newKey, iv);
    const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([ENC_MAGIC, iv, cipher.getAuthTag(), enc]);
  } catch { return buf; }
}

  return {
    _reEncryptBuffer,
    _reEncryptText,
  };
};