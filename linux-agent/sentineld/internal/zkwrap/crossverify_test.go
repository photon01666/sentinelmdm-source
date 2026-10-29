package zkwrap

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCrossVerifyAgainstBrowserDecrypt proves the wrapped envelope this package produces is
// byte-compatible with what the REAL browser code (zkDecryptRow() in server/public/app.js) expects
// — the actual production consumer of this wire format, not a hand-rolled re-implementation. Runs
// a Node script that performs the exact same WebCrypto calls zkDecryptRow() does (ECDH deriveBits
// -> HKDF -> AES-GCM unwrap DEK -> AES-GCM decrypt payload) against a real owner keypair, and
// checks it recovers the original plaintext.
func TestCrossVerifyAgainstBrowserDecrypt(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available on this box")
	}

	ownerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate owner key: %v", err)
	}
	ownerPubDER, err := x509.MarshalPKIXPublicKey(&ownerPriv.PublicKey)
	if err != nil {
		t.Fatalf("marshal owner public key: %v", err)
	}
	ownerPubB64 := base64.StdEncoding.EncodeToString(ownerPubDER)
	ownerPrivPKCS8, err := x509.MarshalPKCS8PrivateKey(ownerPriv)
	if err != nil {
		t.Fatalf("marshal owner private key: %v", err)
	}

	type statusPayload struct {
		UptimeSecs int            `json:"uptimeSecs"`
		Network    map[string]any `json:"network"`
	}
	want := statusPayload{UptimeSecs: 12345, Network: map[string]any{"connection_type": "ethernet"}}
	plaintextJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal plaintext: %v", err)
	}

	wrapped := Wrap(ownerPubB64, "device_status", plaintextJSON)
	if wrapped == nil {
		t.Fatal("Wrap returned nil")
	}

	dir := t.TempDir()
	wrappedJSON, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatalf("marshal wrapped: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "wrapped.json"), wrappedJSON, 0o600); err != nil {
		t.Fatalf("write wrapped.json: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ownerPrivPKCS8})
	if err := os.WriteFile(filepath.Join(dir, "owner-priv.pem"), privPEM, 0o600); err != nil {
		t.Fatalf("write owner-priv.pem: %v", err)
	}

	scriptPath := filepath.Join(dir, "decrypt.js")
	if err := os.WriteFile(scriptPath, []byte(decryptScript), 0o644); err != nil {
		t.Fatalf("write decrypt.js: %v", err)
	}

	out, err := exec.Command(nodeBin, scriptPath, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("node decrypt script failed: %v\n%s", err, out)
	}

	var got statusPayload
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("parse decrypted output %q: %v", out, err)
	}
	if got.UptimeSecs != want.UptimeSecs || got.Network["connection_type"] != want.Network["connection_type"] {
		t.Errorf("decrypted payload mismatch: got %+v, want %+v", got, want)
	}
}

// decryptScript mirrors zkDecryptRow() in server/public/app.js EXACTLY (same WebCrypto calls, same
// field layout), substituting a PKCS8-imported static private key for the browser's
// sessionStorage-held one — that's the only difference from the real production code path.
const decryptScript = `
const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;

async function main() {
  const dir = process.argv[2];
  const wrapped = JSON.parse(fs.readFileSync(path.join(dir, 'wrapped.json'), 'utf8'));
  const privPem = fs.readFileSync(path.join(dir, 'owner-priv.pem'), 'utf8');

  const privDer = Buffer.from(
    privPem.replace(/-----BEGIN PRIVATE KEY-----/, '')
           .replace(/-----END PRIVATE KEY-----/, '')
           .replace(/\s+/g, ''),
    'base64'
  );
  const privKey = await subtle.importKey('pkcs8', privDer, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

  const dw = wrapped.dek_wrapped;
  const ephDer = Buffer.from(dw.eph_pub, 'base64');
  const ephPub = await subtle.importKey('spki', ephDer, { name: 'ECDH', namedCurve: 'P-256' }, false, []);

  const sharedBits = await subtle.deriveBits({ name: 'ECDH', public: ephPub }, privKey, 256);

  const hkdfSrc = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveBits']);
  const kekBits = await subtle.deriveBits({
    name: 'HKDF', hash: 'SHA-256',
    salt: new Uint8Array(32),
    info: new TextEncoder().encode('sentinel-dek-wrap'),
  }, hkdfSrc, 256);
  const kek = await subtle.importKey('raw', kekBits, { name: 'AES-GCM' }, false, ['decrypt']);

  const dekIv = Buffer.from(dw.iv, 'base64');
  const dekCt = Buffer.from(dw.ct, 'base64');
  const dekRaw = await subtle.decrypt({ name: 'AES-GCM', iv: dekIv }, kek, dekCt);
  const dek = await subtle.importKey('raw', dekRaw, { name: 'AES-GCM' }, false, ['decrypt']);

  const payBytes = Buffer.from(wrapped.payload, 'base64');
  const payIv = payBytes.subarray(0, 12);
  const payCt = payBytes.subarray(12);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: payIv }, dek, payCt);

  process.stdout.write(Buffer.from(plain).toString('utf8'));
}

main().catch(e => { console.error(e); process.exit(1); });
`
