// Package zkwrap implements zero-knowledge envelope encryption for private telemetry — the Go
// port of ZkPayloadHelper.cs (Windows client) / ZkPayloadHelper.kt (Android agent), byte-for-byte
// wire-compatible: the browser's zkDecryptRow() has no idea which platform produced a given
// zk_data blob, and doesn't need to.
//
// Encryption scheme per event (identical across all three platforms):
//  1. Generate a 256-bit random DEK.
//  2. AES-256-GCM encrypt the plaintext JSON with the DEK -> iv(12) || ciphertext || tag(16).
//  3. Generate an ephemeral EC P-256 key pair.
//  4. ECDH(ephemeral_priv, owner_pub) -> raw shared secret (X-coordinate only, no KDF applied).
//  5. HKDF-SHA256(shared_secret, salt=32 zero bytes, info="sentinel-dek-wrap", 32 bytes) -> wrap key.
//  6. AES-256-GCM encrypt the DEK with the wrap key -> dek_iv(12) || dek_ciphertext || dek_tag(16).
//
// Wire format (sent as the "zk_data" Socket.IO event — see server.js's socket.on('zk_data', ...)):
//
//	{ zk: true, event: "<name>", payload: "<b64(iv||ct||tag)>",
//	  dek_wrapped: { eph_pub: "<b64 DER SPKI>", iv: "<b64>", ct: "<b64(ct||tag)>" } }
//
// Go's crypto/ecdh performs the same raw (unhashed) X-coordinate ECDH as .NET's
// ECDiffieHellman.DeriveRawSecretAgreement and Android's own manual ECDH — no translation needed.
package zkwrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const hkdfInfo = "sentinel-dek-wrap"

// Wrap encrypts plaintextJSON under the owner's EC P-256 public key (base64 of a DER
// SubjectPublicKeyInfo blob — the same format the browser/Android/Windows all use for
// users.zk_public_key). Returns nil on ANY crypto failure — per the ZK Security invariant, the
// caller MUST drop the event on a nil return and never fall back to sending it in plaintext.
func Wrap(ownerPubKeyB64, eventName string, plaintextJSON []byte) map[string]any {
	result, err := wrap(ownerPubKeyB64, eventName, plaintextJSON)
	if err != nil {
		return nil
	}
	return result
}

func wrap(ownerPubKeyB64, eventName string, plaintextJSON []byte) (map[string]any, error) {
	ownerPub, err := parseOwnerPublicKey(ownerPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("parse owner public key: %w", err)
	}

	// 1. 256-bit DEK.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}

	// 2. AES-256-GCM encrypt plaintext with DEK. The `payload` field combines iv||ct||tag into a
	// single blob (unlike dek_wrapped below, which keeps iv as a separate field) — matches the
	// C#/Kotlin wire format exactly.
	payloadIv, payloadCtTag, err := gcmSeal(dek, plaintextJSON)
	if err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}
	payloadBlob := append(append([]byte{}, payloadIv...), payloadCtTag...)

	// 3. Ephemeral EC P-256 key pair.
	ephPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephECDH, err := ephPriv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert ephemeral key to ECDH: %w", err)
	}

	// 4. ECDH: ephemeral private x owner public -> raw shared secret (X-coordinate only, no hash).
	sharedSecret, err := ephECDH.ECDH(ownerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// 5. HKDF-SHA256(sharedSecret, salt=32 zero bytes, info="sentinel-dek-wrap") -> 32-byte wrap key.
	wrapKey := make([]byte, 32)
	kdf := hkdf.New(sha256.New, sharedSecret, make([]byte, sha256.Size), []byte(hkdfInfo))
	if _, err := io.ReadFull(kdf, wrapKey); err != nil {
		return nil, fmt.Errorf("derive wrap key: %w", err)
	}

	// 6. AES-256-GCM encrypt the DEK with the wrap key. dek_wrapped.ct is ct||tag ONLY (iv is its
	// own separate field here, unlike payload above).
	dekIv, dekCtTag, err := gcmSeal(wrapKey, dek)
	if err != nil {
		return nil, fmt.Errorf("encrypt DEK: %w", err)
	}

	ephPubDER, err := x509.MarshalPKIXPublicKey(&ephPriv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal ephemeral public key: %w", err)
	}

	return map[string]any{
		"zk":      true,
		"event":   eventName,
		"payload": base64.StdEncoding.EncodeToString(payloadBlob),
		"dek_wrapped": map[string]any{
			"eph_pub": base64.StdEncoding.EncodeToString(ephPubDER),
			"iv":      base64.StdEncoding.EncodeToString(dekIv),
			"ct":      base64.StdEncoding.EncodeToString(dekCtTag),
		},
	}, nil
}

// parseOwnerPublicKey decodes a base64 DER SubjectPublicKeyInfo blob into an EC P-256 ECDH public
// key, ready for use in an ECDH exchange.
func parseOwnerPublicKey(ownerPubKeyB64 string) (*ecdh.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(ownerPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	ownerECDSA, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA (got %T)", pubAny)
	}
	ownerECDH, err := ownerECDSA.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert to ECDH public key: %w", err)
	}
	return ownerECDH, nil
}

// gcmSeal AES-256-GCMs plaintext under key, returning a fresh random 12-byte nonce and the
// ciphertext with its 16-byte tag appended (Go's cipher.AEAD.Seal's standard output shape) —
// matches AesGcm's 12-byte IV / 16-byte tag convention used on the C#/Kotlin side.
func gcmSeal(key, plaintext []byte) (nonce, ciphertextWithTag []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertextWithTag = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertextWithTag, nil
}
