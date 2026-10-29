package enroll

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
)

func TestDeviceIdentity_SignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateDeviceIdentityIn(dir)
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentityIn: %v", err)
	}

	pubB64, err := id.PublicKeyBase64()
	if err != nil {
		t.Fatalf("PublicKeyBase64: %v", err)
	}

	sigB64, err := id.Sign("device-123", 1234567890)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Independently reparse the exported public key and verify the signature exactly the way a
	// server-side verifyWithPublicKey() implementation would: base64-decode DER SPKI, re-derive
	// the SAME message string, base64-decode the DER ASN.1 signature, verify.
	pubDER, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("decode pubkey b64: %v", err)
	}
	parsedPub, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecdsaPub, ok := parsedPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("exported public key is not ECDSA (got %T)", parsedPub)
	}

	msg := fmt.Sprintf("%s:%d", "device-123", 1234567890)
	digest := sha256.Sum256([]byte(msg))

	sigDER, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature b64: %v", err)
	}
	if !ecdsa.VerifyASN1(ecdsaPub, digest[:], sigDER) {
		t.Error("signature does not verify against the exported public key")
	}

	// Confirm the signature is REALLY DER ASN.1 SEQUENCE{r,s} (Rfc3279DerSequence) — the exact
	// format the .NET server side documents expecting — not some other encoding that happens to
	// verify via the Go-side round-trip alone.
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sigDER, &sig); err != nil {
		t.Errorf("signature is not a valid DER ASN.1 SEQUENCE{r,s}: %v", err)
	}
}

func TestDeviceIdentity_StableAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	first, err := loadOrCreateDeviceIdentityIn(dir)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := loadOrCreateDeviceIdentityIn(dir)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	pub1, _ := first.PublicKeyBase64()
	pub2, _ := second.PublicKeyBase64()
	if pub1 != pub2 {
		t.Error("public key changed across calls — should be persisted and stable")
	}
}

func TestDeviceIdentity_DifferentTimestampsProduceDifferentSignatures(t *testing.T) {
	dir := t.TempDir()
	id, err := loadOrCreateDeviceIdentityIn(dir)
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentityIn: %v", err)
	}
	sig1, _ := id.Sign("dev", 1000)
	sig2, _ := id.Sign("dev", 2000)
	if sig1 == sig2 {
		t.Error("signatures for different timestamps should differ")
	}
}
