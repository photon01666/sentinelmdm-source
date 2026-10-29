package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// DeviceIdentity is the Go port of DeviceIdentity.cs: a persistent EC P-256 keypair used for the
// Socket.IO control-channel handshake — DISTINCT from the Hop-1 ed25519 SSH keypair in identity.go
// (that one authenticates the reverse SSH tunnel to the bastion; this one authenticates the
// control-channel connection itself to the tracker server, matching the Android agent's
// hardware-Keystore signed-handshake scheme, docs/ARCHITECTURE.md "Device Identity & Handshakes"). Server's
// verifyWithPublicKey() (server.js) expects: public key = base64(DER SPKI), signature =
// base64(DER ECDSA-SHA256 over UTF8 "{deviceId}:{timestampMs}") — Go's ecdsa.SignASN1 produces the
// same DER ASN.1 SEQUENCE{r,s} encoding as .NET's DSASignatureFormat.Rfc3279DerSequence, so no
// format translation is needed on either side, same as the C# comment documents.
type DeviceIdentity struct {
	priv *ecdsa.PrivateKey
}

const deviceIdentityKeyFile = "device_ecdsa.pem"

// PublicKeyBase64 returns base64(DER SubjectPublicKeyInfo) — sent as `publicKey` in both the
// enrollment-ticket auth payload and the signed-reconnect auth payload.
func (d *DeviceIdentity) PublicKeyBase64() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&d.priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal SPKI public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// Sign signs "{deviceId}:{timestampMs}" — the exact string the server's verifyWithPublicKey()
// checks — and returns base64(DER ECDSA-SHA256 signature).
func (d *DeviceIdentity) Sign(deviceID string, timestampMs int64) (string, error) {
	msg := fmt.Sprintf("%s:%d", deviceID, timestampMs)
	digest := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, d.priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// loadOrCreateDeviceIdentityIn mirrors loadOrCreateIdentityIn's self-healing pattern: a
// missing/corrupt key file mints a fresh keypair rather than crashing (same fallback
// DeviceIdentity.cs itself documents), since this identity has no external state to lose track of
// besides itself.
func loadOrCreateDeviceIdentityIn(stateDir string) (*DeviceIdentity, error) {
	path := filepath.Join(stateDir, deviceIdentityKeyFile)

	if pemBytes, err := os.ReadFile(path); err == nil {
		if priv, err := parseECDSAPrivateKeyPEM(pemBytes); err == nil {
			return &DeviceIdentity{priv: priv}, nil
		}
		// Fall through to regenerate on any parse failure (corrupt file, wrong curve, etc.).
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EC P-256 key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, fmt.Errorf("persist device identity key: %w", err)
	}

	return &DeviceIdentity{priv: priv}, nil
}

func parseECDSAPrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA (got %T)", key)
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("key is not on the P-256 curve")
	}
	return priv, nil
}
