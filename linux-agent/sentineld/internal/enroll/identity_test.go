package enroll

import (
	"os"
	"strings"
	"testing"
)

func TestLoadOrCreateIdentity_GeneratesValidOpenSSHKeypair(t *testing.T) {
	dir := t.TempDir()

	id, err := loadOrCreateIdentityIn(dir)
	if err != nil {
		t.Fatalf("loadOrCreateIdentityIn: %v", err)
	}
	if id.DeviceID == "" {
		t.Error("DeviceID is empty")
	}
	if !strings.HasPrefix(id.PublicKeyOpenSSH, "ssh-ed25519 ") {
		t.Errorf("PublicKeyOpenSSH doesn't look like an OpenSSH ed25519 key: %q", id.PublicKeyOpenSSH)
	}
	if !strings.Contains(id.PublicKeyOpenSSH, "sentineld-"+id.DeviceID) {
		t.Errorf("PublicKeyOpenSSH comment should embed the device id, got: %q", id.PublicKeyOpenSSH)
	}
}

func TestLoadOrCreateIdentity_IsStableAcrossCalls(t *testing.T) {
	dir := t.TempDir()

	first, err := loadOrCreateIdentityIn(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := loadOrCreateIdentityIn(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if first.DeviceID != second.DeviceID {
		t.Errorf("device id changed across calls: %q -> %q", first.DeviceID, second.DeviceID)
	}
	if first.PublicKeyOpenSSH != second.PublicKeyOpenSSH {
		t.Errorf("public key changed across calls — TOFU identity should be stable once persisted")
	}
}

func TestLoadOrCreateIdentity_RecoversFromCorruptPublicKeyFile(t *testing.T) {
	dir := t.TempDir()

	first, err := loadOrCreateIdentityIn(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Simulate a state dir copied from a different machine / a truncated write: public key
	// present but empty.
	pubPath := dir + "/" + publicKeyFile
	if err := os.WriteFile(pubPath, nil, 0o600); err != nil {
		t.Fatalf("corrupt pub key: %v", err)
	}

	second, err := loadOrCreateIdentityIn(dir)
	if err != nil {
		t.Fatalf("second call after corruption: %v", err)
	}
	if second.PublicKeyOpenSSH == "" {
		t.Error("expected a freshly-minted keypair after corruption, got empty public key")
	}
	if second.DeviceID != first.DeviceID {
		t.Error("device id should NOT be regenerated just because the SSH keypair was corrupt")
	}
}
