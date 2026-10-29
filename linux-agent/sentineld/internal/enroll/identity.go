// Package enroll implements sentineld's CLI enrollment flow: interactive email/password login
// against the SentinelMDM control server (mirroring AccountAuthClient.cs's prehash-v1 login), and
// the persistent per-install Hop-1 identity keypair (mirroring Hop1Identity.cs).
package enroll

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sentineld/internal/config"
)

// Identity holds this install's persistent Hop-1 keypair, control-channel device identity, and
// shared device ID.
type Identity struct {
	DeviceID         string
	PublicKeyOpenSSH string // "ssh-ed25519 AAAA... <comment>", trimmed — sent to the server verbatim
	PrivateKeyPath   string // path to the OpenSSH-format private key file (mode 0600)

	// Device is the SEPARATE EC P-256 identity used to authenticate the Socket.IO control-channel
	// handshake — distinct from the ed25519 keypair above, which authenticates the Hop-1 SSH
	// tunnel. Same shared DeviceID, two different keys for two different purposes, mirroring the
	// Windows client's Hop1Identity + DeviceIdentity split.
	Device *DeviceIdentity
}

const (
	deviceIDFile   = "device-id.txt"
	privateKeyFile = "hop1_ed25519"
	publicKeyFile  = "hop1_ed25519.pub"
)

// LoadOrCreateIdentity returns the persistent per-install Hop-1 identity, generating a fresh
// ed25519 keypair (via the system's own ssh-keygen, so the files are natively OpenSSH-formatted —
// directly usable by `ssh -i` and directly matching what the bastion's authorized_keys expects,
// same rationale as Hop1Identity.cs shelling out to ssh-keygen.exe) if none exists yet, or if the
// existing files are missing/corrupt (e.g. state directory copied from a different machine).
func LoadOrCreateIdentity() (*Identity, error) {
	return loadOrCreateIdentityIn(config.StateDir)
}

// LoadOrCreateIdentityAt is LoadOrCreateIdentity against an explicit directory instead of the
// real config.StateDir — exported so other packages' tests (e.g. cmd/sentineld's daemon
// integration test) can exercise a real identity without touching /var/lib/sentinel-ra, which
// needs root and shouldn't accumulate test artifacts on a real machine.
func LoadOrCreateIdentityAt(stateDir string) (*Identity, error) {
	return loadOrCreateIdentityIn(stateDir)
}

// loadOrCreateIdentityIn is LoadOrCreateIdentity parameterized by directory — split out so it can
// be exercised against a throwaway temp dir in tests instead of the real /var/lib/sentinel-ra
// (which needs root to create and shouldn't accumulate test artifacts on a real machine).
func loadOrCreateIdentityIn(stateDir string) (*Identity, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	deviceID, err := loadOrCreateDeviceIDIn(stateDir)
	if err != nil {
		return nil, err
	}

	device, err := loadOrCreateDeviceIdentityIn(stateDir)
	if err != nil {
		return nil, fmt.Errorf("load/create control-channel device identity: %w", err)
	}

	privPath := filepath.Join(stateDir, privateKeyFile)
	pubPath := filepath.Join(stateDir, publicKeyFile)

	if pub, err := os.ReadFile(pubPath); err == nil {
		if _, err := os.Stat(privPath); err == nil {
			trimmed := strings.TrimSpace(string(pub))
			if trimmed != "" {
				return &Identity{DeviceID: deviceID, PublicKeyOpenSSH: trimmed, PrivateKeyPath: privPath, Device: device}, nil
			}
		}
	}

	// No usable existing pair — mint a fresh one. Delete stale halves first so ssh-keygen
	// never refuses to overwrite an existing file.
	_ = os.Remove(privPath)
	_ = os.Remove(pubPath)

	cmd := exec.Command("ssh-keygen",
		"-t", "ed25519",
		"-N", "", // no passphrase — the daemon must be able to use this unattended
		"-f", privPath,
		"-C", "sentineld-"+deviceID,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ssh-keygen failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := os.Chmod(privPath, 0o600); err != nil {
		return nil, fmt.Errorf("chmod private key: %w", err)
	}

	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read generated public key: %w", err)
	}
	trimmed := strings.TrimSpace(string(pub))
	if trimmed == "" {
		return nil, fmt.Errorf("ssh-keygen produced an empty public key")
	}

	return &Identity{DeviceID: deviceID, PublicKeyOpenSSH: trimmed, PrivateKeyPath: privPath, Device: device}, nil
}

func loadOrCreateDeviceIDIn(stateDir string) (string, error) {
	path := filepath.Join(stateDir, deviceIDFile)
	if b, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	}

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate device id: %w", err)
	}
	id := hex.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("persist device id: %w", err)
	}
	return id, nil
}
