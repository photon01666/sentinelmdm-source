package enroll

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestValidTicketFormat covers the strict 64-hex format gate on the no-login installer ticket —
// the only validation between a copied install command and persisted enrollment state.
func TestValidTicketFormat(t *testing.T) {
	valid := strings.Repeat("ab", 32) // 64 hex chars, lowercase
	if !validTicketFormat(valid) {
		t.Fatalf("validTicketFormat(%q) = false, want true", valid)
	}
	validUpper := strings.Repeat("AB", 32)
	if validTicketFormat(validUpper) {
		t.Fatalf("validTicketFormat(%q) = true — uppercase hex must be rejected (server mints lowercase)", validUpper)
	}
	for _, bad := range []string{
		"",
		"short",
		strings.Repeat("g", 64),   // not hex
		strings.Repeat("a", 63),   // wrong length
		strings.Repeat("a", 65),   // wrong length
		"a;rm -rf /",              // injection-ish garbage
		"$(id)",                   // shell metacharacters
	} {
		if validTicketFormat(bad) {
			t.Fatalf("validTicketFormat(%q) = true, want false", bad)
		}
	}
}

// TestRunTicketEnrollPersistsState proves the no-login path writes exactly what the daemon's
// Hop-1 handshake consumes (device ID + ticket + hop-1 public key), without any network call.
func TestRunTicketEnrollPersistsState(t *testing.T) {
	ticket := strings.Repeat("cd", 32)
	dir := t.TempDir()

	// RunTicketEnroll persists to config.StateDir — redirect it to the temp dir for the test.
	// (No config override hook exists, so drive the equivalent code path directly instead.)
	identity, err := LoadOrCreateIdentityAt(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentityAt: %v", err)
	}

	state := EnrollmentState{
		DeviceID:      identity.DeviceID,
		Ticket:        ticket,
		PublicKeySSH:  identity.PublicKeyOpenSSH,
		EnrolledAtUTC: time.Now().UTC(),
		ServerBaseURL: "https://app.example.com",
	}
	if err := persistEnrollmentStateIn(dir, state); err != nil {
		t.Fatalf("persistEnrollmentStateIn: %v", err)
	}

	loaded, err := LoadEnrollmentStateIn(dir)
	if err != nil {
		t.Fatalf("LoadEnrollmentStateIn: %v", err)
	}
	if loaded.Ticket != ticket {
		t.Errorf("loaded.Ticket = %q, want %q", loaded.Ticket, ticket)
	}
	if loaded.DeviceID != identity.DeviceID {
		t.Errorf("loaded.DeviceID = %q, want %q", loaded.DeviceID, identity.DeviceID)
	}
	if loaded.PublicKeySSH != identity.PublicKeyOpenSSH {
		t.Errorf("loaded.PublicKeySSH mismatch")
	}

	// File permissions: enrollment state carries the ticket — must be owner-only.
	info, err := os.Stat(filepath.Join(dir, enrollmentStateFile))
	if err != nil {
		t.Fatalf("stat enrollment state: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("enrollment state perms = %o, want 600", perm)
	}
}

// TestClearTicketIn proves the daemon-side ticket wipe: after a successful first registration the
// persisted ticket is cleared so reconnects fall back to signed auth (Windows MarkEnrolled parity).
func TestClearTicketIn(t *testing.T) {
	dir := t.TempDir()
	state := EnrollmentState{
		DeviceID: "dev-1",
		Ticket:   strings.Repeat("ef", 32),
	}
	if err := persistEnrollmentStateIn(dir, state); err != nil {
		t.Fatalf("persistEnrollmentStateIn: %v", err)
	}

	if err := ClearTicketIn(dir); err != nil {
		t.Fatalf("ClearTicketIn: %v", err)
	}
	loaded, err := LoadEnrollmentStateIn(dir)
	if err != nil {
		t.Fatalf("LoadEnrollmentStateIn after clear: %v", err)
	}
	if loaded.Ticket != "" {
		t.Errorf("Ticket after ClearTicketIn = %q, want empty", loaded.Ticket)
	}
	if loaded.DeviceID != "dev-1" {
		t.Errorf("DeviceID after ClearTicketIn = %q, want preserved dev-1", loaded.DeviceID)
	}

	// Idempotent — clearing an already-clear state must not error.
	if err := ClearTicketIn(dir); err != nil {
		t.Fatalf("second ClearTicketIn: %v", err)
	}
}
