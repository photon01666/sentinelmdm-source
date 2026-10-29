package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentineld/internal/enroll"
	"sentineld/internal/xraytransport"
)

// TestRunControlLoop_RegisterAndHop2ArmDisarm drives runControlLoop against a REAL local
// socket.io server (testdata/fake-control-server.js, not a Go mock) that: validates the same auth
// payload shape the real server would (ticket OR signed), acknowledges registration, then pushes
// real hop2_session_open/hop2_session_close events on a timer. This proves the daemon's actual
// event-handling code (buildAuthPayload, the registration handshake, and the Hop-2 arm/disarm
// file writes that libexec/hop2-authkeys.sh depends on) works end-to-end.
//
// Deliberately NOT covered here: the remote_assist_provision -> full xray config -> hop1.Open
// path. Testing that meaningfully would require either a live REALITY node (unavailable, and
// sending real traffic to production nodes with fake credentials from an automated test isn't
// appropriate) or faking out REALITY entirely (which would stop testing the real code path). That
// path's two halves are instead covered separately and for real: internal/xraytransport's own
// tests prove the full config is valid and xray actually starts and binds the local port from it;
// internal/hop1's own tests prove the SSH tunnel mechanics work against a real sshd. This test
// covers everything else in the daemon's control loop.
func TestRunControlLoop_RegisterAndHop2ArmDisarm(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available on this box")
	}
	serverScript := "testdata/fake-control-server.js"
	if _, err := os.Stat(serverScript); err != nil {
		t.Skipf("fake control server not found: %v", err)
	}
	if _, err := os.Stat("testdata/node_modules/socket.io"); err != nil {
		t.Skip("run `npm install` in cmd/sentineld/testdata first")
	}

	for _, tc := range []struct {
		name        string
		ticket      string
		useSignedID bool
	}{
		{name: "enrollment ticket auth", ticket: "fake-ticket-123"},
		{name: "signed reconnect auth", ticket: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identityDir := t.TempDir()
			identity, err := enroll.LoadOrCreateIdentityAt(identityDir)
			if err != nil {
				t.Fatalf("LoadOrCreateIdentityAt: %v", err)
			}
			state := &enroll.EnrollmentState{DeviceID: identity.DeviceID, Ticket: tc.ticket}

			xrayDir := t.TempDir()
			mgr, err := xraytransport.NewManager(xrayDir)
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}

			port := mustFreePort(t)
			const fakePubKey = "ssh-ed25519 AAAAFAKE integration-test-hop2-key"
			cmd := exec.Command(nodeBin, serverScript, fmt.Sprint(port), fakePubKey)
			stdout, _ := cmd.StdoutPipe()
			if err := cmd.Start(); err != nil {
				t.Fatalf("start fake control server: %v", err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
			go logPipe(t, stdout)

			if !waitPort(port, 5*time.Second) {
				t.Fatal("fake control server never started listening")
			}

			runDir := t.TempDir()
			controlURL := fmt.Sprintf("http://127.0.0.1:%d", port)
			errCh := make(chan error, 1)
			go func() {
				errCh <- runControlLoop(controlURL, nil, state, identity, mgr, xrayDir, runDir, identityDir, 0, port, 0, "127.0.0.1")
			}()

			armPath := filepath.Join(runDir, "hop2-armed.pub")

			if !waitForFile(armPath, 3*time.Second) {
				t.Fatal("hop2 arm file was never written after hop2_session_open")
			}
			content, err := os.ReadFile(armPath)
			if err != nil {
				t.Fatalf("read arm file: %v", err)
			}
			if got := string(content); got != fakePubKey+"\n" {
				t.Errorf("arm file content = %q, want %q", got, fakePubKey+"\n")
			}

			if !waitForFileGone(armPath, 3*time.Second) {
				t.Fatal("hop2 arm file was never removed after hop2_session_close")
			}

			// Shut the fake server down and confirm runControlLoop does NOT crash — it should
			// reconnect on its own (see the crash-loop fix, memory
			// linux-remote-assist-crash-loop) rather than returning a fatal error and relying
			// on systemd's RestartSec to recover. Proven by starting a FRESH fake server on
			// the SAME port and observing the daemon reconnect and re-arm hop2 again, without
			// any external help.
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			select {
			case err := <-errCh:
				t.Fatalf("runControlLoop returned (%v) after the control channel died instead of reconnecting on its own", err)
			case <-time.After(2 * time.Second):
				// Expected: still running, retrying in the background.
			}

			cmd2 := exec.Command(nodeBin, serverScript, fmt.Sprint(port), fakePubKey)
			stdout2, _ := cmd2.StdoutPipe()
			if err := cmd2.Start(); err != nil {
				t.Fatalf("start replacement fake control server: %v", err)
			}
			t.Cleanup(func() { _ = cmd2.Process.Kill(); _, _ = cmd2.Process.Wait() })
			go logPipe(t, stdout2)

			if !waitForFile(armPath, 10*time.Second) {
				t.Fatal("hop2 arm file was never re-written after the daemon's automatic reconnect")
			}
		})
	}
}

// TestRunControlLoop_DeviceStatusZkRouting proves that when the server's "registered" ack
// includes a zkPubKey (as it does for every account-linked device — this build is always
// public/ZK-owned, see config.AdminAgent), the daemon routes its device_status heartbeat through
// "zk_data" (ZK-envelope-encrypted, via internal/zkwrap — cross-verified against the real browser
// decrypt code in internal/zkwrap's own test) instead of the plaintext "device_status" event that
// server.js silently drops for any ZK-owned device (found live 2026-07-29 — the Linux daemon
// previously never sent device_status at all, so this path was never exercised).
func TestRunControlLoop_DeviceStatusZkRouting(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available on this box")
	}
	serverScript := "testdata/fake-control-server.js"
	if _, err := os.Stat(serverScript); err != nil {
		t.Skipf("fake control server not found: %v", err)
	}
	if _, err := os.Stat("testdata/node_modules/socket.io"); err != nil {
		t.Skip("run `npm install` in cmd/sentineld/testdata first")
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

	identityDir := t.TempDir()
	identity, err := enroll.LoadOrCreateIdentityAt(identityDir)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentityAt: %v", err)
	}
	state := &enroll.EnrollmentState{DeviceID: identity.DeviceID, Ticket: "fake-ticket-zk"}

	xrayDir := t.TempDir()
	mgr, err := xraytransport.NewManager(xrayDir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	port := mustFreePort(t)
	const fakePubKey = "ssh-ed25519 AAAAFAKE zk-routing-test-hop2-key"
	cmd := exec.Command(nodeBin, serverScript, fmt.Sprint(port), fakePubKey, ownerPubB64)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake control server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	capture := newCapturePipe(t, stdout)

	if !waitPort(port, 5*time.Second) {
		t.Fatal("fake control server never started listening")
	}

	runDir := t.TempDir()
	controlURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	go func() {
		_ = runControlLoop(controlURL, nil, state, identity, mgr, xrayDir, runDir, identityDir, 0, port, 0, "127.0.0.1")
	}()

	line := capture.waitForLine("EVENT zk_data ", 5*time.Second)
	if line == "" {
		t.Fatal("daemon never emitted zk_data(device_status) within 5s")
	}
	if strings.Contains(capture.snapshot(), "EVENT device_status ") {
		t.Error("daemon ALSO emitted a plaintext device_status event — must be ZK-only when zkPubKey is present")
	}

	jsonPart := strings.TrimPrefix(line, "EVENT zk_data ")
	var wrapped struct {
		Zk         bool   `json:"zk"`
		Event      string `json:"event"`
		Payload    string `json:"payload"`
		DekWrapped struct {
			EphPub string `json:"eph_pub"`
			Iv     string `json:"iv"`
			Ct     string `json:"ct"`
		} `json:"dek_wrapped"`
	}
	if err := json.Unmarshal([]byte(jsonPart), &wrapped); err != nil {
		t.Fatalf("parse captured zk_data payload %q: %v", jsonPart, err)
	}
	if !wrapped.Zk {
		t.Error("wrapped.zk = false, want true")
	}
	if wrapped.Event != "device_status" {
		t.Errorf("wrapped.event = %q, want %q", wrapped.Event, "device_status")
	}
	if wrapped.Payload == "" || wrapped.DekWrapped.EphPub == "" || wrapped.DekWrapped.Iv == "" || wrapped.DekWrapped.Ct == "" {
		t.Errorf("wrapped envelope missing fields: %+v", wrapped)
	}
}

// capturePipe tees a subprocess's stdout to both t.Logf and a synchronized in-memory buffer, so a
// test can poll for a specific substring without racing the log writer.
type capturePipe struct {
	mu  sync.Mutex
	buf strings.Builder
}

func newCapturePipe(t *testing.T, r interface{ Read([]byte) (int, error) }) *capturePipe {
	c := &capturePipe{}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := string(buf[:n])
				t.Logf("fake server: %s", chunk)
				c.mu.Lock()
				c.buf.WriteString(chunk)
				c.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *capturePipe) snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// waitForLine polls for a line containing substr and returns that full line (trimmed), or "" on
// timeout.
func (c *capturePipe) waitForLine(substr string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(c.snapshot(), "\n") {
			if strings.Contains(line, substr) {
				return strings.TrimSpace(line)
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ""
}

func logPipe(t *testing.T, r interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			t.Logf("fake server: %s", buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func mustFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForFile(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func waitForFileGone(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
