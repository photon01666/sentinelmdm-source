package controlchannel

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestConnect_RealSocketIOServer starts a REAL Node.js socket.io v4 server (not a mock) and
// drives a full handshake + event round-trip against it: Engine.IO open, Socket.IO CONNECT with
// an auth payload the server's `io.use` middleware actually inspects, an emitted "register"
// event the server handles and answers with a server-pushed "registered" event, and a
// ping/pong-style round trip. This is the strongest verification available without a live
// production bastion — it proves the hand-rolled Engine.IO/Socket.IO framing genuinely
// interoperates with a real socket.io implementation, not just "looks right by protocol
// inspection."
//
// Requires `node` + a local `socket.io` install — see
// swarm-stacks/ssh-bastion-client-linux/testdata note in README if this ever needs to run in a
// stripped-down CI image without them; skips gracefully if node isn't found.
func TestConnect_RealSocketIOServer(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available on this box")
	}

	serverScript := sioTestServerPath(t)

	port := mustFreePort(t)
	cmd := exec.Command(nodeBin, serverScript, fmt.Sprint(port))
	cmd.Dir = filepath.Dir(serverScript)
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node test server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	go drainToLog(t, stdout)

	if !waitForTCP(port, 5*time.Second) {
		t.Fatal("node test server never started listening")
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	auth := map[string]any{
		"deviceId":  "test-device-1",
		"platform":  "linux",
		"agentKind": "remote_assist",
	}

	client, err := Connect(baseURL, auth, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	registered := make(chan map[string]any, 1)
	client.On("registered", func(raw json.RawMessage) {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil {
			registered <- m
		}
	})

	if err := client.Emit("register", map[string]any{
		"platform":  "linux",
		"agentKind": "remote_assist",
		"deviceId":  "test-device-1",
	}); err != nil {
		t.Fatalf("Emit register: %v", err)
	}

	select {
	case resp := <-registered:
		if resp["ok"] != true {
			t.Errorf(`expected {"ok":true,...}, got %v`, resp)
		}
		if resp["echoedPlatform"] != "linux" {
			t.Errorf("expected echoedPlatform=linux, got %v", resp["echoedPlatform"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for \"registered\" event")
	}

	// Second round-trip on the SAME connection — proves the read loop keeps dispatching events
	// after the first one, not just the first message after connect.
	pong := make(chan map[string]any, 1)
	client.On("pong_test", func(raw json.RawMessage) {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err == nil {
			pong <- m
		}
	})
	if err := client.Emit("ping_test", map[string]any{"seq": 1}); err != nil {
		t.Fatalf("Emit ping_test: %v", err)
	}
	select {
	case resp := <-pong:
		received, ok := resp["received"].(map[string]any)
		if !ok || received["seq"] != float64(1) {
			t.Errorf("unexpected pong_test payload: %v", resp)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for \"pong_test\" event")
	}
}

// TestPingPong_SurvivesMultipleCycles configures the test server with a very short ping interval
// (300ms) and holds the connection open across ~10 ping/pong cycles. Engine.IO v4 flipped the
// ping/pong direction from v3 (server pings, client pongs, not the other way around) — a client
// that gets this backwards, or that gets it right only by accident because a single short test
// never triggers a real timeout, would fail here: the server's own pingTimeout enforcement drops
// silently-non-responding clients, so surviving this long is direct evidence the client answers
// correctly, not just that the initial handshake happened to work.
func TestPingPong_SurvivesMultipleCycles(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available on this box")
	}
	serverScript := sioTestServerPath(t)

	port := mustFreePort(t)
	cmd := exec.Command(nodeBin, serverScript, fmt.Sprint(port), "300", "1000")
	cmd.Dir = filepath.Dir(serverScript)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node test server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	if !waitForTCP(port, 5*time.Second) {
		t.Fatal("node test server never started listening")
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	client, err := Connect(baseURL, map[string]any{"deviceId": "ping-test"}, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	const holdOpen = 3500 * time.Millisecond // ~10+ ping cycles at 300ms
	select {
	case <-client.Done():
		t.Fatalf("connection closed within %v — client failed to answer the server's pings correctly", holdOpen)
	case <-time.After(holdOpen):
		// Still connected after many ping/pong cycles — correct.
	}

	// And the connection is still genuinely usable afterward, not just technically-open.
	registered := make(chan struct{}, 1)
	client.On("registered", func(json.RawMessage) { registered <- struct{}{} })
	if err := client.Emit("register", map[string]any{"platform": "linux", "deviceId": "ping-test"}); err != nil {
		t.Fatalf("Emit after hold: %v", err)
	}
	select {
	case <-registered:
	case <-time.After(3 * time.Second):
		t.Fatal("connection open but no longer functional after ping/pong hold period")
	}
}

func TestConnect_RejectsMissingAuth(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available on this box")
	}
	serverScript := sioTestServerPath(t)

	port := mustFreePort(t)
	cmd := exec.Command(nodeBin, serverScript, fmt.Sprint(port))
	cmd.Dir = filepath.Dir(serverScript)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start node test server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	if !waitForTCP(port, 5*time.Second) {
		t.Fatal("node test server never started listening")
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	_, err = Connect(baseURL, map[string]any{}, nil) // no deviceId -> server's io.use rejects
	if err == nil {
		t.Error("expected Connect to fail against a server that rejects the auth payload, got nil error")
	}
}

func drainToLog(t *testing.T, r interface {
	Read([]byte) (int, error)
}) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			t.Logf("node server: %s", buf[:n])
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

// sioTestServerPath resolves the repo-committed test server (testdata/sio-test-server.js),
// overridable via SENTINELD_SIO_TEST_SERVER for a non-standard layout. Skips (not fails) if the
// script or its node_modules/socket.io install isn't present — node_modules is gitignored
// (testdata/.gitignore), so a fresh checkout needs one `npm install` in testdata/ before these
// tests actually run; until then they degrade to a skip rather than a spurious failure.
func sioTestServerPath(t *testing.T) string {
	t.Helper()

	path := os.Getenv("SENTINELD_SIO_TEST_SERVER")
	if path == "" {
		path = "testdata/sio-test-server.js"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("socket.io test server script not found at %s: %v", path, err)
	}

	nodeModules := filepath.Join(filepath.Dir(path), "node_modules", "socket.io")
	if _, err := os.Stat(nodeModules); err != nil {
		t.Skipf("run `npm install` in %s first (socket.io not found): %v", filepath.Dir(path), err)
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve absolute path for %s: %v", path, err)
	}
	return abs
}

func waitForTCP(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}
