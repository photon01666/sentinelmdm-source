package xraytransport

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// TestManager_StartStop actually launches the real xray-core process (not just `-test` schema
// validation) against a bootstrap config and confirms: it stays alive, it actually binds the
// declared local dokodemo-door port (proving the process is live and functioning, not just
// exited-0-immediately), and Stop() cleanly kills it. This can't reach a real REALITY node from
// this environment, so it doesn't prove the tunnel itself works — it proves the Manager's process
// lifecycle code (extract/start/detect-alive/stop) is correct, which is the part that was
// actually written in Go here (config.go's shape was already proven separately in
// TestBuildConfig_PassesXrayValidation).
func TestManager_StartStop(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	controlPort, err := FreeLocalPort()
	if err != nil {
		t.Fatalf("FreeLocalPort: %v", err)
	}

	cfg := BuildBootstrapConfig(BuildOptions{
		Node: RealityNodes[0], SNI: RealitySnis[0], ControlPort: controlPort,
	})

	if err := mgr.Start(dir, cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.Stop()

	if !waitUntil(3*time.Second, mgr.Running) {
		t.Fatal("xray process did not stay running")
	}

	if !waitUntil(3*time.Second, func() bool { return portIsListening(controlPort) }) {
		t.Errorf("xray never bound the declared local dokodemo-door port %d", controlPort)
	}

	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if mgr.Running() {
		t.Error("Manager still reports Running() after Stop()")
	}
	if portIsListening(controlPort) {
		t.Error("local port still listening after Stop() — xray process didn't actually exit")
	}
}

func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

func portIsListening(port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
