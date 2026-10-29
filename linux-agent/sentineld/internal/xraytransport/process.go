package xraytransport

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"sentineld/internal/xraytransport/embedded"
)

// Manager owns the extracted xray binary and the running xray-core subprocess — the Linux port
// of XrayTransportManager.cs's process-lifecycle half (config generation lives in config.go).
type Manager struct {
	binaryPath string

	mu      sync.Mutex
	cmd     *exec.Cmd
	cfgPath string
}

// NewManager extracts the embedded xray binary to dir/xray (overwriting any existing copy, so a
// version bump in this binary always takes effect on the next start — same "always re-extract"
// posture as the Windows client) and returns a Manager ready to Start().
func NewManager(dir string) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create xray dir: %w", err)
	}
	binPath := filepath.Join(dir, "xray")
	if err := os.WriteFile(binPath, embedded.XrayBinary, 0o700); err != nil {
		return nil, fmt.Errorf("extract xray binary: %w", err)
	}
	return &Manager{binaryPath: binPath}, nil
}

// ValidateConfig runs `xray run -test -config <path>` — pure offline syntax/schema validation,
// no network required. Always run this before Start() on a freshly (re)generated config; a typo
// in the hand-written JSON-tag structs in config.go would otherwise only surface as an opaque
// process-exit-immediately failure.
func (m *Manager) ValidateConfig(cfgJSON []byte) error {
	tmp, err := os.CreateTemp("", "sentineld-xray-validate-*.json")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(cfgJSON); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	tmp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, m.binaryPath, "run", "-test", "-config", tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xray config validation failed: %w\n%s", err, out)
	}
	return nil
}

// Start writes cfgJSON to disk and launches (or, if already running, restarts) xray-core against
// it. Mirrors the "always re-extract, always regenerate config, always restart clean" posture the
// Windows client uses rather than trying to hot-reload xray's config in place.
func (m *Manager) Start(dir string, cfgJSON []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.stopLocked(); err != nil {
		return fmt.Errorf("stop previous xray instance: %w", err)
	}

	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, cfgJSON, 0o600); err != nil {
		return fmt.Errorf("write xray config: %w", err)
	}

	cmd := exec.Command(m.binaryPath, "run", "-config", cfgPath)
	cmd.Stdout = nil // xray's own logging goes to loglevel-controlled stdout; wired to journald
	cmd.Stderr = nil // via the parent process's own stdout/stderr once run under systemd
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start xray: %w", err)
	}

	m.cmd = cmd
	m.cfgPath = cfgPath
	return nil
}

// Running reports whether the xray subprocess is currently alive.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil && m.cmd.Process != nil && m.cmd.ProcessState == nil
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

func (m *Manager) stopLocked() error {
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	_ = m.cmd.Process.Kill()
	_, _ = m.cmd.Process.Wait()
	m.cmd = nil
	return nil
}
