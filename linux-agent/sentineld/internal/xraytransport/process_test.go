package xraytransport

import (
	"encoding/json"
	"testing"
)

// TestBuildConfig_PassesXrayValidation is the one test in this package that actually matters:
// it extracts the REAL embedded xray-core binary and runs `xray run -test` against a config this
// package generated, for both the bootstrap (control-channel-only) and full (Hop-1 + control)
// shapes. This can't validate the REALITY handshake itself (needs a live node), but it does prove
// the generated JSON is schema-valid xray-core config, not just "looks right on inspection" —
// exactly the gap a hand-written JSON-tag struct set could silently have.
func TestBuildConfig_PassesXrayValidation(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	node, sni, err := PickNode(0)
	if err != nil {
		t.Fatalf("PickNode: %v", err)
	}

	localPort, err := FreeLocalPort()
	if err != nil {
		t.Fatalf("FreeLocalPort: %v", err)
	}
	controlPort, err := FreeLocalPort()
	if err != nil {
		t.Fatalf("FreeLocalPort: %v", err)
	}

	base := BuildOptions{Node: node, SNI: sni, LocalPort: localPort, ControlPort: controlPort}

	t.Run("bootstrap (control-channel only)", func(t *testing.T) {
		cfg := BuildBootstrapConfig(base)
		assertValidJSON(t, cfg)
		if err := mgr.ValidateConfig(cfg); err != nil {
			t.Errorf("xray rejected bootstrap config: %v", err)
		}
	})

	t.Run("full (Hop-1 + control)", func(t *testing.T) {
		full := base
		full.RemoteAssistEgressUUID = "00000000-0000-4000-8000-000000000000" // syntactically valid UUID; auth itself needs a live node
		cfg := BuildConfig(full)
		assertValidJSON(t, cfg)
		if err := mgr.ValidateConfig(cfg); err != nil {
			t.Errorf("xray rejected full config: %v", err)
		}
	})
}

func TestSNIForNode_IndexAlignment(t *testing.T) {
	if len(RealityNodes) != len(RealitySnis) {
		t.Fatalf("RealityNodes (%d) and RealitySnis (%d) must stay index-aligned — a mismatch "+
			"silently breaks whichever node runs off the end of the shorter array (documented "+
			"footgun, xray-camouflage-pool.md)", len(RealityNodes), len(RealitySnis))
	}
	for i := range RealityNodes {
		if got := SNIForNode(i); got != RealitySnis[i] {
			t.Errorf("SNIForNode(%d) = %q, want %q", i, got, RealitySnis[i])
		}
	}
}

func assertValidJSON(t *testing.T, b []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("generated config is not valid JSON: %v\n%s", err, b)
	}
}
