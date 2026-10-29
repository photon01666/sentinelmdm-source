// Package xraytransport manages the embedded xray-core process that carries both Hop-1
// (the reverse SSH tunnel to the bastion) and the control channel, camouflaged via REALITY —
// the Linux port of XrayTransportManager.cs. Confirmed reuse of the org's real production REALITY
// fleet, not a rebuild: the constants below are copied verbatim from the live values already
// baked into the Windows client (`Config.cs`) and Android agent (`TransportManager.kt`/
// `Prefs.realitySniCsv`) — they are documented there as public/non-secret ("safe to bake in like
// the APK does"), confirmed against this repo's own live server config
// (`swarm-stacks/sentinelmdm-ha.yml`, the xray service's REALITY inbound `command:` JSON) which
// shows the server-side `sni-dispatch`/`reality-ms`/`reality-decoy*` inbounds these dial into.
package xraytransport

import (
	"os"
	"strings"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envList(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// REALITY parameters — public/non-secret, shared with every other build (Android, Windows,
// desktop). The matching PRIVATE key never leaves the server (`sentinel_xray_private_key`
// secret).
var (
	RealityPublicKey   = env("SENTINEL_REALITY_PUBLIC_KEY", "")
	RealityShortID     = env("SENTINEL_REALITY_SHORT_ID", "")
	RealityFingerprint = "chrome"

	// RealityControlUUID is the shared public control-channel VLESS user ID — same value baked
	// into every build. Used for the Socket.IO control-channel path (to-control-local ->
	// app.example.com:443) and for the pre-enrollment bootstrap connection, BEFORE the
	// per-account remoteassist egress UUID (secret, "NOT in the APK" per sentinelmdm-ha.yml's own
	// comment — see design plan §7's decision to push it post-enrollment rather than bake it) is
	// available. Server-side this VLESS user is tagged `email: control@sentinel`.
	RealityControlUUID = env("SENTINEL_REALITY_CONTROL_UUID", "")

	// RemoteAssistBastionKnownHostsLine pins the Hop-1 SSH bastion's real host key (captured live
	// via `ssh-keyscan -p 22022 remote.example.com`, same value Config.cs bakes in) — used for
	// REAL host-key pinning in the Go SSH client (internal/hop1), stronger than the Windows
	// client's TOFU accept-new fallback since we have the actual pinned value available here too.
	RemoteAssistBastionKnownHostsLine = env("SENTINEL_BASTION_KNOWN_HOSTS", "")

	// RemoteAssistBastionHost/Port is what the Hop-1 SSH client dials THROUGH xray — the local
	// dokodemo-door's own declared target is functionally moot (the server always overrides the
	// destination via a `freedom` outbound `redirect`, keyed by VLESS user, confirmed against
	// sentinelmdm-ha.yml's `to-bastion-ssh` outbound + the `remoteassist@sentinel` routing rule),
	// but is kept meaningful/consistent with the Windows client's own BuildConfigJson rather than
	// left as an arbitrary placeholder.
	remoteAssistBastionLocalTarget = "127.0.0.1:22"
	controlChannelLocalTarget      = env("SENTINEL_CONTROL_TARGET", "app.example.com:443")
)

// RealityNodes/RealitySnis — fleet REALITY node public IPs and their index-aligned per-node
// camouflage SNI (CA, VA, OR). A single shared SNI is REJECTED on every node whose decoy `dest`
// differs (documented footgun, `xray-camouflage-pool.md`) — keep these two arrays index-aligned
// with each other and in lockstep with the server's per-node dest/serverNames.
var (
	RealityNodes = envList("SENTINEL_REALITY_NODES")
	RealitySnis  = envList("SENTINEL_REALITY_SNIS")
)

// RealityNodesV6 — index-aligned IPv6 literals for the SAME fleet nodes (CA, VA, OR), same
// public/non-secret posture as RealityNodes. Values are copied verbatim from the Android agent's
// `reality_nodes_v6` default (Prefs.kt — the reference implementation, shipped 2.26.0.22) and
// were re-verified live 2026-09-26: all three answer on [v6]:443 (TCP) alongside their v4
// literals; the nodes' xray :443 listeners are dual-stack, so no infra change is involved.
// An empty/missing entry simply means "this node has no v6 literal" — NodeCandidates then returns
// the v4 literal alone, exactly like Android's nodeAddresses().
var RealityNodesV6 = envList("SENTINEL_REALITY_NODES_V6")

// SNIForNode returns the camouflage SNI for a node index, falling back to the first entry if the
// arrays are ever out of sync (mirrors the Windows client's `RealitySni` fallback constant).
func SNIForNode(nodeIdx int) string {
	if nodeIdx >= 0 && nodeIdx < len(RealitySnis) {
		return RealitySnis[nodeIdx]
	}
	if len(RealitySnis) > 0 {
		return RealitySnis[0]
	}
	return "www.microsoft.com"
}
