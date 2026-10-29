package xraytransport

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func mustMarshalIndent(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		// Only reachable on a programmer error (an unmarshalable field type) — every value passed
		// through this package is a plain struct of strings/ints, so this should never actually
		// fire outside a test that deliberately breaks it.
		panic(fmt.Sprintf("xraytransport: config marshal failed: %v", err))
	}
	return b
}

func splitHostPort(hostPort string) (string, int) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// FreeLocalPort asks the kernel for an unused loopback TCP port — mirrors
// XrayTransportManager.GetFreeLocalPort().
func FreeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listener address type %T", l.Addr())
	}
	return addr.Port, nil
}

// PickNode selects the PREFERRED dial address for a fleet node — its IPv6 literal when this host
// has a v6 route to it, else its IPv4 literal (see NodeCandidates). Kept as a tiny seam so callers
// (and tests) can pin a specific index instead of relying on real randomness.
func PickNode(nodeIdx int) (node, sni string, err error) {
	return PickNodeCandidate(nodeIdx, 0)
}

// PickNodeCandidate returns the addrIdx-th dial candidate for a node (clamped into the candidate
// range) together with that node's camouflage SNI. addrIdx 0 = the IPv6 literal on a v6-capable
// host, 1 = the IPv4 literal — the same "v6 first, same-node v4 second" ladder the Android agent
// implements via realityAddrIdx (see docs/ARCHITECTURE.md); the daemon walks it when
// repeated control-channel connects fail against the current address.
func PickNodeCandidate(nodeIdx, addrIdx int) (node, sni string, err error) {
	cands := NodeCandidates(nodeIdx)
	if len(cands) == 0 {
		return "", "", fmt.Errorf("node index %d out of range (have %d nodes)", nodeIdx, len(RealityNodes))
	}
	if addrIdx < 0 {
		addrIdx = 0
	}
	if addrIdx >= len(cands) {
		addrIdx = len(cands) - 1
	}
	return cands[addrIdx], SNIForNode(nodeIdx), nil
}

// NodeCandidates returns the ordered dial candidates for a node index: its IPv6 literal first —
// but ONLY when this host actually has a v6 route to it — then its IPv4 literal. The route probe
// is the daemon-side equivalent of the Android agent's `physicalV6Available` gate (a v6-capable
// network address with no working path must not burn dial attempts before falling back), just
// measured with a route lookup instead of a LinkProperties default-route check.
func NodeCandidates(nodeIdx int) []string {
	if nodeIdx < 0 || nodeIdx >= len(RealityNodes) {
		return nil
	}
	out := make([]string, 0, 2)
	if nodeIdx < len(RealityNodesV6) {
		if v6 := strings.TrimSpace(RealityNodesV6[nodeIdx]); v6 != "" && hasIPv6Route(v6) {
			out = append(out, v6)
		}
	}
	return append(out, RealityNodes[nodeIdx])
}

// hasIPv6Route reports whether this host can route to addr over IPv6. A UDP "connect" performs a
// route lookup but sends no packets, so this is a cheap, side-effect-free probe: it fails exactly
// when the kernel would fail xray's own dial with ENETUNREACH ("Network is unreachable") — the
// condition that made the Android agent's v6 dials fail before the uid-carveout fix (memory
// agent-reality-ipv6-first).
func hasIPv6Route(addr string) bool {
	c, err := net.DialTimeout("udp6", net.JoinHostPort(addr, "443"), 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
