package xraytransport

import (
	"strings"
	"testing"
)

// TestNodeCandidatesShape pins the two invariants the daemon's IPv6 address ladder relies on:
// every node always ends with its IPv4 literal (so a v6 failure can always degrade to the legacy
// path), and when a v6 candidate is present it is FIRST and is the node's real v6 literal.
// The route probe is live (a UDP connect to the real node), so on a v6-less host the candidate
// list legitimately shrinks to the v4 literal alone — the assertions accept either shape.
func TestNodeCandidatesShape(t *testing.T) {
	for i := range RealityNodes {
		cands := NodeCandidates(i)
		if len(cands) == 0 {
			t.Fatalf("node %d: no candidates", i)
		}
		if last := cands[len(cands)-1]; last != RealityNodes[i] {
			t.Errorf("node %d: last candidate %q, want the IPv4 literal %q", i, last, RealityNodes[i])
		}
		seen := map[string]bool{}
		for _, c := range cands {
			if c == "" || seen[c] {
				t.Errorf("node %d: empty or duplicate candidate %q in %v", i, c, cands)
			}
			seen[c] = true
		}
		if len(cands) > 1 {
			if !strings.Contains(cands[0], ":") {
				t.Errorf("node %d: first candidate %q is not an IPv6 literal", i, cands[0])
			}
			if want := RealityNodesV6[i]; cands[0] != want {
				t.Errorf("node %d: first candidate %q, want the v6 literal %q", i, cands[0], want)
			}
		}
	}
}

// TestPickNodeCandidateClamping covers the ladder's index arithmetic: addrIdx 0 is the preferred
// (v6) candidate, an over-range index clamps to the LAST candidate (v4 — never past the end of the
// node's address list), a negative index clamps to the first, and an unknown node errors.
func TestPickNodeCandidateClamping(t *testing.T) {
	for i := range RealityNodes {
		cands := NodeCandidates(i)

		first, sni, err := PickNodeCandidate(i, 0)
		if err != nil || first != cands[0] {
			t.Errorf("node %d addrIdx 0: got (%q,%v), want %q", i, first, err, cands[0])
		}
		if sni != SNIForNode(i) {
			t.Errorf("node %d addrIdx 0: sni %q, want %q", i, sni, SNIForNode(i))
		}

		last, _, err := PickNodeCandidate(i, 99)
		if err != nil || last != cands[len(cands)-1] {
			t.Errorf("node %d addrIdx 99: got (%q,%v), want %q", i, last, err, cands[len(cands)-1])
		}

		neg, _, err := PickNodeCandidate(i, -1)
		if err != nil || neg != cands[0] {
			t.Errorf("node %d addrIdx -1: got (%q,%v), want %q", i, neg, err, cands[0])
		}
	}

	if _, _, err := PickNodeCandidate(len(RealityNodes), 0); err == nil {
		t.Error("node index len(RealityNodes) must error")
	}
	if _, _, err := PickNodeCandidate(-1, 0); err == nil {
		t.Error("negative node index must error")
	}
}

// TestRealityNodesV6Aligned guards the index alignment the ladder depends on: entry i of
// RealityNodesV6 belongs to the same node as entry i of RealityNodes (CA, VA, OR). A short list
// silently falls back to v4 for the missing nodes, but an entry that isn't a v6 literal at all is
// a bug (it would produce a bogus xray dial target).
func TestRealityNodesV6Aligned(t *testing.T) {
	if len(RealityNodesV6) != len(RealityNodes) {
		t.Errorf("RealityNodesV6 has %d entries, want %d (index-aligned with RealityNodes)", len(RealityNodesV6), len(RealityNodes))
	}
	for i, v6 := range RealityNodesV6 {
		if !strings.Contains(v6, ":") {
			t.Errorf("RealityNodesV6[%d] = %q is not an IPv6 literal", i, v6)
		}
	}
}
