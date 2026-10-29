// Package itaudit is the Linux IT Audit Mode forensics collector — the Linux counterpart to
// bastion-web.py's FORENSICS_KINDS / _FORENSICS_PS1. See the design plan §5.1 for the full
// category-by-category mapping from the Windows original.
//
// Every category collector returns a guaranteed-parseable Result even on partial failure (design
// plan §3 "lesson 6" — guaranteed status output, never let a mid-collection crash produce
// unparseable output that reads as a silent, unexplained failure). Collect() recovers from a
// panic in any single category collector and reports it as that category's Error field rather
// than crashing the whole run.
package itaudit

import (
	"os"
	"time"
)

// Row is one collected finding/record within a category — deliberately a loose map (mirrors the
// Windows collector's PSCustomObject rows) since each category's shape differs.
type Row map[string]any

// Result is one category's collection outcome.
type Result struct {
	OK             bool      `json:"ok"`
	Kind           string    `json:"kind"`
	CollectedAtUTC time.Time `json:"collected_at"`
	Hostname       string    `json:"hostname"`
	Rows           []Row     `json:"rows"`
	Error          string    `json:"error,omitempty"`
	Count          int       `json:"count"`
}

// AllResult wraps every category's Result, mirroring run_session_forensics_all()'s shape
// (kinds/kind_order/kinds_failed) so the bastion-side consumer and reporting logic can stay
// structurally aligned with the Windows "Collect all" pack.
type AllResult struct {
	OK             bool              `json:"ok"`
	Kind           string            `json:"kind"`
	CollectedAtUTC time.Time         `json:"collected_at"`
	Hostname       string            `json:"hostname"`
	Kinds          map[string]Result `json:"kinds"`
	KindOrder      []string          `json:"kind_order"`
	KindsFailed    []string          `json:"kinds_failed"`
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
