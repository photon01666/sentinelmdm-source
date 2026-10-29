//go:build amd64

// Package embedded holds the pinned xray-core Linux binary, extracted directly from the
// project's own pinned server image (`teddysun/xray:26.3.27` — see the docs/ARCHITECTURE.md "DPI" invariant:
// do NOT bump this version without re-vetting on the canary rig). Embedding via go:embed means
// `sentineld` needs no network fetch or package-manager dependency to get a working xray at
// runtime — same self-contained rationale as the Windows client embedding xray.exe.
package embedded

import _ "embed"

//go:embed xray
var XrayBinary []byte

const XrayVersion = "26.3.27"
