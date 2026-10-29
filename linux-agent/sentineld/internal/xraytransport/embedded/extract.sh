#!/bin/sh
# Extracts the pinned xray-core Linux binaries (amd64 + arm64) from the project's own pinned
# server image (teddysun/xray:26.3.27 — see docs/ARCHITECTURE.md's "DPI" invariant on why this version is
# pinned) into this directory, where embed_amd64.go/embed_arm64.go go:embed them.
#
# Run this ONCE after a fresh checkout, before `go build`/`go test` — the binaries themselves are
# gitignored (they're ~30MB each; regenerating them from the pinned image on demand keeps the repo
# small and, more importantly, keeps the binary's provenance verifiable — anyone can re-run this
# and diff, rather than trusting an opaque blob sitting in git history).
set -eu
cd "$(dirname "$0")"

IMAGE="teddysun/xray:26.3.27"

extract() {
    platform="$1"
    outname="$2"
    echo "pulling $IMAGE ($platform)..."
    docker pull --platform "$platform" "$IMAGE" >/dev/null
    cid=$(docker create --platform "$platform" "$IMAGE")
    docker cp "$cid:/usr/bin/xray" "./$outname"
    docker rm "$cid" >/dev/null
    chmod +x "./$outname"
    echo "  -> $outname ($(du -h "./$outname" | cut -f1))"
}

extract linux/amd64 xray
extract linux/arm64 xray-arm64

echo "done. Verify:"
./xray version
