#!/bin/sh
# Cross-compiles sentineld for the architectures this repo targets — see design plan §7. No
# target sysroot needed (unlike the Windows client's win-x64 cross-compile, which needs
# EnableWindowsTargeting=true); CGO_ENABLED=0 produces a fully static binary that runs unmodified
# on glibc or musl (minimal/Alpine-style server images) with zero runtime deps.
set -eu
cd "$(dirname "$0")"

VERSION="${1:-dev}"
mkdir -p bin

for arch in amd64 arm64; do
    echo "building linux/$arch..."
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
        -ldflags "-X main.version=$VERSION -s -w" \
        -o "bin/sentineld-linux-$arch" \
        ./cmd/sentineld
done

# Default architecture gets the unsuffixed name install.sh expects.
cp bin/sentineld-linux-amd64 bin/sentineld

echo "done:"
ls -la bin/
