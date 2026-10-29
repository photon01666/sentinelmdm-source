#!/bin/sh
# Run periodically by sentinel-hop2-reaper.timer. NO-OP since 2026-08-18: the armed session
# key's TTL was removed entirely (hop2-common.sh), so there is no stale-by-age arm file to reap —
# the key is trusted until hop2_session_close disarms it (the daemon deletes the file), a newer
# session overwrites the arm file, or the box reboots (tmpfs /run). Kept as an inert placeholder
# so the sentinel-hop2-reaper.timer unit keeps working unchanged; if session keys ever get a TTL
# again, restore the age-based reap here.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/hop2-common.sh"

exit 0
