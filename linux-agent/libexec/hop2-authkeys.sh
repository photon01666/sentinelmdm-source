#!/bin/sh
# sshd_hop2_config's AuthorizedKeysCommand — see design plan §3. Invoked by sshd (as the
# AuthorizedKeysCommandUser, never root) on every Hop-2 connection attempt. Two independent trust
# paths, both printed (sshd accepts a key matching ANY line in the output):
#   1. The armed session key (/run/sentinel-ra/hop2-armed.pub) — a human clicked Connect in
#      the dashboard; trusted with NO TTL since 2026-08-18 (previously a 900s/10800s freshness
#      window). Removed only by hop2_session_close (daemon disarmHop2), a newer re-arm
#      overwriting it, or a box reboot (tmpfs).
#   2. The standing bastion admin key (/var/lib/sentinel-ra/bastion-support-key.pub) — ALWAYS
#      trusted, no TTL, mirroring the Windows agent's ADMIN_SUPPORT_KEY (bastion-web.py's
#      hop2_run() family). Needed for automated one-shot bastion actions with no human in the
#      loop: arbitrary exec buttons, fleet fan-out, IT Audit Mode's "Collect all". Added after
#      discovering the original design here only covered the interactive case — see
#      hop2-common.sh's comment on HOP2_ADMIN_PUBKEY_FILE for the full story.
# ⚠️ PLANNED REMOVAL (noted 2026-08-18): the standing admin key is slated to be removed — the
#      dashboard-armed session key is intended to become the ONLY Hop-2 trust path. Until that
#      lands, this path stays (bastion one-shot automation depends on it: Snap/Forensics/
#      IT-Audit/fleet actions). Re-evaluate this block when that automation is reworked to use
#      the armed key.
# Prints nothing if neither is present/fresh, which sshd treats as "no matching key" and rejects
# the connection immediately. Presence of these files — not the sentinel-hop2.socket unit's
# activation state — is what "dormant vs armed" means.
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/hop2-common.sh"

if hop2_arm_file_armed; then
    cat "$HOP2_ARM_FILE"
fi

if [ -f "$HOP2_ADMIN_PUBKEY_FILE" ]; then
    cat "$HOP2_ADMIN_PUBKEY_FILE"
fi
# Deliberately no `else`/error branch for the "neither present" case — an unarmed, not-yet-
# provisioned connection attempt is the routine, expected state, not a fault.
