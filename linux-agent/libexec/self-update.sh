#!/bin/sh
# Self-update helper for the Linux Remote Assist agent (sentineld) — invoked via a narrowly-scoped
# sudo rule (see install.sh's /etc/sudoers.d/sentinel-remote-assist entry) by the sentinel-support
# account, itself triggered remotely by bastion-web.py's agent_self_update_linux() over Hop-2 in
# response to the dashboard's "Update Now" button.
#
# Unlike the Windows agent (a per-account custom BUILD, pushed to the box via SCP from bastion),
# sentineld is a single GENERIC binary for every Linux device — enrollment happens interactively
# via `sentineld enroll` on the box itself, nothing is baked in at build time. So this script just
# re-runs, as root, the exact same curl+install+systemctl sequence already documented as the
# manual update command — remotely, instead of requiring physical/SSH access to the box.
set -eu

SERVER_BASE_URL="${SENTINEL_SERVER_BASE_URL:-https://app.example.com}"

case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "ERROR: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

TMP_BIN=$(mktemp)
trap 'rm -f "$TMP_BIN"' EXIT

if ! curl -fsSL --max-time 60 -o "$TMP_BIN" "${SERVER_BASE_URL}/api/remote-assist/linux/sentineld?arch=${ARCH}"; then
    echo "ERROR: download failed" >&2
    exit 1
fi
[ -s "$TMP_BIN" ] || { echo "ERROR: downloaded binary is empty" >&2; exit 1; }
chmod +x "$TMP_BIN"

# Sanity check: the downloaded file must actually run and print a version string before we trust
# it enough to install over the currently-working binary — a truncated/corrupt download must never
# brick the agent.
NEW_VERSION_LINE=$("$TMP_BIN" version 2>/dev/null) || { echo "ERROR: downloaded binary failed to execute" >&2; exit 1; }

# ⚠️ The live binary may carry the immutable attribute (chattr +i) — a common hardening applied
# externally (found live 2026-08-20 on the reference host: the update failed with
# "install: cannot remove '/usr/local/bin/sentineld': Operation not permitted" — even root cannot
# replace an immutable file). Capture the current immutable state, clear it if set, and restore it
# after the new binary is in place so the hardening intent is preserved across updates.
TARGET_BIN=/usr/local/bin/sentineld
IMMUTABLE=0
if command -v lsattr >/dev/null 2>&1 && lsattr "$TARGET_BIN" 2>/dev/null | grep -q '^....i'; then
    IMMUTABLE=1
fi
if [ "$IMMUTABLE" = 1 ]; then
    chattr -i "$TARGET_BIN" 2>/dev/null \
        || { echo "ERROR: failed to clear immutable flag on $TARGET_BIN (chattr -i)" >&2; exit 1; }
fi

install -o root -g root -m 0755 "$TMP_BIN" "$TARGET_BIN"

# Restore the immutable flag if the box had it set — the file is freshly installed and now root-
# owned, so re-applying is safe (and keeps the original hardening in force for the new binary too).
if [ "$IMMUTABLE" = 1 ]; then
    chattr +i "$TARGET_BIN" 2>/dev/null || echo "WARN: could not re-apply immutable flag (chattr +i) on $TARGET_BIN" >&2
fi

# Restarting sentineld SYNCHRONOUSLY here would kill the very Hop-1 tunnel this Hop-2 SSH session
# is currently riding on, before the "OK" line below could ever reach bastion — even though
# sentinel-hop2.socket/sentinel-hop2@.service are separate systemd UNITS from sentineld.service,
# the actual TCP forward carrying THIS session's traffic is provided by sentineld's own Hop-1
# tunnel process, so killing it severs the session the SSH client (bastion) is reading this
# script's stdout/exit code from. Found live 2026-07-29: the update always succeeded on the box
# (confirmed via `sentineld version` + journalctl) but the dashboard reported "Update failed"
# every time — the response never made it back before the connection died. Fix: defer the actual
# restart a couple seconds so THIS script's own process (and its stdout) can fully exit and flush
# its result back over the still-alive-for-now tunnel FIRST; the restart (and the expected tunnel
# drop/self-heal it causes — see the tunnel self-heal fix) then happens safely just after.
#
# ⚠️ SECOND BUG, found live 2026-07-29 (same day, after the fix above shipped): a plain
# `nohup sh -c 'sleep 2; systemctl restart sentineld' & disown` does NOT reliably survive this
# script's own process exiting. nohup only blocks SIGHUP; the child is still inside the same
# session's systemd-logind/PAM scope, and when the Hop-2 SSH session this script runs under tears
# down, systemd can reap the whole scope's remaining processes before the 2s sleep elapses —
# confirmed live: the binary on disk was updated (`sentineld version` correctly showed the new
# version) but `systemctl show sentineld -p ExecMainStartTimestamp` never changed, i.e. the
# deferred restart silently never ran, so the actually-running daemon process (and the version it
# reports at `register`) stayed on the OLD build indefinitely — the dashboard kept showing the
# pre-update version even though "Update Now" reported success. Fix: hand the restart to a
# transient systemd unit via `systemd-run`, which is NOT a child of this script's process/session
# at all — it's scheduled directly by PID 1, so it's immune to the calling session's cgroup being
# torn down.
systemd-run --quiet --unit="sentineld-self-update-restart-$$" \
    -- sh -c 'sleep 2; systemctl restart sentineld' \
    || { echo "ERROR: failed to schedule restart via systemd-run" >&2; exit 1; }

# Machine-parseable last line — agent_self_update_linux() extracts the version from between the
# parens via regex and matches on the "OK: installed" prefix.
echo "OK: installed, restart scheduled (${NEW_VERSION_LINE})"
