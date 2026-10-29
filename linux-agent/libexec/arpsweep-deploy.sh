#!/bin/sh
# Linux ARP scan + ARP-sweep detection — the sentineld counterpart of the Windows bastion ARP
# features (_ARP_SCAN_PS1 / _ARP_SWEEP_LOOP_PS1). Root wrapper invoked via a narrowly-scoped
# sudo rule (see install.sh's /etc/sudoers.d/sentinel-remote-assist entry), same pattern as
# usblock-deploy.sh. All the actual work lives in the sentineld binary:
#
#   - scan   -> `sentineld arp-scan`: one point-in-time network-discovery scan (parallel ping
#     sweep of every local /22-/30 subnet to populate the kernel ARP cache, then a read-back of
#     the neighbor table + best-effort reverse DNS). Needs root for the ICMP ping sockets.
#   - watch  -> `sentineld arp-sweep-watch`: the passive sweep-velocity detector — a root-only
#     AF_PACKET capture of ARP requests in ~4s windows, queueing an event for any foreign MAC
#     hitting >=15 distinct target IPs in one window. Same state contract as Windows:
#     /var/lib/sentinel-ra/arpsweep/{queue.json,heartbeat.json}.
#
# The watcher is a long-running systemd service (sentinel-arpsweep-watch.service, created on
# enable / removed on disable) — the Linux analog of the Windows SentinelArpSweepWatch SYSTEM
# scheduled task, including reboot persistence and self-restart on crash. The server-side worker
# drains queue.json via the bastion /arp-sweep-drain endpoint (same contract as Windows).
set -eu

BIN=/usr/local/bin/sentineld
ACTION="${1:-status}"
STATE_DIR=/var/lib/sentinel-ra/arpsweep
QUEUE="$STATE_DIR/queue.json"
HEARTBEAT="$STATE_DIR/heartbeat.json"
WATCH_SERVICE=sentinel-arpsweep-watch.service
WATCH_UNIT=/etc/systemd/system/$WATCH_SERVICE
# Extra VLAN subnets passed from the bastion via --extra-subnets flag (comma-separated CIDR list).
EXTRA_SUBNETS=""
shift 2>/dev/null || true
while [ $# -gt 0 ]; do
    case "$1" in
        --extra-subnets)
            EXTRA_SUBNETS="${2:-}"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

json_escape() {
    printf '%s' "$1" \
        | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' \
        | sed 's/\\/\\\\/g; s/"/\\"/g' \
        | tr -d '\000-\011\013-\037' \
        | awk '{printf "%s\\n", $0}' \
        | sed 's/\\n$//'
}

fail() {
    printf '{"ok":false,"error":"%s"}\n' "$(json_escape "$1")"
    exit 1
}

ensure_state_dir() {
    mkdir -p "$STATE_DIR"
}

# JSON array output for queue.json contents — always a valid array, never a bare object.
read_queue() {
    if [ -f "$QUEUE" ]; then
        data=$(cat "$QUEUE" 2>/dev/null || true)
        case "$data" in
            \[*) printf '%s' "$data" ;;
            *)   printf '[]' ;;
        esac
    else
        printf '[]'
    fi
}

do_scan() {
    # One scan on demand — the schedule is bastion-driven (same as Windows: the cron tick calls
    # the bastion's arp_scan() per configured interval), so no on-box persistence is needed here.
    # sentineld prints its result as a single compact JSON line; pass it through untouched.
    # Extra subnets (--extra-subnets) are passed through from the bastion for manual VLAN scanning.
    if [ -n "$EXTRA_SUBNETS" ]; then
        "$BIN" arp-scan --extra-subnets "$EXTRA_SUBNETS" 2>/dev/null || fail "sentineld arp-scan failed (exit $?)"
    else
        "$BIN" arp-scan 2>/dev/null || fail "sentineld arp-scan failed (exit $?)"
    fi
}

do_status() {
    # "installed" = the watcher service is installed (the unit file exists), NOT "the sentineld
    # binary exists". The binary is always present (it's the agent itself); installing the watcher
    # is the opt-in act this status reports. The dashboard shows an Enable button iff installed is
    # false -- measuring the binary here permanently misrendered the panel as "Enabled" with a
    # no-op Disable button (found live 2026-08-04: a fresh Linux box's enable click silently ran
    # disable). A missing binary still reads as "not installed" so the UI offers Enable, and
    # do_enable() independently fails hard on a missing binary.
    installed="false"
    [ -f "$WATCH_UNIT" ] && installed="true"
    systemd_state="inactive"
    if [ "$installed" = "true" ]; then
        systemd_state=$(systemctl is-active "$WATCH_SERVICE" 2>/dev/null) || true
        [ -n "$systemd_state" ] || systemd_state="inactive"
    fi
    active="false"
    [ "$systemd_state" = "active" ] && active="true"
    task_state="Stopped"
    [ "$active" = "true" ] && task_state="Running"

    heartbeat="null"
    if [ -f "$HEARTBEAT" ]; then
        hb=$(cat "$HEARTBEAT" 2>/dev/null || true)
        case "$hb" in
            \{*) heartbeat=$hb ;;
        esac
    fi

    queue_length=0
    if [ -f "$QUEUE" ]; then
        queue_length=$(grep -o '"mac"' "$QUEUE" 2>/dev/null | wc -l)
    fi

    printf '{"ok":true,"installed":%s,"active":%s,"systemd_state":"%s","taskState":"%s","heartbeat":%s,"queueLength":%s}\n' \
        "$installed" "$active" "$(json_escape "$systemd_state")" "$task_state" "$heartbeat" "$queue_length"
}

do_enable() {
    [ -x "$BIN" ] || fail "sentineld binary not installed at $BIN"
    ensure_state_dir

    # Watcher service (created on enable, removed on disable) — the Linux analog of the Windows
    # SentinelArpSweepWatch SYSTEM AtStartup task (reboot persistence + RestartCount self-heal).
    cat > "$WATCH_UNIT" <<UNIT_EOF
[Unit]
Description=Sentinel Remote Assist ARP sweep detection watcher
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$BIN arp-sweep-watch
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl daemon-reload
    systemctl enable --now "$WATCH_SERVICE" >/dev/null 2>&1 || fail "failed to enable $WATCH_SERVICE"

    # Read-after-write like the Windows register script: confirm the unit is actually active,
    # not just assumed — a daemon-reload/systemctl hiccup must surface as a real error, not a
    # silent false "enabled".
    if ! systemctl is-active --quiet "$WATCH_SERVICE" 2>/dev/null; then
        fail "unit registered but service is not active"
    fi

    do_status
}

do_disable() {
    if systemctl is-active --quiet "$WATCH_SERVICE" 2>/dev/null; then
        systemctl stop "$WATCH_SERVICE" >/dev/null 2>&1 || true
    fi
    systemctl disable "$WATCH_SERVICE" >/dev/null 2>&1 || true
    rm -f "$WATCH_UNIT"
    systemctl daemon-reload
    # Remove the on-box state (queue + heartbeat) like the Windows unregister script's
    # Remove-Item of the whole arpsweep dir.
    rm -rf "$STATE_DIR"
    do_status
}

# Drains (reads THEN CLEARS) the on-box sweep queue — not idempotent, deliberately not folded
# into the read-only status action. Heartbeat rides along so the caller can tell "watch running
# but network quiet" apart from "watch not running" even on a drain that returns zero events.
# Same contract as the Windows _ARP_SWEEP_DRAIN_PS1: {ok, events:[...], heartbeat}.
do_drain() {
    events="[]"
    if [ -f "$QUEUE" ]; then
        events=$(read_queue)
        rm -f "$QUEUE"
    fi
    heartbeat="null"
    if [ -f "$HEARTBEAT" ]; then
        hb=$(cat "$HEARTBEAT" 2>/dev/null || true)
        case "$hb" in
            \{*) heartbeat=$hb ;;
        esac
    fi
    printf '{"ok":true,"events":%s,"heartbeat":%s}\n' "$events" "$heartbeat"
}

case "$ACTION" in
    scan)      do_scan ;;
    status)    do_status ;;
    enable)    do_enable ;;
    disable)   do_disable ;;
    drain)     do_drain ;;
    *) fail "unknown action: $ACTION (expected scan|status|enable|disable|drain)" ;;
esac
