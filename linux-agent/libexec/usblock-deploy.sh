#!/bin/sh
# Linux USB Lockdown — the USBGuard counterpart to the Windows USB Lockdown feature. Root
# wrapper invoked via a narrowly-scoped sudo rule (see install.sh's /etc/sudoers.d/sentinel-
# remote-assist entry), same pattern as appcontrol-deploy.sh/self-update.sh.
#
# USBGuard is a userspace daemon that authorizes/deauthorizes USB devices at the kernel level
# (uevent-based): a device that does not match an `allow` rule in /etc/usbguard/rules.conf and is
# not covered by the daemon's ImplicitPolicyTarget gets DEAUTHORIZED — the kernel refuses to
# activate it, so the OS never even enumerates it. That is the closest real Linux equivalent to
# the Windows GP AllowDeviceIDs allowlist, without any registry policy machinery:
#
#   - Enforce mode  -> ImplicitPolicyTarget=block: only devices with an allow rule (regenerated
#     from the CURRENTLY ATTACHED devices on every enable) are usable; anything newly plugged is
#     blocked on the spot.
#   - Audit mode    -> ImplicitPolicyTarget=allow: same rules.conf generated, but any non-matching
#     new device is auto-ALLOWED (tracked, never blocked) — the analog of fapolicyd's permissive
#     flag / AppLocker's Audit Only. Nothing is ever blocked in this mode.
#
# ⚠️ INPUT-DEVICE SAFETY NET (2026-08-07 hardened): HID devices (keyboards, mice, pointing
# devices — bInterfaceClass=03) that are ALREADY in the persisted approved list get an
# unconditional allow rule. New/unapproved HID devices (including Rubber Ducky, Bash Bunny,
# etc.) are NOT auto-allowed — they require manual approval via the dashboard. This prevents
# attack devices that present as HID keyboards from slipping through while still allowing
# previously-approved input devices across disable/re-enable cycles.
#
# PERSISTED APPROVALS (2026-08-05): approvals recorded via the `approve` action are remembered
# in $STATE_DIR/approved.txt as `vid:pid|friendly-name` entries (the name is a durable
# convenience for the WebUI — see do_approved) and re-applied on EVERY enable. Without
# this, an approved device that is unplugged at enable time gets re-blocked the moment it is
# plugged back in — do_enable regenerates rules.conf from the CURRENTLY ATTACHED devices only
# (reset-first), which wipes the rule `allow-device -p` persisted. USBGuard renumbers device ids
# on re-enumeration, so ids are useless across replugs; vid:pid is the same granularity the rest
# of the policy (generate-policy output, the input safety net) already uses.
#
# The on-device watcher is a long-running systemd service (sentinel-usblock-watch.service,
# created on enable / removed on disable — the Linux analog of the Windows Sentinel-UsbLockdownWatch
# scheduled task): it scans `usbguard list-devices` every 30s and writes one JSONL event per
# newly-blocked device to /var/lib/sentinel-ra/usblock-outbox/, which the server-side worker
# poller drains via the bastion /usblock/drain endpoint (same contract as the Windows outbox).
set -eu

CONF=/etc/usbguard/usbguard-daemon.conf
RULES=/etc/usbguard/rules.conf
ACTION="${1:-status}"

STATE_DIR=/var/lib/sentinel-ra/usblock
OUTBOX=/var/lib/sentinel-ra/usblock-outbox
HEARTBEAT="$STATE_DIR/watcher_heartbeat.json"
SEEN_FILE="$STATE_DIR/seen.txt"
WATCH_SERVICE=sentinel-usblock-watch.service
WATCH_UNIT=/etc/systemd/system/$WATCH_SERVICE

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

ensure_installed() {
    command -v usbguard >/dev/null 2>&1 && return 0
    # Distro dispatch: the live Linux RA fleet is Debian/Ubuntu (apt) but real customer boxes
    # include Arch (this project's own desktop is Omarchy/Arch) and Fedora-family hosts. usbguard
    # ships in all three distros' main repos, so installation is a package-manager pick, not a
    # build-from-source problem.
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq || fail "apt-get update failed"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq usbguard || fail "apt-get install usbguard failed"
    elif command -v pacman >/dev/null 2>&1; then
        # Try the existing sync DB first (no partial-upgrade risk); fall back to a single -Sy
        # refresh only if the package isn't in the stale DB. Deliberately NOT -Syu — an agent
        # button must never silently full-upgrade a rolling-release host.
        pacman -S --noconfirm --needed usbguard >/dev/null 2>&1 \
            || pacman -Sy --noconfirm --needed usbguard >/dev/null 2>&1 \
            || fail "pacman install usbguard failed"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q usbguard || fail "dnf install usbguard failed"
    else
        fail "usbguard is not installed and no supported package manager (apt-get/pacman/dnf) was found"
    fi
}

# Same flat `key = value` setter as appcontrol-deploy.sh's set_conf() — usbguard-daemon.conf is
# a flat key = value file, so an anchored sed/grep is safe.
set_conf() {
    key="$1"; val="$2"
    if [ -f "$CONF" ] && grep -qE "^${key}[[:space:]]*=" "$CONF"; then
        sed -i "s|^${key}[[:space:]]*=.*|${key}=${val}|" "$CONF"
    else
        echo "${key}=${val}" >> "$CONF"
    fi
}

# Parses one `usbguard list-devices` line into $LINE_ID / $LINE_STATUS / $LINE_NAME / $LINE_PORT
# (+ $LINE_VPID, the `id <vid>:<pid>` token). Format (verified live 2026-08-01):
# `12: allow id 1d6b:0002 serial "..." name "Usb KeyBoard" ...`
# — note `name` and the value are space-separated, NOT `name="..."` (that's the rules.conf format).
# via-port is the kernel port path (e.g. "4-2.3") — the sysfs handle used by the reprobe action.
parse_line() {
    LINE_ID=$(printf '%s' "$1" | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    LINE_STATUS=$(printf '%s' "$1" | sed -n 's/^[0-9][0-9]*:[[:space:]]*\([a-z][a-z]*\).*/\1/p')
    LINE_NAME=$(printf '%s' "$1" | sed -n 's/.*name[[:space:]]*"\([^"]*\)".*/\1/p')
    LINE_PORT=$(printf '%s' "$1" | sed -n 's/.*via-port[[:space:]]*"\([^"]*\)".*/\1/p')
    LINE_VPID=$(printf '%s' "$1" | sed -n 's/.*id[[:space:]]*\([0-9a-fA-F][0-9a-fA-F]*:[0-9a-fA-F][0-9a-fA-F]*\).*/\1/p')
}

# Current policy outcome as reported by the daemon: "block" (enforce) / "allow" (audit) / "" (daemon
# not running). Read from the conf file — the daemon applies it at (re)start.
conf_mode() {
    if [ -f "$CONF" ]; then
        case "$(grep -E '^ImplicitPolicyTarget[[:space:]]*=' "$CONF" 2>/dev/null | tail -1 | sed 's/.*=//')" in
            allow) echo "Audit" ;;
            *)     echo "Enforce" ;;
        esac
    else
        echo "Enforce"
    fi
}

# ⚠️ User-mandated safety net: HID devices (keyboards, mice, pointing devices —
# bInterfaceClass=03) that are ALREADY in the persisted approved list get an unconditional
# allow rule. New/unapproved HID devices (including Rubber Ducky, Bash Bunny, etc.) are NOT
# auto-allowed — they require manual approval via the dashboard. This prevents attack devices
# that present as HID keyboards from slipping through while still allowing previously-approved
# input devices across disable/re-enable cycles.
ensure_input_allowed() {
    added=0
    # Build a set of already-approved vid:pid values
    approved_vpids=""
    if [ -f "$STATE_DIR/approved.txt" ]; then
        while IFS= read -r entry; do
            vp=${entry%%|*}
            case "$vp" in *:*) approved_vpids="$approved_vpids $vp" ;; esac
        done < "$STATE_DIR/approved.txt"
    fi
    for iface in /sys/bus/usb/devices/*:*/bInterfaceClass; do
        [ -f "$iface" ] || continue
        [ "$(cat "$iface" 2>/dev/null)" = "03" ] || continue
        base=$(dirname "$iface")
        iface_dir=$(dirname "$base")
        vid=$(cat "$iface_dir/idVendor" 2>/dev/null || true)
        pid=$(cat "$iface_dir/idProduct" 2>/dev/null || true)
        [ -n "$vid" ] && [ -n "$pid" ] || continue
        vpid="${vid}:${pid}"
        # Only auto-allow if this vid:pid was previously approved via the dashboard
        case " $approved_vpids " in *" $vpid "*) ;; *) continue ;; esac
        if ! grep -qE "^allow[[:space:]]*id[[:space:]]*${vpid}([[:space:]]|\$)" "$RULES" 2>/dev/null; then
            echo "# sentinel input-device safety net (always-allowed)" >> "$RULES"
            echo "allow id ${vid}:${pid}" >> "$RULES"
            added=$((added + 1))
        fi
    done
    echo "$added"
}

# Watcher outbox dir — mirrors the Windows outbox contract (event_*.json, drained/ subdir).
ensure_state_dirs() {
    mkdir -p "$STATE_DIR" "$OUTBOX" "$OUTBOX/drained"
}

do_status() {
    installed="false"; command -v usbguard >/dev/null 2>&1 && installed="true"
    systemd_state="inactive"
    if [ "$installed" = "true" ]; then
        systemd_state=$(systemctl is-active usbguard 2>/dev/null) || true
        [ -n "$systemd_state" ] || systemd_state="inactive"
    fi
    active="false"
    [ "$systemd_state" = "active" ] && active="true"

    mode=""
    if [ "$active" = "true" ]; then
        mode=$(conf_mode)
    fi

    devices=""
    device_count=0
    blocked_count=0
    if [ "$active" = "true" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            parse_line "$line"
            case "$LINE_STATUS" in
                allow)
                    device_count=$((device_count + 1))
                    [ -z "$devices" ] && devices="${LINE_ID}" || devices="${devices} ${LINE_ID}"
                    ;;
                block|reject) blocked_count=$((blocked_count + 1)) ;;
            esac
        done <<EOF
$(usbguard list-devices 2>/dev/null || true)
EOF
    fi

    printf '{"ok":true,"installed":%s,"active":%s,"systemd_state":"%s","mode":"%s","deviceCount":%s,"blockedCount":%s,"deploying":false,"devices":[' \
        "$installed" "$active" "$(json_escape "$systemd_state")" "$mode" "$device_count" "$blocked_count"
    first=1
    for id in $devices; do
        # Re-list just to grab each allowed device's friendly name (list-devices is one cheap IPC
        # round trip; the status view is not hot-path).
        line=$(usbguard list-devices 2>/dev/null | grep -E "^${id}:" | head -1 || true)
        parse_line "$line"
        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        printf '{"friendlyName":"%s","instanceId":"%s","class":""}' \
            "$(json_escape "$LINE_NAME")" "$id"
    done
    printf ']}\n'
}

do_enable() {
    target="$1"  # "Audit" or "Enforce"
    ensure_installed
    ensure_state_dirs

    # Reset-first on every enable (same discipline as the Windows deploy): the allowlist is
    # regenerated from the CURRENTLY attached devices, so devices that have since been unplugged
    # drop out and everything present is (re)covered. Previously-approved HID devices are
    # re-allowed via the safety net; new/unapproved HID devices require manual dashboard approval.
    policy=$(usbguard generate-policy 2>/dev/null) || fail "usbguard generate-policy failed"
    if [ -z "$policy" ]; then
        # A box with nothing attached at all: a bare allow-all would silently keep everything
        # usable — instead fail loudly so nobody mistakes an empty policy for a real lockdown.
        fail "generate-policy produced an empty rule set (is this machine headless?)"
    fi
    printf '%s\n' "$policy" > "$RULES"

    # Input-device safety net — only re-allows previously-approved HID devices (see doc comment).
    ensure_input_allowed >/dev/null

    # Persisted approvals — re-apply every previously approved device (by vid:pid) on every
    # enable, so approvals survive disable/re-enable (the regenerated policy above only covers
    # devices attached right now). Skip anything the fresh policy already allows; a stale
    # vid:pid (device long gone) is a harmless no-op rule. See top-of-file doc comment.
    if [ -f "$STATE_DIR/approved.txt" ]; then
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            # Entries are `vid:pid|name` — only the vid:pid feeds the policy rule.
            vp=${entry%%|*}
            case "$vp" in
                *:*) ;;
                *) continue ;;
            esac
            grep -qE "^allow[[:space:]]*id[[:space:]]*${vp}([[:space:]]|\$)" "$RULES" 2>/dev/null && continue
            echo "# sentinel persisted approval (re-applied on every enable)" >> "$RULES"
            echo "allow id ${vp}" >> "$RULES"
        done < "$STATE_DIR/approved.txt"
    fi

    # Track the target mode in the conf file BEFORE the restart below applies it.
    if [ "$target" = "Audit" ]; then
        set_conf "ImplicitPolicyTarget" "allow"
    else
        set_conf "ImplicitPolicyTarget" "block"
    fi

    systemctl enable usbguard >/dev/null 2>&1 || true
    # --no-block for parity with appcontrol-deploy.sh: the daemon start is fast (rules load in
    # ms), but a synchronous restart that ever blocks would blow this action's Hop-2 budget.
    systemctl restart --no-block usbguard || fail "failed to schedule usbguard restart"

    # Watcher service (created on enable, removed on disable) — the Linux analog of the Windows
    # Sentinel-UsbLockdownWatch scheduled task. A long-running loop is a better fit here than a
    # timer: it scans list-devices continuously and writes outbox events as blocks actually happen.
    cat > "$WATCH_UNIT" <<UNIT_EOF
[Unit]
Description=Sentinel Remote Assist USB Lockdown watcher
After=usbguard.service
[Service]
Type=simple
ExecStart=/usr/local/libexec/sentinel-ra/usblock-deploy.sh watch
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
UNIT_EOF
    systemctl daemon-reload
    systemctl enable --now "$WATCH_SERVICE" >/dev/null 2>&1 || true

    do_status
}

do_disable() {
    if systemctl is-active --quiet "$WATCH_SERVICE" 2>/dev/null; then
        systemctl stop "$WATCH_SERVICE" >/dev/null 2>&1 || true
    fi
    systemctl disable "$WATCH_SERVICE" >/dev/null 2>&1 || true
    rm -f "$WATCH_UNIT"
    systemctl daemon-reload

    if command -v usbguard >/dev/null 2>&1; then
        systemctl disable usbguard >/dev/null 2>&1 || true
        systemctl stop usbguard >/dev/null 2>&1 || true
        # usbguard-dbus has Requires=usbguard.service — left enabled it fails at every boot
        # once the daemon is off (the failed-unit noise from the 2026-08-09 `allow all`
        # incident). Disable it in lockstep so "off" is truly off.
        systemctl disable usbguard-dbus >/dev/null 2>&1 || true
        systemctl stop usbguard-dbus >/dev/null 2>&1 || true
        # Reset the policy file to allow-all so a stray manual `systemctl start usbguard` (or a
        # reboot with the daemon re-enabled by hand) can never silently re-block anything.
        echo "allow" > "$RULES"
    fi
    do_status
}

# Per-device approve — the Linux counterpart to the Windows approve flow. usbguard's device id
# (the number in `usbguard list-devices`) is what the dashboard's Refresh & Approve hands over;
# `allow-device -p` authorizes it immediately AND persists an allow rule into rules.conf so it
# survives daemon restarts/reboots. Additionally the device's vid:pid is recorded in
# $STATE_DIR/approved.txt so the approval ALSO survives a disable/re-enable cycle — do_enable
# regenerates rules.conf from currently-attached devices only, which would otherwise silently
# un-approve a device that isn't plugged in at enable time (found live 2026-08-05).
do_approve() {
    id="$2"
    if [ -z "$id" ] || ! printf '%s' "$id" | grep -qE '^[0-9]+$'; then
        fail "approve requires a numeric usbguard device id"
    fi
    out=$(usbguard allow-device -p "$id" 2>&1) || fail "usbguard allow-device failed: $(json_escape "$out")"
    line=$(usbguard list-devices 2>/dev/null | grep -E "^${id}:" | head -1 || true)
    parse_line "$line"
    if [ -n "$LINE_VPID" ]; then
        ensure_state_dirs
        [ -f "$STATE_DIR/approved.txt" ] || : > "$STATE_DIR/approved.txt"
        # Lines are `vid:pid|friendly-name` — the name is a durable convenience for the WebUI's
        # persisted-approvals card (devices are usually UNPLUGGED when viewed, so a live name
        # lookup is empty; the name captured at approve time is the reliable one).
        grep -qE "^${LINE_VPID}(\||\$)" "$STATE_DIR/approved.txt" 2>/dev/null || echo "${LINE_VPID}|${LINE_NAME}" >> "$STATE_DIR/approved.txt"
    fi
    printf '{"ok":true,"instanceId":"%s","vidPid":"%s"}\n' "$id" "$LINE_VPID"
}

# List the persisted approvals (approved.txt) — the devices that get re-allowed on every enable.
# Entries are `vid:pid|name`; the name captured at approve time is returned, but a LIVE name from
# list-devices wins when the device happens to be attached (it may be fresher than what was
# recorded). This is the Linux-only complement of the server-side Approval History (which is
# bookkeeping; THIS is the actual allowlist source).
do_approved() {
    ensure_state_dirs
    printf '{"ok":true,"approvals":['
    first=1
    if [ -f "$STATE_DIR/approved.txt" ]; then
        while IFS= read -r entry; do
            [ -n "$entry" ] || continue
            vp=${entry%%|*}
            stored_name=${entry#*|}
            [ "$stored_name" = "$entry" ] && stored_name=""
            name="$stored_name"
            vpline=$(usbguard list-devices 2>/dev/null | grep -E "[[:space:]]id[[:space:]]*${vp}([[:space:]]|\$)" | head -1 || true)
            if [ -n "$vpline" ]; then
                parse_line "$vpline"
                [ -n "$LINE_NAME" ] && name="$LINE_NAME"
            fi
            if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
            printf '{"vidPid":"%s","friendlyName":"%s"}' "$vp" "$(json_escape "$name")"
        done < "$STATE_DIR/approved.txt"
    fi
    printf ']}\n'
}

# Un-approve a persisted device (the dashboard's per-entry Remove button): drop the vid:pid from
# approved.txt, strip its allow rules from rules.conf, and remove the live rules from the daemon
# so an attached device is deauthorized immediately. Refuses HID devices — the input safety net
# re-allows them at the next enable anyway, and deauthorizing a live keyboard/mouse is never
# wanted (same doctrine as do_reprobe).
do_remove() {
    vp="$2"
    if [ -z "$vp" ] || ! printf '%s' "$vp" | grep -qE '^[0-9a-fA-F]{4}:[0-9a-fA-F]{4}$'; then
        fail "remove requires a vid:pid (vendor:product, XXXX:XXXX)"
    fi
    ensure_state_dirs
    vp_lower=$(printf '%s' "$vp" | tr 'A-F' 'a-f')
    for iface in /sys/bus/usb/devices/*:*/bInterfaceClass; do
        [ -f "$iface" ] || continue
        [ "$(cat "$iface" 2>/dev/null)" = "03" ] || continue
        base=$(dirname "$iface")
        iface_dir=$(dirname "$base")
        vid=$(cat "$iface_dir/idVendor" 2>/dev/null || true)
        pid=$(cat "$iface_dir/idProduct" 2>/dev/null || true)
        [ -n "$vid" ] && [ -n "$pid" ] || continue
        if [ "$(printf '%s:%s' "$vid" "$pid" | tr 'A-F' 'a-f')" = "$vp_lower" ]; then
            fail "device $vp is an input device (keyboard/mouse) — refusing to remove"
        fi
    done
    if [ -f "$STATE_DIR/approved.txt" ]; then
        # Lines may carry a `|name` suffix — strip it so the vid:pid comparison is exact.
        sed -i -E "/^${vp_lower}(\||\$)/Id" "$STATE_DIR/approved.txt" || true
    fi
    if [ -f "$RULES" ]; then
        sed -i -E "/^allow[[:space:]]*id[[:space:]]*${vp}([[:space:]]|\$)/Id" "$RULES" || true
    fi
    removed=0
    while IFS= read -r rline; do
        [ -n "$rline" ] || continue
        rid=$(printf '%s' "$rline" | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
        [ -n "$rid" ] || continue
        rvp=$(printf '%s' "$rline" | sed -n 's/.*[[:space:]]allow[[:space:]]*id[[:space:]]*\([0-9a-fA-F][0-9a-fA-F]*:[0-9a-fA-F][0-9a-fA-F]*\).*/\1/p')
        if [ -n "$rvp" ] && [ "$(printf '%s' "$rvp" | tr 'A-F' 'a-f')" = "$vp_lower" ]; then
            usbguard remove-rule "$rid" >/dev/null 2>&1 && removed=$((removed + 1))
        fi
    done <<EOF
$(usbguard list-rules 2>/dev/null || true)
EOF
    printf '{"ok":true,"vidPid":"%s","removedRules":%s}\n' "$vp" "$removed"
}

# Software replug for an already-allowed device whose drivers never bound. The classic Linux
# USBGuard quirk: a device plugged in WHILE blocked gets deauthorized at the kernel level, so
# usb-storage never binds and no block device appears — approving it later only flips usbguard's
# authorization, the kernel does NOT re-run enumeration for an already-connected device. Toggling
# the sysfs `authorized` flag (0 → 1) is the driver-free equivalent of unplugging and replugging:
# the kernel re-enumerates the port, the persisted allow rule from the approve makes usbguard
# re-authorize it, and the storage driver binds (→ /dev/sdX appears in the file manager).
# ⚠️ Input-device safety net: devices exposing a HID interface (bInterfaceClass=03 — keyboards,
# mice, pointing devices) are REFUSED here — the operator's input is never toggled.
do_reprobe() {
    id="$2"
    if [ -z "$id" ] || ! printf '%s' "$id" | grep -qE '^[0-9]+$'; then
        fail "reprobe requires a numeric usbguard device id"
    fi
    line=$(usbguard list-devices 2>/dev/null | grep -E "^${id}:" | head -1 || true)
    [ -n "$line" ] || fail "no usbguard device with id $id"
    parse_line "$line"
    [ -n "$LINE_PORT" ] || fail "no via-port for device $id (is it still connected?)"

    # Never touch input devices — the human in front of the box stays in control.
    for iface in /sys/bus/usb/devices/${LINE_PORT}:*/bInterfaceClass; do
        [ -f "$iface" ] || continue
        if [ "$(cat "$iface" 2>/dev/null)" = "03" ]; then
            fail "device $id is an input device (keyboard/mouse) — refusing to reprobe"
        fi
    done

    devdir="/sys/bus/usb/devices/$LINE_PORT"
    [ -d "$devdir" ] || fail "sysfs path $devdir missing for device $id"

    echo 0 > "$devdir/authorized" 2>/dev/null || fail "failed to deauthorize device $id"
    sleep 1
    echo 1 > "$devdir/authorized" 2>/dev/null || fail "failed to re-authorize device $id"
    sleep 3

    # Report the device's post-reprobe status (allow = usbguard re-authorized it via the
    # persisted allow rule; the kernel driver binding follows).
    line2=$(usbguard list-devices 2>/dev/null | grep -E "^${id}:" | head -1 || true)
    status2=""
    [ -n "$line2" ] && parse_line "$line2" && status2="$LINE_STATUS"
    printf '{"ok":true,"instanceId":"%s","viaPort":"%s","status":"%s"}\n' "$id" "$LINE_PORT" "$status2"
}

do_blocked() {
    devices=""
    count=0
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        parse_line "$line"
        case "$LINE_STATUS" in
            block|reject)
                count=$((count + 1))
                [ -z "$devices" ] && devices="${LINE_ID}" || devices="${devices} ${LINE_ID}"
                ;;
        esac
    done <<EOF
$(usbguard list-devices 2>/dev/null || true)
EOF
    printf '{"ok":true,"count":%s,"devices":[' "$count"
    first=1
    for id in $devices; do
        line=$(usbguard list-devices 2>/dev/null | grep -E "^${id}:" | head -1 || true)
        parse_line "$line"
        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        printf '{"friendlyName":"%s","instanceId":"%s","class":"USB","problem":"blocked by policy"}' \
            "$(json_escape "$LINE_NAME")" "$id"
    done
    printf ']}\n'
}

# Long-running watcher loop (systemd service, see do_enable). Polls list-devices every 30s and
# writes one event_*.json per NEWLY blocked device — deduped via the seen file so a device that
# stays blocked doesn't re-alert every 30s (same semantics as the Windows watcher's event files).
do_watch() {
    ensure_state_dirs
    touch "$SEEN_FILE"
    while true; do
        ts=$(date +%s 2>/dev/null || echo 0)
        ms=$((ts * 1000))
        while IFS= read -r line; do
            [ -n "$line" ] || continue
            parse_line "$line"
            case "$LINE_STATUS" in
                block|reject)
                    grep -qx "$LINE_ID" "$SEEN_FILE" 2>/dev/null && continue
                    printf '{"friendlyName":"%s","instanceId":"%s","class":"USB","problem":"blocked by policy","ts":%s}\n' \
                        "$(json_escape "$LINE_NAME")" "$LINE_ID" "$ms" \
                        > "$OUTBOX/event_${ts}_${LINE_ID}.json" || true
                    echo "$LINE_ID" >> "$SEEN_FILE"
                    ;;
            esac
        done <<EOF
$(usbguard list-devices 2>/dev/null || true)
EOF
        printf '{"ts":%s}\n' "$ms" > "$HEARTBEAT" 2>/dev/null || true
        sleep 30
    done
}

# Drain the watcher outbox — read every event file, return them, then move them to drained/
# (same read-and-clear contract as the Windows drain; the server worker alerts on the events).
do_drain() {
    ensure_state_dirs
    printf '{"ok":true,"events":['
    first=1
    for f in "$OUTBOX"/event_*.json; do
        [ -f "$f" ] || continue
        data=$(cat "$f" 2>/dev/null || true)
        [ -n "$data" ] || continue
        if [ "$first" -eq 1 ]; then first=0; else printf ','; fi
        printf '%s' "$data"
        mv -f "$f" "$OUTBOX/drained/" 2>/dev/null || true
    done
    printf ']}\n'
}

case "$ACTION" in
    status)        do_status ;;
    enable-audit)  do_enable Audit ;;
    enable-enforce) do_enable Enforce ;;
    disable)       do_disable ;;
    approve)       do_approve "$@" ;;
    approved)      do_approved ;;
    remove)        do_remove "$@" ;;
    reprobe)       do_reprobe "$@" ;;
    blocked)       do_blocked ;;
    watch)         do_watch ;;
    drain)         do_drain ;;
    *) fail "unknown action: $ACTION (expected status|enable-audit|enable-enforce|disable|approve|approved|remove|reprobe|blocked|watch|drain)" ;;
esac
