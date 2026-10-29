#!/bin/sh
# Linux Application Control — the fapolicyd counterpart to the Windows AppLocker feature. Root
# wrapper invoked via a narrowly-scoped sudo rule (see install.sh's /etc/sudoers.d/sentinel-
# remote-assist entry), same pattern as self-update.sh/it-audit.
#
# fapolicyd is a default-deny execute-allowlisting daemon (fanotify-based) — the closest real
# Linux equivalent to AppLocker's actual behavior, unlike AppArmor/SELinux (per-profile mandatory
# access control, a different model entirely). Two trust sources matter here:
#   - The distro's own package database (every file a package manager installed is "trusted" —
#     mirrors AppLocker's %WINDIR%/%PROGRAMFILES% path-based trust, just verified by hash instead
#     of by path). fapolicyd defaults to `trust = rpmdb,file` (Fedora/RHEL-centric); on a
#     dpkg-based system there is no rpmdb, so this script explicitly sets `trust = debdb,file`
#     instead — see the doc comment on that config line below for why this matters. ⚠️ NOT
#     "dpkgdb" — that was an incorrect guess (no such backend exists in this build) that produced
#     a hard, silent-to-the-dashboard "dpkgdb backend not supported, aborting!" failure, found
#     live 2026-07-29 by fetching fapolicyd's OWN startup log via the events action and by
#     `strings /usr/sbin/fapolicyd | grep -i debdb` confirming the real compiled-in backend name
#     (the upstream man page is stale and only documents rpmdb/file — it doesn't mention this
#     Debian-specific backend at all, so the binary's own strings were the authoritative source).
#   - `/etc/fapolicyd/trust.d/*.trust` (path + size + sha256 lines) for anything installed
#     OUTSIDE the package manager (matches AppLocker's "each approved app path" allow-rules).
#
# Audit vs Enforce is fapolicyd's own `permissive` config flag — NOT a separate mechanism to
# build: permissive=1 logs every would-be denial but allows execution anyway (identical intent to
# AppLocker's "Audit Only" mode); permissive=0 is real enforcement.
set -eu

CONF=/etc/fapolicyd/fapolicyd.conf
ACTION="${1:-status}"

json_escape() {
    # Minimal JSON string escaping for values that only ever come from our own trusted
    # config/package data (not arbitrary attacker input) — backslash, double-quote, and control
    # chars are the only things that matter here.
    #
    # ⚠️ Found live 2026-07-29: real fapolicyd log lines carry ANSI color escape sequences (e.g.
    # ESC[33mWARNING ESC[0m) — a raw ESC (0x1b) byte inside a JSON string is invalid per spec, and
    # Python's strict json.loads() rejected the WHOLE events response over it, surfacing as an
    # opaque "unparseable output" error even though the events fetch itself worked fine. Strip
    # recognizable ANSI sequences first (harmless — this feeds a plain-text log viewer, not a
    # terminal), then strip every other raw control byte except newline (\012 octal / decimal 10),
    # which the awk/sed pair below still needs intact to convert into a literal `\n` escape.
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
    if ! command -v fapolicyd >/dev/null 2>&1; then
        # Distro dispatch: fapolicyd ships in Debian/Ubuntu, Arch and Fedora main repos. This was
        # hardcoded to apt-get, so on a non-Debian host (Arch/Omarchy — this project's own desktop)
        # the install step died at `apt-get: not found`, surfacing as "apt-get update failed".
        # Mirrors usblock-deploy.sh's ensure_installed() dispatch exactly — same three-way pick,
        # same deliberate -Syu avoidance (an agent button must never silently full-upgrade a
        # rolling-release host).
        if command -v apt-get >/dev/null 2>&1; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq || fail "apt-get update failed"
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fapolicyd || fail "apt-get install fapolicyd failed"
        elif command -v pacman >/dev/null 2>&1; then
            # ⚠️ fapolicyd is NOT in any official Arch repository (checked against `extra` on
            # 2026-09-30: zero matches across 29,908 packages). Both attempts below therefore
            # cannot succeed on Arch and the failure is expected, not transient.
            #
            # We deliberately do NOT fall back to an AUR helper. The one AUR fapolicyd package
            # (2.0.1-1, submitted 2026-09-03) is unvetted (0 votes) and, on this exact desktop,
            # PROVEN BROKEN on install: its PKGBUILD never applies sysusers.d/tmpfiles.d (daemon
            # user and /var/lib/fapolicyd both missing afterwards), it ships upstream's
            # 22-buildroot.rules which trusts an RPM-only `mock` user Arch doesn't have, and it
            # never substitutes the %ld_so_path% placeholder in 43-known-elf.rules. Its source
            # tarball hash does match upstream exactly — the packaging, not the source, is the
            # problem. Compiling and running third-party PKGBUILD code as root-adjacent on an
            # admin's desktop to reach a default-deny security daemon is not a decision this
            # script gets to make on its own, so it fails closed and says why.
            if pacman -S --noconfirm --needed fapolicyd >/dev/null 2>&1; then
                :
            elif pacman -Sy --noconfirm --needed fapolicyd >/dev/null 2>&1; then
                :
            else
                fail "fapolicyd is not available in any official Arch repository, so App Control cannot be installed on this host. This script will not build it from the AUR automatically (the only AUR package is unvetted and installs broken on this exact desktop). No changes were made."
            fi
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q fapolicyd || fail "dnf install fapolicyd failed"
        else
            fail "fapolicyd is not installed and no supported package manager (apt-get/pacman/dnf) was found"
        fi
    fi
}

# Sets one `key = value` line in fapolicyd.conf, replacing an existing uncommented line for that
# key if present, else appending. fapolicyd.conf is a flat `key = value` file (no sections), so a
# simple anchored-key sed/grep is safe and doesn't risk corrupting unrelated settings.
set_conf() {
    key="$1"; val="$2"
    if [ -f "$CONF" ] && grep -qE "^${key}[[:space:]]*=" "$CONF"; then
        sed -i "s|^${key}[[:space:]]*=.*|${key} = ${val}|" "$CONF"
    else
        echo "${key} = ${val}" >> "$CONF"
    fi
}

# ⚠️ Found live 2026-08-05: a single corrupt line in a trust.d file silently broke EVERY
# `fapolicyd-cli --file add` on the box — the live sentinel-approved.trust carried a truncated
# bare `253a5bfd14f4d980812e0239cf9398fb35534f815` fragment (a substring of a real SHA256 from a
# first-run trust build that raced a file being regenerated mid-scan), and fapolicyd-cli parses
# the WHOLE file on every add, aborting with "Can't parse <hash>" (rc=1) for any valid input.
# Dashboard symptom: every approve/approve-many silently reported 0 approved while the daemon
# itself kept running fine — nothing told anyone the trust file was corrupt.
# This strips any line that isn't a v3-format `PATH SIZE SHA256` entry or a `#` comment/blank —
# a truncated/binary/random line can never contribute trust anyway, so dropping it is strictly
# a repair, and the atomic rewrite (tmp + mv) is safe against the daemon re-reading the file.
EXCLUDED_FOLDERS_FILE="/etc/fapolicyd/sentinel-excluded-folders.txt"

repair_trust_files() {
    for f in /etc/fapolicyd/trust.d/sentinel-approved.trust \
             /etc/fapolicyd/trust.d/sentinel-preexisting.trust \
             /etc/fapolicyd/trust.d/sentinel-infra.trust \
             /etc/fapolicyd/trust.d/sentinel-excluded-folders.trust; do
        [ -f "$f" ] || continue
        tmp="${f}.repair"
        # ⚠️⚠️ Found live 2026-09-30 (pre-existing, unrelated to the preflight work next door, but
        # discovered BY it): the original validity regex used an interval expression,
        # `$3 ~ /^[0-9a-fA-F]{64}$/`. Debian/Ubuntu's default awk is MAWK 1.3.4, which does not
        # support `{n}` interval expressions — it treats the braces literally, the regex matches
        # NOTHING, and this "repair" therefore rewrote every trust.d file down to EMPTY on every
        # Enable and Approve click on every dpkg host. The wipe was invisible only because
        # `trust = debdb,file` still covers apt-installed binaries, so the daemon kept working and
        # nothing looked wrong — while every APPROVED path, every sentinel-infra entry, and every
        # pre-existing-process trust entry was silently destroyed. A trust-repair routine that is
        # itself the most destructive thing in the file.
        # Fixed by testing the LENGTH explicitly instead of with an interval — `length($3) == 64`
        # plus a plain character-class match is portable across mawk, gawk and busybox awk.
        # Verified against both mawk 1.3.4 and gawk.
        awk '($0 ~ /^#/ || NF==0) || (NF==3 && $1 ~ /^\// && $2 ~ /^[0-9]+$/ && length($3) == 64 && $3 ~ /^[0-9a-fA-F]+$/) { print }' "$f" > "$tmp"
        mv -f "$tmp" "$f"
    done
}

# ── Pre-flight validation: prove the install is FUNCTIONAL before we ever start the daemon ────
# ⚠️⚠️ Found live 2026-09-30: this function exists because a hand-run `systemctl start fapolicyd`
# on the project's own Arch/Omarchy desktop HARD-FROZE the whole machine (90k+ "Operation not
# permitted" exec denials; systemd couldn't spawn executors, Docker couldn't fork/exec runc; the
# box needed a hard reset). Mechanism: an incomplete fapolicyd install left `trust = file` pointed
# at an EMPTY trust DB (5 lines in fapolicyd.trust, 0 files in trust.d/) while `permissive = 0`
# was in force — so the sample rules' `deny perm=execute all : all` catch-all denied execve() for
# every binary not in that 5-line file. systemd, runc and the compositor are all binaries. On
# dpkg/rpm hosts `trust = debdb,file`/`rpmdb,file` populates from the package DB and covers
# everything, which is exactly why this is invisible in the field and only bites hosts whose trust
# backend can never match anything.
#
# The lesson is NOT "don't start fapolicyd" — the daemon is fine once correctly installed. The
# lesson is that this script must never issue a restart on an install it has not first PROVEN
# good, because the failure mode is an unrecoverable box, not a failed action. Every check below
# is cheap and read-only; all of them must pass before do_enable() is allowed to schedule a
# restart. On failure we return a specific error and the daemon is never started.
preflight_check() {
    perm_wanted="$1"  # "1" = audit, "0" = enforce

    # 1. The service must actually exist. A package that installs binaries without a unit file
    #    (or a container/WSL box with no working systemd) can't be started at all.
    systemctl cat fapolicyd >/dev/null 2>&1 \
        || fail "fapolicyd is installed but has no systemd unit — cannot start it on this host"

    # 2. The daemon runs as a dedicated user/group. The AUR package ships a sysusers.d unit that
    #    Arch's post-transaction hook never applied (its PKGBUILD uses process substitution that
    #    silently installs nothing), so the user is simply absent and fagenrules dies with
    #    status=5/NOTINSTALLED — observed live. Create it rather than fail: the unit needs it,
    #    and this is exactly the repair the missing packaging should have done.
    if [ ! -e /etc/passwd ] || ! getent passwd fapolicyd >/dev/null 2>&1; then
        if getent group fapolicyd >/dev/null 2>&1; then
            useradd -r -g fapolicyd -d /var/lib/fapolicyd -s /usr/sbin/nologin \
                    -c "fapolicyd daemon user" fapolicyd >/dev/null 2>&1 || true
        else
            groupadd -r fapolicyd >/dev/null 2>&1 || true
            useradd -r -g fapolicyd -d /var/lib/fapolicyd -s /usr/sbin/nologin \
                    -c "fapolicyd daemon user" fapolicyd >/dev/null 2>&1 || true
        fi
        getent passwd fapolicyd >/dev/null 2>&1 \
            || fail "fapolicyd daemon user/group could not be created — refusing to start (an incomplete install wedges the box)"
    fi

    # 3. The state directory must exist and be owned by the daemon user. Same root cause as (2):
    #    the package's tmpfiles.d entry never ran, and without /var/lib/fapolicyd the daemon
    #    aborts on startup with "Failed writing db version" (observed live) — after fagenrules
    #    has already succeeded, so it is NOT caught by check 4 alone.
    if [ ! -d /var/lib/fapolicyd ]; then
        mkdir -p /var/lib/fapolicyd 2>/dev/null || true
        chown fapolicyd:fapolicyd /var/lib/fapolicyd 2>/dev/null || true
        chmod 0700 /var/lib/fapolicyd 2>/dev/null || true
    fi
    [ -d /var/lib/fapolicyd ] \
        || fail "/var/lib/fapolicyd is missing and could not be created — refusing to start"

    # 4. THE decisive check: run the same rule-compilation step the unit's ExecStartPre runs, and
    #    refuse to start if it fails. This is what actually catches a broken/partial install —
    #    on Arch it fails with "user mock is unknown" (22-buildroot.rules trusts an RPM-only
    #    build-isolation user) and "cannot obtain set name from 'ld_so_path%'"
    #    (43-known-elf.rules ships an unsubstituted %ld_so_path% placeholder that upstream's own
    #    install scripts normally sed-replace). Both were hit live; both leave the daemon in a
    #    restart loop. Rules are compiled, NOT loaded (--check), so this cannot itself wedge the
    #    box, and it needs no daemon running.
    if ! fagenrules --check >/tmp/fapolicyd-preflight.err 2>&1; then
        rm -f /tmp/fapolicyd-preflight.err
        fail "fapolicyd's own rule compilation fails on this host (fagenrules --check) — the install is incomplete or has distro-specific sample rules this script doesn't handle. Refusing to start rather than risk wedging the box."
    fi
    rm -f /tmp/fapolicyd-preflight.err

    # 5. Enforce-only: refuse to arm default-deny unless the trust database actually covers
    #    something. This is the check that would have saved the 2026-09-30 freeze had the daemon
    #    been started in enforce mode with an empty trust source. Audit mode (permissive=1) can
    #    never block anything, so it is deliberately NOT gated on this — the whole point of audit
    #    mode is to observe what would break before you commit to breaking it.
    if [ "$perm_wanted" = "0" ]; then
        trust_entries=0
        if [ -d /etc/fapolicyd/trust.d ]; then
            for tf in /etc/fapolicyd/trust.d/*.trust; do
                [ -f "$tf" ] || continue
                # ⚠️ `n=$(grep -cv ... || echo 0)` is WRONG: grep -c prints "0" AND exits 1 on a
                # zero-match file, so the `|| echo 0` appends a SECOND 0 and n becomes "0\n0",
                # which dash then rejects as "Illegal number" and aborts the whole script —
                # found by the preflight regression suite (scenario E). Suppress only the exit
                # status, never synthesize the value.
                n=$(grep -cvE '^[[:space:]]*(#|$)' "$tf" 2>/dev/null) || true
                case "$n" in (''|*[!0-9]*) n=0 ;; esac
                trust_entries=$((trust_entries + n))
            done
        fi
        if [ -f /etc/fapolicyd/fapolicyd.trust ]; then
            n=$(grep -cvE '^[[:space:]]*(#|$)' /etc/fapolicyd/fapolicyd.trust 2>/dev/null) || true
            case "$n" in (''|*[!0-9]*) n=0 ;; esac
            trust_entries=$((trust_entries + n))
        fi
        [ "$trust_entries" -gt 0 ] \
            || fail "refusing to enable Enforce: the fapolicyd trust database is empty (0 entries). With default-deny active this denies exec() for every binary on the box and hard-freezes it. Enable Audit mode first, review what it would block, then switch to Enforce."
    fi
}

# Cheap probe for "is execve() being denied right now?". fapolicyd intercepts every exec/open
# synchronously via fanotify, so a denied exec surfaces as the shell reporting 126 (or EPERM).
# Used to DETECT a live wedge and roll back, not to predict one — preflight_check() is the
# predictive half. Tries several candidates and only reports failure if ALL are denied, because
# any single untrusted-path binary returning 126 must not be mistaken for a system-wide wedge.
exec_canary() {
    for probe in /bin/sh /usr/bin/sh /usr/bin/env /usr/bin/id; do
        [ -x "$probe" ] || continue
        if "$probe" -c ':' >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

configure_base() {
    ensure_installed
    repair_trust_files
    reapply_excluded_folders

    # ⚠️ Self-trust for our OWN infra (2026-07-30) — mirrors the Windows AppLocker deploy's
    # unconditional allow-list entry for its own ProgramData path. sentineld and every libexec
    # wrapper script are installed directly via `install`, NOT via apt/dpkg, so `trust = debdb,file`
    # never covers them — under Enforce mode fapolicyd's default-deny would block sentineld's own
    # NEXT exec (crash-restart, reboot, self-update cutover). The already-running process wouldn't
    # be killed, but Remote Assist's own control channel could get permanently stranded on this
    # exact box with no remote way to fix it. Add these to trust BEFORE any enable — including
    # Audit mode, so the trust entry is already in place the moment someone switches to Enforce.
    # fapolicyd-cli is idempotent here (safe to re-run on every Enable click).
    if command -v fapolicyd-cli >/dev/null 2>&1; then
        SENTINEL_INFRA_PATHS="/usr/local/bin/sentineld"
        for f in /usr/local/libexec/sentinel-ra/*.sh; do
            [ -f "$f" ] && SENTINEL_INFRA_PATHS="$SENTINEL_INFRA_PATHS $f"
        done
        for p in $SENTINEL_INFRA_PATHS; do
            fapolicyd-cli --file add "$p" --trust-file sentinel-infra.trust >/dev/null 2>&1 || true
        done
    fi
    # Trust-source selection is distro-dependent — fapolicyd has backends for the RPM database
    # (`rpmdb`) and the dpkg database (`debdb`) but NOTHING for pacman's libalpm/local DB, so a
    # hardcoded `debdb,file` silently under-trusts on Arch (see below).
    #
    # dpkg-based system: no RPM database exists at all, so fapolicyd's Fedora/RHEL-default
    # `trust = rpmdb,file` would treat the RPM half as permanently empty (harmless but useless)
    # while never recognizing ANY apt-installed package as trusted — every ordinary system binary
    # would then depend entirely on the sample allow-rules matching its path, which is fragile.
    # `debdb` is fapolicyd's dpkg-database-backed trust source for this case — see the top-of-file
    # doc comment for why it's "debdb" and not the more obviously-named "dpkgdb" this script used
    # in its first version (a wrong guess that hard-failed at startup).
    #
    # ⚠️ Arch/pacman (this project's own Omarchy desktop): there is NEITHER an rpmdb NOR a dpkg
    # database. Naming `debdb` there gives a trust source that can never match anything, and
    # `rpmdb` would behave the same way — so under Enforce (default-deny) every ordinary
    # pacman-installed binary would depend entirely on the sample allow-rules matching its path.
    # fapolicyd upstream has no pacman/alpm trust backend, so `file` (our own trust.d files) is
    # the only correct source here. That makes trust_running_processes() — the /proc scan already
    # run before every Enforce transition — the thing that actually covers the system, so on
    # Arch the existing "approve what breaks" loop is doing real work rather than being a
    # belt-and-braces extra.
    if command -v dpkg >/dev/null 2>&1; then
        set_conf "trust" "debdb,file"
    elif command -v rpm >/dev/null 2>&1; then
        set_conf "trust" "rpmdb,file"
    else
        set_conf "trust" "file"
    fi

    # ⚠️ Found live 2026-07-29 (same day, right after the debdb fix above worked): fapolicyd's
    # own default `db_max_size` (megabytes, NOT entry count — confirmed via
    # `man fapolicyd.conf`'s own doc comment: "The default value is 50 megabytes") is nowhere
    # near enough for a real desktop's package set. Confirmed live via the events log on this
    # exact device: "Entries in trust DB: 216897", "Trust database at 99% capacity", "db_max_size
    # needs to be increased", "Failed updating the trust database" — a real, current capacity
    # problem, not a one-off historical message. 500MB gives generous headroom over the ~370k
    # total entries observed here without needing per-device tuning.
    DESIRED_DB_MB=500
    set_conf "db_max_size" "$DESIRED_DB_MB"

    # A LMDB-backed environment (data.mdb) pre-allocates its max size AT CREATION — confirmed
    # live: the existing file was exactly 52428800 bytes (= 50MB, the OLD default) on the nose.
    # A config change alone does NOT retroactively grow an already-created database; fapolicyd
    # needs to recreate it from scratch to pick up a larger db_max_size. Only do this (stop +
    # delete + let the next start rebuild) when the on-disk file is actually smaller than what we
    # now want, so a repeat Enable click on an already-correctly-sized database doesn't force a
    # multi-minute full rebuild for no reason.
    db_file=/var/lib/fapolicyd/data.mdb
    if [ -f "$db_file" ]; then
        current_bytes=$(stat -c '%s' "$db_file" 2>/dev/null || echo 0)
        desired_bytes=$((DESIRED_DB_MB * 1024 * 1024))
        if [ "$current_bytes" -lt "$desired_bytes" ]; then
            systemctl stop fapolicyd 2>/dev/null || true
            rm -f /var/lib/fapolicyd/data.mdb /var/lib/fapolicyd/lock.mdb /var/lib/fapolicyd/db.ver
        fi
    fi

    # ⚠️ Found live 2026-08-05: this box had `q_size = 800` (manually set) — far below
    # fapolicyd's own 10000 default. q_size is the size of the kernel-side fanotify event queue;
    # in audit mode every open() produces a decision event, and once the queue fills the kernel
    # blocks every open()/exec() on the box with NO timeout until the daemon drains — the
    # synchronous-stall mechanism behind the hard-freeze/reboot reports (see the override.conf
    # doc comment above for the full chain). 10000 = the upstream default: enough burst headroom
    # for real workloads (recursive tree walks, boot-time exec storms) without unbounded memory
    # growth. Always owned by this script so a manual edit can't silently shrink it again.
    set_conf "q_size" "10000"

    # ⚠️ Found live 2026-07-29: unlike the Fedora/RHEL RPM package (whose postinst symlinks the
    # sample rules into place automatically), the Debian/Ubuntu package ships the same sample
    # rule units under /usr/share/fapolicyd/sample-rules/ but does NOT create /etc/fapolicyd/
    # rules.d/ at all, populated or otherwise. fagenrules (the service's ExecStartPre) hard-fails
    # with no useful stderr when its source directory doesn't exist, which surfaces to the
    # dashboard as an opaque "fapolicyd failed to start" — confirmed via `systemctl status
    # fapolicyd` showing `ExecStartPre=/usr/sbin/fagenrules (code=exited, status=1/FAILURE)`.
    # Fix: assemble the "known-libs" rule set here ourselves — this is fapolicyd upstream's own
    # documented default/recommended policy (see /usr/share/doc/fapolicyd/README.md: "goals:
    # anything requesting execution must be trusted; any library or interpreted
    # application/module must be trusted; everything else is not allowed" — i.e. default-deny).
    # Idempotent: safe to re-run on every Enable click, always reflects this exact list.
    mkdir -p /etc/fapolicyd/rules.d
    KNOWN_LIBS_RULES="10-languages.rules 20-dracut.rules 21-updaters.rules 30-patterns.rules 40-bad-elf.rules 41-shared-obj.rules 42-trusted-elf.rules 70-trusted-lang.rules 72-shell.rules 90-deny-execute.rules 95-allow-open.rules"
    for f in $KNOWN_LIBS_RULES; do
        src="/usr/share/fapolicyd/sample-rules/$f"
        if [ -f "$src" ]; then
            cp -f "$src" "/etc/fapolicyd/rules.d/$f"
            # ⚠️ Found live 2026-07-29: the sample rules ship with `_audit` decision suffixes
            # (e.g. `deny_audit perm=execute all : all`), which route decision events through the
            # KERNEL AUDIT SUBSYSTEM (libaudit → netlink), not plain syslog. Confirmed live on
            # this exact device: no auditd installed/running, no /proc/sys/kernel/audit_status at
            # all — so every `_audit` decision (including the final default-deny catch-all) was
            # being silently dropped with NO record anywhere, even though fapolicyd's own startup
            # diagnostics (a separate code path) log fine via its normal syslog tag. Confirmed by
            # triggering real test executions of untrusted/modified binaries and finding zero
            # corresponding entries via `journalctl -t fapolicyd` afterward. fapolicyd's own docs
            # (README.md "WRITING RULES" section) explicitly describe `_syslog` as the alternative
            # decision suffix that writes straight to syslog/journald independent of the kernel
            # audit subsystem — swap every `_audit` for `_syslog` so Recent Decisions actually
            # shows denials on a system without a working kernel audit subsystem, which is
            # apparently the case here despite this being an otherwise fully modern kernel.
            sed -i 's/_audit\b/_syslog/g' "/etc/fapolicyd/rules.d/$f"
        fi
    done
    [ -n "$(ls -A /etc/fapolicyd/rules.d 2>/dev/null)" ] || fail "no sample rule files found under /usr/share/fapolicyd/sample-rules — is fapolicyd actually installed?"

    # ⚠️ Found live 2026-07-29 (same day as the rules.d fix above): once fagenrules succeeds,
    # fapolicyd itself got stuck in a genuine restart loop — confirmed via `systemctl show
    # fapolicyd -p NRestarts` climbing (12 restarts observed) and `ActiveEnterTimestamp` resetting
    # every ~90s. First theory (WRONG, corrected below): assumed this was a slow one-time
    # trust-database build (hashing every file in every installed package) racing systemd's
    # default 90s TimeoutStartSec. The REAL cause, found by actually fetching fapolicyd's own
    # startup log via the events action: `trust = dpkgdb` (the wrong backend name — see the
    # top-of-file doc comment) made fapolicyd abort near-instantly every single time
    # ("dpkgdb backend not supported, aborting!"), and the ~90s cadence between restarts was
    # simply Restart=on-abnormal plus systemd's own restart back-off, not a slow build at all —
    # nothing was ever actually building. Fixed for real by correcting the backend name to
    # `debdb`. The TimeoutStartSec raise below is kept anyway: a genuine first-run debdb trust
    # scan across ~3000 packages is real work and legitimately slower than instant, even if it
    # was never what caused the ORIGINAL loop — this only matters for the one-time initial build
    # (persisted afterward in /var/lib/fapolicyd/data.mdb), so a generous ceiling here doesn't
    # mean every future start/restart actually takes this long.
    # Kernel-enforced safety net (2026-07-29, corrected 2026-08-05): fapolicyd intercepts every
    # exec/open on the box synchronously via fanotify, in BOTH audit and enforce mode — audit
    # mode only changes the final allow/deny outcome, not the per-event evaluation cost. The
    # original version of this cap relied on "fanotify is documented to fail OPEN when its
    # listener dies" — true for daemon DEATH (OOM-kill, crash, stop: the kernel releases the
    # group and every blocked open() unblocks), but NOT for a daemon that is ALIVE yet too slow
    # to drain. ⚠️ Found live 2026-08-05: the fanotify event queue has NO kernel-side timeout —
    # once it fills, the kernel parks every open()/exec() on the box in D-state until the
    # daemon catches up. With CPUQuota=50% + MemoryHigh=1536M in force, the daemon was being
    # throttled to under half a core while an audit-mode decision flood (syslog_format logs
    # EVERY open as a decision event) filled the queue — the whole desktop froze into hard
    # reboots. CPU throttling is therefore the WRONG tool for this daemon (its throughput is
    # what the entire system synchronously depends on), and memory.high throttling is a close
    # second — both dropped. MemoryMax=2048M stays: a hard cgroup OOM-kill is the one failure
    # mode that genuinely fails OPEN (daemon death), so it remains a safe backstop.
    mkdir -p /etc/systemd/system/fapolicyd.service.d
    cat > /etc/systemd/system/fapolicyd.service.d/override.conf <<'OVERRIDE_EOF'
[Service]
TimeoutStartSec=1800
MemoryMax=2048M
OVERRIDE_EOF

    systemctl daemon-reload
}

# ⚠️ User-mandated pre-flight (2026-07-30): NEVER switch this box from audit into enforce without
# first bulk-trusting every executable currently running. debdb+file trust covers apt-installed
# software and our own explicitly-approved paths, but a real desktop legitimately runs things
# outside both (browser-downloaded helper binaries, IDE-fetched language servers, manually built
# tools, etc.) — flipping default-deny on cold would immediately deny any of THOSE the moment they
# next exec or spawn a child, with no warning (this is audit mode's whole blind spot: it never
# surfaced these as "will break" ahead of time because audit mode never blocks anything). Scans
# every live process's real executable path via /proc, dedupes, and adds each to its own trust.d
# file — safe/idempotent to re-run (fapolicyd-cli recomputes the hash each time).
#
# ⚠️⚠️ Found live 2026-07-30, first real Enforce-mode test on this box: trusting the EXECUTABLE
# alone is not enough — fapolicyd independently checks every SHARED LIBRARY a process dynamically
# links against as its own separate object, regardless of whether the executable that loads it is
# trusted. `hyprctl` (Hyprland's CLI, /usr/local/bin — this desktop's compositor stack is built
# outside apt, so debdb never covers it) got approved and then immediately denied again on loading
# `libhyprutils.so` (/usr/local/lib — same story). A desktop with a substantial non-apt-packaged
# stack (this one: Hyprland + its libs in /usr/local, several tools in ~/.local/bin) needs its
# runtime library dependencies covered too, not just top-level executables — so this now also
# walks every process's /proc/PID/maps and trusts every mapped regular file. Reconstructs the
# pathname from field 6 onward (not just $NF) because a line with no mapped file has FEWER than 6
# fields and a deleted-file mapping has the literal suffix " (deleted)" as a trailing token, not
# part of $NF alone — grabbing only the last field would silently mis-parse both cases. Device
# nodes, memfd/anonymous regions, and deleted mappings are excluded naturally: `[ -f "$real" ]`
# only matches real regular files on disk, which none of those are.
trust_running_processes() {
    tmp=$(mktemp)
    for exe_link in /proc/[0-9]*/exe; do
        real=$(readlink "$exe_link" 2>/dev/null) || continue
        case "$real" in *" (deleted)") continue ;; esac
        [ -n "$real" ] && [ -f "$real" ] && printf '%s\n' "$real" >> "$tmp"
    done
    # ⚠️ Found live 2026-07-30: a bare `awk ... "$maps"` with no `|| true` aborted the WHOLE script
    # instantly (empty stdout, exit 2) under `set -e` the very first time this ran on a real busy
    # desktop — a process from the /proc/[0-9]*/maps glob had already exited by the time awk tried
    # to open its maps file, awk failed (file gone), and an unguarded simple command's failure is
    # NOT exempted from `set -e` the way an `&&`/`||` chain used as a bare statement is (the
    # exe-scan loop above already handles this exact race via its own explicit `|| continue`).
    for maps in /proc/[0-9]*/maps; do
        awk 'NF>=6 { line=$6; for(i=7;i<=NF;i++) line = line " " $i; print line }' "$maps" 2>/dev/null || true
    done >> "$tmp"
    sort -u "$tmp" -o "$tmp"
    count=0
    while IFS= read -r real; do
        case "$real" in *" (deleted)") continue ;; esac
        [ -f "$real" ] || continue
        fapolicyd-cli --file add "$real" --trust-file sentinel-preexisting.trust >/dev/null 2>&1 \
            && count=$((count + 1))
    done < "$tmp"
    rm -f "$tmp"
    printf '%s' "$count"
}

# Reports whether App Control can be serviced on THIS host at all, plus which distro/package
# manager said so. The dashboard hides the App Control UI off the back of this rather than
# guessing from a browser-side distro list — a hardcoded list in app.js goes stale the moment a
# new distro gets a working fapolicyd package, and it can't know anything about THIS box.
#
# ⚠️ The package-manager pick order here MUST stay identical to ensure_installed()'s. If the UI
# says "supported" for a host where the install path would fail, we get a dead button; if it says
# "unsupported" where the install would have worked, we hide a working feature. One source of
# truth, same order, both sides.
#
# Fail-SAFE default is "unsupported": a box we can't positively identify gets no App Control
# buttons rather than buttons that would only produce errors.
detect_appcontrol_support() {
    pm="none"
    if command -v apt-get >/dev/null 2>&1; then pm="apt"
    elif command -v pacman >/dev/null 2>&1; then pm="pacman"
    elif command -v dnf >/dev/null 2>&1; then pm="dnf"
    fi
    distro="unknown"
    # Parse, don't `source` — /etc/os-release is attacker-influenced in theory and this script
    # runs as root under `set -eu`, where sourcing a file with an unset var aborts the script.
    if [ -r /etc/os-release ]; then
        distro=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | head -1 | tr -d "\"' \r" || true)
        [ -n "$distro" ] || distro="unknown"
    fi
    reason=""
    case "$pm" in
        apt|dnf)
            supported="true"
            ;;
        pacman)
            supported="false"
            reason="fapolicyd is not available in any official Arch repository, and this agent will not build it from the AUR automatically. App Control cannot be enabled on this host."
            ;;
        *)
            supported="false"
            reason="No supported package manager for fapolicyd was found (looked for apt-get, dnf; pacman is present but carries no fapolicyd package)."
            ;;
    esac
}

do_status() {
    detect_appcontrol_support
    installed="false"; command -v fapolicyd >/dev/null 2>&1 && installed="true"
    # `systemctl is-active` alone collapses several real states (starting/activating,
    # deactivating, failed) into one boolean — not enough to tell "still building its trust
    # database, be patient" apart from "actually failed, go look." Read the raw ActiveState
    # instead and surface it directly so the dashboard can show something meaningful during the
    # (potentially many-minutes-long) first-run trust-db build.
    # ⚠️ Found live 2026-07-29: `systemctl is-active` prints the REAL state ("activating",
    # "failed", etc.) to stdout AND exits non-zero for anything other than "active" — a naive
    # `$(systemctl is-active ... || echo inactive)` runs the fallback too (since the exit code
    # is non-zero), concatenating both into e.g. "activating\ninactive" and permanently hiding
    # the real "activating" state from the mode logic below (which only ever saw the garbled
    # value, never matching "activating", so a still-starting daemon silently reported as "off").
    # ⚠️⚠️ Found live 2026-07-29 (same day, second bug from the same line): the naive-looking fix
    # for the above — dropping the inline `|| echo` and just doing
    # `systemd_state=$(systemctl is-active fapolicyd 2>/dev/null)` — reintroduced a WORSE problem
    # under this script's `set -eu`: per POSIX, a bare `var=$(cmd)` assignment's own exit status
    # IS the substituted command's exit status, and `systemctl is-active` returns non-zero for
    # EVERY state except "active" (e.g. 3 for "activating"). With `set -e` active, that made the
    # entire script abort silently (empty stdout, exit code 3) the instant fapolicyd wasn't
    # already fully active — i.e. on every single real deployment attempt, since a freshly
    # enabled/still-starting daemon is never "active" the moment status is checked. The `||
    # echo inactive` version never hit this because ITS inline `||` guaranteed the whole
    # substitution's own exit status was always 0 (masking the concatenation bug's root cause
    # instead of fixing it). Correct fix needs BOTH halves: capture the real single-line value
    # AND neutralize its exit status so `set -e` doesn't see it.
    systemd_state="inactive"
    if [ "$installed" = "true" ]; then
        systemd_state=$(systemctl is-active fapolicyd 2>/dev/null) || true
        [ -n "$systemd_state" ] || systemd_state="inactive"
    fi
    active="false"
    [ "$systemd_state" = "active" ] && active="true"
    mode="off"
    if [ -f "$CONF" ]; then
        perm=$(grep -E "^permissive[[:space:]]*=" "$CONF" 2>/dev/null | tail -1 | sed 's/.*=[[:space:]]*//')
        if [ "$active" = "true" ]; then
            [ "$perm" = "1" ] && mode="audit" || mode="enforce"
        elif [ "$systemd_state" = "activating" ]; then
            mode="starting"
        fi
    fi
    # ⚠️ Wedge detector + automatic rollback (added after the 2026-09-30 hard freeze). preflight_check()
    # stops us STARTING in a bad state, but a trust database can also go bad AFTER the daemon is
    # live — a package removed underneath it, a trust.d file truncated, a rule set edited by hand.
    # The signature is unmistakable and unrecoverable without a hard reset: execve() denied box-wide
    # (90k+ EPERMs, systemd can't spawn executors). This runs on the status poll the dashboard
    # already makes, so detection lands within seconds of the daemon going live instead of at the
    # next reboot — and the remediation (stop + force back to audit-only) is a config write and a
    # stop, both of which still work, because a box that can't exec binaries can still run the
    # shell this script is already running in. Audit mode is never rolled back: it cannot block.
    rolled_back="false"
    if [ "$mode" = "enforce" ]; then
        if ! exec_canary; then
            set_conf "permissive" "1"
            systemctl disable --now fapolicyd >/dev/null 2>&1 || true
            rolled_back="true"
            mode="off"
            active="false"
            systemd_state="inactive"
        fi
    fi
    rules_count=0
    [ -d /etc/fapolicyd/rules.d ] && rules_count=$(find /etc/fapolicyd/rules.d -maxdepth 1 -name '*.rules' 2>/dev/null | wc -l | tr -d ' ')
    trust_count=0
    [ -d /etc/fapolicyd/trust.d ] && trust_count=$(find /etc/fapolicyd/trust.d -maxdepth 1 -name '*.trust' 2>/dev/null | wc -l | tr -d ' ')
    printf '{"ok":true,"installed":%s,"active":%s,"systemd_state":"%s","mode":"%s","rules_count":%s,"trust_count":%s,"auto_rolled_back":%s,"distro":"%s","pkg_manager":"%s","appcontrol_supported":%s,"appcontrol_reason":"%s"}\n' \
        "$installed" "$active" "$(json_escape "$systemd_state")" "$mode" "$rules_count" "$trust_count" "$rolled_back" \
        "$(json_escape "$distro")" "$(json_escape "$pm")" "$supported" "$(json_escape "$reason")"
}

do_enable() {
    perm="$1"  # "1" = audit (permissive), "0" = enforce
    configure_base
    # MUST happen before the restart below (which is what actually flips enforcement) — see
    # trust_running_processes()'s doc comment. Only gated on the enforce transition; audit mode
    # never blocks anything so there's nothing to pre-approve for it.
    [ "$perm" = "0" ] && trust_running_processes >/dev/null
    set_conf "permissive" "$perm"
    # ⚠️ MUST run AFTER set_conf (it validates the config/rules we just wrote) but BEFORE the
    # restart below — see preflight_check()'s doc comment for the 2026-09-30 hard-freeze this
    # prevents. On a broken/partial install this fails closed: specific error, daemon never
    # started, box never touched.
    preflight_check "$perm"
    # Deliberately NOT `systemctl enable`: no boot-time auto-start (2026-08-05). The boot window
    # is the single highest-risk moment for this daemon — systemd's exec storm racing a fresh
    # trust-db rebuild floods the fanotify queue while the box is at its most fragile, which is
    # exactly when the hard freezes happened. Enabled state now lasts only until the next
    # reboot; the WebUI Status view reflects "off" after boot, and one Enable click re-arms it.
    # ⚠️ Deliberately --no-block (async), NOT a synchronous `systemctl restart`. Found live
    # 2026-07-29: `Type=forking` + a raised TimeoutStartSec (see configure_base's doc comment)
    # means a plain `systemctl restart` can legitimately BLOCK for the same many-minutes-long
    # first-run trust-db build before returning — far longer than this action's own Hop-2 SSH
    # timeout (120s server-side) or any browser fetch would tolerate. Fire the restart job and
    # return immediately; the dashboard polls Status (do_status above) to watch it move from
    # "starting" to "audit"/"enforce" (or "off"/failed if something's actually wrong).
    systemctl restart --no-block fapolicyd || fail "failed to schedule fapolicyd restart"
    do_status
}

do_disable() {
    if command -v fapolicyd >/dev/null 2>&1; then
        systemctl disable --now fapolicyd >/dev/null 2>&1 || true
    fi
    do_status
}

# Linux counterpart to AppLocker's per-event "Approve" button — the closest fapolicyd has to a
# manual allow-rule is its own file-trust database, managed via fapolicyd-cli rather than by
# hand-editing trust.d files ourselves (fapolicyd-cli computes the size+sha256 itself, which is
# both less code here and avoids ever getting the hash wrong). Kept in ITS OWN trust.d file
# (sentinel-approved.trust, via --trust-file) rather than appending to the default
# fapolicyd.trust — keeps every approval this dashboard ever made separately auditable/reversible
# from anything else that might touch the default file.
do_approve() {
    path="$2"
    if [ -z "$path" ]; then
        fail "approve requires a path argument"
    fi
    if [ ! -f "$path" ]; then
        fail "path does not exist or is not a regular file: $path"
    fi
    if ! command -v fapolicyd-cli >/dev/null 2>&1; then
        fail "fapolicyd-cli not found — is fapolicyd installed?"
    fi
    repair_trust_files
    # `if add_out=$(...)` (NOT a bare assignment) — under dash's set -e, a plain
    # `add_out=$(cmd)` aborts the whole script the instant fapolicyd-cli exits non-zero,
    # which is exactly what already-trusted duplicates do; found live 2026-08-05 as a
    # silent rc=1 with zero output.
    if add_out=$(fapolicyd-cli --file add "$path" --trust-file sentinel-approved.trust 2>&1); then
        add_rc=0
    else
        add_rc=$?
    fi
    if [ "$add_rc" -ne 0 ]; then
        # Already-trusted files (debdb scan, another trust file, a prior approve) are the goal
        # state already — fapolicyd-cli exits 1 with "nothing to add" for them, not an error.
        case "$add_out" in *"nothing to add"*) add_rc=0 ;; esac
    fi
    if [ "$add_rc" -ne 0 ]; then
        fail "fapolicyd-cli --file add failed: $add_out"
    fi
    # --update notifies the ALREADY-RUNNING daemon to reload its trust database live — no
    # restart, no interruption to whatever else is executing at the time.
    fapolicyd-cli --update >/dev/null 2>&1 || true
    printf '{"ok":true,"path":"%s"}\n' "$(json_escape "$path")"
}

# Bulk counterpart to do_approve() (2026-07-30) — the dashboard's Recent Decisions view groups
# denials by process+directory so one click approves everything in a group instead of N separate
# clicks/round-trips. `$2` is a NEWLINE-separated blob of absolute paths (same base64-encode-then-
# decode-on-remote discipline as the single-file approve — the support service passes it as ONE quoted
# shell argument, so embedded newlines survive intact). Deliberately only trusts the EXACT paths
# the caller already saw denied — not a recursive directory walk — so this can't accidentally
# widen trust to files that were never actually touched.
do_approve_many() {
    blob="$2"
    if [ -z "$blob" ]; then
        fail "approve-many requires a newline-separated list of paths"
    fi
    if ! command -v fapolicyd-cli >/dev/null 2>&1; then
        fail "fapolicyd-cli not found — is fapolicyd installed?"
    fi
    repair_trust_files
    tmp=$(mktemp)
    errfile=$(mktemp)
    printf '%s\n' "$blob" | while IFS= read -r path; do
        [ -n "$path" ] || continue
        case "$path" in
            /*) ;;
            *) echo BAD >> "$tmp"; continue ;;
        esac
        if [ -f "$path" ]; then
            if add_out2=$(fapolicyd-cli --file add "$path" --trust-file sentinel-approved.trust 2>&1); then
                echo OK >> "$tmp"
            else
                # Already-trusted files (debdb scan, another trust file, a prior approve) are the
                # goal state already — fapolicyd-cli exits 1 with "nothing to add" for them.
                case "$add_out2" in *"nothing to add"*) echo OK >> "$tmp" ;;
                *) echo BAD >> "$tmp"; echo "$add_out2" >> "$errfile" ;;
                esac
            fi
        else
            echo BAD >> "$tmp"
        fi
    done
    ok=$(grep -c '^OK$' "$tmp" 2>/dev/null) || ok=0
    bad=$(grep -c '^BAD$' "$tmp" 2>/dev/null) || bad=0
    rm -f "$tmp"
    # ⚠️ Found live 2026-08-05: an all-failed batch used to report {"ok":true,"approved":0} — a
    # misleading success toast ("Approved 0 file(s)") while the WebUI optimistically removed the
    # rows anyway. If EVERY path failed there is something structurally wrong (e.g. a corrupt
    # trust file fapolicyd-cli can't parse); surface the first real fapolicyd-cli error instead
    # of success-with-zero so the dashboard shows a failure and keeps the rows visible.
    if [ "$ok" -eq 0 ] && [ "$bad" -gt 0 ]; then
        first_err=$(head -c 300 "$errfile" 2>/dev/null | tr '\n' ' ' || true)
        rm -f "$errfile"
        fail "no paths were approved ($bad failed): ${first_err:-see fapolicyd-cli output}"
    fi
    rm -f "$errfile"
    fapolicyd-cli --update >/dev/null 2>&1 || true
    printf '{"ok":true,"approved":%s,"failed":%s}\n' "$ok" "$bad"
}

# Re-trust every file under each previously excluded folder — called from configure_base (enable)
# so the exclusions survive disable/re-enable cycles without requiring the operator to re-submit
# each folder. Reads EXCLUDED_FOLDERS_FILE (one absolute directory path per line); skips any
# line that isn't an existing directory (cleaned up or never existed). No output on success.
reapply_excluded_folders() {
    [ -f "$EXCLUDED_FOLDERS_FILE" ] || return 0
    # ⚠️ Found live 2026-08-06: this ran under the ENABLE action, whose bastion-side hop2_run
    # timeout is only 30s (linux_appcontrol_enable(), the support service). With no bound of its own,
    # re-trusting a large previously-excluded folder (e.g. an operator once excluded an entire
    # project tree) would blow straight through that 30s ceiling every single Enable click,
    # orphaning a background job on the device with the dashboard stuck reporting nothing.
    # Bounded well under 30s so the REST of configure_base (self-infra trust, debdb setup) still
    # has room to run within the same request.
    reapply_start_ts=$(date +%s)
    reapply_time_budget=12
    while IFS= read -r dir; do
        [ -n "$dir" ] || continue
        case "$dir" in /*) ;; *) continue ;; esac
        [ -d "$dir" ] || continue
        # dash's `read` builtin has no `-d` option (bash-only extension) — `read -r -d ''` used to
        # throw "Illegal option -d" on every invocation (this script is #!/bin/sh = dash on
        # Ubuntu), so this loop silently ran zero iterations and never re-trusted a single file.
        # Newline-delimited find, matching every other file-list loop in this script (e.g.
        # do_excluded_folders below) — filenames containing a literal newline are the accepted
        # tradeoff, same as elsewhere in this file.
        find "$dir" -type f 2>/dev/null | while IFS= read -r f; do
            now_ts=$(date +%s)
            if [ $((now_ts - reapply_start_ts)) -ge "$reapply_time_budget" ]; then
                break
            fi
            fapolicyd-cli --file add "$f" --trust-file sentinel-excluded-folders.trust >/dev/null 2>&1 || true
        done
        now_ts=$(date +%s)
        if [ $((now_ts - reapply_start_ts)) -ge "$reapply_time_budget" ]; then
            break
        fi
    done < "$EXCLUDED_FOLDERS_FILE"
}

# The Linux counterpart to Windows AppLocker's path-based allow rules — recursively trusts
# every regular file under a given directory. The directory is persisted in
# EXCLUDED_FOLDERS_FILE so reapply_excluded_folders() can re-trust it on the next enable.
# Accepts a single absolute directory path as $2.
do_exclude_folder() {
    dir="$2"
    if [ -z "$dir" ]; then
        fail "exclude-folder requires a directory path argument"
    fi
    case "$dir" in /*) ;; *) fail "path must be an absolute path" ;; esac
    if [ ! -d "$dir" ]; then
        fail "path is not a directory: $dir"
    fi
    if ! command -v fapolicyd-cli >/dev/null 2>&1; then
        fail "fapolicyd-cli not found — is fapolicyd installed?"
    fi
    repair_trust_files
    tmp=$(mktemp)
    # dash's `read` builtin has no `-d` option (bash-only extension) — `read -r -d ''` used to
    # throw "Illegal option -d" on every invocation (this script is #!/bin/sh = dash on Ubuntu),
    # so this loop silently ran zero iterations: every "Exclude Folder" click reported
    # {"ok":true,"trusted_files":0} and never actually trusted a single file. Found live
    # 2026-08-06. Newline-delimited find, matching every other file-list loop in this script.
    find "$dir" -type f 2>/dev/null > "$tmp"
    # ⚠️ Found live 2026-08-06: an operator pointed this at an entire project tree (hundreds of
    # thousands of files) — the per-file loop below measured ~14 files/sec (each fapolicyd-cli
    # invocation is its own process + sqlite write), so that target alone would have taken over an
    # hour. The bastion's exclude-folder hop2_run timeout is 180s, but that only stops the LOCAL
    # ssh client from waiting — the REMOTE process keeps running unattended (SSH doesn't reliably
    # propagate the client giving up into a remote SIGHUP), so the dashboard showed "Excluding
    # folder…" forever while a runaway background job kept grinding for hours. Two independent
     # guards, both needed:
     #  (1) warn about large targets but don't block — the time budget below handles them.
     #      The path is persisted to EXCLUDED_FOLDERS_FILE and reapply_excluded_folders()
     #      continues the trust on each re-enable, so partial progress is not lost.
     file_count=$(wc -l < "$tmp" | tr -d ' ')
     capped=false
     [ "$file_count" -gt 20000 ] && capped=true
     #  (2) bound the actual work by WALL-CLOCK TIME, not just a file-count cap — a cap alone
    #      doesn't protect against many files that are each individually slow to hash. Budget
    #      leaves ~60s headroom under the bastion's 180s hop2_run timeout for repair_trust_files
    #      + the final fapolicyd-cli --update below.
    count=0
    start_ts=$(date +%s)
    time_budget=120
    while IFS= read -r f; do
        [ -f "$f" ] || continue
        now_ts=$(date +%s)
        if [ $((now_ts - start_ts)) -ge "$time_budget" ]; then
            break
        fi
        fapolicyd-cli --file add "$f" --trust-file sentinel-excluded-folders.trust >/dev/null 2>&1 \
            && count=$((count + 1))
    done < "$tmp"
    rm -f "$tmp"
    capped=false
    [ "$count" -lt "$file_count" ] && capped=true
    # Persist the directory so it survives disable/re-enable cycles — even on a time-capped run,
    # so reapply_excluded_folders() (also time-budgeted) can pick up where this left off on the
    # next Enable, rather than losing the partial progress entirely.
    mkdir -p /etc/fapolicyd
    if ! grep -qxF "$dir" "$EXCLUDED_FOLDERS_FILE" 2>/dev/null; then
        printf '%s\n' "$dir" >> "$EXCLUDED_FOLDERS_FILE"
    fi
    fapolicyd-cli --update >/dev/null 2>&1 || true
    printf '{"ok":true,"path":"%s","trusted_files":%s,"total_files":%s,"capped":%s}\n' \
        "$(json_escape "$dir")" "$count" "$file_count" "$capped"
}

# Lists every excluded folder and how many trust entries it has. Read-only, no side effects.
do_excluded_folders() {
    printf '{"ok":true,"folders":['
    first=1
    if [ -f "$EXCLUDED_FOLDERS_FILE" ]; then
        while IFS= read -r dir; do
            [ -n "$dir" ] || continue
            case "$dir" in /*) ;; *) continue ;; esac
            count=0
            if [ -d "$dir" ]; then
                count=$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
            fi
            [ "$first" -eq 1 ] || printf ','
            first=0
            printf '{"path":"%s","exists":%s,"file_count":%s}' "$(json_escape "$dir")" "$([ -d "$dir" ] && echo true || echo false)" "$count"
        done < "$EXCLUDED_FOLDERS_FILE"
    fi
    printf ']}\n'
}

# Removes an excluded folder: strips it from EXCLUDED_FOLDERS_FILE, deletes all its trust
# entries from sentinel-excluded-folders.trust, then reloads fapolicyd.
do_remove_folder() {
    dir="$2"
    if [ -z "$dir" ]; then
        fail "remove-folder requires a directory path argument"
    fi
    case "$dir" in /*) ;; *) fail "path must be an absolute path" ;; esac
    # Remove from the persisted list.
    if [ -f "$EXCLUDED_FOLDERS_FILE" ]; then
        tmp=$(mktemp)
        grep -vxF "$dir" "$EXCLUDED_FOLDERS_FILE" > "$tmp" 2>/dev/null || true
        mv -f "$tmp" "$EXCLUDED_FOLDERS_FILE"
    fi
    # Remove trust entries whose path starts with $dir.
    trust_file="/etc/fapolicyd/trust.d/sentinel-excluded-folders.trust"
    if [ -f "$trust_file" ]; then
        tmp=$(mktemp)
        awk -v d="$dir/" '{ if (index($1, d) != 1 && $1 != d) print }' "$trust_file" > "$tmp"
        mv -f "$tmp" "$trust_file"
    fi
    fapolicyd-cli --update >/dev/null 2>&1 || true
    printf '{"ok":true,"path":"%s"}\n' "$(json_escape "$dir")"
}

do_events() {
    # fapolicyd logs every rule decision to syslog (SYSLOG_IDENTIFIER=fapolicyd) when
    # syslog_format is configured — journalctl is the universal read path regardless of whether
    # this box also runs classic auditd. Deliberately returned as raw lines (not hand-parsed
    # fields) since the exact log format hasn't been verified live against a real capture yet —
    # safer to show operators the real text than to silently drop/mis-map fields from a guessed
    # regex. Limited to the last N lines (default 200) to keep the response small.
    n="${2:-200}"
    if ! command -v journalctl >/dev/null 2>&1; then
        printf '{"ok":true,"lines":[]}\n'
        return
    fi
    # ⚠️ Found live 2026-07-29: a plain `-n N` over the whole fapolicyd syslog tag mixes in
    # earlier restart attempts (failed startup errors from BEFORE a config fix landed) alongside
    # the currently-running instance's own clean log — genuinely confusing in the dashboard, since
    # it reads as a live/current error even once the underlying problem is long fixed. Scope to
    # ONLY the current instance's own messages via --since <ActiveEnterTimestamp> when the service
    # is actually up; fall back to the old whole-tag behavior if it's not running at all (nothing
    # "current" to scope to) so this action still works for something to look at.
    since_ts=""
    if command -v fapolicyd >/dev/null 2>&1; then
        since_ts=$(systemctl show fapolicyd -p ActiveEnterTimestamp --value 2>/dev/null) || true
        case "$since_ts" in ""|"n/a") since_ts="" ;; esac
    fi
    if [ -n "$since_ts" ]; then
        lines=$(journalctl -t fapolicyd --since "$since_ts" -n "$n" --no-pager -o cat 2>/dev/null) || true
    else
        lines=$(journalctl -t fapolicyd -n "$n" --no-pager -o cat 2>/dev/null) || true
    fi
    printf '{"ok":true,"lines":['
    first=1
    if [ -n "$lines" ]; then
        printf '%s\n' "$lines" | while IFS= read -r line; do
            [ "$first" -eq 1 ] || printf ','
            first=0
            printf '"%s"' "$(json_escape "$line")"
        done
    fi
    printf ']}\n'
}

case "$ACTION" in
    status)           do_status ;;
    enable-audit)     do_enable 1 ;;
    enable-enforce)   do_enable 0 ;;
    disable)          do_disable ;;
    events)           do_events "$@" ;;
    approve)          do_approve "$@" ;;
    approve-many)     do_approve_many "$@" ;;
    exclude-folder)   do_exclude_folder "$@" ;;
    excluded-folders) do_excluded_folders ;;
    remove-folder)    do_remove_folder "$@" ;;
    *) fail "unknown action: $ACTION (expected status|enable-audit|enable-enforce|disable|events|approve|approve-many|exclude-folder|excluded-folders|remove-folder)" ;;
esac
