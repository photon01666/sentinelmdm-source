#!/bin/sh
# Shared by hop2-authkeys.sh and hop2-reap.sh — ONE place for the arm-file path and TTL check, so
# the auth-decision logic and the cleanup logic can never drift out of sync with each other.
#
# Design plan §3 lesson: TTL freshness is decided by comparing raw unix-epoch integers only
# (file mtime vs `date +%s`), never by parsing a stored ISO8601 timestamp string — this sidesteps
# the whole class of timezone/Kind bug that cost real debugging time twice in the Windows codebase
# (see docs/ARCHITECTURE.md's "Windows Update — Force Update Now" invariant row).

HOP2_ARM_FILE="/run/sentinel-ra/hop2-armed.pub"

# NO TTL on the armed session key (removed entirely 2026-08-18 at the operator's request — the
# 900s/10800s freshness window kept expiring mid-session and the copied connect command died
# "Permission denied" between re-arms). The armed session key is now trusted for as long as the
# arm file EXISTS: it is removed only by an explicit disarm (hop2_session_close -> daemon
# disarmHop2 deletes the file), overwritten by a newer re-arm (hop2_session_open writes the new
# session key in its place, so a rotated/regenerated key immediately supersedes the old one), or
# a box reboot (the arm file lives in tmpfs /run, wiped on boot). The TTL was the fallback for an
# ungraceful bastion-side crash/network loss with no close event; that fallback is deliberately
# gone — the residual exposure (a forgotten session's key stays valid until the next re-arm or
# reboot) was accepted. Never touches an already-authenticated session (design plan §3) — this
# only gates whether a NEW connection's AuthorizedKeysCommand lookup succeeds.

# HOP2_ADMIN_PUBKEY_FILE: a SEPARATE, STANDING trust path alongside the TTL-armed one above —
# added after actually reading the Windows bastion's real hop2_run()/ADMIN_SUPPORT_KEY code
# (swarm-stacks/custom-images/ssh-bastion/bastion-web.py), which revealed the original design here
# only accounted for the human "click Connect, get a live shell" case. In production, the bastion
# ALSO needs to reach Hop-2 on its own for automated one-shot actions with no human in the loop —
# arbitrary exec buttons, fleet fan-out, and (most importantly for this project) IT Audit Mode's
# "Collect all" and any future scheduled AI-report sweep. Windows handles this by trusting one
# fixed admin key (ADMIN_SUPPORT_KEY) UNCONDITIONALLY, always, for every customer — same posture
# adopted here: this file (pushed post-enrollment, see cmd/sentineld/daemon.go's provision
# handler, NOT baked into the install like Windows' admin key is, since this port already
# committed to "never bake secrets at build time") is trusted ALWAYS, with no TTL, alongside the
# TTL-armed session key. Written under config.StateDir (sentinel-ra-owned) rather than
# /etc/sentinel-ra so the unprivileged daemon can write it without a sudoers escalation.
HOP2_ADMIN_PUBKEY_FILE="/var/lib/sentinel-ra/bastion-support-key.pub"

# hop2_arm_file_armed: exit 0 if the arm file exists (the session key is trusted — no TTL), exit 1
# otherwise. See the NO-TTL note above for why there is no age check.
hop2_arm_file_armed() {
    [ -f "$HOP2_ARM_FILE" ]
}
