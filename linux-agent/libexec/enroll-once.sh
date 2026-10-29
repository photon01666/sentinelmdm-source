#!/bin/sh
# First-boot enrollment for the SHARED rescue ISO (fleet-maintenance mode): generates a FRESH
# device identity and consumes ONE use of the baked installer ticket, so every boot of the same
# ISO registers as its OWN device in the account that minted the ticket (each maintenance
# session = one ephemeral device). Wired up by sentinel-enroll.service (Before=sentineld.service)
# when the ISO was built with a ticket; a normal install has no ticket file and this exits 0.
# Idempotent: does nothing if an enrollment already exists (a persistent-media boot or a re-run
# after a partially-failed first boot) — the daemon then reconnects via signed auth.
set -eu

TICKET_FILE=/etc/sentinel-ra/enrollment-ticket
[ -f "$TICKET_FILE" ] || exit 0
[ -f /var/lib/sentinel-ra/enrollment.json ] && exit 0

TICKET=$(cat "$TICKET_FILE")
# Strict 64-lowercase-hex check — mirrors sentineld's own validTicketFormat guard; anything else
# is a corrupted bake, not a credential to pass through.
case "$TICKET" in
  ''|*[!0-9a-f]*) echo "invalid baked enrollment ticket" >&2; exit 1 ;;
esac
[ "${#TICKET}" -eq 64 ] || { echo "invalid baked enrollment ticket length" >&2; exit 1; }

exec /usr/local/bin/sentineld enroll --ticket "$TICKET"