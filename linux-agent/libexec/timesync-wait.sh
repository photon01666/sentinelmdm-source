#!/bin/sh
# Wait (bounded) for network time sync before the daemon's first signed reconnect. Live rescue
# boxes often boot with a wildly-wrong RTC (no persistence) — sentineld's signed-auth reconnect
# is rejected when the clock is >60s off the server (memory remote-assist-clock-skew-invalid-
# signature; found live 2026-08-17: the box was 5h behind and every reconnect after the first
# ticket-auth connect got "Invalid signature"). The FIRST connect is ticket-auth (timestamp-free)
# so a failed sync never blocks boot — this just maximizes the chance the daemon's first signed
# reconnect succeeds.
set -eu

i=0
while [ "$i" -lt 45 ]; do
  if chronyc tracking 2>/dev/null | grep -q '^Leap status.*Normal'; then exit 0; fi
  if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = "yes" ]; then exit 0; fi
  sleep 1
  i=$((i + 1))
done
exit 0
