#!/bin/sh
printf '%s %s\n' "$*" "$(wc -c < "$2")" >> "${FAKE_OPKG_LOG:-/dev/null}"
if [ -n "${FAKE_OPKG_DAEMON:-}" ]; then
    ( exec > /dev/null 2>&1 < /dev/null; exec sleep 30 ) &
    echo "$!" > "$FAKE_OPKG_DAEMON"
fi
if [ -n "${FAKE_OPKG_HOLD:-}" ]; then
    i=0
    while [ ! -e "$FAKE_OPKG_HOLD" ] && [ "$i" -lt 200 ]; do
        sleep 0.05
        i=$((i + 1))
    done
fi
[ -n "${FAKE_OPKG_KILL_PARENT:-}" ] && kill -9 "$PPID"
echo "Installing firc (0.3.0-1) to root..."
echo "opkg: an error on stderr" >&2
exit "${FAKE_OPKG_RC:-0}"
