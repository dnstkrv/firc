#!/bin/sh
printf "%s\n" "$1" > "$FAKE_SH_LOG"
exec /bin/sh "$@"
