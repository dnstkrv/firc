#!/bin/sh
set -eu

NAME="${1:?need a library name}"
SRC="${2:?need the source directory}"
OUT="${3:?need the output archive path}"
INCS="${4:?need the include directories}"
DEFS="${5:-}"
shift 5
CC="${CC:-cc}"
AR="${AR:-ar}"
CFLAGS="${CFLAGS:--O2}"

[ -d "$SRC" ] || { echo "$NAME: no sources in $SRC" >&2; exit 2; }
SRC=$(cd "$SRC" && pwd)
mkdir -p "$(dirname "$OUT")"

INC=
for d in $INCS; do INC="$INC -I$SRC/$d"; done
TRIPLE=$($CC -dumpmachine 2>/dev/null || echo unknown)
STAMP="$(cat "$0"; echo "$*|$CC|$CFLAGS|$DEFS|$INC|$TRIPLE|$(cat "$SRC/.steer-$NAME" 2>/dev/null)")"
if [ -f "$OUT" ] && [ -f "$OUT.stamp" ] && [ "$(cat "$OUT.stamp")" = "$STAMP" ]; then
    exit 0
fi
OBJ="$OUT.obj"
rm -rf "$OBJ"
mkdir -p "$OBJ"

failed=
for f in "$@"; do
    o="$OBJ/$(echo "$f" | tr '/' '_').o"
    # shellcheck disable=SC2086
    if ! $CC $CFLAGS $DEFS $INC -c "$SRC/$f" -o "$o" 2>"$o.err"; then
        failed="$failed $f"
        echo "$NAME: $f failed to compile ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    elif [ -s "$o.err" ]; then
        echo "$NAME: warnings in $f ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    fi
    rm -f "$o.err"
done
[ -z "$failed" ] || { echo "$NAME: files failed to compile:$failed" >&2; exit 1; }

rm -f "$OUT"
$AR rcs "$OUT" "$OBJ"/*.o
printf '%s\n' "$DEFS$INC" > "$OUT.cflags"
printf '%s' "$STAMP" > "$OUT.stamp"
rm -rf "$OBJ"
