#!/bin/sh
set -eu
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
SIZES="${SIZES:-2000 20000}"
PASSES="${PASSES:-20}"
OUT="${OUT:-$(mktemp -d)}"
mkdir -p "$OUT"
make -C "$REPO/src/backend-c" passbench >/dev/null
cd "$REPO/src/backend-c"
echo "# $(uname -sm), $(cc --version | head -1), out in $OUT"
for n in $SIZES; do
    build/host/bench/passbench "$n" "$PASSES" > "$OUT/steps-$n.txt" 2> "$OUT/log-$n.txt"
    cat "$OUT/steps-$n.txt"
    sed -n '/passbench: warm-up done/,/passbench: full passes/p' "$OUT/log-$n.txt" |
        grep -E 'x_tables ipv[46] (nat|filter|mangle): (unchanged, )?read' |
        awk -v n="$n" '{
            fam = $4; tbl = $5; sub(":", "", tbl);
            for (i = 6; i <= NF; i++) if ($(i + 2) ~ /^us,?$/ && $(i + 1) ~ /^[0-9]+$/) { key = fam " " tbl " " $i; v[key] = v[key] " " $(i + 1); }
        } END {
            for (k in v) { m = split(v[k], a, " "); asort(a); printf "N=%s %s p50 %s us (%d samples)\n", n, k, a[int((m + 1) / 2)], m }
        }' | sort
done
