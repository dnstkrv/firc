#!/bin/sh
[ $# -ge 5 ] || { echo "usage: run_ktcp_ab.sh <case> <A|B> <round> <seconds> <client-iface>..." >&2; exit 2; }
CASE=$1 MODE=$2 ROUND=$3 W=$4
shift 4
case $MODE in A|B) ;; *) echo "mode must be A or B" >&2; exit 2 ;; esac
for i in "$@"; do [ -r "/sys/class/net/$i/statistics/tx_bytes" ] || { echo "no interface $i" >&2; exit 2; }; done
pt() { for p in $(pidof "$1" 2>/dev/null); do cat "/proc/$p/stat" 2>/dev/null; done | awk '{s+=$14+$15} END{printf "%.0f\n", s}'; }
cpu() { awk '/^cpu /{printf "%.0f %.0f\n", $2+$3+$4+$7+$8+$9, $5+$6}' /proc/stat; }
out() { for i in "$@"; do cat "/sys/class/net/$i/statistics/tx_bytes"; done | awk '{s+=$1} END{printf "%.0f\n", s}'; }
a1=$(pt tunvless); f1=$(pt fircd); c1=$(cpu); o1=$(out "$@"); t1=$(cut -d' ' -f1 /proc/uptime)
sleep "$W"
a2=$(pt tunvless); f2=$(pt fircd); c2=$(cpu); o2=$(out "$@"); t2=$(cut -d' ' -f1 /proc/uptime)
awk -v c="$CASE" -v m="$MODE" -v r="$ROUND" -v c1="$c1" -v c2="$c2" -v a1="$a1" -v a2="$a2" -v f1="$f1" -v f2="$f2" -v o1="$o1" -v o2="$o2" -v t1="$t1" -v t2="$t2" \
  'BEGIN{split(c1, x, " "); split(c2, y, " ");
  printf "case=%s mode=%s round=%s busy=%.0f idle=%.0f tv=%.0f fircd=%.0f out=%.0f dt=%s\n", c, m, r, y[1] - x[1], y[2] - x[2], a2 - a1, f2 - f1, o2 - o1, t2 - t1}'
