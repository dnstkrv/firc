#!/bin/sh
set -u
cd "$(dirname "$0")/.."
BIN="${TUNVLESS:-./out/tunvless}"
[ -x "$BIN" ] || { echo "control: no binary $BIN (make)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "control: needs root — skipped"; exit 0; }
for t in ip python3 wget; do
    command -v $t >/dev/null 2>&1 || { echo "control: no $t — skipped"; exit 0; }
done

H=tvc-host N=tvc-node
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
GW=10.74.0.1 HOSTIP=10.74.0.2 A=10.75.0.1 B=10.75.0.2 PORT=10800
W="$(mktemp -d)"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    for p in ${TP:-} ${TK:-} ${TB:-} ${HOLD:-} ${TS:-} ${SRV_A:-} ${SRV_B:-} ${S2A:-} ${S2B:-} ${S2C:-} ${LONG:-}; do kill "$p" 2>/dev/null; done
    ip netns pids $H 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns pids $N 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $H 2>/dev/null; ip netns del $N 2>/dev/null
    rm -rf /etc/netns/$H
    if [ "$fail" != 0 ]; then echo "--- tunnel log (tail)"; tail -n 30 "$W/tun.log" 2>/dev/null; echo "--- events"; cat "$W/ev" 2>/dev/null
        echo "--- swap log (tail)"; tail -n 30 "$W/tun2.log" 2>/dev/null; echo "--- swap events"; cat "$W/ev2" 2>/dev/null; fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

"$BIN" --control -d tvc0 < /dev/null 2> "$W/empty.err"
# catches: a tunvless that has no node to carry and says so untagged, so fircd keeps it at info
check "no node on stdin: exits 2" 2 "$?"
check "no node on stdin: an error line" "tunvless[error]: no usable VLESS node" "$(cat "$W/empty.err")"
"$BIN" --control -d tvc0 -A 0 < /dev/null 2> "$W/opt.err"
# catches: a refused option told untagged
check "a bad option value: an error line" "tunvless[error]: bad option value: 0" "$(cat "$W/opt.err")"
"$BIN" --control -d tvc0 -a 300.1.1.1 < /dev/null 2> "$W/addr.err"
# catches: a refused --addr told untagged
check "a bad --addr: an error line" "tunvless[error]: --addr 300.1.1.1 is not an IPv4 address" "$(cat "$W/addr.err")"
"$BIN" --control -d 0123456789abcdefg < /dev/null 2> "$W/dev.err"
# catches: a refused device name told untagged
check "a long device name: an error line" "tunvless[error]: device name must be 1..15 characters" "$(cat "$W/dev.err")"

head -c 1100000 /dev/zero | tr '\0' x | "$BIN" --control -d tvc0 > /dev/null 2> "$W/big.err"
check "stdin over the limit exits 2" 2 "$?"
# catches: a node list too big to read told as a warning, though the tunnel never starts
check "stdin over the limit: an error line" "tunvless[error]: nodes on stdin exceed 1048576 bytes" "$(cat "$W/big.err")"
printf 'vless://%s@nohost.invalid:443?security=none&type=tcp#X\n\n' "$UUID" \
  | "$BIN" --control --no-retry -d tvc0 > /dev/null 2> "$W/dns.err"
check "no name resolves, no retry: exits 1" 1 "$?"
# catches: a tunnel ended by names that never resolve told as a warning
check "no name resolves: an error line" 1 "$(grep -cxF 'tunvless[error]: nohost.invalid does not resolve' "$W/dns.err")"
printf 'vless://%s@192.0.2.1:1?security=none&type=tcp#X\nvless://%s@192.0.2.2:1?security=none&type=tcp#Y\n\n' \
  "$UUID" "$UUID" | "$BIN" --control --no-retry -t 1 -d tvc0 > /dev/null 2> "$W/dead.err"
check "no node answers, no retry: exits 1" 1 "$?"
# catches: a tunnel ended by dead nodes told as a warning
check "no node answers: an error line" 1 "$(grep -cxF 'tunvless[error]: no node answered' "$W/dead.err")"
printf 'vless://%s@192.0.2.1:1?security=none&type=tcp#X\n\n' "$UUID" \
  | "$BIN" --control -d lo > /dev/null 2> "$W/lo.err"
check "a device that is not a tun: exits 1" 1 "$?"
# catches: a device that cannot be created told as a warning, though the tunnel ends there
check "a device that is not a tun: an error line" 1 \
    "$(grep -c '^tunvless\[error\] tunnel: device lo was not created' "$W/lo.err")"

HX() { ip netns exec $H "$@"; }
ip netns del $H 2>/dev/null; ip netns del $N 2>/dev/null
ip netns add $H; ip netns add $N
ip link add v0 netns $H type veth peer name v1 netns $N
HX ip link set lo up; HX ip addr add $HOSTIP/24 dev v0; HX ip link set v0 up
HX ip route add default via $GW
ip netns exec $N ip link set lo up; ip netns exec $N ip addr add $GW/24 dev v1; ip netns exec $N ip link set v1 up
ip netns exec $N ip addr add $A/32 dev lo
ip netns exec $N ip addr add $B/32 dev lo
mkdir -p /etc/netns/$H
: > /etc/netns/$H/hosts
echo "nameserver 127.0.0.1" > /etc/netns/$H/resolv.conf

node_up() {
    eval addr=\$$1
    ip netns exec $N python3 tests/fake-vless.py --port $PORT --uuid $UUID --mb 1 \
        --bind "$addr" > "$W/srv-$1.log" 2>&1 &
    eval SRV_$1=\$!
}
node_up A
node_up B
sleep 1

printf 'vless://%s@%s:%s?security=none&type=tcp#A\nvless://%s@%s:%s?security=none&type=tcp#B\n\n' \
  "$UUID" "$A" "$PORT" "$UUID" "$B" "$PORT" > "$W/nodes"
TAB=$(printf '\t')
printf 'vless://%s@%s:%s?security=none&type=tcp#A\nvless://%s@%s:%s?security=none&type=tcp#B\n\n' \
  "$UUID" "$A" "$PORT" "$UUID" "$B" "$PORT" | HX "$BIN" --probe -t 3 - > "$W/probe.out" 2> "$W/probe.err"
check "probe from stdin exits 0" 0 "$?"
check "probe from stdin: two lines" 2 "$(wc -l < "$W/probe.out")"
check "probe from stdin: A answers" 1 "$(grep -c "^0${TAB}A${TAB}ok${TAB}" "$W/probe.out")"
check "probe from stdin: B second" 1 "$(grep -c "^1${TAB}B${TAB}" "$W/probe.out")"
check "probe from stdin: no link in stdout" 0 "$(grep -c "vless://\|$UUID" "$W/probe.out")"
check "probe from stdin: no link in stderr" 0 "$(grep -c "vless://\|$UUID" "$W/probe.err")"
printf 'garbage-%s@host:1\nvless://%s@%s:%s?security=none&type=tcp#A\n\n' "$UUID" "$UUID" "$A" "$PORT" \
  | HX "$BIN" --list - > "$W/list.out" 2> "$W/list.err"
check "list from stdin: the link line listed" 1 "$(grep -c "^0${TAB}A${TAB}" "$W/list.out")"
check "list from stdin: malformed line named by number" 1 "$(grep -c 'line 1: not a vless:// link' "$W/list.err")"
check "list from stdin: no uuid on either stream" 0 "$(cat "$W/list.out" "$W/list.err" | grep -c "$UUID")"
tv_pid() {
    for d in /proc/[0-9]*; do
        [ "$(cat "$d/comm" 2>/dev/null)" = tunvless ] && [ "$(readlink "$d/fd/0" 2>/dev/null)" = "$W/nodes" ] && { echo "${d#/proc/}"; return; }
    done
}
HX "$BIN" --control -d tvc0 -A 1 --interval 5 < "$W/nodes" > "$W/ev" 2> "$W/tun.log" 9< "$W/nodes" & TP=$!
sleep 4
check "ready line" '{"type":"ready","dev":"tvc0","tcpPort":0}' "$(grep '"ready"' "$W/ev" | head -1)"
check "first active" '{"type":"active","nodes":["A"],"index":[0]}' "$(grep '"active"' "$W/ev" | head -1)"
TV=$(tv_pid)
check "inherited fd 9 closed" "${TV:-none} no" "${TV:-none} $([ -e "/proc/$TV/fd/9" ] && echo yes || echo no)"
check "tunvless found" 1 "$([ -n "$TV" ] && echo 1 || echo 0)"
kill "$SRV_A"; sleep 12
check "A down reported" 1 "$(grep -c '"node_down","node":"A"' "$W/ev")"
check "B takes over" '{"type":"active","nodes":["B"],"index":[1]}' "$(grep '"active"' "$W/ev" | tail -1)"
check "no link in stderr" 0 "$(grep -c "vless://\|$UUID" "$W/tun.log")"
check "no link in stdout" 0 "$(grep -c "vless://\|$UUID" "$W/ev")"
printf 'garbage-%s@host:1\n\n' "$UUID" | HX "$BIN" --control -d tvc1 > /dev/null 2> "$W/bad.log"
check "malformed line: no uuid in stderr" 0 "$(grep -c "$UUID" "$W/bad.log")"
check "malformed line named by number" 1 "$(grep -c 'line 1: not a vless:// link' "$W/bad.log")"
HX "$BIN" --control -d tvc2 "vless://$UUID@$A:$PORT#x" < /dev/null > /dev/null 2> "$W/argv.err"
check "--control with a link on argv exits 2" 2 "$?"
# catches: a refused --control invocation told as a warning, so it never reaches an error-only log
check "--control with a link on argv: an error line" \
    "tunvless[error]: --control takes nodes on stdin, not as arguments" "$(cat "$W/argv.err")"
HX "$BIN" --control -d tvc2 -A 9 < "$W/nodes" > /dev/null 2> "$W/nine.err"
check "--control with nine active nodes exits 2" 2 "$?"
# catches: -A 9 told at another level than -A 0, though both come from the same option
check "--control with nine active nodes: an error line" \
    "tunvless[error]: --control allows at most 8 active nodes" "$(cat "$W/nine.err")"

HX "$BIN" --control -d tvc2 --list < "$W/nodes" > /dev/null 2> "$W/list.err"
check "--control with --list exits 2" 2 "$?"
# catches: a refused --control combination told as a warning
check "--control with --list: an error line" \
    "tunvless[error]: --control does not combine with --list or --probe" "$(cat "$W/list.err")"
wait_in() {
    i=0
    while [ $i -lt 50 ] && ! grep -qF "$2" "$1"; do sleep 0.2; i=$((i + 1)); done
}
mkfifo "$W/ink"
ip netns exec $H sh -c 'ulimit -Sn 512; exec "$@"' sh "$BIN" --control -d tvk0 -A 1 -t 3 --tcp-port 3600 \
    --tcp-pool 198.18.0.0/15 < "$W/ink" > "$W/evk" 2> "$W/tunk.log" & TK=$!
exec 7> "$W/ink"
cat "$W/nodes" >&7
wait_in "$W/evk" '"ready"'
check "--tcp-port and --tcp-pool: ready" '{"type":"ready","dev":"tvk0","tcpPort":3600}' "$(grep '"ready"' "$W/evk" | head -1)"
check "the open file limit is raised to the hard limit" raised \
    "$(awk '/^Max open files/ { print ($4 == $5) ? "raised" : $4 " of " $5 }' "/proc/$TK/limits" 2>/dev/null)"
check "a direct connection to the port is reset" reset "$(HX python3 -c '
import socket
s = socket.create_connection(("127.0.0.1", 3600), 3)
s.settimeout(3)
try:
    print("eof" if s.recv(1) == b"" else "data")
except ConnectionResetError:
    print("reset")
except socket.timeout:
    print("timeout")
')"
printf 'map\n198.18.0.5 10.0.0.1\n198.18.0.6 -\n\n' >&7
wait_in "$W/evk" '"type":"map"'
check "a map command is acknowledged with its count" '{"type":"map","count":2}' "$(grep '"type":"map"' "$W/evk" | head -1)"
printf 'close\n198.18.0.0/24\n\n' >&7
wait_in "$W/evk" '"type":"close"'
check "a close command is acknowledged by the loop" '{"type":"close","count":0}' "$(grep '"type":"close"' "$W/evk" | head -1)"
exec 7>&-
kill "$TK" 2>/dev/null; wait "$TK" 2>/dev/null; TK=""
ip netns exec $H python3 -c '
import socket, time
s = socket.socket()
s.bind(("0.0.0.0", 3601))
s.listen(1)
time.sleep(30)
' & HOLD=$!
sleep 0.5
ip netns exec $H "$BIN" --control -d tvk2 -A 1 -t 3 --tcp-port 3601 < "$W/nodes" > "$W/evb" 2> "$W/tunb.log" & TB=$!
wait_in "$W/evb" '"ready"'
check "a taken port: ready with tcpPort 0" '{"type":"ready","dev":"tvk2","tcpPort":0}' "$(grep '"ready"' "$W/evb" | head -1)"
check "a taken port: one warn line" 1 "$(grep -c 'tunvless\[warn\] tunnel: cannot listen on port 3601: .*, TCP stays on the TUN' "$W/tunb.log")"
kill "$TB" "$HOLD" 2>/dev/null; wait "$TB" "$HOLD" 2>/dev/null; TB="" HOLD=""
ip netns exec $H "$BIN" --control -d tvk3 -A 1 -t 3 --tcp-port 65535 < "$W/nodes" > "$W/evm" 2> /dev/null & TB=$!
wait_in "$W/evm" '"ready"'
check "--tcp-port 65535 is taken" '{"type":"ready","dev":"tvk3","tcpPort":65535}' "$(grep '"ready"' "$W/evm" | head -1)"
kill "$TB" 2>/dev/null; wait "$TB" 2>/dev/null; TB=""
bad_tcp() {
    HX timeout 15 "$BIN" --control -d tvk1 "$1" "$2" < "$W/nodes" > /dev/null 2> "$W/badk.log"
    echo "$? $(grep -c "bad option value: $2" "$W/badk.log")"
}
check "--tcp-port 0 is a usage error" "2 1" "$(bad_tcp --tcp-port 0)"
check "--tcp-port 70000 is a usage error" "2 1" "$(bad_tcp --tcp-port 70000)"
check "--tcp-port 65536 is a usage error" "2 1" "$(bad_tcp --tcp-port 65536)"
check "--tcp-pool without a length is a usage error" "2 1" "$(bad_tcp --tcp-pool 198.18.0.0)"
check "--tcp-pool 198.18.0.0/+15 is a usage error" "2 1" "$(bad_tcp --tcp-pool 198.18.0.0/+15)"
check "--tcp-pool 0.0.0.0/0 is a usage error" "2 1" "$(bad_tcp --tcp-pool 0.0.0.0/0)"
check "--tcp-pool 198.18.0.0/33 is a usage error" "2 1" "$(bad_tcp --tcp-pool 198.18.0.0/33)"
check "--tcp-pool ::/0 is a usage error" "2 1" "$(bad_tcp --tcp-pool ::/0)"
P2=10801 C=10.75.0.3
ip netns exec $N ip addr add $C/32 dev lo
srv2() {
    ip netns exec $N python3 tests/fake-vless.py --port $P2 --uuid $UUID --mb "$2" --kbps "$3" \
        --bind "$1" > "$W/srv2-$4.log" 2>&1 &
}
srv2 $A 1 200 A; S2A=$!
srv2 $B 2 0 B; S2B=$!
srv2 $C 3 0 C; S2C=$!
lnk() { eval addr=\$$1; printf 'vless://%s@%s:%s?security=none&type=tcp#%s\n' "$UUID" "$addr" "$P2" "$1"; }
wait_ev() {
    i=0
    while [ $i -lt $(($2 * 5)) ]; do
        grep -qF "$1" "$W/ev2" && return 0
        sleep 0.2; i=$((i + 1))
    done
    return 1
}
fetch() { HX wget -q --tries=1 -O "$W/dl-$1" -T 20 "http://203.0.113.7/$1" && wc -c < "$W/dl-$1" || echo 0; }
sleep 1
mkfifo "$W/in"
HX "$BIN" --control -d tvs0 -A 1 --interval 5 -r 203.0.113.0/24 < "$W/in" > "$W/ev2" 2> "$W/tun2.log" & TS=$!
exec 8> "$W/in"
{ lnk A; lnk B; echo; } >&8
wait_ev '"ready"' 15
check "swap: first active A" '{"type":"active","nodes":["A"],"index":[0]}' "$(grep '"active"' "$W/ev2" | head -1)"
IFX=$(HX cat /sys/class/net/tvs0/ifindex 2>/dev/null)
case "$IFX" in ''|*[!0-9]*) IFX_OK=no ;; *) IFX_OK=yes ;; esac
check "swap: the device has an ifindex" yes "$IFX_OK"
( fetch long > "$W/long.size" ) & LONG=$!
sleep 1
{ echo nodes; lnk B; echo "garbage-$UUID"; lnk C; echo; } >&8
wait_ev '"type":"nodes"' 2
check "swap: acknowledged with the usable count" '{"type":"nodes","count":2}' "$(grep '"type":"nodes"' "$W/ev2" | head -1)"
wait_ev '"index":[1]' 10
check "swap: B active" '{"type":"active","nodes":["B"],"index":[1]}' "$(grep '"active"' "$W/ev2" | tail -1)"
wait "$LONG"; LONG=""
check "swap: the download through A completes" 1048576 "$(cat "$W/long.size")"
check "swap: no second ready" 1 "$(grep -c '"ready"' "$W/ev2")"
check "swap: the same device" "$IFX" "$(HX cat /sys/class/net/tvs0/ifindex 2>/dev/null)"
sizes=""
for i in 1 2 3 4; do sizes="$sizes $(fetch s$i)"; done
check "swap: new connections go to B" " 2097152 2097152 2097152 2097152" "$sizes"
{ echo nodes; lnk A; lnk C; echo; } >&8
wait_ev '"nodes":["A"]' 10
check "swap: two commands acknowledged" 2 "$(grep -c '"type":"nodes"' "$W/ev2")"
check "swap: A comes back under its first index" '{"type":"active","nodes":["A"],"index":[0]}' "$(grep '"active"' "$W/ev2" | tail -1)"
check "swap: new connections go to A again" 1048576 "$(fetch a1)"
check "swap: every added node's name resolves" 0 "$(grep -c 'does not resolve' "$W/tun2.log")"
check "swap: malformed line named, not shown" 1 "$(grep -c 'line 2: not a vless:// link' "$W/tun2.log")"
check "swap: no link in stderr" 0 "$(grep -c "$UUID" "$W/tun2.log")"
check "swap: no link in stdout" 0 "$(grep -c "vless://\|$UUID" "$W/ev2")"
exec 8>&-
sleep 1
check "swap: stdin closed, the tunnel keeps running" yes "$(kill -0 "$TS" 2>/dev/null && echo yes || echo no)"
echo "control: $pass ok, $fail fail"
[ "$fail" = 0 ]
