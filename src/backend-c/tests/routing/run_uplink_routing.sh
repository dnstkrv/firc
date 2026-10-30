#!/bin/sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BE=$(cd "$HERE/../.." && pwd)
TV=$(cd "$BE/../tunvless" && pwd)

if [ "${FIRC_UPLINK_ROUTING_INNER:-}" != 1 ]; then
    make -s -C "$BE" build/host/fircd >/dev/null || exit 1
    make -s -C "$TV" >/dev/null || exit 1
    T=$(mktemp -d)
    mkdir -p "$T/up" "$T/work"
    FIRC_UPLINK_ROUTING_INNER=1 unshare -Urmn sh -c "mount -t tmpfs tmpfs /run && \
        mount -t overlay overlay -o lowerdir=/etc,upperdir=$T/up,workdir=$T/work /etc && \
        exec sh '$HERE/run_uplink_routing.sh'"
    rc=$?
    chmod -R u+rwx "$T" 2>/dev/null
    rm -rf "$T"
    exit $rc
fi

N=urn
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
W=$(mktemp -d)
export FIRC_TUNNELS_CACHE_DIR="$W/cache"
export FIRC_HWID_PATH="$W/hwid"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
cleanup() {
    [ -n "${FP:-}" ] && kill "$FP" 2>/dev/null && wait "$FP" 2>/dev/null
    ip netns pids $N 2>/dev/null | xargs -r kill 2>/dev/null
    ip netns del $N 2>/dev/null
    if [ "$fail" != 0 ]; then
        echo "--- fircd log (tail)"; tail -n 40 "$W/fircd.log" 2>/dev/null
    fi
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

NX() { ip netns exec $N "$@"; }
ip link set lo up
ip netns add $N
ip link add v0 type veth peer name v1 netns $N
ip addr add 10.78.0.2/24 dev v0
ip addr add 2001:db8:78::2/64 dev v0 nodad
ip link set v0 up
NX ip link set lo up
NX ip addr add 10.78.0.1/24 dev v1
NX ip addr add 2001:db8:78::1/64 dev v1 nodad
NX ip link set v1 up
ip link add v2 type veth peer name v3 netns $N
ip addr add 10.77.0.2/24 dev v2
ip link set v2 up
NX ip addr add 10.77.0.1/24 dev v3
NX ip link set v3 up
ip route add default via 10.78.0.1
ip -6 route add default via 2001:db8:78::1

mkdir -p /etc/firc
cat > /etc/firc/firc.conf <<EOF
configVersion: 0.7.0
app:
  httpWeb:
    enabled: false
  dnsProxy:
    host:
      address: "127.0.0.1"
      port: 13597
    upstream:
      address: 127.0.0.1
      port: 53
    disableRemap53: true
  netfilter:
    iptables:
      chainPrefix: FIRC_
  link: []
EOF
tunnels() {
    cat > /etc/firc/tunnels.yaml <<EOF
tunnels:
  - id: t0
    device: tunvless0
    enable: true
    uplink: iface:$1
    sources:
      - link: "vless://$UUID@[2001:db8:78::1]:10800?security=none&type=tcp#V6"
    active: 1
    interval: 5s
    advanced: { timeout: 3s }
EOF
}

rule6() { ip -6 rule show | grep '^48:'; }
rule4() { ip rule show | grep '^48:'; }
routes6() {
    ip -6 route show table all | grep -vE "(^| )table (local|${TABLE:-local})( |\$)" |
        grep -vE '^unreachable fd[0-9a-f:]+/48 dev lo proto 102 ' |
        grep -vE '^fe80::/64 dev tunvless0 proto kernel '
}
ours6() { grep -vE "^48:[[:space:]]+from all fwmark 0x[0-9a-f]*0000/0xff0000 lookup $TABLE\$"; }

start() {
    TABLE=
    tunnels "$1"
    routes6 > "$W/routes6.before"
    ip -6 rule show > "$W/rules6.before"
    FIRC_TUNVLESS_BIN="$TV/out/tunvless" "$BE/build/host/fircd" --config /etc/firc/firc.conf >> "$W/fircd.log" 2>&1 &
    FP=$!
    i=0
    while [ $i -lt 50 ]; do
        TABLE=$(rule6 | sed -n 's/.* lookup \([0-9]*\).*/\1/p')
        [ -n "$TABLE" ] && [ "$(ip -6 route show table "$TABLE" 2>/dev/null | wc -l)" -ge "$2" ] && break
        sleep 0.2; i=$((i + 1))
    done
    sleep 0.5
}

running() {
    check "$1: one IPv6 rule at 48, on a mark field, to the tunnel's table" "1 1" \
        "$(rule6 | wc -l) $(rule6 | grep -cE "^48:[[:space:]]+from all fwmark 0x[0-9a-f]*0000/0xff0000 lookup $TABLE\$")"
    FW6=$(rule6 | sed -n 's/.* fwmark \([^ ]*\) .*/\1/p')
    FW4=$(rule4 | sed -n 's/.* fwmark \([^ ]*\) .*/\1/p')
    check "$1: the IPv4 rule at 48 carries the same fwmark" "1 $FW6" "$(rule4 | wc -l) $FW4"
    check "$1: the marked rule is the only IPv6 rule added" "" "$(ip -6 rule show | ours6 | diff "$W/rules6.before" -)"
    check "$1: no IPv6 route outside the tunnel's table" "" "$(routes6 | diff "$W/routes6.before" -)"
    ip -6 route show table "$TABLE" > "$W/t6"
}

stop() {
    kill -TERM "$FP"
    wait "$FP"
    rc=$?
    FP=
    check "$1: fircd exits 0 on SIGTERM" 0 "$rc"
    check "$1: no rule at 48 is left in either family" "0 0" "$(rule6 | wc -l) $(rule4 | wc -l)"
    check "$1: the IPv6 rules are as before fircd" "" "$(ip -6 rule show | diff "$W/rules6.before" -)"
    check "$1: the tunnel's IPv6 table is empty" "" "$(ip -6 route show table "$TABLE" 2>/dev/null)"
    check "$1: no IPv6 route is left outside it" "" "$(routes6 | diff "$W/routes6.before" -)"
}

start v0 2
running v0
check "v0: the tunnel's IPv6 table holds the unreachable and the default via v0" "2 1 1" \
    "$(wc -l < "$W/t6") $(grep -cE '^unreachable default .*metric 20' "$W/t6") $(grep -cE '^default via 2001:db8:78::1 dev v0 .*metric 10' "$W/t6")"
stop v0

start v2 1
running v2
check "v2: the tunnel's IPv6 table holds the unreachable only" "1 1" \
    "$(wc -l < "$W/t6") $(grep -cE '^unreachable default .*metric 20' "$W/t6")"
stop v2

echo "uplink routing: $pass ok, $fail fail"
[ "$fail" = 0 ]
