#!/bin/sh
set -eu

HELPER=${FIRC_ROUTECHECK:?set FIRC_ROUTECHECK to the firc-routecheck binary}
IPT=${IPT_LEGACY:-iptables-legacy}
SAVE=${IPT_LEGACY_SAVE:-iptables-legacy-save}
SAVE6=${IP6T_LEGACY_SAVE:-ip6tables-legacy-save}

if [ -z "${FIRC_ROUTING_INSIDE:-}" ]; then
    if [ "$(id -u)" = 0 ]; then
        exec env FIRC_ROUTING_INSIDE=1 unshare -mn sh "$0" "$@"
    fi
    exec env FIRC_ROUTING_INSIDE=1 unshare -Urmn sh "$0" "$@"
fi

PIDS=""
T=$(mktemp -d)
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    rm -rf "$T"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

for tool in "$IPT" "$SAVE" "$SAVE6"; do command -v "$tool" >/dev/null || fail "$tool is not installed"; done

mount -t tmpfs tmpfs /run
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.ip_forward=1
ip link set lo up

"$HELPER" barrier v6 2>"$T/w6" || fail "the v6 barrier was not written: $(cat "$T/w6")"
"$SAVE6" -t filter > "$T/save6" || fail "$SAVE6 cannot read the table firc wrote"
grep -qxF -- '-A FIRC_POOLREJECT -m conntrack --ctdir ORIGINAL -m connmark --mark 0x40000000/0x40000000 -m mark ! --mark 0x40000000/0x40000000 -j DROP' "$T/save6" ||
    fail "the v6 barrier has no drop of unmarked firc flows: $(cat "$T/save6")"
sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1

netns() {
    unshare -n sleep 600 >/dev/null 2>&1 &
    p=$!
    i=0
    while [ "$(readlink /proc/$p/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || fail "a namespace never appeared"
        sleep 0.05
    done
    echo "$p"
}
in_ns() {
    p=$1
    shift
    nsenter -t "$p" -n "$@"
}

FAR=$(netns); PIDS="$PIDS $FAR"
LAN=$(netns); PIDS="$PIDS $LAN"

ip link add tun0 type veth peer name tun0p
ip link set tun0p netns "$FAR"
ip addr add 10.99.0.1/30 dev tun0
ip link set tun0 up
in_ns "$FAR" ip link set lo up
in_ns "$FAR" ip addr add 10.99.0.2/30 dev tun0p
in_ns "$FAR" ip link set tun0p up
in_ns "$FAR" ip addr add 9.9.9.9/32 dev lo
in_ns "$FAR" ip route add default via 10.99.0.1
nsenter -t "$FAR" -n "$HELPER" serve 9.9.9.9 53 &
PIDS="$PIDS $!"

ip link add lan0 type veth peer name lan0c
ip link set lan0c netns "$LAN"
ip addr add 10.10.1.1/24 dev lan0
ip link set lan0 up
in_ns "$LAN" ip link set lo up
in_ns "$LAN" ip addr add 10.10.1.2/24 dev lan0c
in_ns "$LAN" ip link set lan0c up
in_ns "$LAN" ip route add default via 10.10.1.1
ip route add 9.9.9.9/32 via 10.99.0.2 dev tun0
sleep 0.2

"$HELPER" barrier v4 2>"$T/w4" || fail "the v4 barrier was not written: $(cat "$T/w4")"
"$SAVE" -t filter > "$T/save4" || fail "$SAVE cannot read the table firc wrote"
grep -qxF -- '-A FIRC_POOLREJECT -m conntrack --ctdir ORIGINAL -m connmark --mark 0x40000000/0x40000000 -m mark ! --mark 0x40000000/0x40000000 -j DROP' "$T/save4" ||
    fail "the v4 barrier has no drop of unmarked firc flows: $(cat "$T/save4")"

marks_on() {
    $IPT -t mangle -A PREROUTING -s 10.10.1.2 -j MARK --set-xmark 0x40010000/0x40ff0000
    $IPT -t mangle -A PREROUTING -s 10.10.1.2 -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000
}
send() { # <label> <source port> <want reply>
    got=$(in_ns "$LAN" "$HELPER" send 9.9.9.9 53 0 "$2")
    [ "$got" = "src=10.10.1.2 reply=$3" ] || fail "$1: got \"$got\", want reply=$3"
    echo "ok: $1"
}

marks_on
send "a marked flow passes, and its unmarked replies come back" 40000 yes
$IPT -t mangle -F PREROUTING
send "the same flow without its marks is dropped" 40000 no
send "a new flow that firc never marked passes" 40001 yes
marks_on
send "the flow resumes once its marks are back" 40000 yes
echo "PASS: barrier routing"
