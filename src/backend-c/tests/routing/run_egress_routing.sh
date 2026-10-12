#!/bin/sh
set -eu

HELPER=${FIRC_ROUTECHECK:?set FIRC_ROUTECHECK to the firc-routecheck binary}
IPT=${IPT_LEGACY:-iptables-legacy}
IPT6=${IP6T_LEGACY:-ip6tables-legacy}
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

for tool in "$IPT" "$IPT6" "$SAVE" "$SAVE6"; do command -v "$tool" >/dev/null || fail "$tool is not installed"; done

mount -t tmpfs tmpfs /run
sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.forwarding=1
ip link set lo up

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

link() { # <router side> <far side> <v4 net> <v6 net>
    ip link add "$1" type veth peer name "$2"
    ip link set "$2" netns "$FAR"
    ip addr add "$3.1/30" dev "$1"
    ip addr add "$4::1/64" dev "$1" nodad
    ip link set "$1" up
    in_ns "$FAR" ip addr add "$3.2/30" dev "$2"
    in_ns "$FAR" ip addr add "$4::2/64" dev "$2" nodad
    in_ns "$FAR" ip link set "$2" up
}
in_ns "$FAR" ip link set lo up
link tun0 tun0p 10.99.0 fd99
link wan0 wan0p 10.98.0 fd98
in_ns "$FAR" ip addr add 9.9.9.9/32 dev lo
in_ns "$FAR" ip addr add 2001:db8:9::9/128 dev lo
in_ns "$FAR" ip route add 10.10.1.0/24 via 10.99.0.1
in_ns "$FAR" ip -6 route add fd10::/64 via fd99::1
nsenter -t "$FAR" -n "$HELPER" serve 9.9.9.9 53 &
PIDS="$PIDS $!"
nsenter -t "$FAR" -n "$HELPER" serve 2001:db8:9::9 53 &
PIDS="$PIDS $!"

ip link add lan0 type veth peer name lan0c
ip link set lan0c netns "$LAN"
ip addr add 10.10.1.1/24 dev lan0
ip addr add fd10::1/64 dev lan0 nodad
ip link set lan0 up
in_ns "$LAN" ip link set lo up
in_ns "$LAN" ip addr add 10.10.1.2/24 dev lan0c
in_ns "$LAN" ip addr add fd10::2/64 dev lan0c nodad
in_ns "$LAN" ip link set lan0c up
in_ns "$LAN" ip route add default via 10.10.1.1
in_ns "$LAN" ip -6 route add default via fd10::1
nsenter -t "$LAN" -n "$HELPER" serve 10.10.1.2 53 &
PIDS="$PIDS $!"
nsenter -t "$LAN" -n "$HELPER" serve fd10::2 53 &
PIDS="$PIDS $!"

ip route add 9.9.9.9/32 via 10.98.0.2 dev wan0
ip -6 route add 2001:db8:9::9/128 via fd98::2 dev wan0
ip route add default via 10.99.0.2 dev tun0 table 100
ip -6 route add default via fd99::2 dev tun0 table 100
ip route add default via 10.98.0.2 dev wan0 table 200
ip -6 route add default via fd98::2 dev wan0 table 200
i=0
while ip -6 addr | grep -q tentative || in_ns "$FAR" ip -6 addr | grep -q tentative || in_ns "$LAN" ip -6 addr | grep -q tentative; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "IPv6 addresses stayed tentative"
    sleep 0.05
done
sleep 0.2

GUARD='-A FIRC_EGRESS ! -i tun0 ! -o tun0 -m mark --mark 0x40010000/0x40ff0000 -m conntrack --ctdir ORIGINAL -j DROP'
UNMARKED='-A FIRC_EGRESS -m mark --mark 0x0/0x40000000 -j RETURN'

pkts() { # <iptables> <chain> [target]
    $1 -t filter -L "$2" -v -x -n | awk -v t="${3:-}" 'NR > 2 && (t == "" || $3 == t) { s += $1 } END { print s + 0 }'
}
mark_from() { # <iptables> <match words> <mark>
    $1 -t mangle -A PREROUTING $2 -j MARK --set-xmark "$3/0x40ff0000"
    $1 -t mangle -A PREROUTING $2 -j CONNMARK --save-mark --nfmask 0x40ff0000 --ctmask 0x40ff0000
}
unmark() { # <iptables>
    $1 -t mangle -F PREROUTING
}
send() { # <label> <namespace> <destination> <source> <source port> <want reply>
    got=$(in_ns "$2" "$HELPER" send "$3" 53 0 "$5")
    [ "$got" = "src=$4 reply=$6" ] || fail "$1: got \"$got\", want src=$4 reply=$6"
    echo "ok: $1"
}

egress() { # <family> <iptables> <save> <ip> <far> <lan> <tunnel peer>
    f=$1 ipt=$2 save=$3 ipf=$4 far=$5 lan=$6
    "$HELPER" egress "$f" tun0 2>"$T/w" || fail "$f: the group was not written: $(cat "$T/w")"
    "$save" -t filter > "$T/save" || fail "$save cannot read the table firc wrote"
    grep -qxF -- "$UNMARKED" "$T/save" || fail "$f: the dispatch chain does not return unmarked traffic: $(cat "$T/save")"
    grep -qxF -- "$GUARD" "$T/save" || fail "$f: the guard is not as written: $(cat "$T/save")"
    [ "$(grep -m1 -- '^-A FORWARD ' "$T/save")" = "-A FORWARD -j FIRC_POOLREJECT" ] ||
        fail "$f: the pool barrier is not first in FORWARD: $(cat "$T/save")"
    grep -qxF -- "-A FORWARD -j FIRC_EGRESS" "$T/save" || fail "$f: FORWARD does not jump to the guard"
    $ipt -t nat -A POSTROUTING -o wan0 -j MASQUERADE
    ip $ipf rule add pref 50 fwmark 0x10000/0xff0000 lookup 100

    mark_from "$ipt" "-s $lan" 0x40010000
    before=$(pkts "$ipt" FIRC_g1)
    send "$f: a marked flow leaves by its group's interface" "$LAN" "$far" "$lan" 41000 yes
    [ "$(pkts "$ipt" FIRC_g1)" -gt "$before" ] || fail "$f: the marked flow did not leave by tun0"

    ip $ipf rule del pref 50
    before=$(pkts "$ipt" FIRC_EGRESS DROP)
    send "$f: with its ip rule gone, a marked flow is not let out by main" "$LAN" "$far" "$lan" 41001 no
    [ "$(pkts "$ipt" FIRC_EGRESS DROP)" -gt "$before" ] || fail "$f: something other than the guard dropped it"
    ip $ipf rule add pref 50 fwmark 0x10000/0xff0000 lookup 100
    ip $ipf rule add pref 10 fwmark 0x10000/0xff0000 lookup 200
    send "$f: a marked flow a foreign rule steals to another interface is dropped" "$LAN" "$far" "$lan" 41002 no
    ip $ipf rule del pref 10
    send "$f: and leaves by its group's interface once the rule is gone" "$LAN" "$far" "$lan" 41003 yes

    ip $ipf rule del pref 50
    unmark "$ipt"
    before=$(pkts "$ipt" FIRC_EGRESS RETURN)
    send "$f: an unmarked flow leaves by main" "$LAN" "$far" "$lan" 41004 yes
    [ "$(pkts "$ipt" FIRC_EGRESS RETURN)" -gt "$before" ] || fail "$f: unmarked traffic did not return at the dispatch chain's head"
    mark_from "$ipt" "-s $lan" 0x10000
    send "$f: a mark carrying the field without firc's bit is not firc's" "$LAN" "$far" "$lan" 41005 yes
    unmark "$ipt"
    $ipt -t mangle -A PREROUTING -i wan0 -j MARK --set-xmark 0x40010000/0x40ff0000
    send "$f: a reply carrying the mark is not an original packet" "$LAN" "$far" "$lan" 41006 yes
    unmark "$ipt"

    mark_from "$ipt" "-i tun0" 0x40010000
    if [ "$f" = v4 ]; then
        ip $ipf rule add pref 50 fwmark 0x10000/0xff0000 lookup 100
        ip $ipf rule add pref 49 iif tun0 fwmark 0x10000/0xff0000 lookup main suppress_prefixlength 0
        send "$f: a marked flow coming in by the group's interface goes to the LAN by the reply twin" "$FAR" "$lan" "$7" 41007 yes
        ip $ipf rule del pref 49
        ip $ipf rule del pref 50
    else
        send "$f: a marked flow coming in by the group's interface goes to the LAN by main" "$FAR" "$lan" "$7" 41007 yes
    fi
    unmark "$ipt"
}

egress v4 "$IPT" "$SAVE" -4 9.9.9.9 10.10.1.2 10.99.0.2
egress v6 "$IPT6" "$SAVE6" -6 2001:db8:9::9 fd10::2 fd99::2
echo "PASS: egress routing"
