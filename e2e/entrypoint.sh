#!/bin/sh
# Per-role setup for the e2e stack. Listeners are dual-stack socat processes so tests can probe
# them over IPv4 and IPv6; clients and server touch /tmp/ready once routed, for their healthcheck.
set -eu

# TCP listeners that accept and immediately close; enough for `nc -z` probes.
listen() {
    for port in "$@"; do
        socat "TCP6-LISTEN:$port,ipv6only=0,reuseaddr,fork" EXEC:/bin/true &
    done
}

# UDP echo services, probed by sending a datagram and expecting it back.
echo_udp() {
    for port in "$@"; do
        socat "UDP6-RECVFROM:$port,ipv6only=0,reuseaddr,fork" EXEC:/bin/cat &
    done
}

# Emulates WireGuard's lack of neighbour discovery on the external network (see compose.yaml).
pin_neighbour() { # pin_neighbour <ipv6> <mac> <dev>
    ip -6 neigh replace "$1" lladdr "$2" dev "$3" nud permanent
}

case "$1" in
gateway)
    pin_neighbour fd00:30::10 02:00:00:30:00:10 wg0
    pin_neighbour fd00:30::11 02:00:00:30:00:11 wg0
    listen 2222 2223
    # Keep the container alive after the gateway exits so tests can inspect the aftermath.
    drawbridge run || echo "drawbridge exited with $?"
    exec sleep infinity
    ;;
client)
    ip route add 10.10.0.0/24 via 172.30.0.2
    ip -6 route add fd00:10::/64 via fd00:30::2
    pin_neighbour fd00:30::2 02:00:00:30:00:02 eth0
    listen 7000
    touch /tmp/ready
    exec sleep infinity
    ;;
server)
    ip route add 172.30.0.0/24 via 10.10.0.2
    ip -6 route add fd00:30::/64 via fd00:10::2
    # 8999 and 9002 sit just outside the allowed 9000-9001 range.
    listen 8080 8081 8999 9000 9001 9002
    echo_udp 5353 8080
    touch /tmp/ready
    exec sleep infinity
    ;;
*)
    echo "unknown role: $1" >&2
    exit 2
    ;;
esac
