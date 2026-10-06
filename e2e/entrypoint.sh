#!/bin/sh
# Per-role setup for the e2e stack. Listeners are plain `nc -lk` so tests can probe with `nc -z`;
# clients and server touch /tmp/ready once routed, for their healthcheck.
set -eu

listen() {
    for port in "$@"; do nc -lk "$port" >/dev/null </dev/null & done
}

case "$1" in
gateway)
    listen 2222 2223
    # Keep the container alive after the gateway exits so tests can inspect the aftermath.
    drawbridge run || echo "drawbridge exited with $?"
    exec sleep infinity
    ;;
client)
    ip route add 10.10.0.0/24 via 172.30.0.2
    listen 7000
    touch /tmp/ready
    exec sleep infinity
    ;;
server)
    ip route add 172.30.0.0/24 via 10.10.0.2
    listen 8080 8081 9000 9001
    touch /tmp/ready
    exec sleep infinity
    ;;
*)
    echo "unknown role: $1" >&2
    exit 2
    ;;
esac
