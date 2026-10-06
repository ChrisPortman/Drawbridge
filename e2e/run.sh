#!/usr/bin/env bash
# End-to-end test: brings up the compose stack, probes allowed and denied paths through the
# gateway, then stops the gateway and checks its rules are gone (fail-open).
set -euo pipefail
cd "$(dirname "$0")"

dc() { docker compose -p drawbridge-e2e "$@"; }
trap 'dc down --remove-orphans --timeout 1 >/dev/null 2>&1' EXIT

dc up -d --build --wait

failures=0
report() { # report <expected> <actual> <description>
    if [[ $1 == "$2" ]]; then
        echo "PASS  $3: $1"
    else
        echo "FAIL  $3 (expected $1, got $2)"
        failures=$((failures + 1))
    fi
}

tcp() { # tcp <open|closed> <service> <host> <port>
    local got=closed
    dc exec -T "$2" nc -z -w2 "$3" "$4" 2>/dev/null && got=open
    report "$1" "$got" "$2 -> $3:$4/tcp"
}

ping_() { # ping_ <open|closed> <service> <host>
    local got=closed
    dc exec -T "$2" ping -c1 -W2 "$3" >/dev/null && got=open
    report "$1" "$got" "$2 -> $3 icmp"
}

SERVER=10.10.0.20
GATEWAY=172.30.0.2

echo "== gateway running"
tcp open   client-allowed $SERVER 8080
tcp open   client-allowed $SERVER 9000
tcp open   client-allowed $SERVER 9001
tcp closed client-allowed $SERVER 8081
ping_ open client-allowed $SERVER
tcp open   client-allowed $GATEWAY 2222
tcp closed client-allowed $GATEWAY 2223
tcp closed client-denied  $SERVER 8080
tcp closed client-denied  $SERVER 8081
ping_ closed client-denied $SERVER
tcp closed client-denied  $GATEWAY 2222
tcp open   server         172.30.0.10 7000   # internally originated traffic is not filtered

echo "== gateway stopped"
dc exec -T gateway pkill -TERM -x drawbridge
for _ in $(seq 20); do
    dc exec -T gateway pgrep -x drawbridge >/dev/null || break
    sleep 0.25
done
if dc exec -T gateway nft list table inet drawbridge >/dev/null 2>&1; then
    report absent present "drawbridge table removed"
else
    report absent absent "drawbridge table removed"
fi
tcp open   client-denied $SERVER 8081
tcp open   client-denied $GATEWAY 2223

if ((failures)); then
    echo "== $failures failure(s); gateway logs:"
    dc logs gateway
    exit 1
fi
echo "== all checks passed"
