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

udp() { # udp <open|closed> <service> <ipv4 host> <port>  (expects the server to echo)
    local got=closed reply
    reply=$(dc exec -T "$2" sh -c "echo probe | socat -T2 - UDP:$3:$4" 2>/dev/null) || true
    [[ $reply == probe ]] && got=open
    report "$1" "$got" "$2 -> $3:$4/udp"
}

refused() { # refused <expected output pattern> <description> <command...>  (run in gateway)
    local pattern=$1 desc=$2 out status=0 got
    shift 2
    # `timeout` guards against the command wrongly starting a long-running gateway.
    out=$(dc exec -T gateway timeout 10 "$@" 2>&1) || status=$?
    if ((status != 0 && status != 124)) && grep -q "$pattern" <<<"$out"; then
        got=refused
    else
        got="exit $status: $out"
    fi
    report refused "$got" "$desc"
}

SERVER=10.10.0.20
SERVER6=fd00:10::20
GATEWAY=172.30.0.2

echo "== gateway running: IPv4"
tcp open   client-allowed $SERVER 8080
tcp open   client-allowed $SERVER 9000
tcp open   client-allowed $SERVER 9001
tcp closed client-allowed $SERVER 8999   # just below the allowed range
tcp closed client-allowed $SERVER 9002   # just above the allowed range
tcp closed client-allowed $SERVER 8081
udp open   client-allowed $SERVER 5353
udp closed client-allowed $SERVER 8080   # only tcp/8080 is allowed
ping_ open client-allowed $SERVER
tcp open   client-allowed $GATEWAY 2222
tcp closed client-allowed $GATEWAY 2223
tcp closed client-denied  $SERVER 8080
tcp closed client-denied  $SERVER 8081
udp closed client-denied  $SERVER 5353
ping_ closed client-denied $SERVER
tcp closed client-denied  $GATEWAY 2222
tcp open   server         172.30.0.10 7000   # internally originated traffic is not filtered

echo "== gateway running: IPv6"
tcp open   client-allowed $SERVER6 8080
tcp closed client-allowed $SERVER6 9000   # allowed over IPv4 only
tcp closed client-allowed $SERVER6 8081
ping_ open client-allowed $SERVER6
tcp closed client-denied  $SERVER6 8080
ping_ closed client-denied $SERVER6
tcp open   server         fd00:30::10 7000

echo "== second instance"
refused "another drawbridge instance holds" "second instance refuses to start" drawbridge run

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
# Fail-open: everything denied above is now reachable, proving the denials came from the rules.
tcp open   client-denied $SERVER 8081
tcp open   client-denied $SERVER 8999
tcp open   client-denied $SERVER 9002
udp open   client-denied $SERVER 8080
tcp open   client-denied $GATEWAY 2223
tcp open   client-denied $SERVER6 8081
tcp open   client-denied $SERVER6 9000

echo "== misconfiguration"
refused "not found" "unknown external interface refuses to start" \
    drawbridge run --external-iface nope0
if dc exec -T gateway nft list table inet drawbridge >/dev/null 2>&1; then
    report absent present "no table after refused start"
else
    report absent absent "no table after refused start"
fi

if ((failures)); then
    echo "== $failures failure(s); gateway logs:"
    dc logs gateway
    exit 1
fi
echo "== all checks passed"
