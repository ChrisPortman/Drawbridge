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

PORTAL=https://172.30.0.2:8443

# login <service> <user> [query]: logs in through the portal as a browser would (cookie jar in
# /tmp/jar), submitting Dex's password form; prints the final HTTP status.
login() {
    # shellcheck disable=SC2016 # expanded by the container's shell
    dc exec -T "$1" sh -c '
        form=$(curl -sk -L -c /tmp/jar -b /tmp/jar -o /dev/null -w "%{url_effective}" "$1/login$3")
        curl -sk -L -c /tmp/jar -b /tmp/jar -o /dev/null -w "%{http_code}" \
            --data-urlencode "login=$2" --data-urlencode password=password "$form"
    ' sh "$PORTAL" "$2" "${3:-}"
}

# The session's expiry (Unix seconds) as the portal reports it to client-user's browser.
expiry() {
    dc exec -T client-user curl -sk -b /tmp/jar "$PORTAL/api/session" |
        grep -o '"expires_at":[0-9]*' | cut -d: -f2
}

session_cookie() {
    dc exec -T client-user awk '/drawbridge_session/ {print $7}' /tmp/jar
}

# Dispatch rules in the gateway's sessions chain.
session_rules() {
    dc exec -T gateway nft list chain inet drawbridge sessions | grep -c ' jump ' || true
}

# flow_start <service> <host> <port>: holds one TCP connection to an echo service open, appending
# a line to /tmp/flow in <service> for each message echoed back.
flow_start() {
    dc exec -T "$1" rm -f /tmp/flow
    dc exec -d "$1" socat -T5 "TCP:$2:$3" \
        SYSTEM:'while echo p && read -r _; do echo ok >>/tmp/flow; sleep 1; done'
}

flow() { # flow <alive|dead> <service> <description>  (is the connection from flow_start passing?)
    local before after got=dead
    before=$(dc exec -T "$2" sh -c 'cat /tmp/flow 2>/dev/null | wc -l')
    sleep 3
    after=$(dc exec -T "$2" sh -c 'cat /tmp/flow 2>/dev/null | wc -l')
    ((after > before)) && got=alive
    report "$1" "$got" "$3"
}

wait_until() { # wait_until <unix seconds>
    local now
    now=$(date +%s)
    if (($1 > now)); then sleep $(($1 - now)); fi
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

echo "== portal login"
tcp open   client-user $GATEWAY 8443   # every client may reach the portal
tcp closed client-user $SERVER 8081
report 403 "$(login client-user bob@example.com)" "bob (no policy) is refused"
tcp closed client-user $SERVER 8081
report 0 "$(session_rules)" "no session after a refused login"
report 200 "$(login client-user alice@example.com)" "alice logs in"
tcp open   client-user $SERVER 8081
tcp closed client-user $SERVER 8080    # not in alice's allow list
tcp closed client-user $SERVER6 8081   # the session is for the address alice logged in from
tcp closed client-denied $SERVER 8081  # and for no other client
report 1 "$(session_rules)" "one session provisioned"

echo "== session lifetime"
flow_start client-user $SERVER 8082
flow alive client-user "connection opened during the session"
exp1=$(expiry)
cookie1=$(session_cookie)
sleep 3
report 200 "$(login client-user alice@example.com '?silent=1')" "alice re-authenticates"
exp2=$(expiry)
got="not later"
((exp2 > exp1)) && got=later
report later "$got" "re-authentication extends the session"
report "$cookie1" "$(session_cookie)" "re-authentication keeps the session cookie"
wait_until $((exp1 + 2))
tcp open   client-user $SERVER 8081    # past the first token's expiry
flow alive client-user "connection survives re-authentication"
wait_until $((exp2 + 2))
tcp closed client-user $SERVER 8081    # expired without re-authentication
flow dead  client-user "connection opened during the session dies with it"
report 0 "$(session_rules)" "expired session removed"

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
tcp open   client-user   $SERVER 8080
tcp open   client-user   $SERVER 8081
tcp open   client-user   $SERVER6 8081
flow_start client-user $SERVER 8082
flow alive client-user "new connection to the echo service"

echo "== misconfiguration"
refused "not found" "unknown external interface refuses to start" \
    drawbridge run --external-iface nope0
refused "is not https" "http issuer refuses to start without opt-in" \
    env DRAWBRIDGE_OIDC_ALLOW_INSECURE_HTTP=false drawbridge run
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
