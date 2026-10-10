#!/usr/bin/env bash
# End-to-end test: brings up the compose stack, probes allowed and denied paths through the
# gateway, logs in through the portal (including silent re-authentication from Dex's SSO session,
# and the fallback to Dex's form without one), then stops the gateway and checks its rules are gone
# (fail-open).
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
DEX=http://10.10.0.30:5556/dex

# submit_password <service> <user> <form url>: submits Dex's password form from <service>'s browser
# (cookie jar in /tmp/jar), following redirects; prints the final HTTP status.
submit_password() {
    dc exec -T "$1" curl -sk -L -c /tmp/jar -b /tmp/jar -o /dev/null -w "%{http_code}" \
        --data-urlencode "login=$2" --data-urlencode password=password "$3"
}

# login <service> <user>: logs in through the portal as a browser would, submitting Dex's password
# form; prints the final HTTP status. The browser must have no Dex session (see forget_provider),
# or Dex logs it in again as that session's user without showing the form.
login() {
    local form
    form=$(dc exec -T "$1" curl -sk -L -c /tmp/jar -b /tmp/jar -o /dev/null \
        -w "%{url_effective}" "$PORTAL/login")
    submit_password "$1" "$2" "$form"
}

# silent_login <service>: what the portal page's timer does, one top-level GET of /login?silent=1,
# following redirects and submitting nothing; prints "<status> <final url>". The headers of every
# hop are left in /tmp/hops in <service>.
silent_login() {
    dc exec -T "$1" rm -f /tmp/hops
    dc exec -T "$1" curl -sk -L -c /tmp/jar -b /tmp/jar -o /dev/null -D /tmp/hops \
        -w "%{http_code} %{url_effective}" "$PORTAL/login?silent=1"
}

# hops_include <service> <pattern>: yes/no, did a redirect of the last silent_login match?
hops_include() {
    if dc exec -T "$1" grep -qi "^location: .*$2" /tmp/hops 2>/dev/null; then
        echo yes
    else
        echo no
    fi
}

# provider_session <service>: how many Dex SSO session cookies <service>'s browser holds (0 or 1).
provider_session() {
    dc exec -T "$1" grep -c "$(printf '\t')dex_session$(printf '\t')" /tmp/jar || true
}

# forget_provider <service>: drops Dex's SSO session cookie, as signing out of the provider would;
# the portal's cookies stay.
forget_provider() {
    dc exec -T "$1" sed -i '/\tdex_session\t/d' /tmp/jar
}

now_ts() { date +%s.%N; }

# logs_between <service> <since> <until>: <service>'s log lines in the window, colours stripped.
logs_between() {
    dc logs --no-log-prefix --since "$2" --until "$3" "$1" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'
}

# log_has <present|absent> <service> <since> <until> <pattern> <description>: whether <service>
# logged a line matching the extended regex <pattern> in the window; prints the matching lines as
# evidence. Take <since> just before the action, and <until> a second after it, so docker has read
# its lines. Docker stamps lines with the daemon's clock, so this needs a local (Linux) daemon.
log_has() {
    local lines got=absent
    lines=$(logs_between "$2" "$3" "$4" | grep -E -e "$5" || true)
    if [[ -n $lines ]]; then got=present; fi
    report "$1" "$got" "$6"
    if [[ -n $lines ]]; then sed 's/^/      | /' <<<"$lines"; fi
}

# Gateway log lines that would mean a session was not simply extended. Nothing in the run replaces
# a session, so "replaced" has no positive check; the other two do.
NOT_EXTENDED='session (expired|provisioned|replaced)'

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

# nft_counter <chain> <pattern>: total packets counted by the rules in <chain> matching <pattern>.
nft_counter() {
    dc exec -T gateway nft list chain inet drawbridge "$1" | grep -e "$2" |
        grep -o 'packets [0-9]*' | awk '{n += $2} END {print n + 0}'
}

# The base chains' default action: "drop" or "accept" counted over input and forward.
default_counter() {
    echo $(($(nft_counter input "counter .* $1\$") + $(nft_counter forward "counter .* $1\$")))
}

stop_gateway() {
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

echo "== drop log"
# Three datagrams to one destination port, each from a new source port: one key, so one log line.
logged=$(nft_counter drop_log_ports '@drop_seen4 limit')
dropped=$(default_counter drop)
dc exec -T client-denied sh -c "for i in 1 2 3; do echo probe | socat -u - UDP:$SERVER:8080; done"
report 1 $(($(nft_counter drop_log_ports '@drop_seen4 limit') - logged)) "repeated drops are logged once"
got=fewer
(($(default_counter drop) - dropped >= 3)) && got=all
report all "$got" "every repeated datagram is dropped"
report 1 "$(dc exec -T gateway nft list set inet drawbridge drop_seen4 |
    grep -c '172.30.0.11 . 10.10.0.20 . [a-z0-9]* . 8080')" "the dropped key is remembered"
# The ICMP probes above went to the IPv4 set without ports.
got=no
(($(nft_counter drop_log '@drop_seen4_proto limit') > 0)) && got=yes
report yes "$got" "dropped IPv4 ICMP is logged"
report 0 "$(nft_counter drop_log_ports '@drop_seen4 counter')" "no IPv4 key went unlogged"

echo "== gateway running: IPv6"
tcp open   client-allowed $SERVER6 8080
tcp closed client-allowed $SERVER6 9000   # allowed over IPv4 only
tcp closed client-allowed $SERVER6 8081
ping_ open client-allowed $SERVER6
tcp closed client-denied  $SERVER6 8080
ping_ closed client-denied $SERVER6
tcp open   server         fd00:30::10 7000
got=no
(($(nft_counter drop_log_ports '@drop_seen6 limit') > 0)) && got=yes
report yes "$got" "dropped IPv6 TCP is logged"
got=no
(($(nft_counter drop_log '@drop_seen6_proto limit') > 0)) && got=yes
report yes "$got" "dropped ICMPv6 is logged"

echo "== portal login"
tcp open   client-user $GATEWAY 8443   # every client may reach the portal
tcp closed client-user $SERVER 8081
report 403 "$(login client-user bob@example.com)" "bob (no policy) is refused"
tcp closed client-user $SERVER 8081
report 0 "$(session_rules)" "no session after a refused login"
# bob is still signed in to Dex. As in a real browser, another user must sign out of the provider
# first, or Dex silently logs bob in again.
forget_provider client-user
ta=$(now_ts)
report 200 "$(login client-user alice@example.com)" "alice logs in"
sleep 1
log_has present gateway "$ta" "$(now_ts)" "session provisioned" "gateway provisions alice's session"
tcp open   client-user $SERVER 8081
tcp closed client-user $SERVER 8080    # not in alice's allow list
tcp closed client-user $SERVER6 8081   # the session is for the address alice logged in from
tcp closed client-denied $SERVER 8081  # and for no other client
report 1 "$(session_rules)" "one session provisioned"

echo "== session lifetime"
report 1 "$(provider_session client-user)" "Dex keeps an SSO session after the interactive login"
flow_start client-user $SERVER 8082
flow alive client-user "connection opened during the session"
exp1=$(expiry)
cookie1=$(session_cookie)
sleep 3   # expiries have whole-second resolution

# With an SSO session, Dex answers prompt=none itself: no form, nothing submitted.
t0=$(now_ts)
read -r status url <<<"$(silent_login client-user)"
sleep 1
t1=$(now_ts)
report "200 $PORTAL/" "$status $url" "alice re-authenticates silently"
report no "$(hops_include client-user /auth/local/login)" \
    "silent re-authentication shows no login form"
exp2=$(expiry)
got="not later"
((exp2 > exp1)) && got=later
report later "$got" "silent re-authentication extends the session"
report "$cookie1" "$(session_cookie)" "silent re-authentication keeps the session cookie"
log_has present gateway "$t0" "$t1" "session extended" "gateway logs the extension"
log_has absent  gateway "$t0" "$t1" "$NOT_EXTENDED" "gateway neither deprovisions nor re-provisions"
log_has present dex "$t0" "$t1" "re-authenticated from session" "Dex logs in from its SSO session"
log_has absent  dex "$t0" "$t1" "login successful" "Dex sees no interactive login"

# Without an SSO session, Dex answers login_required and the portal falls back to its form. This
# runs before the wait past exp1 so it has plenty of time before exp2.
forget_provider client-user
t2=$(now_ts)
read -r status form <<<"$(silent_login client-user)"
report "200 $DEX/auth/local/login" "$status ${form%%\?*}" \
    "without an SSO session, silent re-authentication lands on Dex's form"
report yes "$(hops_include client-user error=login_required)" "Dex answers login_required"
report 200 "$(submit_password client-user alice@example.com "$form")" "alice re-enters her password"
sleep 1
t3=$(now_ts)
exp3=$(expiry)
got="not later"
((exp3 > exp2)) && got=later
report later "$got" "the fallback login extends the session"
report "$cookie1" "$(session_cookie)" "the fallback login keeps the session cookie"
log_has present gateway "$t2" "$t3" "session extended" "gateway logs the extension"
log_has absent  gateway "$t2" "$t3" "$NOT_EXTENDED" "gateway neither deprovisions nor re-provisions"
log_has present dex "$t2" "$t3" "login successful" "Dex logs an interactive login"
log_has absent  dex "$t2" "$t3" "re-authenticated from session" "Dex had no SSO session to use"

wait_until $((exp1 + 2))
tcp open   client-user $SERVER 8081    # past the first token's expiry
flow alive client-user "connection survives re-authentication"
wait_until $((exp3 + 2))
tcp closed client-user $SERVER 8081    # expired without re-authentication
flow dead  client-user "connection opened during the session dies with it"
report 0 "$(session_rules)" "expired session removed"
# The absent checks above would have seen an expiry: here is one.
log_has present gateway "$t3" "$(now_ts)" "session expired" \
    "gateway deprovisions at the final expiry"

echo "== second instance"
refused "another drawbridge instance holds" "second instance refuses to start" drawbridge run

echo "== gateway stopped"
stop_gateway
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

echo "== permissive mode"
dc exec -d gateway env DRAWBRIDGE_PERMISSIVE=true drawbridge run
for _ in $(seq 40); do
    dc exec -T gateway nft list table inet drawbridge >/dev/null 2>&1 && break
    sleep 0.25
done
logged=$(nft_counter drop_log_ports 'would-drop')
accepted=$(default_counter accept)
# Denied while enforcing (see above), now let through.
tcp open   client-denied $SERVER 8081
udp open   client-denied $SERVER 5353
tcp open   client-denied $SERVER6 8081
tcp open   client-allowed $SERVER 8080   # allowed traffic is unaffected
got=no
(($(nft_counter drop_log_ports 'would-drop') > logged)) && got=yes
report yes "$got" "traffic outside the policy is logged as would-drop"
got=no
(($(default_counter accept) > accepted)) && got=yes
report yes "$got" "traffic outside the policy reaches the accepting default action"
stop_gateway

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
