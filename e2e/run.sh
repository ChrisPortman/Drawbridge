#!/usr/bin/env bash
# End-to-end test: brings up the compose stack, probes allowed and denied paths through the
# gateway, logs in through the portal (refreshing the session, re-authenticating silently from
# Dex's SSO session, and falling back to Dex's form without one), logs in with `drawbridge client`
# and its (stubbed) user service, then stops the gateway and checks its rules are gone
# (fail-open). Finally it restarts the gateway without refresh tokens and in permissive mode.
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
# a session, so "replaced" has no positive check; the others do.
NOT_EXTENDED='session (expired|provisioned|replaced|ended)'

# The session's expiry (Unix seconds) as the portal reports it to client-user's browser.
expiry() {
    dc exec -T client-user curl -sk -b /tmp/jar "$PORTAL/api/session" |
        grep -o '"expires_at":[0-9]*' | cut -d: -f2
}

session_cookie() {
    dc exec -T client-user awk '/drawbridge_session/ {print $7}' /tmp/jar
}

# page_refresh <service> [unmarked]: what the portal page's timer does, a POST to
# /api/session/refresh with the browser's cookies; prints the HTTP status. "unmarked" leaves out
# the X-Drawbridge header a cross-site request couldn't send. The body is left in /tmp/refresh.
page_refresh() {
    local header=(-H "X-Drawbridge: 1")
    [[ ${2:-} == unmarked ]] && header=()
    dc exec -T "$1" curl -sk -b /tmp/jar -c /tmp/jar -X POST "${header[@]}" -o /tmp/refresh \
        -w "%{http_code}" "$PORTAL/api/session/refresh"
}

# `drawbridge client` runs as the unprivileged `user` of client-user, with systemctl-stub standing
# in for its user service manager.
AS_USER=(-u user -e HOME=/home/user -e XDG_RUNTIME_DIR=/run/user/1000
    -e DRAWBRIDGE_SYSTEMCTL=systemctl-stub)
cli() { dc exec -T "${AS_USER[@]}" client-user drawbridge client "$@"; }
stub() { dc exec -T "${AS_USER[@]}" client-user systemctl-stub --user "$@"; }
unit_state() { stub show drawbridge-client.service | sed -n 's/^ActiveState=//p'; }
service_log() { dc exec -T client-user cat /run/user/1000/stub/service.log 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g'; }
service_running() { dc exec -T client-user pgrep -u user -f 'drawbridge client service' >/dev/null; }
evidence() { sed 's/^/      | /'; } # indents command output printed as evidence

# start_bg <name> <command...>: runs <command> as `user` in client-user in the background, its
# output in /tmp/<name>.out and its exit status, once done, in /tmp/<name>.status.
start_bg() {
    local name=$1
    shift
    dc exec -T client-user rm -f "/tmp/$name.out" "/tmp/$name.status"
    dc exec -d "${AS_USER[@]}" client-user sh -c \
        "$* >/tmp/$name.out 2>&1; echo \$? >/tmp/$name.status"
}

bg_status() { dc exec -T client-user cat "/tmp/$1.status" 2>/dev/null || echo running; }

wait_bg() { # wait_bg <name>: waits up to 15s for it to finish; prints its exit status
    for _ in $(seq 60); do
        [[ $(bg_status "$1") != running ]] && break
        sleep 0.25
    done
    bg_status "$1"
}

# login_url <command...>: waits up to 10s for <command> to print the portal's command-line login
# URL; prints it.
login_url() {
    local url
    for _ in $(seq 40); do
        url=$("$@" 2>/dev/null | grep -o "$PORTAL/login?cli_port=[^ ]*" | head -n1) || true
        [[ -n $url ]] && break
        sleep 0.25
    done
    echo "$url"
}

# drive_login <url>: what the user does in the browser the service opened: follows <url> to Dex's
# form and submits alice's password; prints "<status> <final url>", which should be the service's
# loopback listener.
drive_login() {
    local form
    form=$(dc exec -T client-user curl -sk -L -c /tmp/jar -b /tmp/jar -o /dev/null \
        -w "%{url_effective}" "$1")
    dc exec -T client-user curl -sk -L -c /tmp/jar -b /tmp/jar -o /dev/null \
        -w "%{http_code} %{url_effective}" \
        --data-urlencode login=alice@example.com --data-urlencode password=password "$form"
}

# The loopback URL drive_login should end on.
LOOPBACK='^200 http://127\.0\.0\.1:[0-9]+/\?code=[0-9a-f]{64}&state=[A-Za-z0-9_-]+$'
matches() { if [[ $1 =~ $2 ]]; then echo yes; else echo "no ($1)"; fi; }

# wait_for_portal: after a gateway restart, until the portal answers.
wait_for_portal() {
    for _ in $(seq 40); do
        dc exec -T client-user curl -sk -o /dev/null "$PORTAL/" && break
        sleep 0.25
    done
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

# The page's timer refreshes through the gateway, which holds Dex's refresh token.
report 403 "$(page_refresh client-user unmarked)" "a refresh without the request header is refused"
tr=$(now_ts)
report 200 "$(page_refresh client-user)" "the page refreshes alice's session"
sleep 1
tr1=$(now_ts)
expr=$(expiry)
got="not later"
((expr > exp1)) && got=later
report later "$got" "the refresh extends the session"
report "$cookie1" "$(session_cookie)" "the refresh keeps the session cookie"
log_has present gateway "$tr" "$tr1" 'session extended.*via="?refresh' "gateway logs the refresh"
log_has absent  gateway "$tr" "$tr1" "$NOT_EXTENDED" "gateway neither deprovisions nor re-provisions"
log_has absent  dex "$tr" "$tr1" "login successful|re-authenticated from session" \
    "Dex sees no login for the refresh"
sleep 2

# The page's fallback when a session has no refresh token (see "browser without refresh tokens"
# below): with an SSO session, Dex answers prompt=none itself: no form, nothing submitted.
t0=$(now_ts)
read -r status url <<<"$(silent_login client-user)"
sleep 1
t1=$(now_ts)
report "200 $PORTAL/" "$status $url" "alice re-authenticates silently"
report no "$(hops_include client-user /auth/local/login)" \
    "silent re-authentication shows no login form"
exp2=$(expiry)
got="not later"
((exp2 > expr)) && got=later
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


echo "== client CLI"
# The user service logs in through the browser and refreshes the session until it is stopped.
report 0 "$(cli init --portal-url "$PORTAL" --insecure-skip-tls-verify --no-browser \
    >/dev/null; echo $?)" "client init succeeds"
unit=$(dc exec -T client-user cat /home/user/.config/systemd/user/drawbridge-client.service)
evidence <<<"$unit"
report yes "$(grep -q '^Type=notify$' <<<"$unit" && grep -q 'client service$' <<<"$unit" &&
    echo yes || echo no)" "the unit runs the service as Type=notify"
report yes "$(dc exec -T client-user grep -q 'daemon-reload' /home/user/systemctl.log &&
    echo yes || echo no)" "client init reloads the user manager"
tcp closed client-user $SERVER 8081
forget_provider client-user

start_bg cli-login drawbridge client login
url=$(login_url dc exec -T client-user cat /tmp/cli-login.out)
report yes "$(matches "$url" "^$PORTAL/login\?cli_port=[0-9]+&cli_challenge=[A-Za-z0-9_-]{43}&cli_state=[A-Za-z0-9_-]+$")" \
    "client login prints the login URL"
report running "$(bg_status cli-login)" "client login waits for the browser login"
report activating "$(unit_state)" "the service is starting"
tl=$(now_ts)
report yes "$(matches "$(drive_login "$url")" "$LOOPBACK")" \
    "the browser login lands on the service's loopback listener"
L=$(date +%s)
report 0 "$(wait_bg cli-login)" "client login returns once logged in"
report active "$(unit_state)" "the service is active"
echo "      client login output:"
dc exec -T client-user cat /tmp/cli-login.out | evidence
report yes "$(dc exec -T client-user grep -q '^Logged in as alice@example.com' /tmp/cli-login.out &&
    echo yes || echo no)" "client login reports the logged-in user"
log_has present gateway "$tl" "$(now_ts)" "session provisioned" "gateway provisions the CLI session"
# The portal's certificate is self-signed, so the e2e turns the client's checks off.
report yes "$(service_log | grep -q 'TLS certificate checks for the portal are off' && echo yes ||
    echo no)" "the service warns that certificate checks are off"
tcp open   client-user $SERVER 8081
flow_start client-user $SERVER 8082
flow alive client-user "connection opened during the CLI session"

# The ID token expires at about L+30; the service refreshes at about L+24 and again at L+48,
# with the refresh token Dex rotated the first time.
wait_until $((L + 33))
tcp open   client-user $SERVER 8081    # past the first token's expiry
flow alive client-user "connection survives the service's refresh"
t4=$(now_ts)
log_has present gateway "$tl" "$t4" 'session extended.*via="?refresh' "gateway logs the service's refresh"
log_has absent  gateway "$((L + 1))" "$t4" "$NOT_EXTENDED" "gateway neither deprovisions nor re-provisions"
log_has absent  dex "$((L + 1))" "$t4" "login successful|re-authenticated from session" \
    "Dex sees no login for the refresh"
wait_until $((L + 57))
tcp open   client-user $SERVER 8081    # past the first refresh's expiry
report 2 "$(logs_between gateway "$tl" "$(now_ts)" | grep -cE 'session extended.*via="?refresh')" \
    "the service refreshes twice, with the rotated refresh token"
echo "      service log:"
service_log | evidence || true

tq=$(now_ts)
status=0
out=$(cli logout) || status=$?
report 0 "$status" "client logout succeeds"
evidence <<<"$out"
tcp closed client-user $SERVER 8081    # the session still had about 20s to run
flow dead  client-user "logout cuts the connection"
report 0 "$(session_rules)" "logout removes the session"
sleep 1
log_has present gateway "$tq" "$(now_ts)" "session ended" "gateway ends the session at logout"
log_has absent  gateway "$tq" "$(now_ts)" "session expired" "the session did not just expire"
report yes "$(service_log | grep -q 'session ended at the gateway' && echo yes || echo no)" \
    "the service ends the session as it stops"
report inactive "$(unit_state)" "the service is stopped"
got=gone
service_running && got=running
report gone "$got" "no service process is left"

# Plain systemctl works the same: start blocks until logged in, stop logs out.
forget_provider client-user
start_bg stub-start systemctl-stub --user start drawbridge-client.service
url=$(login_url stub show drawbridge-client.service)
report yes "$(matches "$(drive_login "$url")" "$LOOPBACK")" \
    "systemctl start: the browser login lands on the loopback listener"
report 0 "$(wait_bg stub-start)" "systemctl start returns once logged in"
tcp open   client-user $SERVER 8081
tq=$(now_ts)
stub stop drawbridge-client.service || true
tcp closed client-user $SERVER 8081
sleep 1
log_has present gateway "$tq" "$(now_ts)" "session ended" "systemctl stop ends the session"

echo "== second instance"
refused "another drawbridge instance holds" "second instance refuses to start" \
    drawbridge server run

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

echo "== browser without refresh tokens"
# Without offline_access Dex issues no refresh tokens: the page's refresh gets 409 and falls back
# to re-authenticating silently, and the client service can't keep its session.
# Logging to the container's output (PID 1's), where `dc logs` and log_has see it.
dc exec -d gateway sh -c \
    'DRAWBRIDGE_OIDC_SCOPES=profile,email exec drawbridge server run >/proc/1/fd/1 2>&1'
wait_for_portal
forget_provider client-user
report 200 "$(login client-user alice@example.com)" "alice logs in"
report 409 "$(page_refresh client-user)" "the refresh is refused"
report yes "$(dc exec -T client-user grep -q refresh_unavailable /tmp/refresh && echo yes ||
    echo no)" "the gateway says the session can't be refreshed"
t5=$(now_ts)
read -r status url <<<"$(silent_login client-user)"
sleep 1
report "200 $PORTAL/" "$status $url" "the page's fallback re-authenticates silently"
log_has present gateway "$t5" "$(now_ts)" 'session extended.*via="?login' \
    "gateway extends the session through the fallback"
log_has present dex "$t5" "$(now_ts)" "re-authenticated from session" "Dex logs in from its SSO session"

# The service shares alice's session from this address, which has no refresh token. It keeps
# the session until it expires, so logging out still ends it.
forget_provider client-user
start_bg cli-login drawbridge client login
url=$(login_url dc exec -T client-user cat /tmp/cli-login.out)
report yes "$(matches "$(drive_login "$url")" "$LOOPBACK")" "the service logs in"
L=$(date +%s)
report 0 "$(wait_bg cli-login)" "client login returns once logged in"
wait_until $((L + 26))   # the service tried to refresh at about L+24; the session ends at L+30
report yes "$(service_log | grep -q 'cannot refresh this session' && echo yes || echo no)" \
    "the service says the session can't be refreshed"
report active "$(unit_state)" "the service holds the session until it expires"
tcp open   client-user $SERVER 8081
tq=$(now_ts)
cli logout >/dev/null || true
tcp closed client-user $SERVER 8081   # the session had a few seconds left
sleep 1
log_has present gateway "$tq" "$(now_ts)" "session ended" "logout still ends the session"

# Left alone, it fails at the expiry, and nothing restarts it.
forget_provider client-user
start_bg cli-login drawbridge client login
url=$(login_url dc exec -T client-user cat /tmp/cli-login.out)
report yes "$(matches "$(drive_login "$url")" "$LOOPBACK")" "the service logs in again"
L=$(date +%s)
report 0 "$(wait_bg cli-login)" "client login returns once logged in"
wait_until $((L + 33))
report failed "$(unit_state)" "the service fails once the session expires"
report yes "$(service_log | grep -qx 'exited 1' && echo yes || echo no)" \
    "the service exits with a failure, and nothing restarts it"
tcp closed client-user $SERVER 8081
stop_gateway

echo "== permissive mode"
dc exec -d gateway env DRAWBRIDGE_PERMISSIVE=true drawbridge server run
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
    drawbridge server run --external-iface nope0
refused "is not https" "http issuer refuses to start without opt-in" \
    env DRAWBRIDGE_OIDC_ALLOW_INSECURE_HTTP=false drawbridge server run
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
