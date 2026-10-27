# 0004: Host rules through a transparent proxy

- Issue: https://github.com/ChrisPortman/Drawbridge/issues/7 (#7)
- Status: Accepted
- Date: 2026-10-18

## Context

Admins want to allow HTTPS by hostname and HTTP by hostname and path, not only by IP. nftables only
sees L3/L4, so it can't make these decisions. Drawbridge has to look at the TLS ClientHello (SNI)
or the HTTP request itself.

This touches several invariants in `AGENTS.md`:
- the single `inet drawbridge` table layout, and "nothing else drops";
- one session change is one batch;
- Drawbridge owns the conntrack mark;
- Validation errors name `clients[i].allow[j]` / `users[i].allow[j]`.

## Scope

**In scope:**
- `proto: http|https` allow rules with `hosts`, for clients (always) and users (while a session
  lasts);
- a built-in proxy;
- nftables redirection to the proxy;
- drop logs for what the proxy denies;
- permissive mode;
- IPv4 and IPv6.

**Out of scope:**
- terminating TLS;
- detecting domain fronting;
- cleartext HTTP/2 (h2c);
- defining how client and session rules combine when they overlap (#8).

**Assumptions:**
- Until #8 is resolved, a source IP's host rules are the union of its client rules and its live
  session's rules. This matches how nftables already combines them. The e2e policy has a client
  CIDR (`172.30.0.0/24`) that contains the user-session IPs, so the two do overlap there.

## Definition of done

- Policy schema and validation for host rules, with unit tests.
- `ruleset.rs` IR and rendering for the nat `prerouting` chain, the `proxy_redirect` chain and the
  proxy accept rule, with unit tests.
- `firewall/json.rs` encodes `redirect` and `ct status dnat` as nft JSON that nftables 0.9.3
  accepts, with unit tests and the `example.json` golden regenerated.
- The proxy handles SNI and HTTP, RST and 404, Upgrade, timeouts and size limits, with unit tests.
- The proxy reads a session view, and ending a session closes its proxied connections.
- Deduplicated `drawbridge drop:` / `drawbridge would-drop:` log lines.
- `--proxy-port` / `DRAWBRIDGE_PROXY_PORT` is required when the policy has host rules.
- Regenerated `example.nft`, `example.json`, `example.kernel.nft` and `sessions.kernel.nft`; `tests/kernel.rs`
  extended.
- e2e checks:
  - client http: allowed path, denied path (404), denied host (RST);
  - client https: allowed SNI, denied SNI, no SNI;
  - user rule: denied before login and allowed after, and logout cuts an open connection;
  - an IP rule doesn't bypass a host rule;
  - permissive mode;
  - open checks after shutdown.
- README and AGENTS.md updated.

## Decisions

**Schema.**
- Options:
  - (a) Overload `dest` with hostnames and add `dest_ip`, as in the issue.
  - (b) Add `hosts`, and keep `dest` as backend CIDRs.
- Chosen: (b), so that `dest` keeps one meaning in every rule.
- `ports` is allowed, defaulting to 80 for http and 443 for https.

**Matching.**
- Hosts match exactly, or by a leading `*.` wildcard (one or more labels, not the apex). Matching
  is case-insensitive, and a trailing dot is ignored.
- Paths match as a prefix on `/` boundaries: `/a/b` matches `/a/b` and `/a/b/c`, but not `/a/bc`.

**Upstream.**
- The proxy connects to the connection's original destination, and only if that address is in
  the matched rule's `dest`.
- The alternative was to connect to a configured IP whatever the client was aiming at. That would
  let a client with any allowed hostname reach any backend by sending that SNI, which makes the
  proxy an open relay.

**TLS.**
- The proxy reads the SNI from the ClientHello and splices the connection without terminating
  TLS. Terminating would need a CA on every client.
- A ClientHello with no SNI, or using ECH, is denied.
- Domain fronting can't be detected; this limitation is accepted.

**Denials.**
- A denied host (SNI or `Host`), `CONNECT`, h2c, a timeout, an oversized head, and an upstream
  failure all get a TCP RST "to look a bit more like a firewall" (user's choice over a 403).
- An allowed host with a denied path gets `404 Not Found`, and the connection stays open. A 403
  would tell an attacker that the path exists but is denied.
- Every HTTP request on a keep-alive connection is checked. Checking only the first would let a
  client open with an allowed path and then reuse the connection for anything.

**Redirection and precedence.**
- Two alternatives were considered:
  - (a) redirect only traffic to host rules' `dest` and ports;
  - (b) redirect all web traffic, to log every request by host.
- Chosen: (a), with host rules taking precedence over IP rules for the same source, destination
  and port.
- The redirect happens in a new nat `prerouting` base chain (`iifname <ext> jump
  proxy_redirect`), before the filter chains. A redirected packet's destination is then the
  gateway, so IP rules can't accept it as the backend.
- `client_filter` accepts `tcp dport <proxy port> ct status dnat`, so only redirected flows reach
  the proxy.
- `proxy_redirect` is rebuilt in the session batch, so a session change is still one batch.

**Session end.**
- The proxy closes connections that a session's rule allowed when that session ends (logout,
  expiry or replacement).
- Session redirect rules also set the session's ct mark, so the kernel cuts the client side
  through `session_flows` exactly as it does for IP flows.

**Proxy state.**
- The session task publishes a view (source IP → session id and host rules) on a `watch`
  channel. The session task stays the only writer of session state.

**Logging.**
- Lines in nft-log style: `drawbridge drop: SRC= DST= PROTO= DPT= HOST= [PATH=] [REASON=]`,
  deduplicated per key every 10s.
- Permissive mode lets denied traffic through and logs it as `drawbridge would-drop:`, matching
  the firewall's permissive behaviour.

**HTTP implementation.**
- Options: hyper (already a dependency through axum), or a parser hand-written on httparse.
- Chosen: hyper, for correct keep-alive, pipelining and Upgrade handling, and because it resolves
  request-smuggling ambiguities.
- Trade-off accepted: forwarding isn't byte-transparent, because hyper normalises headers.

**TLS parsing.**
- A hand-written ClientHello parser. rustls' `Acceptor` can't report ECH and consumes its input,
  and tls-parser is a heavy dependency.

**Kernel encoding.**
- Drawbridge drives nftables through the `nft` binary with JSON (ADR 0003), so `redirect` and
  `ct status dnat` are ordinary statements in `firewall/json.rs`. They must stay within what
  nft 0.9.3 parses. A kernel without `nft_redir`/`nft_nat` is reported like the drop log: the
  apply is retried as an `nft -c` dry run without the nat parts.

**Listener.**
- The proxy listens dual-stack on `[::]:<--proxy-port>`, with no separate listen-address flag. A
  redirect rewrites the destination to the incoming interface's own address, so the proxy must
  accept on every address. A direct connection to the port is dropped by the filter. A connection
  from another interface has no original destination, and the proxy closes it.

## Implementation summary

Delivered as sub-issues of #7. They touch these modules:
- `policy.rs`;
- `firewall/ruleset.rs`, `firewall/json.rs` and `firewall.rs`;
- `session.rs`;
- the new `proxy.rs`, with `sni`, `http` and `droplog`;
- `cli.rs` and `cli/gateway.rs`;
- the goldens in `tests/data/`, `tests/kernel.rs`, `e2e/`, the README and AGENTS.md.

## Deviations

None yet.

## Consequences

- Drawbridge now carries user traffic in userspace for host rules. Backends see the gateway as the
  source.
- `ct status dnat accept` would also accept any other DNAT to the proxy port. No other NAT is
  expected on the external interface.
- The cost of a session batch grows with the number of client host rules, because
  `proxy_redirect` is refilled each time.
- Follow-up: #8 (client and session overlap).
