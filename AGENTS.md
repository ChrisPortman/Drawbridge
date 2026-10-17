# AGENTS.md

Guidance for coding agents working on Drawbridge, an identity-aware L3/L4 access gateway.

## What this is

A Rust service that turns a YAML allow-list policy into nftables rules on a Linux gateway. Clients are
identified by source CIDR and arrive on a dedicated external interface (e.g. WireGuard `wg0`). Anything
not explicitly allowed is dropped.

**GitHub issues are the specification from now on.** A feature issue states what to build and a bug
issue states what is broken. Don't add new specification documents to `docs/`. Design decision records
in `docs/decisions/` (`NNNN-<issue-slug>.md`) capture why a design was chosen, and are written when a
feature is planned. Use the `plan-feature` skill for feature issues and the `fix-bug` skill for bug
issues (see `.claude/skills/`).

The documents below specify the milestones built before issues took over. They describe the current
behaviour and are background; where an open issue conflicts with one, the issue wins:

- `docs/00-specification.overview.md`: the full vision, with OIDC/OAuth identity, sessions and Axum.
- `docs/01-specification.prototype.md`: the prototype. It provisions static per-client rules on
  startup and removes them on shutdown.
- `docs/02-specification.oidc.md`: users log in to an HTTPS portal through OIDC, and their
  per-user allow list is applied to their source IP until their ID token expires. Group-based
  access is out of scope. Don't add it unless asked.
- `docs/03-specification.permissive_mode.md`: the last milestone specified this way. `--permissive`
  accepts instead of dropping, and a deduplicated kernel log records what is (or would be) dropped.

## Layout

| Path | Purpose |
|---|---|
| `src/main.rs` | Thin binary: tracing setup, `Cli::parse()`, dispatch to `cli::{run, check, teardown}` (`server`) and `cli::{init, login, logout, service}` (`client`). **No logic here.** |
| `src/lib.rs` | Library crate root. Declares the top-level modules: `cli`, `firewall`, `policy` (`pub`) and `portal`, `session` (`pub(crate)`). |
| `src/cli.rs` | Clap definitions: `server run|check|teardown`, `client init|login|logout` and the hidden `client service`; every flag has a `DRAWBRIDGE_*` env var. Re-exports the subcommands from `gateway` and `client`, and `Secret` (a flag's type) from `portal`. |
| `src/cli/gateway.rs` | `server` implementations: instance lock, interface check, portal flags → `PortalConfig`, signal-driven `run` lifecycle. |
| `src/cli/client.rs` | `client` implementations: `init` writes `client.yaml` and the user unit; `login`/`logout` only start/stop it through `systemctl --user`; `service` (what the unit runs) logs in through the loopback handoff, refreshes, and ends the session on SIGTERM. |
| `src/cli/client/*.rs` | `unit` (pure: unit file, XDG paths, `systemctl show` parsing, timing), `notify` (`sd_notify`), `api` (the service's portal client), `loopback` (the 127.0.0.1 listener). |
| `src/policy.rs` | Serde YAML schema (`clients`, `users`), `Policy::load`/`parse`/`validate`. Shared by every other module. |
| `src/firewall.rs` | `Ruleset` → `rustables` batch; `apply` / `update_sessions` / `teardown`. Builds what touches the kernel. |
| `src/firewall/ruleset.rs` | Pure `Policy` → `Ruleset` IR, including portal rules, `SessionRules`, `Mode` and the drop log's `LogSet`s; `Display` renders nft-style text (used by `check`). |
| `src/firewall/netlink.rs` | Sends finalized batches with buffers sized to the batch, and parses the kernel's acks. |
| `src/firewall/nfraw.rs` | Hand-encoded nf_tables messages for the drop log's sets and rules (which rustables can't express), spliced into the rustables batch. |
| `src/session.rs` | `SessionTable` state machine (login, extend, refresh leases, logout, expire, rebuild on failure) behind an `Enforcer` trait; `spawn` runs it as the single task that changes sessions. |
| `src/portal.rs` | `Prepared` (TLS, OIDC discovery, listener binds) and `Servers` (serve, graceful shutdown); Axum router: `/`, `/login`, `/callback`, `/api/session` (GET, DELETE), `/api/session/refresh`, `/api/cli/token`; cookies, the bounded pending-login and CLI-grant stores, security headers. Re-exports `OidcConfig` and `Secret` from `oidc`, and the wire types from `api`. |
| `src/portal/api.rs` | JSON API types and constants shared by the portal and the client service. |
| `src/portal/oidc.rs` | OIDC relying party (`openidconnect`): discovery, auth URL with PKCE/nonce, code exchange, refresh, ID-token verification, username claim. `Authenticator` trait for tests. |
| `src/portal/*.html` | Confirmation page (inline JS refreshes, falling back to silent re-auth) and message template, embedded with `include_str!`. |
| `examples/policy.yaml` | Example policy, used by unit tests. |
| `tests/data/example.nft` | Golden `check` output for the example policy. |
| `tests/data/example.kernel.nft` | Golden `nft list` output (counters stripped) after applying the example policy. |
| `tests/data/sessions.kernel.nft` | Golden `nft list` output after adding and replacing sessions incrementally. |
| `tests/data/portal-test.{crt,key}` | Self-signed (not CA) certificate for 127.0.0.1; the client's certificate-check tests serve it. Test-only. |
| `tests/data/drop_log.netlink.hex` | What `nft --debug=mnl` sends for the drop log's sets and rules; `nfraw` must match it byte for byte. |
| `tests/kernel.rs` | `#[ignore]`d tests against a real kernel (needs CAP_NET_ADMIN): example golden, permissive mode, 5,000-rule policy, session add/replace/remove golden, 200-session churn. |
| `e2e/` | Docker Compose end-to-end stack (`run.sh`, `compose.yaml`, `Dockerfile`, `policy.yaml`, `dex.yaml`, `systemctl-stub`). |

## Commands

```sh
cargo build
cargo test                                   # unit tests, no privileges needed
cargo clippy --all-targets                   # keep warning-free
cargo fmt
cargo run -- server check --policy examples/policy.yaml --external-iface wg0 \
    --portal-listen 192.168.50.1:8443          # print planned ruleset (matches tests/data/example.nft)
./e2e/run.sh                                 # full end-to-end test (Docker + Compose v2, no root)
```

Kernel integration test (needs CAP_NET_ADMIN). Use either:

```sh
cargo test --no-run && sudo unshare -n cargo test --test kernel -- --ignored
# or, without root, after ./e2e/run.sh has built the image:
docker run --rm --cap-add NET_ADMIN -v "$PWD/target/debug/deps/kernel-<hash>:/t:ro" \
    --entrypoint /t drawbridge-e2e --ignored
```

Never run `drawbridge server run` or `teardown` on the development host itself. They change the host
firewall. Use a network namespace or the e2e containers.

## Design invariants

Keep these unless the user changes them:

- **nftables layout:** there is one `inet drawbridge` table.
  - The `input` and `forward` base chains are filter chains at priority 0 with `policy accept`.
  - Each base chain does `iifname <ext> jump client_filter`, then `iifname <ext> jump drop_log`,
    then the **one default action**: `iifname <ext> counter drop` (`counter accept` in permissive
    mode). Nothing else drops. Anything not accepted must fall back to the base chain.
  - `client_filter` runs `ct mark != 0 goto session_flows`, then
    `ct state established,related accept`, then one portal accept rule per `--portal-listen`
    address, then the per-client rules, then `jump sessions`, and ends without a verdict.
  - `sessions` holds one `ip[6] saddr <ip> jump session_<id>` per live session; each `session_<id>`
    chain holds that user's rules (with the session IP as `saddr`), and each of them does
    `ct mark set <id>` before accepting.
  - `session_flows` holds `ip[6] saddr <ip> ct mark <id> accept` per live session and nothing
    else. It is reached by `goto`, so a marked packet with no live session falls off its end
    straight back to the base chain (the base chain's `jump` is the only return point), skipping
    `ct state established`, and meets the default action. This is how ending a session also cuts
    the connections it opened. Keep the `jump` in the base chains: from a base chain, a `goto`
    would fall through to the chain policy (accept) instead. **Drawbridge owns the conntrack
    mark** of connections arriving on the external interface. Don't add anything else that sets
    ct marks on them.
  - `drop_log` logs each packet about to meet the default action, with prefix
    `drawbridge drop: ` (or `drawbridge would-drop: ` in permissive mode), once per key per 10s:
    TCP and UDP `goto drop_log_ports`, keyed by `saddr . daddr . l4proto . dport`; the rest are
    keyed by `saddr . daddr . l4proto`. Each log rule is
    `<key> != @set limit rate 50/second burst 100 packets add @set { <key> } counter log`, on
    dynamic timeout sets `drop_seen4[_proto]` / `drop_seen6[_proto]` of 65,536 entries, and is
    followed by a miss rule `<key> != @set counter` that counts new keys the limit or a full set
    kept out of the log. The inverted lookup is needed because a dynset `add` of an existing key
    still matches. Logging can lose lines, never verdicts, because the default action is a
    separate rule. The sets and the whole contents of both log chains are built by `nfraw`, not
    rustables. A kernel rejection of those messages is reported as `FirewallError::DropLog`,
    naming the logging modules.
  - Session ids are nonzero `u32`s that start at a random value each run, so connections marked by
    a previous run can't match a new session.
  - A session change is one batch: add new session chains, flush `sessions` and `session_flows`
    and re-add their rules for every live session, then delete the removed chains. It never
    touches the drop log. If it fails,
    `SessionTable` falls back to a full `apply` from its state and retries every 5s until that
    succeeds. It never tears down. Until a retry succeeds, an expired session may stay enforced;
    this is logged at error.
- **Only traffic arriving on the external interface is filtered.** That interface is assumed to be
  dedicated to clients and statically addressed. Don't add DHCP, ARP or ND exceptions.
- **Access to the gateway host comes only through policy.** A client reaches the host by listing
  the gateway's IP as a `dest`. Nothing is hard-coded. The **one exception** is the portal: each
  `--portal-listen` address (which must be specific, not unspecified) gets an accept rule so that
  unauthenticated users can log in. The OIDC provider is *not* exempt: allow it with a normal
  `clients` rule.
- **Apply is atomic.** One batch does add table, delete table, then rebuilds everything. A restart
  therefore replaces leftover state. A batch the kernel rejects changes nothing. After a timeout or
  lost acks (`NetlinkError::Timeout` / `AcksLost`), the batch may already be live. Either way `run`
  must not tear down after a failed apply: at worst that leaves the new rules enforcing.
- **One instance at a time.** `run` and `teardown` hold an exclusive lock on `--lock-file`
  (`DRAWBRIDGE_LOCK_FILE`, default `/run/drawbridge.lock`); `check` takes none.
- **The external interface must exist at startup.** `run` refuses to start otherwise, because rules
  for a misnamed interface match nothing. Names are limited to 1–15 characters from
  `[A-Za-z0-9_.-]`.
- **Shutdown is fail-open.** It deletes the table. `teardown` reports a missing table as success.
- **Permissive mode** (`--permissive`, `DRAWBRIDGE_PERMISSIVE`) changes only the default action
  and the log prefix. Sessions, the portal and the drop log work as in enforcing mode, so it shows
  exactly what enforcing would drop. `run` warns at startup when it is on. Connections it lets
  through aren't marked, so they survive a restart into enforcing mode as `established`; the
  README tells operators to flush conntrack after switching.
- **Policy is allow-only and inline per client or user** (`clients[].cidr`,
  `users[].username`, `allow[].dest/proto/ports`).
  - Validate before touching the kernel.
  - Validation errors name `clients[i].allow[j]`, `users[i].allow[j]` or `users[i]`.
  - Schema structs use `deny_unknown_fields`.
  - Client dests must match the client's address family. User dests may mix families; only those
    matching the login IP apply.
  - `users` without `--portal-listen` is a startup error.
- **Sessions:**
  - The client IP is the TCP peer address (no proxies, no X-Forwarded-For).
  - One session per source IP. Another login by the same user extends it and keeps its token; a
    different user replaces it.
  - A session lasts until the ID token's `exp`, capped at `--session-max-ttl` (default 15m) from
    each login or refresh. At 80% of the remaining lifetime the page (or the client service)
    calls `POST /api/session/refresh`: the gateway redeems the session's refresh token, verifies
    the new ID token (same username required) and extends exactly as a re-login does. On 409 (no
    usable refresh token) the page falls back to a top-level `/login?silent=1` (`prompt=none`);
    the service exits instead. Without either, the session manager removes it at `exp`.
  - Refresh tokens (`offline_access`) live only in the session table, in memory, and never leave
    the gateway. One refresh per session runs at a time (`begin_refresh` lease), and the provider
    is called outside the session task, in a spawned task so a dropped request can't strand it.
  - `DELETE /api/session` ends a session at once through the normal update batch, which also
    cuts its connections. Requests that change a session (`POST /api/session/refresh`,
    `DELETE /api/session`, `POST /api/cli/token`) require `X-Drawbridge: 1`.
  - A CLI login (`/login?cli_port&cli_challenge&cli_state`) sets no cookie: `/callback` verifies
    the login and redirects to `http://127.0.0.1:<port>/` (nothing else) with a one-time code and
    the service's state, which its listener checks. The code is valid 60s, once, from the same IP
    and with the S256 verifier; the session is provisioned only when it is redeemed. The session
    token never appears in a URL.
  - The client service holds the token only in memory. Its unit is `Type=notify` (READY once
    logged in) with `Restart=no`; a lost session fails the unit rather than reopening a browser.
    A session it can't refresh (409) is held until it expires, so a stop still ends it.
  - Sessions live in memory only: a restart drops them (users log in again).
  - Provider URLs (issuer, token endpoint, JWKS) must be https unless
    `--oidc-allow-insecure-http` is set (the e2e sets it for Dex).
  - The portal is a confidential client (secret + PKCE). The browser only holds the `__Host-`
    session cookie (HttpOnly, Secure, SameSite=Lax, no Max-Age), checked against the source IP.
  - `run` sets up the portal (TLS files, OIDC discovery, listener binds, TLS servers) before
    `apply`, so `Prepared::serve` can't fail. Nothing after `apply` may return early: every exit
    goes through teardown. At shutdown it stops the portal, aborts the session manager *then*
    tears down, so a rebuild can't recreate the table.
- `firewall/ruleset.rs` stays pure and kernel-free. Test rule generation there, not in
  `firewall.rs`.
- Keep the public API minimal: `pub` only for what `main.rs` and `tests/kernel.rs` use (and what
  their signatures name). Everything else is `pub(crate)`. Callers outside a top-level module use
  its re-exports or its `pub` child modules (only `firewall::ruleset`), not its private children.
- If you change rule generation or rendering, update `tests/data/example.nft`,
  `tests/data/example.kernel.nft` and the e2e checks to match.

## rustables notes (v0.9)

The docs are sparse, so read the source in `~/.cargo/registry/src/*/rustables-0.9.0/src/`. Known quirks:

- **Don't use `Batch::send`.** It uses default socket buffers. Batches over roughly 220 rules then
  fail: either with `EMSGSIZE` before the send, or with `ENOBUFS` *after* the kernel has committed
  them. Build with rustables, then send `batch.finalize()` through `netlink::send_batch`.
- Its own netlink errors (`QueryError::NetlinkError`) report errno as a positive value. Our
  `NetlinkError::Kernel` stores the positive errno too.
- `Rule::established()` matches only ESTABLISHED. Use `firewall::established_or_related` instead.
- There is no port-range helper. Ranges are a transport `Payload` followed by `Cmp Gte` and
  `Cmp Lte`, with big-endian bytes.
- `Rule::icmp()` is IPv4-only. ICMPv6 needs `Meta L4Proto` plus `IPPROTO_ICMPV6`.
- It has no `dynset` or `limit` expression, names only the four 128-bit registers (so it can't
  build concatenated keys), and its raw-expression type can't be built outside the crate. Sets
  have no `NFTA_SET_DESC` (size) either. That's why `nfraw` exists. To change what it encodes,
  write the nft equivalent, capture it with `nft --debug=mnl` (e.g. in the e2e image with
  `--cap-add NET_ADMIN`), update `tests/data/drop_log.netlink.hex` and match it.
- The build runs bindgen, so libclang must be installed (`libclang-dev` in the Docker builder).
- rustables is licensed **GPL-3.0-or-later**. Drawbridge's own source is `MIT OR Apache-2.0`
  (`LICENSE-MIT`, `LICENSE-APACHE`); the GPL reaches only distributed binaries, through rustables.

## Conventions

- Rust 2024 edition. Library errors use `thiserror`; `cli/gateway.rs`, `cli/client*` and
  `main.rs` use `anyhow` with `.context(...)`.
- Log with `tracing`; the level is set by `RUST_LOG` and defaults to `info`.
- Put unit tests in `#[cfg(test)] mod tests` next to the code they test. Fixtures go in `examples/`
  or `tests/data/`.
- Keep e2e assertions in `e2e/run.sh` and use the `tcp` / `udp` / `ping_` / `refused` / `login` /
  `silent_login` / `page_refresh` / `log_has` helpers, and `cli` / `stub` / `unit_state` /
  `drive_login` for the client CLI.
  - Every "closed" check needs a real listener behind it, and a matching "open" check after
    shutdown, so a denial is shown to come from the rules.
  - The e2e addresses and MACs are fixed in `compose.yaml`, `entrypoint.sh` and `policy.yaml`, so
    keep the three in sync.
  - Dex v2.46 (`e2e/dex.yaml`, 30s ID tokens) is the OIDC provider. It issues no
    `preferred_username`, so the e2e uses `--oidc-username-claim email`.
  - Dex runs with its experimental auth sessions on (`DEX_SESSIONS_ENABLED` in `compose.yaml`
    plus the `sessions:` block; it needs both). It keeps an SSO session in the `dex_session`
    cookie, so `silent_login` completes with no form. Before logging in as another user, or to
    test the `login_required` fallback, drop that cookie with `forget_provider`; otherwise Dex
    logs the browser in again as the previous user.
  - Dex logs a login from its session only at debug, so `dex.yaml` sets debug logging. `log_has`
    checks gateway and Dex log lines in `docker compose logs --since/--until` windows and prints
    them as evidence.
  - The kernel log isn't emitted from containers (non-init network namespaces) unless
    `net.netfilter.nf_log_all_netns=1`, so the e2e checks the drop log through rule counters and
    set contents, not log lines.
  - `drawbridge client` runs as `user` (uid 1000) in client-user, with
    `DRAWBRIDGE_SYSTEMCTL=systemctl-stub`. The stub runs the unit's `ExecStart` with a notify
    socket and models `activating` → `active` on READY=1, `inactive`/`failed` on exit. It is not
    systemd: keep it small, and detach anything it backgrounds from its caller's output.
  - The portal certificate is self-signed, so the e2e's `client init` uses
    `--insecure-skip-tls-verify`. (`openssl req -x509` makes it a CA certificate, which rustls
    refuses as a server's own even through `--ca-cert`.) The verified path, `--ca-cert` included,
    is tested in `cli/client/api.rs` against `tests/data/portal-test.crt`.
  - A gateway restarted with `dc exec -d` logs to the exec, not the container; send its output to
    `/proc/1/fd/1` when `log_has` must see it.
  - The external Docker network stands in for WireGuard. It has pinned IPv6 neighbour entries,
    because Drawbridge (correctly) drops neighbour discovery on the external interface.
