# AGENTS.md

Guidance for coding agents working on Drawbridge, an identity-aware L3/L4 access gateway.

## What this is

A Rust service that turns a YAML allow-list policy into nftables rules on a Linux gateway. Clients are
identified by source CIDR and arrive on a dedicated external interface (e.g. WireGuard `wg0`). Anything
not explicitly allowed is dropped. See `docs/` for the specifications:

- `docs/00-specification.overview.md`: the full vision, with OIDC/OAuth identity, sessions and Axum.
- `docs/01-specification.prototype.md`: the prototype. It provisions static per-client rules on
  startup and removes them on shutdown.
- `docs/02-specification.oidc.md`: the **current milestone**. Users log in to an HTTPS portal through
  OIDC, and their per-user allow list is applied to their source IP until their ID token expires.
  Group-based access is out of scope. Don't add it unless asked.

## Layout

| Path | Purpose |
|---|---|
| `src/main.rs` | Thin binary: tracing setup, `Cli::parse()`, dispatch. **No logic here.** |
| `src/lib.rs` | Library crate root. All other modules live in the library. |
| `src/cli.rs` | Clap definitions (`run`, `check`, `teardown`); every flag has a `DRAWBRIDGE_*` env var. |
| `src/policy.rs` | Serde YAML schema (`clients`, `users`), `Policy::load`/`parse`/`validate`. |
| `src/ruleset.rs` | Pure `Policy` → `Ruleset` IR, including portal rules and `SessionRules`; `Display` renders nft-style text (used by `check`). |
| `src/firewall.rs` | `Ruleset` → `rustables` batch; `apply` / `update_sessions` / `teardown`. Builds what touches the kernel. |
| `src/session.rs` | `SessionTable` state machine (login, extend, expire, rebuild on failure) behind an `Enforcer` trait; `spawn` runs it as the single task that changes sessions. |
| `src/oidc.rs` | OIDC relying party (`openidconnect`): discovery, auth URL with PKCE/nonce, code exchange, ID-token verification, username claim. `Authenticator` trait for tests. |
| `src/portal.rs` | Axum router: `/`, `/login`, `/callback`, `/api/session`; cookies, pending-login store, security headers. |
| `src/portal/*.html` | Confirmation page (inline JS schedules silent re-auth) and message template, embedded with `include_str!`. |
| `src/netlink.rs` | Sends finalized batches with buffers sized to the batch, and parses the kernel's acks. |
| `src/gateway.rs` | Subcommand implementations: instance lock, interface check, signal-driven `run` lifecycle. |
| `examples/policy.yaml` | Example policy, used by unit tests. |
| `tests/data/example.nft` | Golden `check` output for the example policy. |
| `tests/data/example.kernel.nft` | Golden `nft list` output (counters stripped) after applying the example policy. |
| `tests/data/sessions.kernel.nft` | Golden `nft list` output after adding and replacing sessions incrementally. |
| `tests/kernel.rs` | `#[ignore]`d tests against a real kernel (needs CAP_NET_ADMIN): example golden, 5,000-rule policy, session add/replace/remove golden, 200-session churn. |
| `e2e/` | Docker Compose end-to-end stack (`run.sh`, `compose.yaml`, `Dockerfile`, `policy.yaml`, `dex.yaml`). |

## Commands

```sh
cargo build
cargo test                                   # unit tests, no privileges needed
cargo clippy --all-targets                   # keep warning-free
cargo fmt
cargo run -- check --policy examples/policy.yaml --external-iface wg0 \
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

Never run `drawbridge run` or `teardown` on the development host itself. They change the host
firewall. Use a network namespace or the e2e containers.

## Design invariants

Keep these unless the user changes them:

- **nftables layout:** there is one `inet drawbridge` table.
  - The `input` and `forward` base chains are filter chains at priority 0 with `policy accept`.
  - Each base chain does `iifname <ext> jump client_filter`.
  - `client_filter` runs `ct mark != 0 jump session_flows`, then
    `ct state established,related accept`, then one portal accept rule per `--portal-listen`
    address, then the per-client rules, then `jump sessions`, then `counter drop`.
  - `sessions` holds one `ip[6] saddr <ip> jump session_<id>` per live session; each `session_<id>`
    chain holds that user's rules (with the session IP as `saddr`), and each of them does
    `ct mark set <id>` before accepting.
  - `session_flows` holds `ip[6] saddr <ip> ct mark <id> return` per live session, then
    `counter drop`. This is how ending a session also cuts the connections it opened; without it,
    `ct state established` would keep them alive. **Drawbridge owns the conntrack mark** of
    connections arriving on the external interface. Don't add anything else that sets ct marks
    on them.
  - Session ids are nonzero `u32`s that start at a random value each run, so connections marked by
    a previous run can't match a new session.
  - A session change is one batch: add new session chains, flush `sessions` and `session_flows`
    and re-add their rules for every live session, then delete the removed chains. If it fails,
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
    each login. The page re-authenticates (top-level redirect to
    `/login?silent=1`, i.e. `prompt=none`) at 80% of the remaining lifetime, and `/callback`
    pushes the expiry out. Without re-auth, the session manager removes it at `exp`.
  - Sessions live in memory only: a restart drops them (users log in again).
  - Provider URLs (issuer, token endpoint, JWKS) must be https unless
    `--oidc-allow-insecure-http` is set (the e2e sets it for Dex).
  - The portal is a confidential client (secret + PKCE). The browser only holds the `__Host-`
    session cookie (HttpOnly, Secure, SameSite=Lax, no Max-Age), checked against the source IP.
  - `run` sets up the portal (TLS files, OIDC discovery, listener binds) before `apply`. At
    shutdown it stops the portal, aborts the session manager *then* tears down, so a rebuild
    can't recreate the table.
- `ruleset.rs` stays pure and kernel-free. Test rule generation there, not in `firewall.rs`.
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
- The build runs bindgen, so libclang must be installed (`libclang-dev` in the Docker builder).
- rustables is licensed **GPL-3.0-or-later**.

## Conventions

- Rust 2024 edition. Library errors use `thiserror`; `gateway.rs` and `main.rs` use `anyhow` with
  `.context(...)`.
- Log with `tracing`; the level is set by `RUST_LOG` and defaults to `info`.
- Put unit tests in `#[cfg(test)] mod tests` next to the code they test. Fixtures go in `examples/`
  or `tests/data/`.
- Keep e2e assertions in `e2e/run.sh` and use the `tcp` / `udp` / `ping_` / `refused` / `login`
  helpers.
  - Every "closed" check needs a real listener behind it, and a matching "open" check after
    shutdown, so a denial is shown to come from the rules.
  - The e2e addresses and MACs are fixed in `compose.yaml`, `entrypoint.sh` and `policy.yaml`, so
    keep the three in sync.
  - Dex (`e2e/dex.yaml`, 30s ID tokens) is the OIDC provider. It issues no `preferred_username`
    and keeps no SSO session, so the e2e uses `--oidc-username-claim email` and the "silent"
    re-auth step re-submits the password form.
  - The external Docker network stands in for WireGuard. It has pinned IPv6 neighbour entries,
    because Drawbridge (correctly) drops neighbour discovery on the external interface.
