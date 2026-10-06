# AGENTS.md

Guidance for coding agents working on the Access Gateway.

## What this is

A Rust service that turns a YAML allow-list policy into nftables rules on a Linux gateway. Clients are
identified by source CIDR and arrive on a dedicated external interface (e.g. WireGuard `wg0`). Anything
not explicitly allowed is dropped. See `docs/` for the specifications:

- `docs/00-specification.overview.md`: the full vision, with OIDC/OAuth identity, sessions and Axum.
- `docs/01-specification.prototype.md`: the **current milestone**. It provisions rules on startup
  and removes them on shutdown. Auth, OAuth, sessions and client-facing interfaces are out of scope.
  Don't add them unless asked.

## Layout

| Path | Purpose |
|---|---|
| `src/main.rs` | Thin binary: tracing setup, `Cli::parse()`, dispatch. **No logic here.** |
| `src/lib.rs` | Library crate root. All other modules live in the library. |
| `src/cli.rs` | Clap definitions (`run`, `check`, `teardown`); every flag has an `AG_*` env var. |
| `src/policy.rs` | Serde YAML schema, `Policy::load`/`parse`/`validate`. |
| `src/ruleset.rs` | Pure `Policy` → `Ruleset` IR; `Display` renders nft-style text (used by `check`). |
| `src/firewall.rs` | `Ruleset` → `rustables` netlink batch; `apply` / `teardown`. The only kernel-touching code. |
| `src/gateway.rs` | Subcommand implementations and the signal-driven `run` lifecycle. |
| `examples/policy.yaml` | Example policy, used by unit tests. |
| `tests/data/example.nft` | Golden `check` output for the example policy. |
| `tests/kernel.rs` | `#[ignore]`d test that applies rules to a real kernel (needs CAP_NET_ADMIN). |
| `e2e/` | Docker Compose end-to-end stack (`run.sh`, `compose.yaml`, `Dockerfile`, `policy.yaml`). |

## Commands

```sh
cargo build
cargo test                                   # unit tests, no privileges needed
cargo clippy --all-targets                   # keep warning-free
cargo fmt
cargo run -- check --policy examples/policy.yaml --external-iface wg0   # print planned ruleset
./e2e/run.sh                                 # full end-to-end test (Docker + Compose v2, no root)
```

Kernel integration test (needs CAP_NET_ADMIN). Use either:

```sh
cargo test --no-run && sudo unshare -n cargo test --test kernel -- --ignored
# or, without root, after ./e2e/run.sh has built the image:
docker run --rm --cap-add NET_ADMIN -v "$PWD/target/debug/deps/kernel-<hash>:/t:ro" \
    --entrypoint /t access-portal-e2e --ignored
```

Never run `access_portal run` or `teardown` on the development host itself. They change the host
firewall. Use a network namespace or the e2e containers.

## Design invariants

Keep these unless the user changes them:

- **nftables layout:** there is one `inet access_gateway` table.
  - The `input` and `forward` base chains are filter chains at priority 0 with `policy accept`.
  - Each base chain does `iifname <ext> jump client_filter`.
  - `client_filter` runs `ct state established,related accept`, then the per-client rules, then
    `counter drop`.
- **Only traffic arriving on the external interface is filtered.** That interface is assumed to be
  dedicated to clients and statically addressed. Don't add DHCP, ARP or ND exceptions.
- **Access to the gateway host comes only through policy.** A client reaches the host by listing
  the gateway's IP as a `dest`. Nothing is hard-coded.
- **Apply is atomic.** One batch does add table, delete table, then rebuilds everything. A restart
  therefore replaces leftover state.
- **Shutdown is fail-open.** It deletes the table. `teardown` reports a missing table as success.
- **Policy is allow-only and inline per client** (`clients[].cidr`, `allow[].dest/proto/ports`).
  - Validate before touching the kernel.
  - Validation errors name `clients[i].allow[j]`.
  - Schema structs use `deny_unknown_fields`.
- `ruleset.rs` stays pure and kernel-free. Test rule generation there, not in `firewall.rs`.
- If you change rule generation or rendering, update `tests/data/example.nft` and the e2e checks
  to match.

## rustables notes (v0.9)

The docs are sparse, so read the source in `~/.cargo/registry/src/*/rustables-0.9.0/src/`. Known quirks:

- Netlink errno values come back **positive** in `QueryError::NetlinkError(e).error`, because the
  parser applies `abs()`. Compare with `e.error.abs()`.
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
- Keep e2e assertions in `e2e/run.sh` and use the `tcp` / `ping_` helpers. The e2e network
  addresses are fixed in `compose.yaml`, `entrypoint.sh` and `policy.yaml`, so keep the three in
  sync.
