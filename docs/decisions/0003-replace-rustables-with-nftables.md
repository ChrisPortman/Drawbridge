# 0003: Replace rustables with the `nftables` crate and the `nft` binary

- Issue: https://github.com/ChrisPortman/Drawbridge/issues/21 (#21)
- Map: https://github.com/ChrisPortman/Drawbridge/issues/22 (#22)
- Status: Accepted
- Date: 2026-10-27

## Context

Drawbridge builds its nftables ruleset with `rustables` 0.9 and sends it over netlink itself.
rustables can't express the drop log (dynset, `limit`, concatenated keys, set size), so
`firewall/nfraw.rs` hand-encodes those nf_tables messages and splices them into the batch. It also
can't send large batches, so `firewall/netlink.rs` replaces its sender. That is about 750 lines of
low-level netlink code, checked against a byte-for-byte hex capture, for a small product. The issue
asks to drop it for the `nftables` crate, which models nft's JSON schema, and to accept `nft` as a
runtime dependency.

The research behind this is `docs/research/0020-rustables-alternatives.md` (Option A), plus the
findings linked from "Minimum nft version for our JSON" (#23) and "What nft reports when a JSON
batch fails" (#24).

## Decisions

**Full replacement, no fallback backend.** rustables, `netlink.rs` and `nfraw.rs` are all removed.
Keeping a netlink backend as a fallback would keep the maintenance cost the issue wants gone.

**Use the crate's types, run `nft` ourselves.** Only the `nftables` crate's serde schema is used.
Drawbridge spawns `nft -j -f -` itself (absolute path, JSON on stdin, stderr captured, a timeout)
through `tokio::process`, because the crate's helpers give neither a timeout nor the stderr that the
error model needs. Option B (linking libnftables through FFI) was rejected: it needs `unsafe`, a
build-time C library, and swaps one GPL link for another.

**Supported deployments.** Root, or systemd with `AmbientCapabilities=CAP_NET_ADMIN`, so the
capability survives exec into `nft`. File capabilities on the Drawbridge binary alone don't reach
`nft` and are unsupported. The `run` preflight detects this (see below).

**Minimum nft version is 0.9.3** (#23). The JSON leaves `"dynamic"` out of set flags (nft marks
the sets dynamic itself); including it would raise the floor to 1.0.9. 0.9.0 parses
`jump`/`goto` differently and fails. The version comes from `nft --version`, which needs no
privileges.

**Error model** (#24, #25). nft exits 1 with plain-text stderr and applies nothing. Failures are
classified, permission first:
`NotFound { path }`, `Spawn`, `PermissionDenied` (`Operation not permitted`),
`InvalidJson { index }` (`Parsing command array at index N`, a Drawbridge bug; the offending
command is logged), `Rejected`, `DropLog` and `Timeout`. Kernel errors carry no command index, so
`DropLog` is identified by retrying the failed apply once with `nft -c` and without the drop log:
if that passes, the drop log was the cause (usually a missing `nft_log`, `nf_log_syslog` or
`nft_limit` module). Splitting the apply would break atomicity. Teardown is one idempotent batch,
`add table` + `delete table`; `destroy table` needs nft 1.0.8 and Linux 6.3, which rules out
Ubuntu 22.04.

**Preflight and flags** (#26). `--nft-path` / `DRAWBRIDGE_NFT_PATH` defaults to `/usr/sbin/nft`,
must be absolute, and is never looked up in `PATH`. `check`, `run` and `teardown` check the
version. `--nft-skip-version-check` skips only that check, with a warning, so a change to nft's
`--version` output can't stop Drawbridge from starting. `run` also probes with `nft -c` of the
teardown batch, so a missing capability fails before any network side effects. The order is:
lock → interface → version → probe → portal → apply. The probe can't be skipped.

**Timeouts** (#27). Every `nft` child has a fixed 30s deadline. After it, the child is SIGKILLed
and the result is `Timeout`, which may already be live, replacing `NetlinkError::Timeout`;
`AcksLost` goes. Apply and session-update semantics are unchanged. Teardown errors out with no
retry, and is safe to rerun.

**Tests** (#28). `example.nft` (the `check` text) is unchanged. A new `tests/data/example.json`
golden checks the apply batch without privileges. The kernel goldens stay the oracle and must come
through byte for byte. A new kernel test loads `example.json` and compares the result with
`example.kernel.nft`. `drop_log.netlink.hex` is deleted.

**Module layout** (#29). Three layers:
- `firewall/ruleset.rs`: pure IR and its text rendering. Unchanged.
- `firewall/json.rs`: pure IR → JSON for the apply, sessions and teardown batches. Holds all the
  rule building.
- `firewall/nft.rs`: the runner, with pure version parsing and stderr classification.

`firewall.rs` keeps the public surface, a `Firewall` handle built from the nft path with async
`apply`, `update_sessions`, `teardown`, `check_version` and `probe`, plus `FirewallError` and the
DropLog retry. `Enforcer` becomes async (native `async fn`). There is no mock-runner trait;
`Enforcer` is already the test seam.

## Consequences

- `nft` (nftables >= 0.9.3) is a runtime dependency. libclang and bindgen leave the build.
- Distributed binaries no longer link GPL-3.0 code, because the `nftables` crate is
  `MIT OR Apache-2.0`.
- Every kernel change is an exec, so it is slower than netlink. That is acceptable for the batch
  sizes involved; the 5,000-rule and 200-session kernel tests still run.
- Nothing below the JSON level is tested by Drawbridge; that is nft's job.
- Issue #11 features (redirect, `ct status`) are out of scope, but the JSON schema doesn't block
  them.
