# Research: alternatives to rustables

Issue: #20 "Consider nftables in place of rustables", widened to all alternatives. Research notes,
not a spec or decision record. Date: 2026-10-22/23. Release dates come from the crates.io API
(`https://crates.io/api/v1/crates/<name>`); crate sources were downloaded from static.crates.io
and are cited as `<crate>-<ver>/path:line`.

## Option 0: the current approach, as it costs us today

- Code that exists only to talk to the kernel: `src/firewall.rs` (342 lines, rustables builders
  plus apply/update/teardown), `src/firewall/netlink.rs` (281, buffer-sized send and ack
  parsing, needed because `Batch::send` breaks past ~220 rules, AGENTS.md "rustables notes") and
  `src/firewall/nfraw.rs` (463, hand-encoded sets, dynset, limit, concatenations, log; byte-matched
  against `tests/data/drop_log.netlink.hex`). `ruleset.rs` (801) is the pure IR and is needed
  under every option. (`wc -l`.)
- Churn so far is low: `git log -- src/firewall/nfraw.rs src/firewall/netlink.rs` shows one
  commit each (5080acd, a module move); `src/firewall.rs` has 5 commits since ae17354. The cost is
  not churn but extension: every new expression (e.g. issue #11's redirect and `ct status`) needs
  either upstream rustables work or more hand encoding plus a fresh `nft --debug=mnl` capture.
- Upstream status and gaps: see Option F. License GPL-3.0-or-later
  (`~/.cargo/registry/src/*/rustables-0.9.0/Cargo.toml:41`); build needs bindgen/libclang.
- Strengths worth keeping in any replacement: per-message kernel acks (so a rejection can be
  attributed, `FirewallError::DropLog`), no runtime binaries, a single netlink send per session
  change.

## Option A: `nftables` crate (JSON through `nft`)

 Crate examined: `nftables` 0.6.3 (latest stable, 2025-08-15, per
https://crates.io/api/v1/crates/nftables). Experiments ran in the `drawbridge-e2e` image
(`nft` v1.1.3) with `--cap-add NET_ADMIN`; the host has `nft` v1.1.6.

### What the crate is

- A serde model of the libnftables JSON schema plus helpers that spawn `nft`. `apply_ruleset_raw`
  runs `nft -j -f -` and writes the JSON to stdin (`nftables-0.6.3/src/helper.rs:272-326`);
  reading runs `nft -j list ruleset` (`helper.rs:97-101`). Optional `tokio` / `async-process`
  features give async variants (`helper.rs:332-437`, `Cargo.toml` `[features]`).
- License `MIT OR Apache-2.0`, MSRV 1.76, edition 2021 (crates.io API; crate `Cargo.toml`).
  Runtime needs nftables >= 0.9.3 (`README.md:52`).
- Deps: serde, serde_json, serde_path_to_error, schemars, strum, thiserror (crate `Cargo.toml`).

### Can it express everything Drawbridge needs today and in planned work?

Everything rustables could not (the reasons `nfraw` exists, AGENTS.md "rustables notes") is in
the crate's model:

| Need | rustables 0.9 | `nftables` 0.6.3 |
|---|---|---|
| dynset `add @set { key }` | no | `Statement::Set` with `SetOp::Add` (`src/stmt.rs:55,315-330`) |
| `limit rate .. burst ..` | no | `Statement::Limit` (`src/stmt.rs:41,186-206`) |
| concatenated keys | no (4 regs only) | `Expression::Concat` (`src/expr.rs:45-46`) |
| set `size` / `timeout` / flags | no `NFTA_SET_DESC` | `Set.size`, `timeout`, `flags` (`src/schema.rs:321-336`) |
| `log prefix` | (in nfraw) | `Statement::Log` (`src/stmt.rs:57,333-378`) |
| `redirect to :P` (issue #11) | no | `Statement::Redirect` (`src/stmt.rs:53,488`) |
| `ct status dnat` (issue #11) | no | `Expression::CT` + match (`src/expr.rs:72`) |
| bitwise `&` | - | `BinaryOperation::AND` (`src/expr.rs:645-648`) |

Verified empirically: the drop-log set and both log rules exactly as AGENTS.md specifies, a
`ct mark set 7 redirect to :8443` nat rule, `tcp dport 8443 ct status dnat counter accept` and a
`goto` were loaded with `nft -f`, exported with `nft -j list ruleset`, deserialized into
`nftables::schema::Nftables` and re-serialized: the JSON compared **equal** to nft's output, and
`nft -j -f` of it reproduced the same ruleset. (Scratch test: deserialize/serialize round trip
with `serde_json`; inputs in the session scratchpad, not committed.) So the whole of
`src/firewall/nfraw.rs` (463 lines) and the planned #11 encoders would be unnecessary.

### Atomicity and failure behaviour

- `nft -f` applies a file as one transaction: "in one atomic operation it swaps the old config for
  the new one" (https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement).
  JSON input goes through the same path ("an alternative frontend to the standard CLI syntax
  parser, therefore basic behaviour is identical", `man 5 libnftables-json`, DESCRIPTION).
- Verified: a JSON batch `add table inet t` + a rule into a non-existent table exits 1 and leaves
  no tables. The "add table, delete table, rebuild" apply pattern also works in JSON (below).
- Error quality is weak: the failure printed `internal:0:0-0: Error: Could not process rule: No
  such file or directory`, with no index of the failing command. Today's `netlink.rs` parses
  per-message acks itself (AGENTS.md), which is how `FirewallError::DropLog` can name the drop-log
  messages; with `nft` that attribution would need to come from parsing stderr or splitting batches.
- **Crate bug relevant to that:** `apply_ruleset_raw` pipes stdin and stdout only
  (`helper.rs:286-291`); stderr is inherited, so `NftablesError::NftFailed.stderr` is always empty
  and nft's message goes to Drawbridge's own stderr instead. Same in the async variant
  (`helper.rs:416-425`). Calling `nft` ourselves (or patching upstream) fixes it.
- No timeout on the child (`wait_with_output`, `helper.rs:307`). The rustables path has
  `NetlinkError::Timeout`/`AcksLost`; with `nft` a hung child is the equivalent, and killing it
  mid-commit leaves the same "may already be live" ambiguity.
- The socket-buffer quirk (AGENTS.md: `Batch::send` fails past ~220 rules) is nft's problem, not
  ours. Measured: a JSON batch of add/delete/add table + 5,000 rules applied in ~180 ms per run
  (3 runs, e2e container), all 5,000 rules present.

### Costs and risks

- **Runtime dependency on the `nft` binary** (and libnftables) of a compatible version; the
  crate's own floor is 0.9.3 but JSON for newer statements varies by nft version. The e2e image
  already installs `nftables` (`e2e/Dockerfile:15`).
- **Capabilities across exec:** if Drawbridge runs non-root with ambient/file capabilities, the
  child only keeps CAP_NET_ADMIN via the ambient set
  (`P'(ambient) = (file is privileged) ? 0 : P(ambient)`, `man 7 capabilities`, "Transformation of
  capabilities during execve()"). Root or a systemd `AmbientCapabilities=` unit is fine;
  file-caps-only deployments are not.
- **PATH trust:** the crate defaults to `nft` looked up in `PATH` (`helper.rs:13`); a privileged
  service should pass an absolute path (`apply_ruleset_with_args` takes `program`).
- **Process spawn per session change** (fork/exec + JSON parse) instead of one netlink send; at
  ~180 ms for 5,000 rules this is fine for login/logout rates, but it's per change.
- **Golden tests change:** `tests/data/drop_log.netlink.hex` byte-matching would go; goldens
  could become JSON documents or keep `nft list` text (`tests/data/*.kernel.nft` stay valid).
  `server check` stays kernel-free if `ruleset.rs` renders JSON itself.
- **Licensing improves:** rustables is `GPL-3.0-or-later`
  (`~/.cargo/registry/src/*/rustables-0.9.0/Cargo.toml:41`), which reaches distributed binaries.
  The crate is MIT/Apache-2.0; `nft`/libnftables are GPL-2 (`/usr/share/doc/libnftables1/copyright`)
  but are invoked as a separate program, not linked. (Whether exec counts as aggregation is the
  usual FSF position, not verified legal advice.)
- Build no longer needs bindgen/libclang (AGENTS.md; `e2e/Dockerfile:4`).

### What would shrink

`src/firewall/nfraw.rs` (463 lines), `src/firewall/netlink.rs` (281) and most of the rustables
builder code in `src/firewall.rs` (342) would be replaced by a `Ruleset` -> `Nftables` JSON
conversion. `src/firewall/ruleset.rs` (801) is the IR and stays.

## Option B: link libnftables directly (FFI)

- libnftables exposes `nft_ctx_new`, `nft_ctx_buffer_error`/`nft_ctx_get_error_buffer` and
  `nft_run_cmd_from_buffer` (`man 3 libnftables`, SYNOPSIS lines 9-40). It accepts the same JSON
  (`man 5 libnftables-json`, DESCRIPTION), so the `nftables` crate's types could be serialised and
  handed to it in-process.
- Existing bindings: `libnftables-sys` 0.1.0, released 2018-07-17, GPL-2.0, no repository listed
  (crates.io API): unmaintained. We would write our own (about five `extern "C"` functions).
- Gains over Option A: no exec, no `PATH` or capability-inheritance issues, and errors are
  captured in a buffer. Costs: the binary links against libnftables, which is GPL-2+
  (`/usr/share/doc/libnftables1/copyright`). That swaps rustables' GPL-3 for a GPL-2 link. It
  also needs `unsafe` FFI, the `libnftables-dev` package at build time and `libnftables.so.1` at
  run time (present on the host: `/usr/lib/x86_64-linux-gnu/libnftables.so.1.1.0`).
  Thread safety of a shared `nft_ctx` was not checked.

## Option C: `nftnl` (Mullvad, wraps libnftnl)

- `nftnl` 0.9.4 (2026-08-11) and `nftnl-sys` 0.6.4 (2025-11-26), MIT OR Apache-2.0, at
  github.com/mullvad/nftnl-rs. Commits were landing on 2026-09-05 (GitHub API). It is
  rustables' ancestor. Batches are sent with Mullvad's `mnl` crate (0.3.1, 2026-02-10).
- It is a wrapper over the C libnftnl (`nftnl-sys-0.6.4/Cargo.toml:18-19` `links = "nftnl"`,
  located with pkg-config). That brings libnftnl and libmnl as build and runtime C dependencies,
  and both are GPL-2+ libraries linked into the binary.
- Built-in expressions: bitwise, cmp, counter, ct, immediate, lookup, masquerade, meta, nat,
  payload, socket, verdict (`nftnl-0.9.4/src/expr/`). There is no dynset, limit, log or redir,
  and `Register` has only Reg1-4 (`src/expr/mod.rs:22-27`), so no concatenations.
- **However, the `Expression` trait is public** (`src/expr/mod.rs:12-16`) and `nftnl-sys` binds
  libnftnl's full attribute set, including the DYNSET and LIMIT attributes. Missing expressions
  could therefore be written in-crate against libnftnl's setters, without hand-encoding bytes.
- Errors: we'd still parse acks ourselves, as `netlink.rs` does today.

## Option D: `netlink-packet-netfilter` (rust-netlink, pure Rust)

- 0.4.0 (2026-08-22), MIT, from the rust-netlink org, whose `netlink-packet-core` has about 42M
  downloads. Commits up to 2026-09-13 (GitHub API). It has an `nftables` module with typed
  messages for table, chain, rule, set, set element and gen
  (`netlink-packet-netfilter-0.4.0/src/nftables/message.rs:17-40`).
- Sets include `Description`, `Timeout` and the GC interval (`src/nftables/set/attribute.rs:40-70`).
- The typed expressions are bitwise, cmp, immediate, lookup, meta and payload only. Everything
  else is `Unknown(Vec<DefaultNla>)` (`src/nftables/attributes/expression.rs:33-39`), which is a
  raw-attribute escape hatch. `Register` includes the 32-bit registers `Reg32_*`
  (`.../expression/register.rs:31-41`), so concatenations are expressible.
- No batch-begin/end helper was found in the nftables module, and transport comes through
  `netlink-sys`. Batching and ack parsing stay ours, but in typed Rust instead of byte offsets.
- No C dependencies, no bindgen, no GPL.

## Option E: `neli`

- 0.7.5 (2026-10-20), BSD-3-Clause, actively released. It is a generic netlink framework with
  typed headers and sockets, but has no nf_tables message or expression types. Every nf_tables
  attribute would be defined by us, which amounts to a generalised `nfraw` with nicer framing.

## Option F: stay on rustables (upgrade, patch or fork)

- 0.9.0 (2026-09-21) is what we use. The recent commits are "add timeout to set" (2026-09-19)
  and minimal E2E tests (2026-06-27). Releases come every few months (0.8.5 in 2024-10, 0.8.6 in
  2024-12, 0.8.7 in 2025-07, 0.8.8 in 2026-06). There is one open issue ("Unable to list sets or
  their elements") and no open MRs. Most commits are by two people (GitLab API:
  projects/rustwall%2Frustables).
- 0.9.0 still has no dynset, limit or redir expression (`rustables-0.9.0/src/expr/` lists
  bitwise, cmp, counter, ct, immediate, log, lookup, masquerade, meta, nat, payload, reject,
  verdict). `NatType` covers only SNat/DNat (`src/expr/nat.rs:11-15`). Registers stop at Reg1-4
  (`src/expr/register.rs:11-16`), and `Set` has a timeout field but no desc/size
  (`src/set.rs:37`). AGENTS.md also notes that `RawExpression` can't be built outside the crate.
- Contributing upstream would mean adding dynset, limit, redir, 32-bit registers, set desc and
  a public raw expression. Each lands only at the maintainers' pace, and the crate stays
  GPL-3.0-or-later with bindgen/libclang. A fork carries that load ourselves.

## Option G: generalise `nfraw.rs` into a full hand-rolled encoder

- No dependencies at all, and we keep full control of the error attribution we have today.
  The cost is that we own every byte: `nfraw.rs` is already 463 lines for one feature, and #11
  adds more. Correctness relies on golden captures from `nft --debug=mnl`. This is the most code
  to maintain, with no upstream to share it.

## Option H: shell out to `nft -f` with generated *text*

- `ruleset.rs` already renders nft-style text for `server check` (`impl fmt::Display`,
  `src/firewall/ruleset.rs:183` onwards; golden `tests/data/example.nft`). Option H feeds that
  kind of text to `nft -f -` instead of JSON.
- Verified in the `drawbridge-e2e` image (`nft` 1.1.3, `--cap-add NET_ADMIN`): a file with
  `add table` / `delete table` / full table including a `size 65536; flags dynamic,timeout;
  timeout 10s` concatenated set, the exact drop-log rule shape
  (`... != @s limit rate 50/second burst 100 packets add @s { ... } counter log prefix ...`),
  `ct mark != 0 goto c` and `ct mark set 7 accept` loaded with exit 0. The same file plus
  `jump nosuch` exited 1, **left no table behind** (atomic), and reported
  `/t.nft:15:10-15: Error: Could not process rule: No such file or directory` with a caret under
  the offending token. `nft -c -f` (check only, `man nft` "-c, --check") reported the same kernel
  error without committing. (Scratch file in the session scratchpad, not committed.)
- So text input gives **better error attribution than JSON** (file:line:column against the
  kernel error, versus `internal:0:0-0` for JSON in Option A), which partly answers Option A's
  open question about keeping `FirewallError::DropLog`: the failing line identifies the
  drop-log rules.
- Costs: same runtime `nft` dependency, exec per change, capability and PATH concerns as Option
  A. Without a typed model, quoting/escaping (log prefix, interface names) is ours; names are
  already restricted to `[A-Za-z0-9_.-]` (AGENTS.md), which keeps this small. The text grammar is
  the user-facing one nft keeps stable across versions; JSON output details have varied between
  releases (Option A, "Costs and risks").
- Migration effort is the smallest of all: the renderer exists, and `tests/data/example.nft`
  would become the literal input (today it is "nft-style" text for display, so it would need to
  become exactly loadable, plus the `add/delete table` preamble and session-batch variants).

## Option I: other Rust crates checked

- `mnl` 0.3.1 (2026-02-10, github.com/mullvad/mnl-rs, crates.io API): bindings to libmnl socket
  and batch helpers only; it is the transport under Option C, not an nf_tables model.
- `netlink-packet-route`/`rtnetlink` (rust-netlink): rtnetlink only; nf_tables lives in
  `netlink-packet-netfilter` (Option D).

## Option J: firewall daemons (firewalld etc.)

- firewalld manages its own `inet firewalld` table and its zone/policy model
  (https://firewalld.org/2018/07/nftables-backend). It has no notion of per-session dynamic
  chains, ct-mark-owned flows or the drop-log sets, and adds a D-Bus daemon dependency. Its
  "direct rules" are iptables-only. Unsuitable: Drawbridge would lose atomic whole-table replace
  and its layout invariants. A Drawbridge table can coexist beside firewalld's, which is all that
  is needed. Same reasoning for ufw/shorewall (generators of their own rulesets).

## Comparison

| | A `nftables`+`nft` | B libnftables FFI | C `nftnl` | D `netlink-packet-netfilter` | E `neli` | F rustables | G own encoder |
|---|---|---|---|---|---|---|---|
| Last release | 2025-08-15 | (own bindings) | 2026-08-11 | 2026-08-22 | 2026-10-20 | 2026-09-21 | n/a |
| License (crate / linked) | MIT/Apache / none | ours / GPL-2+ | MIT/Apache / GPL-2+ C libs | MIT / none | BSD-3 / none | GPL-3+ | ours |
| Sets: timeout/size | yes | yes | via sys | yes | DIY | timeout only | DIY |
| dynset, limit, concat | yes | yes | via sys (trait) | raw NLAs | DIY | no | DIY |
| log, ct mark/status, redirect | yes | yes | log/redir via sys | raw NLAs | DIY | no redir | DIY |
| Atomic batch | nft -f (one transaction) | same | ours (+mnl) | ours | ours | ours (custom send) | ours |
| Large batches | handled by nft (5k rules ~180 ms) | same | ours | ours | ours | needs `netlink.rs` | ours |
| Error reporting | nft text, no command index; crate drops stderr | text in buffer | kernel acks (ours) | kernel acks (ours) | acks | acks | acks |
| Build deps | none (serde) | libnftables-dev | libnftnl, libmnl, pkg-config | none | none | bindgen, libclang | none |
| Runtime deps | `nft` binary, caps on exec | libnftables.so | libnftnl, libmnl .so | none | none | none | none |
| Our code | - ~1,090 lines (nfraw, netlink, firewall), + a few hundred for JSON | as A + ~100 FFI | - rustables use; + custom exprs | - nfraw bytes; + raw NLA builders | ~ same as G | + nfraw grows (#11) | + most |
| Tests affected | `drop_log.netlink.hex` byte-match goes; kernel goldens stay | same | goldens stay | hex goldens likely stay | stay | stay | stay |

Option H (text through `nft`) matches column A except: no crate (MIT/Apache question moot), error
reporting is file:line:col with the kernel error, and the existing `Display` renderer is reused.

(Line counts are from `wc -l src/firewall*.rs src/firewall/*.rs`. Additions are estimates, not
measured.)

## Recommendation

**Option A: build `nftables::schema::Nftables` from `Ruleset` and run it with `nft -j -f -`.**
Call `nft` ourselves by absolute path, capturing stderr and applying a timeout, rather than
through the crate's `apply_ruleset`.

Reasons:
- It is the only option that covers every current and planned feature (#11 included) with
  typed values and no byte encoding. That was verified by round-tripping the drop log, redirect
  and `ct status` rules.
- It deletes the most code we own (`nfraw`, `netlink`, the rustables builders) along with the
  GPL-3 and libclang dependencies.
- Atomicity and large batches become `nft`'s job, and `nft` is the kernel project's own reference
  client.

Trade-offs accepted:
- A runtime `nft` dependency and an exec per session change.
- Coarser error messages: there is no per-message index, so `FirewallError::DropLog` loses its
  precision.
- Capability inheritance must be handled in deployment (root or `AmbientCapabilities=`).

Variant to decide during planning: generate **text** (Option H) instead of JSON. It reuses the
existing renderer, gives line-attributed errors, and needs no `nftables` crate; JSON gives typed
construction and round-trip parsing of `nft -j list`. Either way the executor is the same.

Upgrade path: if exec becomes a problem, switch the executor to Option B (libnftables FFI). It
takes the same JSON, so only the transport changes.

Second choice, if "no runtime dependencies" is a hard requirement: **Option D**. It is pure
Rust, MIT, typed for tables, chains, sets and the common expressions, and has a raw-NLA escape
hatch plus 32-bit registers for the rest. It turns `nfraw` from byte offsets into typed
attributes, but batching, ack parsing and the hex goldens stay ours.

Options C and F keep the gaps or add C/GPL linkage. G and E maximise the code we own.

## Open questions / unverified

- Exact minimum `nft` version that accepts every JSON statement Drawbridge would emit (tested only
  1.1.3 and parsing on 1.1.6). Distro targets need checking.
- (Partly answered by Option H: text input attributes kernel errors to file:line:col.) Whether `nft`'s JSON error output can reliably attribute a failure to the drop-log/logging-module
  part of the batch (to keep `FirewallError::DropLog`'s message), e.g. with `nft -e`/`--echo`
  or by a separate `nft -c` check. Not tested.
- Behaviour of `nft` after SIGKILL mid-transaction (timeout handling) was not tested.
- Options B, C and D were assessed from source only. No prototype of them was built or run against a kernel.
- netlink-packet-netfilter: whether its `Unknown(DefaultNla)` expressions emit correctly nested
  attributes for dynset and limit, and whether batch framing exists elsewhere in the crate.
- Thread safety of libnftables contexts. Whether linking libnftables or libnftnl versus exec'ing
  `nft` changes our GPL obligations (not legal advice).
- The added-line estimates in the comparison table are judgement, not measured.
