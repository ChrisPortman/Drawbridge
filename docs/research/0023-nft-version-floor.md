# 0023: Minimum nft version for Drawbridge's JSON

Research for issue #23 (parent #22). Question: what is the oldest `nft`/libnftables whose JSON
input (`nft -j -f -`) accepts everything Drawbridge emits, and how do we read the version
reliably? That version is the floor preflight enforces.

## Answer

- **Floor: nftables 0.9.3**, provided set objects do **not** list `"dynamic"` in `flags`.
  0.9.3 is the oldest release confirmed by experiment. **0.9.1** is the oldest whose JSON parser
  takes the current schema, going by its source; no distro ships 0.9.1 or 0.9.2 to test with.
- **If the JSON lists `"dynamic"` in set `flags`, the floor is 1.0.9.** Every release before
  that rejects it with `Invalid set flag`.
- **Recommendation:** leave out `"dynamic"`, as all versions tested accept that, and enforce
  **>= 0.9.3**. That covers Ubuntu 20.04 (0.9.3), Debian 11 (0.9.8), Ubuntu 22.04 (1.0.2),
  Debian 12 (1.0.6) and Ubuntu 24.04 (1.0.9). Debian 10 (0.9.0) is below it, because its JSON
  uses a different `jump`/`goto` shape. Leaving `"dynamic"` out costs nothing: nft's evaluator
  marks a set that a rule's `set` statement updates as dynamic itself, and the kernel then
  accepts and fills the set (shown below).
- **Reading the version:** run `nft --version` (no privileges or netlink needed) and parse
  `^nftables v(\d+)\.(\d+)\.(\d+)` (there may be a 4th component, e.g. `1.0.6.1`). The JSON
  `metainfo` object (`version`, `release_name`, `json_schema_version`) is a cross-check, not
  the primary source: it needs netlink access (`nft -j list ...`), and 0.9.0 doesn't emit it.

## Experiment

The input was the golden `tests/data/sessions.kernel.nft`. It contains everything listed in
the issue: four concatenated-key timeout sets of `size 65536`, `limit rate 50/second burst 100
packets`, `add @set { ... }`, `!= @set` lookups, `counter`, `log prefix`, `goto`/`jump`, and
`ct mark set` / `ct mark` matches. It was loaded into nft 1.1.3 (the `drawbridge-e2e` image),
dumped with `nft -j list ruleset`, and turned into an input batch: `add table`, `delete table`,
then `{"add": ...}` for each set, chain and rule. Handles and counter values were stripped
(`"counter": null`). There were two variants: `with_dynamic` (set flags
`["timeout","dynamic"]`, exactly what 1.1.3 lists) and `no_dynamic` (`["timeout"]`). Each
was applied with `nft -j -f` inside a container (`--cap-add NET_ADMIN`, so in the container's
own netns; the host firewall was never touched).

| Image | nft | `with_dynamic` | `no_dynamic` |
|---|---|---|---|
| debian:buster | 0.9.0 | FAIL: `Invalid set flag` | FAIL: `Verdict goto needs chain argument` |
| ubuntu:20.04 | 0.9.3 | FAIL: `Invalid set flag at index 1` | OK |
| debian:bullseye | 0.9.8 | FAIL: `Invalid set flag` | OK |
| ubuntu:22.04 | 1.0.2 | FAIL: `Invalid set flag` | OK |
| debian:bookworm | 1.0.6 | FAIL: `Invalid set flag` | OK |
| ubuntu:24.04 | 1.0.9 | OK | OK |
| drawbridge-e2e | 1.1.3 | OK | OK |

After the `no_dynamic` load, `nft list ruleset` on 1.0.2, 1.0.6, 1.0.9 and 1.1.3 shows
`flags dynamic,timeout` on all four sets. So the evaluator adds the flag, and the result
matches what `with_dynamic` produces. 0.9.3 and 0.9.8 don't print the flag, so the
experiment was run again on 0.9.3 with `iifname "lo"` and two pings to 127.0.0.1. The
dynset filled the set and the default action counted the packets:

```
elements = { 127.0.0.1 . 127.0.0.1 . 1 expires 7s994ms }
iifname "lo" counter packets 2 bytes 168 drop
```

So on 0.9.3 the kernel accepted the dynset on the set and it works: the drop log
deduplicates as intended.

## Source evidence (release tarballs from netfilter.org)

The files are `src/parser_json.c`, `src/json.c`, `src/evaluate.c` and
`doc/libnftables-json.adoc` from
`https://www.netfilter.org/projects/nftables/files/nftables-<v>.tar.{bz2,xz}`, for every
release from 0.9.0 to 1.1.3.

- **JSON parser exists since 0.9.0**, with these already present: the `set` statement with
  `op: "add"|"update"` (`json_parse_set_stmt`, mapped to `NFT_DYNSET_OP_ADD`), `limit` with
  `rate`/`burst`/`per`, `concat`, `log` (`prefix`), `counter`, `mangle` (used for
  `ct mark set`), and set objects with `size`, `timeout`, `gc-interval` and a type given as an
  array (concatenated keys).
- **`jump`/`goto` changed shape in 0.9.1.** 0.9.0 parses the verdict as a bare string
  (`json_unpack(root, "s", &chain)`, so `{"goto": "chain"}`). From 0.9.1 on it is
  `{"goto": {"target": "chain"}}` (`json_unpack_err(ctx, root, "{s:s}", "target", &chain)`),
  and current nft emits only that form. 0.9.1 is also the first tarball that ships
  `doc/libnftables-json.adoc` (`*{ "goto": { "target": * 'STRING' *}}*`) and the first whose
  output has the `metainfo` object with `json_schema_version` (still 1 in 1.1.3).
- **`"dynamic"` set flag in JSON since 1.0.9.** In 0.9.0–1.0.8 the parser's set flag table is
  only `constant`, `interval` and `timeout`. 1.0.9 adds `{ NFT_SET_EVAL, "dynamic" }` to
  `parser_json.c`, and `json.c` begins listing it. Even the 1.1.3 man page still documents
  `SET_FLAG := "constant" | "interval" | "timeout"`, so on this point the man page is behind
  the code.
- **The evaluator sets `NFT_SET_EVAL` itself** on a set that a dynset statement targets. This
  is the `set->set_flags |= NFT_SET_EVAL` path in `evaluate.c`, present throughout the 0.9.x
  and 1.x tarballs. That is why `no_dynamic` works.
- **`json_schema_version` on input:** if present, it must not exceed the parser's built-in
  value (libnftables-json(5), "METAINFO OBJECT"). Drawbridge can leave it out, or send 1.

## Implications for #22 / #26

- Emit `{"goto": {"target": ...}}` / `{"jump": {"target": ...}}` (the 0.9.1+ form). Never put
  `"dynamic"` in set `flags` unless the floor is raised to 1.0.9.
- Preflight: parse `nft --version`, then reject anything below 0.9.3 with a message naming the
  floor. Optionally, `nft -c -j -f` the planned batch (a check needs CAP_NET_ADMIN but commits
  nothing) as a stronger, feature-based test than a version compare.
- Not covered here: kernel feature requirements (concatenated dynset keys, `th` payload,
  set `size`), which are a separate floor from nft's. Every container shared the Docker host's
  kernel, so these results say nothing about older kernels.
