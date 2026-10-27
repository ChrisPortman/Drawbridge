# 0024: What nft reports when a JSON batch fails

Issue: #24. Question: when `nft -j -f` rejects a batch, what do we get (stdout, stderr, exit
code), can a failure be mapped to the offending command, and what do EPERM and a missing binary
look like?

## Method

All results are empirical, from the `drawbridge-e2e` image (nftables **v1.1.3**, built with
`json: yes`), in containers with `--network none` (a private netns; the host firewall was never
touched). One container had `--cap-add NET_ADMIN`, one had default caps. Inputs were JSON files run
through `docker exec <c> nft -j -f /j/<case>.json`; reading from stdin (`-f -`) gave the same
messages. Kernel: host 7.0.0.

## Findings

### 1. Output channels and exit code

- **Every failure exits 1**, whatever the cause: kernel error, schema error, malformed JSON,
  EPERM, unreadable file. The exit code does not tell the kinds apart.
- **All error text goes to stderr; stdout is empty on failure**, including with `--echo`.
- **Errors are plain text, never JSON**, even with `-j`. There is no machine-readable error output.
- **A rejected batch changes nothing.** `nft list ruleset` was empty after each failed case,
  including ones whose first commands (`add table`) were valid.

### 2. Kernel errors (ENOENT, etc.)

| Case | stderr |
|---|---|
| `add set` in a missing table | `internal:0:0-0: Error: No such file or directory` |
| `add element` to a missing set | `internal:0:0-0: Error: No such file or directory` |
| `add rule` to a missing chain | `internal:0:0-0: Error: Could not process rule: No such file or directory` |
| `jump` to a missing chain | `internal:0:0-0: Error: Could not process rule: No such file or directory` |
| two bad `delete`s in one batch | the `Could not process rule: ...` line **twice**, once per failed command |

Location is always `internal:0:0-0`. Note the first two: nft's own cache/evaluation catches a
missing table or set before the kernel and reports bare `strerror(ENOENT)`, without even
"Could not process rule". The `-c` (check) flag gives the identical message and exit 1.

The same two bad deletes in **native syntax** (`nft -f file.nft`) report each one with
`file:line:col`, the source line and a caret. So nft *does* map each kernel error back to its
command (it matches the netlink ack's sequence number to the command), but the JSON parser
gives commands no source location, so the mapping is lost on output.

### 3. JSON schema / value errors (before anything is sent)

- Missing required field (`"nam"` for `"name"` in an `add chain`):
  ```
  /j/3schema.json:1:4-4: Error: Object item not found: name
  {"nftables":[...]}
     ^
  internal:0:0-0: Error: Parsing command array at index 1 failed.
  ```
  **This is the only message that names a command index** (0-based in the `nftables` array; index
  0 is the `metainfo`-less first command here, the `add table`). The caret position is useless.
- Invalid value (`tcp dport == "notaport"`):
  `internal:0:0-0: Error: Could not resolve service: Servname not supported for ai_socktype`, no
  index.
- **Malformed JSON** (truncated document): nft falls back to the native parser and reports
  `file:1:1-1: Error: syntax error, unexpected '{'`, which is misleading. Treat any such message
  as "our JSON is broken".

### 4. Mapping a failure to the command

- `--echo` (`-e`): prints the committed commands, with `-a` their handles, **only on success**,
  e.g. `{"nftables": [{"add": {"table": {..., "handle": 6}}}, {"add": {"chain": {..., "handle": 1}}}]}`.
  On failure it prints nothing on stdout. Useful to learn handles, not to locate errors.
- `-j` error output: none exists (see 1).
- `-c`: same messages as a real run; no extra detail. It does exercise the kernel (it caught the
  missing jump target), so it's a full dry run but no better at locating errors.
- Handles: irrelevant for failures; a failed batch assigns none.
- Only schema errors carry `index N`. Kernel errors appear one line per failed command, in batch
  order, but with no index, so counting them can't tell *which* commands failed.
- Practical options if we need the culprit: (a) re-run with the native-syntax rendering we already
  have (`server check`) to get line numbers; (b) bisect by submitting prefixes with `-c`; (c) keep
  validating up front so kernel errors are limited to "state changed under us" cases.

### 5. Missing permission (EPERM)

Without CAP_NET_ADMIN (default caps, or uid 1000 in a container that has the cap, i.e. caps lost
across exec: `CapEff` was 0 for the non-root process):

```
netlink: Error: cache initialization failed: Operation not permitted
```
exit 1. With `-c` too: the check needs the cache, so it needs the capability. `nft list ruleset`
additionally prints `Operation not permitted (you must be root)` first. A **schema error is still
reported without the capability** (parsing happens before the cache), so validation-only failures
can mask EPERM. The stable string to match is `Operation not permitted`.

### 6. Missing binary

There is nothing from nft at all: spawning fails. In a shell it's exit 127
(`docker exec`: `executable file not found in $PATH`). From Rust, `std::process::Command::spawn`
/ `output` returns `Err(io::Error)` with `ErrorKind::NotFound` (ENOENT) and no exit status
(std docs, `Command::spawn`), so it is distinguishable from every nft failure above.

## Summary for Drawbridge

Classify an `nft -j -f -` result by: spawn error `NotFound` → binary missing; exit 0 → applied;
exit 1 → failed and nothing changed, with stderr containing `Operation not permitted` → EPERM,
`Parsing command array at index N` → our JSON is wrong at N, otherwise a kernel/evaluation error
whose offending command is not identified. Pass stderr through verbatim in the error. Timeouts
and lost acks (our current `NetlinkError::Timeout`/`AcksLost`) have no equivalent: nft waits for
all acks itself.

## Sources

- Experiments above, nftables v1.1.3 in `drawbridge-e2e`, 2026-10-27.
- `nft(8)` (options `-j`, `-e`, `-a`, `-c`); `libnftables-json(5)` (command array schema).
- Rust std: `std::process::Command::spawn` returns `io::Error` when the program can't be run.
