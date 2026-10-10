# 0001: SSO-capable OIDC provider in the e2e stack

- Issue: https://github.com/ChrisPortman/Drawbridge/issues/3 (#3)
- Status: Accepted
- Date: 2026-10-10

## Context

The portal's confirmation page re-authenticates silently (`/login?silent=1`, i.e. `prompt=none`) at
80% of the remaining ID-token lifetime. With a provider that keeps an SSO session this extends the
session with no interaction. The e2e stack used Dex v2.44.0, which keeps no SSO session and ignores
`prompt=none`. It showed its password form again, so the e2e "silent" step re-submitted the form.
Anyone trying the stack in a browser saw the session expire (#2, closed as working as designed).
The seamless path was never tested end to end. The portal's fallback for a provider that answers
`login_required` (`src/portal.rs`, `INTERACTION_ERRORS`) was never exercised either.

The portal logic itself is out of scope: it already follows `docs/02-specification.oidc.md`.

## Scope

In scope: an SSO-capable provider in the e2e stack; `e2e/run.sh` checks that a silent re-auth
extends the session with no credentials submitted; log evidence from the gateway and the provider;
the fallback when the provider has no session; AGENTS.md and README updates.

Out of scope: changes to `src/`, golden files and kernel tests; automating the browser countdown
check (it is documented in the README instead).

Assumptions made without asking:
- ID tokens stay at 30s.
- `rememberMeCheckedByDefault: false`, so Dex's SSO cookie lasts for the browser session only.
- The no-SSO fallback check runs before waiting past the first token's expiry rather than after it,
  for timing margin (see Decisions).
- The "absent" gateway log check also rejects `session provisioned` and `session replaced`, so the
  re-auth is shown to extend the existing session rather than create a new one.

## Definition of done

- [ ] Dex holds an SSO session (`dex_session` cookie) after the interactive login.
- [ ] A silent re-auth (one GET of `/login?silent=1`) ends on the portal page with 200, with no
      redirect through Dex's password form and no credentials submitted.
- [ ] The session's expiry moves out and the portal session cookie is kept.
- [ ] In that window the gateway logs `session extended` and none of `session expired`,
      `session provisioned` or `session replaced`; the lines are printed.
- [ ] In that window Dex logs `re-authenticated from session` and no `login successful`; the lines
      are printed.
- [ ] Without the SSO cookie, a silent re-auth gets `error=login_required` and lands on Dex's form;
      submitting it extends the session with no deprovisioning logged.
- [ ] The existing checks still pass (open past the first expiry, flow survives, closed at the final
      expiry, flow dies, session removed), and a final `session expired` log check shows the
      "absent" checks would see an expiry.
- [ ] A user's Dex session does not leak into the next user's login.
- [ ] `./e2e/run.sh` passes; `cargo fmt --check`, `cargo clippy --all-targets`, `cargo test` clean.
- [ ] AGENTS.md and README updated, including how to watch re-auth in a browser.

## Decisions

**Which provider.** Options: upgrade Dex to v2.46.0 and enable its auth sessions; switch to
Keycloak; Authentik; Authelia. The user pointed out that Dex can keep SSO sessions. v2.46.0
(released 2026-10-07) answers `prompt=none` from its session and returns `login_required` without
one. Chosen: upgrade Dex. It is the smallest change: same container, users, client and policy. The
trade-off accepted is that sessions are experimental in Dex (`DEX_SESSIONS_ENABLED`), so the image
tag is pinned (by tag, like the stack's other images, not by digest). Keycloak was the alternative: mature, but a heavy JVM image with slower startup, a
realm file to maintain and no `ip` tool for the reply route.

**How to keep the no-SSO coverage.** Options: drop the provider's SSO cookie and check the portal
falls back to the form on `login_required`; keep a second Dex without sessions; drop the check.
Chosen: drop the cookie. It is cheap, and it exercises the portal's fallback, which the old Dex
never reached. Providers that ignore `prompt=none` entirely are no longer tested; the portal shows
their form the same way.

**Log evidence.** Options: assert and print, assert only, print only. Chosen: assert and print,
using `docker compose logs --since/--until` windows around each action, so every run shows the
evidence the issue asks for. The trade-off accepted is a dependence on log wording; the Dex message
(`re-authenticated from session`) is logged only at debug, so `e2e/dex.yaml` sets debug logging.

**Ordering of the fallback check.** It runs straight after the silent re-auth, before waiting past
the first expiry. Run after the wait it would have about 8s before the extended session expired, so
a slow `docker exec` could turn an extension into a fresh login; before the wait it has about 24s.

**Same browser, different user.** With sessions on, Dex logs a browser back in as whoever it last
saw. The e2e therefore drops Dex's cookie (`forget_provider`) before logging in as another user, as
a real browser would need a provider logout.

## Implementation summary

- `e2e/dex.yaml`: `sessions:` block, debug logging.
- `e2e/compose.yaml`: Dex v2.46.0, `DEX_SESSIONS_ENABLED=true`.
- `e2e/run.sh`: helpers `submit_password`, `silent_login`, `hops_include`, `provider_session`,
  `forget_provider`, `now_ts`, `logs_between`, `log_has`; `forget_provider` between bob and alice;
  the "session lifetime" section rebuilt around silent re-auth, the fallback and log checks.
- `AGENTS.md` (e2e conventions) and `README.md` (Development, watching re-auth in a browser).
- No `src/`, golden file or kernel test changes.

## Deviations

- After review, a positive `session provisioned` log check was added around alice's interactive
  login, so the "absent" gateway checks are shown to match that wording too. `session replaced`
  has no trigger in the run and keeps no positive check.
- The pre-existing drop-log check "the dropped key is remembered" fails on `main` as well as on
  this branch. It is unrelated to this change and was left for a separate bug.

## Consequences

The e2e now tests the path production users see with an SSO provider, and the portal's
`login_required` fallback. It depends on an experimental Dex feature and on a debug log message;
upgrading Dex needs these checks re-verified. Any future e2e login as a second user must call
`forget_provider` first.
