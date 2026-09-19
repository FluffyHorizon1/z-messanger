# ADR 0014 — Telling a user they are behind, without becoming a beacon

**Status:** **Accepted** (2026‑09‑19) — built (24.4). Client‑only notice; the
relay grows one read‑only route and no client is ever updated in place.
**Decides:** whether the app checks for a newer build at all, where it asks, and
what that check is allowed to reveal.

## Context

`THREAT_MODEL.md` R8 records a real gap: a desktop user can be served an older
release with valid provenance, and Play aside, nothing tells them. The honest
fix is a notice — "a newer version exists, here is where to get it" — **not** an
in‑app updater. An updater is a code‑execution channel into every install, which
is exactly the power this project refuses to hold; R8 says so and this does not
touch it.

The hard part of a notice is not the comparison, it is the *call*. Any
"am I current?" check fetches a "latest" from some host, and that host learns an
address and a time. Done naively — a GitHub `releases/latest` poll — it hands a
third party (GitHub/Microsoft) every install's IP on a schedule, which for a
zero‑trust messenger is a new and needless metadata leak.

## Decision

A **self‑hosted, identity‑free, user‑triggered** check.

1. **Source: the relay's own `/latest.json`.** The web host `pages.js` already
   serves the site; it gains one route that returns `{"version","url"}` from a
   `Z_LATEST_VERSION` env var, and **404s when unset** — the same honest shape as
   `/.well-known/assetlinks.json` (unset is no claim, not a claim of "0"). A
   non‑semver value is treated as unset, so a typo cannot ship a junk "latest".
2. **The client asks the host it already dials.** `update_check.dart` derives
   `https://<relay-host>/latest.json` from the relay URL (`wss`→`https`,
   `ws`→`http`), so the check reaches **no new party** — the relay already sees
   this address on the WebSocket. The GET is identity‑free: no account, no
   routing id, no cookie, no body; the same file every install gets.
3. **User‑triggered, once a day.** The check runs when Settings is opened, at
   most once per 24 h (a timestamp in the plaintext `prefs.json`). It is not a
   background poll — R30's periodic‑beat shape is deliberately not repeated.
4. **The version is the build's own.** `package_info_plus` reads the version
   from the platform bundle, so the number cannot drift the way the old
   hardcoded "1.0.0" did (eighteen releases stale). A strictly‑newer answer
   shows a non‑blocking notice with the version and a link; equal, older,
   malformed, missing or unreachable shows nothing.

## Rejected

- **A GitHub `releases/latest` poll.** Nothing new to host, but it hands a third
  party every install's IP on a schedule. The self‑hosted source keeps the check
  on infrastructure the user already chose and already talks to.
- **An in‑app updater / auto‑download.** A code‑execution channel into every
  install (R8). The notice links out; nothing is fetched or run.
- **A background poll, or a check on every launch.** More timely, but a periodic
  beacon is exactly R30's shape and a worse metadata trade than the notice is
  worth. Once a day, on a screen the user opened, is enough to close R8's "nobody
  tells them" without becoming a heartbeat.
- **A hardcoded version const + a CI drift guard.** Considered (it avoids a
  dependency and is reproducible‑safe), but `package_info_plus` reads the real
  built version, so it cannot drift at all — no guard, no release‑time step, and
  it is the mechanism the settings screen's own comment already anticipated.

## Consequences

- **New residual: R35.** The check reveals to the relay host that an install
  looked for an update — its address and a daily timestamp. Accepted, because
  that host already sees the WebSocket from the same address, the request names
  nobody, and a self‑hoster who leaves `Z_LATEST_VERSION` unset prompts nobody.
- **Zero‑knowledge, sealed sender, ratchet, wire protocol:** untouched. The relay
  route is a static read; the client call is a plain GET beside the traffic it
  already sends.
- **Self‑hosting:** `SELF_HOSTING.md` documents `Z_LATEST_VERSION` — set it to
  your release version to prompt your users, leave it unset to prompt nobody.
  The official relay sets it on each release.
- **Dependency:** `package_info_plus` (+ its platform interface), small and
  reading only build metadata the bundle already carries; no `.so` on Android,
  so the reproducibility fingerprint is unchanged.
- Tested in `update_check_test.dart` (the compare and the fetch, no network) and
  `server/test/pages.test.js` (the route, served only when configured). C38.
