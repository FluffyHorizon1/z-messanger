# ADR 0014 — Telling a user they are behind, without becoming a beacon

**Status:** **Accepted** (2026‑09‑19) — built (24.4). Client‑only notice; the
relay grows one read‑only route and no client is ever updated in place.
**Amended 2026‑10‑04:** the link is the app's own, never the relay's — the Play
listing for a Google Play install, the release page otherwise (see the end).
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
  The official relay does not set it yet: no Blueprint does, and its
  `/latest.json` answered 404 on 2026‑10‑03, so its users are not prompted.
- **Dependency:** `package_info_plus` (+ its platform interface), small and
  reading only build metadata the bundle already carries; no `.so` on Android,
  so the reproducibility fingerprint is unchanged.
- Tested in `update_check_test.dart` (the compare and the fetch, no network) and
  `server/test/pages.test.js` (the route, served only when configured). C38.

## Amendment (2026‑10‑04) — the relay says *whether*, the app says *where*

Decision 1 had the route return `{"version","url"}`, and the client showed that
`url` as where to get the newer build. That made the download address the
relay's choice. The relay — or anyone able to answer in its name on that host:
whoever terminates its TLS, a self‑hoster's proxy — could put any address in
front of every user of it, with the app's own notice vouching for it. And the
one address the official relay serves, the GitHub release page, is wrong for a
Google Play install: Play App Signing signs the Play build with Google's key
and the release page's APK with the project's, and Android will not install one
over the other.

1. **The client never reads `url`.** The answer decides whether a newer version
   exists, and its number; nothing else in it is used.
2. **The link is a constant in the app, chosen by who installed it**
   (`updateDestination`, `update_check.dart`): an install whose installer is
   Google Play (`com.android.vending`) is sent to the Play listing; everything
   else — the desktop builds, an APK from the release page installed through
   the system installer, a browser or a file manager, another store, `adb` — is
   sent to the project's release page. The installer is read through
   `package_info_plus`, already a dependency (`installerStore`: on Android the
   installing package, from `InstallSourceInfo` on Android 11 and later; null on
   the desktop platforms). No native code of ours changes. A build flavour or a
   build‑time define was the alternative and is not available: CI builds the
   Play bundle and the release APK from the same sources with no flavour and no
   define, so the installer is the signal that exists.
3. **No link is stored.** `prefs.json` keeps the time of the check and the
   version. A `upd.url` an earlier build stored there is not read back, and the
   next check's write drops it.
4. **The route is unchanged.** It still sends `url` (the release page), because
   builds before this one show it. This one ignores it.

Consequences:

- **What the relay still decides:** whether a notice appears, and the version
  it names. It can claim a newer version — the user is sent to the real release
  page or Play listing and finds what is there, a nuisance rather than a
  redirect — or withhold one, which is R8's gap as before. R35 gains a sentence.
- **A store that installs Play's build under another installer name** (a
  third‑party Play client) is not recognised, and its users are shown the
  release page, whose APK will not install over that build. Accepted: rare, and
  the failure is an install Android refuses, not a different app.
- **Operating the official relay:** Play users are now sent to Play, so
  `Z_LATEST_VERSION` should name a version only once Play offers it; set
  earlier, Play users are told of an update Play does not have yet.
- **Forks and self‑hosters** who publish builds elsewhere change
  `releasesPageUrl` and `playListingUrl` in `update_check.dart`. The trust
  decision belongs in the build the user installed, not in a server's answer.
- Tested in `update_check_test.dart` (criteria 3 and 6–9): the link in the
  answer is not what is shown; the Settings notice shows the release page to an
  install not from Play even with a planted link left in `prefs.json`, and the
  Play listing to a Play install even when the relay names the release page;
  the installer alone picks the link; and nothing about it is kept.
