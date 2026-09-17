# Handoff: fix/connect-invites-progress
Phase: 17 — connecting without meeting (17.3 / 17.3b)   Base: main @ 39a2852 (Release 3.4.3)   Built: 2026-09-17

## What changed
- `app/lib/core/connect_invites.dart` — the ceremony carries itself: a 20 s
  foreground poll (`resume()`/`pause()` from the app lifecycle) while anything
  is pending; `pump()` serialised (a second call joins the one in flight);
  every step failure recorded on the invite (`lastFailure`) instead of
  swallowed; finished runs no longer stepped; a tick after the vault closed
  does nothing.
- `app/lib/core/deep_links.dart` — a link-opened invite is pumped at once
  (awaited) and held in `takeUnshown()` for the first screen to ask, since
  the launch intent is drained before any screen exists to listen.
- `app/lib/ui/invite_link_watcher.dart` (new) — inside the `MaterialApp`,
  wrapping the home screen: opens Add contact on the CONNECT tab when a link
  arrives, one screen at a time.
- `app/lib/ui/add_contact_screen.dart` — `AddContactScreen(connect: true)`.
- `app/lib/ui/connect_tab.dart` — the card shows `lastFailure`
  (`connectLastFailure`, en + es).
- `app/lib/main.dart` — `resume()` after the service starts and on every
  resume; `pause()` on paused/hidden; the watcher around `HomeScreen`.
- `app/android/.../AndroidManifest.xml` — `www.zmessengers.com` beside the
  apex in the invite filter; comment corrected (no chooser on Android 12+).
- `server/pages.js` — `/i` tells a person whose app did not open how to hand
  the invite over by hand (no script; the page test still forbids one);
  comment corrected.
- `docs/USING_Z.md`, `docs/AUDIT_SCOPE.md` C32 (4 → 5, 6 → 9),
  `docs/GA_CHECKLIST.md` (17 → 18 screens), `docs/ROADMAP_8_15.md` entry 93,
  `tool/check_l10n.py` (the new screen held to zero literals).

## Why
Finnian: "the feature where users can generate a code to give to another
user in order to add them doesn't work". Traced at 39a2852: `pump()` ran
only from the CONNECT tab's `initState` and its "Check now" button, so a
four-message ceremony needed both people to press the button alternately in
the right order; a deep-linked invite was written to the vault and nothing
pumped it or showed it; and `pump()`'s `catch (_)` turned every relay
refusal into "Waiting for them". Live: `zmessengers.com` 301s to `www.` and
`/.well-known/assetlinks.json` is 404, so on Android 12+ the link opens in
the browser and the `/i` page offered no way into the app. Design:
`claude/z-remote-add-design.md` ("poll/reconnect the rendezvous mailbox");
ADR 0009; PROTOCOL §20.

## Invariants touched
- Zero knowledge at the relay — unchanged. Each poll is what "Check now"
  always was: a throwaway identity connecting, reading its mailbox, leaving.
  Nothing new is sent, logged or stored server-side; the page gained no
  script (`pages.test.js` asserts it over every route).
- Metadata — unchanged in kind: the relay still sees two ephemeral mailboxes
  exchange four envelopes. It sees them polled every 20 s instead of on a
  human's tap, only while the app is in front.
- The fragment never leaves the device — unchanged. `open()` still touches
  no network; the pump after it is the ceremony's own round, not a fetch of
  the link.
- Sealed sender, ratchet, keys at rest — untouched.
- Wire protocol: unchanged.
- Supply chain: no new dependency.

## How I verified
- protocol/ `dart test`: 198/198 (188 + the 10 relay-driven, which needed
  a `ws` module — the npm registry is not on this sandbox's allowlist, so
  `ws` 8.20.0 was copied in from a global install for the run only; nothing
  under `server/node_modules` is in the patch). Baseline main: identical.
- server/ `npm test`: 106 tests, 84 pass, 22 skipped (no Redis here), 0
  fail. Baseline main: identical.
- app/ `flutter test --concurrency=1` with Flutter 3.44.7 (CI's pin):
  **273 passed, 6 skipped, 1 failed** — the failure is
  `store_full_test.dart` setUpAll "relay did not start in Redis mode", the
  same environment failure as the baseline. **Baseline main: 269 passed,
  6 skipped, 1 failed (the same one).** The +4 are criteria 7–9 of
  `connect_invite_test.dart` and 5 of `deep_link_test.dart`.
- Mutation checks, each restored afterwards: the poll never arming → 7
  fails; failures swallowed as before → 9 fails; `pump()` returning a fresh
  future per call → 8 fails deterministically; the post-open pump and
  `takeUnshown` removed → deep-link 5 fails.
- `flutter analyze`: no issues. Guards: `check_test_criteria`, `check_l10n`
  (18/18, 0 literals), `check_relay_url`, `check_audit_scope`, `check_ga`,
  `check_workflow`, `check_blueprints`, `check_a11y` all exit 0.
- Not run: anything on a device. The App Link path (manifest + `/i` page)
  is verified by reading and by `curl` against the live site, not by a
  phone.

## Not done / watch out
- **Operator, not code — and until it is done the LINK still opens in the
  browser on Android 12+.** (1) Set `ANDROID_CERT_SHA256` on the relay
  service to the Play App Signing SHA-256 (Play Console → Setup → App
  signing), comma-separated if the upload key should also be listed.
  (2) Android's verifier fetches `/.well-known/assetlinks.json` from the
  host in the link and does not follow redirects, so while
  `zmessengers.com` answers 301 to `www.`, the apex can never verify.
  Either make the apex the primary domain on Render (www → apex instead),
  or decide to move `connectLinkHost` to `www.` — that touches
  `docs/vectors/connect/connect.json`'s recorded link and the canonical
  URL, so it is yours, not a builder's. Until one of those, the working
  path is the code (or the link pasted under "I have an invite"), which
  this branch makes work without button-pressing.
- The poll is 20 s, foreground only. A phone left on the CONNECT tab for an
  hour makes ~180 throwaway auths per pending invite; each is one `stats()`
  call on the relay (review finding 43). Not a problem at today's numbers.
- A poll tick between `vault.wipe()` and `exit(0)` is guarded by
  `db.isOpen`; there is no test for that window.
- `retry: 2` was not added to the new relay-driven tests; criterion 7 has a
  120 s deadline inside a 3-minute timeout instead.

## Suggested pusher actions
- changelog: Roadmap entry 93 is in the commit; version bump: yes (3.4.4);
  release: yes — it is a user-visible fix; redeploy relay: yes, for the `/i`
  page text (no relay logic changed), and set `ANDROID_CERT_SHA256` while
  there.
