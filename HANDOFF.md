# Handoff: fix/retire-test-retries
Phase: continuous — the retries the 3.9.0 failure taught us to distrust
Base: main @ `9ec3496` (Release 3.9.2)   Built: 2026-09-30

## Why
3.9.0's release build failed three attempts running on `contact_erasure_test`,
and the `retry: 2` that had been on it since 3.7.7 — added with a comment
blaming a busy build machine — turned out to be hiding a real erasure bug. That
raised the obvious question about the other 31. This branch is the answer to
it: every one was triaged against its test body and its originating commit.

## What the triage found
- **11 of the 32 were never a finding.** `replies_test` (9) and `search_test`
  (2) have no comment at all, and `git log -S` shows each arrived in the *same
  commit that introduced the test* — `d4922ca`, `7c4234e`, `05ce539` — none of
  whose messages mentions a flake. They are boilerplate copied onto new
  real-relay tests, and all 11 sit on one copied
  `await Future.delayed(const Duration(seconds: 1))` after the mutual add.
- **One test seam was lying.** `pqSendPending` read `_pqTimers.isNotEmpty`,
  which is false in two places a send actually occupies: the ANSWER path never
  registers a timer, and the timer path removes its entry before sending. A
  settle loop polling it could return with an envelope still being sealed.
- **One test contradicted the app's own contract.** `group_test`'s post-leave
  case asserted a removed member's message count does not change, while
  `_drainGroupFanout` deliberately still serves anything queued before the
  leave propagated. The retry was absorbing the app behaving as designed.
- **One flake was real and is now understood.** `pq_identity_exchange`'s
  `quick()` shrank the send debounce to 100 ms, which is competitive on a
  two-core box with the work the debounce exists to outlast (an ML-DSA check,
  a vault seal, a sqlite write) — so the volunteer scheduled on the `hello`
  sometimes fired before the answer to the `pqid` behind it could cancel it,
  and the side sent twice. That is what the test counts and refuses.

## What changed
- `pqSendPending` now counts sends in flight as well as scheduled
  (`_pqInFlight`), and in-flight `pqack`s (ADR 0021), so it is true for a
  send's whole life.
- `_scheduleDevlistRecheck` no longer pushes out a re-check that is already due
  sooner. It blindly cancelled and re-armed one shared timer, so one contact's
  steady traffic could delay the re-check another contact's echo was waiting
  for — the `unissued` alert. (The common case was always covered by the inline
  `_reevaluateDevlistPending` after each echo; this closes the quiet-echo case.)
  `_offerPqIdentity` already bounds its re-sends this way.
- `replies_test`, `search_test`, `voice_test`: the copied sleep replaced by a
  `settled()` helper. **13 retries removed.**
- `key_transparency_test`: `heldVersion()` fired its vault read UNAWAITED
  inside a synchronous predicate and tested the previous poll's value, so it
  lagged by at least one poll always and by much more under load — every 30 ms
  it queued another read onto the serialised sqlite connection. Awaited.
  **3 retries removed.**
- `pq_identity_exchange_test`: the counting test gets a debounce comfortably
  longer than the work it must outlast; the three tests whose nudge arithmetic
  needs the short one keep it, and now say why. **1 retry removed.**
- `group_test`: the post-leave case asserted something the app does not promise
  (`_drainGroupFanout` deliberately still delivers what was queued before the
  leave propagated), and its negative now waits for the fan-out AND the
  sender's outbox to drain before its margin starts. **1 retry removed.**
- `devlist_transparency`, `devlist_distribution`: the waits watched
  `transport.isConnected`, the IDENTIFIED link, then depended on consequences
  of the ANONYMOUS one — `onConnected`, which flushes the outbox and
  re-asserts a root's list, fires only when both are up. A `linked()` helper
  waits on both, and the version polls got the same budget as the waits around
  them. **No retries removed** — see below.

## How I verified
Each de-retried file run **three times in a row on an idle machine** — a single
green run proves nothing about a retry you have just removed:
- `replies_test` + `search_test` + `voice_test` + `group_test` +
  `key_transparency_test`: 3/3 clean, 32 tests, after the helper rewrite below.
- `pq_identity_exchange_test`: 4/4 clean.
- `group_test` again after its margin change: 3/3.
Plus the full app suite — **346 passed, 6 skipped, 1 failed**, the one
failure being `destructive_confirm_test.dart: 40. resetting a secure session
asks first`, which this branch does not touch, carries no `retry:`, fails
only on this two-core box under load and passes in CI. Plus `flutter
analyze` and every repository guard.

**Three things went wrong on the way, and they are the reason to trust the
rest.** First: I neutered `quick()` entirely, on the theory that the production
debounce was safer; `asking and answering are both bounded` then failed 3 out
of 3, because its rounds are arithmetic on multiples of that debounce. Second:
I removed the six device-list retries after two green runs, and the next run
failed — so they are back, with a comment saying what is known and what is
not. Third: the first `settled()` sampled `pqSendPending` once BEFORE its
awaited outbox reads and never re-tested it, and everything it watched was
local send-side state — so between both sides handing their contact requests
to the relay and either processing one, it could return having waited for
nothing at all. It now waits for a positive signal first (each side that has
the other as a contact actually holds their post-quantum key, which means the
requests crossed, the hello landed and a session exists), then for quiescence,
reading the outbox last and re-reading the flag after it.

## Not done — the remaining 14, triaged
For the next branch.

- **`devlist_transparency` (3) and `devlist_distribution` (3) — kept, and the
  honest state is "improved, cause not yet found".** The waits now use
  `linked()` (both transport links, which is what `onConnected` gates on) and
  the version polls got the same budget as the waits around them. That took
  the family from failing often to failing about one first attempt in three on
  this two-core box. I removed the retries on two green runs, the next run
  failed, and I put them back. What still times out is unidentified; the waits
  have no `what:` labels, so the first job on this next is to label them and
  find out which one it is.
- **`pq_rekey` (1), `durability` (1)** — nothing in either body is wall-clock;
  every wait is an awaited poll. What varies is only how much of a 3-minute cap
  a loaded box eats across ~10 real-relay round trips or ~10 vault reopens.
  `durability` also still carries the copied 1-second handshake sleep, which
  `settled()` would replace.
- **`pq_upgrade` (2)** — an unsynchronised NEGATIVE assertion
  (`expect(offerer.isPostQuantumWith, isFalse)`) taken right after a positive
  `waitUntil`: the instant the initiator holds the secret, every envelope it
  seals carries the ciphertext, and it has unprompted sends due right then, so
  "the offerer has no ciphertext yet" is only true at an instant no poll can
  name. The fix is to sample it inside `debugBeforeSendCommit`, which runs
  after the seal and before the outbox row. Its sibling has a
  `Future.delayed(500 ms)` sitting exactly on `pqSendDebounce`.
- **`history_sync` (1)** — `addMyDevice` fires the replay unawaited, so an
  exact-count assertion rests on 500 ms being longer than whatever is still
  coming. Wants a seam exposing that future.
- **`backup` (1)** — waits on a message body in memory, then asserts on state
  read off disk; `_appendLoaded` runs INSIDE the inbound transaction, so the
  body is visible before the commit. Wants a "committed" barrier.
- **`attachment_sync` (1), `group` (1)** — the copied sleep again, and a
  negative assertion bounded by a bare two seconds.

A subagent produced exact before/after patches for all eight of the
non-devlist ones; they are sound on reading and none of them is applied here,
because applying eight unverified changes at the end of a branch about not
trusting unverified changes would be the joke writing itself. They are the
next branch's starting point.

Two things the triage raised that I checked and **did not** act on, because the
code already handles them: `flushOutbox` gating on the identified link (the
transport's `_maybeAnnounceUp` only announces when both links are up, and
`_handleSenderClosed` resets it, so the outbox does flush on reconnect); and
the device-list alert being suppressible by a chatty contact (line 7031
evaluates inline after each echo, preserving `seen`). Both were plausible and
specific and both were wrong; I mention them so nobody re-derives them.

## Suggested pusher actions
- changelog: n/a; version bump: **no** (tests and two small app changes, no
  user-visible behaviour); release: no; redeploy relay: no
- Unrelated and pre-existing on `main`, noticed while running the analyzer and
  deliberately left alone so this branch stays one thing: `flutter analyze`
  reports one warning, an unused `identity.dart` import at
  `protocol/lib/src/connect.dart:42`. CI does not run the analyzer, so nothing
  is red because of it.
- The two `app/lib` changes are the reviewable part: `_pqInFlight` and the
  `_devlistTimer` deadline. Both are small and both have tests behind them only
  indirectly — worth a second pair of eyes on whether the devlist one deserves
  a test of its own.
