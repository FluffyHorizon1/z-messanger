# Handoff: fix/retire-test-retries
Phase: continuous — the retries the 3.9.0 failure taught us to distrust
Base: main @ `05ddc3e` (Release 3.9.1)   Built: 2026-09-27

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
  (`_pqInFlight`), so it is true for a send's whole life.
- `_scheduleDevlistRecheck` no longer pushes out a re-check that is already due
  sooner. It blindly cancelled and re-armed one shared timer, so one contact's
  steady traffic could delay the re-check another contact's echo was waiting
  for — the `unissued` alert. (The common case was always covered by the inline
  `_reevaluateDevlistPending` after each echo; this closes the quiet-echo case.)
  `_offerPqIdentity` already bounds its re-sends this way.
- `replies_test`, `search_test`, `voice_test`: the copied sleep replaced by a
  `settled()` helper that waits on every service being quiet and every outbox
  empty. **13 retries removed.**
- `pq_identity_exchange_test`: the counting test gets a debounce comfortably
  longer than the work it must outlast; the three tests whose nudge arithmetic
  genuinely needs the short one keep it, and now say why. **1 retry removed.**
- `group_test`: the post-leave case drains what is already owed, then asserts
  the thing actually promised. **1 retry removed.**

**32 → 17.** The 17 that remain all name a mechanism; they are listed below for
the next branch rather than removed on a guess.

## How I verified
Each de-retried file run **three or four times in a row on an idle machine** —
a single green run proves nothing about a retry you have just removed:
- `replies_test` + `search_test`: 3/3 clean, 18 tests.
- `pq_identity_exchange_test`: 4/4 clean, 4 tests.
- `voice_test` + `group_test`: 3/3 clean, 5 tests.
Plus the full app suite, `flutter analyze`, and the repository guards.

An intermediate step is worth recording because it disproved something: I first
neutered `quick()` entirely, on the theory that the production debounce would
be safer. That made `asking and answering are both bounded` fail **3 out of 3**
— its rounds are sized against multiples of the debounce, so the knob is
load-bearing arithmetic there, not a speed-up. The narrower fix is what shipped.

## Not done — the remaining 17, triaged
For the next branch. Each already names a mechanism in its comment, or was
classified by reading:
- `devlist_transparency` (3) and `devlist_distribution` (3): several waits
  watch `transport.isConnected`, the *identified* link, then depend on
  consequences of the *anonymous* one; and `versionReaches` is capped at 15 s
  while the surrounding `waitUntil` has 60. Fix the signal, then the retries go.
  "split view (a)" is measurably ~1-in-5 on this hardware, on `main` too.
- `key_transparency` (3): the file's `heldVersion()` helper polls with an
  unawaited read and returns the *previous* iteration's value, so it degrades
  exactly when the box is loaded. There is a `checkUntil` helper in the same
  file that does it properly.
- `pq_rekey` (1), `durability` (1): honestly environmental — a real relay and
  ~10 round trips or ~10 vault reopens. Worth converting to a larger inner
  deadline rather than a retry, but that is a judgement call, not a bug.
- `pq_upgrade` (2), `history_sync` (1), `backup` (1), `attachment_sync` (1),
  `group` (1): unsynchronised negative assertions and snapshot reads. Each is a
  small deterministic fix of the same family as this branch.

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
- The two `app/lib` changes are the reviewable part: `_pqInFlight` and the
  `_devlistTimer` deadline. Both are small and both have tests behind them only
  indirectly — worth a second pair of eyes on whether the devlist one deserves
  a test of its own.
