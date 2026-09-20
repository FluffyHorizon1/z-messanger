# Handoff: fix/contact-erasure-race
Phase: release hotfix — 3.9.0's release build failed twice
Base: main @ `df062b3` (Release 3.9.0)   Built: 2026-09-20

## What changed
- `deleteContact` now runs under the **per-contact lock** every send already
  takes (`_withLock(rid)`), so a send that is in flight cannot commit into the
  middle of the sweep.
- `_sendInner` re-checks membership **inside** that lock: a send queued behind
  a deletion writes nothing — no envelope, no conversation, no message row.
- `_fanToContactExtras` re-reads the extras session under the lock and skips a
  contact that is gone, so nothing is queued to their laptop and `cextra_` is
  not rewritten after the sweep.
- `_sendContactRequest` (a direct `outbox` insert, no session, no lock) gets
  the same membership check.
- `_appendLoaded` no longer creates a thread for a rid that is neither a
  contact nor a group — the in-memory half of the same race, which would have
  put a deleted conversation back on the home screen.
- `contact_erasure_test.dart`: `retry: 2` **removed** from criterion 1, and two
  new criteria that force the race instead of waiting for it (4, 5), using a
  new `@visibleForTesting` seam `debugBeforeSendCommit` that holds a send
  inside the lock one step before its transaction.
- `docs/DATA_MAP.md` erasure row and `docs/AUDIT_SCOPE.md` C33 evidence updated.
- Version 3.9.0+177 → 3.9.1+178.

## Why
The v3.9.0 release run failed in the `test` job, three attempts in a row:

```
❌ app/test/contact_erasure_test.dart: 1. after deleting a contact, nothing in the vault names them
   Expected: empty  Actual: ['outbox.rid', 'outbox.thread_rid']
   Expected: empty  Actual: ['conversations.rid', 'outbox.rid', 'outbox.thread_rid']   (x2)
##[error]332 tests passed, 1 failed, 7 skipped.
```

Nothing downstream ran — `android`, `linux`, `windows`, `macos`,
`reproducible` and `release` all `needs: test` — so there are no artifacts and
no draft release for v3.9.0.

`deleteContact` took no lock. A send holds `_withLock(rid)` from the ratchet
step through the commit, which on a busy machine is tens of milliseconds of
sealing; the deletion's sweep is a sequence of awaited `DELETE`s over the same
rows. Interleave the two and the send commits *into* the sweep. The two leaked
sets are the two places it can land: after the `outbox` delete but before the
`conversations` one (attempt 1), or after both (attempts 2 and 3) — the
deletion's own statement order, read off the failure. 3.7.7 diagnosed this as a
busy build machine and added `retry: 2`; that reading was wrong, and this is
the bug it was hiding.

It is a correctness bug, not a test bug: `DATA_MAP.md` says of deleting a
contact "Nothing locally", and what survived is the contact's routing id, a
sealed envelope addressed to them, and a fresh conversation row — for the life
of the install, in a vault that is supposed to have forgotten them. Deleting a
contact while a message to them is being sent is an ordinary thing to do.

## Invariants touched
- Zero knowledge at the relay — unchanged. Nothing new is sent, logged or
  metered; the change only stops writes to the local vault.
- Metadata minimisation — unchanged. No new message kinds, no new sizes, no new
  timing. One envelope that used to be queued after a deletion is now not
  queued at all, which is strictly less traffic.
- Forward secrecy / PCS — unchanged. The ratchet step for a deleted contact no
  longer happens, but that session is being destroyed in the same breath.
- Erasure (`DATA_MAP.md`, AUDIT_SCOPE C33) — this is the invariant being
  repaired.
- Wire protocol: unchanged.
- New dependencies: none.

## How I verified
- `app/`: `flutter test --concurrency=1` on the committed tree — **335 passed,
  6 skipped, 1 failed**, the one failure being `destructive_confirm_test` 40,
  which fails on `main` on this machine too (see below) and passed in CI. An
  earlier full run of the same tree was **336 passed, 6 skipped, 0 failed**.
  CI's failing run for comparison: 332 passed, 1 failed, 7 skipped.
- Mutation-checked both halves of the fix, which is the part worth re-running:
  - lock removed from `deleteContact` → criterion 4 fails
    (`the deletion waits for the send that holds the lock`) **and** criterion 5
    fails with `['messages.rid']`;
  - membership check removed from `_sendInner` → criterion 5 fails with
    `['conversations.rid', 'messages.rid', 'outbox.rid', 'outbox.thread_rid']`
    — the CI shape exactly.
- `protocol/`: `dart test` — 224 passed.
- `server/`: `npm test` — 119 passed, 0 failed.
- `kt/`: `npm test` — 78 passed, 0 failed.
- `python3 kt/tools/verify_vectors.py` — 344 values reproduced.
- `python3 protocol/tool/verify_mldsa.py` — 39 checks (dilithium-py).
- Guards: `check_audit_scope`, `check_test_criteria`, `check_ga`, `check_l10n`,
  `check_a11y`, `check_android_data_safety`, `check_workflow`,
  `check_blueprints`, `check_relay_url`, `app/tool/contrast.py`,
  `test_verify_reproducible`, `test_check_live_relay`, `test_release_verify`,
  `dry_run_release` — all pass.
- `flutter analyze` — no issues.

## Not done / watch out
- **`app/test/devlist_transparency_test.dart` "split view (a)" is flaky on this
  machine, at about one first attempt in five**, timing out on a 60-second
  `waitUntil` and passing on its own retry. I measured it because a bisect
  appeared to blame this branch: five runs on this branch gave 4 clean / 1
  retried, five on `main` gave 4 clean / 1 retried — the same rate, so it is
  pre-existing and nothing here touches it. (That flake is also why two earlier
  bisect results in this session were wrong; the signal only became readable
  once nothing else was running on the box.) It passed in CI's 3.9.0 run. Its
  own comment already records losing three attempts "on a tag whose code was
  unchanged". Worth its own branch: it is the same kind of retry-as-diagnosis
  this fix just undid.
- **`app/test/destructive_confirm_test.dart` 40 ("resetting a secure session
  asks first") fails on THIS machine under full-suite load**, looking for the
  snackbar text "Secure session reset" and finding none. It failed the same way
  on an unmodified `main` run here, passes in isolation on this branch (2/2),
  and passed in CI's 3.9.0 run — a widget-pump timing issue on a two-core box,
  not this bug and not this branch. It has no retry, so a full local run ends
  "Some tests failed" on it. Worth a look on its own; one bug per branch.
- `_fanToContactExtras` keeps its pre-lock early-out for a contact with no
  extra devices. An earlier draft moved that check inside the lock, which made
  the common case pay a lock acquisition per send for nothing.
- The seam `debugBeforeSendCommit` is `@visibleForTesting` and reads as
  `final gate = ...; if (gate != null)` rather than `await gate?.call(...)` on
  purpose: awaiting a null yields a microtask on every send, and that alone was
  enough to flip `pq_identity_exchange_test`'s envelope counting (I saw it
  fail once with exactly that, and it went green when the null-await went).
  If that call ever becomes unconditional again, expect those counts to move.
- The `retry: 2` still on `pq_identity_exchange_test`'s first test, and on
  `pq_rekey_test`/`pq_upgrade_test`, is a different race (a 100 ms debounce
  against 150 ms settle rounds) and is untouched. Given what this one turned
  out to be, they are worth the same treatment — a seam and a forced
  interleaving — rather than a retry. Not in this branch.
- Version bumped to **3.9.1**. Nothing downstream of the failed v3.9.0 run
  produced artifacts, so re-cutting v3.9.0 would also be defensible; 3.9.1 is
  what I have prepared, since a tag with a failed run attached is confusing.

## Suggested pusher actions
- changelog: n/a (this repo logs releases in the release commit message)
- version bump: done (3.9.1+178) — the release commit message is in this branch
- release: yes — tag `v3.9.1` once CI is green
- redeploy relay: no (no server change)
