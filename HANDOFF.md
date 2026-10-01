# Handoff: fix/retire-test-retries-2
Phase: continuous — the fourteen retries the first pass left
Base: main @ `50d9786` (Release 3.9.4)   Built: 2026-10-01

## Why
`50d9786` ended the first pass with fourteen live `retry:` annotations in
`app/test`, each triaged in the previous handoff and none acted on. The rule
this pass ran under came from 3.9.0: a `retry: 2` on `contact_erasure_test`,
blamed on a busy machine, had hidden a real erasure bug since 3.7.7. So no
retry came off here without a diagnosed cause and at least four consecutive
clean runs of its file under the shared lock, and every count below was
measured.

## What the triage found
- **Thirteen of the fourteen arrived in the same commit as the test they sit
  on** (`git log -S`): `71a5fc8` durability, `134d04e` devlist_transparency
  (3), `43423fa` devlist_distribution (3), `b805ff5` pq_upgrade (2),
  `17be9c1` pq_rekey, `4569558` history_sync, `eb8a408` backup, `e584b9d`
  group (the attachments case). None of those messages mentions a flake.
- **The fourteenth was a response to one.** attachment_sync's `retry: 3`
  went on in `4a01302` beside two real self-sync fixes (a ~25% CI flake),
  "to absorb residual ratchet-establishment timing". Ten days later
  `e584b9d` found the most plausible residual: concurrent assembly — the
  offer's post-processing and the last chunk both calling `_tryAssemble` —
  storing a key from a different run than the bytes, an attachment that
  never opens. That is the linked device's exact path in this test, and
  assembly has been serialized per fid since. Plausible, not proven.
- **One was covering a real race, and it was in a fixture**:
  devlist_transparency's split view (a), which failed about one run in two.
  The device whose routing id sorts first opens the phone–laptop sync
  session, and until it has heard back on it, everything it sends there
  carries the session's ephemeral key (`ek`). The rogue holds the phone's
  identity key and takes over the phone's mailbox, so when the LAPTOP was
  the opener and the phone went offline inside that window, the first such
  envelope the rogue received (one the phone had not acknowledged, or the
  laptop's next mirror) let it re-derive the SAME session — same id, same
  root key — and answer on it with a ratchet key of its own. The laptop
  followed the rogue's branch; the honest phone came back on its own branch
  of that session, which the laptop could no longer decrypt ("authentication
  failed"), and the laptop's answers failed at the phone ("pq message without
  a shared secret"). The phone's re-asserted v2 never arrived and the wait
  for the laptop's `olderList` alert timed out. Seen directly in decrypt
  traces, then confirmed by forcing the order: laptop as opener, 4 runs in 8
  failed (two on both attempts, past `retry: 1`); phone as opener, 0 in 6.
- **Two of the previous triage's premises did not survive checking**, so the
  seams it proposed were not added:
  - history_sync: the replay is ONE envelope here (12 items, batch of 100)
    and the test's own wait for ten messages is that envelope landing, so
    nothing of the replay can still be coming. The exact counts rest on
    message-id de-duplication (`_appendLoaded` and the `(rid, mid)` key both
    ignore a repeat); the 500 ms only let the live message's second copy
    arrive to be counted. A seam exposing the replay future would be a no-op
    with no failing test behind it.
  - backup: sqflite queues a read on the database behind an open transaction
    (`sqflite_common` 2.5.11, `txnSynchronized` takes `_rawLock`, which a
    transaction holds until it commits), so a body seen in memory and then
    read back through `vault.db` is read committed. No "committed" barrier
    needed; none added.
- pq_upgrade's negative (`offerer.isPostQuantumWith` is false) was a real
  race in the test: true only at an instant no poll can name, because the
  initiator's unprompted sends carry the ciphertext the moment it holds the
  secret.

## What changed (test files only)
- `devlist_transparency_test.dart`: every wait labelled (`what:`, required);
  `bringUpAccount` now ends with `syncSettled` — each side has heard back on
  the sync session it sends on (read from the persisted `sync_session`) and
  the relay holds nothing unacknowledged (`/health` `queuedEnvelopes`); a
  relay per test so that question has an answer after the first test; the
  control case's negative margin now starts when the echoes have arrived,
  not at the send. **3 retries removed.**
- `devlist_distribution_test.dart`: every wait labelled; no failure in any
  run. **3 removed.**
- `pq_upgrade_test.dart`: the negative is sampled inside
  `debugBeforeSendCommit` at the commit of the initiator's first envelope
  sealed with the secret; in the sibling, the 500 ms sleep (equal to
  `pqSendDebounce`, covering nothing) is gone and the test's premise — the
  hello reaches a stranger and is dropped — is made true by waiting, before
  the offerer adds, until the initiator's outbox is empty and then the relay
  holds nothing. **2 removed.**
- `durability_test.dart`, `backup_test.dart`, `history_sync_test.dart`,
  `attachment_sync_test.dart`, `group_test.dart`: the copied one-second
  handshake sleep replaced by `settled()` (the final form from
  `replies_test.dart`; group case 1 had it too, unretried). group case 2's
  two-second negative now starts after Alice's fan-out and outbox have
  drained; history_sync's 500 ms margin now waits for the phone to hold the
  message, every outbox to be empty and then the relay to hold nothing;
  labels where missing. **1 removed each.**
- `pq_rekey_test.dart`: body unchanged — every wait was already an awaited,
  labelled poll. **1 removed.**

Live count, `grep -rn "retry: [0-9]" app/test/ | grep -v "^\S*:[0-9]*: *//" | wc -l`:
**14 before, 0 after.**

## Invariants touched
- None. `git diff 50d9786 -- app/lib protocol server kt` is empty: zero
  knowledge at the relay, sealed sender, forward secrecy, key material and
  the trust model are untouched, and nothing new is trusted.
- Wire protocol: unchanged (no protocol or app code changed at all).
- The investigation used temporary `print` tracing in
  `protocol/lib/src/session.dart`, `app/lib/core/device_sync.dart` and
  `app/lib/core/chat_service.dart`; all of it was reverted to `50d9786`
  before any run counted below.

## How I verified
Every run under the shared test lock, one file per run, Flutter
3.47.5. A run is clean only if it exits 0 AND prints no `Retry:` line.
- Before the fix, devlist_transparency with labels: 4 of 6 runs retried,
  every one at "the laptop's owner alert after the honest root re-asserts v2";
  with decrypt tracing, 1 of 4 at the same wait.
- Forced order, old fixture: laptop opens 4/8 dirty, phone opens 0/6 dirty.
  Fixed fixture with the laptop forced to open, retries off: 8/8 clean.
- Final code, retries off, consecutive clean runs: devlist_transparency 8/8,
  devlist_distribution 6/6 (plus 6/6 with labels before), pq_upgrade 6/6,
  durability 6/6, history_sync 6/6, backup 6/6, attachment_sync 6/6,
  group 6/6, pq_rekey 6/6 with its retry never firing and 4/4 after removal
  (each test body ~2 s against its 3-minute cap). pq_upgrade and
  history_sync ran 6/6 again after their last change (the quiet checks now
  read the outbox before the relay).
- Full app suite once, on the final tree: **346 passed, 6 skipped, 1
  failed**, no `Retry:` line, 13 min 35 s. The failure is
  `devlist_hybrid_test.dart: ADR 0010 floor ...` — a file this branch does
  not touch, compiled against code identical to `50d9786`; re-run three
  times: failed, passed, passed. Pre-existing; see below.
- `flutter analyze --no-pub` (from `app/`): No issues found.
- All guards: rc=0 (sweep verbatim in the report).

## Not done / watch out
- **The adoption window is real outside the test.** An attacker holding a
  device's identity key who is on that device's mailbox while a sibling's
  sync session to it is still unanswered can take that session over, and
  the sync channel has no repair for a forked session (the contact path has
  the notice-and-hello; `DeviceSyncService.handleInbound` just drops what it
  cannot decrypt). The device-side detection (the laptop's `olderList`) is
  then silenced and that channel stops carrying mirrors, with nothing on
  the sync path that would notice and open a fresh session. Narrow:
  the attacker already holds the root, the window is the opening of a sync
  session, and the contact-side detections are a different path (not
  exercised in a forked run here). Not fixed: it is protocol behaviour and
  wants its own branch, probably an ADR; no THREAT_MODEL row added (rows
  are coordinated).
- `_initSync` replaces the `DeviceSyncService` with a new instance that
  reloads `sync_session` from the vault while an operation on the old one
  may still be running and saving — a possible lost update of the sync
  ratchet on one device. Read, not observed to fail; worth a look.
- Test coupling: `syncSettled` reads the persisted sync session's JSON
  (`convs/<rid>/outboundSid`, `sessions/<sid>/receivedAny`), and
  `relayUnacked` reads `queuedEnvelopes`, which the RAM store reports and
  the Redis store does not (-1). Both are documented where they are used.
- history_sync's margin has one stated gap: a device acknowledges a message
  a few awaits before it queues the mirror of it, so a quiet relay read
  inside that gap counts one copy fewer — it can miss a doubling, never
  invent one.
- **A pre-existing flake with no retry on it**: `devlist_hybrid_test.dart`,
  "ADR 0010 floor", line 144 — `ktInstallFromLog(v3)` returning false (2
  failures in 4 runs here). From reading, not confirmed by a trace: the
  persist path of `_installContactDeviceList` reads `cdev_ver_`, checks it
  and writes it with no lock, and both its callers run outside the
  per-contact lock — the in-band one in the inbound post-processing, the
  log one in `ktInstallFromLog`. Ben re-sends v2 when Alice's earlier `hi`
  echoes v1, so an install of that v2 can read 2, let the test's v3 write
  3, and write 2 back. If that is it, the held list can go backwards under
  a race, which is an app bug and wants its own branch and test.
- Nearly all runs above were on an idle box. A batch of runs under a
  deliberate two-core CPU load was started; its results were not read, so
  nothing here rests on it.

## Suggested pusher actions
- changelog: n/a; version bump: no (tests only, no user-visible behaviour);
  release: no; redeploy relay: no.
- The three findings above (the adoption window, `_initSync`, the
  `cdev_ver_` race behind `devlist_hybrid`) are each a candidate for a
  branch of their own.
