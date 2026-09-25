# Handoff: fix/pq-number-upgrade
Phase: a reported bug in published 3.7.0 — the safety number two people could never make agree
Base: main @ `05ddc3e` (Release 3.9.1)   Built: 2026-09-25

## What changed
ADR 0021, `docs/adr/0021-pq-number-upgrade-in-session.md`. In one line: a
post-quantum key that arrives with no commitment to check it against is now
**kept as a candidate, for the safety number and nothing else**, both sides show
the post-quantum number only once each holds the other's key and has said so,
and **comparing that number is what establishes the key**.

- `Contact` gains `pqCandidate` (sealed), `pqAcked`, `pqTold`, and a `PqDisplay`
  enum — what the number on screen is derived from, which is a different
  question from `IdentityAssurance`, what the key may be trusted for.
- `_onPqIdentity` keeps an uncommitted key instead of dropping it; first key
  wins; a refused contact is never given one.
- New keyless inner kind **`pqack`** ("I hold your key") for when no `pqid` of
  ours is going out to carry the same fact in its `ack`. 1 024-byte bucket, at
  most once per contact, gated by a durable flag.
- `setVerified` promotes a compared candidate to an established key.
- `addContactFromCode` on an existing contact upgrades the record instead of
  throwing; the CONNECT ceremony opts out (`upgradeExisting: false`) so its own
  refusal rule is untouched.
- Vault schema 13; all three fields travel in the backup archive.
- Contact screen keyed on `PqDisplay`; new strings in en + es; the refused case
  finally gets words of its own instead of borrowing "pending".
- Version 3.9.1+178 → 3.9.2+179.

## Why
Reported against 3.7.0: *"when an account that just has a classical number tries
to compare with a quantum number they don't match"*, and *"I can't see a way the
person can upgrade to a quantum number."* §18.2 said an uncommitted key is
discarded, and a commitment is one-sided — so the side that scanned a `zc3.`
code showed the v2 number and the side that added them from a classical code (or
by accepting a contact request, or from a pre-v3 record) showed v1, for ever.
`addContactFromCode` threw for an existing rid, so re-scanning did nothing
either. The only escape was deleting the contact and all its history.

## Invariants touched
- **A candidate is never an assurance.** Not `hybridKey`, not `assurance`
  hybrid, never verifies a device list (§18.9), never mirrored to one's own
  devices, never swapped for a later key. Checked by two independent reviews.
- **Zero knowledge at the relay** — unchanged. One extra 1 024-bucket envelope
  per contact per install, the bucket short chat already occupies.
- **Metadata** — the nudge for a key we were never promised is bounded to once
  per run per contact, deliberately tighter than the three a met commitment
  gets, because a 16 384 envelope at a v1 peer that can never answer is pure
  mark (R17).
- **Wire** — additive only: one new kind, and `ack` widened in a direction an
  older client cannot misread.
- **13.3** — the tick still records WHICH number was compared.

## How I verified
- `app/`: `flutter test --concurrency=1` — see the report at the end of this
  session for the exact run; `safety_number_mixed_test.dart` is 10 tests over a
  real relay.
- `protocol/`: `dart test` — 224 passed.
- `server/`: `npm test` — 119 passed. `kt/`: `npm test` — 78 passed.
- `kt/tools/verify_vectors.py` — 344 values. `protocol/tool/verify_mldsa.py` —
  39 checks under dilithium-py.
- Every guard in `tool/` plus `app/tool/contrast.py` — all pass.
- **Three subagent reviews**, run in parallel with the build: a doc-vs-code
  audit, an adversarial security review, and a final pre-delivery audit. They
  found, and this branch fixes: a **P0 TOCTOU in `setVerified`** (the number and
  the promotion decision were read either side of an await, so a peer's `ack`
  landing in the gap turned a confirmation of the *classical* number into the
  establishment of a post-quantum key nobody compared — now one snapshot, with
  test 4b as the regression); an unbounded `pqack` when the durable write fails;
  a re-scan mismatch that reported success to the user at the one moment the app
  has hard evidence of a substituted key; the CONNECT contract being widened
  silently; a test that proved nothing because it never checked the §18.9
  signature had arrived; and two doc claims that were wrong about 3.7.x
  behaviour.

## Not done / watch out
- **The limit is real and is documented, not hidden.** Where a pre-0021 peer
  already established our key, it shows the post-quantum number and we may show
  the classical one; no change of ours reaches a build in the field. Test 3b
  pins the rule rather than an outcome, because which way it falls depends on
  send ordering. `docs/PROTOCOL.md` §18.5 carries a MUST NOT against the obvious
  "fix" (withholding the number over an established key), which would break the
  pair that works today.
- A careless "verified" tick now installs a trust anchor rather than a label —
  recorded in THREAT_MODEL R37, which is the row to read before signing this off.
- Still untested: that a candidate is never mirrored to one's own devices
  (verified by reading `_contactInner`, not by a test with a linked device).
- `app/test/destructive_confirm_test.dart` 40 fails on this machine under
  full-suite load and passes in isolation; it failed the same way on unmodified
  `main` here and passed in CI. Untouched by this branch.
- `app/test/devlist_transparency_test.dart` "split view (a)" is flaky at about
  one first attempt in five on this machine (measured 4/1 on both this branch
  and `main` in an earlier session) and recovers on its own retry. Untouched.

## Suggested pusher actions
- changelog: n/a (this repo logs releases in the release commit message)
- version bump: done (3.9.2+179); release commit is in this branch
- release: yes — tag `v3.9.2` once CI is green
- redeploy relay: no (no server change)
