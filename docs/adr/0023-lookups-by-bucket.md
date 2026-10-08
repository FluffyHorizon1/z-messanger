# ADR 0023 — Lookups by bucket: a reader asks for a prefix of labels, and gets all of them with a proof

**Status:** **Accepted** 2026‑10‑08 — the decision the handle spec made (lookups
ask for a prefix bucket with a completeness proof, never the exact label, for
both logs), which Finnian may still veto before it lands. The log's side and
the reader are built (36.2); no client asks yet. Phase 35 moves the
key‑transparency client onto it and adds its refresh policy here; phase 38
resolves handles with it.
**Decides:** how a reader learns one label's state from a log — the
key‑transparency log (§19) or the handle log (§21.5) — without telling the log
which label.

## Context

Today a client checks each contact with `GET /kt/v1/lookup/<label>`, where the
label is `SHA‑256("z-kt-label-v1:" ‖ accountEdPub)` of the contact — one
request per contact from the user's address, every six hours
(`checkEvery`), at start, and thirty seconds after a contact's list changes
(`recheckDelay`; `app/lib/core/key_transparency.dart`). The log's operator, and
Cloudflare, which terminates its TLS, learn the user's contact list: P0‑5 of
the 2026‑10‑03 analysis. The label hides nothing from them, because the
operator learns every account key at publish (§19.6) and can compute every
label.

Handles make it worse. A handle log's label is Argon2id of the handle, and the
handle is public by design: anyone, the operator first, can compute the label
of any handle they can guess. An exact lookup there says "this address is
looking for @finnian.07" in so many words.

What any replacement must keep is what makes a lookup worth asking: the answer
is a proof against the head the log signed — the map says which entry is the
label's latest, or proves there is none — and not the log's word.

## Decision

**Ask for a bucket: every label sharing the first k bits of the one wanted,
with the map siblings that fold their subtree to the signed root.** The same
query for both logs (§19.9):

- `GET /kt/v1/bucket?prefix=<hex>&bits=<k>`, `0 ≤ k ≤ 24`; `POST /kt/v1/buckets`
  for up to 64 buckets under one head. The answer carries the head, the
  bucket's leaves in label order with each label's `(index, version)`, and the
  k siblings from depth k−1 up to depth 0.
- The reader recomputes the depth‑k subtree from the leaves (the map's own leaf
  hash and empty subtrees), folds it through the siblings by the prefix's bits,
  and compares the result with `mapRoot`. A label left out, added or changed
  changes the subtree, so a bucket that verifies is complete: a label with the
  prefix that is not among the leaves is a verified absence.
- The handle log's leaves also carry the latest record, its hour, the owner's
  signature and the entry's audit path, so a resolver reads the record in the
  same answer; a second request for the value would name the label.
- The key‑transparency log's leaves carry no value — a sealed device list is
  a kilobyte, and most checks only need to see that `(index, version)` has
  not moved. A client that needs a value asks `POST /kt/v1/entries` with the
  index and decoys beside it.
- The log recommends k in `/kt/v1/sth` as `bucketBits = max(0, ⌊log₂(labels / 32)⌋)`
  (at most 24): 32 to 64 labels a bucket on average, whatever the log's size.
  At the live log's 20,600 labels that is k = 9, about 40 labels a bucket.
- Bounds: a bucket over 4096 leaves is refused `bucket_too_large`, as are a
  `POST`'s buckets past 4096 between them, and the handle log's answers past
  256 KiB; the reader asks narrower buckets, or fewer at once. These are
  routes a client's check depends on, so — like a lookup and a label's
  history — they are bounded by the cost of one answer and never refused by a
  budget other readers can spend.

## What it costs, measured (36.2)

- **Bytes.** A key‑transparency leaf is 80 bytes of JSON (`vectors/kt/bucket.json`):
  a bucket of 40 is ~3.9 KB with its head and nine siblings — about what
  today's lookup weighs (~4 KB, SELF_HOSTING), which carries the entry's
  sealed value whether or not it moved. A handle leaf is ~520 bytes (a record
  of ~155–390 bytes and its signature) plus 47 for each level of its audit
  path: ~710 in the vectors' fourteen‑entry log, ~1.5 KB at a million entries.
- **The reader's CPU.** A label alone below depth k is a chain of empty
  siblings to depth 256, so a bucket of B labels is about
  B × (256 − k − log₂ B) hashes, where a map proof is 256. Measured with the
  Dart reader (`ktBucketSubtreeRoot`, synchronous SHA‑256, JIT on the shared
  build box): 15 ms for 40 labels at k = 9, 19 ms for 48 at k = 10, 77 ms for
  200, and 1.75 s for a full 4096 — which is why a reader refuses more.
- **The log's.** Nothing is recomputed: the path to depth k is ~log₂ N nodes
  whose hashes the tree already holds, a bucket's leaves are a walk of its
  subtree that stops at 4097, and the handle log's audit paths share the
  tree's ragged right edge (`MerkleLog.inclusionProofs`) instead of
  recomputing it per leaf.

## What it does not hide

- **The bucket.** The log learns that the reader wanted one of ~32–64 labels;
  as the log grows, k grows with it, and the set stays that size — not larger.
- **How many.** One bucket per contact says how many contacts the reader has,
  and the buckets themselves are a fingerprint of the contact list that
  repeats on every check. Decoys and padding — a fixed number of buckets per
  check, the same buckets each time — are phase 35's to define and add here.
- **When and from where.** The address, and the moment, as for every request;
  R56 records this for the handle log.

## Considered and rejected

- **Exact lookups** (today): the log learns every label asked for. Kept on the
  key‑transparency log for clients that predate phase 35, and on the handle
  log for an owner checking its own handle; a resolver must not use them.
- **A full snapshot**: download every label's `(index, version)` and check the
  whole map against `mapRoot`. Perfect privacy — the log learns only that a
  client synced — at a cost that grows with the log for every client on every
  check: ~45 bytes a label, 0.9 MB at today's 20,600 and growing, and the
  whole map's hashes to recompute. A later option for a client on an
  unmetered link, served from a mirror; not the default.
- **An anonymous path through the relay** (the sealed connection of ADR 0007,
  or a proxy): hides the address from the log, not the label — and the relay's
  operator and the log's are the same party today, so it moves the knowledge
  rather than removing it. Compatible with buckets as an addition, not a
  substitute.
- **Private information retrieval**: hides the label entirely, but
  single‑server PIR costs the log a pass over the whole database on every
  query, the efficient schemes need a client‑side hint and a lattice
  implementation this project would have to add as a dependency and audit,
  and a retrieved record still has to be proved against the signed root —
  PIR answers "what is at this position", not "and nothing was left out".
  Buckets give the completeness proof for free and most of the privacy for a
  fraction of the cost; PIR can be layered on a bucket later.
- **VRF‑blinded labels** (considered in ADR 0006): hide labels from readers of
  a mirror, not from the operator a lookup is sent to.

## Consequences

- Both logs answer the same query, so one reader verifies both
  (`protocol/lib/src/transparency_bucket.dart`, `ktVerifyBucketAnswer`, with
  `KtLogMode.kt` or `KtLogMode.handles` and the pinned key of that log);
  `kt/lib/log.js` (`verifyBucketAnswer`) and `kt/tools/verify_vectors.py` are
  the same text, and `vectors/kt/bucket.json` pins all three.
- No client changes in 36.2. Until phase 35, every lookup still names its
  label, and THREAT_MODEL's account of what the log learns stays as it is.
- A log that serves part of a bucket is caught by the reader; a log that
  refuses buckets is unreachable for that reader, as a log that refuses
  lookups is today.
- Phase 35 adds here: which k a client uses (the log's recommendation, or
  more), how it pads and how often it asks, how it fetches values with decoys,
  and what it shows when a bucket is refused.
