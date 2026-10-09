# ADR 0023 — Lookups by bucket: a reader asks for a prefix of labels, and gets all of them with a proof

**Status:** **Accepted** 2026‑10‑08 — the decision the handle spec made (lookups
ask for a prefix bucket with a completeness proof, never the exact label, for
both logs), which Finnian may still veto before it lands. The log's side and
the reader are built (36.2); the key‑transparency client asks this way
since phase 35, whose refresh policy is the dated section below; phase 38
resolves handles with it.
**Decides:** how a reader learns one label's state from a log — the
key‑transparency log (§19) or the handle log (§21.5) — without telling the log
which label.

## Context

Until phase 35 a client checked each contact with `GET /kt/v1/lookup/<label>`, where the
label is `SHA‑256("z-kt-label-v1:" ‖ accountEdPub)` of the contact — one
request per contact from the user's address, every six hours
(`checkEvery`), at start, and thirty seconds after a contact's list changes
(`recheckDelay`; `app/lib/core/key_transparency.dart`). The log's operator, and
Cloudflare, which terminates its TLS, learned the user's contact list: P0‑5 of
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
  check, the same buckets each time — are defined below (phase 35).
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
- No client changed in 36.2. Since phase 35 a client's check names no
  contact's label (below), and THREAT_MODEL R40 says what the log learns.
- A log that serves part of a bucket is caught by the reader; a log that
  refuses buckets is unreachable for that reader, as a log that refuses
  lookups is today.
- Phase 35 added here which k a client uses, how it pads and how often it
  asks, how it fetches values with decoys, and what it shows when a bucket is
  refused (below).

## The client's refresh policy (phase 35, 2026‑10‑09)

*The reference client's side (`app/lib/core/kt_private_lookups.dart`, applied
by `key_transparency.dart`; PROTOCOL §19.9.1). The log's side above is
unchanged.*

**What a refresh asks.** Every contact's label is mapped to its bucket, and
the buckets go in one `POST /kt/v1/buckets` (up to 64 a request) beside this
install's decoys, sorted by prefix so the order says nothing. Never a
contact's label: no `lookup`, no `history`.

- *k.* The log's `bucketBits`, never finer — and never finer than the log's
  signed size allows, ⌊log₂(size / 32)⌋, because `bucketBits` is unsigned and
  the operator writes it: at 24 bits a bucket of today's log is one label,
  which is the label. And never finer than the answers bear out: the decoy
  buckets are random buckets, so their mean size is the log's labels over 2^k
  whatever `bucketBits` claims; under 16 the next refresh asks one bit
  coarser, and at 64 a ceiling set that way is lifted a bit.
- *Padding.* The number of buckets asked is a multiple of 16, and at least
  16 (or every bucket, below k = 4). A client with no contacts, one, or
  sixteen in sixteen different buckets asks the same sixteen; the log learns
  ⌈n / 16⌉ and not n. Sixteen buckets at the live log's k = 9 are about 650
  labels and, by 36.2's measurements (above), about 60 KB and a quarter of a
  second of hashing on the build box — an ordinary lookup per contact cost
  about 4 KB, so the floor is fifteen lookups' worth. It grows with the
  contacts: four hundred fall in about 280 buckets at k = 9, so a refresh
  asks about 290 — about a megabyte and four seconds of hashing, verified a
  bucket at a time in the background.
- *Decoys that survive intersection.* Fresh decoys at each refresh would be
  no decoys at all: what two refreshes have in common is exactly the real
  buckets. So the decoys are drawn once and kept — 32 random bytes each,
  mapped to a bucket as a label is, sealed in the vault (`kt_decoys`) and
  carried in a backup — and a refresh's buckets are a function of them and of
  the contacts, nothing redrawn. Two refreshes, a restart and a restore ask
  the same set. It changes only when the contacts do, and then in a shape
  that says as little as it can: a contact whose bucket is already asked
  changes nothing; a contact who is removed leaves their bucket behind as a
  decoy inside it, so a removal changes nothing either; a contact in a bucket
  not yet asked arrives in a block of sixteen new buckets, one of them theirs.
  When k changes, every bucket — real or decoy — maps to its own ancestor or
  descendant, as the labels in it do.
- *Values.* A bucket gives each label's latest `(index, version)`, and a
  label's versions only rise (§19.6), so an unchanged version is an entry
  already judged: nothing more is fetched, and the status keeps what a later
  check needs from it (its fingerprint; whether it opened; the list the
  device‑list rules refused, so the next check tries again from there rather
  than fetching it again, which would single it out). A contact whose entry
  is new needs its value, by `POST /kt/v1/entries`, and what is fetched is a
  set the log could list for itself: every entry in the asked buckets that
  this client had not seen at its last refresh, whether or not any contact is
  among them — so it is fetched when no contact moved too. A needed entry the
  client had already seen (a contact added in a bucket it already asked)
  would stand out among new ones, so then every entry in the asked buckets is
  fetched. Past 1,024 entries, and on a client's first refresh, the needed
  ones go with a sample of the rest (64 on a first refresh) drawn in an order
  this install's key fixes, so a fetch asked again after a failure is the
  same fetch.

**When.** One refresh in each six‑hour window, counted from the epoch, at a
random moment in it, kept across restarts. Not at start, and not when a
contact's list changes: until phase 35 the client also checked at every start
and thirty seconds after a contact's list arrived, and the second told the
log by its timing alone whose contact this was — a contact publishes, and
thirty seconds later their contacts ask, whatever they ask for. A client that
has had no refresh for a whole window — the app may simply not be running at
the window's moment — catches up at a random moment between one and ten
minutes after it is next running. A moment the app slept through (a phone
suspends an app it is not showing, and its timer fires the instant the app
is back) is drawn again from then, not run then. A contact's changed list is checked at the
next refresh; if the user opens that contact's screen first, a refresh runs
then, of the usual shape — as one does when the user asks for a check in
Settings. A list this account has signed and the log has not
acknowledged is still published at start: a publish names only this account,
which the log learns from every publish.

**The account's own label is still asked by name** — its `lookup` and its
`history`, for the self‑monitoring of §19.8. The history is only served that
way, and asking for the account's own label tells the log who is asking, not
whom they talk to: the root hands it the account key at every publish, and the
operator can open the account's lists (§19.1) and so name its devices'
routing ids to whatever relay it also runs. The decoys are built on the
assumption that the log knows who is asking; they do not depend on hiding it.

**A refusal.** A bucket refused `bucket_too_large` is asked again as its two
halves one bit finer — both, so together they say what the bucket did — and a
request of several as two of half the size. A log that refuses the bucket
routes (one older than 36.2), or answers them wrongly, checks nobody: the
refresh is a failure, the contacts keep their last state, and after a day
without one the log is shown unreachable. There is no falling back to asking
by name. An answer that does not verify is a log fault, as a lookup's was.

**What the operator, and Cloudflare in front of it, still learn.** Cloudflare
terminates the log's TLS and sees every request as the operator does.

- *Which buckets an address asks for*, and so, of each, that it holds a
  contact or a decoy — on one refresh the two cannot be told apart, and
  across refreshes the set does not change unless the contacts do. A bucket
  is about one label in 32 to 64.
- *How many blocks* of sixteen, and *when a block is added*: a contact in a
  new bucket, among sixteen new buckets — about 650 labels.
- *Whether a refresh fetched every entry in its buckets*, which says a
  contact was added in a bucket already asked, or that this is a first
  refresh — never which entry it was for.
- *When and from where*: the address, and a moment random in its window —
  except a refresh the user starts: the contact screen's tells the log that
  the user looked at a contact whose list had changed, not which.
- *The account itself*, from its own label and its publishes.
- *Across an account's devices*, which each draw their own decoys: an
  operator that links them — from the own‑label request, or through a relay it
  runs — intersects their sets down to the real buckets and the decoys they
  share by chance. Carrying the decoys in the enrolment payload (PROTOCOL
  §10, whose members phase 33 is adding) closes this; until then it is open.
  A restore keeps the decoys; a reinstall without a backup draws new ones.
- *Labels of its own making.* An operator that fills buckets with labels it
  minted shrinks the real population each bucket hides a contact among, as it
  could shrink any anonymity set it serves; the map it signs shows it to
  every mirror. To learn more than the bucket it has to move entries, and to
  move a contact's entry without that contact's key is a conflict the user
  sees.
- *History*: what the log learned before phase 35, it keeps.

**Alternatives, and what each would add.** *An anonymous path* — the sealed
connection of ADR 0007, or an OHTTP‑style relay that sees the address and not
the request while the log sees the request and not the address — would take
the address away, and with it the linking across refreshes and across an
account's devices that the decoys have to survive. It needs a relay run by
somebody other than the log's operator to mean anything: today the relay and
the log are one operator behind one Cloudflare, so it would move the
knowledge rather than remove it. *PIR* would hide the bucket as well, at a
pass over the database per query and a lattice implementation to add and
audit; it can be layered on buckets later (retrieve a bucket privately, prove
it complete as now). *A full snapshot* from a mirror — every label's
`(index, version)`, checked against `mapRoot` — hides everything but that a
client synced, at about 45 bytes a label (0.9 MB today, growing) per sync: a
later option for a client on an unmetered link.
