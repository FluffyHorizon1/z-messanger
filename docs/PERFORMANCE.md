# Performance (15.3)

What Z costs, measured rather than assumed. The numbers below come from
`app/test/fanout_bench_test.dart`, which is skipped by default and run
deliberately:

```
cd app && flutter test --run-skipped --tags bench
```

Measured in this project's build container — 2 cores, 8 GB, a debug Flutter
test VM. **Absolute numbers on a real phone will differ; the shapes will not**,
and the shapes are what the design questions turn on.

---

## The question worth asking

Z has no group key. Every group message is encrypted separately for every
recipient *device*, over that device's own pairwise ratchet. That is what makes
removal meaningful — a member removed before a send cannot read what follows,
because there was never a shared key to rotate or leak.

It is bought with fan-out that grows as members × devices, and that cost is
exactly the argument someone will eventually make for adding a shared group
key. That argument deserves a number rather than a shrug.

## Fan-out is linear, and the design holds

Sender-side cost of one group message, five repetitions after a warm send:

| members | total | per member |
|---:|---:|---:|
| 2 | 69 ms | 34.3 ms |
| 5 | 153 ms | 30.5 ms |
| 10 | 273 ms | 27.3 ms |
| 25 | 603 ms | 24.1 ms |
| 50 | **1 205 ms** | 24.1 ms |

Per-member cost at 50 members is **0.79×** what it is at 5 — slightly
*sub*-linear, as fixed overhead amortises. There is no quadratic term: no scan,
no re-read, no lock held across the loop.

**So the no-group-key design is not what makes large groups slow.** The
per-recipient work is the price of the property, it is paid once per recipient,
and it does not compound. The benchmark asserts this bound, so a future change
that introduces an O(n²) term fails rather than merely feeling sluggish.

## But a fifty-member send takes 1.2 seconds, and the UI waits for it

`chat_screen.dart` awaits `sendGroupText` with the composer disabled
(`_sending = true`). In a fifty-member group that is a frozen send button and
no message on screen for over a second.

This is the finding that matters, and it is not a cryptography problem. The
message is durable the moment its outbox rows are committed; nothing requires
the user to watch the fan-out finish. **The fix is to stop waiting, not to make
the crypto cheaper.**

## Where the time goes

One 1:1 send — exactly one iteration of the group loop:

| | |
|---|---:|
| connected | 26.3 ms |
| transport stopped | 20.3 ms |
| **attributable to delivery** | **6.2 ms** |

So roughly three quarters is local. Of that, measured directly:

| | |
|---|---:|
| one vault transaction (outbox insert) | 3.25 ms |
| `SealedEnvelope.seal` | 2.49 ms |
| — of which ephemeral X25519 keygen + DH | 2.13 ms (86%) |
| `vault.seal` of one payload | 0.18 ms |
| **unattributed** | **≈14 ms** |

### The remainder, attributed

That was left unattributed on purpose rather than guessed at. It has since
been measured, and none of the candidates was what the guesses assumed:

| | |
|---|---:|
| the transaction as a send actually builds it | 3.94 ms |
| `SealedEnvelope.seal` | ~2.0 ms |
| the ratchet step (`conv.encrypt`) | **0.23 ms** |
| `Conversation.fromJson` (only when a rollback fires) | 0.11 ms |
| the rollback snapshot (`toJson` + `jsonEncode`) | **0.02 ms** |

The two that were expected to matter — the ratchet and the snapshot — are
together a quarter of a millisecond. The earlier "one transaction per insert:
3.25 ms" figure was a *bare* insert, which is not what a send does; the real
shape is 3.94 ms.

**A hypothesis that turned out to be wrong**, recorded because it was worth
testing: every send fires an unawaited `flushOutbox()`, so a user offline with
a growing backlog might pay more per message than one with none — exactly
backwards, and the sort of thing nobody notices. Measured at 20 queued rows
against 2 040: **15.25 ms versus 16.97 ms**. A 1.7 ms difference across a
hundredfold backlog is not a scaling problem.

~~About 8 ms of a 16 ms offline send is still unaccounted for, spread across
lock acquisition, the contact lookup, the post-quantum offer check, wire
decoration and async scheduling. **No single term dominates it**, which is the
useful finding: there is no further win here of the size the skipped-key cache
was, and the next person to look should start somewhere else.~~

**That paragraph was wrong, and the way it was wrong is instructive.** "Wire
decoration" was one item in a list of five things sharing 8 ms; it was never
timed on its own. The receive-side measurement below timed it: the own
device-list claim that `_decorateForWire` stamps on every outgoing message
cost **13.8 ms** to compute — eleven vault reads and an Ed25519 signature over
the device's own certificate, redone from scratch every time, for every
account that has never linked a second device (that is, nearly every
account). It was the single largest term in a send, larger than the seal and
the transaction together, and the paragraph above had it filed under "spread
across". It is memoised now; the 1:1 send it belongs to went from ~22 ms to
~10 ms. See "Receive side" for the measurement that found it.

### Batching the writes is not the answer

Forty outbox inserts in one transaction cost 0.37 ms each against 3.25 ms each
in their own transactions — **8.7× cheaper**. Tempting, and worth roughly 13%
of a send.

It is not the fix, for two reasons. It is a small share of the cost, and the
per-recipient transaction is deliberate: `_sendInner` rolls the conversation
back if the write fails, and one transaction spanning fifty recipients turns
one recipient's failure into fifty rolled-back ratchets. Worth doing carefully
one day; not worth doing first.

## The latent one: skipped message keys

Every send serialises the whole conversation twice, and that state includes the
ratchet's cache of out-of-order message keys, capped at 1536.

In the benchmark above the phantom recipients never reply, so the cache is
empty and **those numbers are a best case**. Encoding and sealing a
conversation carrying that cache costs:

| skipped keys held | encode + seal, per send |
|---:|---:|
| 0 | 0.19 ms |
| 768 | 6.92 ms |
| 1536 (the cap) | **20.94 ms** |

A conversation at the cap therefore adds about **+20.7 ms per recipient, per
send** — it roughly *doubles* the cost — and the growth is worse than linear in
the cache size.

Two things make this the most interesting number here:

* **It is latent.** It appears only after out-of-order delivery, which is to say
  on a bad network — precisely when things are already going badly. Nothing in
  ordinary testing provokes it.
* **It is paid on the hot path for a cold reason.** Skipped keys exist to
  decrypt late arrivals. They have no bearing on *sending*, yet they are
  encoded and sealed on every send because they share a blob with the ratchet
  state that does.

A fifty-member group whose conversations are all at the cap would cost roughly
50 × 47 ms ≈ **2.3 seconds** per message.

## What to do, in order

1. ~~**Do not block the composer on fan-out.**~~ **Done.** See below.
   Measured: a twenty-member send went from ~406 ms to under 250 ms of
   recorded-and-returned, and the bound is now a test.
2. ~~**Separate the skipped-key cache from the persisted conversation
   blob.**~~ **Done** — see below. A send with the cache at its 1536-entry cap
   now costs 2.2 ms more than one with an empty cache, against 20.7 ms before.

   The objection worth checking first was the frozen vectors, which *do*
   contain `skipped` and which `vectors_test.dart` asserts. It turned out to
   assert the live `RatchetState.skipped` keys against the recorded ones —
   a statement about **which keys the ratchet caches**, not about where they
   are stored — so this was a storage change rather than a protocol one, and
   all 147 protocol tests passed unchanged.

3. ~~**Make the rollback snapshot cheaper.**~~ **Not worth doing.** Measured
   at **0.02 ms**. An earlier version of this document reasoned that it "costs
   a full `jsonEncode` of the ratchet on every send" — true, and irrelevant,
   because a ratchet without its skipped-key cache is a handful of 32-byte
   keys and three integers. The third time in this document that an inference
   stood in for a measurement.

4. **Batch the outbox writes** — still open, still not obviously worth it. The
   transaction as a send actually builds it (seal, upsert the state, insert
   the outbox row) measures **3.94 ms** of a ~16 ms offline send, and one
   transaction spanning fifty recipients still turns one recipient's failure
   into fifty rolled-back ratchets. The case for it got weaker, not stronger,
   once the fan-out stopped happening while the user waits.

None of these is a change to the protocol, and none of them is a reason to
introduce a group key.

## The first fix: the fan-out is written down before it is performed

Not awaiting would have removed the stall and made something else worse.
Before this, a fan-out interrupted part-way — the app killed, a vault write
failing — dropped its remaining recipients **silently and permanently**. With
a spinner on screen the user at least knew something was in flight; without
one they would have had no idea a message reached eleven of fifty people.

So the work is recorded before it is done, exactly as the outbox already does
for delivery. `group_fanout` (vault schema 8) holds one row per (message,
recipient); the sender writes them all in a single transaction — about 18 ms
for fifty, against 1 200 ms to perform them — returns, and drains the queue in
the background. Rows are deleted only after the recipient's outbox row is
committed, so a kill mid-drain resumes on the next start and the members
already served are not served twice (`UNIQUE (mid, rid)` makes re-queuing
idempotent).

A row whose send fails is left in place and retried rather than dropped, and
the message stays `pending`, which is the truth. Reconnecting kicks a retry,
because a queue with no trigger would sit until the next group send.

Which operations use it: the **content** ones — group text, reactions, edits,
delete-for-everyone. Membership changes (create, add, remove, leave) stay
synchronous: they are rare, the user expects them to take a moment, and their
ordering carries a security property worth keeping obvious. A message queued
before a removal is still delivered — it was sent before the removal — while
a message sent after one snapshots the reduced membership at queue time, so
**"a member removed before a send never receives it" still holds**.

`sendGroupFile` is not queued. Its fan-out carries the encrypted chunk
payloads per recipient, which for a 24 MB attachment would mean storing them
again per row. It keeps the synchronous loop and stays on the list above.

### What the numbers look like afterwards

The group table above measured `sendGroupText` returning, and once the fan-out
was queued rather than performed, that stopped being the same thing. The
benchmark now reports both, because conflating them would flatter the result:

| members | perceived | total | per member |
|---:|---:|---:|---:|
| 2 | 10.0 ms | 104 ms | 52.1 ms |
| 10 | 17.6 ms | 346 ms | 34.6 ms |
| 50 | **17.0 ms** | 1 097 ms | 21.9 ms |

**Perceived** is what the user waits for. It is flat in the member count —
seventeen milliseconds at fifty members, against 1 205 ms before — because all
the send does is write the queue. **Total** is the work, which has not gone
anywhere; it just no longer happens while somebody watches.

(These are a noisier run of the same container than the first table; absolute
values move by a third between runs, shapes do not.)

## The second fix: the out-of-order cache is stored apart from the hot state

Vault schema 9 gives `conversations` an `enc_skipped` cell. The ratchet's
cache of skipped message keys goes there; `enc_state` no longer carries it.
A send writes only `enc_state`; a receive writes both, in one transaction,
because `nr` advancing without the keys it stepped over would lose exactly the
messages the cache exists to rescue.

Measured, on a conversation holding the full 1 536 keys:

| | |
|---|---:|
| send with an empty cache | 20.99 ms |
| send with 1 536 cached | 23.16 ms |
| **difference** | **2.16 ms** |

Against **+20.7 ms** before the split. The send cost is now essentially
independent of how much out-of-order history the conversation is carrying.

### Two things this nearly got wrong

**`INSERT OR REPLACE` empties columns it does not mention.** `_saveConv` used
it, and REPLACE deletes the conflicting row before inserting — so the moment
the cache moved to its own column, every send silently set it to NULL. Nothing
failed at the time. The loss would have surfaced days later as a late message
that would not decrypt, with no way to trace it back. It is an upsert naming
its columns now, and there is a test that fails if it goes back.

**The rollback snapshot.** `_sendInner` snapshots the conversation before
encrypting so it can restore on a write failure. That snapshot was a full
`toJson()` — cache included — which would have left half the cost in place;
and simply dropping the cache from it would have emptied the cache on every
rolled-back send, a message-loss bug hiding inside an error path. The snapshot
now omits it and the catch block carries the live cache across by hand, which
is correct precisely because a send never touches it.

### Not done

The remaining items are unchanged: the rollback snapshot is still a full
encode of everything else, and the outbox writes are still one transaction
each. Both are small next to what has been taken out.

## Receive side (2026-09-10)

Measured last, and it should have been measured first: it is where the
out-of-order key cache is *used*, and it turned out to hold the largest
single cost in the app. `receive_bench_test.dart`, no network — the sender's
outbox rows are the sealed envelopes the relay would deliver, handed straight
to the receiver's inbound path.

### What one inbound text message cost

| | before | after the memo | after all three fixes |
|---|---:|---:|---:|
| whole inbound path, in order | **54.7 ms** | 25.2 | **16.3 ms** |
| a message that arrives early, skipping 20 keys | 53.6 | 33.8 | 16.8 |
| a late arrival decrypted from the cache | 53.1 | 26.2 | 16.6 |
| in order, with the cache at its 1536-key cap | 68.0 | 42.5 | 16.2 (+0.0 for the cache) |

The ratchet is not where the time goes — creating twenty skipped keys costs
about what one in-order step does, and a cache hit is a lookup. Attributed,
one inbound text message, before the fix:

| | ms |
|---|---:|
| sealed-sender open | 2.9 |
| ratchet decrypt | 0.6 |
| conversation-state seal | 0.3 |
| message-row transaction | 2.7 |
| **own device-list claim, computed for the gossip check** | **13.8** |
| **delivery receipt — a full send, which computes the claim again** | **22.0** |
| dedupe, claim bookkeeping, lock, notify | ~12 |

Three findings, three fixes, each measured on its own.

**The own-list claim was recomputed on every message, in both directions.**
`_ownListClaim()` reads `own_list_v`/`own_list_h` from the vault; for an
account that has never signed a device list — any single-device account —
they are absent, and the fallback rebuilt the claim from scratch: five more
vault reads (each a miss costs two queries), `AccountIdentity.fromV1`, which
*signs the device's own certificate with Ed25519*, and a fingerprint. 13.8 ms
alone; ~40 ms wall time inside the inbound path, waiting behind the delivery
receipt's own transaction. Every receive did it once for the transparency
gossip check and once more inside the receipt it sends back; every send did
it once in `_decorateForWire`. The answer changes only when the device list
does, and every path that changes it is known, so it is memoised and
forgotten at those five points — *after* each write, not before: the first
version forgot first, and a send interleaved between the forget and the
write recomputed the claim from the old keys and cached it again, which
`devlist_distribution_test.dart` turned into a one-run-in-three flake until
the order was fixed (3/3 clean before the memo, 3/3 clean after the fix).
Effect: receive 54.7 → 25.2 ms, and the receipt (a send) 22.0 → 10.4 ms.

**The cache was re-sealed on every receive whether or not it changed.**
15.3 moved the cache out of the send path and into its own cell, written by
the receive transaction — every receive, unconditionally. An in-order
message, the common case, neither adds a key nor consumes one, so at the cap
the receive was paying 13.7 ms to seal 1536 keys that had not moved: the
send-side cost relocated rather than removed. The cache is now re-sealed only
when a cheap shape check (per session: key count and last key) shows the
decrypt changed it. `skipped_keys_test.dart` criterion 5 pins both halves —
untouched means unwritten, changed means written — and the first version of
that test passed against the old code because it ran with an empty cache
(null over null); it runs with keys in the cache now.

**The delivery receipt was one full send per inbound message.** After the
memo a receive was ~25 ms and 10 of it was the receipt: an outbound send of
a 'dlv' inner, `unawaited`, but holding the same per-conversation lock the
next inbound needed, so fifty queued messages on reconnect paid fifty sends
in line. The wire format had always carried a list — `'mids': [...]` — and
now it is used as one: receipts wait 300 ms for company, or until 64 have
gathered, and go as a single send; the sender sees its ticks a third of a
second later than before. `delivery_receipts_test.dart` pins one receipt
per burst, the cap, and the lone receipt going out on its own. (Its cap
test passed with the cap removed on the first try — delivering seventy
messages takes longer than the window, so the timer kept the batch small
and the cap was never reached. The test now holds the window shut.) Effect:
receive 25.2 → 16.3 ms, and the receipt's cost, ~9 ms, is paid once per
burst.

### What a receive costs now

| | ms |
|---|---:|
| sealed-sender open | 2.6 |
| message-row transaction | 3.1 |
| ratchet decrypt | 0.6 |
| conversation-state seal | 0.3 |
| own-list claim | 0.0 |
| dedupe, claim bookkeeping, lock, notify | 1.6 |
| **whole inbound path** | **16.3** |

Open plus the transaction are two thirds of it, and both are what they
are: an X25519 agreement and an AEAD to open the envelope, and a sealed
write. There is no term left of the size any of the three above were.

The send side moved with it: a 1:1 send that was ~22 ms is ~10 ms, since
`_decorateForWire` computed the same claim. PERFORMANCE.md's earlier
send-side conclusion is struck through above rather than deleted.

## Cold start (2026-09-11)

What `ChatService.init` costs against the number of contacts — the time
between the vault opening and the first screen having anything to show.
Desktop VM, each contact with a settled session and one message each way,
`coldstart_bench_test.dart`:

| contacts | before | after |
|---:|---:|---:|
| 10 | 120 ms | 73 ms |
| 100 | 633 ms | 102 ms |
| 400 | **2 527 ms** (6.3 ms/contact) | **397 ms** (1.0 ms/contact) |

Attributed at 100 contacts before the fix: `_loadDevlistState` 269 ms,
`_refreshDeviceAssurance` 141, `_computeUnread` 102, `_loadContactDeviceLists`
66, `_loadConversations` 54, `_loadContacts` 47. Every loader read its
per-contact keys with `kvGet`, which tried the sealed storage class and then
the plain one as **two queries** — so a plain value cost two round trips and
a miss, which most per-contact keys are, cost two as well. Fifteen queries
per contact at startup, and one `COUNT` per chat for unread on top.

Three changes. `kvGet` is one query (`k IN (?, ?)`) for every read in the
app. `Vault.kvScan(prefix)` reads a key family in one query, and `init` reads
every per-contact family once and hands the snapshot to the loaders — six
queries where there were fifteen per contact. Unread is one `GROUP BY` with
a correlated subquery on the plain `last_open_` row, measured against one
`COUNT` per chat: 274 → 0 ms for 400 chats of one message, 238 → 11 ms for
400 chats of fifty, 33 → 24 ms for 50 chats of a thousand — never slower
(`vault_kv_test.dart` pins that the two agree). What is left, at 400
contacts: `_loadContacts` 184 ms and `_loadConversations` 162 ms — one
unseal per sealed cell, which is the vault doing its job — and the bench
asserts the per-contact cost stays under 3 ms so a loader cannot quietly go
back to a query per contact.

The same shape, on the receiving end of a device link: `_applyHistoryBatch`
wrote each replayed message as its own autocommit — a hundred rows in 268
ms; sealed up front and written in one transaction, 99 ms (measured, a
throwaway on the vault alone). A new device replaying fifty chats of two
hundred is the difference between 27 s and 10 s of database work.

On the way, the bench closed the vault right after `init` and found the
group fan-out drain that `init` kicks unawaited throwing an unhandled
`DatabaseException` — an app crash on the way out if the vault closes under
it. It swallows that now, as `flushOutbox` already did; the rows are durable
and the next launch drains them.

## The relay under load (2026-09-11)

`server/bench/latency.js` (`npm run bench:latency`): N sender/recipient
pairs, each sender at a steady rate under the per-connection limit
(`RATE_PER_SEC`, 80), sealed-sender envelopes of the 1 024 bucket — 1 450
characters, what a short text is on the wire — for ten seconds; each
message's latency is the time from `send` to the recipient's `msg` frame,
measured in-process. One relay on loopback, one machine, the load generator
sharing the same Node process and event loop as the relay, so these are
pessimistic:

| pairs × rate | offered | delivered | p50 | p90 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|
| 50 × 20/s | 991/s | 991/s, 0 lost | 0.61 ms | 2.1 | 6.6 | 11.7 |
| 200 × 10/s | 1 980/s | all | 1.76 | 4.3 | 32.9 | 38.9 |
| 500 × 5/s (1 000 sockets) | 2 449/s | all | 2.23 | 12.0 | 72.2 | 74.8 |
| 100 × 50/s | 4 895/s | all | 1.64 | 3.1 | 13.8 | 46.0 |

Nothing was lost at any shape and `/health` showed no queue afterwards. The
tail grows with the number of sockets more than with the message rate —
1 000 connections at 2 449/s has a worse p99 than 200 at 4 895/s — which is
the event loop servicing more sockets per turn, not the relay's own work per
message. For a self-hoster: one small relay carries thousands of messages a
second with a median under 3 ms; the abuse limits (`load.test.js`), not
throughput, are what size a deployment.

### Two sockets per device (16.1)

Since sealed envelopes leave on an anonymous connection (PROTOCOL §12.1),
a device holds two sockets. The bench's pairs were already two sockets each
(one sending, one receiving), so its senders now simply skip the challenge;
the question is what a doubled socket count costs at the same message rate.
Same commit, same ~1 950 envelopes a second, ten seconds:

| sockets (pairs × 2) | p50 | p90 | p99 | max |
|---:|---:|---:|---:|---:|
| 500 (250 × 8/s) | 1.3 ms | 4.1 | 46 | 46 |
| 1 000 (500 × 4/s) | 3.1 ms | 13.1 | 46 | 47 |
| 2 000 (1 000 × 2/s) | 6.0 ms | 55 | 164 | 166 |

The median doubles with the sockets and the tail triples past a thousand,
at a rate the process handles comfortably on fewer. The cost of the
anonymous link is therefore a sizing rule, not a throughput one: count
sockets as twice the devices (`SELF_HOSTING.md`). `/health` now reports
`sockets` beside `connections` so the number sized for is the number seen.

### What jitter and cover traffic would have cost (16.2)

`server/bench/patterns.js` (`npm run bench:patterns`, ~150 s) is not a
measurement of the relay but of two things that were considered for it and
not done — delaying each copy of a group message by a random amount, and
sending every mailbox dummy traffic — against a relay operator who clusters
mailboxes by when they light up together. The result and the decision are
in `THREAT_MODEL.md` ("Timing patterns"); the costs, which are this
document's business, are these. A jitter of D is up to D of added latency
on every group message for every recipient, and on the mirror to a person's
own devices, and the study finds nothing under ten minutes worth having.
Cover traffic at the rate that moves a cell — a thousand dummy deliveries a
day per device — is about 1.4 MB a day per device in 1 024‑bucket
envelopes, sent and received, and for the relay one extra envelope per
device every 86 seconds: 116 a second for ten thousand devices, a twentieth
of what one relay delivered in the table above, so the relay could carry it;
the phones' batteries and the operator's patience are the reasons it is not
sent.

## The transparency log (2026-09-11)

`kt/bench/proofs.js` (`npm run bench` in `kt/`): a log with one entry per
label plus a second entry for a tenth of them, and for each population the
cost of a publish, a lookup, and what a phone downloads to verify one
contact. In-process, one machine, so the log's own cost and not the
network's:

| labels | entries | publish | lookup | map siblings (avg / max) | inclusion path | lookup response |
|---:|---:|---:|---:|---|---:|---:|
| 1 000 | 1 101 | 1.1 ms | 0.06 ms | 10 / 13 | 10 | 3.7 KB |
| 10 000 | 11 001 | 1.3 ms | 0.07 ms | 14 / 16 | 12 | 4.0 KB |
| 100 000 | 110 001 | 1.4 ms | 0.11 ms | 17 / 19 | 16 | 4.3 KB |

Of each response, 2.2 KB is the sealed device list (a four-device classical
list, base64); the proofs are the rest. A publish is dominated by two
256-hash chains in the map (Node's per-call SHA-256 overhead, ~2 µs each)
and one Ed25519 verification; a lookup by the map walk. A new head after a
publish costs 0.1 ms at every size. The first version of the map made that
last figure 104 ms at ten thousand labels (roadmap revision 33); the bench
is what found it.

On the client (`protocol/tool/kt_verify_bench.dart`, the VM, pure Dart),
verifying one lookup — parse, head signature, map proof, inclusion — is
**4.4 ms**, of which the Ed25519 verification is 3.5 and the map proof's
256 SHA-256 computations 0.6; a phone will differ, as everywhere in this
document. A check of four hundred contacts is four hundred HTTPS requests
every six hours, and that, not the arithmetic, is its cost.

## Cryptography on the device (2026-09-11)

Every cryptographic operation in Z runs in Dart: the `cryptography` package
without `cryptography_flutter`, so no platform implementation is wired in
on any platform, and `pqcrypto` for the post-quantum pair, which has no
platform implementation to wire in. `protocol/tool/crypto_bench.dart`
(`dart run tool/crypto_bench.dart`, or `dart compile exe` for the AOT
column, which is what a release build runs) times every primitive the way
Z uses it, medians after a warm-up; `server/bench/native_crypto.js` (`npm
run bench:crypto`) runs the classical ones through OpenSSL on the same machine as a stand-in for
what a platform implementation would cost (Android's is BoringSSL, Apple's
is corecrypto — compiled code of the same kind). Same machine as every
other number here.

| primitive | operation | Dart, VM (JIT) | Dart, AOT | OpenSSL | AOT ÷ OpenSSL |
|---|---|---:|---:|---:|---:|
| SHA-256 | 1 KB | 23 µs | 14 µs | 2 µs | 7× |
| SHA-256 | 64 KB | 736 µs | 890 µs | 42 µs | 21× |
| HMAC-SHA256 | 1 KB | 62 µs | 20 µs | 3 µs | 7× |
| HKDF-SHA256 | 32 bytes out | 87 µs | 27 µs | 8 µs | 3× |
| XChaCha20-Poly1305 | seal 1 KB | 192 µs | 47 µs | 9 µs | 5× |
| XChaCha20-Poly1305 | open 1 KB | 88 µs | 47 µs | 9 µs | 5× |
| XChaCha20-Poly1305 | seal 64 KB | 2.02 ms | 2.46 ms | 91 µs | 27× |
| XChaCha20-Poly1305 | open 64 KB | 2.04 ms | 2.43 ms | 39 µs | 62× |
| X25519 | keygen | 725 µs | 609 µs | 34 µs | 18× |
| X25519 | shared secret | 711 µs | 605 µs | 34 µs | 18× |
| Ed25519 | keygen | 1.57 ms | 1.15 ms | 33 µs | 35× |
| Ed25519 | sign 200 B | 3.16 ms | 2.37 ms | 33 µs | 72× |
| Ed25519 | verify 200 B | 2.77 ms | 2.48 ms | 98 µs | 25× |
| ML-KEM-768 | keygen | 1.23 ms | 751 µs | — | — |
| ML-KEM-768 | encapsulate | 1.67 ms | 809 µs | — | — |
| ML-KEM-768 | decapsulate (from seed) | 2.96 ms | 1.70 ms | — | — |
| ML-DSA-65 + Ed25519 | keygen | 8.98 ms | 3.69 ms | — | — |
| ML-DSA-65 + Ed25519 | sign 200 B | 8.09 ms | 9.04 ms | — | — |
| ML-DSA-65 + Ed25519 | verify 200 B | 5.56 ms | 4.84 ms | — | — |
| sealed envelope | seal (1 024 bucket) | 1.88 ms | 1.45 ms | — | — |
| sealed envelope | open (1 024 bucket) | 1.92 ms | 1.46 ms | — | — |
| Argon2id | 19 MiB, t=2 (passphrase unlock) | 261 ms | 128 ms | 38 ms | 3.4× |

(The OpenSSL AEAD line is ChaCha20-Poly1305 with a 12-byte nonce; XChaCha20
adds one HChaCha20 block, a rounding error at these sizes. Argon2id's
native figure is OpenSSL 3.5 through Python's `cryptography`, since Node
does not expose it. ML-KEM and ML-DSA have no platform implementation on
Android at all; on this machine's OpenSSL they exist but neither binding
exposes them, and they would not be the ones to move anyway.)

What the gap costs, in things a user does. A sealed envelope is 1.5 ms of
crypto, and a text message is one of them plus a ratchet step (0.23 ms,
measured above): **crypto is a few milliseconds of the ~10 ms a send
costs, and it is not the part a user notices**; the vault transaction and
the wire decoration were. Where it does add up:

* **A group send** is one sealed envelope per member device. Fifty members
  is ~75 ms of sealing inside a fan-out that takes 1.2 s for other
  reasons, and no longer blocks the composer at all.
* **A transparency check** (§19) verifies one Ed25519 signature per
  contact and one per head: 2.5 ms each in Dart against 0.1 ms native.
  Four hundred contacts is a second of verification every six hours,
  against 40 ms. It runs in the background either way.
* **An attachment** travels in 140 KiB chunks, each encrypted under the
  file key and then sealed as an envelope of its own — two AEAD passes and
  one X25519 per chunk. Scaling the 64 KB line, a 25 MB file is ~180
  chunks and **about two seconds of AEAD in Dart against under a tenth of
  a second native**, on the send and again on the receive. This is the one
  a user could see, and the line to read first on a phone.
* **The passphrase unlock** is one Argon2id: **128 ms here against 38 ms
  native**, and a phone is slower than this machine by a factor the phone
  has to tell us — a mid-range phone that is 4× slower on this line makes
  the passphrase unlock half a second, which is the border of noticeable
  and well inside acceptable for a step that is meant to be slow.

Absolute numbers on a phone are not in this table because this machine is
not one. **Settings → Developer → Cryptography benchmark** runs exactly
these rows on the device and copies them as this table
(`crypto_bench_screen.dart`; `bench_test.dart` keeps the two in step), so
the phone's column is one tap and a paste away, and a reader who wants the
number for their own phone can have it.

**The decision, and the rule for changing it.** Not adopting
`cryptography_flutter` now. The dependency is a second package from the
same author, platform channel code on each platform, and a native boundary
per operation whose own overhead is the first thing a measurement would
have to subtract at these sizes; what it accelerates on which platform
has to be read from the package at the version chosen, and it would leave
the post-quantum pair, the ratchet and everything on Linux and Windows
exactly where they are. Against that, the table says the per-message cost
is a few milliseconds and invisible, and the two places the gap could show
— a large attachment, the passphrase unlock — are bounded and known. The
rule: **measure on a phone first, with the screen built for it; adopt a
platform implementation only if the passphrase unlock passes one second
or a 25 MB attachment passes five seconds of crypto on a mid-range phone
— longer than its own transfer on a decent connection** — and then for
those operations, measured before and after. Below
that, the pure-Dart build keeps its property — one implementation, read
in one language, the same on every platform — which was the reason it was
chosen.

## Not measured

Named so this document does not read as more complete than it is:

* ~~**Real hardware.** Everything here is a desktop test VM. Phone numbers,
  especially for the asymmetric operations, will differ — and all of the
  crypto runs in Dart (`cryptography` without `cryptography_flutter`), so on
  a phone Ed25519, X25519 and ChaCha20-Poly1305 are software where the
  platform has native implementations. What that costs, and whether the
  dependency is worth its supply-chain surface, is unmeasured and a
  decision, in that order.~~ Measured above on 2026-09-11 — pure Dart
  against OpenSSL on this machine, with the decision and the rule for
  revisiting it — and the phone's own column is a Developer-mode screen
  away. The rest of this document is still a desktop VM.
* ~~**Multiple devices per member.** The fan-out to a contact's extra devices
  happens in `_fanToContactExtras`, which is `unawaited` — it does not block
  the send, and it is not in these timings.~~ Measured on 2026-09-11, and
  the sentence struck through was true of the send it was part of and false
  of the next one: the fan-out ran its network sends *inside* the
  per-conversation lock, awaiting the relay's ack — up to 20 s per device on
  a stalled link — while every other send and receive for that contact
  waited. It also threw and was swallowed when the link was down, so the
  laptop's copy simply did not go from us (the contact's phone mirrors it
  across, which is why it was never missed). It goes through the durable
  outbox now, and the lock covers only the ratchet step and the writes
  (`extras_fanout_test.dart`, every property broken once to see it fire;
  the 7.7a removal notice and the ML-KEM offer to an extra device were
  direct sends of the same shape and go through the outbox now too). Cost, offline, twenty messages each, one run: a text to a contact
  with 0 / 1 / 2 / 3 extra devices takes 14.5 / 24.5 / 28.6 / 27.6 ms until
  every copy is queued, of which the `sendText` call itself is 13.6 / 16.2 /
  20.2 / 19.8 ms — the first extra device costs about one more send, and
  the ones after it much less, because the extra-device session encrypts
  the message once per device but decorates and seals it in one pass.
  Members × devices for groups is still only members here.
* ~~**Cold start** and **relay load profile**, both named in roadmap 15.3.
  The relay's abuse and capacity behaviour is exercised by
  `server/test/load.test.js`; its latency profile under sustained load is
  not.~~ Both measured on 2026-09-11 — cold start above, and it was linear in
  the contact count at a rate that would have been seconds on a phone; the
  relay below.
* ~~**Receive-side cost**, which is where the skipped-key cache is actually
  *used*.~~ Measured above, and it held the largest cost in the app.
