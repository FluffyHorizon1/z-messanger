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

| | before | after |
|---|---:|---:|
| whole inbound path, in order | **54.7 ms** | **25.2 ms** |
| a message that arrives early, skipping 20 keys | 53.6 | 33.8 |
| a late arrival decrypted from the cache | 53.1 | 26.2 |
| in order, with the cache at its 1536-key cap | 68.0 | 42.5 → *see below* |

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

Two findings.

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

### What is left, and the next fix

After the memo, a receive is ~25 ms and 10 of it is the delivery receipt:
one full outbound send per inbound message, `unawaited`, but holding the
same per-conversation lock the next inbound needs, so a burst of fifty
queued messages on reconnect pays fifty sends in line. The wire format
already carries a list — `'mids': [...]` — so coalescing receipts over a
short window (a few hundred milliseconds) turns that into one send per
burst. Not done in this pass; it is the next thing here, and it is the same
shape as the fan-out queue: do the per-message work once per burst.

## Not measured

Named so this document does not read as more complete than it is:

* **Real hardware.** Everything here is a desktop test VM. Phone numbers,
  especially for the asymmetric operations, will differ.
* **Multiple devices per member.** The fan-out to a contact's extra devices
  happens in `_fanToContactExtras`, which is `unawaited` — it does not block
  the send, and it is not in these timings. Members × devices is the real
  shape; only members were varied here.
* **Cold start** and **relay load profile**, both named in roadmap 15.3. The
  relay's abuse and capacity behaviour is exercised by
  `server/test/load.test.js`; its latency profile under sustained load is not.
* ~~**Receive-side cost**, which is where the skipped-key cache is actually
  *used*.~~ Measured above, and it held the largest cost in the app.
