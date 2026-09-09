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

The unattributed remainder is the rest of the send path: the ratchet step, two
serialisations of the conversation state (one for the rollback snapshot, one to
persist), and lock bookkeeping. **It is left unattributed on purpose rather
than guessed at** — attributing it further is the first step for anyone who
wants to optimise, and this document should not invent a breakdown it has not
measured.

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

1. **Do not block the composer on fan-out.** The message is durable once
   committed; show it and let the outbox drain. This removes the user-visible
   stall entirely and is independent of every other item here.
2. **Stop serialising the conversation twice per send.** The rollback snapshot
   is a full `jsonEncode` of state that is about to be re-encoded anyway.
3. **Separate the skipped-key cache from the hot ratchet state**, so a cold
   cache is not re-sealed on every send.
4. **Batch the outbox writes** — but only with a per-recipient rollback story
   that survives one recipient failing.

None of these is a change to the protocol, and none of them is a reason to
introduce a group key.

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
* **Receive-side cost**, which is where the skipped-key cache is actually
  *used*.
