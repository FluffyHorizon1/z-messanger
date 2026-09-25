# ADR 0021 — A post‑quantum key nothing commits to is kept as a *candidate*, and comparing the safety number is what confirms it

**Status:** **Accepted** (2026‑09‑20) — built (3.9.2). Amends §18.2, §18.3 and
§18.5; extends ADR 0003.
**Decides:** what a client does with an ML‑DSA‑65 key that arrives for a
contact it holds no commitment for, which safety number each side of a pair
shows, and how two people who started classical reach the post‑quantum number
without deleting each other.

## Context

Reported against published 3.7.0, in two sentences: *"when an account that
just has a classical number tries to compare with a quantum number they don't
match"*, and *"I can't see a way the person can upgrade to a quantum number"*.

Both come out of one rule in §18.2. A post‑quantum key that arrives in‑band
with **no commitment to check it against** was *discarded*. The reasoning was
sound as far as it went — nothing binds that key, so nothing can be checked,
and keeping it would be trust‑on‑first‑use — but it missed that **holding a
commitment is one‑sided**. A commitment is the state of whoever scanned the
other person's `zc3.` code. The other person may never have scanned anything:
they added you from a classical code, or accepted a contact request (ADR
0011), or hold a record made before v3 existed. Nothing in the design makes
the two sides symmetric, and the common paths make them asymmetric.

So one pair, two screens:

| | Alice — scanned Bob's current `zc3.` code | Bob — added Alice from a classical code, by accepting a contact request, or from a pre‑v3 record |
|---|---|---|
| commitment held for the other | yes | **no** |
| the other's ML‑DSA key arrives in‑band | checked against `pqc`, matches, kept | **discarded** — §18.2 as it stood |
| assurance (§18.3) | `hybrid` | `classical` |
| safety number shown (§18.5) | v2 — both halves of both account keys | v1 — the two Ed25519 keys |

Alice reads twelve groups of digits; Bob reads twelve different groups of
digits; neither number is wrong and they will never agree. The verification
ceremony — the one thing in this app a user is asked to do by hand, and the
thing every other guarantee is anchored to — cannot be completed, and the
screen offers no account of why. That is the first sentence.

The second is the first one's consequence. Bob's state was **terminal**.
Nothing that happened next could change it: the key would be re‑offered on
traffic and discarded again every time. Re‑scanning Alice's code was not a
way out either, because `addContactFromCode` threw *"already in your contacts
as …"* on an rid it already held, so the scan that would have given Bob the
commitment did nothing at all. The only escape was to delete the contact —
and with it the conversation and its history — and add them again.

This is not a corner. Every contact added by accepting a request lands on
Bob's side of that table by construction, because a request carries no
commitment; so does every contact that predates v3.

## What was rejected

- **Trust the key on first use: no commitment, accept it anyway and go
  `hybrid`.** The shortest fix, and it deletes the point of the design. §18.2
  carries a commitment rather than a key id precisely so that an adversary
  present at the exchange cannot supply their own ML‑DSA key and pass every
  hybrid check afterwards; ADR 0003 spends a QR code's entire budget on it.
  Accepting an unbacked key makes the commitment decorative against exactly
  the adversary §18 exists for — one who can forge the classical channel — and
  it would do so silently, on a screen that says "post‑quantum" in green.
- **Make re‑scanning the primary path** — fix `addContactFromCode` and tell
  Bob to scan Alice's code again. Rejected first on the user's own objection,
  that he dislikes having to re‑scan; and then on reach, which is the harder
  objection: it helps only two people who are in the same room. It does
  nothing for a pair who are apart, nothing for a pair neither of whom holds a
  v3 code of the other, and nothing for the accepted‑request case that
  produced the report. A remedy that requires the meeting is no remedy for
  people whose whole relationship with the app is that they did not meet.
- **Show the post‑quantum number as soon as we hold their key, commitment or
  not.** This is today's bug with one more state in it. Whichever side holds
  the other's key first moves its number alone, so the two screens disagree
  during the window — and against a peer running a build that discards the key
  outright, the window never closes.
- **Require the acknowledgement for an established key too**, making the rule
  perfectly symmetric — show the post‑quantum number only when each side holds
  the other's key *and* has said so. It would close the one gap named below,
  and it cannot be done: a 3.7.x peer sets `ack` only on a `pqid`, sends that
  `pqid` once, and does not answer one that already carries `ack`. So where
  our key reached it after its own send had gone, it holds ours and will never
  say so — and we would drop to the classical number while it shows the
  post‑quantum one. That is a *new* disagreement, in the case that works
  today, traded for an old one that ends when the peer updates. The asymmetry
  is the cost of not breaking the field.
- **A manual "switch to the post‑quantum number" control.** It asks the user
  to resolve, by hand and in the dark, the one question the client is supposed
  to answer for them: which number the *other* screen is showing. Two people
  toggling until the digits match is not a ceremony; it is a ceremony's
  failure mode, and it trains the habit that makes a real mismatch survivable.

## Decision

**1. The key is kept, as a candidate, and it is only ever a number.**
`Contact.pqCandidate` (`contacts.enc_pq_cand`, sealed at rest exactly as
`enc_pq_pub` is) holds an ML‑DSA‑65 key that arrived in‑band for a contact no
commitment is held for. It is used to derive the safety **number** and for
nothing else. It is never `hybridKey`, so it never verifies a device list
(§18.9) and never backs a transparency claim; it does not move the assurance
state, which stays `classical`; and it is not mirrored to the account's own
devices, which continue to receive `pqk` — an established key — and never a
candidate. **The first key to arrive is the candidate**: a later, different
one does not replace it and is ignored. Nothing distinguishes the two (the
ratchet authenticated both as this contact), so a swap would buy no
information while moving a number the user may be reading aloud at that
moment. A key already refused against a commitment (`pq_mismatch`) is not
replaced by a candidate either.

**2. Which number is shown, decided the same way on both screens.** A client
shows the post‑quantum number when the key behind it is **established**, or
when it is a **candidate and the peer has said it holds ours**; otherwise the
classical one (`Contact.showsPostQuantumNumber`). The peer says so with `ack`
on a `pqid` — widened from "I hold your key, checked against my commitment" to
"I hold your key", candidate included — or with `pqack`, a new keyless inner
message for the case where no `pqid` of ours is going to carry it. Both sides
evaluate the same rule over the same two facts and arrive at the same answer,
which is the property the number needs and the previous behaviour did not have.

The mixed‑version case then falls out without a special case, for the pair the
report came from: a client from before this ADR discards an uncommitted key and
never acknowledges one, so a current client facing one never sees the
acknowledgement, keeps its candidate off the number, and shows the classical
number — which is what that peer is showing. Both screens agree, on the number
the older build is able to compute.

**The limit, stated exactly.** Where the older peer holds a commitment of ours,
it establishes our key and shows the post‑quantum number whatever we do, and
whether we can join it there turns on one thing: a pre‑0021 client can say "I
hold your key" only as `ack` on a `pqid`, and it recomputes that flag at each
send. So it tells us if and only if one of its sends falls after our key
reached it — which its opening volunteer usually does not, and which our answer
then suppresses, since a `pqid` carrying `ack` is not answered. Both orderings
occur. When it did acknowledge, both screens show the post‑quantum number. When
it did not,
it shows the post‑quantum number and we show the classical one — the reported
bug, surviving in the one shape no change of ours can reach, because the code
that would have to speak is already in the field. What this ADR guarantees
there is narrower and worth saying plainly: the disagreement ends when that
side updates, instead of lasting for the life of the contact. It can also end
earlier by accident — §18.2 has a client re‑offer its key when the recipient's
device list gains a device, so linking a device of ours gives that peer another
send in which to set `ack`. That is luck, and the fix does not rest on it. Criteria 3 and 3b
of the test file pin both halves, the second by asserting the display rule
rather than an outcome that depends on which envelope won.

**3. Confirming a candidate‑derived number establishes the key.** When the
user ticks "verified" against a number computed over a candidate, that
candidate becomes `pqPub`: hybrid assurance, usable for device lists, durable.
This is not a concession. A commitment is evidence of one specific kind — a
human read a value off the other person's screen over a channel the adversary
does not control — and the comparison is the same evidence by a different
route. The number binds both halves of both account keys, so a match says the
key that arrived in‑band is the key on their device; a planted key makes the
comparison **fail**, which is precisely what the ceremony is for. The tick
continues to record *which* number was compared (13.3), so the reclassification
is computed before the key moves and no green tick is ever observable against a
number the user never read. Withdrawing the tick later does not un‑establish
the key; withdrawing a tick never has.

**4. Re‑scanning is kept, as the second path, and now upgrades.**
`addContactFromCode` on an rid already held no longer throws: a code carrying a
commitment the record lacks gives the record that commitment
(`_upgradeContactFromCode`). A candidate already held is checked against it on
the spot — a match is established with no comparison needed, since the code was
scanned in person; a mismatch is refused exactly as an in‑band mismatch is, and
takes the candidate's number off the screen with it. The refusals are strict: a
code whose commitment differs from one already held, a code naming a different
identity than the record's, and a code that disagrees with an already‑established
key are all rejected with a message saying so. A person's post‑quantum key does
not change under the same classical identity unless something is wrong, and
"delete the contact and add them again" remains the honest path for a genuine
reset.

## Consequences

- **One new inner kind, `pqack`** — `{"k":"pqack","mid":…,"ts":…}`. Additive
  under §14 and ignored by clients that predate it, like `pqek` and `pqid`
  before it. A few dozen bytes: it pads into the **1 024‑byte** bucket (§8),
  the one read receipts, reactions and short chat occupy, so unlike a `pqid`
  at 16 384 it is not a distinctive mark on the relay's view (R17). It is sent
  **at most once per contact**, gated by a flag (`pq_told`) that survives a
  restart and travels in the archive rather than one held in memory, and never
  when a `pqid` we are about to send will carry the same fact in its own `ack`.
- **Vault schema 13.** `contacts` gains `enc_pq_cand` (sealed), `pq_acked` and
  `pq_told`. Migration is three `ALTER TABLE`s with defaults; nothing is
  rewritten.
- **All three travel in the backup archive** as `pqcand`, `pqack` and `pqtold`
  on the `contact` record (`BACKUP.md`). A restore that dropped them would show
  the classical number again for every contact whose post‑quantum half was
  established by comparison rather than by a scan, and would ask those people
  to compare a second time for nothing.
- **The contact screen is keyed on a new `PqDisplay` enum, not on
  `IdentityAssurance`.** They genuinely differ for a candidate — the number is
  post‑quantum while the identity is still classical — and collapsing them
  would force one of the two to lie. `PqDisplay` adds `waitingForThem` ("Waiting
  for them", neutral: we hold theirs, they do not hold ours, both screens show
  the classical number) and `unverified` ("Post‑quantum, unconfirmed", in the
  **warning** colour and deliberately not the green one: the digits are the
  post‑quantum ones, and nothing has yet checked the key they came from).
- **Opening a contact asks for the key** (`requestPqIdentity`) when none is
  held, bounded like any other nudge, so an upgrade does not wait for the next
  message on a screen the user opened in order to compare.
- **THREAT_MODEL R37** records what a held-but-unchecked candidate is worth
  before the comparison.
- **Wire, relay, ratchet, sealing:** otherwise untouched. No version bump
  (§14), no change to the commitment, the code formats, or any signing input.

## Exit criteria

The exit criteria are the eleven tests in `app/test/safety_number_mixed_test.dart`.
