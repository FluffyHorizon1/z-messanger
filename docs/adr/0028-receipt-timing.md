# ADR 0028 — A receipt leaves at a moment of its own, and can be turned off

**Status:** **Proposed** (2026‑10‑09) — built (phase 41, unreleased), for
review. Amends `PROTOCOL.md` §6.3; `THREAT_MODEL.md` R41; ADR 0007 ("What is
still true").
**Decides:** when a delivery or read receipt leaves the device, whether a
person can stop sending them, and what the ticks still say.

## Context

Sealed sender (§8, ADR 0007) keeps the sender off an envelope: the relay is
told only which mailbox it is for. The answer to it is addressed to the
sender. When a message arrives, the recipient's app sends an end‑to‑end
`dlv` back to the sender's mailbox (§6.3); 15.3 gathered a burst into one for
300 ms, and sent at once the moment 64 were waiting. A read receipt went when
the chat was opened — at once, if it was open when the message arrived.

So a relay — or anyone terminating its TLS, which for the public deployment
is Cloudflare (R44) — that writes envelope E to mailbox B and a fraction of a
second later takes a small envelope for mailbox A has A as E's sender. Nothing
else is needed: not the network address R21 is about, so carrier‑grade NAT,
a VPN or Tor in front of the app do not help; and not many messages, because
the receipt is automatic and prompt. This is the attack Martiny et al.
demonstrated against Signal's sealed sender (NDSS 2021), and the analysis of
3 October recorded it here (P1‑15, R41). Measured on the code before this
change, from the relay's own sockets (`receipt_timing_test.dart` 1 run against
it): twelve deliveries from six senders, and every receipt to its sender
233–366 ms after the delivery it answered.

## Decision

1. **A receipt is held.** When one becomes owed — a message stored, or read —
   it may not leave sooner than a **floor** of 5 s after that moment, and
   leaves at the latest at a moment drawn uniformly between 5 s and a
   **ceiling** of 60 s after it (`ReceiptTiming.standard`).
2. **Per person.** At the earliest such moment among one person's held
   receipts, every one of theirs past its floor goes: one `dlv` and, if any,
   one `read`, each naming at most 64 mids — a larger batch goes as several,
   at that moment, never early. A receipt still inside its floor stays for a
   later one. Measured: a `dlv` naming one to three messages is a 1 024‑byte
   envelope, four to sixty‑four a 4 096 one — the size of a text of a hundred
   characters or more.
3. **Not at the moment the device comes back.** On its own a receipt leaves
   only while both relay links are up, and after every (re)connection nothing
   held leaves sooner than the floor; a receipt whose moment fell while the
   device was away gets a new one. Otherwise a phone that drained its mailbox
   and answered everyone the moment it came online would point at all of
   them at once.
4. **Riding.** A receipt past its floor goes with the next thing the user
   sends that person — a text, a file, a reaction, an edit, a delete, a
   timer, or their copy of a group message — queued directly behind it in
   the same flush. That moment is the user's, and it was a moment the relay
   saw a message to that mailbox anyway. Things this client sends on its own
   (a hello, a key, a list, a group's answer to `gsync`) carry none: they
   leave at moments other people's messages choose.
5. **Read receipts the same way**, so a read receipt no longer marks the
   moment of reading. The read state mirrored to the user's own devices
   (30.3) still goes at once: it is R19's correlation, which this does not
   change, and releasing it WITH the receipt would put the user's laptop
   mailbox beside the contact's at one moment.
6. **Held durably.** The receipts owed are in the vault (`rcpt_<rid>`,
   sealed), removed with the contact, and not in a backup. A backgrounded or
   killed app sends them on its next start, at a moment of its own (3) — a
   300 ms window could afford to drop them; a minute cannot.
7. **A switch.** Settings › Privacy › *Delivery and read receipts*, per
   device, **on by default**. Off, the device sends neither kind — not on a
   timer, not riding — and forgets what it held; a backup carries the choice
   (`receipts_enabled`, an account‑level `state` key older importers skip).

**No wire change.** A ridden receipt is its own `dlv` beside the message, not
a member inside it. A member would be smaller and invisible, but a contact's
older devices would drop it, and their ticks would stop for good; knowing
that every device of a contact reads it needs a capability nobody announces
yet. What the relay sees instead is one more envelope in the burst a message
already makes — at no new moment, which is what R41 is about.

### The default

On. The tick is the only delivery signal Z has: there is no presence and no
"last seen", and a single tick is what tells someone a message is still
waiting at the relay for a phone that is off. Off by default would take that
from everyone to defend against an attack that, after this change, needs
patience rather than one message — and patience is rewarded anyway by what
receipts do not touch: a reply is an envelope to the sender too, at a human
moment seconds or minutes after the delivery, and a conversation is a run of
them. What turning receipts off protects is the one‑way case — someone who
receives and does not answer — and the people who need that can turn it off;
`USING_Z.md` says what it costs them and what it does not hide.

### What the ticks still say

A tick is a claim the recipient's device made about itself. Holding it
changes when the claim arrives, never what it says: one tick is still "the
relay has it", two "their device has it", two in colour "they opened the
chat". Nothing on the sender's screen moves before the receipt arrives
(`receipt_timing_test.dart` 3, 7), and a group message still turns only when
every current member has said so. Two things a reader could misread, and the
docs now say: two ticks can arrive up to a minute after the message did; and
from someone who turned receipts off, one tick is all that will ever come,
however long ago the message arrived — in a group, from every message, since
two ticks there wait for every member.

## What it buys, and what it does not

Measured at the relay, the same twelve deliveries
(`receipt_timing_test.dart` 1): before, every receipt 233–366 ms after the
delivery it answered; after, over six runs (72 receipts), every one between
6.3 s and 59.4 s after it, median 37.1 s. The floor is a guarantee: no
receipt reaches the relay in the first 5 s after a delivery it acknowledges.
The spread is what a watcher who knows this rule must search through —
every envelope any mailbox receives in a 55‑second window, rather than in
300 ms.

It does not defeat a patient relay. A delivery to B followed, somewhere in
the next minute, by an envelope to A is still evidence, and evidence adds up.
The closest row the 16.2 study measured (`THREAT_MODEL.md`, "Timing
patterns") is a pair of mailboxes that co‑activate on every message with up
to a minute of jitter: named after 8 messages in a quiet population and 30 in
a busy one, against 2 and 3 with none. That is an analogue, not a measurement
of this rule — batching and riding mean fewer receipt events than messages —
but its lesson stands: a delay buys a factor, not immunity, and in a quiet
population very little.
What defeats patience is a relay that cannot see which mailbox a delivery
reached (a mixnet, R15) or one that is yours, and for the one‑way case,
receipts off.

Each of a person's devices answers for itself (30.3): someone with a phone and
a laptop sends two receipts for each message, each at its own moment — two
samples for a watcher where there was one, as there were two before.

Other answers still go promptly, and are rarer: the post‑quantum exchange
answers a new contact's first messages once (`pqid`, `pqack`), a session
repair answers an undecryptable envelope with a `hello`, and an owner's list
request is answered with the list (`pdlreq`, ADR 0026). Each is once per
contact or per fault, not per message.

## Considered and rejected

**Receipts inside the next message** (an optional member of any inner
message). Smaller, and the relay would not see the receipt at all when it
rides. Rejected for now: see "No wire change" — it needs every device of the
contact to read the member, and a client that does not drops it silently,
which turns ticks off for that contact without anyone deciding to. Worth
doing behind a capability the devices announce.

**A longer ceiling** — ten minutes or an hour. The 16.2 table says that is
where a busy population stops being named within three days, and it is
email's delay: a tick an hour late is not a tick. The switch is the answer
for anyone who needs more than a minute buys.

**Cover receipts** (dummy envelopes to every contact on a schedule). 16.2:
a thousand dummies a day per device buys days, not weeks, at about 1.4 MB a
day each way.

**Ephemeral reply mailboxes** — Martiny et al.'s "sealed sender
conversations": the sender gives each conversation a mailbox not linked to
its own, and receipts go there. It removes the beacon rather than blurring
it, and it is a protocol of its own (a mailbox per conversation, rotation,
what the sender's other devices do); a candidate for a later ADR, not this
one.

**Off by default.** See "The default".

## Consequences

- Two ticks arrive 5 s to a minute after a message reaches the recipient's
  device, or with the recipient's reply. A sender looking at one tick for
  that minute is seeing the design work.
- A held receipt is a row in the vault for up to a minute (DATA_MAP), and a
  killed app sends it later rather than never.
- `PROTOCOL.md` §6.3 states the rule a client should follow; it is not a
  wire format, and an older client's prompt receipts still interoperate.
- `THREAT_MODEL.md` R41 moves from open to accepted: the beacon is gone, the
  statistical residual is stated, and the switch is there for anyone who
  needs more; ADR 0007 says what sealed sender does not hide by timing.
- Tests: `app/test/receipt_timing_test.dart` (7, measured at the relay
  through `server/test/support/observed_relay.js`), and
  `delivery_receipts_test.dart` rewritten for the held batch (15.3's
  immediate cap removed).

## References

* `PROTOCOL.md` §6.2, §6.3, §8, §12.1; ADR 0007; `THREAT_MODEL.md` R15, R19,
  R21, R41, R44 and "Timing patterns" (16.2).
* I. Martiny, G. Kaptchuk, A. J. Aviv, D. S. Roche, E. Wustrow, "Improving
  Signal's Sealed Sender", NDSS 2021.
