# ADR 0011 — Contact requests: an add you can refuse

**Status:** **Accepted** (2026‑09‑18) — the protocol (`creq`, §8.1), the model
(`ChatService` requests/blocklist and the `requests`/`blocked` tables), and the
Requests surface are built. Scope: the **scan / paste** add paths. The CONNECT
invite (ADR 0009) is left as‑is (auto‑add + optional safety number); a consent
gate for it is a possible follow‑on.
**Decides:** what happens on the *receiving* side when someone adds you, what a
request is worth, and how it cannot lie about who it is from.

## Context

Adding a contact was unilateral and, on the other person's side, silent.
`addContactFromCode` added the target at the unverified floor and sent them a
`hello`; the target had not added *you*, so to them you were an unknown sender
and the hello was dropped — the code said so in as many words. A real
connection therefore needed **both** people to add each other, and until the
second add the first person's messages sat unheard. That is the friction this
ADR removes: *scan or paste, and the other side gets "someone wants to connect
— accept or decline", instead of having to scan you back.*

Two things were missing, the same thing from two sides: no **consent** on the
receiving side (being added was invisible), and no way to **refuse** (a silent
add cannot be declined or blocked). The moment an add can reach you unsolicited,
refusal has to exist with it.

ADR 0009 already removed the *remote* two‑round‑trip (one CONNECT invite adds
both). It auto‑completes, and that is left unchanged here: both parties actively
participate in that ceremony, so the consent it lacks is a smaller gap than the
scan/paste one this closes.

## Decision

A **contact request** (`creq`): adding someone by scan or paste sends them a
request they can **Accept**, **Decline**, or **Block**, and the drop becomes
that request instead of nothing.

**It rides sealed but outside any ratchet, and carries its own signature.**
When it arrives there is no session — the receiver drops unknown senders before
it would decrypt one — so a `creq` is a self‑contained sealed payload (§8.1),
parallel to a file chunk, not an inner ratchet message. The sealed layer hides
the sender from the relay but proves nothing to the recipient, so the requester
signs, with the identity key its routing id is the hash of, the recipient's
routing id, a timestamp, and the exact bundle offered:

```
sigInput = "z-contact-request-v1:" || edPub || xPub || len(to)||to || u64(ts) || len(name)||name
```

A recipient accepts only a request whose bundle self‑verifies, whose routing id
is the sealed sender, and whose signature verifies under the bundle's own key.
**A forged "X wants to connect" is therefore impossible**: an attacker holding
X's public `zc1.` code cannot produce X's signature, and cannot replay a genuine
request at a different recipient because `to` is signed. This is the part a
reviewer should argue with, and it is why the request is signed rather than a
bare sealed bundle.

**Accept adds them exactly as a scan would.** From `bundle`, at the classical
floor; the account identity and post‑quantum key follow in‑band (§18.2), as
after any scan. Accepting sends a `creq` back, which lets the other side stop
waiting and re‑poke its opening hello if that was dropped — so the session
establishes both ways by the same path a mutual scan uses. **Decline** drops the
request in silence. **Block** drops it and every future request and message from
that routing id without a trace.

**The adder's side shows "requested".** A contact you added and they have not
answered is marked, and clears the moment any traffic from them arrives. It says
nothing about authenticity — only that they have not answered.

**Verification does not move.** An accepted request is a contact at the existing
unverified floor; the safety number, KT (ADR 0001/0006) and §18.3 are the
separate machinery that ends *verified*. A request is worth exactly what an
unauthenticated hello was worth — *someone holding these keys asked to connect*
— and the UI says that and no more. **No fourth assurance state.**

## Rejected

- **An unsigned sealed request.** Simpler, but then anyone could seal a request
  carrying a real person's public code and the recipient would be shown a
  request that person never made. The signature is the difference between "an
  add you can refuse" and "an impersonation you can be talked into".
- **Auto‑add on both sides (extended to scan).** No consent, no block; an
  unsolicited add could not be refused. The "no" is the whole feature.
- **A fourth assurance state for "requested".** §18.3 keeps three and ADR 0009
  kept three; a pending request is a pre‑contact object, not an assurance level.
- **Relay‑side request storage / a "who wants to add me" endpoint.** A request
  is an ordinary sealed envelope; the relay learns nothing new. A relay that
  *knew* requests would be a directory, which ADR 0009 rules out.
- **A consent gate on the CONNECT invite, in this ADR.** Deferred, not refused.

## Consequences

- **Zero knowledge, sealed sender, ratchet, keys at rest — unchanged.** `creq`
  is one sealed payload shape more (§8.1).
- **A new surface, written down as `THREAT_MODEL.md` R34.** Anyone with your
  code can now put a request in front of you. It is strictly better than the
  old silent drop — you see it and can Block — but it is your attention that it
  can spend, so a request is a quiet surface (not a per‑message notification),
  nothing reaches a chat until you accept, and Block is per routing id and
  silent.
- **No wire break, no new trusted party.** `creq` reuses the `zc1.` bundle. An
  old client never sends one and keeps dropping the opening hello; a new
  client's `creq` to an old client is dropped as an unknown sender exactly as
  today — nobody is worse off, only new↔new gains the request.
- **Storage:** `requests` (the sealed bundle, name, arrival) and `blocked`
  (routing ids), both sealed at rest; a `contacts.requested` flag. Adding a
  blocked id clears the block, so `contacts` and `blocked` never both name one
  id, and both request and block for a routing id are erased with the contact
  (`contact_erasure_test` sweeps them, C37).
- **`verified_sn` and the assurance badge are untouched.**

## Evidence

`AUDIT_SCOPE.md` C37. `protocol/test/contact_request_test.dart` (6: round‑trip
and verify, one‑recipient binding, sealed‑sender binding, tamper of each signed
field, a victim's public bundle cannot be minted, non‑requests parse as null).
`app/test/contact_requests_test.dart` (5: request appears as pending not a
contact and accept connects both ways with "requested" clearing; decline;
block silences future requests; a mutual add folds; deletion leaves no row).
