# ADR 0015 — Handles: a name you can be found by, and what it costs

**Status:** **Proposed** (2026‑09‑19) · **revised 2026‑09‑19** — awaiting
decision. The technical design is settled below; what is not settled is
whether Z wants to be findable, which is a product decision with a claims
bill attached. The revision adds shape **E**, which is now the recommended
one; see *Revision* at the end for what prompted it and what it replaces.
**Decides:** whether an account can claim a searchable name, where such a
registry would live, and what would have to stop being true for it to exist.

## Context

The ask, in its original form: let people claim a username on setup, append
it to a list the way the transparency log appends device lists, refuse a name
already on the list, and give the claiming account sole use of it — with no
password database.

The last part is right, and it is the part people usually get wrong. Z needs
no password database for this because an account already holds an Ed25519
root key. Ownership of a name is not a secret the server stores and checks;
it is a signature the claimant produces and anyone verifies. Nothing on the
server side needs protecting, because nothing on the server side is a secret.

So the mechanism is not the problem. Three other things are.

### What Z says today, in three places

- `THREAT_MODEL.md`, under "Design decisions that follow from zero trust":
  **"No accounts, no phone numbers, no directory, no key server."**
- `adr/0008` (federation) decides the client‑to‑many‑relays shape expressly
  **"no relay‑to‑relay protocol, no directory"**.
- The Play listing: *"No phone number, no email, no username, no password."*
  The Data‑safety notes add that introducing **a directory service** requires
  the console form to be updated *before* the change ships.

A handle registry is a directory service. Building one is not a change of
implementation, it is a change of claim, and this project's usual failure
mode is a claim outliving the code that justified it. Whatever is decided,
those three move first or not at all.

### The property a searchable name would invert

`R20` accepts a real cost: anyone holding an account's public key can read
that account's publish history from the log or a mirror — how many device
lists, at which versions, when. The justification is explicit, and it is an
entropy argument:

> Labels are `SHA‑256(context ‖ accountEdPub)`, so only a party already
> holding the key can compute one; a VRF‑blinded label (`adr/0006`,
> considered and rejected) would hide labels from readers of a *mirror* at
> the cost of a proof per lookup and a second key, **for identifiers that are
> 256‑bit random and cannot be enumerated**.

A handle is low‑entropy by construction. Being guessable is the feature. Put
handles in the same log under the same label scheme and R20's premise — only
someone who already holds your key can compute your label — stops being true,
and R20's accepted cost starts landing on anyone who can guess your name.
`adr/0006`'s rejection of VRF blinding was reasoned *from* unenumerability,
so it would have to be reopened, not inherited.

Hashing the handle does not rescue this. `alice`, `jsmith`, `finnian` are
dictionary‑sized. An append‑only log that anybody can mirror is an offline
cracking target with no rate limit to apply, and being downloadable in full
is the point of the mirror design (`adr/0006`), not an oversight to fix.

### What the existing log does and does not give for free

The substrate is close but the semantics are opposite. The log is keyed by
label, and a publish is accepted **only under the account key's signature and
only at a version above the label's last** — latest‑version‑wins, one owner
per label, established by whoever published first and re‑asserted by the same
key thereafter. A handle registry wants **first‑claim‑wins and then refusal**:
a later claim on a bound name must be rejected even though it is validly
signed, because it is signed by the wrong key. That is a new rule on the same
machinery, not a configuration of the existing one.

The four publish gates (`PUBLISH_PER_MIN` 30, `PUBLISH_PER_MIN_TOTAL` 120,
`PUBLISH_PER_ACCT_PER_DAY` 20, `PUBLISH_NEW_ACCOUNTS_PER_MIN` 10) bound the
*rate* of claims. They do not bound the total, and a keypair costs nothing, so
they do not make squatting expensive — only slow.

## The shapes

**A. Handles in the KT log.** One log, one mirror, one witness story. Labels
become `SHA‑256("z-handle-v1:" ‖ handle)`.

**B. A separate log, plaintext handles.** Same code, own instance, own head.
The KT log's analysis stays true of the KT log.

**C. A separate log, hashed handles with a discriminator.** Names are claimed
as `alice#7f3a`, the discriminator assigned by the log from the claim's own
hash; the label is `SHA‑256("z-handle-v1:" ‖ handle ‖ "#" ‖ disc)`. Lookup is
exact‑match on the full string.

**D. Do not build it.** Keep contact codes (`adr/0009`), one‑time invites and
contact requests (`adr/0011`) as the only ways to reach someone.

**E. A handle resolves to an introduction, not to an identity.** Opt‑in, and
the registry never holds the account key at all.

A claim binds `handle → ownerPub`, where `ownerPub` is a **handle key**
generated for this purpose and unrelated to the account root. The value it
signs is `{introPub, displayName?}`; the introduction mailbox is
`b64url(SHA‑256(introPub))`, which is how every routing id in Z is already
derived (`identity.dart:70`). Resolving `@finnian` therefore yields a random
32‑byte pseudonym and a mailbox — not `accountEdPub`, and so not the input to
`SHA‑256("z-kt-label-v1:" ‖ accountEdPub)`. **R20's premise survives intact
and `adr/0006`'s rejection of VRF blinding can be cited rather than
reopened.**

Reaching someone by handle is then the request flow that already exists: the
initiator sends a `creq` (`adr/0011`) to the introduction mailbox, bound to
that mailbox's rid by the signature it already carries; the owner sees it on
the Requests screen and accepts, declines or blocks. Identity is exchanged on
accept, and safety numbers decide verification exactly as they do today.

The registry is the log's own semantics with a different label input:
`label = SHA‑256("z-handle-v1:" ‖ handle)`, publishes accepted only under
`ownerPub` and only above the label's last version. First claim establishes
the owner; the owner rotates `introPub` — to end a spam wave, or to retire the
handle by publishing no mailbox at all — without losing the name. No new
publish rule is needed, which is the point: the first‑claim‑wins‑then‑refuse
semantics the original framing wanted are what the log already does, once the
label stops being derived from the thing that must stay secret.

Z has the primitive already. `connect_relay.dart` derives "two throwaway relay
identities HKDF'd from the invite secret, one per role", precisely so a
ceremony runs between mailboxes that are not the participants' own. E is that
idea made durable and one‑sided.

| | A. in the KT log | B. separate, plaintext | C. separate, hashed + discriminator | D. not built | E. introduction, opt‑in |
|---|---|---|---|---|---|
| R20's unenumerability premise | **broken** — reopens `adr/0006`'s VRF rejection | intact for KT; absent for handles | intact for KT; handles enumerable by dictionary, not by listing | intact | **intact** — the account key is never in the registry |
| a public roster of who uses Z | yes, plus their device‑list history | yes | recoverable by dictionary; no listing endpoint | none | a roster of **volunteers**, and of pseudonyms rather than account keys |
| squatting | free and permanent | free and permanent | pointless — the namespace is not scarce | n/a | free, and it **harvests** — see R37 |
| "no directory" claim | gone | gone | gone | kept | gone |
| new service to run | none | one | one | none | one, and it needs a witness |
| lost key | name gone for ever | same | same, but a fresh `alice#…` is available | n/a | name gone for ever (the handle key is in the vault and the backup) |

## Decision (recommended, not taken)

**Do not put handles in the transparency log.** Unchanged and not close: the
log's published privacy analysis rests on labels nobody can guess, and handles
are guessable on purpose. Shape A trades a documented, reasoned property for
convenience and would require `adr/0006` to be reopened rather than cited.

**If Z is to be findable, build E.** It is the only shape that leaves R20
where it is. Making handles opt‑in — which was the question that produced this
revision — removes the census objection completely: a registry of volunteers
is a directory in the sense that matters legally and not in the sense that
matters to someone who never claimed a name. But opt‑in on its own does not
save shapes B or C, because in those a handle must resolve to something you
can message, everything you can message carries `accountEdPub`, and
`accountEdPub` is the KT label input. **Consent to be listed would silently be
consent to publish your device‑list history**, and "anyone who guesses this
name can see when you add or remove a device" is not a sentence that belongs
under a username field. E severs that link rather than disclosing it.

**Sequence it after G3.** A registry that can show two people different
answers for `@finnian` is the same targeted attack `adr/0006` built the log to
make detectable, and it wants a witness for the same reason. Z does not yet
have a witness for the log it already runs (`GA_CHECKLIST.md` G3). Adding a
second unwitnessed log first would be taking on the debt twice.

**Whether to be findable at all is still not this record's to decide.** With E
the security cost is small and stated; what remains is a product question and
a claims bill, and everything in the threat model currently answers no.

**What E does not fix, and what would have to be accepted:**

- **A squatter harvests.** A `creq` carries the requester's bundle and display
  name (`contact_request.dart`), so whoever holds `@finnianbond` learns the
  identity of everyone who tried to reach Finnian, and that they were trying.
  The disclosure is a public bundle and the accept screen names the sender, so
  nobody is *added* wrongly — but the correlation is real and new, and it is
  worse in a sparse opt‑in namespace, where the genuine person's absence is
  invisible. A two‑round opening that withholds the bundle until accept would
  limit it, at the cost of an owner deciding with no name in front of them —
  which is the thing `adr/0011` was written to end.
- **A standing open inbox.** `adr/0009`'s invite is one‑time and 24 hours
  because a bearer token that persists is a standing risk; a handle is
  deliberately durable, so that rule does not transfer. It does not have to: a
  handle is not a bearer token, because it confers the ability to *reach* you,
  never to *be* you. The consent gate moves from the invite to the response,
  which is `adr/0012`'s framing. What it costs is an address anyone can send
  to, bounded by the relay's existing `NEW_MAILBOX_PER_MIN` and
  `MAX_QUEUE_BYTES_PER_USER`, drained by the 72‑hour TTL, and endable by
  rotating `introPub`.
- **Traffic to the introduction mailbox is visible to the relay**, and anyone
  who resolves the handle can compute that mailbox. So the relay, and anyone
  watching it, can see how much first‑contact a given handle attracts. It is a
  pseudonym, not an account key, and it is rotatable — but it is a leak the
  account mailbox does not have, because the account mailbox is unguessable.
- **Erasure is bounded, not solved.** The owner can rotate to a value with no
  mailbox, which stops the handle working. The label and its history remain,
  because that is what an append‑only log is. Consent makes the legal position
  better than the unsolicited case; it does not make the record deletable.

## Rejected

- **A password or recovery secret per handle.** Nothing to add: the account
  key already proves the claim, and a recovery secret would be the first
  server‑side secret in the system.
- **Plaintext handles in any public log (B).** It publishes a roster of every
  user with no compensating benefit over C.
- **Prefix or fuzzy search.** Any interface that answers "names starting
  with…" is an enumeration API however the storage is arranged.
- **A handle that resolves to the account identity (B and C).** Superseded by
  E. Any lookup that hands back enough to message someone hands back
  `accountEdPub`, and that is the KT label input — so B and C make a guessable
  name into a key R20 assumed could only be given, not found. Opt‑in does not
  change this; it only makes it consented, and consented to something the
  consent screen cannot state briefly enough to be honest.
- **Handles as a verification signal.** A name that matches is not a key that
  matches. Safety numbers stay the only thing that catches a substituted
  exchange (`adr/0009`), and any handle UI must say so where it is read, not
  in a settings page.

## Consequences if E is accepted

1. **Three claims change before any code ships:** the `THREAT_MODEL.md`
   "no directory" line, `adr/0008`'s "no directory" clause, and the Play
   listing's "no username" — plus the Data‑safety form, which the console
   notes say must be updated *before* the change ships, not after. Opt‑in does
   not reduce this bill; the form has a Required/Optional field and this is a
   declaration either way.
2. **Two new residuals**, next free numbers **R36** and **R37**.
   *R36*: an introduction mailbox is guessable from a claimed handle, so the
   relay and anyone watching it can see the volume of first contact a handle
   attracts — a rotatable pseudonym, never the account mailbox, which stays
   unguessable. *R37*: whoever holds a handle learns the identity of everyone
   who sends to it, including people who meant to reach someone else, and a
   sparse opt‑in namespace makes a squatted name indistinguishable from an
   unclaimed one.
3. **Erasure is bounded.** Rotating to a value with no mailbox stops the
   handle resolving; the label and its history stay, because the record is
   append‑only. The consent an opt‑in claim represents improves the position
   and does not make the record deletable. Take advice rather than designing
   around it.
4. **No recovery, by construction.** The handle key lives in the vault, so it
   travels with a linked device and a restored backup — but lose the account
   and the claim can never be reissued, because no authority could reassign it
   without becoming the trusted party the design exists to remove.
5. **A second log wants a second witness**, for the same reason the first one
   does. G3 is not met for the log Z already runs.
6. **Schema and wire.** Additive: a handle key and its claim in the vault and
   in the backup archive, a registry service, a resolve call, and one new
   screen. The `creq` format is unchanged — E reuses it rather than extending
   it, which is most of why it is the cheap shape as well as the safe one.

## Revision — 2026‑09‑19

Two questions after the first version was written, both from Finnian, and the
record changed for both.

**"Is it worth it given adoption — if the app is too technical people won't
use it?"** A fair criticism of the first version, which weighed privacy
against *convenience*. For a messenger that is the wrong scale: someone who
bounces off Z does not use Z less safely, they use something else, so adoption
is a security property and the original framing understated it. Examined and
it did not carry, for a reason worth recording rather than asserting: to find
someone by handle you must already know their handle, which means they told
you — and anyone who can tell you their handle can send an invite link
instead, which is one tap and no typing. Handles do not shorten the pairwise
path that is nearly all of onboarding; they serve the one‑to‑many case a link
cannot, which is a publishing feature and a real one. `USING_Z.md` already
describes the current flow as scan or send the code however you like, and
*"they do not have to scan you back; accepting is enough"* — `adr/0011` having
removed the genuinely strange part. The larger adoption cliff is `BACKUP.md`'s
own sentence, *"if the only device is lost, the history is gone"*, which no
handle addresses.

**"Can it be optional?"** Yes, and it is the better question. Opt‑in retires
the census objection outright — the strongest thing in the first version — and
in doing so exposed what opt‑in does *not* fix: that in shapes B and C the
resolution itself leaks `accountEdPub`. Shape E came from taking that
seriously, and it is materially better than what it replaces, so C stands
rejected rather than recommended.

## References

- `adr/0006` — the log, its label scheme, and the VRF blinding it rejected
  on unenumerability grounds
- `adr/0008` — federation, and the existing "no directory" decision
- `adr/0009`, `adr/0011`, `adr/0012` — how people are found and added today
- `THREAT_MODEL.md` R20 (publish history), and the design‑decisions list
- `PROTOCOL.md` §19.1 — `label = SHA‑256(utf8("z-kt-label-v1:") ‖ accountEdPub)`
- `protocol/lib/src/connect_relay.dart` — the throwaway‑mailbox primitive E
  makes durable: "two throwaway relay identities HKDF'd from the invite
  secret, one per role"
- `protocol/lib/src/contact_request.dart` — the `creq` E reuses unchanged, and
  the bundle disclosure R37 is about
- `GA_CHECKLIST.md` G3 — the witness a second log would also want
