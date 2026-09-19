# ADR 0015 — Handles: a name you can be found by, and what it costs

**Status:** **Proposed** (2026‑09‑19) — awaiting decision. The technical
design is settled below; what is not settled is whether Z wants to be
findable, which is a product decision with a claims bill attached.
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

| | A. in the KT log | B. separate, plaintext | C. separate, hashed + discriminator | D. not built |
|---|---|---|---|---|
| R20's unenumerability premise | **broken** — reopens `adr/0006`'s VRF rejection | intact for KT; absent for handles | intact for KT; handles enumerable by dictionary, not by listing | intact |
| a public roster of who uses Z | yes, plus their device‑list history | yes | recoverable by dictionary; no listing endpoint | none |
| squatting | free and permanent | free and permanent | pointless — the namespace is not scarce | n/a |
| "no directory" claim | gone | gone | gone | kept |
| new service to run | none | one | one | none |
| lost key | name gone for ever | same | same, but a fresh `alice#…` is available | n/a |

## Decision (recommended, not taken)

**Do not put handles in the transparency log.** That is the one part of this
that should not be decided by preference: the log's published privacy
analysis rests on labels nobody can guess, and handles are guessable on
purpose. Option A trades a documented, reasoned property for convenience and
would require `adr/0006` to be reopened rather than cited.

**If Z is to be findable, build option C**, and state its cost plainly rather
than describing the hash as privacy. The discriminator is what makes it
tolerable: it removes scarcity, so squatting buys nothing; it makes exact
match the only sensible lookup; and it means a lost key costs a suffix rather
than a name. Add a claim that expires unless re‑signed, so abandoned names
return to the pool — an append‑only registry with no expiry is a namespace
that only ever shrinks.

**The recommendation between C and D is not this record's to make**, because
it is not a security question once C's costs are stated. It is whether Z
wants to be a thing you can look people up in. Everything in the threat model
currently answers no.

## Rejected

- **A password or recovery secret per handle.** Nothing to add: the account
  key already proves the claim, and a recovery secret would be the first
  server‑side secret in the system.
- **Plaintext handles in any public log (B).** It publishes a roster of every
  user with no compensating benefit over C.
- **Prefix or fuzzy search.** Any interface that answers "names starting
  with…" is an enumeration API however the storage is arranged.
- **Handles as a verification signal.** A name that matches is not a key that
  matches. Safety numbers stay the only thing that catches a substituted
  exchange (`adr/0009`), and any handle UI must say so where it is read, not
  in a settings page.

## Consequences if C is accepted

1. **Three claims change before any code ships:** the `THREAT_MODEL.md`
   "no directory" line, `adr/0008`'s "no directory" clause, and the Play
   listing's "no username" — plus the Data‑safety form, which the console
   notes say must be updated *before* the change ships, not after.
2. **A new residual**, next free number **R36**: a handle is a low‑entropy
   identifier in a public append‑only record, so the set of handles in use is
   recoverable by dictionary attack, and a handle links an account key to a
   name its owner chose. Mitigation is the discriminator and exact‑match
   lookup; there is no mitigation that makes the record private, and the row
   should say so.
3. **Erasure has no answer.** An append‑only public record of user‑chosen
   names cannot honour a deletion request. A device‑list label is 256‑bit
   random; a handle is usually directly identifying, which is a different
   legal question for a UK company and one to take advice on rather than
   design around.
4. **No recovery, by construction.** Lose the account key and the claim can
   never be reissued — there is no authority that could reassign it without
   becoming exactly the trusted party the design excludes. Expiry is the only
   honest release mechanism.

## References

- `adr/0006` — the log, its label scheme, and the VRF blinding it rejected
  on unenumerability grounds
- `adr/0008` — federation, and the existing "no directory" decision
- `adr/0009`, `adr/0011`, `adr/0012` — how people are found and added today
- `THREAT_MODEL.md` R20 (publish history), and the design‑decisions list
- `PROTOCOL.md` §19.1 — `label = SHA‑256(utf8("z-kt-label-v1:") ‖ accountEdPub)`
