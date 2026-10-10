# ADR 0015 — Handles: a name you can be found by, and what it costs

**Status:** **Accepted** 2026‑10‑08 — revision 2, shape **E′** (Finnian:
*"I need handles to have been implemented soon"*). Proposed 2026‑09‑19 and
revised the same day (shape E recommended, C rejected); revision 2 rewrites
the Decision and the Consequences after the 2026‑10‑03 analysis found E, as
written, not buildable — five flaws (F1–F5) and six lesser points. The
reasoning that chose E, the Context and the shapes, stands as it was.
**Built:** the protocol library (36.1 — `PROTOCOL.md` §21.0–§21.4, §21.7),
the handle log (36.2, §21.5), introduction mailboxes at the relay (37,
§21.6) and the app (38, §21.8), with the claims bill below paid in the
repository. **Not deployed:** no handle log runs yet, and the app's defaults
name none, so until one is deployed and pinned the app says handles are
unavailable; the Play listing and the Data safety form change before the
release that ships them. What Finnian may still veto is listed at the end of
the Decision.
**Decides:** whether an account can claim a searchable name, where such a
registry would live, what would have to stop being true for it to exist —
and, since revision 2, what exactly is built.

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

*Revision 2: this paragraph is flaw F1.* The log accepts a label when it is
`labelFor(signer)`, so its one owner per label comes from deriving the label
from the key; a handle's label is derived from no key, and the owner must be
stored and enforced — the owner rule of §21.4. The rest of E stands.

Z has the primitive already. `connect_relay.dart` derives "two throwaway relay
identities HKDF'd from the invite secret, one per role", precisely so a
ceremony runs between mailboxes that are not the participants' own. E is that
idea made durable and one‑sided.

| | A. in the KT log | B. separate, plaintext | C. separate, hashed + discriminator | D. not built | E. introduction, opt‑in |
|---|---|---|---|---|---|
| R20's unenumerability premise | **broken** — reopens `adr/0006`'s VRF rejection | intact for KT; absent for handles | intact for KT; handles enumerable by dictionary, not by listing | intact | **intact** — the account key is never in the registry |
| a public roster of who uses Z | yes, plus their device‑list history | yes | recoverable by dictionary; no listing endpoint | none | a roster of **volunteers**, and of pseudonyms rather than account keys |
| squatting | free and permanent | free and permanent | pointless — the namespace is not scarce | n/a | free, and it **harvests** — see R48 |
| "no directory" claim | gone | gone | gone | kept | gone |
| new service to run | none | one | one | none | one, and it needs a witness |
| lost key | name gone for ever | same | same, but a fresh `alice#…` is available | n/a | name gone for ever (the handle key is in the vault and the backup) |

## Decision (revision 2): shape E′

**Do not put handles in the transparency log.** Unchanged and not close: the
log's published privacy analysis rests on labels nobody can guess, and handles
are guessable on purpose.

**Build E′: shape E, changed in nine places.** A handle still resolves to an
introduction and never to an identity, it is still opt‑in, and the request
that reaches someone is still `adr/0011`'s `creq`, unchanged — sealed to the
introduction mailbox's X25519 key, `xintro`, which the record carries beside
the Ed25519 `intro` whose routing id is the mailbox; one introduction seed
makes both (§21.3). What changes is everything the analysis found missing:

1. **The name is `nick.digits`** — `alice.42` (§21.1). A discriminator makes
   squatting pointless (`alice` is not scarce; `alice.42` is one of a hundred
   and more) and makes guessing one person's handle a hundred times dearer.
   ASCII only, with no Unicode folding of any kind, so a look‑alike cannot be
   typed at all; 28 reserved nicks, which a client refuses to claim AND to
   look up, since the log, seeing only labels, cannot refuse them itself.
2. **A separate log with an owner rule** (§21.4, §21.5). `kt/` in handle
   mode: its own key, its own head and witness contexts, never the KT log —
   heads carry no log identity, so two logs under one key would have
   interchangeable heads. The first entry for a label is a claim that fixes
   an owner key and a recovery commitment; only the current owner updates,
   and an update changes neither; only the recovery key changes them; each
   entry is the label's next version. One rule, in one order, applied by the
   log on the wire and on replay, by every mirror, and by every client over
   whatever history it holds.
3. **Labels are Argon2id** of the canonical handle, at the vault's 19 MiB and
   two passes (§21.2), not SHA‑256.
4. **Lookups ask for a bucket** — a prefix of the label and a proof that the
   bucket is complete (`adr/0023`) — never for the label itself.
5. **Reaching someone costs work.** A send to an introduction mailbox carries
   a proof‑of‑work stamp over the mailbox, the day and the envelope, checked
   by the relay before it stores anything (§21.6, §21.7); the owner sets the
   difficulty (16–28 bits) in the record and can raise it with an update. An
   introduction mailbox gets no push and a byte cap of its own, and a client
   holds at most 100 pending handle requests. Phase 45 replaces the stamp
   with anonymous tokens.
6. **The answer is signed by the introduction key** (§21.7): the acceptance
   carries `ia`, the introduction key's signature over the requester, the
   accepting account and the request — so the requester knows the account
   that answered is the one the handle introduced.
7. **A recovery key is committed at claim** (§21.3): `rc`, from a code shown
   once and never stored, which alone can install a new owner.
8. **Never at setup.** A claim is offered later, published after a random
   delay, and the handle log keeps hour‑granular timestamps in its entries
   (its heads say when it last grew: F5, below).
9. **v1: the root device only** holds the handle's keys and drains its
   mailbox; linked devices see the contacts it makes through self‑sync.

### Flaw → fix

| Found (analysis, 2026‑10‑03) | What E′ does | Enforced by | Left over |
|---|---|---|---|
| **F1** The log had no owner rule: with `label = H(handle)` anyone could publish v2 of `@finnian` under their own key, and mirrors check only version order — a P0 had it been built | The owner rule (§21.4): a claim fixes owner and `rc`; an update only by the current owner, changing neither; a recover only with an `rpub` that hashes to `rc` and an `rsig` over the new owner and `rc`; each entry the label's next version; 1 KiB at most; every key in a record strong and every signature held to one rule (§21.4). The owner key and the signature are in the entry | the log on the wire and on replay, mirrors (36.2); clients (`applyHandleEntry`, 36.1) — every check of the rule disabled in turn makes `handles_test.dart` fail (the strong keys and the signature rule: `ed25519_strict_test.dart` and `handle_rule_diff_test.dart`, which holds the Dart library and the log's three paths to one verdict over 128 histories), and the Node clean‑room verifier (`server/test/vectors.test.js`) re‑derives every verdict in the vectors from §21.4's text | — |
| **F2** The operator can link a handle to its owner: one connection draining both mailboxes pairs them (R21's own rule); a push token on the introduction mailbox links them at once; the KT operator sees the account key at publish | The introduction mailbox is drained on its own connection, authenticated as the introduction identity (§21.6); push registration for it is refused; the handle log is a separate service and never sees the account key | relay (37), client (38) | the same device's address on both connections, at the relay and at the log: **R49** |
| **F3** The spam bound was wrong: `NEW_MAILBOX_PER_MIN` charges only first contact, limits are per socket, the client stored every verified request; 5,000 identities cost 0.19 s | A stamp per send, checked before storing; a difficulty the owner sets; a per‑mailbox cap; 100 pending at most on the client | relay (37), client (38) | a stamp is SHA‑256, which native code and GPUs compute far faster than the app's pure Dart (measured here, one core: 46 ms at 16 bits, 0.8 s at 20, 12 s at 24) — a bound on volume, not on a determined sender, until phase 45 |
| **F4** The return leg was unspecified: the receive path drops a request addressed to an introduction mailbox (`expectedTo: myRid`), and the acceptance comes from an unrelated routing id | The request is sealed to the record's `xintro` and addressed to its `intro` routing id; the owner's app accepts a `creq` to its introduction mailboxes; the acceptance carries `ia` (§21.7), which the requester checks against the key it resolved | client (38), with `signIntroAck`/`verifyIntroAck` (36.1) | — |
| **F5** A claim at setup links the handle to the account's KT history by millisecond timestamps, reopening R20 | Never at setup; published after a random delay; hour‑granular timestamps in every entry; a separate log, so no shared run of indexes | client (38), log (36.2) | timing across many claims is a statistical hint to the operator, part of **R49**; and the log's heads are signed as it grows, so whoever polls them learns when a record arrived, to how often they poll — a recover published straight after a new account's first transparency publish is linked to it that way. Heads signed only on the hour (2026‑10‑10) would hide that at the price of serving every change up to an hour late — a recover, so the thief's mailbox keeps the handle that much longer, and a rotation away from a leaked introduction key — with no signed head behind its `201` meanwhile; not taken |
| Enumeration: SHA‑256 labels at 2.26 M a second enumerate every six‑character handle in twenty minutes | Argon2id labels, the ×100 of the digits, and buckets rather than labels on the wire | §21.2, `adr/0023` | dearer per name, not unenumerable. Measured here: 21 ms a guess on one core with a native Argon2id (127 ms in the app's pure Dart). A dictionary of 100,000 nicks × 100 two‑digit discriminators is 58 core‑hours. A census is expensive; checking whether one person has a handle is not |
| No recovery: a stolen handle key was a permanent hijack | `rc` committed at claim; the code installs a new owner and a new commitment, at the version after whatever the owner key published — each entry is the label's next, so the key's holder cannot publish one at 2⁵³ − 1 and leave the code none (until 2026‑10‑10 it could) — and a recover has a day of publishes of its own at the log, which the key's holder cannot spend | §21.3, §21.4, §21.5 | the code is the stronger secret: whoever holds it can take the handle |
| No normalisation or confusables rule (Cyrillic `fіnnіan`, `@zsupport`) | An ASCII grammar with no folding; reserved nicks refused for claim and lookup | §21.1, client | ASCII look‑alikes (`rn` for `m`, `finian` for `finnian`) are different names, as on every service; the safety number is still the check |
| Lookup privacy: resolving tells the operator who searched for whom | Bucket queries: the log learns a prefix of a label, shared with the bucket's other names | log (36.2), client (35, 38) | the address that asked: **R49** |
| The handle log must be its own instance with its own key | `KT_MODE=handles`, its own seed, `z-handle-sth-v1` and `z-handle-witness-v1`: a handle head never verifies as a KT head | 36.2 | unwitnessed until phase 19 has an operator: **R50** |
| Requests and blocks are not synced across devices, and an older build's restore drops archive records it does not know — the handle lost for good | v1 keeps the handle on the root device; its keys go in the vault and the backup archive (38); and if they are lost anyway, the code brings the handle back | 38 | lose the keys and the code together, and the handle is gone |

### The claims bill — paid in phase 38, before the release that ships handles

E′ is a directory of volunteers. Every sentence that says Z has no directory
changes first, or handles do not ship. Phase 38 changed items 1, 2 and 4 in
the repository (with the relay's privacy page, `USING_Z.md`,
`WHAT_Z_CANNOT_DO.md` and `DATA_MAP.md`); item 3 is the Play Console's, and
is made before the release that ships handles:

1. `THREAT_MODEL.md`, *Design decisions that follow from zero trust*: **"No
   accounts, no phone numbers, no directory, no key server."**
2. `adr/0008`'s **"no relay‑to‑relay protocol, no directory"**, and its
   rejection of a mailbox directory, which cites that line.
3. The Play listing's **"No phone number, no email, no username, no
   password"** and the **Data safety** form, which the console notes say must
   be updated *before* the change ships. Opt‑in does not shrink this: the form
   has a Required/Optional field, and this is a declaration either way.
4. The sentences elsewhere that repeat it — `AUDIT_SCOPE.md`'s "no directory,
   no key server", `BACKUP.md`'s "no directory", the README and the site; the
   analysis counted about twenty.
5. Already owed and not phase 38's: Play's *What's new* for 3.9.1 advertised
   handles when none existed (analysis §5.1). That is corrected in the Play
   Console now.

### Residuals — R47 to R50

Written into `THREAT_MODEL.md` by phase 38, which ships handles in the app.
Reserved as R54–R57 until then; the register ended at R46, so they were
renumbered when they were written.

- **R47** — Introduction traffic is visible. The relay, and anyone who
  resolves a handle (and so computes its mailbox), can see how much first
  contact it attracts. A pseudonym, rotatable by an update; the account's own
  mailbox stays unguessable.
- **R48** — Whoever holds a handle learns who tried to reach it. A `creq`
  carries the requester's bundle and name, so a squatter on
  `@finnianbond.07` collects everyone looking for Finnian, and in a sparse
  opt‑in namespace a squatted name looks like a real one. A two‑round opening
  that withheld the bundle until accept would limit it, at the cost of an
  owner deciding with no name in front of them — what `adr/0011` was written
  to end.
- **R49** — The operator and its CDN can link a handle to an IP address: at
  the claim and every update (the log), at every drain of the introduction
  mailbox (the relay), and at every lookup (the log — a bucket hides the
  label, not who asked).
- **R50** — The handle log is unwitnessed until phase 19 has an operator: a
  log that shows two people different records for one handle is caught only
  by a witness, as R7 says of the KT log.

Two things are not residuals because they are the design. A handle is a
**standing open inbox** — bounded by the stamp, the caps and the 72‑hour
TTL, and closed by an update with `intro: null`; it is not a bearer token,
because it confers the ability to *reach* someone, never to *be* them, and
the consent gate is the accept, as in `adr/0012`. And **erasure is
bounded**: `intro: null` stops a handle working, while the label and its
history stay, because the log is append‑only. The consent an opt‑in claim
represents improves the legal position and does not make the record
deletable. Take advice rather than designing around it.

### What Finnian may still veto, before phase 38 ships

- **The digits.** `nick.digits` rather than a bare nick: squatting pointless
  and guessing a hundred times dearer, for a name that has to be said with a
  number.
- **Proof of work until phase 45.** A CPU cost now, cheap on a GPU, replaced
  by anonymous tokens later — against no bound on introduction spam until
  then.
- **The recovery code.** A second secret to keep, shown once — against E's
  "lose the key and the name is gone for ever".
- **Running the second service.** A handle log with its own key, and in time
  its own witness.

### Open before phase 38 builds the request — settled by phase 38

Questions this revision did not answer, and how phase 38 answered them
(`PROTOCOL.md` §21.8):

- **Who picks the digits.** The app suggests two random digits, each draw
  checked free (up to five), and the person may choose 2 to 6 instead. So
  most handles have two — the ×100 — and someone who wants a rarer one can
  have it.
- **A signature per leaf in a bucket answer.** The log's leaves carry `sig`
  (36.2), and the resolver checks it — under the owner the record names, for
  a claim, an update and a recover alike — and a recover's `rsig`. The
  owner rule over the label's whole history stays the log's and its
  mirrors' to hold; a resolver keeps no head between lookups, so a log that
  shows it another history is caught by a witness only (R50).

Also settled in building it, each argued in §21.8: a claim is published at
a moment drawn from 10 to 60 minutes after it is confirmed (3 to 20 after a
start, when the moment passed while the app was closed), and a recover and
every update at once; the mailbox is drained on its own connection 3 to 30
seconds after the app comes to the foreground and every 15 minutes, give or
take a third, while it is in front; a request is sent on an anonymous
connection opened for it alone — the first build sent it on the account's
long‑lived anonymous link, which, once the request was accepted, carried the
account's envelopes to the account the handle introduced: one connection
naming both the handle's mailbox and that account, which its test
(`handle_flow_test.dart` 5) caught; at most 100 pending handle requests,
the oldest unseen dropped first; at most 20 outgoing requests kept for
matching an acknowledgement, the three latest ids each; pausing keeps the
introduction keys and resuming reuses them; giving a handle up forgets its
keys, and only the code brings it back; a claim that was pending when a
backup was made comes back from it held, not published.

One question the first draft of this revision left open is settled: the key
a request is sealed to. §8 seals to an X25519 key and the record carried
only the Ed25519 `intro`, so the record gained `xintro` — the introduction
seed's X25519 half by HKDF, right after `intro`, null exactly when `intro`
is — rather than a requester converting `intro` to an X25519 key, which
would have been a construction new to Z.

## Consequences (revision 2)

1. **A second public service** (36.2): the handle log, its key, its disk and
   in time its witness — G3's question asked again — and an operator who
   learns the addresses of claimants and resolvers (R49).
2. **Wire: additive.** A log mode, a relay frame and a send member (37), one
   optional member in a `creq` (`ia`), a new vector file. Nothing an older
   client computes changes: it never claims or resolves, and it ignores `ia`.
3. **Keys:** the owner and introduction seeds in the vault and the backup
   archive (38); the recovery code nowhere.
4. **R20 holds.** The account key never enters the handle log, and
   `adr/0006`'s rejection of VRF blinding is cited rather than reopened.
5. **Cost on the device, measured:** a label 127 ms (pure Dart, AOT, one
   core of a 2.1 GHz Xeon); a stamp 46 ms at 16 bits to 12 s at 24. Both
   off the UI thread.
6. **The claims bill and R47–R50,** above.

## Rejected

- **Plaintext handles in any public log (B).** It publishes a roster of every
  user with no compensating benefit over C.
- **A handle that resolves to the account identity (B and C).** Superseded by
  E. Any lookup that hands back enough to message someone hands back
  `accountEdPub`, and that is the KT label input — so B and C make a guessable
  name into a key R20 assumed could only be given, not found. Opt‑in does not
  change this; it only makes it consented, and consented to something the
  consent screen cannot state briefly enough to be honest.
- **Prefix or fuzzy search over names.** Any interface that answers "names
  starting with…" is an enumeration API however the storage is arranged. A
  bucket query is not one: it asks for a prefix of a *label*, a memory‑hard
  hash, and answers "the labels that share these bits", which names nobody to
  anyone who has not already paid an Argon2id per guess.
- **A server‑side password, reset or recovery.** The first version rejected
  any recovery secret on the grounds that it would be the first server‑side
  secret in the system. That reasoning stands for a secret the server holds;
  revision 2's recovery key is held by the user alone, and the log holds a
  commitment to it. No authority can reassign a name.
- **Handles as a verification signal.** A name that matches is not a key that
  matches. Safety numbers stay the only thing that catches a substituted
  exchange (`adr/0009`), and any handle UI must say so where it is read, not
  in a settings page.
- **SHA‑256 labels** (E as written): two million guesses a second.
- **Exact‑label lookups:** the operator would learn which handle each address
  resolved.
- **A claim offered at setup** (F5), and **push for introduction mailboxes**
  (F2).
- **A durable public introduction link instead** (shape F, analysis §5.3):
  cheaper, with no registry, no second witness and no claims bill — and a link
  someone must still be handed. Finnian chose handles; F stays open as a
  complement, not a replacement.

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

## Revision 2 — 2026‑10‑08

The 2026‑10‑03 analysis (§5) judged E the right direction and not buildable
as written: five flaws, the first of which would have been a P0 the day the
registry went live, and six lesser points. It listed the decisions only
Finnian could make — whether Z should be findable at all, opt‑in, the
discriminator, squatting, a recovery key, one round or two, who runs the
registry, push. He made them, with *"I need handles to have been implemented
soon"*, and they were pinned so that the library, the log and the relay
could be built at the same time against one text.

What this revision changed: the Status; the Decision and the Consequences,
rewritten for E′ with the flaw‑to‑fix table, the claims bill, the residuals
and the vetoes; the Rejected list, where the first version's refusal of any
recovery secret is narrowed to a secret the server holds; and the residual
numbers. The first version named "the next free numbers, R36 and R37" for
E's two residuals; those numbers have since gone to `adr/0018` and
`adr/0021`, and the four residuals E′ leaves are R47–R50, reserved until the
app ships them. The shapes table's pointer for the squatter now says R48.
What it kept: the Context and the shapes, which are the reasoning that chose
E and still hold.

Amended the same day, before anything was published under it: the record
gained `xintro`, so a request has a key to be sealed to; the relay's
refusal of a stamp names its own day, so a client whose clock disagrees
near midnight can re‑stamp once; and the enumeration cost is the measured
one — about 21 ms of one core per guess with a native Argon2id, so a
dictionary of 100,000 nicks × 100 discriminators is about 58 core‑hours —
where the pinned design had assumed about a second per guess. The
parameters stay: a phone has to compute a label too.

## References

- `PROTOCOL.md` §21 — the grammar, label, keys, record, owner rule, stamp
  and acknowledgement this record decides (21.0–21.4, 21.7), the handle log
  (21.5) and introduction mailboxes at the relay (21.6)
- `vectors/handles/handles.json` — every value above, re‑derived from §21
  alone by `server/test/vectors.test.js`
- `adr/0023` — lookups by bucket, for both logs
- `adr/0006` — the log, its label scheme, and the VRF blinding it rejected
  on unenumerability grounds
- `adr/0008` — federation, and the existing "no directory" decision
- `adr/0009`, `adr/0011`, `adr/0012` — how people are found and added today
- `THREAT_MODEL.md` R20 (publish history), R21 (the address of a sealed
  sender), R7 (an unwitnessed log), and the design‑decisions list
- `PROTOCOL.md` §19.1 — `label = SHA‑256(utf8("z-kt-label-v1:") ‖ accountEdPub)`
- `protocol/lib/src/handles.dart` — the protocol half, built (36.1)
- `protocol/lib/src/connect_relay.dart` — the throwaway‑mailbox primitive E
  makes durable: "two throwaway relay identities HKDF'd from the invite
  secret, one per role"
- `protocol/lib/src/contact_request.dart` — the `creq` E′ reuses unchanged,
  and the bundle disclosure R48 is about
- `GA_CHECKLIST.md` G3 — the witness a second log would also want
