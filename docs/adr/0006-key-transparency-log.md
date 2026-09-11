# ADR 0006 — The public transparency log (7.7b)

**Status:** Accepted (2026‑09‑11) · **Roadmap:** 11.1–11.5 · **Builds on:**
ADR 0001 (gossip first, log later) · **Decides:** what the log commits to,
how it is read and written, what a client does with each answer it can get,
and what "key transparency live" (GA criterion G3) means precisely enough to
be ticked.

## Context

ADR 0001 made device‑list transparency detectable with no infrastructure:
every message carries the sender's claim about its own device list and an
echo of the newest list it holds for the recipient, and the parties who
already receive a list cross‑check what they were told (PROTOCOL.md §3.6).
That catches a rogue enrolment or a split view **among the parties who talk
to each other**. What it cannot catch is a split view that never crosses a
conversation the victim is part of — a rogue‑inclusive list handed to one
contact who never mentions it — and it gives the owner no record to consult
after the fact. 0001 deferred the fix, a public append‑only log, until "a
public launch with an operator committed to durable infrastructure", and
`GA_CHECKLIST.md` recorded the resulting circularity: 1.0 requires the log,
the log's trigger was 1.0.

The circularity is resolved by decision, in the direction of running the
log: G3 is an objective of this phase, not a question left to the release.
This record is the design that follows from that, and it inherits 0001's
constraints unchanged — the log is **a second source of the same (version,
fingerprint) facts 7.7a already gossips**, so adding it changes nothing on
the wire between contacts except the proofs; the relay stays RAM‑only and
learns nothing new; and the cost 0001 named — *the operator learns which
accounts exist and when their device sets change* — is accepted, bounded
below, and not hidden.

## Decision

### What is logged

One entry per published signed device list (§3.4):

```
label     = SHA-256("z-kt-label-v1:" || accountEdPub)                      32 bytes
version   = the list's version                                              u64
fp        = SHA-256(signingInput(version, devices))[0..16]                  §3.6, 16 bytes
value     = nonce || ChaCha20-Poly1305(vk, nonce, aad = label, listJSON)   the list itself, sealed
vk        = HKDF-SHA256(ikm = accountEdPub, salt = "z-kt-value-v1", info = "value", 32)
ts        = the log's clock when it accepted the entry, ms                  u64

leafInput = "z-kt-leaf-v1:" || label || u64be(version) || fp || SHA-256(value) || u64be(ts)
```

The **fingerprint is the commitment** — the same sixteen bytes 7.7a gossips,
so a contact who holds a list in‑band and reads the log compares two values
it already has. The **value** is there so the log can be a *source* of
lists, not only a check on them (11.5): a contact whose in‑band copy is
behind fetches the entry, opens it, verifies the account's signature over
the list with the code it already has, and installs it. Sealing it under a
key derived from the account's *public* key means exactly the parties who
could verify the list can read it — its contacts, and the operator, who
learns the public key at publish time anyway — while a mirror, a witness or
anyone reading the log sees labels and ciphertext.

### Two trees, one head

The log is an RFC 9162 Merkle tree over the leaf inputs (append‑only,
inclusion and consistency proofs exactly as Certificate Transparency
defines them; the certificate‑transparency‑go reference vectors are
reproduced in `docs/vectors/kt/log_tree.json`), **and** a sparse Merkle map
from label to `(index of the latest entry, its version)`. Every signed tree
head commits to both roots:

```
sthInput = "z-kt-sth-v1:" || u64be(size) || logRoot || mapRoot || u64be(ts)
sig      = Ed25519(logKey, sthInput)
```

The map is what makes "latest" a proof rather than a claim. With a log tree
alone, an entry from last year has a perfectly valid inclusion proof today;
a log could show one contact the old list and another the new one, each
with a proof that verifies. Under one head, the map root pins one `(index,
version)` per label, so two clients holding the same head must be shown the
same latest entry or a proof fails — and the consistency proof between two
heads shows the log tree only grew, so the head itself cannot be quietly
replaced. The alternative — a single prefix tree with versioned keys, as the
IETF Key Transparency drafts use — gives the same guarantees with a more
involved verifier; two textbook structures were chosen over one clever one
because the verifier is the part a phone runs and a third party re‑implements.

A map proof is the 256 siblings along the label's path, compressed to a
32‑byte bitmap of the non‑empty ones plus those siblings. Measured
(`kt/bench/proofs.js`): a lookup — head, map proof, entry with its sealed
value, inclusion proof — is **3.7 KB at a thousand labels, 4.0 KB at ten
thousand, 4.3 KB at a hundred thousand**, of which the sealed list itself
is 2.2 KB; the map proof carries 10, 14 and 17 siblings respectively, the
inclusion path 10, 12 and 16. Verifying one is 256 + ~20 SHA‑256
computations and one Ed25519 verification.

### Publishing

```
POST /kt/v1/publish  { acct, v, fp, value, sig }
sig = Ed25519(accountSeed, "z-kt-publish-v1:" || label || u64be(v) || fp || SHA-256(value))
```

The log verifies the signature against `acct`, requires `v` to exceed the
version it holds for the label (the first entry may carry any version, since
an account that reached version 7 before the log existed publishes 7), and
keeps `acct` in its own store but never serves it. It does **not** open the
value or check that it matches `(v, fp)`: only the account key can publish
under a label, so a value that disagrees with its own fingerprint is a lie
the account told about itself, detectable by every reader who can open it
and harmful to nobody else; checking it would put the device‑list format
into the log for no security. Publishes are rate‑limited per source address
and bounded in size; there is no other admission control, because the label
space cannot be squatted — a publish is a signature by the key the label is
derived from.

### Heads, freshness and witnesses

A head is re‑signed when the log grows and, otherwise, when the last one is
ten minutes old, so a client can require a recent timestamp and tell a log
that has been *frozen* — kept serving one old head to hide a rewrite — from
one that is quiet. A head older than **24 hours** is treated as unreachable
(below), not as a fault: a stale clock is not an attack, and an attacker who
can freeze the log for a day can more simply block it.

A **mirror** (`kt/tools/mirror.js`) keeps a full copy and, on every sync,
verifies the head's signature, that it extends the last head it verified
(same size ⇒ same roots; larger ⇒ a consistency proof that verifies;
smaller ⇒ a log that shrank), fetches the new entries and re‑derives **both
roots** from them. Any failure is a divergence: it keeps the old head,
writes nothing, and exits non‑zero. A mirror that co‑signs the heads it
verified (`"z-kt-witness-v1:" || sthInput`) and serves `sth.json` from any
static host is a **witness**; a client configured with one checks the log's
head against it and treats disagreement as a log fault. Alternatives
rejected: gossip of heads between clients through the ratchet (an extra
~150 bytes on every message, to reach a fraction of the assurance one
independent witness gives), and third‑party or blockchain anchoring (0001,
option D — a dependency for a guarantee a mirror gives more simply).

### What a client does with each answer

The client keeps its last verified head and, per contact account, the
log's latest `(v_log, fp_log)` under that head beside the in‑band list
`(v_ib, fp_ib)` it verified through §3.4/§3.6. On every check — at start,
every six hours, and on receiving a new list — it fetches a head, verifies
the signature and the consistency proof from the head it holds, checks the
witness if one is configured, and only then reads proofs. The states, and
what each costs the user:

| state | when | what happens |
|---|---|---|
| **unlogged** | absence proof verifies | as before the log: gossip only. A quiet note on the contact screen ("not in the transparency log"); a contact on an older client, or one that has never been online since upgrading |
| **confirmed** | `v_log = v_ib`, `fp_log = fp_ib` | nothing to show |
| **log ahead** | `v_log > v_ib` | fetch the entry, open the value, verify the list (§3.4), require its fingerprint to equal `fp_log`, install it — the log is a source (11.5). A value that does not open or verify is a **conflict** |
| **unconfirmed** | `v_ib > v_log` (or unlogged with `v_ib > 1`) for longer than the **grace period, 24 h** from receipt of the in‑band list | devices that appear **only** in the unconfirmed list stop receiving messages; devices it removed stay removed; the banner says which list is unconfirmed. This is T2 made to cost the attacker something: a rogue device enrolled by a list that never reaches the log goes quiet after a day |
| **conflict** | same `v`, different `fp`; a log entry whose list does not verify; a log history containing a version the contact's own devices claimed with a different fingerprint | **sends are held**, with the reason, until the next check agrees or the user chooses to send anyway. The hard fail 0001 asked for, applied to the one case that is unambiguously either an attack on that account or a log serving lies about it |
| **log fault** | a head that does not verify, or does not extend the held one, or disagrees with the witness, or a proof under a good head that fails | trust freezes at the last good head: nothing new is confirmed, sends to already‑confirmed device sets continue, and a persistent alert names the fault with the two heads for reporting. The log cannot make the client trust anything new, and cannot stop what was already verified — it is not a kill switch |
| **unreachable** | no head within 24 h | sends continue on in‑band verification exactly as before the log; a banner after 24 h says the log has not been reachable since when. The grace period runs regardless: a contact's list that cannot be confirmed for a day is unconfirmed, whether because the account never published or because the log could not be asked — the client cannot tell those apart, and an attacker who could block the log for one victim must not be able to keep a rogue device alive by doing so |

**Self‑monitoring.** Every check also fetches the client's own label's
history. Any entry whose `(v, fp)` this device neither published nor
learned by self‑sync (§9) is the T1/T2 signal, surfaced loudly: *a device
list you did not issue has been published for your account.* This is what
the log adds over 7.7a's owner rule — a record the attacker cannot keep from
the owner by choosing who to send to.

**Publishing** happens on every list change, from the device that issued
the list, through a durable queue retried until the log acknowledges it, and
once on first run after upgrading when the log holds nothing or an older
version for the account (11.5). A list is *not* withheld from contacts
until the log acknowledges it — in‑band delivery is unchanged and the log
catches up within the grace period.

### Operating it, and what "live" means

The log is a separate service (`kt/`), not the relay: plain Node, no
dependencies, an append‑only entries file fsynced per publish and replayed
on start (a Postgres store is a deployment option, not a design change), a
signing key from the environment. It is deployed behind TLS at
`kt.zmessengers.com`, its public key is **shipped in the client** and shown
on the log's own `/kt/v1/pub` only for a first look, never as the pin. One
independent mirror, run by someone who is not the log's operator, publishes
`sth.json` as the witness the client is configured with.

**G3 is ✅ when all of the following hold:** the service is reachable at
its URL over TLS; the client release pins its public key and is configured
with the witness URL; the mirror has run against it and verified at least one
head; and the app's own published list appears in it. `SELF_HOSTING.md`
"Running the transparency log" is the runbook; each of those four is a
line in it.

## Considered and rejected

**VRF‑blinded labels** (0001 named them as the metadata mitigation). A
verifiable random function keyed by the operator makes labels unguessable to
readers of the log, which matters when identifiers are guessable — a phone
number directory can be walked. Z's identifiers are 256‑bit random public
keys: nobody can enumerate labels, and the only party who can map a public
key to a label is someone who already holds that key — the account's
contacts, who learn nothing from the log they were not already told
in‑band, and the operator, who learns the key at publish. A VRF would hide
labels from the operator's *readers* at the cost of a proof in every lookup
and a second key to protect, for a threat that reduces to "someone who has
your contact code can see when your device set changed", which is recorded
as residual (R20) rather than engineered away.

**Storing the list in clear.** Simpler, and it would make the log a
directory. Rejected: 0001's accepted cost is that the *operator* learns
which accounts exist; a public log of device keys would hand every reader
each account's device count and rotation history, which is more than
7.7a ever disclosed to anyone.

**Log‑only, with clients auditing the whole log** (Certificate Transparency's
model). The map is what makes "latest" provable in one lookup; without it a
client must scan every entry for its contacts' labels, which does not fit a
phone, or trust the log's answer to "what is the latest", which is the
question the log exists to answer without being trusted.

**Blocking all sends on any log failure.** The strongest reading of
hard‑fail, rejected because it makes the log operator, or anyone who can
block the log for a victim, a kill switch for the messenger. The chosen
behaviour blocks exactly the thing a transparency failure is evidence
about — a device set that could not be confirmed — and nothing else.

## Consequences

* A fourth document is normative: PROTOCOL.md §19 specifies the log, its
  proofs and its API, pinned by `docs/vectors/kt/` and two verifiers with no
  shared code (`kt/test/vectors.test.js`, `kt/tools/verify_vectors.py`).
* The client gains a network dependency it did not have: an HTTPS endpoint
  besides the relay. It fails safe in both directions described above and
  is configurable (Settings › Transparency log: URL, pinned key, witness),
  so a self‑hoster runs their own or none.
* New residual‑risk rows: the operator learns account public keys and change
  times (0001's accepted cost, now with the log built); anyone holding a
  contact code can read that account's publish history from a mirror (R20);
  a rogue device enrolled by an unpublished list has the grace period before
  it goes quiet.
* `GA_CHECKLIST.md` G3 changes from "needs a decision" to the four‑line
  definition above, and `tool/check_ga.py` checks that the client's pin is
  not a placeholder before the row may read ✅.
* `THREAT_MODEL.md` T1–T3 gain the log as a second detector; T4 and T5 are
  unchanged (a reset is a new label; an exchange the attacker controls is
  out of scope for any log).

## References

* ADR 0001 — the threats, the gossip design, the deferral this record ends.
* RFC 9162 (Certificate Transparency 2.0), §2.1 — the log tree, transcribed.
* IETF Key Transparency architecture draft — the prefix‑tree alternative and
  the monitoring model.
* PROTOCOL.md §3.4 (signed device list), §3.6 (fingerprint and gossip),
  §19 (this log).
* `kt/` — the service, mirror, bench and vectors generator.
