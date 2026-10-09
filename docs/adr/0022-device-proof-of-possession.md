# ADR 0022 — A device certificate proves its device holds the key it names

**Status:** **Accepted** (2026‑10‑09) — built (18.7, unreleased). Amends §3.1,
§3.4 and §9; closes, for a device that has proved itself, the first‑come case
patch 41 left open.
**Decides:** how a device shows that it — and not only an account — puts it
in that account; what a receiver does with that proof; how a device linked
before it gets one into its account's list; what covers its X25519 key; and
what a reader from before it makes of it.

## Context

A device certificate (§3.1) is the account's Ed25519 signature over a
device's two public keys and its id. It proves that the ACCOUNT signed it, not
that whoever holds the account holds the device key it names: an account signs
whatever public keys it is handed. So any contact can put another person's
device in a list of their own — the keys are in that person's code, in their
own account's list, in a group's member list — and the 3 October analysis (P1‑4)
reproduced what that buys: the device's routing id taken over at the receiver,
its messages decrypted against the claimant's account and dropped or filed
under the claimant's name, and envelopes sealed to it sealed beside a key of
the claimant's choosing, which a relay in league with the claimant can hand
to the claimant to read the sealed sender off.

Patch 41 (3.9.10, `794eaf5`) made a receiver refuse a list naming a device it
already holds for another account. What it could not do is tell who was right
when nothing was held yet, and it said so: it is **first come**. A claim that
reaches a receiver before the real owner's list takes the device there, and the
owner's list, arriving second, is the one refused. A claim arrives first
whenever the owner's list is late — a relay can hold it, since it cannot read
it but can delay it — whenever the receiver adds the owner after the claim
reached it, and on a linked device of the receiver's own that learns a sibling
device from its root's list after the claim.

## What was rejected

* **The account signing for its devices.** The party a receiver cannot trust
  here is an account: a claimant's root signs whatever it is handed. A second
  statement by the account adds nothing. Only the device can say which account
  it is in, and only the device key can sign it.
* **A new certificate format, or the proof inside the list's signatures.**
  Every signing input a list has is over fields fixed before this (ADR 0010,
  ADR 0017); widening one is a new input, a new version and a migration of the
  log's history, for nothing: the proof is its own signature and needs no
  cover. The one thing anyone who passes a list on can do to it is take it off,
  and a receiver that has seen it refuses the list without it (rule 2 below).
* **Proving possession of the X25519 key.** A static‑static Diffie–Hellman MAC
  convinces only the party whose key it is computed with: to the account's own
  key it proves the device to the account, the party in question; to each
  contact it is per‑recipient state in a certificate everyone reads. A
  signature BY the X25519 key (XEdDSA) needs Montgomery‑to‑Edwards arithmetic
  the library does not expose — hand‑written curve code in the trusted base —
  and buys nothing for routing (below).
* **Requiring a proof.** Every device linked before this release, and every
  device whose account's root predates it, would be refused: a flag day.
* **A new list version for each proof.** A proof changes no signature and no
  fingerprint, so the version a root already published, signed again, carries
  it. A new version per proof is an extra list, an extra log entry and an
  extra moment of churn for every account with a linked device, for what the
  next re‑send carries anyway (rule 4).
* **The proof inside the pairing frames** (§10.1). A frozen ceremony changed
  to save one self‑sync message; the device hands its proof over as a migrated
  one does.
* **The proof inside contact codes.** About 120 characters more in a linked
  device's QR (ADR 0027 measured what that costs), for what the code already
  says: its binding signature is the device key over its X25519 key (§2.3),
  and its `pqcs` (ADR 0027) is the device key over the account's key.

## Decision

**1. The proof.** A certificate gains an optional member (§3.1):

```
pop      = Ed25519.Sign(device_ed_sk, input)                64 bytes, base64
input    = utf8("z-device-pop-v1:") || account_ed (32) || device_ed (32)
           || device_x (32) || utf8(device_id)
```

No other input any key in the protocol signs begins `z-device-pop-`. A
present `pop` must be a base64 string and verify under the device's own key;
one that does not fails the certificate, and the list or `zc2.` code carrying
it. A certificate **proves possession** for an account when it verifies and
either its key IS the account key — device #1, a `legacy` record, whose `sig`
is already the device key's own signature — or it carries `pop`.

**2. The X25519 key is bound, not proven.** The proof covers it under the
device's Ed25519 key, so nobody but the holder of that key can put any X25519
key beside it under a proof. Possession of the X25519 secret is not shown, and
need not be: what a claim takes over is the routing id and the mailbox, which
are the Ed25519 key's (§2.2, §12.1); and every session binds both devices'
Ed25519 keys in its `AD` (§4, §9), so a certificate pairing someone else's
X25519 key with one's own Ed25519 key names a device nobody can talk to — the
holder of the X25519 key computes another `AD` and cannot open what is sent
there, and the claimant cannot complete a session without the secret. That
harms only the account that signed it. Possession of the X25519 key is
shown by use, in every session that advances.

**3. What a receiver does** (§3.4). It records, for every device a list or a
contact's code proves, the account it proved itself in; the first proof
stands. Then:

* a list from any OTHER account naming that device is refused whole, held or
  not; the claimant's chat says the device has proved it belongs to the other
  contact's account, naming both — unlike patch 41's banner it knows which
  list is wrong;
* once a list from the account itself has carried the device's proof, a list
  from it naming the device without one is refused — the member taken off by
  whoever passed the list on (the log's operator can open a value and seal it
  again, §19.1), or a certificate re‑signed over another ratchet key under the
  old proof, which does not cover it. Silent in‑band, as the signature floor
  is; a conflict from the log. A proof seen only in a contact's code does not
  start this rule, because it shows what the device's build makes, not that
  the account's root carries proofs;
* a list that proves a device another account's list holds by first come
  alone takes it, and the other list is withdrawn — whole, its devices no
  longer that contact's, what was queued for them not delivered, no removal
  notice (nothing that account signed removed them). Its row stays in the
  vault, and the first rule refuses it at every start;
* adding a contact from an account‑anchored code (§18.7) whose device proves
  the account it names — its certificate carries `pop`, or the code signs its
  post‑quantum commitment (ADR 0027), the device key's signature over the
  account key — takes the device back likewise. A code that names no account
  proves nothing: every identity makes a binding signature, a linked device on
  a build before §18.7 hands out such a code for its own key, and anyone can
  present one again — so it cannot tell a phone from somebody's linked device,
  which a list can, since there the account key signed its own device's
  certificate;
* a code naming the device for another account is refused at the scan, and
  a contact one of the receiver's own devices added from such a code is not
  taken in from self‑sync — the certificate in a code is the account's,
  signed over whatever keys it was handed, as a list's is. A contact added
  from one BEFORE the proof arrived stays, and its device with it: its record
  is the device's routing id, and a list does not move a contact the user
  added;
* the receiver's own account's list is the authority on its own devices,
  proof or not: a contact's claim on one of them, made before the receiver
  knew it, is withdrawn when its own list names it;
* a device that has proved nothing is held to patch 41, first come.

What was proven is kept sealed (`dev_pop`) for as long as a contact record of
the account is held, and forgotten with the last one, so a deleted contact's
routing ids do not outlive them. It is not in a backup; the lists a backup
carries carry their proofs, and the start‑up load rebuilds it from them.

**4. Migration: the device hands its proof to its root.** The root cannot
make one for another device. A linked device whose account's list names it
without a proof — every device linked before this, at its first start on a
build with it; a device linked since, when the root's first list naming it
arrives; any device after a restored root's list lost it — sends its proof
over the self‑sync channel (§9, `dir:"pop"`, an inner of kind `devpop`), once
per list version. The root keeps it beside the certificate it holds for the
SENDING device, if it verifies for that certificate and the account, and puts
it in every list it signs from then on — the version it has already
published included, signed again with the same signatures and fingerprint,
which the log already holds and is not asked for again. Nothing is broadcast
for it. It reaches a receiver with the next list the root hands that receiver:
a new contact's hello; a re‑send to a contact whose echo is behind — among
them every receiver that refused the account's list because a claim held the
device first, whose next message to the account brings the list back,
proving; a re‑assertion to the account's own devices, whose copy is what a
linked device hands a contact added from it; and every contact at the
account's next version.

**5. No flag day.** A reader that predates the member reads only the members
it knows: it admits a list carrying proofs exactly as it admits the same list
without, with the same fingerprint, and re‑serialises it without them —
checked with the parsers of `0d00a69`, of 3.9.1 (the build Play serves) and of
3.5.7 run over `v1/device_pop.json`. A reader that knows it enforces it only
as above: a device with no proof is first come, as it was.

## How long the first‑come window stays open

* **For a device that has proved itself**, at a given receiver: until that
  receiver installs a list from the account carrying the proof, or adds the
  owner from a code that proves it. Until then a claim that arrived first
  holds the device, as before — but no longer for good: the first list carrying
  the proof that reaches the receiver withdraws it. The proof reaches the root
  at the device's first start on this build (one self‑sync message through the
  outbox, delivered when both are online), and a receiver with the next list the
  root hands it (rule 4) — for a receiver that refused the owner's list, on its
  next message to the account, at most once a minute (the re‑send's cooldown).
* **For an account whose devices are old**: for each device that makes no
  proof, the window never closes — patch 41's rule, unchanged — until that
  device runs a build with this, AND the account's root does (a root from
  before it drops the member and never carries it). The exception is device
  #1: its certificate is its own key's signature, so a receiver on this build
  holds any account's phone proven from that account's list, whatever build
  the account runs. (Not from its code alone, which cannot tell a phone from a
  linked device; an account with no linked device sends no list, and a claim
  on its phone that reaches a receiver before it is added stays first come.)
* **What the user sees.** Nothing for the migration. On a claimant's chat, the
  new banner, naming whose the device proved to be. For a device that has
  proved nothing, patch 41's banner, naming both and accusing neither.

## Consequences

* **Lists grow by the proofs**: 97 bytes of list JSON for each linked device
  whose proof the root holds (measured: a dual‑signed list with one linked
  device from 715 to 812 bytes, with five from 1 611 to 2 096).
* **An account with two roots, one old**, has lists with and without proofs;
  a receiver that has seen a proof refuses the old root's lists, as the
  signature floor refuses an old signer's (ADR 0017).
* **A root restored from an archive taken before a device's proof reached it**
  signs lists without it, which receivers that saw the proof refuse until the
  device sees its account's list without its proof and sends it again.
* **A device that passes a list on from a build before this** strips the
  proofs; a receiver that saw them refuses that copy and keeps the one it
  holds.
* **Codes are unchanged**, and so are pairing, the relay and the log.
* **Wire:** one optional certificate member and one self‑sync `dir` (§14).
  Every existing vector file is byte‑identical; `v1/device_pop.json` is new,
  reproduced by `protocol/tool/vectors.dart` and re‑derived by the clean‑room
  verifier in `server/test/vectors.test.js`, which also reads it as a reader
  from before the member does.
* **What remains**, in `THREAT_MODEL.md`'s row for a contact: devices that
  have proved nothing are first come — among them the phone of an account
  with no linked device, which sends no list to prove it, when a claim on it
  reaches a receiver before the receiver adds it; a contact added from a code
  that named the device for another account, scanned before the device's
  proof reached the receiver, keeps it (rule 3); a device whose holder signs
  proofs for two accounts is the first's. And "never accepted for another
  account" lasts as long as the receiver keeps a contact record of the
  account: what was proven goes with the last one (rule 3), as everything
  naming a deleted contact does, and a claim on their devices is then first
  come again, as it was before they were added.

## Exit criteria

`app/test/device_pop_test.dart` (9 — through the real relay: a claim on a
contact's linked device that arrived first, withdrawn when the device's proof
arrives — shown keeping the device on `0d00a69`; the same for a device of the
receiver's own; a device linked before proofs handing its own to its root, and
the account's next list carrying it; a device that never proves still listed,
heard and reached; patch 41 holding for such a device; a proven device refused
in another account's list, held or dropped, in English and Spanish, and in a
code naming it for another account; a proof
taken off, or a ratchet key swapped under it, refused in‑band and from the
log; what was proven surviving a restart and going with the account; and a
claim on someone's linked device, made before they were a contact, given up
when they are added from that device's code, which signs their account) and
`protocol/test/device_cert_pop_test.dart` (7).
