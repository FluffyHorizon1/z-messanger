# ADR 0033 — Post-quantum for the classical surfaces (44)

**Status:** **Accepted** (2026‑10‑17), with addendum A below, accepted the
same day. Proposed 2026‑10‑16; Finnian's decisions of 2026‑10‑17 answer its
six open questions — folded into the text where it asked them, and listed
under "Decisions" — and addendum A's. Phase 44; takes up ADR 0031's "one
residual". Adds PROTOCOL §8.2, §10.2, §18.11, §20.9; amends §8.1, §12.1,
§18.2, §21.3; extends ADR 0003, 0007 and 0024. Updates R2, R4, R5, R17, R43,
and adds a register row for each classical surface that remains as its part
lands.
**Built:** 44.2 — the relay treats `zs2.` as sealed (PROTOCOL §12.1); 44.9 —
the introduction key in the protocol library, `sk` in contact codes and the
relay client's frames, with their vectors (§8.3, `vectors/intro-key/`);
44.10 — the relay keeps introduction keys (§12.7). Nothing a client sends has
changed: no client seals `zs2.` before 44.7, which waits for constant‑time
ML‑KEM upstream, and none publishes, fetches or emits an introduction key or
`sk` before 44.11–44.12. The rest of the build plan below is not built.
**Decides:** for each surface the 3 October analysis (§4.3) found classical —
pairing enrolment, CONNECT, the sealed outer layer, contact requests, the
device a scanned code names, session authentication — what becomes hybrid, on
what wire and at what size, how a stripped post-quantum half shows, and what
stays classical and why.

## Context

Every message after a conversation's first round trip is mixed with
ML-KEM-768 (§17). Everything else rests on X25519 and Ed25519 (THREAT_MODEL,
"The quantum layer's edges"). What a recording yields to whoever later holds
a quantum computer (CRQC) — the relay's operator, or Cloudflare in front of it
(R44):

| Surface | A recording yields | Protected by |
|---|---|---|
| Pairing enrolment (§10.1) | the account's contacts: keys, device lists, names, who was verified | `HKDF(dh)` of two X25519 ephemerals |
| CONNECT (§20.8) | both codes and names | X25519, salted with an 80-bit invite secret whose carrier the ceremony assumes hostile |
| Sealed outer layer (§8) | who sent each envelope | X25519 to the device's static key |
| Contact request (§8.1) | requester, name, target | the same, before any session exists |

Authentication is classical too (§4; so is Signal's PQXDH). The sharpest case
is the scanned code (R4, ADR 0031). An adversary who forges Ed25519 and
controls a code exchange keeps the victim's account key and commitment,
substitutes the device's keys, forges `sig`/`cert`, and relays the victim's
ML-DSA public key — sent in-band to every contact, so not secret. It matches
the commitment, the contact reaches `hybrid`, and **both people read the
genuine safety number**, which covers account keys only. For a one-device
account nothing post-quantum covers the ratchet key at all: its lists stay
dual-signed (ADR 0029 never moves it), `mlsig` over the v1 input.
WHAT_Z_CANNOT_DO's "cannot be forged unnoticed, now or later" is not yet true
of that device.

Constraints: v1 frozen; additive, versioned change (§14); no new trusted
party; sealed sender and the buckets intact (ADR 0003/0004); a stripped
post-quantum half never silent.

## Decision

### 1. Every device: a sealing key, and its account's attestation

```
sealKey = ML-KEM-768 pair from a 64-byte seed; one per device, for the device's life, like its X25519 key
pqdc    = ML-DSA-65.Sign(account_ml_sk,
            utf8("z-device-pq-v1:") || acct || ded || dx || SHA-256(sealEk))        fixed width
```

* The seed is sealed in the vault and carried in the archive: a restore that
  drew a new one would leave contacts sealing to a key nobody holds.
* A device announces its key — inner kind `pqseal {alg, ek}` — to every
  device it has a session with, on a mixed (`pq:1`) message, riding its next
  message to each rather than in a burst, repeated on §17.4's clock (bounded
  as `pqid` re-sends are) until the receiver stamps `pqs:1` ("I hold your
  sealing key") on what it sends, like `pqh`. A 4 096-bucket envelope, as
  every `pqek` offer is.
* The root alone holds the ML-DSA seed and signs every `pqdc`: its own at
  first start; a new device's in pairing v3 (§3); an earlier-linked device's
  over self-sync (`dir:"pqdc"`: the device sends its `pqseal`, the root
  answers if its list names that `ded`/`dx`).
* A device sends its `pqdc` as an optional member of its own `pqid` (§18.2):
  3 309 bytes inside the 16 384-bucket envelope `pqid` already is (≈7.1 KB of
  the ≈9 KB of inner message that bucket holds) — **no new envelope, no new
  size**. Contacts that already hold its key get `pqid` once more, spread over
  hours as `dlpq` is (§18.9).
* Per device, never in a list or a code: it says one device belongs, not what
  the set is, so ADR 0004's subset and bucket objections — why ADR 0031
  retired the per-certificate form — do not apply. A list that omits the
  device prevails.

### 2. The scanned device

For the device a contact was added from — scanned, pasted, or an accepted
request — a receiver holding the contact's ML-DSA key **established**
(commitment matched, or number confirmed, ADR 0021) checks `pqdc` over that
device's `acct`, `ed`, `x` and `pqseal` (held until both have arrived).
Verifies: the device link is post-quantum. Fails: refused, recorded and
announced once, as a key that misses its commitment is (§18.3). Absent: the
link is **classical**, and the contact's screen says so beside the number.

The attacker above *is* the scanned device, so no in-band claim can expose an
omission. What holds is that the app never shows "post-quantum, verified"
without the attestation: Finnian's decision of 2026‑10‑17 is that the device
link is **required** for "post-quantum, verified" for contacts added from the
release that builds this, and **shown** for the rest. The QR does not change.

### 3. Pairing v3 (§10.2)

```
pairKey    = HKDF(secret, ∅, "z-pair-key-v3", 32)
commit-v3  N→E { c = HMAC(pairKey, "z-pair-commit-v3:" || ephN || ded || dx || SHA-256(ekN) || sk || id), ek: ekN }
reply-v3   E→N { ephx: ephE, ct }               (ct, K) = Encaps(ekN)
open-v3    N→E { ephx, ded, dx, sk, id }         sk = SHA-256(sealEkN)
channelKey = HKDF(dh || K, pairKey, "z-pair-channel-v3", 32)
SAS        = 8 digits of HKDF(dh || K, ephN || ephE, "z-pair-sas-v3" || ded || dx || sk || id || SHA-256(ekN || ct))
enroll-v3  = §10's enrolment + { "pqdc" }
```

* **The digits cover `K`.** Otherwise an adversary breaking X25519 live passes
  the ephemerals through, swaps only the KEM, reads the enrolment, and both
  screens agree.
* **The side that commits offers the KEM key; the other encapsulates.** Eight
  digits defeat a machine in the middle only because whoever contributes last
  committed first. Were the existing device to offer, whoever speaks for the
  new one would pick its encapsulation randomness after seeing everything and
  grind ≈10⁸ encapsulations — a day on one core in Dart, minutes on a few
  cores natively — to digits already read aloud.
* The code is bound into the keys, as §20.8 bound the invite: a relay without
  it runs neither leg. Defence in depth only — 80 bits, with the rendezvous id
  as an oracle, is no long-term secret.
* As §10.1 rule 4: v3 transacts only on v3 mailboxes, recognises a v2 peer and
  says "update the other device". No fallback.
* Enrolment still never carries `root`; if it ever does, the ML-DSA seed must
  travel with it.

### 4. CONNECT version 3 (§20.9)

```
inviteKey3 = HKDF(secret, "", "z-connect-invite-v3", 32)        marker "8": every older parser refuses it
x1 { k, c, ek }        the inviter's fresh ML-KEM key; each keyed commitment also covers SHA-256 of its side's KEM value
x2 { k, ephx, c, ct }  (ct, K) = Encaps(ek), by the acceptor
channelKey = HKDF(dh || K, inviteKey3, "z-connect-channel-v3")
okm (20.4) = HKDF(dh || K, ephLo || ephHi, "z-connect-sas-v3" || lo… || hi… || SHA-256(ek || ct), 8)
reveal    += { "pqk": the ML-DSA key (required with pqc), "pqseal" }
mailboxes  = "z-connect-relay-v3:" || role
```

The same ordering, and the digits cover `K` for §3's reason: the inviter
commits and offers in x1; the acceptor encapsulates before `ephI` is revealed.
On a confirmed comparison the reveal is as authentic as the digits, so the
device link is post-quantum without `pqdc`, the contact needs no `pqid` (one
fewer R17 pair), and its first envelope is `zs2.` (§5). The rest of
§20.3–§20.8 stands; the go-ahead tag now derives from a hybrid key. The
version rides in the invite, out of the relay's reach; a v3 invite never runs
as v2 (ADR 0024). Frames stay unpadded (§20.5) and grow — x1 and x2 ≈1.6 KB,
x3 and x4 ≈6.3 KB against today's 654-byte x3 — so the relay can tell a v3
ceremony (R24).

CONNECT v3 is **the post-quantum way to add someone**: remotely, or in person
by scanning the invite's QR and comparing the digits there.

It is minted a release after the release that reads it (Finnian's decision of
2026‑10‑17): the readers ship first (44.6), so an older acceptor is never
handed an invite it cannot open, and `connectInviteVersion` moves to 3 in the
release after.

### 5. The sealed outer layer: `zs2.` (§8.2)

```
(ct, K)  = ML-KEM-768.Encaps(recipient's sealEk); eph = fresh X25519 pair        per envelope
key      = HKDF(X25519(eph, recipientXPub) || K, ∅, "z-sealed-v2" || ephPub || recipientXPub || SHA-256(ct), 32)
envelope = "zs2." || b64url(ephPub(32) || ct(1088) || nonce(12) || box || mac(16))   box: §8's padding, unchanged
```

A sender MUST use `zs2.` for every envelope to a device whose sealing key it
holds, attachment chunks included. **As addendum A changes it:** a sender
that holds none fetches the device's introduction key from its relay first
(A3), and seals `zs1.` only where A4 says a key is missing and its route
allows it. The KEM ciphertext sits outside the padding, so **the bucket a
message lands in does not change and every `zs2.` envelope of a bucket has one
length**:

| Bucket | `zs1.` (wire characters) | `zs2.` |
|---|---|---|
| 1 024 | 1 450 | 2 900 (×2.0) |
| 4 096 | 5 546 | 6 996 (+26 %) |
| 16 384 | 21 930 | 23 380 (+7 %) |
| 65 536 · 262 144 | 87 466 · 349 610 | +1.7 % · +0.4 % |

The commonest envelope doubles: a queued short text costs ≈3.2 KB of relay
RAM or ≈3.7 KB of Redis instead of ≈1.75/1.96 KB (`CAPACITY.md`), so 192 MiB
refuses at ≈64 000 of them instead of ≈118 000. Sealing costs +0.8 ms and
opening +1.7 ms (AOT; ≈1.5 ms today, `PERFORMANCE.md`). Finnian's decision of
2026‑10‑17: **accepted, and the stores sized ×2** — `CAPACITY.md` and both
Blueprints' store sizes double before `zs2.` is switched on, the Blueprints
being his to change.

* **Relay.** `zs2.` is accepted on anonymous connections as `zs1.` is
  (§12.1): no `from`, no `delivered`. Roll the relay out first, and never send
  `zs2.` on the authenticated link (ADR 0007). A relay that refuses `zs2.`
  gets `zs1.`, and the sender's Settings say the relay predates post-quantum
  sealing: a degradation the relay can cause, never a silent one. *(Built:
  44.2. The relay checks neither prefix's length; every `zs2.` envelope of a
  bucket is 1 450 characters longer than its `zs1.` one, and the 1 146 880
  bucket is past the default frame cap for both.)*
* **Stripping.** A `zs2.` envelope cannot be made a `zs1.` one: the key
  changes, the AEAD fails, the envelope is dropped — a denial the relay
  already has. Withholding `pqseal` delays the upgrade (R27's shape). A
  classical envelope from a contact holding our key is accepted: it has
  already travelled, so refusing it protects nothing.
* **Distinctiveness.** While both prefixes are in use, `zs2.` tells the relay
  both ends run this release or later (R2's kind). When phase 49 retires
  `zs1.`, first contact becomes `zs2.` with a random KEM field and an
  X25519-only key, tried after the recipient's own, so no envelope announces a
  new contact.
* It ships behind a build constant, the kill switch, like `devlistSignV2Only`
  — and stays off until decapsulation is constant-time: Finnian's decision of
  2026‑10‑17 is to **wait for upstream** `pqcrypto` rather than vendor a
  patched ML-KEM, so 44.7 waits for it and 44.1–44.6 do not.

### 6. Contact requests — replaced by addendum A

As proposed, a request by scan or paste and its opener stayed `zs1.`, an
accepted residual with CONNECT v3 as the alternative, and a request through a
handle was sealed `zs2.` to an ML-KEM key in the handle record (`kintro`
beside `xintro`, §21.3). Addendum A replaces both. First contact on every
route — a code, a request's reply, a device in a list, a handle, a link — is
sealed `zs2.` to the recipient device's sealing key, which its relay keeps
signed by that device's own key and serves on the send's own anonymous
connection (A1–A3); a missing key is never a silent downgrade (A4). A
handle's `kintro` is that relay-held key, signed by `intro`, and the handle
record does not change: an ML-KEM key does not fit a record of at most
1 024 bytes, and a commitment to one would change the canonical record, which
every log, mirror, witness and older resolver refuses (A8, 44.8).

### 7. Session authentication: the plan

Implicit authentication by KEM, on §1's attested keys:

```
SK = HKDF(0xFF×32 || DH1 || DH2 || K_R, 0×32, "Z-X3DH-v2")       (c_R, K_R) = Encaps(responder's sealEk), in the opener
the responder's first reply carries Encaps(initiator's sealEk); K_I joins its first root-key step
```

Only holders of attested decapsulation keys derive the session, so a CRQC can
no longer open one as a device, and a session is post-quantum from its first
message (R5 shrinks to first contact by code). A device whose attested key is
held is refused on a v1 opener, as §17.7 refuses classical after mixing.
Openers move from the 1 024 to the 4 096 bucket. **Not built in 44:** it
changes frozen §4 — convergence, pinning, retired sessions, restore — so the
design goes to the auditor (G1) first, and it needs §1's keys in the field.
Finnian's decision of 2026‑10‑17 puts it **inside phase 49's versioned
step**. Until then session authentication is classical, which a register row
records when this phase's client half lands.

## Rejected

* **A per-pair secret from the ratchet's `K`, with an unlinkable hint:** +8
  bytes instead of +1 088, but opening an envelope would hang on ratchet
  generations and convergence, and a desync is a silent drop. A KEM per
  envelope is stateless.
* **ML-KEM-512 for the seal:** ×1.7 instead of ×2, for a second parameter set.
* **The sealing key in the device list** (one device leaves 4 096, ADR
  0003/0004), **in the QR** (does not fit), **in pasted codes** (the channel
  that carried the paste already told its recorder who added whom).
* ~~**A relay-held introduction key per mailbox, checked against a commitment
  in the code:** key state on the relay, which §4 has refused since v1, and a
  fetch the relay can withhold.~~ *Replaced by addendum A:* Finnian asked for
  it to be designed (decision of 2026‑10‑17); the addendum designs it and
  answers both objections.
* **Reviving `HybridDeviceCertificate`:** it would have gone into lists, and
  does not cover the sealing key.

## Consequences

* **Wire.** `zs2.`; inner kind `pqseal`; members `pqs`, `pqid.pqdc`,
  enrolment `pqdc`; self-sync `dir:"pqdc"`; pairing v3; CONNECT v3; and
  addendum A's introduction key (in place of `kintro` in the record). Additive
  or versioned; every frozen vector byte-identical. Still Ed25519, named so
  nobody infers otherwise: relay authentication, both logs' signed heads,
  handle owner signatures.
* **R43 grows.** A sealing key is long-term and decapsulates any ciphertext
  anyone addresses to its mailbox, and the relay sees when each envelope is
  acknowledged: a KyberSlash-class timing leak in `pqcrypto` meets chosen
  ciphertexts. A recovered key reduces that device's seal to today's, never
  below — but **`zs2.` is not switched on until decapsulation is
  constant-time**, and Finnian's decision of 2026‑10‑17 is to wait for
  upstream for it.
* **Storage.** Vault `seal_seed`, `pqdc`, each contact device's sealing key
  and `pqs`; the archive carries `seal_seed` and `pqdc` as records an older
  build keeps (ADR 0025).
* **Vectors.** `pair-v3/pairing_v3.json`; `connect/invite_v3.json` (with what
  v2 computes from the same inputs); `sealed-v2/sealed_v2.json` (each bucket;
  a swapped and a stripped ciphertext; a `zs1.` body under `zs2.`);
  `v3/device_attestation.json` (refused: swapped `dx`, `acct`, sealing key).
  KEM values re-derived by kyber-py, `pqdc` by dilithium-py, the rest replayed
  by the Node clean-room verifier.
* **Tests.** Protocol `pairing_v3_test`, `connect_v3_test`, `sealed_v2_test`,
  `device_attestation_test`, `sealed_bucket_test` (the lengths above; `pqseal`
  in 4 096; `pqid` + `pqdc` in 16 384). Relay `sealed.test.js`. App
  `pairing_pq_test`, `connect_pq_test`, `sealed_pq_test`,
  `scanned_device_pq_test`. The quantum adversary is modelled as **holding
  every classical private key and no ML-KEM or ML-DSA secret**: it opens
  nothing of pairing v3, CONNECT v3 or `zs2.`; and Context's substitution —
  one matching number on two screens on the base, the reproduction — ends in
  a refused or classical device link.
* **Register.**

| Row | Change |
|---|---|
| R2 | `zs2.` marks a current build at both ends while `zs1.` lasts |
| R4 | narrowed: the code stays classical; the device it names is attested in-band (§2) |
| R5 | CONNECT v3 contacts start hybrid; the rest waits on §7 |
| R17 | a CONNECT v3 contact sends no `pqid` |
| R43 | long-term sealing keys meet chosen ciphertexts; `zs2.` waits on constant-time decapsulation |
| new | first contact by code is sealed classically — as narrowed by addendum A, a row when its client half lands |
| new | session authentication is classical — deferred to §7, a row when this phase's client half lands |

* **Docs.** PROTOCOL §1, §6.2, §8.1–8.2, §9, §10.2, §12.1, §13, §15,
  §18.2–18.3, §18.11, §20.9, §21.3; THREAT_MODEL's edges paragraph;
  AUDIT_SCOPE, a claim for each part as it lands (C39, the relay's
  introduction keys, with 44.10); `CAPACITY.md`; WHAT_Z_CANNOT_DO;
  WHITEPAPER; DATA_MAP's wire shapes; the ADR index.

## Decisions (Finnian's, 2026‑10‑17)

1. `zs2.` doubles what a queued short text costs the relay. Accept and size
   stores ×2, ship it off, or defer the sealed layer? — **Accept, and size the
   stores ×2** (§5). `CAPACITY.md` and both Blueprints' store sizes double
   before `zs2.` is switched on; the Blueprints are his.
2. CONNECT v3: mint it in the release that reads it (ADR 0024's choice; older
   acceptors cannot open new invites), or a release later? — **A release
   later** (§4): 44.6 ships readers only.
3. The device link: required for "post-quantum, verified" at once, or shown
   now and required at phase 49? — **Required for contacts added from this
   release; shown for the rest** (§2), as recommended.
4. Constant-time decapsulation: vendor a patched ML-KEM, owning that code, or
   wait for upstream? It gates `zs2.`. — **Wait for upstream** (§5): 44.7
   stays off until upstream `pqcrypto` decapsulates in constant time; 44.1–44.6
   do not wait.
5. First contact by code stays classical: accept, with the add screen pointing
   to CONNECT — or design a relay-held introduction key? — **Design a
   relay-held introduction key** (a departure from the recommendation):
   addendum A.
6. Session authentication: inside phase 49's versioned step, or its own phase
   once the auditor has the plan? — **Inside phase 49's versioned step** (§7).
   The design goes to the auditor (G1) first.

## Build plan

Each patch carries its own PROTOCOL, THREAT_MODEL and AUDIT_SCOPE edits, a
failing test on the base where it can be expressed, and a mutation check.

| # | Patch | Needs | Status |
|---|---|---|---|
| 44.1 | Protocol cores and vectors: sealing key, `zs2.` seal/open, `pqdc` sign/verify, pairing v3, CONNECT v3 | — | planned; nothing emits |
| 44.2 | The relay treats `zs2.` as sealed | — | **built**; deploy before 44.7 |
| 44.3 | Every device gets a sealing key and attestation: `pqseal`/`pqs`, `pqid.pqdc`, `dir:"pqdc"`, archive | 44.1 | planned; sends keys, uses none |
| 44.4 | Pairing v3 | 44.1, 44.3 | planned; highest value, so land it first |
| 44.5 | The scanned device's link | 44.3 | planned; bites once peers run 44.3 |
| 44.6 | CONNECT v3: readers first; minting is one constant (`connectInviteVersion`), a release later (decision 2) | 44.1, 44.3 | planned |
| 44.7 | `zs2.` switched on | 44.2 deployed, 44.3, constant-time ML-KEM upstream (decision 4) | planned; goes last |
| 44.8 | `kintro`: as addendum A changes it, §21.3's relay-held key signed by `intro`; the record does not change | 44.9–44.12 | planned; the handles hardening it was to land with shipped in 4.3.0 without it |
| 44.9 | Protocol core and vectors of addendum A: `iks`, the entry, `sk` in codes, the FIPS 203 key check, `kintro`, the relay-client frames | 44.1, to be used (built on the library's ML-KEM) | **built**; nothing emits |
| 44.10 | The relay keeps introduction keys | 44.2 | **built**; inert until 44.11, deploy before it |
| 44.11 | Devices publish | 44.3, 44.10 deployed | planned; ships with 44.7 |
| 44.12 | Senders fetch, verify and wait | 44.7, 44.9, 44.11 | planned; after 44.7, in the same release or the next |

Hybrid session authentication (§7) is not in phase 44. It belongs to phase
49, after the auditor has reviewed the plan.

---

## Addendum A — a relay-held introduction key (open question 5)

**Status:** **Accepted** (2026‑10‑17), with the relay half built now (44.9 and
44.10, above); the client half (44.11, 44.12) ships with 44.7. Nothing in it
does anything before 44.7 switches `zs2.` on, and 44.7 waits for
constant-time ML-KEM upstream (decision 4).
- **Replaces:** 0033 §6 ("classical on the code path") and 0033's fourth
  "Rejected" entry.
- **Changes:** 0033 §5's sender rule ("`zs1.` otherwise"), and 44.8.
- **PROTOCOL:** adds §8.3 (A1, A3, A4) and §12.7 (A2, A5); amends §2.4, §8.1,
  §8.2, §12.1, §12.2, §14, §15, §18.2, §21.0, §21.3, §21.6, §21.7 and the
  link's section. *Written with the relay half:* §8.3 with A1 and A3's
  acceptance rule, §12.7 with A2, A5 and A7, and what §12.1, §12.2 and §15
  need for them; the rest is written with the client half.
- **Register:** updates R2, R5, R43 and the first-contact row (0033's
  Register); adds three rows when the client half lands — a withheld key, a
  key's return after a store loss, an entry a flood pushes out — and a claim
  that a first contact is sealed post-quantum or its screen says it was not.
  The relay half's own claim is AUDIT_SCOPE C39.

References: plain "§N" is PROTOCOL, including the sections phase 44 adds
(§8.2, §20.9); "0033 §N" is a section of this ADR, above; "A1"–"A8" are this
addendum's own subsections. ADR 0032 (phase 39's introduction link, `zi1.`)
and ADR 0035 (phase 45's first-contact tokens) are decided, and are written
into this directory when their phases are built.

**Decides:**
- where a sender gets the sealing key of a device it has never heard from;
- how it knows the key is that device's;
- what the relay keeps, for how long, and what a restart does;
- what happens when the relay withholds a key;
- what older clients and relays do;
- what the relay learns.

### Context

First contact is sealed classically (0033 §6, as proposed). After a scan or
paste, the request and the opener go out as `zs1.`. So a recording plus a
later quantum computer reveals who asked whom, under what name, and what the
first flight said (R5).

0033 rejected a relay-held key on two counts:
- it puts key state on the relay, which §4 has refused since v1;
- it adds a fetch the relay can withhold.

Finnian asked for it to be designed anyway. The constraints are 0033's:
- nothing secret, and no contact identity, at the relay;
- sealed sender intact, and no new identifier between sender and recipient;
- forward secrecy unchanged;
- no new trusted party;
- v1 frozen;
- codes that still scan;
- a stripped post-quantum half never silent.

### Decision

#### A1. The key: the device's sealing key, signed by the device

```
sealEk, sealDk = 0033 §1's sealing pair (ML-KEM-768 from seal_seed; one per device, for its life)
iks  = Ed25519.Sign(edSeed, utf8("z-intro-key-v1:") || edPub || SHA-256(sealEk))       64 bytes
sk   = SHA-256(sealEk)                                                                  32 bytes: 0033 §3's and pqdc's value
code += { "sk": b64(sk) }                                                              zc1. and zc3., beside pqc only
```

`edPub` is the key whose SHA-256 is the mailbox (§2.2): the account key on a
root device, `ded` on a linked device, and `intro` for an introduction
mailbox. The two fields after the context are fixed-width, so the
concatenation is unambiguous, and the context is a prefix of no other.

There is no new key. The relay-held key **is** 0033 §1's sealing key, so a
device has one decapsulation key whoever writes to it, and nothing at the
device distinguishes a stranger's envelope from a contact's.

An introduction mailbox (§21.3) gets its own key the same way:

```
kintroSeed = HKDF(ikm = introSeed, salt = utf8("z-handle-intro-k-v1"), info = ∅, L = 64)   → ML-KEM-768 pair (d || z)
iks        = Ed25519.Sign(introSeed, utf8("z-intro-key-v1:") || introPub || SHA-256(kintroEk))
```

Rotating `introSeed` rotates all three of the mailbox's keys, through the
update §21.3 already makes. `kintro` itself never appears in the record.

What each value does:
- **`iks`** makes the key authentic against anyone who cannot forge Ed25519
  when the sender asks for it — which is the first-contact residual's
  adversary: one who records now and holds a quantum computer later.
- **`sk`** binds a scanned code's key against everyone, the active quantum
  adversary included.
  - A device emits `sk` only once its relay holds its key (A2), so a code
    carrying `sk` **promises** a key.
  - `sk` is unsigned, for the reason ADR 0027 gives about a scan that adds
    someone. Anyone who can alter a code before its first scan could replace
    the whole identity in it, and comparing the safety number catches that.
  - In a code for someone the client already holds, `sk` is ignored.
  - A decoder refuses a code that carries `sk` without `pqc`, as it refuses
    one with `pqcs` and no `pqc`.

Neither value is evidence about the device's account. A key checked this way
is a sealing key. It never stands for "post-quantum, verified", which remains
0033 §2's attestation.

#### A2. Publishing (§12.7)

```
S→C  { "t":"challenge", "nonce":…, "auth":2, "ik":1 }                        this relay keeps introduction keys
S→C  { "t":"ready", "id":rid, "ik"?:b64url( SHA-256(ek || iks)[0..16] ) }      the entry it holds for rid, if any
C→S  { "t":"ikey", "ek":b64(1184 bytes), "iks":b64(64 bytes) }               bound (v2) connection; its own routing id
S→C  { "t":"ikey_ok" }
```

When a device sends `ikey` (only to a relay whose challenge said `ik:1`):
- After any login whose `ready` does not name its entry — so the first time,
  and after the relay has lost it — it sends `ikey` on its authenticated link.
- An owner also sends the `kintro` entry on the introduction connection,
  after `intro` (§21.6).

What the relay checks:
- It checks the lengths, and `iks` under the connection's authenticated key.
  Anything else is refused with `error{bad_ikey}`.
- An `ikey` on a connection authenticated with v1 is refused `not_authed`,
  because another relay can have drawn that signature out of the device (R33).

What the relay keeps:

```
RAM    ikeys: rid → (ek, iks, at)    a store of its own; IKEY_CAP entries, the least recently authenticated forgotten first
Redis  ik:{rid} = ek || iks          1 248 bytes, raw; expires OWNED_TTL_DAYS after rid last authenticated (renewed with owned:{rid})
       ik:epoch                      a random value; a store that comes back empty has none
```

How long an entry lives:
- An entry lives as ownership does: `OWNED_TTL_DAYS` (30) from the device's
  last login.
- Every login renews it; a re-publish does not.
- So a device offline for days keeps its key at the relay. Only a month
  without a login, eviction or a store loss removes it.

Pacing and the cap:
- New entries are limited to `IKEY_NEW_PER_IP_PER_MIN` (10) per address a
  minute, where `CLIENT_IP_HEADER` names the address.
- `ikey` frames are limited to `IKEY_PER_RID_PER_MIN` (6) per routing id, as
  `intro` is.
- `IKEY_CAP` (default 20 000) bounds what a flood of fresh keys can push out,
  as `INTRO_CAP` does for flags. It is enforced in each mode as `INTRO_CAP`
  is. *(Built, 44.10: an entry measured at ≈1.6 KB in RAM, so the default
  is ≈32 MB; `CAPACITY.md`.)*

#### A3. Fetching: on the send's own connection, just before it

```
C→S  { "t":"ikey_get", "to":rid }                              a connection that never authenticated
S→C  { "t":"ikey_for", "to":rid, "ek"?:…, "iks"?:… }          both, or neither: the relay holds nothing for rid
S→C  { "t":"error", "code":"anon_only" }                      answer on an authenticated connection; counted
```

**When a sender fetches.** It fetches before its next envelope to a device
whose sealing key it does not hold, provided its relay's challenge said
`ik:1`. After a miss, it fetches only on A4's schedule. After an unpromised
miss and its one retry, it does not fetch for that device again: the in-band
`pqseal` (0033 §1) takes over.

**Where and when it MUST fetch.** It MUST send `ikey_get` on the anonymous
connection that will carry that envelope, immediately before the envelope:
- after its person's tap, when the outbox is flushed;
- one device at a time: fetch, seal, send, then the next device.

For a handle or a link (§21.8), that connection is the one opened for the
request: open, fetch, seal, stamp (pinging meanwhile), send, close.

**What it MUST NOT do.** It MUST NOT fetch:
- on the authenticated link;
- at scan or paste time;
- ahead of the send, in a batch.

**When it accepts the answer.** Only if all of these hold:

```
len(ek) = 1184 and FIPS 203 §7.2's encapsulation-key check passes;   len(iks) = 64;
b64url(SHA-256(edPub)) = rid  and  Ed25519.Verify(edPub, utf8("z-intro-key-v1:") || edPub || SHA-256(ek), iks)   §21.4's one rule
and, when adding a contact from a code that carries sk:   SHA-256(ek) = sk                                   constant time
```

**What it does with an accepted key.** It holds `ek` as that device's sealing
key, exactly as if `pqseal` had brought it:
- `zs2.` (§8.2) from that envelope on;
- `pqs:1` on what it sends;
- the key is never fetched again;
- a later in-band `pqseal` that differs replaces it, and the difference is
  recorded.

**What the relay keeps about fetches.** Nothing. A record of which address
asked about which mailbox is exactly what it exists not to keep. Fetches are
paced as any frame is (§12.4).

**Where `edPub` comes from, and what a missing key means:**

| Route | `edPub` | Checked by | Key missing |
|---|---|---|---|
| a code carrying `sk` | `ed` | `sk` and `iks` | promised: the request waits (A4) |
| a code without `sk` (an older app) | `ed` | `iks` | unpromised: classical, said on the request |
| the reply to a request that came `zs2.` | the request's `bundle.ed` | `iks` | promised: the acceptance waits |
| the reply to a request that came `zs1.` | the same | `iks` | unpromised |
| a device in a verified list, or in a group's member list | `ded` | `iks` | unpromised: one more try, then classical, recorded |
| a handle record, or a `zi1.` link | `intro` | `iks` under `intro` | unpromised: Send asks first |

#### A4. A missing key is never a silent downgrade

**A promised key that does not come**, whatever the reason:
- the relay holds no entry;
- the relay serves one that is refused;
- no answer arrives within 10 s;
- the relay answers `unknown_frame`, or its challenge lacks `ik:1`. Whoever
  made the promise reached this same relay while it said `ik:1`, so this is a
  rollback, an instance part-way through a deploy, or a relay pretending to be
  older.

What the client does:
- The envelopes stay in the outbox **unsealed**: the request, the opener and
  the `pqid`.
- The request shows *Waiting to send with post-quantum protection*.
- It fetches again at its next connection, and after 1 min, 10 min and 1 h,
  then every 6 h at a random moment. That is at most twelve times in 72 h.
- It SHOULD send one **knock** at the first miss, and never more often than
  every 6 h.

```
knock = Seal(recipientXPub = the device's x, f = b64url(SHA-256(32 random bytes)), p = "ik?")      §8, zs1.
```

About the knock:
- It names nobody: a recording opened later shows a random sender and three
  characters.
- A device that is offline and registered for push is woken by it, and its
  next login puts its key back.
- A receiver MUST acknowledge and drop a knock, with no notice and nothing
  sent. An older receiver drops it as an unknown sender.

The client MUST NOT seal to that device classically until its person chooses
*Send without post-quantum protection*. That choice is on a screen which:
- says what is lost: *a recording can show a future quantum computer who you
  asked*;
- offers a connect invite (§20.9) as the post-quantum way.

After 72 h the client tells its person once. A key that is refused is
recorded and said once, as a key that misses its commitment is (§18.3), and
is never tried again.

**A key that was never promised and is missing:**
- *A code from an older app, or the reply to a classical request.* Sealed
  `zs1.` at once. The request says *sealed classically: their app publishes no
  post-quantum key*.
- *A device from a list or a group.* Fetched once more after ten minutes and
  at the next connection, because a device linked a moment ago may not have
  published yet. If still missing, it is reached `zs1.`, and that device's row
  on the contact's screen says it was first reached classically.
- *A handle or a link.* Send asks before anything goes. It says the owner has
  published no key at this relay — either an older app, or a relay that did
  not hand it over.

**A relay whose challenge lacks `ik:1`.**
- If it never had it (an older relay), unpromised first contacts go `zs1.` as
  today, and each request says so. Settings says the relay predates
  post-quantum introductions, as 0033 §5 does for a relay that refuses `zs2.`.
- If it had it before — the client keeps that fact per relay — Settings says
  instead that the relay has stopped handing keys over, and unpromised routes
  behave as they do when a key is missing.
- Either way, promised routes wait, as above.

**The receiver** shows, with each pending request, whether it arrived `zs2.`
or `zs1.`. So a classical request shows on both screens. A list device reached
classically is recorded on the sender's contact screen.

**Existing conversations.** A device of an existing contact whose in-band key
has not arrived is reached the same way, by the list route, at its next
envelope. Conversations from before this release therefore go `zs2.` without
waiting for `pqseal`.

#### A5. What a restart does

| Event | Entries | First contacts meanwhile |
|---|---|---|
| A RAM relay restarts (every deploy, and the free plan's sleep) | all lost, with the queues | Every connected device reconnects and republishes within seconds (estimated). A device that was offline republishes at its next login. Until then promised routes wait (a knock wakes a push device), and the rest go classical, marked. |
| An HA instance restarts (rolling deploy) | kept | nothing changes |
| The HA store restarts (persistence off) | all lost | Each instance keeps a copy of the entry of every socket it holds (≈1.5 KB a connected device, measured). Its heartbeat finds `ik:epoch` changed or gone and puts them back within 25 s. Offline devices as above. |
| Eviction past `IKEY_CAP` | the least recently authenticated | as an offline device after a restart |

The store stays RAM-only. Nothing is written to disk, and a seized machine
holds no key and no list of mailboxes.

#### A6. Versions meeting

Everything here is additive under §14:
- an optional code member;
- frames and members that an older relay or client never sees;
- one context string for each use;
- two error codes, neither carrying `id`.

`creq`, the stamp, the handle record, `zi1.` and every frozen vector stay
byte-identical.

How mixed versions behave:
- An older client never fetches and never publishes.
- A newer client facing an older relay (no `ik:1`) seals first contact as
  today, and says so. A promise from a code still waits (A4).
- An older relay is never sent `zs2.`, which needs 44.2 first.

Rollout order: the relay patches 44.2 and 44.10 first, then 44.11 and 44.12
with 44.7.

*Measured with the relay half: Release 4.3.2's decoder reads a code carrying
`sk` as it reads the same code without it — the member is ignored — and reads
a code with `sk` and no `pqc` as a classical code, which a current decoder
refuses.*

#### A7. What the relay learns

- **At a publish:** that a routing id holds a sealing key — which says its
  build is current, as its login and its `zs2.` traffic already do (R2).
  - The key is public.
  - Each device's entry is its own, signed by its own key, so entries cannot
    be grouped into accounts. The `pqc` chain could be grouped — see Rejected.
- **At a fetch:** that the anonymous socket — an address (R21) — is about to
  reach that mailbox for the first time.
  - The send writes the same thing a moment later, on the same socket, and so
    do R17's `pqid` and ADR 0035's token.
  - A fetch that finds nothing still shows that an address meant to reach that
    mailbox.
  - There is no new identifier: the frame names the mailbox and nothing else.
  - Cloudflare sees the same (R44).
- **What it can do:**
  - Withhold, refuse or delay a key. On a promised route that costs a visible
    wait and a choice the person makes. On the others it costs a classical
    first contact, which the request or the contact's screen records (A4).
  - Serve a key that fails `iks` or `sk`. It is refused and recorded.
  - Serve a stale key. That amounts to a dropped envelope (R14).
  - It cannot serve a key of its own: that needs an Ed25519 forgery now.
- **Presence:** an entry says the device has logged in within 30 days and
  since the store last lost its data. After a loss, anyone who polls learns
  when the device came back (a register row when the client half lands).
- **Enumeration:** none. A fetch has to name a routing id.

#### A8. Where it meets the rest of 0033

- **Linked devices.**
  - Each device publishes its own entry for its own mailbox, and nothing ties
    the entries together.
  - A linked device's code works as a root's does: its own `ed` signs its
    key.
  - Through the list route, a contact reaches a newly linked device `zs2.`
    from its first envelope.
  - The new device reaches the account's contacts and its own sibling devices
    the same way, using the keys in its enrolment. Pairing v3 does not change.
- **The transparency log** holds no key and no commitment (see Rejected).
- **`zs2.` and constant-time decapsulation.**
  - The fetch is no use until 44.7, which waits for upstream (decision 4).
  - Anyone holding the routing id can fetch the key, so anyone can aim chosen
    ciphertexts at it. That makes the gate more important (R43).
- **CONNECT v3** needs no fetch: its reveal carries `pqseal`.
- **Forward secrecy** is unchanged. `zs1.` and `zs2.` alike rest on a static
  recipient key, and this adds no new static secret.
- **ADR 0035.** A request by code spends its token on the same send, after the
  fetch. A request that waited past its token's days takes a fresh one.
- **Phase 49.** 0033 §7's opener encapsulates to the responder's attested
  sealing key.
  - For a scanned code, `sk` provides that.
  - The list route would then need 0033 §1's `pqdc` beside `iks` in the
    entry.
  - Reserved, not specified here.

#### The two objections, answered

**Key state on the relay.** What §4 refused in v1 was a server that holds
prekeys which clients must trust and the protocol cannot work without. This
store is neither:
- It holds public keys only, and each sender checks every key against one it
  already holds. So a relay that changes a key is caught, and one that loses a
  key costs a wait, not a message.
- It is RAM-only, like the queue. Its entries live as long as `owned:{rid}`
  does, and it has the shape of the `intro:{rid}` flag store the relay already
  keeps.
- Without it, first contact works as it does today, and is marked.

What is new is size — about 1.6 KB a device (estimated, and ≈1.6 KB as
measured with 44.10), against about 120–160 bytes for an owner record or a
flag — and that senders read it.

**A fetch the relay can withhold.** True, and it cannot be prevented: any
relay can also drop the envelope itself (R14, R27). What the design
guarantees is that withholding is never mistaken for an older peer:
- a code with `sk`, or a request that came `zs2.`, promises a key;
- a relay that has served a key before is remembered, so it cannot pass itself
  off as an older relay;
- a broken promise leaves the request waiting on screen until its person
  decides, and a classical send then shows on both screens.

The relay's power shrinks from a silent classical first contact to a visible
delay.

### Rejected

- **A hash commitment and nothing else** (the alternative as 0033 phrased it).
  - It binds only scanned codes. A list, a reply, a handle and a link carry no
    code, and codes already handed out carry no commitment.
  - Kept: `sk`, as a code's promise and its post-quantum binding. Every route
    checks `iks`.
- **The `pqc` chain.** Here the relay would serve the account's ML-DSA key
  and 0033 §1's `pqdc` beside the sealing key, checked against the `pqc` every
  code already carries.
  - For: it is post-quantum authentic and needs no change to the code.
  - Against: it adds 5 261 bytes a device, making the entry 5.2 times as
    large.
  - Against: every device's entry would carry the same 1 952-byte account key,
    letting the relay group mailboxes into accounts — the grouping A7 rules out
    — unless the key were sealed under a key derived from `pqc`.
  - Against: it depends on the root having signed `pqdc`.
  - Reserved for phase 49's list route.
- **The transparency log as the key's home, or a commitment inside the list.**
  - The log keeps every entry in memory for ever, about 4 KB an entry and its
    first ceiling (`CAPACITY.md`), and on disk (R31).
  - It can be turned off.
  - A bucket lookup at send time puts a second service, an address and a
    bucket (R40) beside every first contact.
  - A commitment in the list changes its signed input. That would be a fourth
    migration, after ADRs 0010, 0017 and 0029.
  - A relay entry, by contrast, costs nothing on disk and goes away when the
    device does.
- **`kintro` in the handle record** (0033 §6 as proposed, and 44.8).
  - It does not fit: 1 579 characters against 1 024 bytes.
  - A 32-byte commitment would fit, but it changes the canonical record, which
    every log, mirror, witness and older resolver refuses.
- **The requester's key inside the request.**
  - It adds about 2.2 KB to every `creq`, which moves a root device's request
    from the 1 024 bucket to the 4 096 one (computed: 606 → 2 762 bytes
    inside).
  - It does so for something the reply can fetch, and gives two mechanisms
    where one does.
- **A knock answered with the key** (no relay state at all).
  - The device would answer strangers: a presence oracle for anyone with its
    code.
  - Both ends must be online.
  - The answer links two mailboxes.
- **A persistent store.** It would survive restarts, but it writes a table of
  every active mailbox to disk, which "nothing at rest" exists to refuse.
- **Fetching on the authenticated link, at scan time, in a batch, or by bucket
  with decoys.**
  - The first names the sender beside the recipient (ADR 0007).
  - The others separate the fetch from its send.
  - A decoy hides nothing that the send names a moment later.
- **Sending classically after a timeout, automatically.** It hands a
  withholding relay the downgrade for the price of a notice nobody reads.
- **A separate introduction key, or a rotating one signed by the account's
  ML-DSA key.**
  - A second decapsulation key doubles R43's surface for nothing.
  - Rotation would give the outer layer a forward secrecy it has never had,
    but it needs the account's ML-DSA key at the relay or in the code (as
    above), and it breaks a code's `sk`.
- **Pacing fetches per address and mailbox.** That needs a table of who asked
  about whom.

### Consequences

- **Wire.** All additive; every frozen vector stays byte-identical. The new
  pieces:
  - the code member `sk`;
  - the context strings `z-intro-key-v1:` and `z-handle-intro-k-v1`;
  - the frames `ikey`/`ikey_ok` and `ikey_get`/`ikey_for`;
  - the members `challenge.ik` and `ready.ik`;
  - the error codes `bad_ikey` and `anon_only`;
  - the knock's `p`.
- **New at the relay**, in full:
  - one store of public keys (`ik:{rid}`, `ik:epoch`);
  - two frame pairs, two members and two error codes;
  - three settings: `IKEY_CAP`, `IKEY_NEW_PER_IP_PER_MIN` and
    `IKEY_PER_RID_PER_MIN`;
  - five counters: `z_ikey_published_total`, `z_ikey_served_total`,
    `z_ikey_missing_total`, `z_ikey_evicted_total` and `z_ikeys` — and, built,
    `z_ikey_anon_only_total`, the count of the fetches A3 says are refused on
    an authenticated connection;
  - one Ed25519 verification per publish;
  - in Redis mode, a copy of each socket's entry.

  Nothing is written to disk.
- **Sizes** (estimated where marked):

| Item | Size |
|---|---|
| A code | +70 characters (computed; in the vectors a root code goes from 500 to 570 and a linked one from 872 to 942) |
| A publish | ≈1.7 KB, sent only when `ready` does not show the entry |
| A fetch's answer | ≈1.75 KB, once per device reached |
| The store | ≈1.5–1.7 KB a device (estimated) — measured with 44.10 at ≈1.6 KB in RAM and ≈1.5 KB in Redis, so `IKEY_CAP`'s 20 000 are ≈32 MB and ≈29 MB (`CAPACITY.md`) |
| The put-back copy (Redis mode) | ≈1.3 KB per socket an instance holds (estimated) — measured at ≈1.5 KB |
| CPU | sealing costs as 0033 §5 says (+0.8 ms), plus one strict Ed25519 verification per fetched key (a few ms in Dart, estimated — measured with 44.9 at ≈4 ms, JIT) |

- **Storage on the client.**
  - Per relay: whether it has ever served a key (the pin).
  - Per device reached: the fetched key, kept as 0033 §1 keeps contacts'
    sealing keys.
  - Per contact: whether first contact went classical.
  - Outbox rows may wait unsealed.
- **Vectors.** A new file, `intro-key/intro_key.json`:
  - `iks` from seeds, for a root device, a linked device and an introduction
    mailbox (`kintroSeed` and its key pair);
  - refusals: `iks` under another `ed`, `iks` over another key, a truncated
    key, a key that fails the modulus check, a key that misses a code's `sk`;
  - codes with `sk` (root and linked), and their lengths;
  - a knock;
  - a `zs2.` request sealed to a fetched key.

  The Node verifier replays the Ed25519 values, and kyber-py re-derives the
  ML-KEM ones. *(Built with 44.9: all but the knock and the `zs2.` request,
  which need 44.1's `zs2.` and are added with the client half; the file also
  pins the modulus check at its edges and the acceptance rule's verdict on
  each refusal.)*
- **Tests.**
  - Protocol: `intro_key_test.dart`.
  - Relay: `intro_key.test.js`. It checks that:
    - a publish needs a v2 login and an `iks` under the login's key;
    - an entry is renewed by a login, not by a publish;
    - a restart loses every entry;
    - the heartbeat puts entries back after a store loss;
    - `IKEY_CAP` forgets the least recently authenticated first;
    - pacing holds;
    - `ikey_get` gets the same answer for an unknown mailbox as for one
      without a key, and is refused on an authenticated socket.
  - App: `intro_key_pq_test.dart` — two clients over a real relay, with a
    recording tap, 0033's quantum model (every classical private key, no
    ML-KEM or ML-DSA secret) and a relay that withholds:
    1. The first flight, in both directions, is `zs2.`, and the model opens
       none of it.
    2. Every fetch rides the anonymous socket, immediately before its send.
    3. After a restart the request waits, the knock wakes the device, and the
       request then goes `zs2.`.
    4. When the key is withheld, the request waits and nothing classical
       leaves until the person chooses. After that, both screens say so.
    5. With an older relay, or an older peer, the request goes classical at
       once and says so.
    6. A key signed under another device's `ed`, or one that misses `sk`, is
       refused and said once.
    7. A contact's first envelope to a newly linked device is `zs2.`.
    8. Under the model, substitution with a forged `iks` succeeds — that is the
       residual, shown — and is refused for a code that carries `sk`.
  - Extended: `anonymous_sender_test.dart`, `handle_flow_test.dart` (a request
    through a handle is `zs2.`, on its own connection) and
    `pq_every_channel_test.dart`.
- **Register.**

| Row | Change |
|---|---|
| R2 | The relay also knows which mailboxes publish a key: the same "current build" fact. |
| R5 | Narrowed: a first flight sealed `zs2.` is closed to a recording. Authentication stays classical (0033 §7). |
| R43 | A sealing key anyone can fetch is open to anyone's chosen ciphertexts. The gate on constant-time decapsulation stands. |
| first contact (0033's new row) | Narrowed: classical only when the device or the relay cannot publish (an older app or relay), or its person chooses after a refusal — and then the screens say so. An adversary who can forge Ed25519 at the moment of the fetch beats `iks` (as with R4 and 0033 §7), but not `sk`. |
| new | The relay can withhold a key. First contact then waits, visibly; a list device is reached classically and that is recorded. Accepted. |
| new | After a store loss, a key's return tells anyone polling when its device came back. Accepted. |
| new | A flood of fresh keys can push a dormant device's entry out; the entry returns at the device's next login. Bounded by `IKEY_CAP` and pacing. Accepted. |

R17 and R21 do not change: the fetch rides the send's own socket, and it
marks the same first contact the `pqid` already marks.

- **Docs.**
  - PROTOCOL: the sections listed under Status.
  - THREAT_MODEL: the relay's row in the trust table (it now holds public
    sealing keys), and the paragraph on the quantum layer's edges.
  - DATA_MAP: the relay row, and "what leaves your device".
  - CAPACITY.
  - SELF_HOSTING: the new settings, and "what a restart forgets".
  - AUDIT_SCOPE: a claim that a first contact is sealed post-quantum, or its
    screen says it was not; and, with the relay half, C39.
  - WHAT_Z_CANNOT_DO; WHITEPAPER.
  - `render.ha.yaml`: "never keys" becomes "never private keys". That edit is
    Finnian's, alongside ADR 0035's day-key line.

### Decisions (Finnian's, 2026‑10‑17)

Addendum A is accepted, with the relay half built now. Its own questions:

1. **The commitment in the code** — `sk` in the code (70 characters and one QR
   version), or a bare flag `ik:1` (10 characters, no QR version) and `sk`
   left until phase 49? — **`sk` in the code**, as recommended: it is the
   code's promise of a key, binds the key post-quantum, and lets 0033 §7's
   opener cover first contact by code in phase 49.
2. **A promised key that never comes** — wait and ask the person, or send
   classically after a bound (say 72 h), marked?
3. **The knock** — one wake per waiting request every 6 h, or wait for the
   device's own next connection?
4. **The fallback on the list route** — classical after one more fetch,
   recorded on the contact's screen, or hold the first envelope to a new
   device until its key comes, up to 72 h?

   Questions 2–4 belong to the client half (44.11–44.12) and are taken up
   with it. Until then A4 stands as written, which is each one's
   recommendation.
5. **Store size** — **`IKEY_CAP` defaults to 20 000**, as recommended; the
   public relay's figure is Finnian's, on its Blueprint, alongside 0033's
   decision 1, which doubles the stores.
6. **Shipping order** — **the relay half now** (44.9 and 44.10), inert, and
   the client half with 44.7, as recommended.

Finnian's, outside the repository: the `render.ha.yaml` wording ("never
private keys"); `IKEY_CAP` on both Blueprints; deploying the relay (44.2,
44.10) before the app.
