# ADR 0003 — Getting a post-quantum identity through a QR code

**Status:** Accepted (2026‑09‑07) · **Roadmap:** 13.2 · **Decides:** the open
problem the roadmap requires settling *before* 13.1 hardens the v3 format.

> ADR 0002 is reserved for the iOS push architecture, being written in
> parallel. This is 0003 to avoid collision.

## Context

Protocol v2 mixes an ML‑KEM‑768 secret into every message key (PROTOCOL.md
§17), so a recording made today is not readable by a future quantum adversary.
What v2 does **not** do is protect *authentication*: account keys, device keys,
device certificates and safety numbers are all still Ed25519. A
cryptographically relevant quantum computer could therefore forge a device
certificate — mint a device that appears to belong to someone's account — even
though it could not read past traffic. Phase 13 closes that with hybrid
signatures: Ed25519 **and** ML‑DSA‑65 (FIPS 204), both required, verification
failing if either half fails.

The obstacle is not the cryptography. `pqcrypto` already ships ML‑DSA (it is
the same package v2 uses for ML‑KEM), and hybrid verification is a few lines.
The obstacle is that **a hybrid identity does not fit in a QR code**, and
scanning a QR is the core onboarding flow — the thing two people do once, in
person, and judge the product on.

### The numbers

ML‑DSA‑65, from `DilithiumParams.mlDsa65` (k=6, l=5, ω=55, |c̃|=48), matching
FIPS 204 Table 2:

| | bytes |
|---|---|
| public key | 1 952 |
| signature | 3 309 |
| secret key | 4 032 |

A v3 account code carrying hybrid keys and hybrid device certificates:

```
account          = ed_pub(32) + mldsa_pub(1952)                       =  1 984 B
per device       = ed(32) + x(32) + mldsa_pub(1952)
                   + cert_ed_sig(64) + cert_mldsa_sig(3309)           =  5 389 B
```

| devices | raw | base64 |
|---|---|---|
| 1 | 7 373 B | ~9 832 chars |
| 2 | 12 762 B | ~17 016 chars |
| 3 | 18 151 B | ~24 204 chars |

A QR code tops out at **2 953 bytes** (version 40, byte mode, error correction
L) — and a version‑40 symbol is 177×177 modules, at the edge of what a phone
camera reads reliably. A code that scans comfortably across cheap cameras and
bad light is nearer 800 bytes.

So the smallest possible v3 code is **2.5× over the absolute ceiling** and
roughly **9× over what actually scans**. Today's `zc1.` code is ~128 bytes.
This is not a tuning problem.

## Options considered

**(a) Multi-part or animated QR.** Split across 4–8 symbols, or cycle them.
Keeps everything out‑of‑band, which is the strongest position. Rejected on
user experience: both parties must hold cameras steady through a sequence, in
the one flow where failure means the two people give up and use something
else. It also does not degrade — a partially scanned identity is no identity.

**(b) Classical keys in the QR, PQ half exchanged on first contact and
trusted.** Trust‑on‑first‑use for the post‑quantum half. Rejected as
self‑defeating: an attacker present at the first exchange substitutes their own
ML‑DSA key, and every hybrid check thereafter passes for them. The point of
13.1 is that verification fails if *either* half fails; TOFU on the PQ half
means the PQ half adds nothing against precisely the adversary who is there at
the start, which is the adversary safety numbers exist for.

**(c) A binding commitment in the QR, the PQ half delivered in‑band.**
Adopted. See below.

## Decision

**The QR carries a commitment to the post‑quantum half, not the half itself.**

The insight is that the out‑of‑band channel does not need to *transport* the
key. It needs to *bind* it. A collision‑resistant hash does that in 32 bytes:

```
code      = ed_pub(32) ‖ x_pub(32) ‖ binding_sig(64) ‖ pq_commit(32) ‖ name
pq_commit = SHA-256( "z-pqid-v3:" ‖ mldsa_account_pub )
```

**Correction, made when emission was switched on:** this was first built
behind a new `zc3.` prefix, which was wrong. PROTOCOL §14 says a new optional
JSON member is compatible evolution and does not warrant a version bump —
only a change to bytes an existing implementation would compute differently
does, and a commitment changes none. A prefix, meanwhile, is rejected outright
by every build in the field, so a `zc3.` code would have been unreadable to
the entire installed base in order to convey something they would have
ignored. The commitment therefore rides as an optional member of a `zc1.`
code. `zc3.` stays specified and accepted, and is not emitted.

That is **+32 bytes on the existing code** — around 160 bytes total, well
inside a comfortable QR.

The ML‑DSA public keys and the hybrid device certificates are then delivered
**inside the resulting ratchet session**, as an additive inner message, and
checked against the commitment the scanner already holds. A mismatch is a hard
failure: the session is torn down and the user is told the identity did not
match what they scanned. There is no "accept anyway".

Security is therefore equivalent to putting the full 1 952‑byte key in the QR.
An attacker who wants to substitute a PQ key must find a SHA‑256 preimage or
collision, which is exactly the assumption the rest of the design already
rests on — and, notably, a hash whose 128‑bit collision resistance survives
Grover comfortably.

### Why this is stronger than the roadmap's phrasing

ROADMAP 13.2 offers "a compact reference in the QR with the PQ half fetched
over the resulting session". The word *reference* is doing dangerous work: a
lookup identifier (a URL, a key id) provides no binding at all and collapses
into option (b). The security here comes entirely from the QR carrying a
**commitment**, and that word belongs in the spec.

### Consequences

* **Safety numbers (13.3) stay short and stay meaningful.** The number is
  derived from both key halves; since the commitment binds the PQ half to the
  scan, the number is still anchored out‑of‑band. It changes once for every
  existing user, which 13.3 already plans re‑verification UX for.
* **A window where the PQ half is unknown.** Between scanning and the first
  in‑band exchange, only the classical half is held. The client must present
  that state honestly rather than claiming post‑quantum authentication it does
  not yet have.
* **`zc2.` codes still resolve**, marked as classical identities, per 13.5's
  compatibility window.
* **The commitment is account-scoped, and that has multi-device consequences
  the design did not anticipate.** `pq_commit` binds the *account's* ML-DSA
  key to the classical identity printed in the *same code*. On a one-device
  account those are the same identity and the distinction is invisible. On an
  account with a linked device they are not, and two things follow, both found
  by switching emission on rather than by reading the design:
  1. Every device must hold the account's ML-DSA public key — it is public, so
     it travels at enrollment — or a linked device derives one of its own and
     the account acquires a second post-quantum identity.
  2. A contact code names the device that shows it (true since v1, invisible
     until now), so a linked device cannot attach an account commitment
     without producing a code whose binding signature fails. It emits none.
     Closing that properly means the code must carry a device certificate, a
     format change, tracked as ROADMAP 13.6.

## Measured, not assumed

Three things this ADR left open have now been measured against `pqcrypto`
0.4.1 and the current relay. Two are fine. The third is a problem, and it is
the more interesting one.

**Verification cost — acceptable.** Median over 20 runs in this container:
keygen 3.1 ms, sign 10.1 ms, **verify 3.1 ms**. Verification is what lands on
the inbound path, and it is paid once per device certificate *when a device
list is installed* — not per message, because 7.7a gossip carries a 32‑byte
fingerprint rather than the list. A three‑device account therefore costs
~10 ms of verification on a list change, perhaps 3–5× that on a phone in pure
Dart. It sits under the per‑conversation lock, so it should be measured again
on real hardware, but it is not a design problem.

**Relay envelope limits — fine.** `maxEnvelopeBytes` is 1 000 000. A
three‑device hybrid list is ~18 KB. No relay change, so phase 10's "the relay
is untouched" survives into 13.

**Padding buckets — a real leak, and it needs a decision in 13.1.** Sealed
sender pads every envelope into one of `[1024, 4096, 16384, 65536, 262144,
1120·1024]` (PROTOCOL.md §8) precisely so the relay cannot tell one kind of
message from another. Measured wire sizes:

| message | bucket |
|---|---|
| short text ("ok") | 1 024 |
| chatty text (40 chars) | 1 024 |
| 900‑character text | 4 096 |
| device list, classical, 1–3 devices | 1 024 |
| device list, **hybrid**, 1 device | 16 384 |
| device list, **hybrid**, 2–3 devices | 65 536 |

*Correction (2026‑09‑10): the classical‑list row was inferred from inner
bytes, not sent through the pipeline. Measured, a classical device list of
one to four devices is a **4 096**‑bucket envelope — the bucket of a text of
~190 to ~1 900 characters — and the 1 024 bucket holds only inner messages
of ~250 bytes or less. See the addendum to `adr/0004` and
`protocol/test/sealed_bucket_test.dart`. The conclusion below is unchanged:
a device list is the size of ordinary chat; a hybrid one is not.*

Today a device‑list update is *indistinguishable from an ordinary chat
message* — both sit in the ~~1 024~~ 4 096 bucket, which is the whole point
of the bucketing. Hybrid certificates would move it to a bucket almost nothing else
occupies, so the relay would learn **when an account changes its device set**,
and roughly **how many devices it has**, from envelope size alone.

That is a regression against the thing ADR 0001 is about. T1–T3 there are
threats about device‑set changes being invisible *to the user*; making those
same changes visible *to the relay* is a new leak running the other way, and
it would be introduced by a phase whose purpose is to strengthen
authentication.

The fix is the same trick this ADR already adopts, applied in‑band: **a device
list carries the classical certificates plus a per‑device commitment to the PQ
half**, keeping it in ~~the 1 024~~ its bucket, and the PQ halves travel separately —
where they are just bytes, uncorrelated with a device‑list event. 13.1 should
settle the exact shape, but it should not ship a device list that announces
itself by size.

## Status of this decision

Accepted on the owner's go-ahead, and implemented as PROTOCOL.md §18.1–18.3
with vectors in `docs/vectors/v3/`. The QR decision turns only on the size
arithmetic and on option (b) being unsound, both settled and now checkable by
a third party. The bucket finding above remains an input to the device-list
work, and is the one most likely to be missed, since nothing fails — the
messages go through, they are simply legible as a category to anyone watching
sizes.
