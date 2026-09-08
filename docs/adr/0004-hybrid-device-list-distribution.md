# ADR 0004 — Getting a post-quantum signature onto a device list

**Status:** Accepted (2026‑09‑08) · **Roadmap:** 13.1/13.4 · **Decides:** the
last open piece of phase 13, flagged but not settled by `adr/0003`.

## Context

Phase 13's exit criterion is that *a forged device certificate with only a
valid Ed25519 half is rejected*. A device certificate is the account's
statement that a device belongs to it, so forging one inserts a rogue device
into every contact's fan‑out — the one thing a cryptographically relevant
quantum computer could do to this design without touching a single recorded
ciphertext.

`HybridDeviceCertificate` (§18.1, §18.4) has existed since 13.1: Ed25519 and
ML‑DSA‑65 over identical bytes, both required. What has never existed is a way
to get it to a contact. ADR 0003 found why, while measuring something else:

> Hybrid certificates would move [a device‑list update] to a bucket almost
> nothing else occupies, so the relay would learn **when an account changes its
> device set** and roughly **how many devices it has**, from envelope size
> alone.

and sketched the fix — *"a device list carries the classical certificates plus
a per‑device commitment to the PQ half, keeping it in the 1 024 bucket, and the
PQ halves travel separately"* — while explicitly leaving the shape to be
settled here.

## Measured, before deciding

Inner‑message sizes, and the sealed‑sender bucket (§8) each lands in:

| shape | bytes | bucket |
|---|---|---|
| text, `"ok"` | 41 | 1 024 |
| text, 900 characters | 939 | 1 024 |
| `pqid` (one ML‑DSA public key) | 2 659 | 4 096 |
| device list, classical, 1 device | 456 | 1 024 |
| device list, classical, 2 devices | 690 | 1 024 |
| device list, classical, 3 devices | 924 | 1 024 |
| device list, **hybrid certs inline**, 1 device | 4 883 | 16 384 |
| device list, **hybrid certs inline**, 2 devices | 9 544 | 16 384 |
| device list, **hybrid certs inline**, 3 devices | 14 205 | 16 384 |
| separate message, per‑device `mlsig`, 1 device | 4 467 | 16 384 |
| separate message, per‑device `mlsig`, 2 devices | 8 891 | 16 384 |
| separate message, per‑device `mlsig`, 3 devices | 13 315 | 16 384 |
| separate message, **one list‑level `mlsig`** (any count) | 4 458 | 16 384 |

Two things fall out, and both correct ADR 0003.

**The buckets cannot hide 3.3 KB of signature.** Whatever is done, a
post‑quantum artefact lands in the 16 384 bucket. Moving it out of the device
list does **not** move it back to 1 024. What separate delivery buys is
decorrelation in *time*, not indistinguishability in *size* — and that is worth
being precise about, because "the halves travel separately" reads as if it
solved the size problem, and it does not.

**The device‑count leak is coarser than 0003 claimed, and it has a cliff.**
One, two and three devices all sit in 16 384; the fourth crosses into 65 536.
So per‑device signatures leak a *band*, not a count — but the band boundary is
real, and it is exactly where a list‑level signature costs nothing to avoid.

## The argument that actually decides it

Size is not the strongest reason to prefer one signature over the list to one
per device. **Per‑device signatures do not authenticate the set.**

Consider an adversary who can forge Ed25519 but not ML‑DSA — the whole premise
of phase 13. Given a genuine hybrid list for `{phone, laptop, tablet}`, they
can present a list for `{phone, tablet}`: the classical list signature is
forged, and each remaining certificate's `mlsig` is *genuine*, copied
unchanged. Every check passes. The honest device has been excluded, which is
`adr/0001`'s T2, and the post‑quantum half bought nothing at all.

A signature over the **list** — version and the sorted device keys, exactly
the bytes `SignedDeviceList.signingInput` already defines — covers the set
boundary and the version. The same adversary can produce neither a different
membership nor a rollback.

## Decision

**The account signs its device list under ML‑DSA‑65 as well as Ed25519, and
the post‑quantum signature travels as its own message, uncorrelated with the
list.**

```
input  = utf8("z-devlist-v1:") || utf8(version) || ":" || ed_1 || ed_2 || …
             (sorted, exactly §3.4's input — unchanged)
sig    = Ed25519.Sign(account_ed_sk,  input)      in the list, as today
mlsig  = ML-DSA-65.Sign(account_ml_sk, input)     delivered separately
```

* **The device list is unchanged on the wire.** Same bytes, same 1 024 bucket,
  same timing. A v3‑unaware client is unaffected; nothing regresses.
* **The post‑quantum signature is one artefact of constant size**, whatever
  the device count. No band, no cliff, nothing that scales with the set.
* **It is delivered on its own schedule**, not when the set changes. A client
  sends it opportunistically — with the next traffic to that contact after a
  randomised delay — so the 16 384‑bucket envelope carries no information
  about *when* anything changed.
* A contact holds a list as `classical`‑verified until the signature arrives
  and checks, then `hybrid`, per §18.4.

Per‑device `HybridDeviceCertificate` stays specified and implemented. It is
the right shape where size does not matter and the *device*, not the set, is
what is being attested: enrollment hands one to the device it describes. It is
simply not what travels to contacts.

## Options considered and rejected

**(a) Hybrid certificates inline in the device list.** What §18.4 originally
implied. Rejected twice over: it moves the list out of the 1 024 bucket, so a
device‑list update stops being indistinguishable from a chat message — the
regression ADR 0003 identified — and, per the argument above, it does not
authenticate the set anyway.

**(b) Per‑device `mlsig` in a separate message.** ADR 0003's sketch. Fixes the
bucket regression but keeps the set unauthenticated, and reintroduces a
device‑count band at the 4‑device boundary. Strictly worse than one signature
over the list, for more bytes.

**(c) Fragmenting the signature into 1 024‑bucket envelopes.** Six fragments
of ~560 bytes each would be indistinguishable from six chat messages, and cost
*fewer* total bytes than one padded 16 384 envelope. Genuinely tempting, and
rejected on proportion rather than principle: it adds a reassembly mechanism —
partial state, ordering, expiry — to hide the fact that a client is running
v3, which is not a secret worth a new moving part. Six same‑bucket envelopes
in a burst are their own signal unless spread over time, and spreading them
delays the verification they exist for. **Revisit if a general fragmentation
mechanism ever exists for another reason**; do not build one for this.

## Consequences

* **A residual signal remains, and should be stated rather than implied
  away.** A relay operator watching sizes sees an occasional 16 384‑bucket
  envelope. That says "this account runs a v3 client and periodically ships a
  large authentication artefact". It does not say when the device set changed,
  or how large it is. That is the whole of what this design claims.
* **Suppression is possible and not preventable at the network layer.** An
  attacker who drops the signature leaves the list classically verified.
  §18.4 already says this must be surfaced: a client that expects a hybrid
  half — because it scanned a code carrying a post‑quantum commitment — and
  has held a list without one for some time should say so, rather than
  presenting classical verification as the finished state.
* **Ordering matters.** The signature cannot be checked before the contact's
  account ML‑DSA key has arrived and matched its commitment (§18.2). A
  signature that arrives first is held, not discarded, and re‑checked when the
  key lands — otherwise the two independent schedules would have to be made
  dependent on each other, which is what this ADR is avoiding.
* **§18.4's distribution paragraph is superseded** by §18.9. The certificate
  format it specifies is unchanged.
