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
* **Suppression is possible and not preventable at the network layer**, and
  the residual signal above is what makes it easy: the 16 384‑bucket envelope
  is the one to drop. Detecting it turned out to need a piece this ADR did not
  anticipate. "Hybrid identity but classical list" is *not* evidence of
  suppression — a client built before §18.9 has a post‑quantum identity and
  never signs its lists — so alarming on it would fire for every such contact
  during rollout, which is how an alarm stops being read. The sender therefore
  claims, inside the ratchet, that it has **sent** the signature; only a claim
  with nothing behind it is a problem, and the claim cannot be stripped by
  whoever dropped the envelope. See §18.9.
* **Ordering matters.** The signature cannot be checked before the contact's
  account ML‑DSA key has arrived and matched its commitment (§18.2). A
  signature that arrives first is held, not discarded, and re‑checked when the
  key lands — otherwise the two independent schedules would have to be made
  dependent on each other, which is what this ADR is avoiding.
* **§18.4's distribution paragraph is superseded** by §18.9. The certificate
  format it specifies is unchanged.

## Addendum (2026‑09‑10) — the bucket column was inferred, not measured

The table under *Measured, before deciding* gives inner‑message byte counts
and, beside each, a bucket. The byte counts were measured. The buckets were
read off `sealedBuckets` from those byte counts — and between an inner
message and its bucket sit the Double Ratchet's 256‑byte padding, a base64
transport payload wrapped in JSON, the sealed envelope's own JSON, and base64
again. Sent through that whole pipeline, the way `ChatService._sendInner`
sends everything (`protocol/test/sealed_bucket_test.dart`, which now pins
these boundaries), the buckets are:

| shape | inner bytes | bucket |
|---|---|---|
| text, `"ok"` | 74 | 1 024 |
| text, 180 characters | 252 | 1 024 |
| text, 190 characters | 262 | **4 096** |
| text, 900 characters | 972 | **4 096** (table above said 1 024) |
| text, 1 900 characters | 1 972 | 4 096 |
| text, 2 000 characters | 2 072 | **16 384** |
| `pqid` (one ML‑DSA public key) | 2 692 | **16 384** (said 4 096) |
| device list, classical, 1 / 2 / 3 / 4 devices | 489 / 723 / 957 / 1 190 | **4 096** (said 1 024) |
| device list, hybrid certs inline, 1 device | 4 883 | 16 384 |
| device list, hybrid certs inline, 2 / 3 devices | 9 544 / 14 205 | **65 536** (said 16 384) |
| separate message, per‑device `mlsig`, 1 / 2 devices | 4 467 / 8 891 | 16 384 |
| separate message, per‑device `mlsig`, 3 devices | 13 315 | **65 536** (said 16 384) |
| one list‑level `dlpq` (any count) | 4 567 | 16 384 |

The rejected shapes were re‑run as fillers of the byte counts recorded above;
everything else is a real object. Real texts, lists and post‑quantum artefacts
differ by a few bytes from the original fixtures, which changes no bucket.

What this changes:

* **The 1 024 bucket holds one ratchet block** — an inner message of at most
  ~250 bytes, which is a text of at most ~180 characters, a receipt, a
  reaction. A device list has never been in it. **A classical device list is
  a 4 096‑bucket envelope, which is what every text between ~190 and ~1 900
  characters is.** The claim this ADR and ADR 0003 rest on — a device‑list
  update is indistinguishable from an ordinary chat message — holds, for a
  different bucket than either said.
* **The cliff is at three devices, not four.** Per‑device signatures cross
  into 65 536 at the third device, so option (b) leaked a device‑count band at
  a *lower* count than argued here. The decision is unchanged and slightly
  strengthened; nothing in *The argument that actually decides it* depends on
  a size.
* **`pqid` is a 16 384‑bucket envelope, not 4 096.** It is sent early in a new
  conversation, so a new contact is marked by one ~16 KB envelope near its
  start in addition to the periodic `dlpq`. A text of 2 000 characters or more
  is the same size, so "v3 client" is the most the size says; the *timing*
  observation is new and is recorded here rather than argued away. R2 in
  `THREAT_MODEL.md` covers the size.
* ADR 0003's table, `DATA_MAP.md`'s wire‑shape table, `PROTOCOL.md` §18.4
  and §18.9, `AUDIT_SCOPE.md` C23 and the roadmap's 13.1/13.2 entries carried
  the 1 024 figure and are corrected alongside this addendum; R2 in
  `THREAT_MODEL.md` was true as written and now names both chat buckets.

The rule this repository keeps re‑learning applies to its own decision
records: an inference offered where a measurement belongs is a bug, and
this one sat in an *accepted* ADR for two days under a heading that began
with the word "Measured".
