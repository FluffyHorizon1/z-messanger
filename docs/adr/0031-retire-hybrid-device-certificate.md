# ADR 0031 — Retire the dormant hybrid device certificate (18.4)

**Status:** Accepted (2026‑10‑16). Resolves roadmap 18.4, "decide the dormant
hybrid certificate: ship it or delete it."

## Context

`HybridDeviceCertificate` (`protocol/lib/src/identity_v3.dart`) is a device
certificate carrying BOTH of an account's signatures — Ed25519 and ML-DSA-65 —
over the identical signing input, so that a quantum adversary able to forge
Ed25519 but not ML-DSA still cannot attest that a device belongs to an account.
It has existed since 13.1 (§18.1, §18.4) and is fully specified, implemented
and vectored. It is also **constructed nowhere in shipped code**: only the
vector generator and unit tests build one. ADR 0010 named it for exactly this
reason — "an unused signed object in a crypto library is a loaded gun; it is how
the reviewer found the [device-list] hole, by looking for what covers
`deviceXPub` and finding the one class that does, unused" — and left its removal
as deliberate later work ("Finnian can fully drop both later").

Its original role — a hybrid cert **per device, inline in the device list** —
was rejected twice:

- **ADR 0003:** a per-device hybrid entry is 5 389 bytes; a device-list update
  carrying them leaves the 1 024/4 096-byte sealed-sender bucket ordinary chat
  occupies for the 16 384/65 536 buckets almost nothing else does, telling the
  relay when an account changes its device set and roughly how many devices it
  has — a new metadata leak introduced by a phase meant to strengthen
  authentication.
- **ADR 0004 / ADR 0010:** per-certificate halves do not authenticate the
  **set**. Given a genuine hybrid list, an adversary who forges Ed25519 presents
  a subset — forge the classical list signature, copy each surviving
  certificate's genuine ML-DSA half untouched — and an honest device is silently
  excluded. Only one signature over the whole list catches that.

That whole-list signature is what shipped instead: `HybridDeviceListSignature`
(§18.9), the account's ML-DSA-65 over the device list, widened by ADR 0010 to
cover each device's X25519 ratchet key and id (the v2 input) and carried v2-only
(`sig3`) once every reader can read one (ADR 0029, 18.5–18.6). With 18.5–18.7
landed, the post-quantum device→account binding the hybrid certificate was
reached for is delivered on the device-list path — and delivered **better**,
over the set rather than per certificate. The per-certificate form has no
remaining role.

## Decision

**Delete `HybridDeviceCertificate`.** Remove the class, the generator code that
builds its standalone vector records, and its unit tests; regenerate the
`device_cert_v3` vector so the dormant records drop out while the live
device-list-signature and safety-number-v2 records it also holds are untouched;
and update the documents that name it. §18.4 is rewritten to record that the
hybrid **device-list signature** (§18.9), not a per-certificate hybrid, is how
v3 binds devices post-quantum.

Nothing a client constructs, sends, stores or verifies changes: the object was
already built by nothing but tests and vectors, so this removes trusted-base
attack surface and a standing misstatement of the system's shape, and changes
no wire behaviour. It is not a protocol-version event (no v3 form that any
client emits is altered or removed from the wire).

## Alternatives rejected

- **Ship it (wire it into a live path).** Into the device list: reopens the
  ADR 0003 size leak and the ADR 0004 subset attack — already rejected. Into
  enrollment only: enrollment is a trusted local pairing flow, so a per-device
  hybrid attestation there buys almost nothing, and the object would still be
  "used" by nothing a contact verifies. Neither justifies keeping a signed
  crypto primitive in the trusted base.
- **Keep it dormant, documented.** Leaves the loaded gun ADR 0010 flagged, for
  a primitive whose one conceivable future use (below) is a separate phase that
  will specify its own form when it has an ADR and a threat to answer.

## The one residual, and where it belongs

The single device certificate carried inline in a v3 **contact code** (§18.2,
§18.7) is verified Ed25519-only: a CRQC that forges Ed25519 could, present at
or intercepting an out-of-band code exchange, bind its own device to a victim's
account on the scanned-code path. This is the already-accepted THREAT_MODEL R4
("a contact code (QR) is authenticated classically end to end"), and it is **not**
closed by keeping a dormant, un-wired certificate — closing it needs a wire
mechanism of its own. Its home is **phase 44 (post-quantum for the classical
surfaces)**, which already scopes hybrid keys for requests, CONNECT, pairing and
the sealed outer and needs its own ADR. Retiring the dormant class does not
change R4's status; phase 44 will decide the scanned-device binding, choosing a
form then rather than inheriting a per-certificate one rejected for the list.

## Consequences

- `protocol/lib/src/identity_v3.dart`: the class is gone; `HybridDeviceListSignature`
  (live) is untouched.
- `protocol/tool/vectors.dart`: stops emitting the standalone hybrid-cert
  records; the `device_cert_v3` vector is regenerated and keeps its live
  device-list-signature and safety-number-v2 records byte-for-byte. The suite
  is generated from one deterministic DRBG, so the draws the two certificates
  consumed are kept, built into nothing, and every later value is unchanged.
- `protocol/test/identity_v3_test.dart`: the hybrid-cert cases are removed; the
  device-list-signature and safety-number cases stay.
- The Node clean-room replay (`server/test/vectors.test.js`) drops its checks
  of the standalone certificate. It and `protocol/tool/verify_mldsa.py` — which
  never read those records — keep re-deriving the live device-list ML-DSA
  signature, the artefact phase 13's exit criterion rests on.
- Docs updated: PROTOCOL §18.4 (retitled "Device certificates under v3"),
  AUDIT_SCOPE claim C17, the vectors README, this ADR, and retirement notes on
  ADR 0004 and ADR 0010 and in the ADR index; ROADMAP 18.4 marked resolved.
- `grep -r HybridDeviceCertificate` finds only this ADR and the two it amends.
