# ADR 0017 — Mixed-version device lists: hold the fingerprint and ML-DSA at v1 while v1 signing continues

**Status:** **Accepted** (2026‑09‑19) — built (3.7.6). Amends ADR 0010.
**Decides:** what a current client reports as a device list's fingerprint, and
what input its ML‑DSA covers, while clients that predate ADR 0010 are still in
the field.

## Context

ADR 0010 (shipped 3.6.2) made the device‑list signature and its fingerprint
cover each device's X25519 ratchet key, not only its Ed25519 key and the
version — the **v2** input. To keep pre‑0010 contacts verifying, the migration
(`_migrateDeviceListToV2`) **dual‑signs**: a v1 `sig` over the old input and a
v2 `sig2` over the new one, and bumps the list version.

That left a field defect — a P0, reproduced by execution 2026‑09‑19 and present
from 3.6.1 through 3.7.5. A current client, seeing `sig2`, reported the **v2**
fingerprint and signed its account ML‑DSA over the **v2** input. A client still
on 3.5.7 **accepts** that list — the v1 `sig` is what admits it — and then
computes the **v1** fingerprint and verifies the ML‑DSA over the **v1** input,
because it has never heard of v2. Same list, same version, two fingerprints:

```
updated client fingerprint:  147d…   (v2)
3.5.7  client fingerprint:   bf7e…   (v1)   → FINGERPRINTS AGREE: False
```

A fingerprint disagreement at the same version is the one thing each side is
built to treat as an attack. The 3.5.7 contact shows *"their devices disagree
about their device list… one of them may not be theirs"*; the updated one, after
its grace, shows *"a device list your device never issued… **reset your identity
now**"* — it tells the user to destroy their account over a version skew. The
ML‑DSA half fails the same way, more quietly: assurance stays classical and a
false `pqSignatureMissing` is raised. It reaches nearly every account, because
`ktOwn()` gives even a single‑device account a baseline list to migrate.

The v1 signing input (`z‑devlist‑v1:`) is frozen and byte‑identical in 3.5.7 and
HEAD, so a current client can compute exactly what an old one does; the fix uses
that.

## Decision

**A device list reports the v1 fingerprint, and its ML‑DSA covers the v1 input,
for as long as a v1 signature is being produced for it — which today is always,
because every list is dual‑signed.** `SignedDeviceList.fingerprint()`
(`multidevice.dart`) and `_devlistSigningInputFor` (`identity_v3.dart`) both drop
their `sig2 != null ? v2 : v1` switch and return v1. Both sides of every mixed
pair then compute the same v1 fingerprint over the same bytes, and a 3.5.7 client
verifies the ML‑DSA it is handed. No wire format changes; no version handling is
added; the change is three lines of policy plus the tests and vectors that
encoded the old behaviour.

The migration is therefore **two‑staged**:

- **Stage 1 (this release).** Dual‑sign (`sig` + `sig2`) but fingerprint and sign
  the ML‑DSA at **v1**. The v2 signature is still produced and still enforced —
  see below — it just does not drive the fingerprint or the ML‑DSA input yet.
- **Stage 2 (a later release, once the v1 population is gone).** Sign **v2‑only**
  (no v1 `sig`), at which point `fingerprint()` and `_devlistSigningInputFor`
  return v2 for those v2‑only lists and the ratchet‑key commitment takes full
  effect. The downgrade floor already built for this (`cdev_sigfloor_`,
  `chat_service.dart`) is what makes refusing a re‑introduced v1 list safe then.
  This ADR does not build stage 2.

## The cost, stated plainly

Holding the **fingerprint** at v1 is close to free: the classical **v2**
signature (`sig2`) must still verify in `SignedDeviceList.verify()` or the list
is refused (`multidevice.dart`, `if (!okV2) return false;`), so a classically
forged ratchet‑key substitution is still caught at admission — the fingerprint is
only the secondary, gossip‑level check.

Holding the **ML‑DSA** at v1 has a real, bounded cost, and it was a deliberate
choice (Finnian, 2026‑09‑19, over dual‑signing the ML‑DSA): against an adversary
who has broken Ed25519 but not ML‑DSA — the §18 premise — the post‑quantum layer
no longer commits to the ratchet keys *during the transition*. This is **not a
regression below the deployed floor**: 3.5.7, the population we are staying
compatible with, never had the v2 PQ commitment at all, and today's v2 ML‑DSA
"works" only between updated clients while false‑alarming at every 3.5.7 contact.
Stage 1 trades a commitment that is broken‑and‑alarming in the mixed field for
one that is uniform and correct, and stage 2 restores the v2 commitment once the
field is uniform. The trade is temporary and reverses cleanly.

## Rejected

- **Don't bump the version in the migration (the doc's first "option 1").**
  Does not work and must not be attempted: re‑signing in place at version N still
  gives the updated client a `sig2`, so it computes v2 at N while the old client
  computes v1 at N. The mismatch moves from N+1 to N; it does not go away. Any fix
  that leaves the fingerprint flipping while v1 clients exist has this shape.
- **Teach old clients to read a mismatch as version skew (option 3).** A 3.5.7
  client is already deployed; it cannot be taught a format it never shipped.
- **Dual‑sign the ML‑DSA (add an `mlsig2` over the v2 input).** Would keep the v2
  PQ ratchet‑key commitment for updated clients *and* let old clients verify the
  v1 `mlsig` — backward‑compatible, since 3.5.7 reads only `mlsig`. Rejected for
  this hotfix: it is a signature‑format addition (~+3.3 KB per list, ML‑DSA‑65)
  and more surface than a P0 fix should carry. It remains the option if the v2 PQ
  commitment must hold through the transition; recorded here so stage 2 can weigh
  it.

## Consequences

- **Wire/relay/ratchet:** unchanged. `sig2` is still produced, still on the wire,
  still enforced in `verify()`. No new message, no version bump to the protocol.
- **Vectors regenerated.** `docs/vectors/v1/multidevice.json` (its reported
  `fingerprint` flips v2→v1; `fingerprint_v1`/`signing_input`/`signing_input_v2`
  are unchanged reference fields), `docs/vectors/v3/device_cert_v3.json` (`ml_sig`
  is now over the v1 input; notes updated), and `docs/vectors/kt/kt_log.json`
  (its embedded fingerprint tracks the multidevice vector). The clean‑room
  verifiers agree: `kt/tools/verify_vectors.py` and `kt/test/vectors.test.js`
  cross‑check the fingerprint against the **v1** signing input now.
- **The missing test is the durable fix.** `protocol/test/mixed_version_devlist_test.dart`
  builds a dual‑signed list with HEAD and asserts (1) it reports the v1
  fingerprint an old client computes, and (2) its ML‑DSA verifies over the v1
  input an old client checks. Both fail on the pre‑fix code — this is the
  reproduction — and it is honest as a single‑tree test because the v1 signing
  input is frozen and byte‑identical to 3.5.7's.
- **Stage 2 is now owed.** The v2 ratchet‑key commitment does not take effect
  until a later release signs v2‑only. That release, and the floor that guards
  it, are tracked against this ADR.

## What was verified

- **Reproduction:** the mixed‑version test fails on pre‑fix code with the exact
  fingerprint/ML‑DSA disagreement; passes after.
- **Full protocol suite** (`dart test`): green, including the updated
  `devlist_v2_test` (a dual‑signed list now keeps the v1 fingerprint; the ML‑DSA
  is held at v1 and the substitution is caught by `verify()`), `transparency_test`
  and `vectors_test`.
- **Cross‑implementation:** `kt/tools/verify_vectors.py` (Python, "344 values
  reproduced or refused") and `kt/test/vectors.test.js` (Node, 78/78) agree with
  the Dart fingerprint.
- **Full app suite:** run on this branch; the migration and the KT compare paths
  now compute v1 throughout.
