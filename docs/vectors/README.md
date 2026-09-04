# Z protocol test vectors

Known‑answer tests for every construction in [`../PROTOCOL.md`](../PROTOCOL.md).
Each `v<N>/` directory pins one frozen protocol version. Bytes an existing
implementation computes are never changed in a frozen directory — a normative
change produces a new directory (PROTOCOL.md §14). Compatible extensions (a
new inner kind, a new optional member, a new derived value) may *add* entries
to a frozen file; the freeze test then pins the additions too.

| File | Covers | Spec |
|---|---|---|
| `identity.json` | seeds → Ed25519/X25519 keys, routing ids, binding signature, `zc1.` contact codes, safety numbers, relay auth challenge/response | §2, §12.1 |
| `handshake.json` | X3DH‑style `SK`, `AD`, session id | §4 |
| `ratchet.json` | a complete two‑party Double Ratchet transcript (6 messages, 3 DH ratchet steps, one out‑of‑order delivery) with every intermediate key and state | §4, §5 |
| `sealed_sender.json` | `zs1.` envelopes at four sizes (including both sides of the 1024‑byte bucket boundary) | §8 |
| `attachments.json` | chunk nonces (incl. an index above 2³²), AEAD, chunk payloads, chunking | §7 |
| `multidevice.json` | device certificates, `zc2.` account code, signed device list (unsorted input) and its transparency fingerprint, legacy mapping | §3 |
| `pairing.json` | pairing code text, rendezvous, relay identities, channel key, SAS, sealed enrollment | §10 |
| `inner_messages.json` | the plaintext encoding of every inner kind (incl. `dlrm`) and the `dl`/`pdl` transparency members, plus the self‑sync envelope | §6, §9, §3.6 |

`v2/` (post‑quantum hybrid, §17):

| File | Covers | Spec |
|---|---|---|
| `mlkem768.json` | ML‑KEM‑768 known answers from seeds: `KeyGen_internal(d,z)`, `Encaps_internal(ek,m)`, `Decaps`, implicit rejection | §17.1 |
| `pq_ratchet.json` | the nine‑step upgrade transcript: hello, `pqek` offer, encapsulation, first mixed message with `pqct`, mixed reply, steady state | §17.2–17.3 |
| `pq_rekey.json` | the periodic re‑key transcript: generation‑0 establishment, rotation to generation 1 (`pqg`, second encapsulation), a delayed old‑generation message that still decrypts, the retained old secret | §17.7 |

## Conventions

* Byte strings are lowercase hex. Strings that are literally on the wire —
  contact codes, envelopes, transport payloads, safety numbers — are given
  verbatim, and their JSON form is often given alongside (`*_json`) so a
  parser can be checked separately from the base64 wrapper.
* Every random value the reference implementation drew is recorded next to
  the output it produced (`*_seed`, `nonce`, `random_draws`). Feed those in
  place of your RNG and your implementation must reproduce the outputs
  exactly; the `ratchet.json` `transcript` array gives the exact sequence of
  encrypt/decrypt operations and who performs each.
* Intermediate values (`dh1`, `sk`, `ck_before`, `mk`, `root_key_1`, …) are
  there for debugging a divergence; only the final outputs are normative.

## Verifying

Two independent verifiers run in CI:

```
cd protocol && dart test test/vectors_test.dart   # reference implementation reproduces the files bit-for-bit,
                                                  # then consumes them through the public API only
cd server   && node --test test/vectors.test.js   # clean-room Node.js implementation (Node crypto only,
                                                  # no shared code) re-derives every vector from PROTOCOL.md
pip install kyber-py==1.2.0 && python3 protocol/tool/verify_mlkem.py
                                                  # v2: ML-KEM-768 values re-derived by an independent
                                                  # FIPS 203 implementation (kyber-py)
```

The Node file is deliberately self‑contained (~800 lines including an
HChaCha20 for XChaCha20‑Poly1305) and is a reasonable starting point for a
third implementation.

## Regenerating

```
cd protocol && dart run tool/gen_vectors.dart
```

The generator replaces the library's CSPRNG with a seeded splitmix64 DRBG via
a zone‑scoped hook (`randomOverrideKey` in `lib/src/util.dart`) that production
code never sets, and asserts the library's observable state against the
formulas in the spec while it runs. Output is deterministic; a diff after
regeneration means the protocol changed.
