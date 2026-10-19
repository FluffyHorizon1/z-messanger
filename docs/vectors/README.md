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
| `multidevice.json` | device certificates, `zc2.` account code, signed device list (unsorted input) and its transparency fingerprint, legacy mapping — and, added beside the dual‑signed list without changing it, `device_list_v2_only`: the same account's list at the next version signed with `sig3` alone (ADR 0017 stage 2), over the v2 content under its own context, whose fingerprint is over that input — with the lists that must be refused: no signature at all; one device's `deviceXPub` replaced under the genuine `sig3`; the dual‑signed list with its `sig` deleted; its `sig2` moved into `sig3`; every other combination of the three signatures; and the valid lists with a signature member added as `null`, which do not parse | §3 |
| `pairing.json` | pairing code text, rendezvous, relay identities, channel key, SAS, sealed enrollment | §10 |
| `inner_messages.json` | the plaintext encoding of every inner kind (incl. `dlrm`, a `ginvite` carrying `owner`/`admins`/`rv`, `gsync`, and the group‑link answer `gjoin` with its go‑ahead tag) and the `dl`/`pdl` transparency members, plus the self‑sync envelope; and `group_list_digests`: for three lists — the two `ginvite`s, and one whose name needs every escape the canonical form has and whose admins and members arrive unsorted — the canonical JSON a list's digest hashes (as text and as bytes) and the digest itself, which ranks two lists at one version — re-derived from §11.1 alone by the relay's clean‑room verifier | §6, §9, §3.6, §11.1, §20.6 |
| `device_pop.json` | `adr/0022`: a device certificate's proof of possession (`pop`) — its input (the context, the account key, the device's two keys, its id) and the DEVICE key's signature over it; `multidevice.json`'s dual‑signed and v2‑only lists with the second device's proof attached, whose signatures and fingerprints are that file's and whose JSON without the member is that file's byte for byte; a `zc2.` code carrying it; another account's list naming the device — without the proof, which verifies and proves nothing, and with the device's genuine proof, which is refused because it names the first account; the six alterations a reader that knows the member refuses (made by the account key, made for another account, the ratchet key or the id changed under a genuine proof, a byte short, a bit flipped), and three that do not parse. A new file: `multidevice.json` is unchanged. Re‑derived by the Node file with its own Ed25519, which also reads every list as a reader from before the member does, and admits each | §3.1, §3.4 |
| `group_state.json` | `adr/0030`, appended as a file of its own: four group lists — one as every client before 0030 writes it, the same list at the next version with two different timers (`tmr`), which §11.1's digest calls equal, and one naming two members at their positions (`e`, entries arriving in the opposite order to the one their positions sort in) with the timer said off — each with its §11.1 digest, the state text `[tmr, positions]` as text and as bytes, and the state digest that ranks the tie; and a `ginvite`, a `gleave` and a `gmsg` carrying the new members. Read back by the client in `group_timers_test` 8 | §6.2, §11.2 |

`v2/` (post‑quantum hybrid, §17):

| File | Covers | Spec |
|---|---|---|
| `mlkem768.json` | ML‑KEM‑768 known answers from seeds: `KeyGen_internal(d,z)`, `Encaps_internal(ek,m)`, `Decaps`, implicit rejection | §17.1 |
| `pq_ratchet.json` | the nine‑step upgrade transcript: hello, `pqek` offer, encapsulation, first mixed message with `pqct`, mixed reply, steady state | §17.2–17.3 |
| `pq_rekey.json` | the periodic re‑key transcript: generation‑0 establishment, rotation to generation 1 (`pqg`, second encapsulation), a delayed old‑generation message that still decrypts, the retained old secret | §17.7 |

`v3/` (hybrid signatures, §13.1 — in progress):

| File | Covers | Spec |
|---|---|---|
| `mldsa65.json` | ML‑DSA‑65 known answers from seeds (`KeyGen_internal(zeta)`, deterministic signing with `rnd = 0^32`, verification, and a one‑byte tamper that must fail), plus the hybrid Ed25519 + ML‑DSA‑65 construction and the 32‑byte contact‑code commitment | §18.1, `adr/0003` |
| `contact_code_v3.json` | the `zc3.` code end to end: identity seeds → keys → binding signature → routing id, the commitment over the ML‑DSA key, the encoded code and its JSON, the `pqid` inner message that delivers the key, and a substituted key that must be refused | §18.2 |
| `contact_code_pqc_sig.json` | `adr/0027`: the code's Ed25519 signature over its post‑quantum commitment (`pqcs`) — the signing input (context, account key, commitment), the signature by the code's own key, the signed codes of a root device and of a linked one, the unsigned code it reduces to without the member (the code every client before 0027 emits), and six alterations that must be refused — re‑derived by the Node file with its own Ed25519 | §18.10 |
| `device_cert_v3.json` | safety number v2 over both key halves, and the account's post‑quantum attestation of its devices: the account's ML‑DSA over its device list, held at the v1 input on a dual‑signed list (ADR 0017), and, added beside it, `device_list_v2_only`: the ML‑DSA over a list signed with `sig3` alone, which is over the v3 input and so refuses the ratchet‑key substitution the stage‑1 signature could not see — and the dual‑signed list with its `sig` deleted, which its own ML‑DSA still covers and which is refused for its shape. The per‑certificate hybrid records the suite first carried were retired with the form (`adr/0031`) | §18.4, §18.5, §18.9 |

`connect/` pins the connect ceremony (PROTOCOL.md §20, `adr/0009`), on the
same terms:

| File | Covers | Spec |
|---|---|---|
| `connect.json` | the code and both renderings, two v3 identities, both ephemerals and commitments, all four frames, the channel key and the eight digits in canonical order — the ceremony as a client before `adr/0020` runs it | §20.2–20.4 |
| `mailboxes.json` | the two per‑role relay mailboxes an invite derives, and their distinctness from every other id the same secret names | §20.5 |
| `group.json` | `adr/0020`: the same four messages with the group bit — `"grp":1` sealed in message 3 and repeated in message 4 — with both reveals' plaintexts and seal nonces, so the member's bytes can be checked, and the ceremony's go‑ahead tag (HKDF‑SHA256 of the channel key, 16 bytes) that its answer carries | §20.3, §20.6 |
| `invite_v2.json` | `adr/0024`: an invite of version 2, bound to its secret — both renderings with their `9` marker, the invite key, both mailboxes and the rendezvous id under the version‑2 contexts, both keyed commitments with their inputs, all four frames with both reveals' plaintexts and nonces, the channel key salted with the invite key, the digits under their own context and the go‑ahead tag — and, beside them, what version 1 computes from the same inputs. The three files above are version 1 and unchanged | §20.8 |
| `invite_v3.json` | `adr/0033` §4: an invite of version 3, hybrid with ML‑KEM‑768 — both renderings with their `8` marker, which neither base32 nor version 2 reads; `inviteKey3`, both mailboxes and the rendezvous id under the version‑3 contexts; two v3 identities, each with its account's ML‑DSA key and its device's sealing key, the inviter's code carrying `sk`; the inviter's fresh ML‑KEM‑768 key (`ek`, message 1) from its seed, and the acceptor's encapsulation to it (`ct`, message 2) with its randomness `m` and `K`; both keyed commitments, each over SHA‑256 of its side's KEM value, with their inputs; all four frames, with their lengths as the relay carries them, and both reveals' plaintexts (`pqk`, `pqseal`) and nonces; the channel key from `dh ‖ K` salted with `inviteKey3`; the digits with SHA‑256(ek ‖ ct) in their info, and the go‑ahead tag — and, beside them, what version 2 computes from the same inputs. Re‑derived by the Node file; the ML‑KEM values by kyber‑py (`verify_mlkem.py`). The four files above are unchanged | §20.9 |

`kt/` pins the transparency log (PROTOCOL.md §19, `adr/0006`) — a service
beside the protocol rather than a version of it, frozen on the same terms.
Generated by `kt/tools/gen_vectors.js` from fixed seeds (Ed25519 signing is
deterministic and the log's clock is fixed, so every byte is a function of
the generator):

| File | Covers | Spec |
|---|---|---|
| `log_tree.json` | the RFC 9162 log tree against the certificate‑transparency‑go reference data: eight leaves, the root at every size, every audit path and every consistency proof for sizes ≤ 8 | §19.3 |
| `map_tree.json` | the depth‑256 sparse map: the empty constants, the root after each of fourteen sets (two are updates), compressed proofs of presence for twelve labels and of absence for two, and four proofs that must fail | §19.2 |
| `kt_log.json` | the log end to end: labels and value keys from account keys, sealed values with their nonces, publish inputs and signatures, leaf inputs and hashes, the head after every publish (and one re‑signed with no growth), consistency proofs, the lookup and history responses as the API serves them, a witness record, and seven cases that must be refused — including a fork signed by the real log key. Alice's first entry seals `v1/multidevice.json`'s real signed list | §19.1, §19.4–19.8 |
| `bucket.json` | lookups by bucket for both logs: the transparency log's and the handle log's answers as served at k = 0, 1 and 8, an empty bucket, a `POST` of three under one head, entries by index with their inclusion proofs, and the answers a reader must refuse (a label left out or added, a version changed, a sibling dropped, a record changed, a time finer than an hour, either log's head in the other's context); and the handle log itself — its publishes byte for byte (canonical records, publish and recover inputs, signatures), its head, and the owner rule's refusals with their status, code and reason — versions that are not the next, a key of small order and the owner's signature with R the identity among them. Read by the Dart reader (`transparency_bucket_test.dart`) too | §19.9, §21.5 |

`backup/` is a storage format rather than a wire format, so it sits outside the
protocol version directories; it is frozen on the same terms
([`../BACKUP.md`](../BACKUP.md)):

| File | Covers | Spec |
|---|---|---|
| `archive.json` | `.zbk` backup: the recovery code (entropy → Crockford base32 → checksum, and a mangled transcription parsed back), the Argon2id KAT, the header, and a complete four‑frame archive with every nonce, AAD rule, ciphertext and tag — plus the two cases that must fail (a frame moved to another index, the wrong code) | `BACKUP.md` §3–§4 |
| `archive_1_1.json` | `.zbk` format 1.1 (`adr/0025`): the same frame layer under a header naming its minor revision (`mv`), one record of each kind 1.1 adds — a linked device's `identity` with its `account` (whose certificate the Node verifier checks with its own Ed25519), `state`, a `contact` with `req`, `kv` and `sids`, `blocked`, `request` — a record of a type no reader knows marked `keep`, and the same header at major version 2, which a reader of this major refuses | `BACKUP.md` §4.1, §5 |

`handles/` pins the protocol half of handles (PROTOCOL.md §21, `adr/0015`),
and public introduction links (§21.9, `adr/0032`), frozen on the same terms;
the handle log (§21.5) and the relay's introduction mailboxes (§21.6) pin
their own halves:

| File | Covers | Spec |
|---|---|---|
| `handles.json` | the grammar — inputs that are handles with their canonical forms, and inputs that are not with the reason, among them Unicode look‑alikes (Cyrillic letters, the Kelvin sign, long s, dotted I, fullwidth forms, Arabic‑Indic digits, a combining accent, invisible spaces) and every reserved nick; labels at the production Argon2id parameters and at four small ones; owner, introduction and recovery keys from seeds — each introduction seed with its X25519 half, `xintro` — with the printed recovery codes and the commitments; claim, update and recover entries with every signing input and signature; twenty‑five owner‑rule histories with their verdicts, twenty‑four of them refusals — versions that are not the label's next, the owner key's update at 2⁵³ − 1 and signatures only a lenient verifier takes (R the identity, S + L) among them; thirty‑six values that are not records, among them every way `intro` and `xintro` can disagree about being null and keys of small order or at or above p; the small‑order values §21.4 refuses; a contact request sealed to `xintro`, with its draws, that the introduction identity opens; proof‑of‑work stamps at 16 and 18 bits over that envelope, with the four a relay refuses and its today‑or‑yesterday window; and an introduction acknowledgement with the four a requester refuses | §21.1–§21.4, §21.7 |
| `intro_link.json` | `adr/0032`, a file of its own — `handles.json` is unchanged: public introduction links from introduction seeds at `pow` 16, 20 and 28 with every intermediate (the keys exactly as §21.3 derives a handle's, the body `u8(pow) ‖ intro ‖ xintro`, its check — the first four bytes of SHA‑256 under `z-intro-link-v1:` — the 96‑character code and the 126‑character link at the default host); six inputs a reader takes (a bare code, the link, a host beginning `i`, a query before the fragment, surrounding whitespace, no scheme) and 125 it refuses, each with the reason it names — a contact code, both invite versions as text and as links, a handle, `zi2.` and `zi10.`, padding, `+` and `/`, 91 and 93 characters, the prefix in capitals and the letters' case, a flipped check, `pow` 15 and 29, and every weak key: all 48 weak Ed25519 spellings as `intro`, and as `xintro` each X25519 value of small order or at or above p with its top bit clear and set, and an honest key with its top bit set; and a request through the `pow`‑16 link, sealed to its `xintro` with its draws, stamped for its mailbox at 16 bits and at a raised 18, and acknowledged under its `intro` and under no other link's. Re‑derived by the Node file from §21.9 alone, its weak keys from the curve | §21.9 |

`intro-key/` pins the introduction key (PROTOCOL.md §8.3 and §12.7, ADR 0033
addendum A), frozen on the same terms; a directory of its own, so every file
above is unchanged:

| File | Covers | Spec |
|---|---|---|
| `intro_key.json` | a device's sealing key (ML‑KEM‑768 from a 64‑byte seed, `ek` and `dk`) and `iks`, Ed25519 by the key its mailbox is the hash of over `"z-intro-key-v1:" ‖ edPub ‖ SHA‑256(ek)`, for a root device, a linked device (its own `ded`, with the account's certificate) and an introduction mailbox (`kintroSeed` = HKDF of its introduction seed under `"z-handle-intro-k-v1"`, 64 bytes, and the pair it makes) — each with its signing input, the entry `ek ‖ iks` a relay keeps, the hint `ready` names it by, `sk` = SHA‑256(ek), and the `ikey` and `ikey_for` frames; FIPS 203 §7.2's modulus check at its edges (a coefficient at q − 1 and at q, the last coefficient at 2¹² − 1, ρ changed, a byte short); the acceptance rule's verdict on nine served entries, each breaking one check — `iks` under another `ed`, over another key, the key and the signature a byte short, a key failing the modulus check under a genuine signature, S + L, the wrong mailbox, a key that misses a code's `sk` and the same entry for a route with no `sk`, which is taken; and contact codes carrying `sk`, root and linked, with their lengths and the codes without it, which are the codes before byte for byte, and three a reader refuses (`sk` with no `pqc`, 31 bytes, not a string). Re‑derived by the Node file with its own Ed25519 and a modulus check written there from FIPS 203; the ML‑KEM values by kyber‑py (`verify_mlkem.py`) | §8.3, §12.7 |

44.1 adds two files (PROTOCOL.md §8.2 and §18.11, ADR 0033 §1 and §5),
frozen on the same terms — `sealed-v2/` a directory of its own, and one file
beside the others in `v3/` — so every file above is unchanged:

| File | Covers | Spec |
|---|---|---|
| `sealed-v2/sealed_v2.json` | `zs2.`: the recipient device's X25519 key and its sealing key from seeds (`seal_seed`, `ek`, `dk`, `sk`), and an envelope in every bucket — 1 024 at a short payload and at its exact fit, 4 096 one byte past that, then 16 384, 65 536, 262 144 and 1 146 880 — each with its draws (`eph_seed`, `m`, `nonce`), the KEM ciphertext and `K`, the X25519 agreement, the HKDF input and key, the box's SHA‑256, the MAC, and its length beside that of the `zs1.` envelope of the same payload, 1 450 characters shorter; the four smallest verbatim, the three largest by length and SHA‑256 with their payloads as a fill. And what a recipient refuses: the KEM ciphertext swapped for another encapsulation to the same key, stripped and relabelled `zs1.`, stripped under `zs2.`, a genuine `zs1.` envelope's body under `zs2.` and a `zs2.` body under `zs1.`; and the envelope opened with the recipient's X25519 seed and another device's sealing key — ADR 0033's classical adversary — with the implicit‑rejection `K` that gives, and the key `K = 0` would | §8.2 |
| `v3/device_attestation.json` | `pqdc`: an account (Ed25519 and ML‑DSA seeds) and two devices of it, the root and a linked one with its certificate, each with its sealing key from its seed, `sk`, the 143‑byte signing input and the deterministic (`rnd = 0^32`) signature; the eight a verifier refuses — `dx`, `ded`, `acct` and the sealing key each swapped under the root's genuine `pqdc`, the linked device's `pqdc` offered for the root, the `pqdc` and the sealing key each a byte short, and a forgery under an account key whose Ed25519 half is the genuine one and whose ML‑DSA half is the adversary's; and the wire forms — a `pqid` carrying `pqdc` and the same `pqid` without it, a `pqseal`, `pqs:1` on a text, and four `pqseal`s a reader takes no key from | §18.11 |

The KEM values are re‑derived by kyber‑py (`verify_mlkem.py`), each `pqdc`
reproduced and verified by dilithium‑py (`verify_mldsa.py`), and the rest —
each X25519, HKDF, AEAD and padding step, every envelope and its length, the
signing inputs and the wire forms — replayed by the Node file from
PROTOCOL.md alone.

`pair-v3/` pins device pairing v3 (PROTOCOL.md §10.2, ADR 0033 §3), frozen
on the same terms; a directory of its own, so every file above is unchanged:

| File | Covers | Spec |
|---|---|---|
| `pairing_v3.json` | the code, its `pairKey`, the rendezvous and both mailboxes under the v3 contexts; the host (an account with its ML‑DSA key) and the new device, with its four draws, its sealing key and `sk`; the fresh ML‑KEM‑768 key the new device offers beside its commitment, from its seed; the keyed commitment over SHA‑256 of that key, with its input; the reply's ephemeral and its encapsulation (`m`, `ct`, `K`); the opening, with `sk`; the channel key from `dh ‖ K` salted with `pairKey`; the eight digits with SHA‑256(ekN ‖ ct) in their info; the sealed enrolment — v2's members without `root`, then `pqdc`, here 3 309 recorded random bytes standing in for the root's attestation, which pairing carries unread — with its nonce; and what v2 computes from the same inputs. Re‑derived by the Node file; the ML‑KEM values by kyber‑py (`verify_mlkem.py`) | §10.2 |

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

The verifiers CI runs — the reference implementation, and independent ones
that share no code with it:

```
cd protocol && dart test test/vectors_test.dart   # reference implementation reproduces the files bit-for-bit,
                                                  # then consumes them through the public API only
cd server   && node --test test/vectors.test.js   # clean-room Node.js implementation (Node crypto only,
                                                  # no shared code) re-derives every vector from PROTOCOL.md —
                                                  # handles' labels too, with an Argon2id and a BLAKE2b written
                                                  # there and checked against RFC 9106 and RFC 7693 first
pip install kyber-py==1.2.0 && python3 protocol/tool/verify_mlkem.py
                                                  # v2 and intro-key: ML-KEM-768 values re-derived by an
                                                  # independent FIPS 203 implementation (kyber-py)
pip install dilithium-py==1.4.0 && python3 protocol/tool/verify_mldsa.py
                                                  # v3: ML-DSA-65 values, the hybrid construction and the
                                                  # device-list signatures, dual-signed and v2-only, by an
                                                  # independent FIPS 204 implementation (dilithium-py)
cd kt && node --test test/vectors.test.js         # the transparency log reproduces docs/vectors/kt bit-for-bit
pip install cryptography && python3 kt/tools/verify_vectors.py
                                                  # and an implementation written from PROTOCOL.md §19 alone
                                                  # (hashlib + cryptography, no shared code) re-derives every value
```

The device‑list values are re‑derived three times over, independently: by
the Node file, by `verify_mldsa.py` and by `verify_vectors.py`. Each rebuilds a
list's signing inputs from the list's own JSON and applies the rule for which
one it commits to — the v1 input while the list carries `sig`, the v3 input
once it carries `sig3` alone (PROTOCOL.md §3.6) — the three shapes a list may
have, and that a signature member which is present is a signature, rather
than reading the recorded field, so a vector that named the wrong input, a
list with its `sig` deleted or one with a `null` member would be caught.

The Node file is deliberately self‑contained (~800 lines including an
HChaCha20 for XChaCha20‑Poly1305) and is a reasonable starting point for a
third implementation.

## Regenerating

```
cd protocol && dart run tool/gen_vectors.dart
cd kt && node tools/gen_vectors.js               # docs/vectors/kt
```

The generator replaces the library's CSPRNG with a seeded splitmix64 DRBG via
a zone‑scoped hook (`randomOverrideKey` in `lib/src/util.dart`) that production
code never sets, and asserts the library's observable state against the
formulas in the spec while it runs. Output is deterministic; a diff after
regeneration means the protocol changed.
