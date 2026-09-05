# Z — Security audit scope (Phase 5.2)

This is the brief for an independent security review of Z, a zero‑trust,
end‑to‑end encrypted messenger. It says what we claim, where each claim is
specified and tested, what is in and out of scope, what we already know is
weak, and how to run everything. It is written so a reviewer can start
without a call. Companion documents: `PROTOCOL.md` (normative wire format,
frozen v1 + the v2 post‑quantum extension), `THREAT_MODEL.md` (what we do
and do not protect against), `adr/0001-key-transparency.md` (the one design
decision that changes the trust model), `SECURITY.md` (disclosure).

## 1. What we are asking for

A design‑and‑implementation review of the cryptographic protocol and the code
paths that carry secrets, against the threat model, with findings ranked and
reproducible. We are **not** asking for a UI/UX review, a code‑quality review
of screens, or a review of the third‑party primitives' internals (Ed25519,
X25519, ChaCha20‑Poly1305, ML‑KEM‑768 implementations in `package:cryptography`
and `package:pqcrypto`) beyond how we *use* them. A short engagement that
covers §4 in depth is more useful to us than a broad one that skims.

## 2. The system in one page

Three components, one operator‑independent trust story:

| Component | Language / size | Role |
|---|---|---|
| `protocol/` (`z_protocol`) | pure Dart, ~3.3 k lines in 13 modules, ~1.9 k lines of tests | Every cryptographic construction: identities, X3DH‑style handshake, Double Ratchet, sealed sender, attachments, accounts/devices/pairing, groups' inner messages, ML‑KEM hybrid + re‑key, device‑list transparency values |
| `app/` | Flutter (Dart), core ~4.6 k lines (`lib/core/`), UI ~3.7 k lines, 13 integration test files (~2.6 k lines) | The orchestrator: encrypted vault, outbox, session/ratchet persistence, multi‑device self‑sync, groups fan‑out, transparency alerts, voice, search, history sync |
| `server/` | Node.js, `server.js` ~830 lines, ~1.9 k lines of tests incl. the clean‑room vector verifier | RAM‑only relay: authenticated mailboxes, sealed‑envelope storage/delivery, push wake, metrics; two‑instance mode via Redis |

Every message is encrypted on a device and decrypted only on the recipient
devices; the relay sees padded ciphertext addressed to a mailbox id and,
since sealed sender, no sender. Identities are exchanged out‑of‑band; there
is no directory, no key server, no server‑side account. Full model:
`THREAT_MODEL.md`.

## 3. Claims to verify

Each claim names where it is specified and what already tests it. We would
like the review to either confirm or break each one.

| # | Claim | Spec | Existing evidence |
|---|---|---|---|
| C1 | The relay (even hostile) cannot read content, learn senders, forge or replay messages, or recover anything after restart. | `PROTOCOL.md` §5, §8, §12; `THREAT_MODEL.md` | `server/test/relay.test.js` (40), sealed‑sender vectors, `app/test/durability_test.dart` |
| C2 | The Double Ratchet is Signal's construction; message keys are single‑use; forward secrecy and classical post‑compromise security hold; out‑of‑order delivery is bounded (512 per chain, 1536 cached). | §4, §5 | `protocol/test/protocol_test.dart`, `ratchet.json` transcript replayed byte‑for‑byte by the Node clean‑room verifier |
| C3 | Concurrent sends/receives on one conversation can never reuse a message index (per‑conversation lock, rollback on persist failure, ack only after vault commit). | app design, `chat_service.dart` header comment | `concurrency_test.dart`, `durability_test.dart` (crash/restart at every await) |
| C4 | Sealed sender hides the sender from the relay; the unauthenticated outer layer cannot be abused for anything worse than a failed decryption. | §8 | `sealed_sender.json`, `protocol/test/sealed_test.dart`, relay tests |
| C5 | Protocol v2 mixes an ML‑KEM‑768 secret into every message key after the first round trip, cannot be downgraded by an active attacker, and v2↔v1 is exactly v1. | §17.1–17.5 | `pq_test.dart` (15), `mlkem768.json` + `pq_ratchet.json` re‑derived by kyber‑py and replayed by Node, `app/test/pq_upgrade_test.dart` |
| C6 | Periodic re‑key gives the PQ layer post‑compromise security; the crossover cannot lose or mis‑decrypt in‑flight messages; unknown generations fail closed. | §17.7 | `pq_test.dart` re‑key group, `pq_rekey.json` (kyber‑py + Node), `app/test/pq_rekey_test.dart` |
| C7 | Device certificates and signed device lists are verified against the account key; a `legacy` record cannot introduce an unsigned device; contacts fan out to exactly the listed devices. | §3 | `protocol/test/multidevice_test.dart`, `multidevice.json` (Node re‑derives signatures) |
| C8 | Pairing: a machine‑in‑the‑middle on the rendezvous produces a different SAS on each screen; the enrollment payload is bound to the channel. | §10 | `pairing.json` (both roles replayed by Node), `pairing_test.dart` |
| C9 | Groups: no shared key; a member removed before a send never receives the key; membership only changes over the admin's authenticated channel. | §11 | `app/test/group_test.dart` |
| C10 | Device‑list transparency: silent enrolment, split views and silent removal are surfaced to the owner and to a contact; an honest addition raises nothing; a rogue that answers a device's request from the root's mailbox is still caught. | §3.6, `adr/0001` | `app/test/devlist_transparency_test.dart`, `devlist_distribution_test.dart` |
| C11 | Plaintext never touches disk: vault cells, attachments, voice capture, search, history sync. | §13, app invariants | `vault_passphrase_test.dart`, `search_test.dart` (stored cells checked), `voice.dart` design |
| C12 | The wire format is frozen: any change to bytes an implementation computes fails CI; compatible extensions are additive only. | §14, `vectors/README.md` | `protocol/test/vectors_test.dart` freeze, Node clean‑room replay (13 suites) |

## 4. Where we would like the most attention

These are the places we think are most likely to hide a real problem, in
rough priority order. Some are known trade‑offs we want challenged rather
than bugs we expect.

1. **X3DH without server prekeys** (§4). The responder's long‑term X25519
   key stands in for the signed prekey, so the *first* message of a session
   has no ephemeral contribution from the responder. We rely on the DH
   ratchet from the first reply and on the PQ mix thereafter. Is anything in
   §4/§5 weaker than we state because of this substitution? Is the AD
   binding (initiator key first) sufficient against identity misbinding?
2. **Session convergence** (`session.dart` `_converge`). Both sides may open
   a session simultaneously; the designated‑initiator rule picks one. Can an
   attacker who can delay/reorder envelopes force the two sides onto
   different sessions, or make a stale session decrypt something it should
   not? Related: `UnknownSessionException` handling and the reset `hello`.
3. **Sealed sender as the *only* sender attribution** (§8). The relay no
   longer stamps a sender; authenticity is entirely the inner layer's. We
   believe a forged `f` can only cause a dropped envelope. Confirm there is
   no path (chunks, self‑sync, pairing rendezvous frames) where an
   unauthenticated `f` is acted on before inner authentication.
4. **The PQ hybrid's key schedule** (§17.1–17.3, `pq.dart`, `ratchet.dart`).
   `mk' = HKDF(ikm = mk, salt = K, info = "Z-PQ-MK-v2")`. Is the mix in the
   right place (message key rather than root chain), and does the header
   binding (`pq`, `pqg`, `pqct` in the AAD) close every downgrade/strip path?
   The Dart ML‑KEM is best‑effort constant‑time — how much does that matter
   in this hybrid?
5. **Re‑key crossover** (§17.7). One previous generation is retained; a
   message tagged with an older generation is rejected. Is there a reordering
   the interval does not dwarf (e.g. long offline queues) that loses
   messages, and can an attacker exploit generation tags to cause a
   desynchronisation?
6. **Device‑list transparency rules** (§3.6). The grace‑period logic and the
   "root regression" rule are our own design. Look for false negatives
   (an attacker sequence that keeps every party consistent) and for false
   positives an attacker can *provoke* to train users to dismiss alerts.
7. **Self‑sync as a trust channel** (§9). Own devices accept `acct`
   (device list), `hist` (history replay) and mirrors over their pairwise
   ratchet. What can a compromised *linked* device (no account root) do to
   the primary or to other linked devices through these envelopes?
8. **Vault and keys at rest** (`vault.dart`, §13). Key hierarchy (keystore ⟶
   optional passphrase ⟶ per‑cell XChaCha20‑Poly1305), the Argon2id backup
   KDF parameters (m = 19456 KiB, t = 2, p = 1), the keystore fallback file,
   and what the app writes to temp/log locations.
9. **Relay robustness** (`server.js`). RAM caps per mailbox, envelope size
   cap (1,000,000 chars), dedupe/ack semantics, push‑token expiry,
   two‑instance coordination (Redis kick/flush), authentication
   challenge/response — with a view to exhaustion and cross‑mailbox effects.
10. **Groups without a group key** (§11). Membership is admin‑asserted;
    invites carry every member's bundle. Look at what a malicious member or
    a malicious *former* member can do (replay of old invites, version
    games) and at the attachment fan‑out's key handling.

## 5. In scope / out of scope

**In scope:** everything under `protocol/`, `app/lib/core/`, `server/`
(excluding `server/test/vectors.test.js`, which is a verifier, not product
code), the spec and vectors, the Android build's key/permission handling as
it affects the vault, and the CI verification chain. Platforms: Android and
Linux desktop builds (verified in CI); Windows and macOS build but are
unsigned; iOS is not built yet.

**Out of scope:** UI layout and accessibility; third‑party primitive
implementations (report them upstream, but tell us); the website and store
listings; the Firebase push transport's own security (we send it no
content); social engineering of the out‑of‑band code exchange (documented as
unsolvable in the threat model, but do challenge the safety‑number and SAS
derivations themselves).

## 6. Known limitations we are not hiding

- Metadata: the relay learns which mailboxes are active, when, and in which
  padded size bucket. Sealed sender removes senders, not activity.
- The first message of a session, the PQ offer and anything before the
  first round trip are classical (§17.5).
- A stolen account root is the account until detected; transparency makes
  the enrolment visible, it does not prevent it (§3.6, `adr/0001`).
- No public transparency log yet (`adr/0001` 7.7b is deferred until there is
  an operator committed to durable infrastructure).
- Attachments are not replayed to a newly linked device (the sender does not
  retain per‑file key material); the search index is not persisted (search
  decrypts in memory every time).
- ML‑KEM‑768 in pure Dart is not audited for constant‑time behaviour.

## 7. Artifacts and how to run them

```
# Protocol library: 84 tests incl. the vector freeze
cd protocol && dart test

# Relay: 40 tests incl. the clean-room vector replay (13 suites, no shared code)
cd server && npm test

# ML-KEM values re-derived by an unrelated FIPS 203 implementation
pip install kyber-py==1.2.0 && python3 protocol/tool/verify_mlkem.py

# App: 13 test files, most driving real clients through the real relay
# (each spawns its own relay process; node must be on PATH)
cd app && flutter test

# Regenerate vectors (a diff after regeneration means the protocol changed)
cd protocol && dart run tool/gen_vectors.dart
```

`docs/vectors/README.md` explains the vector conventions; every random draw
the reference implementation made is recorded next to the output it produced,
so a third implementation can be checked without any of our code.

Test vectors and both independent verifiers run on every CI push
(`.github/workflows/build.yml`), alongside the Android and Linux builds.

## 8. What we would like back

- Findings with severity (we suggest Critical / High / Medium / Low /
  Informational), a reproduction, and where possible a suggested fix.
- An explicit statement per claim in §3: confirmed, confirmed with caveats,
  or broken.
- A short note on anything in §4 the review did not reach, so we know what
  remains unreviewed.

We will fix findings, publish the report and our responses (`ROADMAP.md`
5.3), and credit the reviewers unless they prefer otherwise. Coordinated
disclosure and contact details: `SECURITY.md`.

## 9. Codebase map

```
protocol/lib/src/
  identity.dart            Ed25519/X25519 identities, routing ids, contact codes, safety numbers
  session.dart             X3DH-style handshake, sessions, convergence, PQ offer/accept, re-key
  ratchet.dart             Double Ratchet, header encoding (incl. pq/pqg/pqct), PqState
  pq.dart                  ML-KEM-768 wrapper, message-key mix
  sealed.dart              sealed-sender envelopes and size buckets
  attachments.dart         per-file keys, chunk AEAD, chunking
  messages.dart            inner message model (kinds, dl/pdl, dlrm, voice members)
  multidevice.dart         accounts, device certificates, signed device lists, fingerprint
  multidevice_session.dart per-device fan-out sessions
  pairing.dart / pairing_relay.dart   enrollment ceremony (SAS) and its relay transport
  relay_client.dart        WebSocket client + challenge/response auth
  util.dart                RNG (with the zone-scoped vector override), KDF/padding helpers
app/lib/core/
  chat_service.dart        orchestrator (see the invariants in its header comment)
  device_sync.dart         self-sync envelopes (out/in/ping/acct/acctreq/hist)
  vault.dart               encrypted SQLite vault, keystore, passphrase, blobs
  transport.dart           relay link with backoff
  voice.dart               in-memory WAV capture wrapper
  backup.dart              identity backup (.zid)
server/server.js           the relay
```
