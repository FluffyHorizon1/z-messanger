# Z — Security audit scope (phase 5.2, prepared 14.3)

This is the brief for an independent security review of Z, a zero‑trust,
end‑to‑end encrypted messenger. It says what we claim, where each claim is
specified and tested, what is in and out of scope, what we already know is
weak, and how to run everything. It is written so a reviewer can start
without a call. Companion documents: `PROTOCOL.md` (normative wire format,
frozen v1, the v2 post‑quantum confidentiality extension and the v3 hybrid
identity layer), `WHITEPAPER.md` (the argument rather than the format — read
this first if you want to know what is claimed before how it is encoded),
`THREAT_MODEL.md` (what we do and do not protect against, and a residual‑risk
register of what is left), `DATA_MAP.md` (every piece of data, where it lives
and who can read it), `BACKUP.md` (the `.zbk` archive format and what it
deliberately refuses to restore), `adr/` (the three design decisions worth
arguing with — `0001-key-transparency.md` is the one that changes the trust
model; 0002 is a reserved number, not a suppressed record), `VDP.md` and `SECURITY.md` (disclosure, and the safe harbour that
covers you while you look).

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
| `protocol/` (`z_protocol`) | pure Dart, ~4.7 k lines in 17 modules, ~3.2 k lines of tests (150) | Every cryptographic construction: identities, X3DH‑style handshake, Double Ratchet, sealed sender, attachments, accounts/devices/pairing, groups' inner messages, ML‑KEM hybrid + re‑key, device‑list transparency values |
| `app/` | Flutter (Dart), core ~8.4 k lines (`lib/core/`), UI ~6.0 k lines, 34 test files (~9.5 k lines), most driving real clients through a real relay | The orchestrator: encrypted vault, outbox, session/ratchet persistence, multi‑device self‑sync, groups fan‑out, transparency alerts, voice, search, history sync |
| `server/` | Node.js, `server.js` ~840 lines, ~2.4 k lines of tests (50) incl. the clean‑room vector verifier | RAM‑only relay: authenticated mailboxes, sealed‑envelope storage/delivery, push wake, metrics; two‑instance mode via Redis |

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
| C1 | The relay (even hostile) cannot read content, learn senders, forge or replay messages, or recover anything after restart. | `PROTOCOL.md` §5, §8, §12; `THREAT_MODEL.md` | `server/test/relay.test.js` (40), `server/test/sealed.test.js` (5), `server/test/load.test.js` (7 — oversized envelopes, malformed frames and a client swarm rejected rather than absorbed), `server/test/ha.test.js` (the same guarantees with two instances sharing one Redis), `protocol/test/relay_integration_test.dart`, sealed‑sender vectors, `app/test/durability_test.dart` |
| C2 | The Double Ratchet is Signal's construction; message keys are single‑use; forward secrecy and classical post‑compromise security hold; out‑of‑order delivery is bounded (512 per chain, 1536 cached). | §4, §5 | `protocol/test/protocol_test.dart`, `ratchet.json` transcript replayed byte‑for‑byte by the Node clean‑room verifier, `app/test/skipped_keys_test.dart` (the 1 536-key cache is stored apart from the hot ratchet state since schema 9 — these prove it survives a restart, is not emptied by a send, and is carried across from a pre-9 vault) |
| C3 | Concurrent sends/receives on one conversation can never reuse a message index (per‑conversation lock, rollback on persist failure, ack only after vault commit). | app design, `chat_service.dart` header comment | `concurrency_test.dart`, `durability_test.dart` (crash/restart at every await) |
| C4 | Sealed sender hides the sender from the relay; the unauthenticated outer layer cannot be abused for anything worse than a failed decryption. The size buckets hold what the documents say they hold, measured through the whole pipeline: a short text and a receipt in 1 024, a device list and a medium text in 4 096, the post-quantum artefacts in 16 384 with texts of 2 000+ characters — and an accepted ADR's bucket column had been inferred from inner sizes until it was (`adr/0004`, addendum). | §8 | `sealed_sender.json`, `protocol/test/sealed_test.dart`, `protocol/test/sealed_bucket_test.dart` (3), `server/test/sealed.test.js` (5 — the relay side, written against the wire format rather than our code) |
| C5 | Protocol v2 mixes an ML‑KEM‑768 secret into every message key after the first round trip, cannot be downgraded by an active attacker, and v2↔v1 is exactly v1. | §17.1–17.5 | `pq_test.dart` (15), `mlkem768.json` + `pq_ratchet.json` re‑derived by kyber‑py and replayed by Node, `app/test/pq_upgrade_test.dart` |
| C6 | Periodic re‑key gives the PQ layer post‑compromise security; the crossover cannot lose or mis‑decrypt in‑flight messages; unknown generations fail closed. | §17.7 | `pq_test.dart` re‑key group, `pq_rekey.json` (kyber‑py + Node), `app/test/pq_rekey_test.dart` |
| C7 | Device certificates and signed device lists are verified against the account key; a `legacy` record cannot introduce an unsigned device; contacts fan out to exactly the listed devices. | §3 | `protocol/test/multidevice_test.dart`, `multidevice.json` (Node re‑derives signatures) |
| C8 | Pairing: a machine‑in‑the‑middle on the rendezvous produces a different SAS on each screen; the enrollment payload is bound to the channel. | §10 | `pairing.json` (both roles replayed by Node), `protocol/test/pairing_test.dart`, `protocol/test/pairing_relay_test.dart` (the rendezvous transport itself) |
| C9 | Groups: no shared key; a member removed before a send never receives the key; membership only changes over the admin's authenticated channel. | §11 | `app/test/group_test.dart`, `app/test/group_fanout_test.dart` (the fan-out is recorded before it is performed, so a send interrupted part-way is resumed rather than silently dropping its remaining recipients — and members already served are not served twice) |
| C10 | Device‑list transparency: silent enrolment, split views and silent removal are surfaced to the owner and to a contact; an honest addition raises nothing; a rogue that answers a device's request from the root's mailbox is still caught. | §3.6, `adr/0001` | `app/test/devlist_transparency_test.dart`, `devlist_distribution_test.dart` |
| C11 | Plaintext never touches disk: vault cells, attachments, voice capture, search, history sync. The biometric pass key opens the vault only through the OS prompt (on Android the keystore enforces that itself), is bound to the passphrase salt, and is removed with the feature. | §13, app invariants | `vault_passphrase_test.dart` (pass‑key path), `app_lock_test.dart` (incl. bound‑store cases), `lock_screen_test.dart`, `search_test.dart` (stored cells checked), `app/test/voice_test.dart` (3 — a voice note is an ordinary sealed attachment, driven through the real relay), `app/test/attachment_sync_test.dart` (a file mirrored to a linked device stays sealed on the way), `BioKey.kt` review |
| C12 | The wire format is frozen: any change to bytes an implementation computes fails CI; compatible extensions are additive only. | §14, `vectors/README.md` | `protocol/test/vectors_test.dart` freeze, Node clean‑room replay (15 suites) |
| C13 | A backup archive restores history onto a wiped device without ever restoring session state; a wrong recovery code, a truncated file or a moved frame all fail closed with no oracle; the restored device re‑handshakes, including the post‑quantum layer, rather than silently downgrading; what was queued for it while it was gone is reported as unreadable — once per episode, with a count, not once per envelope — and never silently dropped. | `BACKUP.md` | `app/test/backup_test.dart` (round trip, fail‑closed, schema compatibility), `app/test/restore_notices_test.dart` (4 — the notice and the re‑opening hello, offline), `app/test/backup_store_test.dart` (11 — where an archive is written and by whom, checked for every platform rather than the one under test), `app/test/restore_test.dart` (4 — one restore path for both `.zbk` and the older `.zid`), `protocol/test/archive_test.dart`, `backup/archive.json` replayed by Node |
| C14 | One account on several devices: each device has its own routing id and its own ratchets, so two devices never contend for a mailbox and never share a chain; the safety number is anchored to the account key and does not move when a device is added or removed; a contact offline for the whole enrollment still learns the new device and fans out to it. | `PROTOCOL.md` §2.5, §3 | `app/test/multidevice_test.dart`, `protocol/test/multidevice_session_test.dart` (6 — the per-device fan-out sessions underneath, at the protocol layer), `devlist_distribution_test.dart`, `devlist_transparency_test.dart`, `history_sync_test.dart`, `app/test/attachment_sync_test.dart` |
| C15 | Hybrid signatures (v3, in progress): a signature verifies only if BOTH the Ed25519 and the ML-DSA-65 halves verify over identical bytes; a stripped half does not parse at all, so a downgrade is not expressible; an identity stays derivable from two 32-byte seeds. | §18.1, `adr/0003-pq-identity-qr.md` | `protocol/test/pqsign_test.dart` (11), `v3/mldsa65.json` re-derived by dilithium-py and structurally replayed by Node |
| C16 | A contact code carrying a commitment stays QR-sized (~370 bytes) while binding a 1952-byte post-quantum key: the key is delivered in-band and refused unless it matches the commitment carried by the scanned code. A v3 code with the commitment stripped is refused rather than treated as a classical one, and a scanned identity's assurance state is never reported as hybrid before the key has arrived and matched. | §18.2, §18.3 | `protocol/test/identity_v3_test.dart` (10), `v3/contact_code_v3.json` replayed by Node with its own Ed25519 and SHA-256 |
| C17 | A device certificate verifies only if BOTH the account's Ed25519 and ML-DSA-65 signatures check out over identical bytes; a certificate whose classical half is genuine but whose post-quantum half attests to a different device is rejected, and a stripped one does not parse. A v1 legacy record cannot be presented as post-quantum verified. Safety number v2 covers both key halves, is anchored to the account key, and can never coincide with a v1 number for the same pair. | §18.4, §18.5 | `protocol/test/identity_v3_test.dart` (19), `v3/device_cert_v3.json` replayed by Node, which confirms independently that the forgery passes a classical-only check |
| C18 | In the app: a scanned code carrying a commitment leaves a contact `pendingPostQuantum`, and only a delivered ML-DSA key that matches the commitment makes it `hybrid`; a substituted key is refused and surfaced rather than absorbed, and the safety number never moves to one derived from an unverified key. A backup carries the post-quantum seed, so a restored device is the same identity rather than a mismatch every contact would read as an attack. | §18.2, §18.5, §18.6 | `app/test/pq_identity_test.dart` |
| C19 | An account has ONE post-quantum identity across its devices: a linked device speaks for the account's key rather than deriving its own, a device enrolled before v3 shows a classical identity rather than inventing one, and a device that cannot honestly commit to the account key emits a code with no commitment rather than a mismatched one. Every device of an account converges on the same safety number for the same contact, including a device linked after that contact's key was already exchanged. | §10, §18.2, §18.5 | `app/test/multidevice_test.dart` (linked-device identity, safety-number stability) |
| C20 | The one-time safety-number change is presented as an upgrade and never as a fait accompli: the app records which number the user compared, drops the verified state the moment the number differs from it, claims "upgraded" only when what was compared is demonstrably the v1 number for that pair, and reports any other difference as unexplained. A refused post-quantum key is durable state, announced once rather than on every arrival, and shown on the contact screen. | §18.3, §18.5 | `app/test/verification_ux_test.dart` (5), `app/test/pq_identity_test.dart` (upgrade, unexplained change, pre-13.3 backfill, single announcement) |
| C21 | A contact code may name the account it belongs to and prove it: the binding signature verifies against the device key, the certificate against the claimed account key, and the certificate is checked to be FOR the device in that code — so a stranger holding a genuine (public) certificate of that account cannot present it beside their own keys and be scanned as that account. The two members are inseparable, a legacy record cannot anchor a code, and stripping the commitment does not fall back to the device-anchored reading. A code with no account claim keeps its §3.5 meaning, so no existing safety number moves. | §18.7 | `protocol/test/identity_v3_test.dart` (10), `app/test/multidevice_test.dart` (scanning a laptop adds the person; its device list verifies), `v3/contact_code_v3.json` anchored suite replayed by Node with its own Ed25519 |
| C22 | A contact announced by one of the account's own devices is inserted, never merged: an rid already held is left untouched, so a verified name cannot be re-pointed by a device that holds no account root. The routing id must be the hash of the key carried beside it, the §18.7 certificate rules are re-checked rather than trusted, the contact is stored unverified (a tick is evidence of an act the user performed on a particular device, not a fact one device asserts to another), and the device that sent it is recorded and shown. | §18.8 | `app/test/multidevice_test.dart` (propagation; overwrite refused; mismatched routing id dropped — both guards verified by removal) |
| C23 | An account's device list carries an ML-DSA-65 signature over the same bytes Ed25519 covers — the version and the sorted device keys — so a device set cannot be forged, a device cannot be excluded from it, and a version cannot be rolled back by an adversary who has broken Ed25519 alone. Per-certificate post-quantum halves would catch none of those, which is why the signature is over the list. It travels as its own delayed message so the list keeps its padding bucket (4 096, the bucket of a medium chat message — measured; see `adr/0004`, addendum), is held rather than discarded when it arrives before the key that checks it, and a list is reported `classical` until a signature over exactly its version and set has verified. | §18.4, §18.9, `adr/0004` | `protocol/test/identity_v3_test.dart` (8), `app/test/devlist_hybrid_test.dart` (3), `v3/device_cert_v3.json` device-list suite replayed by Node and by dilithium-py, both rebuilding the signing input from the list |
| C24 | Suppression of the device-list signature is detected without accusing an innocent peer: a sender claims, inside the ratchet where whoever dropped the envelope cannot strip it, that it has SENT the signature; a contact whose client never signs its lists makes no such claim and is reported classical without an alert; a claim with no signature behind it is asked about (bounded) before the user is told, so an ordinary dropped connection repairs itself silently; and nothing is ever accepted on the strength of a claim. | §18.9, `adr/0004` | `app/test/devlist_pq_suppression_test.dart` (4, including the cry-wolf case verified by removing the guard), `app/test/verification_ux_test.dart` (the list is a separate claim from the identity) |
| C25 | The shipped binary can be checked against the source. Two release builds of the same commit **on different machines, checked out to the same path**, are byte-for-byte identical — measured across two CI runners on 2026-09-09, every native library and ELF build id matching. The build **path** is part of the recipe and is stated: `libapp.so` and `libdartjni.so` embed the absolute build directory, so a verifier who builds elsewhere sees those two differ and everything else match. (The recipe published with v2.3.8–v2.4.7 named only the directory's *last component*, which was an unmeasured inference; measured on 2026-09-10 it failed, and the release job now reads the exact path out of the artefact. No digest published before that correction could have been matched by its own instructions — an auditor should treat those releases' digests as unverifiable, not as verified.) That leak is bounded by a CI assertion — a seventh path-dependent library fails the build. The app carries no encrypted third-party dependency-metadata blob. A verifier is given a tool that reports precisely what differs rather than a bare pass/fail, and each release publishes a **content digest** — a hash over the zip entries only, which signing does not disturb — so an outside rebuild has one line to compare rather than an 80 MB download to diff. **Not yet done: a rebuild by someone outside the project**, which is the phase-14 exit criterion and cannot be self-certified. | `REPRODUCIBLE_BUILDS.md`, `PROVENANCE.md` | `tool/verify_reproducible.py` and `tool/test_verify_reproducible.py` (11 checks, including a real APK signing block inserted to prove the published content digest survives signing, and a folded-entries archive to prove the digest's encoding is injective); the `reproducible` / `reproducible-compare` jobs in `build.yml`, whose four-way run is the measurement — a vs b for the machine, a vs c for the path, a vs d for locale and timezone |
| C26 | A release names its own origin: each artefact carries a SLSA build provenance attestation, signed keyless through Sigstore and recorded in a public transparency log, so the commit and workflow that produced it are stated publicly and cannot be asserted differently to different people. There are no signing keys to steal. The claim is deliberately **Build L2, not L3** — L3 requires the build to be isolated from the signing material — and there is no in-app updater, so no rollback protection on desktop. | `PROVENANCE.md` | `.github/workflows/build.yml` (`reproducible`, `reproducible-compare`, `release`) plus `tool/check_workflow.py`, which asserts every job that runs a repo script checks one out — written after the first tagged build died on a missing checkout, two steps before it would have attested anything. **The attestation path has still never executed**, so this row remains a design and not yet evidence |
| C27 | A researcher can find out where to report and whether they are safe to look: RFC 9116 `security.txt` served by the relay on both the well-known and the bare path, pointing at a policy that grants safe harbour in writing, states response targets, names what is most worth attacking and what is a documented limit, and says plainly that no bounty is funded. The mandatory `Expires` field is enforced by a test rather than by memory. | `VDP.md`, RFC 9116 | `server/test/security_txt.test.js` (5) — including one that fails the build once the expiry passes |
| C28 | What remains after everything built is written down rather than reconstructed: a sixteen-row residual-risk register naming who is exposed, why each risk remains, what reduces it, and whether it is accepted, deferred or open — including the ones the recent phases created (the 16 KB post-quantum envelope, suppression of the device-list signature, SLSA L2 rather than L3, no desktop rollback protection). A data map covers every vault column, everything the relay holds, and every third party. | `THREAT_MODEL.md` residual-risk register, `DATA_MAP.md` | Cross-checked against `vault.dart` schema 9 — every `contacts` column appears |
| C29 | The argument is written down and falsifiable, not only the wire format: `WHITEPAPER.md` states each claim, the mechanism, why that mechanism rather than the obvious alternative, how a reader checks it independently, and what it does not cover — including a section that lists only what Z does **not** claim. Every mechanism it describes cites the normative section and the test, and it names `PROTOCOL.md` as the authority wherever the two disagree, so a discrepancy is a bug in the whitepaper rather than an ambiguity in the protocol. **A disagreement between this document and the code is itself a finding we want.** | `WHITEPAPER.md` | Every claim section resolves to a `PROTOCOL.md` section and a test named in this table (C1–C28); no mechanism is asserted here that is not specified and tested elsewhere |
| C30 | A vault survives its own history. The schema has moved 1 → 9 across eight phases; a database written by an early build opens on this one with every message present and **every sealed cell byte-identical** — migrations add columns and never rewrite a cell, so no upgrade can quietly re-encrypt (or fail to re-encrypt) stored plaintext. Re-opening an already-migrated vault is a no-op rather than an error, and an archive written at an earlier schema restores while a record type from a *later* one is carried rather than dropped. | `vault.dart` migrations, `BACKUP.md` | `app/test/replies_test.dart` (13, incl. a schema-1 database built by hand and upgraded in place, asserting the stored cells come back unchanged), `app/test/skipped_keys_test.dart` (a pre-schema-9 conversation keeps its out-of-order keys through the upgrade and the first send after it), `app/test/backup_test.dart` (the cross-schema archive cases), `app/test/restore_test.dart` |

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
8. **Vault and keys at rest** (`vault.dart`, `app_lock.dart`, §13). Key
   hierarchy (keystore ⟶ optional passphrase ⟶ per‑cell
   XChaCha20‑Poly1305), the Argon2id backup KDF parameters (m = 19456 KiB,
   t = 2, p = 1), the keystore fallback file, and what the app writes to
   temp/log locations. The app lock (7.8): the screen lock is a UI gate
   over an open vault — confirm nothing about storage changes and that the
   lock cannot be bypassed from the navigation stack. Biometric unlock
   keeps the Argon2id output under `z_bio_passkey`: on Android (7.8b,
   `android/.../BioKey.kt`) sealed with AES‑GCM under a Keystore key with
   per‑use user authentication authorised through a `CryptoObject` —
   review the `KeyGenParameterSpec` (auth types per API level,
   `setInvalidatedByBiometricEnrollment`), the error → outcome mapping and
   that an invalidated key fails closed; on macOS/Windows a plain keystore
   entry read after the app's own prompt, documented as making the
   passphrase a UI gate there. On all platforms confirm the entry is
   deleted on disable / passphrase removal, re‑sealed on passphrase change,
   and that a stale entry fails closed. Schema 2 (8.1) adds `reply_to` to
   `messages` in the clear — deliberately, since `mid`/`rid` already are —
   plus `edited_ms`/`deleted` and a `reactions` table whose emoji are sealed;
   confirm the migration is additive and that `rt` is resolved scoped to one
   conversation (§6.4). Schema 3 adds `forwarded`. The **authorship rule**
   (§6.6) is the security-relevant part of 8.1c: an `edit`/`del` must apply
   only to messages the sender wrote, which in a group is checked against the
   sender rid recorded in the sealed envelope (`sr`) and fails closed on rows
   that predate it — try to break it, since pairwise fan-out means any member
   can address any other.
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
- Biometric unlock (opt‑in) is hardware‑bound on Android only. On
  macOS/Windows the passphrase‑derived key is a plain keystore entry gated
  by the app's own prompt, not by Keychain access control / Windows Hello
  user presence — native code that cannot be verified without those
  toolchains; planned as 7.8c.

## 7. Artifacts and how to run them

Everything below, in one command, reported by claim rather than by suite:

```
tool/audit_verify.sh            # everything (~6 min)
tool/audit_verify.sh --quick    # skip the app suite (~1 min)
tool/audit_verify.sh --list     # which suite backs which claim
```

It says what it could not run and which claims that leaves unverified, rather
than passing quietly with a toolchain missing — a green run with `flutter`
absent would otherwise mean eleven claims went unchecked. The suite‑to‑claim
mapping is read out of the table in §3, so it cannot drift from this document.

The pieces individually:

```
# Protocol library: 147 tests incl. the vector freeze
cd protocol && dart test

# Relay: 50 tests incl. the clean-room vector replay (18 suites, no shared code)
cd server && npm test

# ML-KEM and ML-DSA values re-derived by unrelated FIPS 203/204 implementations
pip install kyber-py==1.2.0 dilithium-py
python3 protocol/tool/verify_mlkem.py
python3 protocol/tool/verify_mldsa.py

# This brief itself: every file it names exists, and every test suite in the
# repository is cited by a claim (or listed in the script as deliberately
# claiming nothing, with a reason)
python3 tool/check_audit_scope.py

# App: 34 test files, most driving real clients through the real relay
# (each spawns its own relay process; node must be on PATH)
cd app && flutter test

# Regenerate vectors (a diff after regeneration means the protocol changed)
cd protocol && dart run tool/gen_vectors.dart
```

`docs/vectors/README.md` explains the vector conventions; every random draw
the reference implementation made is recorded next to the output it produced,
so a third implementation can be checked without any of our code.

Test vectors, both independent verifiers and the brief-consistency check run
on every CI push (`.github/workflows/build.yml`), alongside the Android and
Linux builds. Until 14.3 the ML-DSA verifier was documented but not wired in,
which is the kind of gap the consistency check exists to stop recurring.

## 8. What we would like back

- Findings with severity (we suggest Critical / High / Medium / Low /
  Informational), a reproduction, and where possible a suggested fix.
- An explicit statement per claim in §3: confirmed, confirmed with caveats,
  or broken.
- A short note on anything in §4 the review did not reach, so we know what
  remains unreviewed.

### 8.1 What each severity means here

Generic severity scales grade findings against an imagined system. Z states
thirty claims, so severity can be anchored to them: **what a finding lets
someone do**, not how hard it was to find or how elegant the bug is. A trivial
one-line mistake that lets the relay read a message is Critical; a beautiful
piece of cryptanalysis that needs an unlocked device is not.

| | means | examples |
|---|---|---|
| **Critical** | Breaks **C1** or **C4**: the relay, its operator, or someone on the network reads content or learns who is talking to whom. Or recovers plaintext from a vault or archive without the passphrase or recovery code (**C11**, **C13**). | key material recoverable from an envelope; a ratchet flaw exposing past messages; a sealed‑sender construction that reveals the sender |
| **High** | Breaks an identity or verification claim (**C7**, **C8**, **C14**, **C16**, **C17**, **C21**–**C23**, **C30**): a user ends up talking to a party the UI says they are not, a device set can be forged or narrowed, or a verified state survives something that should have cleared it. Or plaintext written to disk anywhere (**C11**). | a device certificate that verifies for a device it does not name; a device list a contact accepts that the account never signed; a safety number that fails to move when the key changes |
| **Medium** | Degrades a claim without breaking it. Post‑compromise security does not recover as specified (**C6**); a downgrade is possible but detectable; a metadata leak beyond what `THREAT_MODEL.md` admits; a fail‑open where the spec says fail‑closed, reachable only from an unusual state. | a re‑key that silently reuses a generation; a state where a suppressed signature raises nothing |
| **Low** | A real defect on a narrow path — an unlikely precondition, an attacker position we already assume is rare, or a concession the threat model makes but understates. | an alert that can be delayed but not prevented; a bucket boundary that leaks slightly more than documented |
| **Informational** | A divergence between spec and implementation with no security consequence, a hardening suggestion, or a residual‑risk row we already publish. | a `PROTOCOL.md` section that describes the code imprecisely |

Three things we would rather you did than not:

* **Grade a documented limit as a finding if you think it is worse than we
  say.** `THREAT_MODEL.md`'s residual‑risk register (R1–R16) is our estimate,
  not a settled fact, and "R7 is Medium, not Low, because …" is one of the more
  useful things a review can return.
* **Report a claim you could not evaluate.** An unexamined claim looks
  identical to a confirmed one in the final report, and only you know which
  it was.
* **Split a finding rather than round it up.** If one bug is Critical on
  Android and Low on desktop, two rows are more useful than one argument.

We will fix Critical and High findings before general availability — that is
phase 15's stated entry condition, and it is the reason this review is gated
in front of it. Medium and Low are triaged publicly with a decision and a
reason, including "accepted, and here is why", which then joins the
residual‑risk register rather than disappearing.

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
  app_lock.dart            screen lock + biometric unlock (local_auth behind a testable gate; BoundKeyStore)
app/android/app/src/main/kotlin/com/zmessenger/www/BioKey.kt
                           hardware-bound pass key: Keystore + BiometricPrompt CryptoObject (7.8b)
  transport.dart           relay link with backoff
  voice.dart               in-memory WAV capture wrapper
  backup.dart              identity backup (.zid)
server/server.js           the relay
```
