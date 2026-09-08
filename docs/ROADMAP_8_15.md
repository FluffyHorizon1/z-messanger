# Z — roadmap, phases 8–15

**Status:** adopted · September 2026 · revised after code review (see
*Revisions after review* at the end for what changed and why)
**Basis:** phases 0–7 done or externally gated (`ROADMAP.md`), phase 8
complete, `ZERO_TRUST_PLAN.md`, `z-multidevice-design.md`.

Every phase keeps the standing constraints: the relay stays RAM‑only and
zero‑knowledge, no server‑side key custody, additive protocol changes wherever
possible, vectors mirrored into `server/test/vectors.test.js`, and the full
verification sweep (protocol / relay / app / vectors / kyber‑py / contrast)
green before a phase closes.

---

## Sequencing at a glance

| Phase | Theme | Blocking dependency | Nature |
|---|---|---|---|
| 8 | Message interactions | — | ✅ complete |
| 9 | Encrypted backup & restore | 8 (schema settled) | app + protocol |
| 10 | Multi-device | 9 (history for a new device) | protocol-heavy |
| 11 | Key transparency | 10 (KT takes over device lists) | infra-gated |
| 12 | Calls | 10 (per-device routing) | new subsystem |
| 13 | Post-quantum identity (protocol v3) | 10 (device cert format) | protocol-heavy |
| 14 | Verifiability & assurance | 13 (freeze before audit) | process |
| 15 | GA | 14 | release |

The two ordering decisions worth arguing about are in *Ordering rationale* at
the end.

---

## Phase 8 · Message interactions ✅

Shipped as three patches. Details in `ROADMAP.md`; spec in PROTOCOL §6.4–6.6.

- **8.1a replies ✅** — `rt` on text/file/gmsg/gfile; only the id travels, the
  quote is rendered from the receiver's own copy. Vault schema 2.
- **8.1b reactions ✅** — `react`/`greact` `{rt, emo}`, one per sender per
  message, sealed per reacting rid.
- **8.1c edit / delete-for-everyone / forward ✅** — authorship enforced
  against the recorded sender, with the group abuse case tested; "edited"
  marker, tombstones, `fw` marker (schema 3).
- **8.2 close-out ✅** — PROTOCOL §6.4–6.6 written, v1 vectors extended (never
  edited), all three checkers agree. *Open:* a real-device pass on Android,
  which needs hardware.

**Deliberately not in scope:** pins, stars and drafts — vault-local
conveniences that can land any time and do not need a phase.

---

## Phase 9 · Encrypted backup & restore

The strongest runner-up when phase 8 was chosen, and it only gets more urgent:
`.zid` carries identity and contacts only, so today losing the sole device
loses all history — permanently, since no server holds a copy to fall back on.
That is the whole case for the phase, and it is enough on its own.

- **9.1 archive format** *(done — `docs/BACKUP.md`, `backup/archive.json`)* — versioned, AEAD-sealed archive of messages,
  contacts, group state, attachment blobs **and the identity**, key derived by
  Argon2id from a user-held 12-word recovery code. Documented in
  `docs/BACKUP.md` and vectored, because a backup you cannot read in two years
  is not a backup.
  **Session state is deliberately excluded.** The vault's `conversations` rows
  hold live double-ratchet state; restoring them can put the same ratchet on
  two devices, reusing chain keys and message numbers, and the relay's
  one-socket-per-routing-id rule (it closes the older with `4002 replaced by
  new connection`) means the two would also fight over the mailbox. An archive
  therefore restores *history*, and every conversation re-handshakes with a
  `hello` on first use — cheap, and the only safe answer.
  **`.zid` becomes a subset of this format**, not a second mechanism: one
  archive format, one unlock story. Two artifacts with two different unlock
  ceremonies is how someone picks the wrong one in a crisis.
- **9.2 export / import** *(done — `app/lib/core/archive.dart`)* — streaming export so large blob sets don't blow
  memory; import with forward-compatible schema migration (an archive written
  at schema 3 must restore on schema 5). Restore builds a **fresh vault** with
  its own device secret and master key: nothing device-bound travels.
- **9.3 destination** *(done — `file_export.dart`, `backup_store.dart`)* — user-chosen local file first. Any cloud target is
  user-supplied storage the client writes ciphertext to; the relay never
  stores or proxies backups. That is an explicit anti-goal, not an omission.
- **9.4 recovery UX** *(done — `backup_screen.dart`, `restore.dart`)* — code generation and confirmation ceremony, restore
  flow, and the honest framing: lose the code and the archive is gone, because
  there is no server-side path to be compelled.
- **9.5 scheduled backup** *(done — `BackupSchedule`)* — optional periodic re-export, off by default.

**Exit:** an archive taken on device A restores every message, contact, group
and attachment on a wiped device B, and B then re-establishes sessions and
exchanges messages with a contact who never knew a restore happened; the
restored vault contains **no** session state; a wrong recovery code fails
closed with no oracle (and a mistyped one is caught by the code's checksum
before the KDF runs); an archive from an older schema restores onto the
current one in test.

---

## Phase 10 · Multi-device *(complete)*

M1–M5 were built incrementally across phases 3–7, so this phase was mostly a
matter of proving the exit criteria rather than writing new machinery — and
proving them found one real bug (revision 13 below).

`z-multidevice-design.md` executed as written: per-device sessions,
sender-side fan-out, **relay unchanged**. M1–M5 there map onto 10.1–10.5.

- **10.1 account/device model** — the Ed25519 identity is promoted to a stable
  **account key** that signs device certificates and anchors the safety number
  but never ratchets and never routes. Each device gets its own X25519 +
  Ed25519 pair, its own `routingId`, and an account-signed cert over
  `(device_ed_pub ‖ device_x_pub ‖ device_id)`. Contact code **v2** (`zc2.`)
  carries the account key plus a device list; `zc1.` codes still resolve as a
  one-device account.
- **10.2 per-device sessions, fan-out, self-sync** — conversations keyed per
  *(my device, their device)*; a send fans out to every device of the contact
  **and** to your own other devices; receivers de-duplicate by message id.
  Extend the concurrency regression to the multi-device case.
- **10.3 enrollment ceremony** — QR + 6-word SAS; the new device generates its
  own keys, the existing device signs the cert and hands over the account key
  and contact list over the verified channel. History for a newly linked
  device already works: 7.6b replays the newest 200 messages per chat over the
  self-sync channel. A phase-9 restore is for resurrecting a *dead* device,
  not for bootstrapping a second live one.
- **10.4 device-list distribution + revocation** — in-band account-signed
  "device list version N" updates over each existing conversation; contacts
  verify against the account key they hold. Removal publishes N+1 and sessions
  to the dropped device are abandoned. Explicitly interim, pending phase 11.
- **10.5 linked-devices UI** — device list screen, enrollment flow, per-account
  verification state, subtle "added/removed a device" notices.

**Exit:** phone and desktop both send and receive on one identity with no
mailbox contention; the safety number is unchanged across a device add and
remove; a device-list update reaches a contact who was offline during
enrollment; relay code and schema are untouched by the whole phase.

---

## Phase 11 · Key transparency *(finishes 7.7b)*

Converts "trust the contact code you scanned" into "catch a substitution."
Gated on a durable-infrastructure operator, since a Merkle log is exactly the
persistent state the relay refuses to hold — so it ships as a **separate
service**, not as relay features.

- **11.1 log service** — prefix tree mapping identity → key history anchored in
  an append-only log tree, signed tree heads, signing key in an HSM/TPM.
  Deployed independently; the relay stays RAM-only.
- **11.2 client verification** — every key used for encryption checked by
  inclusion proof against the current head and consistency proof against the
  last head seen. **A proof that fails is a hard fail**: no send, not a
  warning banner. A log that is merely *unreachable* is not the same thing and
  must not be treated as one — hard-failing on unavailability turns a network
  block into a kill switch, which is precisely the adversary this is for. On
  unreachable: proceed against the last known-good head, in a visibly degraded
  state, and refuse only on mismatch or on a head that cannot be reconciled.
- **11.3 mirrored heads** — cross-published to a public repo and at least one
  independent witness, so a forked view is detectable.
- **11.4 self-monitoring** — background audit of your own log entries ("am I
  mapped to keys I did not publish?"), with an in-app alert path.
- **11.5 device authorisation migration** — device-list distribution moves out
  of 10.4's in-band mechanism into the log, gaining third-party auditability.
  In-band remains as a fallback for one release.

**Exit:** a simulated malicious key substitution blocks the send in the client;
a diverging mirror causes refusal; the self-audit alert fires end to end.

---

## Phase 12 · Calls

The largest remaining consumer-facing gap now that voice *messages* (7.4) have
shipped. Depends on phase 10 because a call has to ring a device, not a person.

- **12.1 signalling** — offer/answer/ICE candidates as ordinary sealed
  envelopes over the existing relay; no call verb the relay can distinguish;
  no call records anywhere. Be honest about the limit: a call is a sustained
  bidirectional flow and is distinguishable from messaging by traffic analysis
  whatever the padding does. The claim is "no identifiable verb", not "the
  relay cannot tell a call is happening".
- **12.2 1:1 voice** — media keys derived from the existing pairwise ratchet,
  SRTP with DTLS as the fallback path; direct P2P preferred.
- **12.3 video** — same transport, added once voice is stable on real devices.
- **12.4 relay-assisted path** — TURN where P2P fails, run as a separate
  service with the IP-exposure trade-off written into `DATA_MAP.md` and stated
  in the UI. Note which way the disclosure runs: **P2P reveals your IP to the
  person you are calling**, TURN reveals it to the TURN operator instead. For
  a product whose whole premise is not trusting infrastructure, "your contact
  learns your IP" is the surprising one — so the default and the per-call
  disclosure both need deciding here, not assumed.

**Anti-scope:** group calls via an SFU. A mixer that sees who is talking to
whom is exactly the metadata concentration this design exists to avoid;
revisit only with a decentralised design, not as a phase-12 stretch.

**Exit:** a 1:1 call connects across NAT on real hardware; call setup leaks no
identifiable verb to a server-side observer in a packet capture; declining and
missing a call are indistinguishable to the relay.

---

## Phase 13 · Post-quantum identity — protocol v3

v2 already mixes ML-KEM-768 into message keys and 7.5b added periodic PQ
re-keying. The remaining gap is **authentication**: identity keys, device
certificates and safety numbers are still purely classical, so a future CRQC
forges identities even though it cannot read past traffic.

- **13.1 hybrid signatures** *(done — `pqsign.dart`, hybrid device certs and a hybrid device-list signature, PROTOCOL §18.1, §18.4, §18.9; `adr/0004`)* — account and device keys become Ed25519 +
  ML-DSA-65; both signatures required, verification fails if either fails.
  Distribution turned out to be the hard half and changed the shape: what
  travels to a contact is **one signature over the device list**, not one per
  certificate, because per-certificate halves do not authenticate the *set* —
  an adversary who can forge Ed25519 presents a subset whose every remaining
  certificate is genuine. It travels as its own message on a delayed,
  jittered schedule, so the list keeps its 1024-byte padding bucket and the
  16 KB envelope the signature needs is uncorrelated with a device change.
- **13.2 contact code v3** *(done — `identity_v3.dart`, PROTOCOL §18.2–18.3)* — `zc3.` carrying hybrid account keys and hybrid
  device certs; v2 codes still resolve with a "classical identity" marker.
  **Open problem — now decided: see `adr/0003-pq-identity-qr.md`.** Measured,
  a one-device v3 code is 7 373 B against a 2 953 B absolute QR ceiling, so it
  does not fit by a factor of nine against what actually scans. The QR carries
  a 32-byte **commitment** to the PQ half (not a "reference", which binds
  nothing and collapses into trust-on-first-use); the ML-DSA keys travel
  in-band and are checked against it, mismatch being a hard failure. The ADR
  also found that shipping hybrid certs in a device list moves it from the
  1 024-byte padding bucket to 16 384 or 65 536, telling the relay when an
  account changes its device set and roughly how many devices it has — 13.1
  must not ship that.
- **13.3 safety number v2** *(done — PROTOCOL §18.5, `verification_ux_test.dart`)* — derived from both key halves. A visible, one-time
  change for every user, so it needed deliberate re-verification UX: the app
  records WHICH number was compared, never shows a tick against a number that
  has since moved, names the upgrade as an upgrade, and refuses to call any
  other change one. A refused post-quantum key is durable state, announced
  once and shown on the contact screen.
- **13.4 spec + vectors** — PROTOCOL §18 for v3, a v3 vector suite with an
  independent checker, v1/v2 suites frozen as usual.
- **13.5 compatibility window** *(done — no flag day was needed; PROTOCOL §18.6)* — one release accepting v2 identities and
  emitting v3, then v2 emission is dropped.
- **13.6 an account-anchored contact code** *(done — PROTOCOL §18.7)* — a
  contact code carried the classical identity of the **device** showing it,
  true since v1 and invisible while every account had one device. Scanning
  someone's laptop added the laptop, not the person: their device list then
  failed the "signed by this contact's account key" check, and the safety
  number was computed against a per-device key. A code may now name its
  account and carry that account's certificate for the device it describes —
  `ed`/`x` stay the reachable mailbox, `acct` is the identity a human
  confirms. That also lets a linked device carry the post-quantum commitment,
  which it could not before. A linked device can now forward the
  account-signed device list it holds, without which a contact scanned from
  one would be told, by ordinary use, that a device-list update never arrived.
- **13.7 contact propagation across an account's devices** *(done — PROTOCOL
  §18.8)* — a contact added on one device was unknown to the account's others,
  which dropped that person's messages as an unknown sender; contacts
  travelled at LINK time and never after. They now sync over the existing
  device-sync channel. Because this is the one assertion a device makes to its
  siblings with no scan behind it, the receiver is **insert-only** (never an
  update, so a name the user verified cannot be re-pointed), checks the
  routing id against the key beside it, re-checks §18.7's certificate rules,
  stores the contact unverified, and records which device sent it so the
  contact screen can say so.

**Exit:** three independent checkers agree on the v3 vectors; a v2 and a v3
client interoperate during the window; a forged device cert with only a valid
Ed25519 half is rejected. **Met** — Dart, a Node clean-room and dilithium-py
each rebuild the device-list signing input from the list itself and confirm
that an excluded device and a rolled-back version both fail.

---

## Phase 14 · Verifiability & assurance

Nothing here adds a feature; all of it converts claims into evidence, which is
the premise of the product. Freeze the protocol at v3 before starting —
auditing a moving spec wastes the money.

- **14.1 reproducible builds** — deterministic APK/AAB and desktop bundles; two
  independent machines produce bit-identical artefacts. Scope this as a spike
  first: Dart AOT snapshot determinism and AGP build timestamps are not a
  given, and the answer may be "reproducible with a pinned toolchain image",
  which is worth knowing before it is promised.
- **14.2 provenance & signing** — SLSA Build L3 provenance in CI, Sigstore
  signing, artefacts in a public transparency log; the updater verifies
  signature *and* log inclusion before applying.
- **14.3 external cryptographic audit** *(the gated 5.2 engagement)* — scope
  per `AUDIT_SCOPE.md`: handshake, ratchet, PQ mixing, device certs and the
  enrollment ceremony, KT client. Remediate to zero open high/critical.
- **14.4 VDP** — `security.txt`, safe-harbour disclosure policy, a bounty that
  actually pays, tested with a live submission.
- **14.5 published documents** — threat model with an honest residual-risk
  column, `DATA_MAP.md` refreshed for calls and KT, protocol whitepaper.

**Exit:** a bit-identical rebuild reproduced by someone outside the project; a
tampered update rejected by the client; audit report closed out; VDP live.

---

## Phase 15 · GA

Everything currently externally gated, plus the work to call it 1.0.

- **15.1 platform completion** — Play submission cleared (the 16 KB blocker is
  fixed; needs re-upload after an emulator or Pixel run), Windows and macOS
  code-signing certificates, iOS build and App Store submission.
- **15.2 carry-over hardening** — 7.8c Keychain / Windows Hello binding for the
  desktop vault.
- **15.3 scale & performance** — large-vault paging, fan-out cost with
  multi-device groups, relay load profile, cold-start time.
- **15.4 docs & support & access** — user documentation, recovery guidance, an
  honest "what a compromised endpoint defeats" page. Also the two things
  missing from this roadmap entirely: **accessibility** (semantics labels and
  a screen-reader pass on every screen, dynamic type — Play checks this
  separately from the items cleared in 3.5) and **localization** (strings are
  hardcoded English today).
- **15.5 GA criteria checklist** — audit ✓, reproducible builds ✓, KT live ✓,
  backup ✓, multi-device ✓, published threat model ✓.

**Exit:** 1.0 shipped on Android, iOS, Windows, macOS and Linux from signed,
reproducible artefacts.

---

## Ordering rationale

**Why backup (9) before multi-device (10).** Multi-device forces a decision on
history for a newly linked device. Building a bespoke history-transfer channel
over the SAS link is real work with its own failure modes; a restore from a
phase-9 archive gets the same result for free and independently solves the
sole-device data-loss problem that exists *today*. Backup is also the smaller,
more self-contained phase, so it is the better one to do while phase 8's schema
changes are fresh.

**Why key transparency (11) after multi-device (10).** KT's first real job here
is authorising devices. Landing 10.4's in-band device lists first gives a
working system immediately and a concrete migration target for 11.5; doing KT
first would mean building the log with nothing to put in it beyond
single-device identities.

**The one alternative worth considering.** If the priority is a visible
consumer win rather than structural work, calls (12) can move ahead of key
transparency (11) — the dependency runs 10 → 12, not 11 → 12. That trades
audit-readiness timing for a feature users actually ask for. Nothing else in
the sequence reorders cleanly.

**Rough shape, not a schedule.** 8 and 9 are small; 10, 12 and 13 are each
multi-patch protocol phases; 11 and 14 are gated on other people (infra
operator, auditor) so they should be *started* early even if they close late.

---

## Revisions after review

The plan above is as adopted, with these changes made after checking it
against the code. Each is a correction of fact rather than a change of
direction; the phases, their order and both ordering arguments stand.

1. **9.1 — session state excluded from the archive.** `conversations.enc_state`
   is live ratchet state; restoring it risks the same ratchet on two devices,
   and the relay kicks the older socket for a routing id, so the two would
   also fight over the mailbox. History restores; sessions re-handshake.
2. **9.1 — `.zid` folded into the same format** rather than kept as a second
   artifact with its own unlock ceremony.
3. **9 exit criteria — "byte-faithfully" replaced.** A faithful restore of
   session state is precisely what must not happen; the criterion is now that
   every message and attachment returns *and* B talks to a contact afterwards.
4. **10.3 — history for a new device already exists** (7.6b, 200 messages per
   chat over the self-sync channel). Phase 9's value is the sole-device
   data-loss case, which is argument enough on its own.
5. **11.2 — mismatch and unavailability separated**, so the log cannot become
   a censorship-triggered kill switch.
6. **12.1 / 12.4 — two honesty corrections**: a call is distinguishable from
   messaging by traffic analysis regardless of padding, and P2P discloses the
   caller's IP to the callee (the surprising direction, given the premise).
7. **13.2 — the QR size problem named** as something to decide in the phase.
8. **14.1 — reproducibility scoped as a spike**; **15.4 — accessibility and
   localization added**, which the roadmap did not cover anywhere.
9. **9.1 — the recovery code is 25 Crockford base32 characters, not 12 words.**
   A word list means shipping and pinning a 2048‑word list per language and
   getting its provenance right, to solve a transcription problem the encoding
   can solve on its own: Crockford's alphabet omits I, L, O and U, is
   case‑insensitive, and folds the usual mis‑copies (I/L→1, O→0) on input. Same
   entropy class (120 bits + a 5‑bit checksum that catches ~31 of 32
   single‑character typos before the KDF runs), shorter to type, nothing to
   localize. `docs/BACKUP.md` §3.
10. **9.1 — the post‑quantum secret moved from the conversation to the
   session** (`PROTOCOL.md` §17.1). The phase‑9 round‑trip test showed the
   restored device receiving nothing: the peer kept mixing the ML‑KEM secret of
   the era the restore threw away, and rejected the fresh generation‑0 offer as
   out‑of‑order. The first fix — drop the old session and reset the secret —
   broke device‑list transparency (7.7a), because a receiver cannot tell a
   restore from a second device holding the same key, and dropping the replaced
   session let either one cut the other off. Two live sessions need two live
   eras, which a conversation‑wide generation counter cannot express. Sessions
   now carry their own secret; the replaced session is pinned out of the
   outbound path but stays readable. Covered in both rid orderings, since both
   the pinning and the PQ roles turn on that comparison.

11. **9.3 — the save-dialog contract was already broken, on macOS.** The app
   passed `bytes` to `FilePicker.saveFile` on every platform and then wrote
   again unless it was on Android. macOS throws outright when given bytes, so
   saving an attachment or an identity backup was broken on a target that
   already ships, and iOS would have written every file twice the moment that
   target existed. The rule now lives in `file_export.dart` as a property of
   the platform, checked for all five from a Linux test runner.
12. **9.5 — automatic backup stores the recovery code, and says so.** An
   unattended run cannot ask for a code. The trade is defensible because
   anyone who can open the vault already has the plaintext history, while the
   code protects the archive after it leaves the device — but it is a trade,
   so the UI states it and disabling the schedule erases the code.

13. **10.1 — the safety number was anchored to the wrong key.**
   `ChatService.safetyNumberWith` used `identity.edPub`, this DEVICE's key,
   where `PROTOCOL.md` §2.5 already specified the ACCOUNT key. On a device
   holding the root the two coincide, so it looked correct for the entire
   single-device era; on a linked device they differ, and a phone and a laptop
   showed different numbers for the same contact. Someone who verified on one
   and checked on the other would read a mismatch as an attack. Fixed to use
   the account key, which is byte-identical for an account that has never
   linked a device — a test pins that, because silently moving this number
   would make every already-verified contact in the wild look compromised.
14. **10 exit criteria are now tested directly** (`app/test/multidevice_test.dart`):
   both devices sending and receiving with no mailbox contention and no
   duplicates, the safety number surviving an add and a remove, and a contact
   who was offline for the whole enrollment still learning the device — and
   then actually reaching the new device, since the device list only matters
   if it changes the fan-out. The relay is untouched: its last commit predates
   the phase.

15. **13.2 — the QR problem is decided, and it uncovered a padding leak**
   (`adr/0003-pq-identity-qr.md`). The roadmap's "compact reference in the QR"
   was unsafe as written: a reference binds nothing, so it degrades to
   trust-on-first-use, where an attacker present at the first exchange
   substitutes their own ML-DSA key and passes every hybrid check afterwards.
   It is a **commitment**. Separately, hybrid device certs would push a
   device-list update out of the 1 024-byte bucket that ordinary chat occupies
   and into one almost nothing else uses — a new metadata leak introduced by a
   phase meant to strengthen authentication, and the opposite direction from
   ADR-0001's T1–T3. Same fix, applied in-band: the list carries commitments,
   the PQ halves travel separately.

16. **13.2/13.5 — the `zc3.` prefix was a mistake, corrected when emission was
   switched on.** PROTOCOL §14 already said a new optional JSON member is
   compatible evolution while a change to computed bytes is a version bump; a
   commitment is the former. Measured: the shipped v1 decoder reads a `zc1.`
   code carrying `pqc` and rejects a `zc3.` code outright. So the commitment
   rides in a v1 code, the whole installed base can still scan what new
   clients hand out, and the compatibility window collapsed from three
   releases to none. `zc3.` remains specified and accepted, unemitted.

17. **13.5 — switching emission on found two multi-device bugs, both of the
   phase-10 family.** Neither is about post-quantum cryptography; both are
   about an account with more than one device disagreeing with itself, and
   both were invisible until a second identity value existed to disagree
   about. (a) A linked device derived an ML-DSA key **of its own** from its
   own seed, so the account had two post-quantum identities and each device
   committed to a different one. The account's ML-DSA public key now travels
   at enrollment (`EnrollmentData.pqpub`), and a device that cannot reach the
   account's key emits no commitment rather than inventing one — `13.6` above
   is the remaining half. (b) A contact's post-quantum key was offered once
   per contact, so a device linked **after** that offer never received it and
   showed a classical safety number while its sibling showed a hybrid one:
   two numbers for one account, and a mismatch that reads to the user exactly
   like a key substitution. The offer is now re-made when a contact's device
   list gains a device, and the exchange completes on the extra-device path
   as well as the primary one.

18. **13.3 — the UX was the hard half, and it changed the data model.** The
   protocol work said "derive from both halves"; what a user sees is a number
   that changed, which is what an attack looks like. `verified` recorded THAT
   a number was compared and not WHICH, so it could not tell an upgrade from
   a substitution — it had to become a stored number (schema 5,
   `contacts.verified_sn`), and the archive had to carry it or a restore
   reinstates a tick nothing backs. The same pass found that a refused
   post-quantum key had no memory at all: it was re-announced on every
   arrival, so whoever was sending the bad key could bury the warning under
   copies of itself. Refusal is now durable (`contacts.pq_mismatch`),
   announced once, and shown on the contact screen.

19. **13.6 — anchoring the code to the account exposed the next layer down.**
   The format change was small: two optional members, `acct` and `cert`, that
   must both be present or both absent, with a verifier that checks the
   certificate is FOR the device in the code (without which a stranger holding
   any genuine certificate of that account — they are public, they travel in
   device lists — presents it beside their own keys and is scanned as that
   account). What it uncovered was that only a root device could hand a
   contact its device list, so a contact scanned from a laptop would sit
   behind the 7.7a grace period and be told an update never arrived: a
   transparency alarm raised by ordinary use, which is how a real one stops
   being read. A linked device now forwards the account-signed list it already
   holds. And one gap is left open rather than papered over: contacts do not
   propagate between an account's own devices (13.7).

20. **13.7 — the interesting part was deciding what NOT to send.** Propagating
   a contact is the only assertion a device makes to its siblings with nothing
   scanned behind it, so the question is what a rogue linked device gains. It
   already reads the account's messages and sends as the account, and it holds
   no root so it cannot enroll devices. Allowing an UPDATE would have handed
   it something worse than either — silently re-pointing a verified name at
   keys of its choosing — so the receiver is insert-only. Forwarding the
   verified flag would have let it inject a contact that already looks
   checked, so the tick does not travel (enrollment has always started
   contacts unverified for the same reason). What is left, a new chat
   appearing, is bounded rather than removed: any device can add a contact,
   because the user scans on whichever one is in their hand — so it is stamped
   with the device that sent it and the contact screen says so. Both guards
   were checked by removing them and watching the tests fail.

21. **13.1 — distribution changed the shape of the signature** (`adr/0004`).
   §18.4 implied a post-quantum half per certificate. Measuring showed the
   buckets cannot hide 3.3 KB whatever is done — moving the halves out of the
   list does not put them back in the 1024 bucket, it only decorrelates them
   in time, and ADR 0003's "16 384 or 65 536" was really 16 384 for one to
   three devices with the cliff at four. But the deciding argument was not
   size: **per-certificate halves do not authenticate the set.** Given a
   genuine hybrid list, an adversary who can forge Ed25519 presents a subset
   — classical signature forged, every remaining certificate's post-quantum
   half genuine and copied — and every check passes while the honest device is
   excluded (ADR-0001 T2). One signature over the list covers membership and
   version, is constant-size whatever the device count, and is what phase
   13's exit criterion actually rests on.
