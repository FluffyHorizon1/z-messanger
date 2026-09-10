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
that an excluded device and a rolled-back version both fail; and suppressing
the signature, the one thing the network can still do, is detected and
surfaced (§18.9) without accusing a peer that simply does not sign lists.

---

## Phase 14 · Verifiability & assurance

Nothing here adds a feature; all of it converts claims into evidence, which is
the premise of the product. Freeze the protocol at v3 before starting —
auditing a moving spec wastes the money.

- **14.1 reproducible builds** *(spike done — `docs/REPRODUCIBLE_BUILDS.md`,
  `tool/verify_reproducible.py`; same-machine reproducibility achieved,
  cross-machine outstanding)* — the spike's answer was better than the question
  expected. Dart AOT and the Android build were **already** deterministic: two
  release builds differed in 8 603 bytes, every one of them inside an AGP
  "dependency metadata" blob (encrypted to Google, fresh randomness per build)
  that has no business in this app anyway. Disabling it makes two builds
  byte-identical, signature included — no timestamp stripping, no
  `SOURCE_DATE_EPOCH`. What is NOT established is cross-machine: both builds
  shared a path, a container and a clock, and a build from a different path was
  attempted and defeated by the container's 2 cores and 8 GB. That check
  belongs in 14.2 and is cheap there.
- **14.2 provenance & signing** *(done — reproducibility measured and
  explained; `docs/PROVENANCE.md`, CI jobs in `build.yml`)* — Sigstore keyless
  signing and a Rekor transparency log entry per release artefact, plus the
  cross-machine reproducibility check 14.1 could not run. Two things the
  roadmap said that turned out not to hold: **this configuration is SLSA Build
  L2, not L3** — L3 needs the build isolated from the signing material, which
  is a restructure into an isolated reusable workflow, not a flag — and
  **there is no updater**, so "the updater verifies signature and log
  inclusion" has nothing to attach to. Android rollback is handled by Play;
  desktop rollback is not handled at all, which belongs in the residual-risk
  column rather than behind the word "signed".

  **Then it ran (2026-09-09), failed, and a redesigned run answered it the
  same day.** The first job varied the runner *and* the checkout path at once
  and so could not name a cause. Three builds — two machines at one path, one
  at a different path — settled it: **the machine is not a variable**, two
  runners fingerprint identically down to the ELF build ids, and the *path* is
  the whole story. `libapp.so` carries its absolute build directory as a
  source URI and `libdartjni.so`, compiled beside it, inherits it; every
  prebuilt library is identical in all three.

  Both guesses made while it was open were wrong — that the identical APK size
  argued against the path (it does not: native libraries are stored
  uncompressed and page-aligned, so the padding absorbs a short string), and
  that `libdartjni.so` was a second unexplained phenomenon (it was the same
  one). Both are kept in `REPRODUCIBLE_BUILDS.md` rather than tidied away.

  So the build path is now part of the recipe — clone into a directory named
  `z` — the way Debian records `Build-Path`. **R16 is accepted, bounded and
  documented** rather than open: CI asserts machine-independence, and asserts
  that a path change moves those two libraries and no others, so the leak
  cannot spread unnoticed. The real fix is a relative URI, which is upstream
  work in the Flutter tool.

  Still outstanding, and not self-certifiable: **a rebuild by someone outside
  the project**, which is phase 14's exit criterion.

- **14.3 external cryptographic audit** *(the package is ready; the engagement
  is not ours to run)* — scope per `AUDIT_SCOPE.md`: handshake, ratchet, PQ
  mixing, device certs and the enrollment ceremony. **The KT client named in
  the original scope does not exist** — `adr/0001` defers the log to phase 11
  and nothing has triggered it — so it is out of scope rather than quietly
  reviewed as if present. What was preparable, and is done:
  - `tool/check_audit_scope.py` makes the brief prove it still describes the
    repository — every path it names exists, every test suite is cited by some
    claim or listed as deliberately claiming nothing, ambiguous names are
    qualified, counts match. It found fourteen problems on its first run,
    including a working note cited as evidence that does not ship, the
    clean-room sealed-sender verifier that C4 never cited, and a security
    property (vault migrations never rewrite a sealed cell) that had been
    guarded by a test filed under a feature since phase 8. That is now C30.
  - `tool/audit_verify.sh` runs every verifier in one command and reports by
    **claim** rather than by suite, naming what it could not run and which
    claims that leaves unchecked — a green run with `flutter` missing would
    otherwise hide eleven unverified claims.
  - A severity rubric anchored to the claims (§8.1), because Critical/High/
    Medium/Low against an imagined system tells a reviewer nothing: here a
    finding is Critical because it breaks C1 or C4, not because it was hard
    to find.
  - CI now runs `verify_mldsa.py`, which three claims cited as evidence and
    which had never run automatically.

  Outstanding, and Finnian's to commission: the engagement itself. Phase 15's
  entry condition is zero open Critical/High, which is what makes this gate
  real rather than decorative.
- **14.4 VDP** *(done bar a live submission — `docs/VDP.md`, RFC 9116
  `security.txt` served by the relay, `server/test/security_txt.test.js`)* —
  safe harbour granted in writing, two independent report channels, published
  response targets, and an explicit statement that **there is no funded
  bounty**: Z has no budget, and "rewards at our discretion" when the answer is
  almost always no wastes the time of the people the policy exists to attract.
  The `Expires` field is enforced by a test that fails the build once it
  passes, because an expired security.txt invites reports to an address nobody
  promises to read. Outstanding: a live submission through both channels, which
  needs somebody outside to send one.
- **14.5 published documents** *(done — `THREAT_MODEL.md` residual-risk
  register, `DATA_MAP.md`, `WHITEPAPER.md`)* — the threat model gained a
  **residual-risk register**: sixteen numbered rows saying what is left after
  everything built, who is exposed, why it remains, and whether it is
  accepted, deferred or open. It gathers what the last five phases left
  behind, which was otherwise findable only by reading every ADR.
  `DATA_MAP.md` is new — every column of the vault, everything the relay holds
  in RAM, every third party, and what leaves the device in what shape. It
  could **not** be "refreshed for calls and KT" as this line originally asked,
  because neither exists; both are listed under "not yet built" with the open
  decision that shapes each. `WHITEPAPER.md` is the third: not a second
  protocol spec but the **argument**, organised around the claims Z makes
  rather than around the wire format.

  This entry lands late and out of order. The register and `DATA_MAP.md` were
  written before the whitepaper but reached `main` after it, after 14.3 and
  after 14.2b — which is why the audit-brief check had to be disabled on
  arrival in `e59e630`: the brief cited two things that did not yet exist. The
  check is re-enabled in the same commit that lands them.

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
- **15.3 scale & performance** *(measured, and the first fix made —
  `docs/PERFORMANCE.md`)* — large-vault paging already had a test with a
  1.5 s budget for the first page of a 50 000-message thread. Fan-out was the
  open question, because it is the cost someone will one day cite as a reason
  to add a shared group key, and it deserved a number.

  **The design holds.** Group send is linear in the member count — per-member
  cost at fifty members is 0.79× what it is at five, slightly *sub*-linear as
  fixed overhead amortises. No quadratic term, and the benchmark asserts that
  bound so a future regression fails rather than merely feeling slow.

  **What is wrong is elsewhere.** A fifty-member send takes ~1.2 s and
  `chat_screen.dart` awaits it with the composer disabled — a frozen send
  button and no message on screen for over a second. The message is durable
  the moment its outbox rows commit; nothing requires the user to watch the
  fan-out finish. That is a UI fix, not a cryptography one.

  **And a latent one worth more than either.** Every send serialises the whole
  conversation twice, including the ratchet's cache of skipped message keys
  (cap 1536). Empty in the benchmark, so those numbers are a best case: at the
  cap it adds **+20.7 ms per recipient per send**, roughly doubling the cost,
  and grows worse than linearly. It only appears after out-of-order delivery —
  on a bad network, when things are already going badly — and it is paid on
  the send path for state that only matters on receive.

  Batching the outbox writes is 8.7× cheaper per insert and is *not* the fix:
  it is ~13% of the cost, and one transaction across fifty recipients turns
  one recipient's failure into fifty rolled-back ratchets.

  **The first fix is made: the fan-out is written down before it is
  performed.** Not awaiting would have removed the stall and made something
  worse — an interrupted fan-out used to drop its remaining recipients
  silently and permanently. `group_fanout` (vault **schema 8**) holds one row
  per (message, recipient), written in one transaction (~18 ms for fifty
  against 1 200 ms to perform them); the drain runs in the background, deletes
  each row only after that recipient's outbox row is committed, and resumes on
  the next start. `UNIQUE (mid, rid)` makes re-queuing idempotent, so a resumed
  fan-out does not serve anyone twice.

  Content operations use it — text, reactions, edits, delete-for-everyone.
  Membership changes stay synchronous, because their ordering carries the
  security property that a member removed before a send never receives it: a
  send snapshots membership at queue time, so removal-then-send still excludes
  them. `sendGroupFile` is not queued — its fan-out carries per-recipient chunk
  payloads that would have to be stored again per row.

  Both exit criteria are tests, and both were verified by removing the guard:
  putting the synchronous loop back makes a twenty-member send take 406 ms and
  fail the bound; removing the resume-on-start makes the interrupted fan-out
  never drain.

  Still unmeasured and named as such: real hardware, devices-per-member (the
  extra-device fan-out is `unawaited` and not in these timings), cold start,
  relay latency under sustained load, and the receive side — which is where
  the skipped-key cache is actually used.
- **15.4 docs & support & access** *(accessibility done; docs and
  localization outstanding)* — user documentation, recovery guidance, an
  honest "what a compromised endpoint defeats" page, and **localization**
  (strings are hardcoded English today) all remain.

  **Accessibility is done and enforced.** The starting position was worse than
  the entry implies: *zero* `Semantics` widgets and eleven tooltips across
  sixteen `IconButton`s. A screen-reader user opening the app heard "button"
  and nothing else in seven places, including the attachment control, the
  settings control and every quick reaction.

  Two checks, deliberately complementary. `app/test/a11y_test.dart` runs
  **Flutter's own** guidelines — `androidTapTargetGuideline`,
  `labeledTapTargetGuideline`, `textContrastGuideline` — plus a 2× dynamic-type
  pass, across both palettes, on the three screens that stand up without a
  `ChatService`. Those are not an arbitrary subset: they are the screens a user
  meets before they have an account. `tool/check_a11y.py` covers the other ten
  breadth-first by reading source: every `IconButton` has a `tooltip:`, and
  every `Image` has a `semanticLabel:` or is *explicitly* marked decorative,
  because "this is decorative" is a decision and saying nothing is an
  oversight — they should not look alike in the source.

  One finding was mine, not the app's, and is recorded because it nearly cost
  a brand change: the first draft pumped screens in a bare `MaterialApp`, and
  `context.z` falls back to the **dark** palette when the theme extension is
  absent — so the tests painted dark-palette amber on Material's white and
  reported a 1.71:1 contrast failure. `app/tool/contrast.py` says every real
  pair clears AA in both palettes, and with the real theme installed they all
  pass. Both checks now run in CI and in `audit_verify.sh`.
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

22. **§18.9 — detecting suppression needed a piece the ADR had not
   anticipated.** The signature is the easiest thing on the wire to drop: the
   only ~16 KB envelope an ordinary conversation makes. But "hybrid identity,
   classical list" is not evidence of an attack — a client built before §18.9
   has a post-quantum identity and never signs its lists — so alarming on it
   would have fired for every such contact during rollout, which is how an
   alarm stops being read. The sender now claims, inside the ratchet where
   whoever dropped the envelope cannot strip it, that it has SENT the
   signature; a claim with nothing behind it is asked about before anyone is
   told, because most losses are a dropped connection. Checked by making the
   detection naive and watching the innocent case fail.
