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

- **11.1 log service** ✅ — an RFC 9162 log tree plus a depth-256 sparse map
  under one signed head (`kt/`, PROTOCOL §19, `adr/0006`), publish
  authenticated by the account key, an append-only store replayed and
  re-verified on start, vectors re-derived by a second implementation. The
  signing key is a file the operator protects (`KT_SEED_FILE`), or a
  dashboard secret on a cloud host (`render.kt.yaml`, revision 40); an HSM
  is a deployment choice the service does not preclude and does not yet
  have. Deployed independently; the relay stays RAM-only. **Not yet
  deployed** — but a Blueprint away.
- **11.2 client verification** ✅ — every contact's list checked by map proof
  and inclusion proof against a head that must extend the last one seen. A
  proof that fails, or a head that does not extend, is a **log fault**: nothing
  new is trusted, nothing already verified is lost. A conflict between the
  log and a contact's devices holds what the user says to them. Unreachable
  is not a fault: in-band verification continues, visibly degraded after a
  day (`key_transparency_test.dart`).
- **11.3 mirrored heads** ✅ — `kt/tools/mirror.js` keeps a full copy,
  refuses any head that does not extend the one it verified (a fork, a
  shrunk log, entries that do not hash to the head), and co-signs the heads
  it verified into a witness record the client checks the log against. The
  "public repo" is any static host for that record — or the mirror itself
  with `--serve`, which is how `render.kt-witness.yaml` runs it (revision
  40); the independent witness is a person, and is one of G3's conditions.
- **11.4 self-monitoring** ✅ — each check reads the account's own history
  and alerts on an entry this device neither signed nor learned by self-sync
  (`key_transparency_test.dart`, the owner's alert).
- **11.5 device authorisation migration** ✅ *as decided in `adr/0006`, not as
  written here* — in-band delivery stays primary; the log is a second source
  of the same facts: a list the log holds and a contact never received is
  installed from the log, every root publishes its baseline at its first check
  after upgrading, and the hold on unconfirmed devices begins with an
  account's own first publish (revision 34).

**Exit:** ✅ a simulated malicious key substitution blocks the send in the
client (the conflict test); a diverging mirror causes refusal (the mirror's
fork tests, and the client's log-fault test); the self-audit alert fires end
to end (the owner's alert). **What the phase does not close is G3 itself:
the log is not deployed.** `adr/0006` says what "live" means.

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
  disclosure both need deciding here, not assumed. *Proposed in
  `adr/0005-call-media-path.md` (2026-09-10): direct after accept by default,
  no address leaves a device before accept, relay one switch away and your
  switch alone is enough; measured, a raw video SDP offer is a 16 384-bucket
  envelope, so 12.1 signals in compact JSON. Awaiting decision.*

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
  jittered schedule, so the list keeps its ~~1024-byte~~ 4 096-byte padding
  bucket (rev. 25) and the 16 KB envelope the signature needs is uncorrelated
  with a device change.
- **13.2 contact code v3** *(done — `identity_v3.dart`, PROTOCOL §18.2–18.3)* — `zc3.` carrying hybrid account keys and hybrid
  device certs; v2 codes still resolve with a "classical identity" marker.
  **Open problem — now decided: see `adr/0003-pq-identity-qr.md`.** Measured,
  a one-device v3 code is 7 373 B against a 2 953 B absolute QR ceiling, so it
  does not fit by a factor of nine against what actually scans. The QR carries
  a 32-byte **commitment** to the PQ half (not a "reference", which binds
  nothing and collapses into trust-on-first-use); the ML-DSA keys travel
  in-band and are checked against it, mismatch being a hard failure. The ADR
  also found that shipping hybrid certs in a device list moves it from the
  ~~1 024-byte~~ 4 096-byte padding bucket (rev. 25) to 16 384 or 65 536, telling the relay when an
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

  So the build path is now part of the recipe — the same absolute path as the
  release, which each release states — the way Debian records `Build-Path`.
  (First written as "clone into a directory named `z`": a third inference
  recorded as a finding, falsified by measurement on 2026-09-10 — the
  snapshot embeds the whole absolute path, and every recipe published from
  v2.3.8 to v2.4.7 was unfollowable. `REPRODUCIBLE_BUILDS.md` has the
  measurement.) **R16 is accepted, bounded and documented** rather than open:
  CI asserts machine-independence, and asserts that a path change moves those
  two libraries and no others, so the leak cannot spread unnoticed. The real
  fix is a relative URI, which is upstream work in the Flutter tool.

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

  Outstanding, and the project's to commission: the engagement itself. Phase 15's
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

  **Both are now fixed.** The fan-out is queued (below), and the skipped-key
  cache moved to its own cell in vault **schema 9**: a send with the cache at
  its 1 536-entry cap now costs **2.2 ms** more than one with an empty cache,
  against 20.7 ms before. All 147 protocol tests passed unchanged — the frozen
  vectors assert *which* keys the ratchet caches, not where they are stored,
  so this was a storage change and not a protocol one.

  Two near-misses on the way, both recorded in `PERFORMANCE.md` because both
  were silent: `INSERT OR REPLACE` empties columns it does not name, so the
  first version wiped the cache on every send with nothing failing at the
  time; and the send's rollback snapshot would have either kept the cost or,
  if the cache were simply dropped from it, emptied the cache on every
  rolled-back send — a message-loss bug inside an error path.

  **The latent one, as originally found:** Every send serialises the whole
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

  **The remaining ~14 ms is now attributed**, and it closes the list rather
  than extending it. The two candidates the earlier write-up assumed mattered
  — the ratchet step and the rollback snapshot — are together a quarter of a
  millisecond (0.23 ms and **0.02 ms**). The transaction as a send actually
  builds it is 3.94 ms. ~~About 8 ms is spread across lock acquisition, the
  contact lookup, the post-quantum offer check and async scheduling, with **no
  single term dominating** — so there is no further win here of the size the
  skipped-key cache was~~, and the batching item is left open but weaker than
  when it was written.

  **The struck-through sentence was wrong** (2.5.4, `PERFORMANCE.md`
  "Receive side"). The receive side — listed below as unmeasured — was
  measured last and held the largest cost in the app: the device's own
  device-list claim, stamped on every outgoing message and checked on every
  inbound one, was rebuilt from scratch each time for any account that had
  never linked a second device — eleven vault reads and an Ed25519 signature
  over its own certificate, 13.8 ms alone and ~40 ms under contention. The
  send-side write-up had it inside "spread across … no single term
  dominating", never timed on its own. Memoised (forgotten *after* each write
  that changes the list — forgetting first raced and flaked a device-list
  test one run in three), and the skipped-key cache re-sealed only when a
  receive actually changed it (a cheap shape check; the first test of it ran
  with an empty cache and passed against the old code, which is exactly the
  guard-that-never-fires mistake): **a receive went from 54.7 ms to 25.2 ms
  and a 1:1 send from ~22 ms to ~10 ms.** The receive at the cache's cap no
  longer pays for the cache at all.

  What is left of a receive is the sealed-sender open and the transaction
  (~6 ms of ~16 in the benchmark's own remaining number, once the delivery
  receipt is taken out — see the next paragraph) and nothing of the size
  any of the three fixes were.

  ~~**Open, and parked rather than shipped:**~~ **Shipped, once the flake
  was caught (rev. 26):** the delivery receipt was one full send per inbound
  message, ~10 ms, holding the same per-conversation lock the next inbound
  needs. Coalescing receipts over a 300 ms window (the wire format already
  carries a list of mids) takes a receive to 16.3 ms. It was built, tested —
  and parked, because it made `backup_test.dart`'s wipe-and-restore case
  fail intermittently, 6 first attempts in 22 against 0 in 12 on `main`,
  with a 0 ms window clean in 6, and sixteen instrumented runs had not
  caught the mechanism. "Probably a late receipt on a replaced session" was
  an inference, and shipping an inference is how this section acquired its
  struck-through sentence. Caught from the test side instead: the fourth
  row in a three-row history was a `decrypt_failed` system message — Bob's
  receipt for the last message, queued at the relay after the device was
  wiped, undecryptable after the restore. The test now waits for every tick
  before the phone is lost; the app was right.

  One hypothesis was tested and rejected, recorded because it was worth
  asking: every send fires an unawaited `flushOutbox()`, so a user offline
  with a growing backlog might have paid more per message than one with none.
  At 20 queued rows against 2 040 the difference is 1.7 ms. Not a scaling
  problem.

  Still unmeasured and named as such: ~~real hardware~~, devices-per-member (the
  extra-device fan-out is `unawaited` and not in these timings), cold start,
  and relay latency under sustained load. ~~And the receive side.~~ The
  cryptography itself — every primitive, pure Dart against OpenSSL on the
  same machine, and a Developer-mode screen that runs the same rows on a
  phone — was measured last, with the decision not to wire in a platform
  implementation and the rule for revisiting it (revision 39).
- **15.4 docs & support & access** *(accessibility, user docs and
  localization done: 14 of 14 screens migrated, and the app ships in English
  and Spanish — revision 35)*.

  `USING_Z.md` is the first document in this repository written for someone
  who is not reading the code: adding people, what a safety number is and what
  each of its three states actually says on screen, linked devices, why groups
  have no shared key, and an "if something goes wrong" section covering the
  five ways people lose access — forgotten passphrase, lost device with a
  backup, lost device without one, lost recovery code, stolen device. It is
  meant to be read before it is needed, and it says plainly that a lost
  identity with no backup is gone, because a support page that implies
  otherwise is worse than none.

  `WHAT_Z_CANNOT_DO.md` is the "what a compromised endpoint defeats" page the
  entry asked for, widened to every limit worth stating: the device in your
  hand, the person you are talking to, a global observer, no account recovery,
  an unaudited design, and the fact that nobody outside the project has yet
  rebuilt a release. It ends with what *is* left, precisely, because a claim
  too broad gets someone hurt and a claim too narrow gets ignored.

  **Localization has a foundation and a ratchet, not a finished migration.**
  There are ~480 hardcoded English strings across thirteen screens, and a
  large share of them is security wording — the safety-number banners, the
  "there is no way to recover it" note — where a careless translation
  misleads somebody. Extracting all of it in one pass at the end of a session
  would be the wrong way to do it, so what landed is: `flutter_localizations`
  and `flutter gen-l10n` wired up, `lib/l10n/app_en.arb` with per-string
  descriptions saying what each one is *for* (translators get the intent, not
  just the words), and the two pre-account screens migrated end to end as the
  worked example.

  `tool/check_l10n.py` is what stops it stalling at screen two: a screen
  listed as migrated must contain **zero** user-visible literals, so it cannot
  silently regress, and everything else is counted so the remaining work is a
  number that goes down. It found four strings on its first run — a
  concatenated multi-line footnote I had put in the ARB and never actually
  substituted.

  The a11y test also gained an **RTL pass**. Arabic is one of the six locales
  Z publishes release notes in, and right-to-left breaks in ways nobody sees
  until somebody tries it — a `Row` that wanted an alignment, an
  `EdgeInsets.only` that wanted to be directional. Forcing the direction
  catches those before the strings exist to test with.

  One consequence worth knowing: any test pumping a localized screen must
  supply `AppLocalizations.localizationsDelegates`, or `AppLocalizations.of`
  throws. Four suites needed it, including `screenshots_test`, which is how
  the README's screenshots get rendered.

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
- **15.5 GA criteria checklist** *(written — `docs/GA_CHECKLIST.md`; the
  answer is **NOT READY**)* — nine criteria with their real status. Met:
  backup and restore, multi-device, published threat model, accessibility
  (for the checks that exist), localization (English and Spanish, with a
  native reader's review named as the caveat). Unmet: the audit is not
  commissioned, iOS does not exist, the transparency log is built end to end
  and not deployed, and reproducible builds hold as a property but **nobody
  outside the project has checked** — the one criterion this project
  structurally cannot self-certify.

  **The finding was G3.** "KT live" was written into the GA criteria at the
  start of phase 8, and `adr/0001` gated key transparency on *"public launch
  with an operator committed to durable infrastructure"*. So GA required KT
  and KT's trigger was a public launch: a circular dependency that no amount
  of code resolves. It was resolved by decision, in the direction of running
  the log (`adr/0006`); phase 11 built it, and what remains of G3 is a
  deployment with four conditions the checklist names.

  `tool/check_ga.py` keeps the page honest: it fails if a KT client appears
  while the page says none exists, if G3 is ticked while the client's pinned
  log key is empty, if G9 is ticked with one locale file, if `app/ios/`
  appears while the page says it does not, if the migrated-screen count
  drifts, if the status sentence's number disagrees with the ❌ rows, and —
  the one that matters — if the summary says READY while any row below is
  still ❌. Each verified by breaking it. The string-count guard needed fixing first: its regex
  wanted a space where the prose had a line wrap, so it matched nothing and
  passed silently, which is worse than no guard at all.

**Exit:** 1.0 shipped on Android, iOS, Windows, macOS and Linux from signed,
reproducible artefacts.

---

## Phase 16 · What the relay can still see, and other relays

Added 2026-09-11, after phase 11. Two threads that were named as "choices"
rather than planned: what an honest look at the relay's remaining view
turns up and what, if anything, buys it down; and whether Z should have
more than one relay that talk to each other.

- **16.1 sender anonymity at the relay, actually** ✅ — the study's first
  item was a finding, not a measurement: sealed envelopes were sent on the
  device's authenticated connection, so the relay *process* held the sender
  of every envelope the *envelope* withheld (`adr/0007`, revision 36). Fixed:
  the relay accepts sealed sends on a connection that never authenticated,
  the client holds an anonymous link for them and never falls back to the
  authenticated one, and the relay's own metrics count that every sealed
  envelope a conversation produces arrived unattributable
  (`anonymous_sender_test.dart`). What remains is the network address —
  R21, written down where the stronger claim used to be. Cost measured:
  two sockets per device; at the same rate, the tail triples past a
  thousand sockets (`PERFORMANCE.md`).
- **16.2 the pattern study (R18, R19)** ✅ — what jittering or delaying the
  group fan-out and the device mirror would buy against a relay that
  clusters mailboxes by co-occurrence over many messages, and what cover
  traffic would cost. `server/bench/patterns.js` (`npm run bench:patterns`):
  a seeded simulation, 600 mailboxes over three days, an attacker who
  counts co-activations per pair and flags what chance cannot explain. The
  numbers (`THREAT_MODEL.md`, "Timing patterns"): with nothing done a
  five-member group is named after 8 messages and a person's two devices
  are paired after 3; a minute of jitter makes those 50 and 30; only ten
  minutes of delay on every message pushes a busy population past the
  2 000 messages the study stops at, and a quiet one needs an hour; cover
  traffic of 1.4 MB a day per device buys days, not weeks; and a patient
  relay gets every cell eventually, because a real pair's count grows with
  every message and a chance pair's spread only with the square root. The
  decision is the documented "not worth it": no jitter, no cover traffic;
  R18 and R19 now carry the price of the option they reject, and the
  answer stays a mixnet or your own relay (revision 37 for what the study
  got wrong on the way).
- **16.3 federation** ✅ *as a design* — `adr/0008`: if Z ever lets people
  on different relays talk it is client-to-many-relays — the sender opens an
  anonymous link to the recipient's relay and nothing travels between
  relays — with a device-signed relay statement (`rs`, `z-relay-v1:`)
  carried in codes and device lists as a compatible extension. Shape B
  (relay-to-relay) puts an extra operator on every envelope and needs a
  protocol Z does not have; a directory is the thing Z refuses to build.
  **Not built**: one public relay, and the self-hosted ones serve closed
  groups; the trigger is a second relay whose users need the first's. The
  members and context are reserved by the record.

**Exit:** 16.1's claim holds from the relay's side; 16.2 has a number for
every option it considers and a decision; 16.3 is an accepted or rejected
ADR.

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
   device-list update out of the ~~1 024-byte~~ 4 096-byte bucket (rev. 25) that ordinary chat occupies
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
   list does not put them back in the ~~1024~~ chat buckets, it only decorrelates them
   in time, and ADR 0003's "16 384 or 65 536" was ~~really 16 384 for one to
   three devices with the cliff at four~~ 16 384 for one or two devices with
   the cliff at three (rev. 25 — that sentence was itself an inference). But the deciding argument was not
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

23. **15.3 — the receive side, measured last, held the largest cost in the
   app.** The send-side write-up closed the performance list with "no single
   term dominates the remaining 8 ms". The receive side, which that write-up
   listed as unmeasured, was then measured and found `_ownListClaim()` being
   rebuilt from scratch — eleven vault reads and an Ed25519 signature — on
   every message in both directions for any single-device account, which is
   nearly every account. It had been sitting inside "spread across". A
   receive went from 54.7 ms to 25.2 ms, a send from ~22 to ~10 ms, and
   the send-side conclusion is struck through in place rather than removed.
   Two of the fixes' first versions were wrong in ways their tests caught
   only after the tests themselves were fixed (an invalidate-before-write
   race; a guard that ran with an empty cache and so could not fire), and
   a third — coalescing delivery receipts — ~~is parked unshipped because it
   made a restore test fail one time in four and the mechanism is not yet
   caught~~ was parked until the mechanism was caught (rev. 26). The lesson is the one this section keeps re-learning: measure
   the thing before concluding about it, and the thing listed as unmeasured
   is the thing to measure first.

24. **14.2 — "the parent directory does not matter" was never measured, and
   it is false.** Every CI slot that agreed built at the same absolute path;
   the one that differed varied the last component only. Built once at two
   parents with the same leaf name: different bytes, the whole absolute path
   embedded. Every content digest published from v2.3.8 to v2.4.7 was
   unmatchable by its own recipe, and the release APK was not even built at
   the path the recipe named. The release job now reads the build path out
   of the APK's own `libapp.so` and prints that; since 2.5.4 it also builds
   at the slots' path and writes whether a debug-signed build at the same
   path reproduced the digest into `SHA256SUMS.txt`. `--split-debug-info`
   was tried as a way out and does not remove the URI. The fix is upstream.

25. **§8 buckets — the bucket column in two accepted ADRs was inferred from
   inner byte counts, and the boundaries are a quarter of what it implied.**
   ADR 0003's and ADR 0004's size tables read buckets off `sealedBuckets`
   from inner-message sizes. Between an inner message and its bucket sit the
   ratchet's 256-byte padding and two layers of base64 in JSON. Sent through
   the real pipeline, the 1 024 bucket holds one ratchet block — a text of at
   most ~180 characters, a receipt, a reaction — and a classical device list
   of any realistic size is a 4 096-bucket envelope, the bucket of a text of
   ~190 to ~1 900 characters. `pqid` is 16 384, not 4 096. The per-device
   cliff ADR 0004 put at four devices is at three. Every decision stands —
   a device list is still the size of ordinary chat, a post-quantum artefact
   still is not, and nothing in 0004's deciding argument is a size — but
   six documents (both ADRs, PROTOCOL §18.4 and §18.9, DATA_MAP, this file,
   AUDIT_SCOPE C23) stated a number that was never measured, one of them
   under a heading that began "Measured". `protocol/test/sealed_bucket_test.dart`
   now pins the boundaries the documents quote, and was broken once to
   check it fires. Found while measuring call signalling shapes for
   `adr/0005`, which is why that ADR quotes only what the same harness
   produced.

26. **15.3 — the receipt flake was the test, and the inference was wrong.**
   Coalesced delivery receipts were parked (rev. 23) because
   `backup_test.dart`'s restore case failed one time in four and sixteen
   instrumented runs had not caught why; the suspected mechanism was a late
   receipt landing on a replaced session. Instrumenting the *test* instead
   of the service — a dump of the chat when the count was wrong — caught it
   on the second run: the extra row was a `decrypt_failed` system message.
   Bob's receipt for Alice's last message, delayed by the 300 ms window, was
   queued at the relay after her device was wiped, and the restored device,
   holding no session, reported an envelope it could not read. Correct
   behaviour. The dispose-time flush the first version had failed the same
   assertion, 4 in 6, not the session-convergence story recorded against
   it. The test now waits until every message Alice sent shows delivered
   before the phone is lost — Bob has nothing left to send — and the
   receipts ship: receive 25.2 → 16.3 ms. Two lessons. Instrumentation in
   the thing under test moves the race; instrument the observer. And a
   mechanism written down as "suspected" is a to-do, not a finding — this
   one was recorded in a commit message as if seen. One follow-up worth
   noting, ~~not done~~ done in the commit after: after a restore, every
   envelope queued while the device was gone produced its own notice,
   receipts and typing included; it is now one notice per contact per
   episode, with a count, and one hello per burst
   (`restore_notices_test.dart`, `BACKUP.md` §2.2).

27. **§18.2 — the identity exchange sent its 16 KB envelope twice each way,
   and completed by accident.** Counted from the relay's side in an offline
   harness, a mutual add queued the ML-DSA key twice in each direction: the
   volunteering and nudging paths both fired on the same hello, and the nudge
   fired again on the first envelope of the reply batch with the peer's key
   one envelope behind it. Worse: the case the nudge exists for — an opening
   send that vanished because the peer had not added us — completed only
   because that accidental nudge fired; the answer-in-kind path was gated on
   "already volunteered", which is precisely the send that had vanished, so
   with the batch in the other order the exchange never completed. Now
   every reason to send is one debounced send that says whether the peer's
   key is held (`ack`, an additive field older clients ignore), a key that
   arrives with `ack` is not answered, the opening key goes with the hello so
   the two land in one batch, a re-send waits longer than an answer and
   much longer on the initiator (its key went with its hello) so two do not cross, and a re-send whose
   commitment was met while it waited is dropped. One envelope each way, in
   both cases, in either batch order (`pq_identity_exchange_test.dart`, four
   criteria, two broken on purpose: ack ignored — 4 where 1 was expected;
   the nudge never skipped — 2). The pairing signal that remains is R17 in
   the threat model, which did not exist as a row before because nobody had
   counted.

28. **M4 — the copy to a contact's other devices held the conversation lock
   across the network, and vanished when the link was down.**
   `_fanToContactExtras` was a direct `transport.send` per extra device,
   awaiting the relay's ack (20 s timeout each) inside the per-conversation
   lock, so a stalled link froze every send and receive with that contact
   for as long as it stalled; and with the link down it threw and was
   swallowed, so the laptop's copy never left us — the contact's phone
   mirrors what it receives to its siblings, which is the only reason
   nothing was ever missed. It goes through the durable outbox now, like the
   primary copy, and the lock covers the ratchet step and the writes only.
   `extras_fanout_test.dart`: two outbox rows for a two-device contact with
   the link down (was one); a second message accepted at once with the link
   stalled (was: a five-second timeout). Two relatives of the same shape
   went the same way — the 7.7a removal notice to a dropped device, which is
   the whole of what tells a silently excluded device it was excluded and
   was a direct send that a down link turned into no notice at all, and the
   ML-KEM offer to a contact's extra device. All four fired on the old code.
   The
   cost is in PERFORMANCE.md, measured: about one extra send's worth for
   the first extra device, little for the ones after. Found by reading the
   "not measured" list for the next thing to measure — the same way the
   receive side was found — and it was the same shape as the receipts: a
   send nobody waited for that everybody waited behind.

29. **The trust table said the relay "cannot learn who is in a group". It
   can, from the pattern.** No group id and no membership travel on the
   wire, which is what that cell meant; but a group message is one envelope
   per member sent in one burst, and the same mailboxes burst together every
   time anyone in the group speaks. Measured (`group_spread_bench_test.dart`,
   five members, one relay on loopback): the members' copies are
   relay-stamped within 64–135 ms of each other, every message. The cell now
   says "from any envelope", R18 records the pattern with the number, and
   spreading the fan-out was considered and rejected there — it costs every
   group message a delay and does not survive a relay that averages over a
   conversation. The threat model already said the relay "can correlate
   timing across mailboxes" in prose; the table contradicted it in a cell,
   and a cell is what an auditor reads. The same measurement, made for a
   person's own devices (`device_link_spread_bench_test.dart`): the laptop's
   copy is relay-stamped 15–22 ms after the contact's when the phone sends
   and 31–53 ms after the phone's when the contact sends — so "the relay
   cannot group a person's devices" (WHITEPAPER §3) was the same
   overstatement, now qualified the same way, with R19 — which also records
   that linking is loud on its own: the history replay reaches the new
   mailbox as 65 536-bucket envelopes (two for a 250-message chat, measured),
   a size nothing but linking produces. The user-facing
   `WHAT_Z_CANNOT_DO.md` and the website's "Groups" and "does not protect
   against" paragraphs said the flat version too ("indistinguishable from
   direct traffic at the relay"; "cannot work out who is talking to whom")
   and now say from what, in plain words. Two relay tests also stopped
   deriving their port from the clock (the last two that did; a collision
   failed a whole file in setUpAll once today).

30. **15.3 — cold start was the last thing on the "not measured" list, and
   it was linear in the contact count at 6 ms each.** 2.5 s for four
   hundred contacts on a desktop VM, several times that on a phone, before
   the first screen had anything to show. Every startup loader read its
   per-contact keys with `kvGet`, which tried the sealed storage class and
   then the plain one as two queries — fifteen round trips per contact —
   and unread was a `COUNT` per chat. Now `kvGet` is one query for every
   read in the app, `init` reads each per-contact key family once by prefix
   (`Vault.kvScan`), and unread is one `GROUP BY` measured never slower than
   the per-chat form. 400 contacts: 2 527 → 397 ms; per contact 6.3 → 1.0
   (`coldstart_bench_test.dart`, PERFORMANCE.md "Cold start";
   `vault_kv_test.dart` pins the store's semantics, broken once). The bench
   also caught the group fan-out drain that `init` kicks unawaited throwing
   unhandled when the vault closes under it — an app crash on the way out —
   which now returns quietly like `flushOutbox`. The receive side taught
   this section to measure the thing listed as unmeasured first; this was
   the last such thing, and it was the biggest number left.

31. **A durable queue needs a rule for a device that stops existing.** Once
   the extra-device copy went through the outbox (rev. 28), a message
   queued for a contact's laptop while the link was down would have been
   delivered after that laptop was dropped from the contact's list — the
   direct send it replaced had simply lost it, which was accidentally the
   safer behaviour for a *revoked* device. Now a list that drops a device
   discards everything queued for it before queuing the removal notice,
   and removing one of my own devices discards the self-sync traffic queued
   for it (`extras_fanout_test.dart` criteria 5 and 6, both fired without
   the deletes; PROTOCOL §3.6). The lesson is the general one: making a
   path durable changes what "late" means, and every late case has to be
   read again.

32. **15.3 — the relay's latency profile, the other unmeasured item, is
   measured.** `server/bench/latency.js` runs sender/recipient pairs at a
   steady rate under the per-connection limit and times each message from
   `send` to the recipient's frame, in-process. On loopback, one Node
   process, load generator sharing its event loop: ~1 000/s at p50 0.6 ms
   and p99 6.6; ~2 000/s at p99 33; ~2 450/s across a thousand sockets at
   p99 72; ~4 900/s across two hundred sockets at p99 14 — nothing lost at
   any shape. The tail follows the socket count, not the message rate.
   PERFORMANCE.md has the table; SELF_HOSTING.md says what it means for
   sizing. The "not measured" list is now real hardware and nothing else.

33. **The transparency log's first map was correct and could not have run.**
   `kt/lib/smt.js` v1 kept the labels sorted and memoised internal nodes by
   range, clearing the memo on every set — right in every test, and a head
   after a publish cost O(N) hashes: 104 ms at ten thousand labels, found
   by `kt/bench/proofs.js` on its first run, not by the eight tests that
   passed. The compact tree replaced it (one record per single-label
   subtree, log N internal nodes on a set, the root free); the same bench
   also found the log tree's memo growing as N log N by remembering ragged
   ranges no later proof asks for. A test says a structure is correct; a
   bench says whether it can be used. Both files say so in their headers.

34. **11.5 was rewritten before it was built, and the ADR says why.** The
   roadmap's text moved device-list distribution *into* the log with in-band
   as a one-release fallback. Built that way, a log outage would stop
   messaging — the kill switch 11.2 forbids in its own words. So in-band
   stays primary and the log is the check on it and a source when it is
   ahead (`adr/0006`, "Considered and rejected"). The related rule that
   took the most deciding: an account with *no* entry never has its devices
   held, because an older client and an attacker who never publishes look
   the same, and holding would cut every multi-device contact on an older
   build off after a day. The protection begins with the account's own
   first publish, which every root makes at its first check after
   upgrading — the window closes as clients update, without a flag day.
   The ADR's table originally read otherwise in one parenthesis; the client
   and the table now agree, and `key_transparency_test.dart` pins the
   unlogged case.

35. **G9 — the app ships in Spanish, and the guard learned what a second
   locale can get wrong.** `app_es.arb`: 408 strings, the same claim per
   string as the English, neutral Spanish in the tú form, "relay" left as
   the product's own word. The guard that held screens to zero literals
   now holds every other locale to exactly the English key set with the
   same placeholders and plural cases — because a missing key does not
   fail a build, it shows one English sentence among Spanish ones, and a
   placeholder renamed in one locale is a crash in that locale only; both
   were broken once to see it fire. `locale_es_test.dart` checks the
   plurals, the stored system messages rendered in Spanish with their
   durations, and that no string was copied through. The caveat is on the
   checklist in the same words as G8's: the translation was made
   in-project, and a native reader is the step that remains. It is a
   review, not a blocker.

36. **The relay was being handed the sender by the socket.** Sealed sender
   removed the sender from the envelope and every document said the relay
   could not tell who sent one; `send` required an authenticated
   connection, the client had one connection, and it was authenticated as
   the device — so `state.rid` sat next to `to` in the handler of every
   sealed send. True of the relay's memory dump, false of its operator, for
   as long as sealed sender has existed. Found by reading the relay for
   16.2 rather than by any test, because every test checked the envelope
   and the stored entry — the channels the mechanism was designed around —
   and none asked what else the relay held at that moment. Fixed in 16.1
   (`adr/0007`): sealed envelopes go on an anonymous connection, the relay
   accepts them there, and the test that pins it counts from the relay's
   metrics. The claim was rewritten to what is now true — an address
   remains, R21 — rather than deleted. The rule: **a claim about what a
   party cannot learn has to be checked against every channel that party
   has, not the one the mechanism was designed for.**

37. **The pattern study produced three plausible tables before it produced
   a true one, and all three were the attacker's null model.** The
   simulation (16.2, `server/bench/patterns.js`) gives the attacker a
   chance model — how often two unrelated mailboxes co-activate by
   accident — and lets it flag what the model cannot explain. Three bugs in
   that model, in turn: the expectation was rounded to three decimals
   before it was tallied, which sent every small one to zero, so forty
   quiet pairs a run passed the threshold "by chance" that the model said
   was impossible; the fast counting path (bins of the window's width,
   same-or-adjacent) catches pairs across 3W while the model was told 2W, so
   the count ran half again above the expectation and half the population
   was flagged; and the threshold search was capped at 64, so a busy cell
   in which the attacker needed a count of 80 read as ">2 000". Each
   produced a table that looked like a result — one in which the quiet
   column, the easiest for the attacker, read ">2 000" all the way down;
   one in which every mitigation worked; one in which a minute of jitter
   was enough at ordinary rates and a person's devices could never be
   paired — and each would have gone into the threat model with a straight
   face. What caught them was not reading the tables but checking the
   model against a brute-force count of the same events before reading
   them: the measured chance mean against `n_a·n_b·2W/T`. The first
   suspect for the half was the random generator, which was swapped and
   later cleared (either one matches the expectation within noise). The
   rule: **a simulation's null model is checked against brute force before
   its table is read, because a wrong null model does not produce nonsense
   — it produces a table.** Two smaller ones: `GROUPS` is a bash variable,
   so the environment knob is `NGROUPS`; and `pkill -f <pattern>` matches
   the shell command that contains it and killed the chain that was
   editing the file, which is why two of the fixes above were applied
   twice.

38. **The queue caps evicted, and the two modes did not even agree on
   which.** A recipient's queue has a count cap and a byte cap. In RAM
   mode both were enforced by shifting the *oldest* entry out; in Redis
   mode only the count was (`rpush` + `ltrim`), and a Redis LIST has a
   length, not a size, so the byte cap was a setting with nothing behind
   it. Both facts surfaced from the HA deployment: release 2.7.3's
   Blueprint chose `noeviction` for the store — a full store refuses a
   send, loudly, rather than evicting a queue whose sender had already
   been told `sent` — and the commit that chose it wrote down that one
   sender to one offline recipient could fill the whole store, because the
   per-mailbox byte cap did not exist there. Reading the RAM path for the
   fix showed that it had the same flaw one level down: eviction meant
   anyone holding a routing id could *erase* what was queued for it by
   sending 64 MB of junk, silently, with every honest sender holding a
   `sent`. Fixed the way the store was: a `send` that would cross either
   cap is refused with `error{queue_full, id}` — a compatible extension,
   §14 — and nothing queued is ever made room for; in Redis mode the byte
   count is a counter beside the list, settled in the same Lua script as
   every push and removal so two instances cannot race past the cap,
   self-healing to zero whenever the list empties (which is also how the
   entries a running store already held, queued by the older relay
   without a size, cannot leave it wrong for long). The client keeps a
   refused envelope pending, lets nothing else in its outbox wait behind
   it, and retries in a minute; before this it would have stopped its
   whole flush at the first full mailbox, as it does for any code it does
   not know. `queue_caps.test.js` (against a real `redis-server`, two
   instances, and the old-entry transition) and `queue_full_test.dart`
   (three clients through the real relay) pin it; the flood case in
   `load.test.js` now asserts the eighty refusals and that the first
   hundred are untouched. R22 records what remains — a mailbox can be
   *filled* while its owner is away — and why that is accepted. The rule:
   **a limit that exists as a setting has to be tested at the setting,
   in every mode the setting applies to** — the byte cap had a row in
   three documents and a test in none.

39. **The last "not measured" item was the cryptography, and measuring it
   changed the question.** The list had said since 15.3 that all of Z's
   crypto runs in Dart and that what a platform implementation would buy
   was "unmeasured and a decision, in that order". `protocol/lib/bench.dart`
   times every primitive the way Z uses it — medians after a warm-up,
   through `cryptography` and `pqcrypto` and the protocol's own sealed
   envelope — and `server/bench/native_crypto.js` runs the classical ones
   through OpenSSL on the same machine as the stand-in for a platform
   implementation. Pure Dart, compiled ahead of time, is 5–7× slower than
   OpenSSL on hashing and the AEAD at a kilobyte, 18–35× on X25519 and
   Ed25519, 72× on an Ed25519 signature, and 3.4× on Argon2id; the VM's JIT
   is slower still on most lines and, oddly, faster on the 64 KB AEAD. So
   the gap is real and large in ratio — and small in what a user does: a
   sealed envelope is 1.5 ms, a text is one of those plus a quarter of a
   millisecond of ratchet, and the two places it could add up are a large
   attachment (about two seconds of AEAD for 25 MB, each way) and the
   passphrase unlock (128 ms here, a phone's multiple of that). The
   question stopped being "native or not" and became "what would have to
   be true on a phone for native to be worth a second dependency and a
   platform boundary per call": the rule is written in PERFORMANCE.md
   (unlock past a second, or a 25 MB attachment past five seconds of
   crypto, on a mid-range phone), and the phone measurement is one tap —
   Settings → Developer → Cryptography benchmark runs exactly the same
   rows (`crypto_bench_screen.dart`, the fifteenth screen, migrated on
   arrival) and copies them as the document's table, so the phone's column
   is a paste away rather than a guess. Two things worth writing down. The
   JIT column is what `flutter test` measures and the AOT column is what
   ships, and they differ by up to 3× on individual lines in both
   directions — every earlier number in PERFORMANCE.md is a JIT number, and
   its *shapes* were the point, not its milliseconds. And the post-quantum
   pair has no platform implementation on Android to move to at all, so
   the ceiling on what native would buy is lower than the ratios suggest.

40. **G3 was four conditions and an afternoon; now it is four conditions
   and a few pastes.** The runbook for the log was a systemd unit and a
   `docker run`, and the witness was "serve `sth.json` from any static
   host" — true, and the kind of true that keeps a criterion open for
   months. Two Blueprints beside the relay's: `render.kt.yaml` deploys the
   log from its image with a persistent disk for the entries file and the
   signing seed as a dashboard-only secret (`sync: false` — the file that
   describes the service never holds the key, and the guard refuses a
   literal); `render.kt-witness.yaml` deploys the *same* image with the
   mirror as its command, which is why the mirror gained a `--serve` mode
   (`GET /sth.json`, the co-signed head a client fetches; `GET /health`)
   and reads every option from the environment. Two decisions on the way.
   A witness that diverges keeps serving the head it last verified rather
   than exiting: that head is exactly what a client needs to catch the
   fork, since the log can no longer produce a consistency proof from it —
   so `/health` stays 200 with `diverged: true`, because a host that
   restarted an "unhealthy" witness would only make it reload the same head
   and diverge again. And the image starts as root for two chores and
   then drops privileges (`docker-entrypoint.sh`): a mounted volume or a
   cloud disk arrives owned by root, and a seed file mounted read-only is
   root's and mode 600 — which means the Docker command the runbook had
   given since 11.1 could not have read the seed it mounted. Nobody had
   run it. `tool/check_blueprints.py` holds every `render*.yaml` to no
   literal secret, a health check, a disk mounted where its data variable
   points on a plan that can carry one, and quoted `"off"`s; each of those
   was tried wrong once to see it fire. Not verified here: the image build
   and the Blueprint creation themselves, which need a daemon and a
   dashboard; the entrypoint was run as root against a root-owned
   directory and a root-only seed with the real log behind it, and the
   witness service against the real log, a fork, and the environment
   alone. The rule: **a runbook step nobody has executed is a hypothesis
   with a heading.**

41. **A full store used to lock everyone out, and the fix started by
   finding out what "full" actually refuses.** The production store runs
   `noeviction` (2.7.3), so at its memory limit it refuses writes. The
   master's note on the cutover said what followed: a send threw inside
   the relay and the client got `error{internal}` with no id, so every
   send waited out a twenty-second timeout; and a login failed at the
   presence write, so nobody could connect — not even the owner of the
   mailbox that needed draining. Before building anything, a real
   `redis-server` was put at `maxmemory` and every operation the relay
   makes was tried against it, because the plan in my head had a third
   failure in it: that 2.7.6's removal script would be refused too, and
   the store could never drain. It would not have been. Redis refuses
   `SET`, `INCRBY`, `RPUSH` and any script whose *first* write is one of
   those, and allows every read, `LREM`, `DEL`, `EXPIRE`, `PUBLISH` — and a
   script that has already written is allowed to go on writing, so a
   script whose first write is `LREM` gets its later `DECRBY` too. The
   relay had been leaning on that rule without knowing it; the scripts now
   say it out loud with Redis 7 flags (`allow-oom` on the removal, none on
   the push, which is refused before it runs). The two real failures are
   fixed: a send the store cannot hold is answered `store_full` with its id
   in milliseconds and the client's outbox pauses on its own timer rather
   than the next reconnect; a login whose presence write fails still gets
   `ready` and its flush, its acks still land, and the heartbeat writes
   presence once there is room — meanwhile an instance serves its own
   sockets live from its own knowledge rather than from the store's, which
   was the right rule anyway. `full_store.test.js` drives it end to end on
   two instances at 4 MB: refused in under two seconds, a login while full
   that drains, a drain that heals, a heartbeat that repairs;
   `store_full_test.dart` watches the client's timer keep knocking through
   the relay's refusal counter. The rule: **a store's limit is part of the
   relay's contract — every operation the relay makes at that limit is
   either allowed or refused, and which is a measurement, not a
   recollection.**

42. **Draining a mailbox on the production path was quadratic, and the
   bench that showed it found a second fault in the way.** In Redis mode
   every acknowledgement read the recipient's whole mailbox back from the
   store to find the one entry to remove, so a backlog of two thousand
   short texts cost 38 seconds and four gigabytes of reads to empty
   (`server/bench/drain.js`; PERFORMANCE.md, "Draining a mailbox"). The
   bench hung at five hundred before it could show that, and the reason
   was the second fault: acknowledgements counted against the per-
   connection rate limit, so a device acknowledging a backlog as fast as
   it persisted it had everything past the burst of 240 dropped — the
   entries stayed queued, and a mailbox of more than 240 could not be
   emptied in one connection. The queue is now a list of keys with the
   entries in a hash beside it: a flush is two reads, an acknowledgement
   one read and one small script, five thousand envelopes empty in under
   half a second, and reads are twice the mailbox instead of hundreds of
   times it. Acknowledgements are exempt from the rate limit, which they
   should always have been — one costs the relay almost nothing and frees
   memory. A retried send with the same id is now stored once and
   acknowledged, which the layout made free. Entries a running store still
   holds from the older relay are read and removed the way it left them
   until they expire (`drain.test.js`, all three cases). Two rules. **A
   per-operation cost on the drain path is paid once per envelope in the
   backlog, so measure it against a backlog, not a message.** And the
   bench's own artefact — one sender crossing the burst — was the same
   fault seen from the other side; a benchmark that will not finish is a
   finding before it is a bug in the benchmark.

43. **Two promises the relay was making and one of them was not true.**
   `QUEUE_TTL_HOURS` is documented per envelope — "undelivered envelopes
   vanish on expiry" (§12.5), "until delivered, until TTL, or until the
   store restarts" (DATA_MAP) — and in RAM mode it was, untested. In Redis
   mode the lifetime sat on the mailbox's *keys* and every new push
   refreshed it, so a mailbox that kept receiving held its oldest
   envelopes for as long as anything arrived, up to the cap: an abandoned
   account whose contacts keep writing is exactly that mailbox, and a
   seventy-two-hour promise became indefinite for the one case where it
   mattered most. Expiry is per entry now, from the head, at every flush
   and from a SCAN-driven sweep. The second promise was never written
   down, which is why nothing caught it: a reconnecting device asked for
   its whole backlog and the relay read all of it and wrote all of it into
   that one socket, so the relay held the backlog — up to the 64 MB cap —
   until the device finished reading. Measured on a client that pauses its
   TCP socket with 19 MB waiting: **15.1 MB held for one paused reader**,
   against 320 KB after. On a 512 MB instance a hundred such reconnects
   was the machine, and a device on a slow link was the normal case, not
   the abuse case. The flush is paged now, waiting between pages until the
   socket drains below a mark, in both modes; the store is spared the same
   way (4 MB read rather than 19 while the reader is paused). Writing the
   ordering consequence down in §12.5 was part of the fix: a live envelope
   can now arrive between pages, which changes nothing a client may rely
   on — delivery was already at-least-once and unordered across
   reconnects — but a reader of the protocol should not have to derive
   that. One thing found on the way: the legacy-entry removal path added
   in 2.7.9 decremented the byte counter for entries that counter never
   held, so a mailbox mid-transition under-counted itself and
   under-enforced its cap (clamped at zero, reset when the mailbox
   emptied — transitional, and wrong). The rule: **a limit in a document
   is a claim about every mode the code runs in, and the mode nobody
   tests is the one the claim is false in.**

44. **The documents described one process; production had been two since
   the cutover.** Not a bug — a set of sentences that were true when they
   were written and became imprecise the day `zmessengers.com` moved to two
   instances sharing a RAM-only store. The claim that mattered was
   retention: "the machine forgets it on restart" was in the threat model,
   the whitepaper, the data map, the user guide, `WHAT_Z_CANNOT_DO` and
   three places on the website, and with a shared queue a *relay* restart
   no longer forgets anything — the store's does. That cuts both ways and
   both halves are worth saying: a redeploy no longer drops what is in
   flight (better for users), and there is a second piece of memory whose
   "no persistence" setting has to hold (more surface for the same trust).
   So the pass says where the bytes are, that the setting is in a
   Blueprint in the repository rather than in an assurance, and that the
   host running the store is the host already running the relay — one
   party, not a new one. R14 gains that sentence; the trust table says
   "once the memory holding it has restarted — every instance's and the
   store's, which is what nothing at rest means here"; `DATA_MAP` gains
   the store column, the presence record's instance and its minute-long
   life, and per-instance metrics; `AUDIT_SCOPE`'s system table says the
   Redis path is the one production runs and that a queueing change has to
   be read in both. The privacy page needed it most and had the weakest
   version of it, which is the pattern: **the further a claim is from the
   code, the longer it survives being false.** Nothing here changes what
   the relay holds or who can read it; four documents now say so about the
   deployment that exists.

45. **Five releases of relay code written and reviewed by the same
   session, then read by a stranger.** 2.7.9 to 2.8.2 rewrote the queue,
   the acknowledgement path, expiry, the flush and the rate limit — and
   every line of it was written and reviewed in one context, which is
   exactly the arrangement the builder/pusher split exists to prevent. So
   the accumulated diff was given to an adversarial review with no memory
   of writing it. It came back with three findings; all three reproduced,
   and each was a case of the same thing — **a claim tested at the size
   that makes it true.**

   *A group's delivery receipts, three sent and one delivered.* An entry's
   key was `m:<id>` for a message and `r:<id>` for a receipt, and a push
   that found the key taken discarded the entry and answered `sent`. But an
   `id` is the sender's choice: one group message is one id sent to every
   member, and each member's acknowledgement produces a receipt carrying
   that one id. The first member to acknowledge took the key and the other
   two receipts were dropped, so a sender in a group of three saw one tick
   instead of three. Only in Redis mode — the RAM queue appended and kept
   all three — and no test compared the two coordinators, because each was
   tested against what it happened to do. A key now carries the party the
   entry belongs to; where the relay cannot attribute an entry at all (a
   sealed envelope carries no sender) it keeps up to `ID_SLOTS` of them
   rather than guessing which duplicate to drop, and the client dedupes on
   the inner id — which it can read and the relay cannot.

   *Ten acknowledgements, 59 MB.* The 2.7.9 rewrite made the *matching*
   acknowledgement cheap and left the miss with the old fallback: read the
   whole mailbox and look. Anything reached it — a device retrying an
   acknowledgement the relay had already acted on, or a socket sending
   whatever it liked — and the same release had exempted `recv` from the
   rate limit, for the good reason that a draining device must not be
   throttled. Ten unknown ids against a 5.9 MB mailbox pulled **58.6 MB**
   out of the store in four seconds and were still going. The fallback is
   gone; an acknowledgement is a fixed, small number of keyed lookups
   whatever it names (1 436 bytes for the same ten, measured), and the
   exemption now covers only an acknowledgement that frees an envelope —
   which is what the exemption was always about.

   *The paged flush did not bound what the document said it bounded.*
   2.8.1's page was `FLUSH_PAGE` *entries*, and `PERFORMANCE.md` said the
   relay therefore held "a page plus the mark, about 5 MB". An envelope may
   be `MAX_ENVELOPE_BYTES`, so a page of 64 is 64 MB: against envelopes
   that size a paused reader had the relay buffering **4.8 MB**, and every
   backpressure test had used 64 KB envelopes, where the entry count keeps
   a page small on its own. The tests passed for a reason unrelated to the
   claim they were written for. A page is bounded by both now, on the
   bodies actually read, and the honest figure is the mark plus the one
   envelope that crossed it.

   Two things came out of the pass that outlast the three fixes.
   `server/test/parity.test.js` runs one scripted scenario against both
   coordinators and compares the frames the clients receive, frame for
   frame — the group receipts, a retry, two senders on one id, a sealed
   envelope, a full queue, a refused recipient — so a future change that
   makes the two modes disagree fails a test rather than waiting for a
   stranger to read the diff. And each new criterion was checked against
   the *old* code first: criteria 4 and 5 of `flush_backpressure.test.js`
   report 4.8 MB against the pre-2.8.3 bound and 977 KB against this one,
   which is the difference between a test and a decoration. The rule:
   **a test written by whoever wrote the code tends to be sized to the
   answer, and the size is where the claim hides.** The reviewer had no
   such incentive, and neither does the parity test.

   The parity test earned its keep before it was committed: it failed one
   run in three, and the difference was a recipient handed one envelope
   twice in Redis mode. Not a divergence — `ready` is sent before the
   mailbox is flushed (so that a client is not kept waiting on a 64 MB
   backlog to learn it is authenticated), and an envelope that arrives in
   that window is delivered live *and* picked up by the flush still
   starting. At-least-once, working as designed, in a window §12.5 had not
   named. The script now waits for its own flush, and §12.5 names the
   window.

46. **The client read by strangers: four reviews, six of them real.**
   Revision 45 took five releases of relay code that had been written and
   reviewed in one context and gave the diff to a reader with no memory of
   writing it; three findings came back and all three were real. The same
   argument applies harder to the client — more code, more releases, and no
   independent reader had ever looked at it — so four adversarial reviews ran
   in parallel over the delivery path, the cryptographic core, groups and
   multi-device, and storage. Twelve P0/P1 findings reproduced. Six were P0,
   and the pattern in every one is revision 45's: **a claim that was true of
   the configuration it was tested in and false of the one that ships.**

   *A revoked device of your own account kept reading your mail.* Removing a
   device rewrote the device list, bumped the version, deleted what was
   queued for it and told every contact — and left it a target in the
   persisted self-sync session, which is restored add-only and fanned to in
   full. A stolen, revoked laptop went on decrypting everything the account
   sent and received, across restarts, with no symptom; and because the seal
   keys were rebuilt only for current devices, the mirror to it stopped being
   sealed, handing the relay the sender it had been built to withhold. The
   test that should have caught it revoked the account's *only* device, where
   the sync channel is torn down wholesale and the bug is masked.

   *A linked device was told it had been removed from every group.* Group
   membership is a property of the account; the code compared the invite's
   member bundles against `myRid`, which is *this install's* routing id. On
   the device the tests run on that is the account's; on every linked device
   it is not, so the first membership change in any group took the removal
   branch — "You were removed from trip", then silently dropping the group's
   traffic and refusing to send. The same confusion had three more sites: a
   linked device could add its own account as a contact, accept its own
   account as a mirrored contact, and showed its own reactions as someone
   else's. `_myAccountRids` names the account now, and the four sites use it.

   *Two inbound paths acknowledged an envelope before storing it.* The rule
   is written down — a client MUST NOT acknowledge before it has persisted —
   and the contact path keeps it exactly, persisting inside a transaction and
   rolling the ratchet back from a snapshot if that fails. The self-sync and
   extra-device paths acknowledged first and stored afterwards, so a process
   killed in that window lost the message from the relay *and* from the
   device, with an advanced ratchet making the redelivery undecryptable. Both
   now store first; `handleInbound` hands back a snapshot and the caller rolls
   the ratchet back rather than acknowledge something it did not keep.

   *A session that had ended could be re-created by its own opening
   envelope.* `SK` is a pure function of `(IK_A, IK_B, ek)` and nothing
   recorded that a session had been retired, so a relay holding a captured
   opener could replay the first chain's plaintext after an explicit reset —
   reproduced: three messages read again — and could have a pruned session
   re-created and then *pinned* by §4's "the peer lost its state" rule,
   moving outbound traffic onto a session the peer had discarded. Retired ids
   are recorded now, bounded, and persisted with the conversation.

   *Every attachment ever sent had an unencrypted copy outside the vault.*
   The file picker does not hand over the file the user chose; it copies it
   into the app's cache directory and hands over the copy. Nothing deleted
   it — not the sweeper, not the disappearing-message timer, not "reset
   identity". The fix is one call, and the test that pins it is a source
   check rather than a mock, which is what found the *second* call site: the
   identity-restore picker, whose copy is the archive that with its secret is
   the whole account.

   *And the platform was backing the vault up to the cloud.* The manifest had
   never set `android:allowBackup="false"`, so the default put the vault
   directory in Auto Backup: the database seals cells and not structure, so
   the copy carried the contact graph and every message's direction and
   timing in the clear, and before Android 9 that backup had no end-to-end
   encryption. A restore is no better than the leak — the wrapped master key
   comes back without the hardware key that protects the device secret, so
   the vault cannot be opened and the install is dead on every launch.

   Two rules came out of it. The first is the one the Android finding is a
   pure case of: **a default you never wrote down is a decision you never
   made**, and the answer is a guard rather than a memory —
   `tool/check_android_data_safety.py` is the eighth. The second is about
   where to point a reviewer: every one of these six lives at a *boundary
   between two identities or two lifetimes* — this install versus the
   account, the live device list versus the persisted one, the ratchet's
   state versus the store's, a session that exists versus one that did. The
   code inside each of those is careful. Nobody had been made to read across
   them.

47. **The only step in the pipeline that left no record.** A landed `server/`
   change is not live until someone clicks Deploy — `render.ha.yaml` sets
   `autoDeployTrigger: "off"` deliberately, because a relay is a live system
   and `main` moves several times a day. Everything else in the chain writes
   something down: a commit, a guard's output, a release note, a test count.
   That click does not, and for four days six releases of relay work sat on
   `main` unserved while the relay answered every health check happily. Three
   separate sessions noticed, and each of them worked it out the same way by
   hand: fetch `/metrics`, look for a counter the code emits and the output
   does not, conclude the deployed build predates it.

   That deduction is now `tool/check_live_relay.py`, and the reason it is
   worth a tool rather than a note in a runbook is that it derives what to
   expect **from the code it is run beside** — the `# TYPE` lines
   `renderMetrics` writes — instead of from a table of version numbers, which
   is the thing that would go stale next. Two GETs, no credential, and it
   distinguishes the three answers that matter: behind (exit 1, naming the
   missing counter and what to click), unreachable (exit 2 — not the same
   thing), and current.

   Writing it produced two lessons of its own, both from its tests rather
   than from thinking about it. The first: a naive comparison cries wolf. The
   relay emits one gauge only in RAM mode (`z_queued_envelopes`, omitted
   where no instance knows the total) and one histogram whose samples are
   three differently-named series, so demanding every name the code mentions
   would have failed against a perfectly current relay. Reading `# TYPE`
   lines on *both* sides fixes the histogram, and indentation distinguishes
   the conditional gauge. The second came from running the test suite: the
   first version compared the live coordinator against `render.ha.yaml`
   unconditionally, so it failed against a relay built from this checkout and
   run locally in RAM mode — correct for the public deployment and wrong for
   every self-hoster, who is the reader `SELF_HOSTING.md` is written for. The
   Blueprint comparison is opt-in now. **A check that is wrong about a
   legitimate configuration gets switched off, and then it is not a check.**

   Verified against the live relay while writing this: 11 of 11 metrics
   present including `z_ack_miss_total` (2.8.3), both instances seen across
   two calls, `coordinator=redis`, `presenceStale=0`. `render.ha.yaml` also
   picked up `MAX_QUEUE_BYTES_PER_USER=16777216` in this pass — at the 64 MB
   default, four full mailboxes fill a 256 MB store, and a full store refuses
   every sender where a mailbox at its own cap refuses only its own.

48. **Two holes of the same shape, and only one of them was safe to close in
   the same week.** The client review (revision 46) found that neither the
   pairing SAS nor the device-list signature covered the ratchet key the
   other party was about to certify. Same mistake, same consequence — a key
   substituted where the users' own comparison cannot see it — and opposite
   answers on what to do about it.

   **Pairing was safe to fix immediately, and is fixed** (§10.1). The v1 SAS
   covered the ephemerals and the new device's *signing* key, while the
   existing device signed a certificate over the `dx` and `id` it read from
   an unauthenticated rendezvous frame: a relay rewriting nothing but `dx`
   left both screens showing the same six digits while the account certified
   an X25519 key the attacker held. v2 puts a commitment in front — which
   also closes the separate, milder defect that the responder chose its
   ephemeral after seeing the initiator's, and could therefore grind a
   six-digit code it had already read aloud — and puts every certified field
   into an eight-digit SAS. New contexts, new vectors, v1's text and vectors
   untouched.

   What made it safe is worth naming, because it is the whole difference
   between the two: **pairing is a one-off act between two devices one person
   holds, and its failure mode is visible.** Both devices are theirs to
   update, nothing is published, no stored value changes, and a version
   mismatch shows as "update the other device" rather than as silence. A v2
   host even holds its v1 mailbox open to *recognise* an old peer and refuses
   to answer it: detect, do not transact.

   **The device list was not, and became ADR 0010 instead.** The naive fix —
   one new context string over an input that includes `deviceXPub` — breaks
   two things, and the second is worse than the bug. A v2-signed list does
   not verify on any installed client, so the moment a user on the new build
   adds a device, that device is invisible to every contact who has not
   updated, with nothing on screen to say why. And the 16-byte fingerprint
   that gossip and the log compare is `SHA-256(signingInput)`, so changing
   the input changes the value every transparency mechanism compares: a
   half-upgraded population would raise `changedUnexpectedly` alarms about
   lists that had not changed. Making a true alarm untrustworthy costs more
   than a hole that needs an Ed25519 forgery to walk through.

   So 0010 proposes the migration rather than the edit: dual signatures (the
   post-quantum half over the new input, so a list produced by the new build
   is already protected while the old signature is still accepted), a
   per-account version floor so a downgrade cannot be replayed, a fingerprint
   that follows the format its list was signed under, and the timing
   argument — **the log is not deployed, so today's fingerprints exist only
   between clients, and this is the cheapest week the change will ever have.**

   The rule: **a fix that changes bytes other parties have already verified
   is a migration, and a migration is a decision, not a diff.** The tell for
   which kind you have is not how small the code change is — both of these
   are a few lines — but whether anyone else has already committed to the old
   answer.

49. **Phase 17.1 — the ceremony remote adding needed already existed, and the
   thing that had to change first was the reason it was not safe to reuse.**
   Adding a contact in person is a QR code, and the QR *is* the verification:
   the channel is your eyes. Remotely there was one path — copy your code,
   send it over a channel you trust, they paste it — and four things wrong
   with it, the worst being that "a channel you trust" is exactly what
   someone who has only WhatsApp does not have, and that nothing ends
   verified.

   Device pairing (§10) is already a one-time code, a rendezvous mailbox
   derived from it, an ephemeral exchange and a string two people compare,
   and it needs no relay change at all: a routing id is `SHA-256(ed25519
   pub)`, so a keypair derived from a shared secret is a mailbox *both* sides
   can hold, and rendezvous mailboxes queue like any other, which is the
   whole difference between linking your own two devices and reaching someone
   three time zones away. So the work was never "design a remote add".

   What had to change is that §10's string is sound for a code on a screen in
   your hand and not for a code sent over WhatsApp. Three differences, each
   forced by that:

   *Both sides commit before either reveals.* §10's responder chose its
   ephemeral after seeing the initiator's, and the ephemerals were the whole
   input — about 2²⁰ tries to hit a value already read aloud. Here the
   inviter commits first and the acceptor commits to its own ephemeral **and
   its own claimed identity** while holding only a hash, so neither can steer
   the string. A machine-in-the-middle gets one blind guess at eight digits.

   *The string is bound to the identities, not only to the channel.* It
   covers both account keys and both post-quantum commitments, sorted by
   account key so it is a property of the pair rather than of who invited
   whom. That is what makes a confirmed comparison mean what a safety-number
   comparison means — and therefore what makes marking the contact verified
   defensible rather than wishful. That last step is a trust-model change, so
   it is ADR 0009's open question rather than something a builder decides.

   *One ceremony adds both people.* Each side's contact code travels sealed
   under the channel, in both directions: the same string a QR would have
   carried, so the receiving side feeds it to the verification path a scan
   already uses. No second round of copy-and-paste.

   Two smaller things worth recording. The invite's two renderings — the
   printed `ABCDE-FGHIJ-KLMNO-P` and the `…/i#<code>` link — are computed
   from one secret in one place, because a link and a code that can drift
   apart is a bug waiting to be reported as "the code doesn't work"; and the
   code sits in the **fragment**, which no browser sends to a server, so the
   site that serves the landing page never receives an invite. And the base32
   rendering moved from private helpers in `pairing.dart` into `util.dart` so
   both ceremonies share it — the frozen v1 pairing vectors are what proves
   the move changed nothing, which is the cheapest possible test of a
   refactor and the reason the freeze is worth having.

50. **Phase 17.2 — an invite sent at lunchtime may be opened at midnight, and
   that one sentence decides the whole shape of the transport.** Pairing's
   relay layer is a live choreography: two sides online at once, two futures
   racing to a shared rendezvous, and if either walks away the run is over.
   It works because the two devices are in the same pair of hands. None of
   that survives two people in different time zones, so connect's transport
   is not a coroutine at all — it is a state machine with storage behind it.
   `step()` connects, does whatever the mailbox makes possible, disconnects;
   the run is written to JSON after every call and read back before the next.
   Which is why resumability had to be pushed *down* into 17.1's ceremony
   classes rather than wrapped around them: a `ConnectInviter` that lives
   only in memory cannot span a night, however good its cryptography.

   **Two mailboxes rather than one, and a sentence that stopped being true.**
   A single shared rendezvous hands each side its own frames back on the
   relay's flush — harmless, and a permanent source of "why am I reading my
   own commitment". Two mailboxes, one per role, derived from the same secret
   under one new context, cost nothing and remove the question. But 17.1 had
   already shipped a `rendezvousRoutingId()` whose comment said "the
   rendezvous mailbox both sides meet at" — true when it was written, false
   one wave later. That is the same failure the client review had just found
   at `PROTOCOL.md:804`, committed again four days after reporting it, which
   says something about how comments age next to code that is still moving.
   It is corrected, and the derivation the transport actually uses now has
   its own vector file (`connect/mailboxes.json`): getting it wrong in a
   second implementation is the worst kind of bug, because both sides
   authenticate successfully, listen politely, and never meet.

   **A finished ceremony has to empty its own mailboxes — and the test that
   proved it passed first time, which is how we knew it proved nothing.** The
   first version of the transport never acknowledged what it read, and
   everything was green. Turning the acknowledgements off *after* writing
   them is what showed what they were for: a second person arriving on a
   spent invite was answered by the frames still sitting in relay RAM, and
   got a partial ceremony that aborted on the commitment check. The binding
   held, which is the right outcome — but relying on it means relying on the
   last line of defence for something the first line does for free. A
   completed ceremony now leaves both mailboxes empty, so the 72-hour queue
   lifetime has no transcript to sit on and no partial ceremony for anyone to
   start. Both of this phase's load-bearing assertions were shown to bite by
   breaking the code on purpose; a test written after the code, and passing
   on its first run, has not yet been shown to test anything.

   **And a claim about the relay was asserted against the relay.** "The relay
   sees only two ephemeral mailboxes" cannot honestly be checked by reading
   our own client's intentions — that restates the claim rather than testing
   it. So the test stands a recording WebSocket between the clients and the
   relay, about twenty lines of it, and asserts against the bytes that
   crossed: the two mailbox ids and nothing else, and no routing id, account
   key, contact code or display name of either party anywhere in the traffic.

51. **Phase 17 finished — the tab, the tap, the page, and the one decision a
   builder should not have made alone.** 17.1 built the ceremony and 17.2 the
   transport; what was left was everything a person actually touches, and it
   turned out to be where the interesting mistakes were.

   **"Confirmed" and "not confirmed" are three states, not two.** The plan
   said the comparison either passes or it does not. Building the screen made
   it obvious that *nobody compared the digits* and *the digits did not match*
   must never be the same button: the first is trust-on-first-use, which is
   exactly what the paste flow has always been and is fine as long as the app
   says so; the second means somebody is relaying between the two people, and
   the only honest offer is to stop. So there are three buttons, the middle
   one adds the contact unverified and names that state on screen, and the
   third adds nothing and spends the invite — because a retry would meet
   whoever produced the mismatch. R25 is the row that says so.

   **A confirmed comparison sets `verified_sn`, and that was not ours to
   decide.** ADR 0009 held it open on purpose. The argument for yes is that
   the eight digits cover both account keys and both post-quantum commitments
   in canonical order — the same facts a safety-number comparison establishes,
   in a different encoding, over a channel where the two people recognise each
   other. So the tick means what it means everywhere else, and what gets
   recorded is the pair's own safety number, so every reader of that column
   works on one kind of evidence rather than two. It is written in one method
   with the reasoning next to it and the single line to remove if the answer
   is ever no.

   **Two meanings on one enum value, on the one button that must never be
   reachable twice.** The comparison panel first hid itself when the run
   reached `ConnectProgress.done`. But `done` means the CEREMONY is over —
   true the moment both sides reveal — and says nothing about whether anybody
   has looked at the digits. Depending on how many poll rounds it took, the
   panel either vanished before the user could answer or stayed up with a live
   "they match" button after they had. A separate `answered` flag now says
   what it means. The lesson is not about enums: it is that a value named for
   one lifecycle gets reused for another because the word fits, and the place
   it does damage is the one screen where the second press must be impossible.

   **A lenient parser at a public entry point.** `base32Decode` skips what it
   does not recognise, which is right for a code read down a phone line and
   wrong for deciding whether a string *is* one. Every URL has enough letters
   between its punctuation to make ten bytes, so `ConnectCode.parse` turned
   `https://zmessengers.com/` into a perfectly good invite. Harmless in a
   paste field; not harmless once any app on the device can hand the same
   function a VIEW intent. The separators are named now. Leniency and
   validation are different jobs and the same function had been doing both.

   **The landing page's best feature is what it cannot do.** An invite is
   `…/i#<code>`, and the fragment is never sent to a server, so the page is
   identical for every visitor and cannot tell that an invite exists. The page
   says so, and says it is checkable in the reader's own network tab rather
   than asking for trust. The test asserts it over every route on the site —
   no script, no inline handler, no mention of the location object anywhere —
   because a guarantee that can be lost by adding a script to some other page
   later is not much of a guarantee.

   **What is deliberately unfinished.** The Android app link needs
   `/.well-known/assetlinks.json` with the Play App Signing fingerprint, which
   is public but readable only from the Play Console. The route serves nothing
   until `ANDROID_CERT_SHA256` is set, because an unverifiable claim about
   which app owns those links is worse than no claim; until then an invite
   opens a chooser, which works. And connecting to somebody already in the
   contact list is refused rather than quietly re-verified: the digits would
   support it, but the revealed bundle need not be the one already held, so it
   is another decision.

52. **The relay was told who was in every group, by the client, in the one
   field nobody thought of as a field.** A group message is one inner message
   fanned to N members over N pairwise ratchets — N envelopes, N mailboxes,
   one socket. The outbox row carried the message's own `mid` as its relay
   envelope id, so all N envelopes arrived bearing one identical string. That
   is the recipient set, handed over outright, with none of the timing
   analysis R18 spends two paragraphs on. Worse in kind: a `mid` is plaintext
   to every member, so any one of them could name a message to the operator
   and be told retroactively who else had received it.

   `PROTOCOL.md` §12.2 had said the envelope id was "unrelated to `mid`" since
   the protocol was written, and `THREAT_MODEL.md`'s relay row said membership
   could not be learned "from any envelope". Both were right; the client
   simply did not do it. **A rule stated once in a specification and never
   asserted anywhere is a rule that holds only while nobody needs it to.** The
   fix is four characters at the insert (`newMessageId()`), and the test that
   pins it reads the ids off the relay rather than off our own intentions —
   because the claim is about what the relay receives, and asserting it
   against the sending code is the claim restated.

   **The same confusion had a visible half nobody connected to it.** A group
   message's status update looked for its row under the *member's* routing id
   while the row lives under the *group's*, so it matched nothing, every time,
   and a group message kept a grey clock for ever. One conflation — the
   mailbox an envelope goes to, and the thread the message belongs to — with
   one symptom the relay could see and one the user could. The outbox now
   carries both.

   **And the fix had a race the test found before a user could.** Marking a
   message sent when no envelope remains for it looks right and is not: a
   group's copies are queued one member at a time, so the first member's
   envelope can be sent and deleted before the second has been queued at all,
   and an outbox count alone calls that "sent". What is still to be queued is
   exactly what `group_fanout` holds, and the rule has to ask both. The test
   that caught it stages the real case — one member's mailbox full, against a
   relay started with a small cap — rather than the convenient one.

53. **The release job's shell had never run, and two of its assertions had
   never been evaluated at all.** C26 said "the attestation path has still
   never executed", which was true and understated: the three steps *before*
   the attestation — collecting the artefacts, computing the content digest,
   comparing it against an independently signed build — are reachable only
   from a pushed tag. Their first execution was always going to be the moment
   a version number had already been spent, and that is not a theory: the
   first tagged build died in that job on a missing `actions/checkout`, one
   line, one tag.

   `tool/dry_run_release.py` reads those step bodies **out of the workflow
   file** rather than restating them — one copy, so a drift between the dry
   run and the real job is not possible — stages a workspace shaped like a
   tagged run's, and executes them. It runs on every push.

   Writing it found the two things worth having. The release job refuses to
   publish unless `libapp.so` carries **exactly one** embedded build path,
   because the recipe it prints names that path and a second would make the
   recipe wrong — and that assertion lived nowhere else, so a tag was the
   first and only place it would ever be evaluated. It is asserted in the
   `reproducible` job now, on every push. And the copy that assembles
   `release/` **flattens** every artefact's tree into one directory, so two
   files sharing a basename would silently become one asset and
   `SHA256SUMS.txt` would list the survivor as though nothing had been lost.
   Nothing produces a collision today; the android job uploads a glob, so one
   build flag would. It refuses now.

   The general shape, which is the same one as revision 45 and the client
   review: **a step that only a rare event can reach is a step nobody has
   read closely**, because reading it closely has never been rewarded. The
   five passes are deliberately about what the job does when something is
   wrong — a slot that disagrees must be stated and still published, a
   missing APK must be refused loudly rather than skipped quietly — because
   what a release job does when everything is fine is the least interesting
   thing about it.

   What is still a design rather than evidence is the signature itself.
   Sigstore mints its signing material from a short-lived OIDC token that
   only a real runner can be issued, so `actions/attest-build-provenance` is
   the one step a tag has to exercise. Everything it depends on now runs
   without one.

54. **A file chunk is the one inbound thing with nobody to hold
   responsible, and it was being stored unconditionally and relayed
   onward.** Everything else that arrives is either inside the ratchet (so
   the sender is authenticated before a byte of it is believed) or is a
   mirror from one of the account's own devices (so the sync ratchet
   authenticates it). A chunk is neither: it travels outside the ratchet,
   sealed under a file key that arrives in the **offer**, so until the offer
   is here there is nothing to check it against. Its MAC cannot be verified;
   its `fid` names nothing; its sender is whoever knows the routing id, and
   the routing id is derivable from the contact code, which the app tells
   people to hand out — "someone who copies it can add you, **and that is
   all**".

   It was not all. Every chunk was stored, at any index, under any fid,
   however many arrived — and then **relayed to every linked device**, so a
   stranger's junk became N envelopes the victim's own phone emitted on
   their behalf. Nothing ever swept a chunk whose offer never came.

   Three changes, and the middle one is the one that matters. Unexplained
   chunks are **held** rather than refused, because they legitimately arrive
   before their offer — the holding is capped and oldest-out-first, since an
   offer arrives within moments of its chunks or not at all. Nothing
   unexplained is **relayed**, which removes the amplification entirely: the
   fan happens when the offer lands and explains what was held. And once an
   offer names a fid, its shape bounds what may be stored under it — an
   index outside the range is not a chunk of that file.

   **A cap enforced before the insert is not a cap.** The first version
   counted, evicted if at the limit, then inserted — and the test flooded it
   to 260 against a limit of 256, because envelopes arrive concurrently and
   a check-then-act overshoots by however many are in flight. An attacker
   reading that code would simply send faster. Trimming *after* the insert,
   under a lock, is exact whatever the concurrency.

   And the test for the amplification passed for the wrong reason twice
   before it passed for the right one: first against an account with no
   linked device, where the fan-out has nowhere to go and the assertion is
   vacuous; then by counting the outbox, which drains, so it measured the
   flusher's timing rather than the behaviour. It counts what arrives in the
   linked device's mailbox now. **A test that cannot fail is worse than no
   test, because it is also a claim.**

55. **"An active attacker cannot force a downgrade" answered the wrong
   attack.** §17.4's argument is about tampering: the ML-KEM offer is inside
   the ratchet, `pqct` is in the AAD, stripping either only produces an
   authentication failure. Every word of that is true, and none of it is
   about the attack that works. A relay does not have to modify anything —
   it can decline to deliver the one envelope that carried the offer, which
   every relay can always do and which looks, from both ends, exactly like a
   peer who was briefly offline. **Nothing authenticates an envelope that
   never arrives.**

   The offer was made once per session and never again, so that single
   dropped envelope left the conversation classical for its whole life, on
   both sides, with nothing on either screen to say so. An unanswered offer
   is now repeated after a bounded interval, and repeated as the **same**
   encapsulation key regenerated from the persisted seed — a retry is not a
   re-key, and an answer to the first copy turning up late must still
   establish. The periodic re-key is no substitute: it only runs once the
   secret exists, which is precisely the state the attack prevents.

   §18 had already learned this. The identity offer (`pqid`) is re-made for
   several reasons, with a debounce and an `ack` flag, because somebody
   thought about what happens when one is lost. The same reasoning was never
   carried back thirty sections to `pqek`, and the document's confident
   sentence is part of why: **a claim that sounds like it covers the case
   stops anyone checking whether it does.** The paragraph now says which
   attack each half answers, and R27 records what is left — a delay rather
   than a downgrade, and the fact that nothing on screen distinguishes a
   classical session from a hybrid one, because the assurance badge reports
   the identity's state and not the session's.

56. **A delivery tick was two claims, and the client checked neither.** The
   receipt handler marked a message delivered "wherever they live" — its own
   comment, and an exact description of the bug. A `mid` is plaintext to
   everyone who received the message, so in a group every member holds every
   member's ids; with no thread scope, **any contact could name any id and
   flip whatever it matched**, including a one-to-one message in a
   conversation they were not part of. The read-receipt handler two cases
   above it was scoped correctly, which is the tell: the rule was known and
   one path did not follow it.

   And a group message reached the double tick on the *first* member's
   receipt — a tick that says "they have it" while four people do not. Patch
   13 had made the relay send one receipt per member and said so in its
   notes; the client went on collapsing them into the first, so the
   improvement was real and invisible.

   Both come from the same missing idea: **a receipt is a claim, and a
   sender has to decide what each party is allowed to claim.** A receipt from
   P for message M counts only if M is outgoing in a thread P is a party to.
   A group message is delivered when every current member has confirmed, one
   row per (message, member), which is also the only version of "delivered"
   the icon already means.

   The rule is about a set that shrinks, and that is the part the test
   caught. Evaluating it only when a receipt *arrives* leaves a message
   waiting for ever on somebody who has left — a worse failure than the one
   it replaces, because it never resolves. Membership changes ask the
   question again.

   The rows go with their message, including when a disappearing-message
   timer fires. A message that vanishes but leaves behind a record of who
   received it and when has not vanished.

57. **The log's self-monitoring judged the list the log volunteered, and not
   the answer it could not shade.** `adr/0006`'s whole argument for a
   transparency log is that an operator cannot quietly serve one reader a
   different answer from everybody else — and the account's own check is what
   turns that into a detection. The check fetched two things: a **lookup**,
   which proves the `(version, fingerprint)` the log is serving as current,
   and a **history**, which is a list the log volunteers. It read the lookup
   only to decide whether to publish, and raised alerts solely while walking
   the history.

   An empty history is not a fault — an account that has never published
   legitimately has one. So a log that answered the head honestly, answered
   the lookup honestly with a rogue entry it had signed and proved, and
   simply left that entry out of the history was believed in full and said
   nothing to the account it was about. Every reader saw the rogue value as
   current. Its owner saw nothing. That is precisely the failure the log was
   built to make impossible, achieved by omission rather than by forgery.

   The judgement is one method now and both callers use it, because having
   it in only one of the two places is exactly how this happened. **The test
   for it does not forge anything**: it runs the real log, publishes a real
   rogue entry under the account key, and puts a proxy in front that
   forwards every byte unchanged except for emptying `entries` — one lie,
   the cheapest one an operator could tell, and the only one that used to
   work.

58. **One refusal, twenty seconds of a stopped outbox.** The relay names the
   envelope in exactly four of its refusals — `too_large`, `bad_send`,
   `queue_full`, `store_full` — because only those four are refusals *of an
   envelope*. The rest refuse a frame before, or regardless of, what it
   names. The client matched errors to sends by id and dropped the ones
   without, so the sender's future sat until its twenty-second timeout with
   `_flushing` held for the whole of it, and every message behind it waited.

   The code that does this most is `rate_limited`, which is not an edge case:
   it is what a relay says to a client that has just come back online with a
   backlog — precisely when the outbox matters most. And the old handler's
   answer to it, `return; // retry on next connect`, waits for a *reconnect*
   on a link that is working perfectly well and has no reason to drop.

   A connection processes frames in order, so an unattributed refusal is
   about what was just sent; failing every outstanding send with it is the
   conservative reading and costs nothing, because each row is still in the
   durable outbox and the relay dedupes a retry on (id, sender). `§12.2` now
   says which refusals name an envelope and what a client must do with the
   ones that do not, because "match the error to the send" is the obvious
   implementation and it is wrong.

   The same patch fixes a line the envelope-id change (52) missed: a
   permanently refused envelope marked failed `WHERE mid = <envelope id> AND
   rid = <mailbox>`, which was right only while those were the same two
   strings as the message and its thread. It was the last reader of the old
   convention, and it failed silently — the message simply stayed pending
   for ever. **Separating two things that were one leaves as many readers as
   there were uses, and the compiler finds none of them.**

59. **Four controls, one claim.** The audit brief's claims table grew from 32
   rows to 35 during phase 17 without gaining a single new claim. Each of
   17.3, 17.3b and 17.4 added its evidence by copying the row above,
   appending one more citation and taking the next free number, so C32–C35
   were the same 563-character paragraph four times over. Worse, each copy
   also carried a *stale* version of the sentence at the end: 17.3 replaced
   "the trust-model half is proposed and not yet built" with "a confirmed
   comparison sets `verified_sn`" because it had just built it, and 17.4's
   copy quietly reverted to "not yet built" — so the table contradicted
   itself about whether shipped code exists, and dropped the two app suites
   17.3b had cited.

   One row now, with the union of the citations and the built form of the
   sentence. The prose under the table has said "thirty-two claims" all
   along and was never wrong; the table drifted away from it.

   `check_audit_scope.py` refuses two rows that state the same claim word for
   word. It already checked that every cited file exists, that ids are
   contiguous, that no cell is empty and that every test file is cited
   somewhere — none of which notices a row copied wholesale, which is why
   three of them went through green CI. **A count is evidence about the
   document, not about the system, and this one was inflated by 10% before
   anybody read it.**

60. **Delete removed the row and kept the file.** `deleteMessage` — "delete
   for me", the button that means *get this off my phone* — deleted the
   `messages` row and the delivery receipts and stopped. For an attachment
   that left everything: the `files` row, which holds the name the user gave
   the file and the key its blob is sealed under; the blob; any chunks not
   yet drained; and the reactions. Nothing in the app could reach any of it
   afterwards and nothing ever collected it, so it stayed for the life of the
   vault.

   The way out was worse than the way it sat there. `BackupArchive.export`
   walks `files` directly rather than through `messages` — on purpose, so a
   file whose message row was lost is still recoverable — which makes that
   table the archive's definition of what exists. So a photo the user deleted
   was written into **every archive taken afterwards, under the filename they
   deleted it by**, and an archive is the one artefact this design expects to
   be handed to somebody.

   The other three deletion paths — `_tombstone`, the disappearing-message
   sweeper and removing a contact — all destroyed the blob, the row and the
   chunks already. This one was the odd one out, and it is the only one a
   user reaches deliberately.

   Fixed in one transaction, with the blob unlinked after the commit rather
   than before it: a blob unlinked ahead of a transaction that then fails
   leaves a message pointing at nothing, while this way round the worst case
   is a blob whose key has already been destroyed. `Vault.open` now sweeps
   rows no message names and blobs no row names — what earlier builds
   orphaned, and what a crash between `writeBlob` and the transaction that
   records it leaves. The vault also sets `PRAGMA secure_delete`, which the
   bundled SQLite already defaults on: a pin, not a fix, so that a property
   worth having does not depend on a dependency's default surviving its next
   bump. Written down as such, in the code and in the claim.

   R28 records what none of this reaches: flash does not overwrite in place,
   so a page a wear‑levelling controller retired is beyond anything above the
   filesystem. Sealing is what makes that ciphertext, and factory reset is
   the platform's job. **"Deleted" in an app means removed from the store it
   controls; saying more than that would be a claim about hardware.**

61. **The sender chose the filename.** An attachment's `fid` is what §7 calls
   an opaque chunk-routing id: `b64url(12 random bytes)`, sixteen characters,
   meaningless. It is also what the receiver names the blob's *file* by —
   `files/$fid.bin` — and it arrives in an ordinary inner field that the
   **sender** filled in.

   Nothing checked it. `../escaped` is a valid Dart string; so is
   `/z-absolute-escape`, and `p.join` discards its base entirely when the
   second part is absolute, so an absolute id was an absolute path. A contact
   could therefore choose where on the device an attachment landed, and a
   `.bin` file written outside the vault directory is one `Vault.wipe` —
   "reset identity", the button that means *everything goes* — walks straight
   past. `deleteBlob` pointed the same arbitrary name at a zero-and-unlink.

   Be exact about the size of it: the bytes are not the attacker's, because
   `writeBlob` seals them under a fresh random key, so what lands is
   ciphertext. What they get is the **place**, plus a delete primitive aimed
   the same way, both suffixed `.bin`. That is a real capability and a modest
   one, and calling it either more or less than that would be wrong.

   The pre-fix test run names the file it finds: `<vault>/escaped.bin`, put
   there by a contact sending one offer and one chunk, both otherwise
   perfect — real key material, a real encrypted chunk, the real SHA-256 of
   the real bytes. The only wrong thing in the exchange is the id.

   Enforced now at every door an id arrives through — the offer, the chunk,
   an archive record — and in `Vault` itself, which throws rather than
   accepts, so a future caller who forgets cannot bring it back. The check
   lives in `protocol/`, next to the generator, because the two have to agree.

   Two notes against over-reading the fix. Matching the shape costs an
   attacker nothing, so this does not replace the flood cap (54): a
   well-formed unexplained chunk is still held, and `file_id_test.dart`
   asserts that it is, so nobody later decides one check covers both.
   `chunk_flood_test.dart` used `fid-$i` for its junk and would have passed
   for the new reason instead of the old one; it now floods with well-formed
   ids.

   **§7 had specified the shape all along. A rule in the document that no
   code reads is a comment.**

62. **A restore that held the whole backup.** `BACKUP.md` has had a row called
   Streaming since phase 9, and it said: *neither export nor import ever holds
   the archive, or a whole attachment, in memory*. The format is built for the
   first half — frames, a nonce unique by construction from the frame index,
   256 KiB attachment pieces — and export does walk one attachment at a time.

   Import accumulated every attachment in the archive in a
   `Map<String, BytesBuilder>` and wrote none of them until the terminator had
   been read. A vault with two hundred photographs restored by holding two
   hundred photographs. The failure mode is the OS killing the app part-way
   through the one operation a person runs when they have already lost the
   device, and it gets likelier the more history there is: the backups that
   matter most were the ones this handled worst.

   Each attachment's frames now go to a spill file as they arrive, and are
   sealed into the vault one at a time afterwards — with the spill directory
   removed whatever the outcome, because an archive's attachments sitting in a
   directory of their own, outside the vault's `files/`, is the same leak by
   another route and one nothing would ever collect. The spill is named by
   `fid`, which is only safe because 61 made a malformed one impossible.

   Two things the first attempt got wrong, both found by measuring rather than
   reasoning. Writing the spill through an `IOSink` moved the memory instead
   of removing it — `add` queues and returns, so 80 MiB went through the sink
   and stayed there; it is a `RandomAccessFile.writeFrom` now. And most of
   what remained was `writeBlob` building its output as `<int>[...cipherText,
   ...mac]`: a growable `List<int>` at eight bytes an element that doubles its
   way up, so writing a 2 MiB blob churned tens of megabytes. That one is on
   the path of **every attachment received**, not just restores. Exact-size
   typed buffers now, there and in `sealFrame` and `blobPayload`.

   One attachment at a time is a floor rather than a choice: a blob at rest is
   a single AEAD message, so producing one means having its whole plaintext.
   The row now says that instead. Peak RSS around an import is measured
   against an export of the same vault — export has always been one at a time,
   so the yardstick is the machine's own and there is no constant to go stale:
   0.5–0.7 of the export with the fix, 1.5 with the accumulation.

   **A claim in a document is a claim about code, and this one had been true
   of only half of it since the day it was written.**

63. **A contact's name, written into the database in the clear.** The
   device-list banners — "Dana's devices disagree about their device list",
   "Dana's app says it sent the post-quantum signature" — were stored as their
   finished English sentences, in the `kv` table, with `sensitive: false`. So
   a display name sat in the database unencrypted, beside the routing id that
   says exactly whose name it is, in a vault whose own documentation opens
   with: *every sensitive value (message bodies, **names**, contact bundles,
   session state, file metadata) is encrypted cell-by-cell before it touches
   SQLite*.

   The same sentences were a second problem. `chat_screen.dart` and
   `contact_info_screen.dart` are both on `check_l10n.py`'s migrated list,
   which is a promise that they carry no user-visible English — and they
   rendered a paragraph of it, handed to them by the service at run time,
   where the check cannot see it. A Spanish user got the banner in English.

   One change answers both, and it is the one `system_messages.dart` has
   described since phase 10 for system messages: store the KIND, never the
   sentence. `{"k":"dl_conflict"}`. The name is not stored at all — the screen
   has the contact — and the words are chosen in the reader's language when
   the banner is drawn. Five ARB keys in both locales, each with a description
   naming its load-bearing clause.

   An alert an older build wrote is **dropped** when the app next opens,
   rather than shown as it is (which is what system messages do with old
   rows). The difference is that the sentence is the defect: keeping it on
   screen would mean keeping the name on disk. The cost is a banner that
   clears on upgrade and comes back at the next check, which for the
   device-list alerts is `devlistGrace` and for the post-quantum one is the
   contact's next claim.

   Underneath, the same defect in general: `kvPut` wrote the new storage
   class and left the old one, so a key rewritten from plain to sealed kept
   its cleartext row for the life of the vault — correct to every reader,
   because `kvGet` prefers the sealed one, and therefore invisible to all of
   them. Sealing something that was written in the clear has to mean the
   cleartext is gone.

   **The vault's documentation said names were sealed. Nobody had checked
   whether that was a description or an intention.**

64. **A relay that isn't TLS, and one button that said so.** Four things wrote
   `server_url`: onboarding, linking a device, the developer-mode field in
   Settings, and a restored archive's own `meta` record. Exactly one of them
   ever mentioned that a `ws://` address is not TLS — a notice that appeared
   beside a "Test" button, which nobody has to press. So three of the four,
   plus the one that takes its answer from a **file**, dialled a cleartext
   public relay without a word.

   What that costs is not the messages. Those are end-to-end encrypted
   whatever the transport, and the app has always said so. It is the routing
   metadata — which mailbox, how much, how often — which is precisely what the
   rest of this design spends its effort on: sealed sender, per-device routing
   ids, padding buckets, three register rows (R15, R18, R19) about what a
   relay can still infer from timing. Handing all of it to anyone on the path
   because a URL was typed with one `s` missing is not a trade anybody made.

   One funnel now. `setRelayUrl` refuses a public `ws://` address unless the
   caller says a human was asked and agreed; the three screens ask, with
   "Connect anyway" deliberately not the default and a dismissed dialog
   counting as no. A restored archive's address is refused outright rather
   than confirmed — a backup is a file, and the question "do you accept this?"
   has no useful answer when the thing asking is a document (the same
   reasoning as 61's file ids).

   Local, LAN and `.local` addresses connect with no question at all, which is
   what `cleartextTrafficPermitted` in the manifest is for and why it stays
   true: a private range cannot be written as a domain-config exception, and
   there is nobody on that path to hide from.

   `tool/check_relay_url.py` holds it: only `relay_url.dart` may write
   `server_url`, and only the five callers listed there — each with its reason
   — may say the user agreed. The manifest comment used to describe the whole
   policy; it now says which half it is.

   **The strongest thing here is the confirmation nobody can route around, and
   the reason it exists is that the weakest thing was a notice beside a button
   nobody presses.**

65. **What the invite card was missing (17.9).** An invite is a bearer token
   for 24 hours (§20, R23), and the card that showed it said "Pending". Not
   which hour of the 24: the one number a person needs in order to decide
   whether to send it again was the one number the screen did not have. It
   also went on offering the link, the code and a copy button for an invite
   that had run out — a token that no longer works, still sitting there to be
   copied and sent to somebody.

   The card now says how long is left, rounded **down** so it never promises
   more time than it has, and says "Expired" rather than counting past zero.
   The clock decides that, not `progress`: `progress` only moves when
   something pumps, so an invite that ran out while nobody was looking still
   reads `waiting`, and it is the 24 hours that determine whether it is worth
   handing to anyone. Once it is answered or over, every rendering goes and
   only "Discard" remains.

   Two new ways to hand it over. A **QR** of the link — the third rendering of
   the same one secret, encoding the link verbatim, so a photograph of the
   screen is the same bearer token rather than a second one, with the quiet
   zone kept white regardless of theme because a scanner needs the contrast.
   And the system **share sheet**, on a channel of its own
   (`ShareText.kt` → `z/share`), because "it is on the clipboard now" leaves
   the person to find their messaging app and paste into the right
   conversation themselves. Text only and `createChooser` every time: an
   invite is a bearer token, so a subject line would put a second copy of it
   in a mail header and a notification preview for nothing, and a default
   share target would quietly become where every invite goes. Where there is
   no share sheet — every platform but Android today — the link goes to the
   clipboard and the message says so, rather than a button that sometimes
   does nothing.

   The QR does cut slightly against R23: a token that is easier to broadcast
   is easier to broadcast to the wrong person. It stays because the alternative
   for "show this to someone on a video call" is reading out twenty
   characters, and the one-time-and-24-hours line sits directly beneath it.

   `InviteQr` is a named widget rather than a bare `QrImageView` for one
   reason worth recording: `QrImageView` keeps its data private, and what a
   test needs to know about that widget is precisely that the thing encoded is
   the link and not a second secret. **A property nothing can assert is a
   property nobody is keeping.**

66. **A group id is also a thread key, and the sender chose it.** §11 says a
   group id is `"g" || b64url(12 random bytes)`. The client generated exactly
   that and accepted anything: `_applyGroupInvite` took any non-empty string.

   The id is not a label. It is the key messages are filed under
   (`messages.rid`), and the chat screen decides what a conversation **is** by
   looking it up — `groups[rid] != null` means group. A routing id is 43
   base64url characters and a group id is seventeen, so they can only collide
   if nobody checks. Nobody checked. Measured with three real clients through
   a real relay, before the fix:

       GROUPS=[D5R9H30EV96KmLg6SV70gu69yv_rXPOYJbz4Kfmhf8k]
       HIJACKED=true name=Alice (verified)
       THREAD=[null:the real Alice,
               null:{"k":"added_to_by","by":"Mallory","name":"Alice (verified)"},
               Mallory:transfer the money to this account]

   Alice's conversation, with Alice's real message still in it, retitled to
   whatever Mallory typed and subtitled "2 members".

   What it is and is not, exactly. The injected message carries Mallory's
   name and a system message says she added you, so it is not a clean
   impersonation of Alice. What Mallory gets is the thread's **title and
   membership**, and the disappearance of every banner the chat screen draws
   only for a 1:1 — the device-list warning about Alice, the transparency
   log's conflict hold, the disappearing-messages control. The send is still
   refused by the service (`kt.sendsHeld` is checked in `_sendInner`, not only
   on screen), so a victim under an active key-substitution attack gets
   messages that do not go and no explanation of why. That is the worst of
   both halves and it is a third party's to arrange.

   The shape is checked now, at the one place a group can be created from the
   wire, together with an explicit refusal of any id that is already a
   contact's — belt and braces, because the property that matters is "a group
   never shadows a conversation" and it should be written down rather than
   deduced from two string lengths. `newGroupId` and `isWellFormedGid` live
   together in `protocol/`, so the generator and the check cannot drift. A
   group an older build accepted is dropped when the vault opens, and the
   conversation underneath it comes back.

   R29 records what remains: any contact can still put you in a group, name
   it, and name its other members. That is inherent to pairwise fan-out with
   no shared key, the members it adds arrive unverified, and leaving is one
   tap. **The thing worth preventing was not an unwanted group. It was a group
   that could pretend to be a conversation.**

67. **A rule's second door.** 61 made a malformed file id impossible at three
   places: the offer handler, the chunk handler, and an archive record. There
   was a fourth. An offer from a contact's **linked device** arrives through
   `_dispatchExtraInner` — a different path into the same tables — and it was
   not checked there, because the rule was written while reading the other
   one.

   What got through was less than it sounds, and the reason is worth keeping:
   `Vault.blobFile` throws on a malformed id, so nothing was ever written
   where it should not be. The defence in depth that 61 added "so a future
   caller who forgets cannot reintroduce it" caught a caller that already had.
   What it could not catch was the row: a `files` entry and a message
   placeholder under an id nothing can ever complete, in a thread, for ever —
   and no sweep collects those, because the message row they belong to is
   real.

   Checked at the fourth door now, with the same two lines. **A rule enforced
   at three of four doors is a rule with a door.**

68. **The log held the whole of itself, twice.** `FileStore.readAll` read
   `entries.jsonl` into one JavaScript string, and `KtLog._apply` kept every
   entry — `value` included — in `this.entries` for the life of the process.
   So a replay's peak was the file plus a parsed copy of it, and the resident
   set afterwards was a multiple of the file rather than a function of the
   number of entries. At the 256 KiB value cap one entry was 256 KiB of memory
   for ever, and the trees need none of it: they commit to `leafHash`, and a
   hash is 32 bytes.

   Two ways that ends a live log, and the review found it with days on the
   clock. On a 512 MB instance the ceiling is tens of megabytes of file, after
   which the process OOMs during replay on **every** start — permanently,
   because the file it cannot read is the file it must read to start. And a
   file past V8's ~512 MB string limit cannot be read at all by this reader,
   which made the 1 GB disk it is deployed on more than twice the largest file
   its own code could open. `render.kt.yaml` said "a few KB per publish" and
   nothing about either.

   A fixed read window with a carried remainder has a peak of one chunk plus
   the longest line whatever the file weighs; an entry keeps the byte range of
   its own line instead of its value, and serving one is a read rather than a
   residency. Measured, on a 16 MiB file carrying 12 MiB of values: **0.6 MiB
   retained**, against 12.7 MiB holding them and 16.2 MiB to read one entry
   the old way.

   Measuring it took two corrections worth keeping. `heapUsed` reports 0.1 MiB
   either way, because a `value` is a Buffer and a Buffer over a few kilobytes
   lives outside V8's heap — a measurement that cannot fail. And without a
   forced collection the number is dominated by the garbage from parsing
   sixteen megabytes of JSON, not by what is kept. Retention is what survives
   a collection, counted in heap **and** external.

   What is not in this patch, and is the operator's: raising the instance so
   RAM matches the disk, and a disk and heap alarm. What is still the dominant
   remaining term: `/history` and `/entries` have no byte cap (review finding
   8), so a page of a thousand entries now hydrates values that used to be
   resident — the same bytes, moved from a permanent cost to a per-request
   one. **A component that cannot start is worse than one that is slow, and
   the file that stops it starting is the file it exists to keep.**

69. **The limiter was keyed on a value that is the same for the whole
   internet.** `kt/server.js` limited publishes per source address, and the
   address was `req.socket.remoteAddress` — which behind Cloudflare → Render
   is the proxy, on every request. A gate meant to bind one client bound
   everybody together at one bucket, which is to say it bound nothing.
   Measured on the day the log went live: 35–175 publishes a minute against a
   nominal 30, and 3,853 entries from 3,579 distinct account keys in about a
   hundred minutes, while the relay beside it saw four envelopes.

   Keying on the signed `acct` instead is the obvious repair and it is **not
   sufficient**, which is the part worth being exact about: the flood used
   3,579 different accounts, and a per-account limit lets every one of them
   through. Ed25519 keys are free. A log's disk is not.

   Three gates now. A **total** rate, whatever the source — the one that
   actually stops a flood, and the only one that works when there is no
   trusted header to identify a client with. The **per-address** rate that
   existed, now genuinely per-client when `KT_CLIENT_IP_HEADER` names a
   header something in front is known to set — empty by default, because a
   forwarded address is the caller's to choose unless something overwrites
   it, and a limiter keyed on a value the caller picks is worse than one keyed
   on a value they cannot. And a **per-account** daily ceiling, charged only
   after the signature verifies, so nobody can spend an account's budget but
   that account: `checkPublish` was split out of `publish` for exactly that
   ordering.

   Both cheap gates run **before** the body is read. Moving the limit after
   the parse, which keying on `acct` appears to require, would have traded a
   limiter that bound nothing for a limiter that bound nothing until after a
   400 KB read.

   The buckets are capped and drop the least recently seen. A limiter keyed on
   something an attacker can mint is a map an attacker can grow, and a limiter
   that costs more memory the harder it is pushed is not a limit — which is
   the same sentence as 68, arrived at from the other direction.

   **A rate limit is a claim about who is asking. Ours was keyed on an answer
   that was the same for everyone, and nobody checked what it was keyed on
   until the log filled up.**

70. **Full ratchet state, written to disk unsealed.** `vault.dart` opens by
   saying what it is: *every sensitive value (message bodies, names, contact
   bundles, session state, file metadata) is encrypted cell-by-cell with
   XChaCha20-Poly1305 under the master key before it touches SQLite*. Two
   `kvPut` calls passed `sensitive: false`, and between them they held the
   session state.

   `sync_session` is the self-sync ratchet with this account's own devices,
   and the mirror carries every message the phone sends or receives.
   `cextra_<rid>` is the ratchets with each contact's non-primary devices.
   Both serialise `RatchetState.toJson()`: `rk`, `dhsSeed`, `cks`, `ckr` and
   the cached `skipped` message keys. Base64, in a plain SQLite file. Anyone
   who read `z.db` without the vault key could decrypt that traffic and forge
   mirrors back into the user's own devices. C11 — "plaintext never touches
   disk" — was false as published, and by the project's own severity scale
   that is High.

   The repair is not two call sites. `sensitive: false` was being used as a
   performance note, and "may this be plain?" was a judgement made thirty
   times, at the moment of writing, by whoever was there. It is a **declared
   list** now — exact keys and per-contact prefixes, each with its reason —
   that `kvPut` enforces by throwing, and that `Vault.open` applies to what is
   already on disk: anything in the plain class that is not on the list is
   sealed as the vault opens, and the cleartext goes with the rewrite rather
   than sitting beside the sealed copy, because `kvPut` removes the other
   storage class's row (67's fix, doing the work it was written for).

   The test the review asked for is the one that closes the class rather than
   the instance: drive an app through a message, a reply, a reaction, an
   attachment, a group, a relay change and a device id, then assert that
   **no** plaintext key survives that the list does not name. The two keys are
   the bug. The list is the fix.

   **A vault that decides cell by cell whether to seal is a vault whose
   guarantee is a habit.**

71. **Anyone could fill the store with mailboxes nobody would ever drain.**
   `to` is checked for the shape of a routing id — 43 base64url characters —
   and nothing else, because the relay has no way to know which hashes name a
   real identity and is not supposed to; and a sealed envelope may be sent on
   a connection that never authenticated (§12.1), by design. So four hundred
   random strings and a few seconds filled a 256 MB `noeviction` store, every
   real send afterwards got `store_full`, and the deployment was down.

   R22 said a full store heals. It does — for the case it was written about.
   Healing means the owner connects and drains their mailbox, and a mailbox
   addressed to a routing id nobody holds **has no owner**. Nothing would ever
   drain those, so the floor was `QUEUE_TTL_HOURS`: three days. The cheap
   variant is many tiny mailboxes, which also defeats the sweeper, one round
   trip each.

   The per-mailbox caps cannot express this — they bound what one recipient
   can be made to hold, and the attack is in how many recipients there are.
   What can express it is the asymmetry: an honest mailbox belongs to somebody
   who will connect and empty it, and a flood's never do. So **creating** a
   mailbox is rate-limited across all senders (`NEW_MAILBOX_PER_MIN`), which
   bounds the flood without bounding anybody's conversation.

   A rate rather than a count of live mailboxes, deliberately. A count shared
   between instances drifts upward the moment a TTL deletes a queue without
   running the code that would decrement it, and a bound that drifts upward
   eventually refuses everybody. A rate has no state to be wrong about, and a
   flood arrives on one socket and therefore one instance; spread across N
   instances it gets N times the allowance, which is a bounded and stated
   degradation rather than a wrong number.

   On the Redis path the decision lives inside the push script rather than in
   a lookup before it. The script already reads the mailbox's length to check
   the caps, so an empty list is a mailbox that does not exist yet and it can
   refuse in the same round trip: an ordinary send costs exactly what it cost
   before, and no mailbox can be created between asking whether one exists and
   writing to it. The instance spends its token before the call and takes it
   back when the push turns out to have landed in a mailbox that was already
   there — so ordinary traffic cannot eat the budget for creating mailboxes,
   which would be a relay that stopped anyone starting a conversation whenever
   it was busy. The first version of this asked `EXISTS` first, and that
   version was both racy between instances and a round trip per send forever
   to catch a flood that lasts seconds.

   The refusal is `store_full`, which §12.4 says to pause and retry on —
   not `queue_full`, which would be a claim about a recipient's cap and a lie
   about a mailbox that does not exist. An honest first message to a
   brand-new contact during a flood is delayed, not lost.

   And `MemoryCoordinator` has a ceiling at last (`MAX_STORE_BYTES`). It had
   no global bound of any kind, so the single-instance deployment answered the
   same flood with an OOM kill rather than the documented refusal — the two
   coordinators disagreeing about the one thing the protocol tells a client
   how to handle.

   **"It heals" was true of the case somebody had in mind and false of the
   cheaper one nobody had.**

72. **A read route with no byte cap is a permanent way to ask for the whole
   log.** `count` never bounded these. A value may be 256 KiB, so
   `/kt/v1/entries?count=1000` was ~333 MB built as one `JSON.stringify`
   string, and `/kt/v1/history/<label>` took no count at all: every version a
   label had ever published, at a fixed URL, repeatable by anyone, and behind
   `cache-control: no-store` so nothing in front absorbs the repeat.

   This is the second half of the publish flood (entry 69). The flood does
   not only grow the log — on a 1 GB disk it can put ~2,900 maximum-size
   entries under **one label if it likes**, which mints a fixed URL that
   returns a gigabyte, permanently, to anyone who asks.

   So both routes are bounded in **bytes** as well as by count, and the bound
   is decided before any value is read back. `valueAt.len` — the length of
   the line the entry was written as — is already known from the replay, so
   the number of entries that fit is a sum over lengths the log already has,
   and the entries that do not fit are never fetched off disk at all. Capping
   after assembly would have done the expensive half of the work anyway:
   `withValue` is a synchronous read per entry.

   Two properties had to survive it, and each is a bug if it does not.

   A page is **never empty while the head says there is something there**.
   `kt/lib/mirror.js` treats a page with no entries as divergence and
   poisons itself permanently, so "too big to serve" cannot be an answer; a
   single entry over the budget is served alone. That floor is unreachable
   over HTTP while a value is capped at 256 KiB and the budget is 4 MiB, so
   it is asserted against the library with a budget of one byte — the day
   either constant moves, it is what stops the cap becoming a fork.

   And both routes report **`total`**, which is the point of the paging
   rather than a convenience. `/history` is what an account's own device
   walks to find a version it did not issue, so a page that simply stopped
   would be a log able to hide an entry by being too big to serve — the same
   failure as the empty `entries` array that §19.8 exists to defeat, reached
   by a different road. The client pages until it has seen `total`.

   What it must **not** do is treat a short page as a log fault. `fault` is
   sticky and suppresses every later check — including the judgement of the
   authenticated `latest`, which is the alarm an incomplete history cannot
   defeat. A first draft of the client did raise a fault there, and the test
   that catches a log omitting a rogue entry from its history failed: the
   log could have switched its own monitoring off by serving one short page.

   **A cap that a reader cannot tell from the whole is a place to hide.**

73. **A write that only half happened, reported as a success.**
   `fs.writeSync` may write a PREFIX and return how much, without throwing.
   Measured: one `writeSync` of a 1 MiB buffer returned **65536** and raised
   nothing. `FileStore.append` ignored that number.

   Everything after it followed: `append` returned a byte range for bytes
   that were never written, `publish` carried on and mutated both trees, and
   the client was answered `201` with a signed head committing to an entry
   the log does not hold. Then the next start died on "a torn write?" — for
   ever, because the following append takes its offset from the file's size
   and splices itself onto the unterminated line. One short write and the
   log never opens again, with nothing in `kt/tools/` to get it back.

   The clean `ENOSPC` path was always safe: it threw, and `publish` appends
   before it touches the trees, so a throw left the log exactly as it was.
   It was the SILENT partial write that was fatal — which is why the fix is
   the return value rather than a wider try/catch.

   So the append loops until every byte is written, and on anything short or
   throwing truncates back to where the line began and rethrows. Both halves
   are tested, and they are different halves: a short write the kernel will
   finish on the next call must be finished (the common case, and the one
   that used to corrupt), while a short write followed by a full disk must
   leave the file byte-for-byte as it was.

   It also fsyncs the **directory** when it creates the file. Fsyncing a
   file does not make the directory entry naming it durable, and the first
   append is also the creation — so a machine that lost power there came
   back with no file, which `readAll` reads as an empty log (`ENOENT` yields
   nothing) and would then have begun signing a fresh history with the
   production key. Once per file, not once per append.

   `kt/tools/repair.js` is the way back from a file an older build tore. It
   drops the bytes after the last newline, keeps them beside the file, says
   whether the log opens afterwards, and writes nothing unless asked. It
   refuses damage inside a complete line: dropping whole entries to make a
   log start is a rewrite of the history, not a repair.

   The mirror's own writer had the same defect and is fixed with it.

   **A partial line is not a smaller log; it is a log that cannot be
   opened.**

74. **A shortened file is not a damaged log; it is a smaller one, signed by
   the real key.** Replay believed whatever was on disk. Truncate
   `entries.jsonl` at a line boundary and the log starts cleanly and `sth()`
   returns a valid signed head at the shorter size — every self-consistency
   check passes, because they are all about a line rather than about the
   history.

   The realistic trigger is not an attacker. `KT_DATA` pointing where the
   Render disk did not mount makes the log come up at **size 0** with
   `/health` answering 200, and it begins signing a brand-new history with
   the production key. Restoring yesterday's snapshot does the same thing
   more quietly. Every client holding a head then enters permanent log-fault
   — which is the state `adr/0006` reserves for a log caught forking, and is
   the correct reading, because that is what this is.

   So the log records the head it signs, beside its entries, before the
   publish that produced it is acknowledged; and on the way back up it
   refuses to start unless the replayed tree reproduces that head's root at
   that size. Not the entry count: the root, so a file of the right length
   with the wrong contents is refused too.

   Two floors, because they fail differently. The head file catches a log
   that lost entries while keeping its directory — a truncation, a restored
   snapshot, a half-copied file. It cannot catch the directory itself going
   missing, because it goes with it; that is what `KT_MIN_SIZE` is for, a
   floor that lives in the environment rather than on the disk. It is a
   floor and not an expected size, so it stays true as the log grows and an
   operator sets it once.

   Neither stops somebody who can write the data directory from removing
   both, and the documents say so rather than implying a guarantee that is
   really a tripwire. What they stop is every way this happens by accident,
   which is every way it has happened.

   **A log with nothing to be held to will sign whatever it finds.**

75. **The publish signature was verified once, in RAM, and then dropped.**
   `entryToStored` kept `acct` and not `sig`, so a replay could check only
   `labelFor(acct) == label` and `sha256(value) == valueHash` — both computed
   from fields whoever wrote the line also chose.

   So anything that could write the file could forge an entry for any account
   in it. Take a victim's `acct` out of the file, seal a device list under
   `HKDF(acctPub)` — the sealing key is derived from the account's PUBLIC
   key, because the log must not be able to open a value — append one line at
   a higher version, and the log starts normally and serves the forgery as
   that account's latest with a valid map proof. Nothing downstream can tell,
   because §19.6 says `acct` is never served, and neither is `sig`.

   It also made `SELF_HOSTING.md`'s "refuses to start on a torn or edited
   file" false in the half that matters, which is the sentence an operator
   reads before deciding the file is safe to copy around.

   The signature is stored and re-verified at replay. It costs one Ed25519
   verify per entry and **no extra I/O at all**: the signed bytes are
   `label ‖ version ‖ fp ‖ valueHash`, every one already in the line and none
   of them the value — so it does not undo entry 68's work, which was to stop
   replay holding values.

   The boundary for lines written before this is **derived, not recorded**.
   A number in a file would be a number editable by exactly whoever is being
   defended against. The rule instead is that a log never goes back: an entry
   with no signature is accepted only while no earlier entry had one. A file
   that predates the change replays as before, the first signed publish
   closes the door behind it, and the forgery — an unsigned line appended
   after signed ones — is refused by the entry that precedes it rather than
   by anything about itself. The live log's existing entries are grandfathered
   without a migration, and nothing had to be re-signed.

   It composes with entry 74 rather than duplicating it. Appending is now
   refused by the signature; truncating and rewriting is refused by the head
   floor, since the replayed tree must reproduce the recorded root at the
   recorded size and the leaf covers every field of every entry below it.
   What is left is replacing the whole directory, which neither can see —
   `KT_MIN_SIZE` is the floor for that, and a witness run by somebody else is
   the real answer. R7 says so now; it had described the operator's power as
   split views alone, which was an understatement.

   The leaf does not cover `sig`, so no root, head or vector moved.

   **A record that keeps only what its writer chose is not evidence about
   its writer.**

76. **A message the relay said it had delivered, that nobody had.** Three
   defects compound into one outage, and the review found them from two ends.

   The presence refresh rethrew anything that was not an out-of-memory error
   out of its loop, and the call site swallows it — so one reset connection
   left every remaining socket's presence unrefreshed with nothing said.
   Presence expires at 60 s against a 25 s refresh, so the window is real.

   A cross-instance delivery was then counted **live** because the `PUBLISH`
   resolved. That says the message bus accepted it, and nothing about whether
   the instance named by `presence:` still holds a socket for the recipient;
   the receiving side drops the frame silently when it does not, and answers
   nobody. So the sender was told `queued: false` — and the wake push, which
   is gated on `queued`, did not fire either.

   And `flush` was called from exactly one place, the `auth` case. The only
   recovery for a live push that went nowhere was the recipient reconnecting,
   which a healthy connected client has no reason to do. The floor was
   `QUEUE_TTL_HOURS`: **three days** of mail that the sender, the relay and
   the recipient all believed had arrived.

   `queued: true` is the honest answer for a cross-instance send. It is not a
   lie in the other direction — the envelope is held until it is acknowledged
   either way — and the wake push it now allows is right in the case that
   matters and harmless in the other, being content-free and going to a
   device that is already awake. The alternative, an acknowledgement back
   over pub/sub with a timeout, would put a second round trip on the hot path
   of every cross-instance send to recover one bit that **no client reads**:
   the Dart client discards it, and the only consumer is the wake push.

   The recovery is a re-flush, and the signal is a mailbox that is not
   EMPTYING rather than one that is full. A device working through a backlog
   holds a non-empty mailbox for as long as that takes and is working
   perfectly; one whose length has not moved across a whole interval, while
   its socket is right here, is one whose mail is not arriving. One `LLEN`
   per local socket per pass — the same shape and cadence as the presence
   refresh beside it — and only a length that has not changed costs a flush.

   `z_cross_instance_total`, `z_reflushed_total` and
   `z_presence_refresh_failed_total` make all three visible. The gap between
   the first and `z_delivered_live_total` is the traffic whose delivery
   depends on a presence record being true; anything but zero on the second
   means a live push was lost; the third used to be an exception that aborted
   a pass in silence.

   Two bugs in the test harness had to be fixed before any of this could be
   observed, and both are worth recording. The clone of `ha.test.js`'s client
   never removes a timed-out waiter, which is harmless until a test **expects**
   a timeout — then the dead waiter sits in front, matches the frame when it
   finally arrives, resolves a promise nobody holds, and the frame is
   consumed. And presence is written at `auth` as well as by the refresh, so a
   failed refresh cannot be seen in the key's value at all; the keys have to
   be cleared first for the pass to be the only writer.

   **A publish is not a delivery, and nothing was checking.**

77. **A kick that names an rid and nothing else closes whoever is there
   now.** The message one instance sends another to drop a replaced socket
   carried `{op:'kick', rid}` — no socket identity, no ordering — so the
   receiving instance closed whatever it held for that rid AT THE MOMENT THE
   KICK ARRIVED, and deleted the entry either way.

   A client moving A→B→A is the case that breaks. B's kick for the A→B move
   can arrive after the move back, and it then closes the socket that has
   just been welcomed — immediately after `ready`, so the client reconnects
   and can re-enter the same race. The unconditional delete was the worse
   half: it left `presence:{rid}` naming an instance with no socket, so the
   other one published deliveries into a channel that dropped them — entry
   76's failure, reached from here.

   The store is the only clock two instances share, so the order comes from
   it: one `INCR` per registration, carried in the kick, and a kick is acted
   on only when the socket it finds is older than the registration that sent
   it. A registration whose `INCR` the store refused keeps 0 and is closed by
   any kick, which is exactly the old behaviour — the right way to degrade,
   since a store under memory pressure must not stop people logging in, and
   `register` already takes that view of the presence write beside it.

   The kick path had **no test at all** before this: nothing in the suite
   opened a second connection for one identity, on either coordinator.

   **A message that says what to close, but not which one, closes the wrong
   one eventually.**

78. **Three ways the relay answered a question it had not been asked.**

   **The `queued` flag was a presence oracle.** It is `!live`, so on an
   authenticated socket it is ordinary feedback about one's own conversation.
   On a connection that never authenticated it is something else: anyone who
   has ever seen a contact code sends a 60-byte sealed envelope to that
   routing id and reads `queued:false` as "that person is online, now". Once
   a minute is a 24/7 activity timeline for someone with no relationship to
   them at all. `THREAT_MODEL.md` grants presence to the relay operator (R1);
   it does not grant it to the internet. An anonymous sender is now told the
   envelope is held, always — which costs that sender nothing real, since the
   client discards the value and sends every sealed envelope this way — while
   the wake push still decides on what actually happened, so it does not
   start firing for recipients who are connected.

   **`recv` bounded neither of the fields that become store keys**, though
   `send` bounds both. A throwaway keypair and 1 MB `id`s made the
   acknowledgement script build nine ~1 MB keys and issue nine `HGET`s inside
   one blocking Lua call — about 9 MB of hashing per frame, at 80 frames a
   second, on the store every mailbox shares. An unbounded `from` was worse
   in kind than in size: in RAM mode it names the mailbox a receipt is
   enqueued to, so it could create one under any string at all. The refusal
   has to be *silence*, because §12.5.2 says an acknowledgement that names
   nothing is answered with no frame — a client must not be able to tell a
   refused frame from an entry that had already gone.

   **The exemption for small acknowledgements bounded the rate and not the
   number in flight.** The debit happens after the lookup, so every
   acknowledgement arriving in one read passed the gate before any was
   charged: fifty thousand in one burst issued their lookups — up to two
   hundred and ten store calls each on a miss — before the bucket moved.
   Charging them synchronously would break what the exemption is *for*, since
   a device draining a backlog really does acknowledge faster than the bucket
   refills and that is correct behaviour which frees memory. So what is
   bounded is how many may be in the store at once (`ACK_IN_FLIGHT`, 256);
   past that they are charged like any other frame and the gate refuses the
   rest unread. A device draining a paged flush has about `FLUSH_PAGE` (64)
   outstanding, so the case the exemption exists for never meets the bound.

   One test had to change rather than be added, and it is the interesting
   one: `sealed.test.js` asserted `queued: false` for an anonymous sealed
   send delivered live. That assertion *was* the oracle, written down and
   guarded. It now asserts the opposite — that the online and offline cases
   are indistinguishable from an anonymous socket — and that an
   authenticated sender still gets the real answer about its own
   conversation, which is what the field is for.

   **A field that is feedback to one sender is surveillance from another.**

79. **The parity test compared one instance against one instance.** It runs
   one scripted transcript against both coordinators and compares the frames
   the clients receive, frame for frame — which is the right idea, and was
   structurally blind to the deployment it exists to protect. `runRedis`
   built a single `RedisCoordinator`, so presence between instances, the
   kick, and `deliver` over pub/sub were outside the comparison entirely.
   And the normaliser dropped `queued` before comparing, so the two
   implementations were free to disagree about whether an envelope had been
   handed to a live socket — which is precisely where they did disagree.

   So `queued` joins the comparison, and the script runs a third time with
   the clients split across two instances sharing one store, every message
   between them crossing the boundary.

   The interesting part is what that run is allowed to differ on. Everything
   a client can observe must be identical to one process — every message,
   every receipt, every refusal, in order — with one exception: a send that
   crossed instances says `queued: true` where one process says `false`,
   because the instance that published it cannot see whether a socket
   received it. The test asserts the difference is exactly that, frame by
   frame, and **fails if no send crossed an instance at all** — otherwise a
   split that quietly stopped splitting would make the comparison pass by
   comparing nothing, which is the failure mode of every test like this.

   Confirmed by restoring the bug: with a cross-instance publish counted
   live again, the two runs agree, `crossed` is zero, and the test fails on
   the guard rather than on the comparison.

   **A comparison that can pass without comparing anything is not one.**

80. **A v3 contact code that would not decode became a classical one.**
   `ConnectIdentity.fromCode` was a try-v3/catch-`FormatException` ladder of
   its own, and the fallback — `ContactBundle.decode` — does not read `pqc`,
   `acct` or `cert` at all. So any malformed v3 member quietly produced an
   identity anchored on the **device** key with a commitment of 32 zero bytes.

   What makes that worse than a downgrade is what the digits are for. Both
   sides degrade the same way, so the derived string agrees; the humans
   compare eight digits that MATCH; and `confirm()` then records the contact
   as verified — over an identity the comparison never covered. The contact
   is added by re-scanning the same string through `scanContactCode`, which
   has refused these codes since v3 shipped, so the stored record could be
   account-anchored while the number that "verified" it was the device's. And
   the account's later post-quantum identity is then guaranteed to be read as
   a key substitution, which is the alarm firing at the wrong person.

   `_carriesV3Members` exists precisely to route these codes to a refusal.
   `fromCode` was the one identity-reading path that did not use it, so the
   two could disagree about what a code IS. They now share one rule:
   `fromCode` goes through `scanContactCode`, and a code that carries a v3
   member and fails to decode raises rather than falling back. A genuinely
   classical code — one carrying no v3 member at all — still reads as the
   classical identity, because that is a supported thing rather than a
   degrade, and the test says so separately.

   The second half is a type error that was not an exception. `j['ed'] as
   String` on a code with `pqc` and no `ed` throws a `TypeError`, which is an
   `Error` — so it escaped every `on FormatException` between the decode and
   the ceremony, including the one that turns a bad reveal into a
   `ConnectAbort`, and came out raw with the invite left unspent. The members
   are read as values and checked by name, and the construction is wrapped:
   the named checks say which member is wrong, and the wrapper is what makes
   "nothing here throws an `Error`" true for the cases nobody enumerated.
   Measured, with the named checks removed, the wrapper still converts it.

   **Two paths that read the same identity must not be able to disagree
   about what it is.**

81. **A contact's post-quantum key, installed because a device said so.**
   Everything else about a mirrored contact is checked: the routing id is
   re-derived from the bundle, the bundle's own signature is verified, and
   §18.7's certificate rules are re-applied rather than trusted. Then `pqk`
   was taken straight out of the message and written into `Contact.pqPub` —
   whose own doc-comment says it is never set from an unverified source,
   because its being non-null is what `assurance` reports as hybrid.

   The sender chooses `pqc` and `pqk` together, so a self-consistent pair
   passed every check there was. One compromised linked device — no account
   root, so well inside the T1/T2 model — mirrors a contact with a commitment
   of its own and the key that matches it, and the receiving device shows
   hybrid assurance and a safety number over a key the contact never
   published. `acceptsPqKey` existed, with a doc-comment saying a false is
   not a retryable failure, and had exactly one production caller.

   It has two now, and the mismatch is recorded the way `_onPqIdentity`
   records one: no key installed, `pq_mismatch` set durably, the commitment
   left standing so the contact can still reach hybrid when a key that
   matches it arrives.

   Three things about the test are worth keeping. The seam that mirrors a
   contact between devices could not express the attack at all — it sent only
   `rid`, `bundle` and `name`, so `pqc` and `pqk` had to be added to it
   before the bug could be written down. The honest case is its own test
   rather than the second half of the refusal: each mirror is one
   fire-and-forget message over the relay, and two in flight in one test was
   flaky one run in three. And both live in a file of their own rather than
   in `multidevice_test.dart`, because each starts a linked pair, that file
   shares one relay across every test in it, and adding them there made an
   unrelated test in it time out under full-suite load about one run in
   three — measured, not guessed: the file went from nine tests to eleven and
   the same neighbour failed three times. A test that makes its neighbours
   flaky is a test in the wrong file.

   **Every other field in that record is checked. This one was taken on
   trust because it arrived beside them.**

82. **A hold released by the thing it was holding.** `noteContactListChanged`
   cleared `unconfirmedSinceMs` and `heldRids` unconditionally, so the one
   cost `adr/0006` imposes on T2 was avoidable by repetition.

   An attacker holding a contact's account root enrols a rogue device and
   never publishes it. After 24 hours the rogue is held and stops receiving.
   The attacker then re-signs **the same device set** as a fresh list and
   delivers it in-band: the hold drops the instant it arrives and the grace
   starts again. Every 23 hours, for ever, and the device the log has never
   seen keeps reading messages.

   The list that "changed" did not remove the rogue — it re-asserted it,
   which is the opposite of a reason to trust it again. So the hold is now
   kept for every device the new list still contains and released only for
   the ones it drops, and the grace clock restarts only when the hold is
   actually released, since otherwise re-sending buys another 24 hours for
   the same device.

   `stillPresent` is a required parameter rather than a defaulted one. A
   default would leave the original bug one forgotten argument away, and the
   caller already has the parsed list in scope — it was discarding it at the
   call boundary.

   The second half was not in the review. `noteContactListChanged` ran even
   when the install had been **refused**: `_installContactDeviceList` returns
   early for a list that is not this account's, that does not verify, or that
   replays an older version, and it returned `void`, so the caller could not
   tell a refusal from an acceptance and told the log a new list had arrived
   either way. "Send a list the device will throw away" was a second way to
   clear the hold, and it did not even need the account root. It returns
   `bool` now, and the test corrupts a signature to reach it.

   **The hold has to survive the arrival of another list, or it holds
   nothing.**

83. **"Wipe everything" left the key that unlocks the vault, and said it had
   not.** Three faults, each of the kind that looks like it works.

   The storage handle in `wipe()` was built **without**
   `AndroidOptions(encryptedSharedPreferences: true)`, which every write site
   passes. Under flutter_secure_storage 9.x that is a different backing
   store, so the delete asked the wrong place, found nothing there, and
   reported no error.

   `z_bio_passkey` was not in the list at all. It is the raw Argon2id output
   of the user's passphrase — the thing that opens the vault — written by
   `AppLock` and deleted by nothing but `disableBiometricUnlock`, which the
   wipe path never called. Its Keystore alias was left too.

   And the shredding overwrite shared one `try` with the delete, so a file
   whose overwrite failed was never deleted either: the worst case, since it
   is exactly the file something else is holding open. Every per-file failure
   was swallowed, `wipe()` returned normally, and the screen then called
   `exit(0)` — so a `z.db` that could not be removed stayed on disk while the
   user had been told the device was clean.

   The keys are one list now, `Vault.secretStorageKeys`, and the test checks
   it against the **writers** rather than against a second copy of itself:
   every `z_`-prefixed literal in the two files that talk to secure storage
   must appear in it. A list kept in step by hand is the bug that lost
   `z_bio_passkey` in the first place.

   `wipe()` throws if anything is left, the screen says so and does not end
   the process, and the biometric entry is torn down first — its pass key
   and its Keystore alias both live outside the vault's directory, so neither
   goes when that directory does.

   One honest gap, recorded rather than papered over: the separation of the
   overwrite from the delete cannot be measured here. Provoking it needs a
   write to fail while a delete succeeds, and this sandbox and CI both run as
   **root** — which ignores the read-only bit, while the immutable attribute
   refuses the delete as well. Removing the separation fails no test, and the
   test says so in as many words rather than implying coverage it does not
   have.

   **A key written by one class and deleted by a list in another is a key
   that survives "delete everything".**

84. **A conflict that stopped a group and told nobody.** Every transparency
   banner on the chat screen was gated on the chat **not** being a group, and
   the kinds a conflict holds include every group kind (`gmsg`, `gfile`,
   `ginvite`, `gleave`, `gedit`, `gdel`). So a group message to a member in
   conflict threw per member inside the fan-out drain, which caught it and
   left the row — and `_markSentIfLast` counts every queued row, so the
   message stayed `pending` for **every** member. No banner, no composer
   notice, and no way to answer it: "send anyway" existed only on the 1:1
   screen, and a group member's private chat is not somewhere the user has
   any reason to go.

   The second-order failure is what made it an outage rather than a
   confusion. The drain reads a page of 32 rows ordered by `seq` and read it
   **from the head every time**. Once 32 held rows accumulated there — 32
   group messages to that one member, or fewer spread across several groups —
   the page was permanently full of rows that could not be sent, so no group
   message to **any** member of **any** group was delivered at all.

   So the drain keeps a cursor and steps past what it cannot send, ending a
   sweep when the query comes back empty and starting another only if
   something actually went. The rows stay queued rather than being dropped,
   so answering the conflict delivers them instead of losing them; the group
   screen names the members and offers the same "send anyway" the 1:1 screen
   has always had; and the held kinds are skipped rather than attempted,
   which is an optimisation — the `KtSendHeldException` arm behind it is what
   makes the behaviour right, and the mutation proving that is the one that
   removed both.

   The loop wanted care. A sweep that skipped rows and sent nothing must
   **stop**: restarting because it skipped something is an infinite loop,
   since the rows it skipped are exactly the ones it will skip again. The
   first version of this did that, in a background drain, and the fix is the
   `sentThisSweep` flag rather than a comment about it.

   **A message that cannot be sent to one member must not be a message that
   cannot be sent to anyone.**

85. **Three guards that reported on nothing, and a token nobody needed.**

   `check_workflow.py`, `check_blueprints.py` and `dry_run_release.py` each
   read YAML, and each began with a `try: import yaml / except ImportError:
   print(...); sys.exit(0)`. The workflow installs `kyber-py`,
   `dilithium-py` and `cryptography` and **never PyYAML** — it relied on the
   runner image happening to ship it. With `yaml` unimportable all three
   print a friendly line, exit 0, and `audit_verify.sh` counts them as
   passes and prints "Every suite passed". `dry_run_release.py` is the only
   thing that exercises the release job before a tag is pushed, so it
   becomes a no-op at exactly the moment it matters.

   They exit 1 now and say what they could not check, and the `test` job
   installs PyYAML — which makes that line load-bearing rather than tidy.
   Verified in both directions: with the import broken, the three refuse
   here and the same three printed "skipping" on `origin/main`.

   **The actions are pinned.** `softprops/action-gh-release@v2` ran inside
   `release`, whose permissions grant `contents: write`, `id-token: write`
   and `attestations: write`; `subosito/flutter-action@v2` ran in six jobs.
   A tag is a pointer its owner can move, so whoever controlled either `v2`
   held a token that can publish a release and mint a Sigstore attestation
   saying this repository produced bytes it did not. Both are now 40-hex
   commits with the version beside them — resolved from the repositories and
   checked against the commit each names (`1a44944`, "Simplify extraction of
   zip files", 2026-03-25; `3bb1273`, "release 2.6.2", 2026-04-11), because
   a pin nobody verified is a number that looks like evidence.

   **And the workflow declares `permissions: contents: read`.** Only
   `release` had a block, so every other job ran with the repository's
   default token — including `test`, which runs `npm install`,
   `dart pub get`, `flutter pub get` and four `pip install`s. That is
   install-time code from four third-party registries, holding a token it
   has no use for.

   `check_workflow.py` gains both as rules, because the fix without the rule
   lasts until the next person adds a step. Each was checked by breaking it:
   unpinning one action names the job and the step; removing the top-level
   block names what the default token reaches.

   **A check that passes when its dependency is missing is not a weaker
   check. It is not a check.**

86. **Four guards that could be made to check nothing, and each was.**

   **`check_l10n.py`** found the ARB's keys with a regex anchored at `^  "` —
   exactly two spaces — and every check in that function walks the list it
   produced. Re-indenting the file emptied the list, so the duplicate-key
   check, the description check and the unused-key check all passed over
   nothing while the script went on reporting that no screen had regressed.
   Demonstrated: the same duplicated key is reported at two spaces and
   invisible at three, and an editor's "format document" does it. A looser
   regex was the same bug with a wider tolerance — it matched the nested keys
   inside `@meta` blocks — so the parser decides now, with duplicates caught
   by `object_pairs_hook`, which is exact and does not care about layout.

   **`app/tool/contrast.py`** matched the palette constructor by name, as the
   literal `ZColors`. Renaming the class — which is what a rebrand does —
   matched nothing, the loop ran zero times, and it printed "all pairs clear
   WCAG AA" and exited 0 having compared no colours. Matching any
   constructor is not the fix on its own, since a theme with no palettes
   would still "pass": what makes it a check is refusing when the palettes
   the app actually references are not among what it found, and refusing
   when a colour it names is missing from one.

   **`check_audit_scope.py`** asked whether a test file's name appeared
   anywhere in the brief. A sentence *disclaiming* the suite satisfies that
   as well as a citation does. It asks the evidence cells now, and says so
   when a file is mentioned in the prose but cited by nothing.

   **`audit_verify.sh` exited 0 when suites were skipped**, contradicting its
   own header — which says the exit code is 0 only if every suite passed, and
   a suite that did not run did not pass. It exits 2 now, distinct from a
   failure, which is what `--quick` always produces since it does not run the
   app suite.

   Two more things about that script, found while fixing it rather than in
   the review. It **never ran the `kt/` suite at all** — sixty tests backing
   C31, absent from the one command the brief points an external reviewer at.
   And in a fresh clone its **first run failed and its second passed**: the
   protocol suite starts the relay, and the relay's dependencies were
   installed in a later section, so the first impression of the reproduction
   command was `protocol/ dart test FAIL … relay did not start`. Both fixed
   and both measured on a clone made for the purpose.

   **Every one of these reported success while measuring nothing, which is
   the only kind of failure a guard can have that nobody notices.**

87. **Three more of the same, found by measuring the guards instead of
    reading them.**

   Entry 86 fixed four guards that could be made to check nothing. The claim
   that the rest were sound was going to be written from having read them.
   Reading them was wrong: emptying `app/lib/ui` and running the other five
   showed **three** printing success over nothing.

   **`check_a11y.py`** reported "every icon button and image announces
   something" with zero files read. Both its rules are regexes over source,
   and a regex that matches nothing produces character for character the
   output of one that matched and was satisfied. It refuses now when the scan
   read no files, and when it found **no `IconButton` at all** — every screen
   here has an app bar, so zero means the pattern stopped matching, which is
   what a wrapper widget or a rename does. Demonstrated both ways, including
   by renaming `IconButton` to `ZIconButton` across the app: 46 files read, 0
   matched, refused. `Image` deliberately gets no floor, because the app
   ships exactly one and a check that fails when an app has no images is a
   check asking for a decorative one to be added.

   **`check_test_criteria.py`** is a check whose whole subject is a
   convention — a numbered list in a leading `//` block — so it fails the
   moment the convention shifts, and fails silently. Changing `//` to `///`
   across both test directories took it to "test files stating criteria: 0"
   and "every stated exit criterion has a test behind it". It also read two
   directories and could not tell you about one it had lost: renaming
   `app/test` left `protocol/test` producing a healthy-looking count. Both
   refused now, separately, because they are different failures.

   **`check_relay_url.py`** was not vacuous — it reads `relay_url.dart`
   directly and would raise if that file went — but nothing checked its
   `ACCEPTORS`, the five files allowed to say the user agreed to a cleartext
   relay. An entry for a file that no longer exists is worse than no entry:
   it reads like a reviewed decision, about a path nothing resolves to.
   Renaming `onboarding_screen.dart` now fails twice — the stale exemption,
   and the new name claiming an acceptance nobody reviewed.

   `check_ga.py` and `check_android_data_safety.py` were put through the same
   test and refused correctly: the first cross-checks its screen count
   against `check_l10n.MIGRATED`, the second returns 1 on a missing manifest.

   **The difference between a guard that works and a guard that reports on
   nothing is not visible in its output. It is only visible if you break the
   thing it watches and check that it notices.**

88. **The witness cried fork when a packet was lost, and could not open its
    own directory after an unclean stop.**

   Two faults in `kt/lib/mirror.js`, both about the difference between a log
   that misbehaved and a network that did — which is the whole value of a
   witness, because a witness is believed exactly once.

   **A dropped connection mid-pagination was reported as a fork.** `sync`
   appended each page to the trees as it arrived, and only a `Divergence` set
   `poisoned`. An ordinary error — a socket hang-up, a 502 — left `entries`
   ahead of both the disk and the last verified head, and the NEXT sync asked
   the log to prove consistency from a size this mirror had never had a head
   for. The log cannot, so it printed `the head of size 15 does not extend the
   head of size 12` and latched: in `--serve` mode the witness stops following
   the log for ever and serves a stale head, from one dropped connection.
   Reproduced at both ends: on a first sync, where `this.head` is still null,
   it was not even a divergence but `TypeError: Cannot read properties of null
   (reading 'logRoot')`.

   The fix is a rule rather than a patch: **nothing is appended until every
   page has been fetched.** Rewinding is not an option — the log tree, the
   sparse map and the version index all mutate, and rebuilding them measured
   **7.3 s at 7,000 entries and 65 s at 50,000**, so a rollback on every
   network blip would have been a worse bug than the one being fixed. The
   cost of fetching first is holding the delta twice for the length of the
   fetch, and the delta is on its way into `entries` regardless.

   The same rule covers the commit: a failed write to `entries.jsonl` or to
   `sth.json` rereads the directory instead of carrying state no head covers.
   The old comment claimed a mirror that threw there would "re-fetch the same
   entries next time" — it would not, for exactly the reason above, and a
   comment asserting the opposite of what the code does is worse than none.

   **And `DIVERGENCE` is now reserved for what the log signed.** A consistency
   object with the wrong fields and a page with no entries used to poison the
   mirror permanently; both are what a cache, a captive portal or an error
   page produces, and neither says anything about what the log signed. They
   are ordinary errors now and the mirror tries again. Entries that fail to
   reproduce the signed roots, a version that goes backwards, a value that
   does not match its commitment: those still poison, because the log is
   answerable for them.

   **The crash window left a directory nothing could open.** `sync` fsyncs the
   entries and then renames `sth.json` into place, so a machine that dies
   between the two leaves entries the stored head does not cover — and `load`
   refused it, for ever, with no repair path: `head size 9, 13 entries on
   disk`. The head is read first now, because it is signed and it is the
   authority on how many lines count; the surplus is truncated and the tool
   says how many bytes it dropped. Nothing is lost and nothing is rewritten:
   those lines sit ABOVE the last head the mirror verified, so they are part
   of no history it has attested to, and the next sync fetches and re-verifies
   them against a signed root. That is precisely why `tools/repair.js` refuses
   to do the same to the LOG's own file — there a dropped line is history the
   log has signed, and a tool that trims it rewrites what a log exists to fix.
   The opposite direction, fewer entries than the head, still refuses: those
   are under a signed root and cannot be re-derived from the directory.

   Five tests, each mutation-checked by putting the old behaviour back.

   **A witness that cries fork on packet loss is worse than no witness,
   because the first real fork is then dismissed as another one of those.**

89. **A witness accepted with no pinned key, which is a check that appears to
    run.**

   `KtConfig.hasWitness` was `witnessUrl.trim().isNotEmpty` — the address
   alone — and `KtWitnessRecord.verify` took `Uint8List? expectedWitnessPub`
   and skipped the comparison when it was null. So a self-hoster who set a
   witness address and left the key empty got a check that fetches, verifies
   two signatures, sets `witnessOkMs` and shows a tick, with **zero**
   assurance in it: with no pinned key to compare against, the co-signature
   was verified against `witness.pub` from inside the record, which
   establishes only that whoever answered the address could sign. The log's
   own operator can do that. The single thing a witness is for — that it is
   somebody else — was the thing not being checked.

   Three changes, because one of them alone leaves the hole reachable:

   * `expectedWitnessPub` is **required** and non-nullable. There is no way
     left to ask the question without answering "against whose key?" first.
     The protocol test asserted `expect(await rec.verify(logPub), isTrue)` —
     the bug written down as an expectation — and now asserts the pin.
   * `hasWitness` requires an address AND a key that parses to 32 bytes. A
     half-set pair is not consulted at all: no request is made, so a client
     that was carrying one does not even tell that address it exists.
   * `setConfig` **refuses** a half-set pair, with the reason as an l10n key
     so core does not decide what language the user reads. Settings edits the
     address and the key on one screen for the same reason — two rows cannot
     express the rule, and editing them one at a time means passing through
     exactly the bad state to reach a good one.

   Found while writing the test: `_offLimitsInTest`, the guard that stops a
   test process talking to the production log, judged only the log's address.
   The witness's was unjudged — invisible today because
   `defaultKtWitnessUrl` is empty, and a live grenade the moment a build
   defines one, since every test that stands up a ChatService would poll a
   stranger's server on a timer. It judges both now, and criterion 6 holds it.

   Six tests, each mutation-checked. **A signature checked against a key that
   arrived beside it is not a second opinion. It is the same opinion, in a
   second envelope.**
