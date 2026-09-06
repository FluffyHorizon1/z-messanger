# Z — roadmap, phases 8–15

**Status:** adopted · September 2026
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
loses all history. It is also the cheapest answer to "does a newly linked
desktop get my history?" in phase 10 — restore from backup instead of building
a bespoke history-transfer channel.

- **9.1 archive format** — versioned, AEAD-sealed archive of the whole vault
  (messages, contacts, group state, attachment blobs), key derived by Argon2id
  from a user-held 12-word recovery code. Documented in `docs/BACKUP.md` and
  vectored, because a backup you cannot read in two years is not a backup.
- **9.2 export / import** — streaming export so large blob sets don't blow
  memory; import with forward-compatible schema migration (an archive written
  at schema 3 must restore on schema 5).
- **9.3 destination** — user-chosen local file first. Any cloud target is
  user-supplied storage the client writes ciphertext to; the relay never
  stores or proxies backups. That is an explicit anti-goal, not an omission.
- **9.4 recovery UX** — code generation and confirmation ceremony, restore
  flow, and the honest framing: lose the code and the archive is gone, because
  there is no server-side path to be compelled.
- **9.5 scheduled backup** — optional periodic re-export, off by default.

**Exit:** an archive taken on device A restores byte-faithfully on a wiped
device B, including attachments; a wrong recovery code fails closed with no
oracle; an archive from an older schema restores onto the current one in test.

---

## Phase 10 · Multi-device

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
  and contact list over the verified channel. History comes from a phase-9
  restore, not a bespoke transfer.
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
  last head seen. **Hard fail**: no send, not a warning banner.
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
  envelopes over the existing relay; no call verb the relay can distinguish by
  size or timing beyond what padding already permits; no call records anywhere.
- **12.2 1:1 voice** — media keys derived from the existing pairwise ratchet,
  SRTP with DTLS as the fallback path; direct P2P preferred.
- **12.3 video** — same transport, added once voice is stable on real devices.
- **12.4 relay-assisted path** — TURN only where P2P fails, run as a separate
  service with the IP-exposure trade-off written into `DATA_MAP.md` and stated
  in the UI. Honesty here matters more than the feature does.

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

- **13.1 hybrid signatures** — account and device keys become Ed25519 +
  ML-DSA-65; both signatures required, verification fails if either fails.
- **13.2 contact code v3** — `zc3.` carrying hybrid account keys and hybrid
  device certs; v2 codes still resolve with a "classical identity" marker.
- **13.3 safety number v2** — derived from both key halves. A visible, one-time
  change for every user, so it needs deliberate re-verification UX.
- **13.4 spec + vectors** — PROTOCOL §18 for v3, a v3 vector suite with an
  independent checker, v1/v2 suites frozen as usual.
- **13.5 compatibility window** — one release accepting v2 identities and
  emitting v3, then v2 emission is dropped.

**Exit:** three independent checkers agree on the v3 vectors; a v2 and a v3
client interoperate during the window; a forged device cert with only a valid
Ed25519 half is rejected.

---

## Phase 14 · Verifiability & assurance

Nothing here adds a feature; all of it converts claims into evidence, which is
the premise of the product. Freeze the protocol at v3 before starting —
auditing a moving spec wastes the money.

- **14.1 reproducible builds** — deterministic APK/AAB and desktop bundles; two
  independent machines produce bit-identical artefacts.
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
- **15.4 docs & support** — user documentation, recovery guidance, an honest
  "what a compromised endpoint defeats" page.
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
