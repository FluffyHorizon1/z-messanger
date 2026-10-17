# Z — Product Roadmap

**Goal:** take Z from a verified, self-hostable v1.1 to a public, store-listed,
independently-audited encrypted messenger.

**Operating model:** solo, aggressive pace. Phases are sized in weeks
and every milestone is scoped so a single focused working session can implement
*and verify* it (a test, a build artifact, or a screenshot — never "trust me").
Dates assume frequent sessions; slip them freely, the ordering is what matters.

**One rule carried from v1.1:** nothing is "done" without executable evidence.
Each milestone below has a **DoD** (definition of done) that names the proof.

---

## Where things stand (updated 2026-10-16)

| Phase | Status | Evidence |
|---|---|---|
| 0 Foundation hardening | ✅ done | `durability_test.dart`, `docs/LOAD.md`, retry/delete affordances |
| 1 Push notifications | ✅ done (1.3 F-Droid flavour dropped with 3.2) | content-free FCM wake; relay push tests |
| 2 Signed builds | 2.1 + 2.4 ✅ · 2.2/2.3 ⛔ need paid certificates | signed AAB/APK + `SHA256SUMS.txt` on every release |
| 3 Store distribution | **3.1 ✅ live on Google Play** · 3.4 ✅ · 3.2 dropped · 3.3 ⏳ · **3.5 Play Console recommendations ✅** (16 KB pages, edge-to-edge; bitmap/PiP items assessed) | the Play listing, `app/tool/check_16k.sh` in CI, `zmessengers.com` landing + privacy page |
| 4 Scale & observability | 4.2/4.3/4.4 ✅ · 4.1 dropped (no telemetry by design) · queue caps refuse rather than evict, in RAM and Redis mode alike (R22, `docs/ROADMAP_8_15.md` revision 38) | `/metrics`, windowed paging, two-relay HA test in CI, `server/test/queue_caps.test.js` |
| 5 Independent audit | **5.1 ✅ done** · 5.2 scope ✅ (engagement ⛔ external) · 5.3 ⏳ | `docs/PROTOCOL.md` (frozen v1 + v2), `docs/vectors/`, three verifiers in CI, `docs/AUDIT_SCOPE.md` |
| 6 iOS | ⛔ needs a Mac + Apple developer account | — |
| 8 Message interactions | **✅ complete** — 8.1a replies · 8.1b reactions · 8.1c edit / delete-for-everyone / forward | `replies_test.dart` (13 cases incl. the group authorship abuse test), `docs/vectors/v1/inner_messages.json`, PROTOCOL §6.4–6.6 |
| 9–15 | see `docs/ROADMAP_8_15.md` — **9, 10, 11, 13, 14, 15 done** except the externally gated items; 11's log is **deployed at `kt.zmessengers.com` and pinned by the shipped app** (`adr/0006` says what "live" means) — its witness runs under another person's account and is pinned since 2026‑10‑17 (G3); 12 (calls) waits on ADR 0005 | `docs/GA_CHECKLIST.md` is the live GA answer |
| 16 | **✅ complete** — 16.1 sealed sender now holds against the relay process, not only its stored data (`adr/0007`, R21) · 16.2 pattern study: jitter and cover traffic measured against a relay that clusters by timing, and rejected with the numbers (`THREAT_MODEL.md` R18/R19) · 16.3 federation decided as client-to-many-relays and deferred (`adr/0008`) | `anonymous_sender_test.dart`, `server/test/sealed.test.js`, `server/bench/patterns.js` |
| 7 Feature depth | 7.1 sealed sender ✅ · 7.2 linked devices ✅ · 7.3 groups ✅ incl. attachments · **7.4 voice messages ✅** · 7.5 post-quantum hybrid ✅ + **7.5b PQ re-key ✅** · **7.7a device-list transparency ✅** (ADR 0001; 7.7b log: `adr/0006`, in progress) · 7.6 search + history sync + themes ✅ · **7.8 app lock (biometrics) ✅** + **7.8b hardware-bound pass key (Android) ✅** (7.8c macOS/Windows binding ⛔ needs those toolchains) | `sealed_test.dart`, `multidevice_*_test.dart`, `group_test.dart`, `pq_test.dart`, `pq_rekey_test.dart`, `devlist_transparency_test.dart`, `devlist_distribution_test.dart`, `voice_test.dart`, `search_test.dart`, `history_sync_test.dart`, `app_lock_test.dart`, `lock_screen_test.dart` |
| 17 Connect without meeting | ✅ done | `adr/0009`, PROTOCOL §20, `connect_test.dart`, `connect_relay_test.dart` |
| 18 Device lists sign ratchet keys | 18.5–18.7 done (4.2.0); 18.4, 18.7's proofs reaching the transparency log and 18.6's claim withheld per device landed, not released — the dormant hybrid certificate retired (`adr/0031`) | `adr/0017`/`adr/0022`/`adr/0029`/`adr/0031`, PROTOCOL §3.7, `devlist_capability_test.dart`, `device_cert_pop_test.dart`; closes P1-2, P1-3, P1-4's first-come half (R42) |
| 19 Transparency witness | pinned (G3) | mirror/witness built (34); run under another person's account and pinned by the app since 2026‑10‑17 (`kt_witness_test.dart` 10); Settings says when it last agreed with the log, or that it has gone quiet (`kt_witness_test.dart` 11–13) |
| 20 Calls | designed | `adr/0005`; media path undecided |
| 21 iOS | people-gated (G7) | nothing committed; needs a Mac, an Apple account, the reserved push ADR 0002 |
| 22 GA | not ready | `docs/GA_CHECKLIST.md`: G1, G3, G7 open |
| 23 Groups | ✅ done (23.4–23.5 in 4.2.0) | `adr/0019`/`adr/0020`/`adr/0030`, `group_roles_test.dart`, `group_invite_link_test.dart`, `group_timers_test.dart`; closes P1-11, the group P2s |
| 24 Desktop | ✅ done (24.1, 24.3, 24.4); 24.2/24.5 gated | `adr/0013`/`adr/0014`/`adr/0018`, `desktop_startup_test.dart`, `update_check_test.dart`; closes P1-18 |
| 25 Scale | ✅ done | `server/test/ha_load.test.js`, `docs/LOAD.md`, `docs/SLO.md`; a run against real infrastructure is yours |
| 26 PQ always-on | ✅ done (26.1–26.3) | `adr/0027`, PROTOCOL §17.7/§18.10, `pq_rekey_test.dart`, `safety_number_mixed_test.dart`; closes P1-1 |
| 27 Federation | designed, deferred | `adr/0008` |
| 28 Every claim true | ✅ done | register R40–R44; closes P0-1/P0-5 doc halves, P1-19, P1-20 doc half |
| 29 Relay hardening | ✅ done | `server/test/mailbox_admission.test.js`, `auth_binding.test.js`; closes P0-4, P1-13, P1-14, P1-16 |
| 30 Message integrity | ✅ done (30.1–30.3) | `attachment_ownership_test.dart`, `inbound_robustness_test.dart`, `linked_kinds_test.dart`; closes P0-2, P1-10, P1-12 |
| 31 Restore resumes the account | ✅ done | `adr/0025`, `restore_test.dart`, register R45; closes P0-3, P1-8 |
| 32 Alarms only on signed evidence | ✅ done | `adr/0026`, `alarm_evidence_test.dart`, register R46; closes P1-7 |
| 33 Linked devices as equals | ✅ done | `linked_equals_test.dart`, `mirrored_contact_test.dart`; closes P1-5 |
| 34 Transparency log health | ✅ done | `kt/test/log_memory.test.js`, `kt/test/publish_limits.test.js`; closes P1-17 |
| 35 Private transparency lookups | ✅ done (4.1.0; its hardening 4.2.0) | `adr/0023`, PROTOCOL §19.9, `kt_private_lookup_test.dart`, `transparency_bucket_test.dart`, `kt/test/bucket.test.js`; closes P0-5 |
| 36–38 Handles | 36.1–36.2/37 done; 38 done (4.1.0); hardening landed, not released; dormant until a handle log is deployed | `adr/0015` rev 2, PROTOCOL §21, `handles_test.dart`, `intro_mailbox.test.js`, `handle_flow_test.dart`, `kt/test/handle_mode.test.js`, register R47–R50 |
| 39 Public introduction link | planned | `adr/0009`'s deferred public invite |
| 40 Invites bound to their secret | ✅ done | `adr/0024`, PROTOCOL §20.8, `connect_test.dart`; closes P1-9 |
| 41 Metadata: receipts, push, CDN | ✅ done (4.2.0) | `adr/0028`, `receipt_timing_test.dart`, `delivery_receipts_test.dart`, register R41/R44; closes P1-15, P1-20 code half |
| 42 Device hardening | ✅ done (4.2.0); the keyboard rule landed, not released | `device_hardening_test.dart`, `screenshots_test.dart`; closes the device and localisation P2s |
| 43 Release integrity | started: the relay deploy checklist, its guard, the `/latest.json` check and a bundle-aware content digest landed, not released | release P2s/P3s; the deploy checklist (`docs/SELF_HOSTING.md`) and `tool/check_blueprints.py` are the lesson of the 2026-10-15 incident |
| 44 PQ for the classical surfaces | started: 44.2 built (the relay takes `zs2.` as sealed), inert until clients send it; `zs2.` waits on constant-time ML-KEM upstream | `adr/0033` (with addendum A), `sealed.test.js`; the §4.3 gaps |
| 45 Reach without spam | planned | blind-signed first-contact tokens; needs an ADR |
| 46 A backup you cannot lose | planned | scheduled encrypted backups, on phase 31's archive 1.1 |
| 47 Accessibility and languages | planned | a screen-reader pass on real devices, more languages (G8, G9 caveats) |
| 48 Large groups | planned | needs 23 complete and an ADR weighing a group-key schedule |
| 49 Protocol v4: retire the compatibility paths | planned | needs 18.6, 40, 44 and the field moved on |
| 50 Z without one operator | planned | `adr/0008` in practice; needs 19, 27, 36 |

**Next up:** 4.2.0 shipped phases 18.5–18.7, 23.4–23.5, 41 and 42 and the
lookups hardening. Landed for the next release: 18.4 (the dormant hybrid
certificate retired, `adr/0031`) and the hardening the handles need before they
are switched on. The transparency log's **witness** (phase 19) runs under
another person's account and is pinned in the app since 2026‑10‑17
(`adr/0006` says what "live" means, `docs/SELF_HOSTING.md` how), so G3 waits
on a release that carries it and on its last condition. Next: **calls** (phase 20) once
ADR 0005's media path is decided. The full plan for phases 18–50 is below;
phases 0–8 are history, 9–16 are in the rows above and in `docs/ROADMAP_8_15.md`
(historical), and `docs/GA_CHECKLIST.md` is the live answer on what GA still
needs and who must supply it.

---

## Guiding priorities (why the order is what it is)

1. **Don't break the security model.** Every feature is checked against
   `THREAT_MODEL.md`; anything that leaks metadata or weakens E2E gets a design
   note before code.
2. **Reliability before reach.** A messenger that loses messages or misses
   notifications fails no matter how many stores it's in. Phase 1 is reliability.
3. **Distribution unlocks users.** Signed builds + stores (Phases 2–3) are the
   gate to real usage and feedback.
4. **Earn trust to keep it.** Public crypto claims demand an audit (Phase 5).

---

## Phase 0 — Foundation hardening · ~1 week · ✅ *done*

Close the correctness gaps that a wider install base would expose fast.

- **0.1 Ratchet concurrency + durability** — ✅ done in v1.1 (per-conversation
  lock, rollback, regression test that fails without the fix).
- **0.2 Crash/restart fuzz of the vault + outbox.** ✅ Kill the app mid-send and
  mid-receive across 100 randomized iterations; assert no message loss, no
  duplication, no ratchet desync. **DoD:** a `flutter test` that survives
  induced failures at every await point in `_sendInner`/`_onInbound`.
- **0.3 Relay load + abuse test.** ✅ Script N concurrent clients, oversized
  frames, rapid reconnects, queue-cap overflow. **DoD:** relay stays up, memory
  bounded, metrics in `/health`; results in `docs/LOAD.md`.
- **0.4 Structured error surfacing.** ✅ Replace silent drops with a visible
  "couldn't decrypt / send failed — retry" state in the UI. **DoD:** each
  failure path renders a user-facing affordance; screenshot per case.

## Phase 1 — Push notifications (the make-or-break UX gap) · ~2–3 weeks · ✅ *done*

Today messages only arrive with the app open. This is the #1 thing standing
between Z and daily use — and the hardest to do without leaking metadata.

- **1.1 Design note first.** Compare options against the threat model:
  self-hosted push (ntfy/UnifiedPush) vs. FCM/APNs with an encrypted,
  contentless "wake" payload vs. a persistent foreground service on Android.
  **DoD:** `docs/adr/0001-push.md` (ADR) with the chosen approach and its
  metadata trade-offs written down.
- **1.2 Contentless wake + fetch.** Push carries no content and no sender — just
  "you have mail"; the device connects to the relay and pulls encrypted
  envelopes as today. **DoD:** a phone with the app backgrounded receives a
  message within seconds; demonstrated on a real device.
- **1.3 Android foreground-service fallback** for users who refuse Google
  services (F-Droid build flavor). **DoD:** message delivery with the app
  backgrounded and FCM absent.
- **1.4 Relay push dispatch.** Relay optionally holds a per-identity opaque
  push token and pokes it on new mail — still storing no message content.
  **DoD:** relay test covering token register/unregister and poke-on-enqueue.

## Phase 2 — Signed, trustworthy builds · ~1–2 weeks

Remove the scary install warnings; make binaries verifiable.

- **2.1 Android signing.** ✅ Release keystore, `key.properties` wiring, CI signs
  the AAB/APK from GitHub secrets. **DoD:** a signed AAB artifact out of CI.
- **2.2 Windows code signing.** ⛔ *gated on a certificate* (CI step scaffolded) Integrate a signing step (cert or Azure Trusted
  Signing) so SmartScreen stops warning. **DoD:** signed `zapp.exe`; signature
  verifies.
- **2.3 macOS sign + notarize.** ⛔ *gated on an Apple Developer account* Developer ID signing and notarization in CI.
  **DoD:** notarized `.app`/`.dmg` that opens without Gatekeeper override.
- **2.4 Reproducible/verifiable releases.** ✅ Publish SHA-256 sums and signed
  release notes. **DoD:** `SECURITY.md` + checksums on the GitHub Release.

## Phase 3 — Store distribution · ~2–3 weeks

- **3.1 Google Play** ✅ *live* — published as
  [Z Messenger](https://play.google.com/store/apps/details?id=com.zmessenger.www)
  (`com.zmessenger.www`). Data-safety form, privacy policy and listing assets
  submitted and accepted. **DoD met:** the app is live on Play.
- **3.2 F-Droid** — dropped: F-Droid requires an OSI-approved open-source
  license, which the proprietary license precludes. Android is covered by
  Play + the direct signed APK. ~~**DoD:** builds
  under F-Droid's reproducible pipeline; metadata merged.~~
- **3.3 Microsoft Store** (MSIX packaging of the Windows build). **DoD:** MSIX
  submitted to Partner Center.
- **3.4 Direct downloads** ✅ polished on the GitHub Releases page as the fallback
  channel. **DoD:** a simple download landing page.
- **3.5 Play Console recommendations** ✅ — the items the Console raised on
  the first upload, each resolved or deliberately declined: **16 KB
  page-size alignment**
  (required for Android 15+ targets) fixed by moving `mobile_scanner` to
  7.4 (ML Kit 17.3 / CameraX 1.6), with `app/tool/check_16k.sh` verifying
  every 64-bit library in the APK and AAB in CI; **edge-to-edge** enabled
  on every Android version with the screens that set their own list
  padding or centre a form now insetting for the navigation bar
  (`edge_to_edge_test.dart`); **bitmap downsampling** traced with dexdump +
  the R8 mapping to library code on paths Z never takes; **picture-in-
  picture** not applicable (no video).
- *(Apple App Store depends on Phase 6 iOS.)*

## Phase 4 — Reliability & observability at scale · ~2 weeks

- **4.1 Crash-free tracking.** — dropped: even opt-in crash reporting contradicts the no-telemetry stance; crashes are reproduced from user reports instead. Opt-in, privacy-preserving crash reporting
  (self-hosted, e.g. GlitchTip/Sentry-compatible). **DoD:** crashes visible in a
  dashboard; opt-in respected.
- **4.2 Delivery SLIs.** ✅ Instrument the relay for delivery latency and
  queue-depth (no content). **DoD:** a `/metrics` endpoint + a Grafana panel in
  `docs/`.
- **4.3 Message list paging.** ✅ Move chat history off full-in-memory to windowed
  DB paging. **DoD:** smooth scroll with 50k-message synthetic history.
- **4.4 Multi-instance relay** ✅ with shared presence so you can run more than one
  behind a load balancer. **DoD:** two relays, one conversation, no lost mail.

## Phase 5 — Independent security audit · ~3–4 weeks (mostly external)

The credibility gate for any encryption product.

- **5.1 Audit-prep pass.** ✅ Freeze the protocol, expand `PROTOCOL.md` to
  RFC-grade, add cross-implementation test vectors. **DoD:** published test
  vectors a third party can run — `docs/vectors/v1/` (8 suites), reproduced
  bit-for-bit by the Dart library (`protocol/test/vectors_test.dart`) and
  independently verified by a clean-room Node.js implementation
  (`server/test/vectors.test.js`), both in CI. The pass also closed two
  findings: a `legacy` device-certificate flag that bypassed verification, and
  relay push tokens that never expired in the in-memory coordinator.
- **5.2 Engage an auditor** (e.g. a firm like Cure53/Trail of Bits, or a
  well-scoped community review). Scope written: `docs/AUDIT_SCOPE.md` —
  twelve numbered claims each mapped to its spec section and existing
  evidence, ten priority areas for scrutiny, in/out of scope, known
  limitations, and how to run every verifier; `docs/THREAT_MODEL.md`
  refreshed to the shipped system (sealed sender, multi-device trust root,
  groups, PQ hybrid + re-key, device-list transparency). **DoD:** signed
  engagement + scope (the scope half is done; the engagement is external).
- **5.3 Remediate & publish.** Fix findings, publish the report and responses.
  **DoD:** public report + a v-bump changelog of fixes.

## Phase 6 — iOS · ~3–4 weeks

The codebase is Flutter, so iOS is "mostly config + platform testing," but it's
real work: Keychain integration, APNs push, App Store review, sandbox quirks.

- **6.1 iOS target + Keychain vault + APNs.** **DoD:** running on a real iPhone,
  push working.
- **6.2 App Store submission.** **DoD:** in TestFlight.

## Phase 7 — Feature depth · ongoing, post-launch

Ordered by value; each is a self-contained project on the existing layering.

- **7.1 Sealed sender** ✅ — hide the sender identity from the relay (biggest
  metadata win). Touches envelope format + relay auth only.
- **7.2 Linked devices** ✅ — use the same identity on phone + desktop. Builds on
  contact bundles + session machinery; needs a device-to-device key transfer
  and per-device sessions.
- **7.3 Group chats** ✅ (text) — shipped as pairwise fan-out over the existing
  1:1 ratchets instead of sender keys: no group key to manage, and group
  traffic is indistinguishable from direct traffic at the relay.
  **7.3b Group attachments** ✅ — the attachment pipeline for groups: one
  file key, offer (`gfile`) fanned to every member over their pairwise
  ratchet, chunks sealed per member and queued durably. **DoD:** a
  `group_test.dart` case where a 7-chunk photo reaches every member with
  attribution, a non-admin's file reaches members who only know them via
  the invite, and a removed member cannot obtain a later one — met. Shipping
  it exposed and fixed two latent attachment bugs: sealed 480 KiB chunks
  exceeded the relay frame cap (every attachment over ~147 KB had been
  rejected as `too_large` since sealed sender), and concurrent assembly of
  the offer and the last chunk could leave an attachment permanently
  undecryptable.
- **7.4 Voice messages** ✅ — a voice note is an ordinary encrypted attachment
  whose offer carries the optional `voice`/`dur` members (§6.2): capture
  streams PCM into RAM and is wrapped as WAV in memory (plaintext never
  touches disk), playback decrypts to RAM and feeds the player from there.
  Mic button + inline player in the chat; direct, group and self-sync all
  reuse the proven pipeline (`voice_test.dart`). Richer media (video preview
  etc.) stays open under 7.6.
- **7.5 Post-quantum hybrid** ✅ — protocol v2: an ML-KEM-768 (FIPS 203)
  shared secret, offered inside the ratchet on first contact and mixed into
  every message key from the first round trip on, for harvest-now-decrypt-
  later resistance. Negotiated without any unauthenticated flag, so v2↔v1
  stays exactly v1. **DoD:** `pq_test.dart`, `pq_upgrade_test.dart` (two real
  clients over the relay), `docs/vectors/v2/` verified by kyber-py and the
  Node replay in CI.
- **7.5b PQ post-compromise security** — ✅ periodic re-key (PROTOCOL.md
  §17.7): the offering side rotates the ML-KEM secret on an interval (app
  default 7 days) with a generation counter (`pqg` header, `g` offer member),
  retaining the previous generation across the crossover so in-flight and
  out-of-order messages still decrypt; a state stolen at one generation cannot
  read the next. Compatible extension, no version bump. **DoD:**
  `pq_test.dart` re-key group (rotation, out-of-order across the boundary,
  persistence), `pq_rekey_test.dart` (two real clients rotate and keep
  talking), `docs/vectors/v2/pq_rekey.json` verified by kyber-py and the Node
  clean-room replay.
- **7.6 Quality-of-life** — **message search ✅**: full-text search across all
  conversations that decrypts bodies (and attachment names) in memory only —
  the query and its matches never touch disk, preserving the vault invariant.
  Home search icon → debounced search screen with highlighted snippets; tapping
  a hit opens the chat. `ChatService.searchMessages`, `search_test.dart` (direct
  / group / attachment-name hits, case-insensitivity, and a check that stored
  cells stay sealed). **History sync ✅** (the "backup sync" item): a device
  that has just been linked receives the newest 200 text/group-text messages
  per chat from its root over the self-sync channel (`dir:"hist"`, batched,
  deduplicated on message id; attachments are not replayed since their key
  material is not retained by the sender) — `history_sync_test.dart`.
  **Jump to message ✅**: a search hit opens the chat with that message on
  screen and briefly outlined — the loaded window runs from the hit to the
  newest message (cap 500, so a deeper hit opens the chat normally) and the
  existing scroll-up paging continues from its far end (`search_test.dart`
  jump group). **Themes ✅**: light and dark palettes as a `ZColors`
  `ThemeExtension` read through `context.z` (every hard-coded colour in the
  UI migrated), `ZTheme.light()/dark()` with the M3 container roles kept on
  the amber scale, `AppPrefs` (`prefs.json`, read before the vault opens so
  the unlock/lock screens are themed too) with Settings › Appearance
  (System / Light / Dark), system-bar icons following the theme. Both
  palettes clear WCAG AA for every text/background pair
  (`app/tool/contrast.py`). Visual verification is built in:
  `screenshots_test.dart` renders eight screens in both modes with real
  Roboto / Material Icons to `build/screenshots/` (uploaded as a CI
  artifact), and the Linux binary was run under Xvfb with `prefs.json`
  forced each way. Also fixed on the way: `ChatScreen.dispose` looked up an
  ancestor after deactivation (a debug-build assertion on every chat close).
- **7.7 Key transparency** — the zero-trust plan's "catch us, don't trust us"
  mechanism (F2). Design decided in `docs/adr/0001-key-transparency.md`:
  **7.7a** device-list transparency by gossip — ✅ **done** (PROTOCOL.md §3.6:
  `dl`/`pdl` claims and echoes on every inner message, `dlrm` removal notices,
  root self-sync of the signed list, conflict/grace rules, alert banners; DoD
  met by `app/test/devlist_transparency_test.dart`, where a rogue holding the
  account root publishes a split view and an exclusionary list and in both
  cases the honest device AND the contact surface alerts, while an honest
  addition raises nothing). Hardened with self-healing distribution (a stale
  echo makes the root re-send the list; the root re-asserts it on reconnect
  and on request; a root list that *regresses* is itself an alert, which is
  what catches a split-view attacker who answers a device's request from the
  root's mailbox) — `devlist_distribution_test.dart`; **7.7b** a public KEYTRANS-style log committing to
  the same fingerprints — deferred until there is an operator for durable
  infrastructure.
- **7.8 App lock** ✅ — biometric / device-credential authentication to open
  the app (`local_auth`: Android, iOS, macOS, Windows Hello; hidden on Linux).
  *Screen lock*: the OS prompt on launch and after a chosen time in the
  background (immediately … 1 hour); a UI gate laid over the navigation stack
  so the open chat survives, with the vault passphrase as fallback when one
  is set, and a lock nobody can pass (device credential removed) opens and
  switches itself off. *Unlock with biometrics*: a passphrase-protected
  vault opens from the prompt via the stored Argon2id pass key
  (`Vault.open(passKey:)`), bound to the passphrase salt, re-derived on
  passphrase change and deleted on disable / removal — with the trade-off
  stated in THREAT_MODEL.md. Android moved to `FlutterFragmentActivity`,
  AppCompat themes and minSdk 24 for `androidx.biometric`. **DoD:**
  `app_lock_test.dart` (timing, prompt outcomes, in-flight noise, auto-off,
  pass-key lifecycle against a real vault), `lock_screen_test.dart`,
  `vault_passphrase_test.dart` pass-key case.
  **7.8b Hardware-bound pass key (Android)** ✅ — the pass key is sealed
  with AES-256-GCM under an Android Keystore key created with
  `setUserAuthenticationRequired(true)` and a per-use timeout (11+:
  biometric or device credential; 7–10: biometric only), authorised through
  `BiometricPrompt` + `CryptoObject`, so the keystore itself refuses to run
  the decryption until the user has just passed the system prompt — the
  entry is useless to anyone who copies the app's data. New biometric
  enrolments invalidate the key (`setInvalidatedByBiometricEnrollment`);
  the app then falls back to the passphrase and explains. Lives in the app
  (`BioKey.kt` + a `z/biokey` method channel behind `BoundKeyStore`), with
  the 7.8 software-gated entry kept as the fallback for devices that cannot
  make such a key and for macOS/Windows; the settings row says which one
  is in effect. **DoD:** `app_lock_test.dart` bound-store cases (sealed
  v2 entry, no UI prompt, re-seal on passphrase change, invalidation resets
  the feature, plain-entry fallback), APK build compiles the Kotlin,
  THREAT_MODEL per-platform paragraph. **7.8c** ⛔: the same binding via
  Keychain access control (`kSecAccessControlBiometryCurrentSet`) and
  Windows Hello — needs a Mac / Windows toolchain to verify.

---

## Phase 8 — Message interactions · ongoing

What people expect of a messenger day to day, built as additive inner kinds
and optional members (§14: no protocol version bump) so an older build simply
ignores what it does not know.

- **8.1a Replies** ✅ — a content message may carry `rt`, the `mid` it answers
  (PROTOCOL §6.4). Only the id travels: the quote a recipient sees is rendered
  from *their own* stored copy, so a reply can never attribute words to
  someone. An id that names nothing in that conversation — expired, never
  received, or belonging to another chat — degrades to "message unavailable"
  rather than resolving, which also stops `rt` being used to probe the vault.
  Long-press a message to reply; the composer shows what is being answered and
  the quote in the bubble taps through to the original (reusing the
  jump-to-message window from 7.6c). Schema 2 migrates an installed vault in
  place. **DoD:** `app/test/replies_test.dart` — a schema-1 database upgrades
  with every message intact, two clients exchange a reply through the real
  relay and each renders the quote from its own copy, cross-chat and unknown
  ids resolve to nothing, malformed `rt` is ignored — plus additive vectors
  and the Node clean-room shape check.
- **8.1b Reactions** ✅ — `react`/`greact` carry `{rt, emo}`: the target id
  (the same member replies use — it is deliberately not called `mid`, which
  already names the inner's own id) and one emoji, `""` to withdraw. One
  reaction per sender per message, so a second replaces the first and no
  "remove" kind is needed; emoji are bounded at 32 code units with no control
  characters, because a reaction is a badge and not a second text channel.
  Stored per reacting rid in the sealed `reactions` table, so a group member
  sees who reacted and nobody can overwrite a neighbour's. A reaction is not a
  message: no row, no unread, no reordering, and it dies with its target.
  **DoD:** the reaction group in `replies_test.dart` — round trip, replace,
  withdraw, reload, two members reacting independently in a group, a hostile
  peer's cross-chat and unknown targets dropped, oversized/control emoji
  rejected at the protocol layer.
- **8.1c Edit, delete for everyone, forward** ✅ — `edit`/`gedit` {rt, body}
  and `del`/`gdel` {mids}. Both are *requests about the sender's own
  messages*, and the receiver is what makes that true (§6.6): in a group,
  where pairwise fan-out lets any member address any other, the stored
  message records the sender's routing id (`sr` inside the sealed envelope)
  and an edit/delete must match it — a row without one (written before 8.1c)
  fails closed. Edits keep the original `ts` and set an "edited" marker, so
  editing can neither reorder a conversation nor be silent; deletes wipe the
  body, the attachment blob and chunks, and any reactions, leaving a
  tombstone so the conversation keeps its shape and replies still resolve.
  Forwarding sends a *new* message with an `fw` marker (schema 3 column — a
  1:1 text row's sealed body is the bare message, with nowhere to put a
  flag), re-keying an attachment for its new recipient. **DoD:** the
  edit/delete group in `replies_test.dart`, including a legitimate group
  member failing to edit *or* delete a neighbour's message over the same
  channel the owner then successfully uses.

## Phases 18–50

Phases 0–8 above are history. From phase 9 on, three numbering schemes had
been in use at once; this is the single one. Phases 0–17 are history or done,
18–27 keep the numbers commits already cite, and 28–50 are new.

| Work | Old numbers | Number now |
|---|---|---|
| Foundation, push, signed builds, store, scale, interactions | ROADMAP.md 0–5, 7, 8 | history |
| Backup, multi-device, transparency log, PQ identity, verifiability | ROADMAP_8_15 9–11, 13, 14 | done; open items below |
| Sealed sender against the relay process | 16 | done |
| Connect without meeting | 17 | done |
| iOS | 6, 15.1 | **21** |
| Calls | 12 | **20** |
| Transparency witness | 7.7b, 11 | **19** |
| External audit, outside rebuild, GA | 5, 14, 15 | **22** (gates G1, G2) |

**Status labels used below:**

- **Done** — on main and in a release.
- **Landed, not released** — on main, going out in the next release, not yet
  shipped.
- **Designed** — an ADR exists; no code.
- **Planned** — neither yet.
- **People-gated** — needs someone outside this work: an operator, an auditor,
  a Mac, a certificate.

What the releases carried: 4.0.1 — phases 23.3, 24, 25, 26.2–26.3, 28–34,
36.1–36.2, 37 and 40; **4.0.2** — a relay-config fix (phase 43's lesson,
below); **4.1.0** — phase 35 (private transparency lookups) and phase 38
(handles in the app, dormant until a handle log is deployed); **4.1.1** — the
relay's unknown-name login diagnostic (phase 29); **4.2.0** — phases 18.5–18.7,
23.4–23.5, 41 and 42, and the lookups hardening (phase 35). The next release
carries 18.4 and the hardening the handles need (36–38).

**GA gates** (`docs/GA_CHECKLIST.md`, the live answer): G1 external audit ❌,
G2 outside rebuild ⚠️, G3 witnessed transparency ❌, G4 backup ✅, G5
multi-device ✅, G6 threat model ✅, G7 every platform ❌ (no iOS), G8
accessibility ✅, G9 localisation ✅. Phases that move a gate say so.

### Phases 18–27 — the existing plan

Every phase here that code alone could finish is done or landed; the rest needs
people or a decision from you.

| Phase | Status | Done | Left | Closes |
|---|---|---|---|---|
| 18 Device lists sign ratchet keys | 18.5–18.7 done (4.2.0); 18.4, the 18.7 log fix and the 18.6 per-device claim landed, not released | `sig2` over ratchet keys (3.6.1), ML-DSA over membership (3.7.8), the v2-only reader (3.9.9); 18.5–18.6 move each account to v2-only signing once every reader has said it can read one (`adr/0029`, PROTOCOL §3.7), and — landed after 4.2.0 — withhold its claim from each device that has not, not only from a contact none of whose devices has; 18.7 proof of possession in device certificates (`adr/0022`), and — landed after 4.2.0 — in the copy of a list the transparency log takes, so a contact that reads the list from the log cannot lose a proven device to a first-come claim; 18.4 the dormant hybrid certificate retired, the list signature being how v3 binds devices (`adr/0031`) | — | P1-2, P1-3, P1-4's first-come half (R42) |
| 19 Transparency witness | Pinned (2026‑10‑17) | Mirror and witness code; the "witness ahead" false fork fixed (phase 34); a witness run under another person's account, pinned in the app; Settings saying when it last agreed, or has gone quiet | A release that carries it | G3 |
| 20 Calls | Designed | `adr/0005` | Your decision on the media path | — |
| 21 iOS | People-gated | Nothing; `app/ios` has never been committed | A Mac, an Apple account, the reserved push ADR 0002 | G7 |
| 22 GA | Not ready | G4–G6, G8, G9 met | G1 audit, G2 outside rebuild, G3's release and last condition, G7 iOS | — |
| 23 Groups | Done (23.4–23.5 in 4.2.0) | 23.1 rename, 23.1b roles, 23.2 durable files, 23.3 invite links; 23.4 disappearing messages and 23.5 a leaver who stays gone (`adr/0030`) | — | P1-11, the group P2s |
| 24 Desktop | Mostly done | 24.1 Linux starts without system libmpv, 24.3 QR images, 24.4 update-notice links (`adr/0013`, `adr/0018`, `adr/0014`) | 24.2 user-presence binding (needs a Mac), 24.5 signed Windows/macOS builds | P1-18, the desktop P2s |
| 25 Scale | Done | Load rig, SLOs, alert rules, a shared mailbox-creation gate (off by default) | A run against real infrastructure, which only you can do | — |
| 26 PQ always-on | Done | 26.1 defaults; 26.2 every channel re-keys; 26.3 honest screens and a signed commitment in contact codes (`adr/0027`, PROTOCOL §18.10) | 26.4 folded into phase 44 | P1-1, the PQ P2s/P3s |
| 27 Federation | Designed, deferred | `adr/0008` | Trigger-based; nothing planned | — |

### Phases 28–35 — the security and truth work

All eight are released (28–34 and 40 in 4.0.1; 35 in 4.1.0). They close four of
the five P0s in code; P0-1 closes when Play serves a build at or past the
post-quantum safety number. Phase 35's hardening from an independent review
shipped in 4.2.0.

| Phase | Status | What it does | Closes |
|---|---|---|---|
| 28 Every claim true | Done | Corrected every doc the 3 October analysis graded against the code; register rows R40–R44; the RNG override unreachable outside tests | P0-1/P0-5 doc halves, P1-19, P1-20 doc half |
| 29 Relay hardening | Done | Caps and a global budget for mailboxes nobody owns, per-IP limits; backpressure, connection caps, idle timeout; `/metrics` behind a token, a bare `/health`; relay auth checked only against configured names | P0-4, P1-13, P1-14, P1-16 |
| 30 Message integrity | Done | 30.1 binds an attachment to its message and caps what a receiver takes; 30.2 acknowledges every envelope once its fate is decided; 30.3 carries edits, timers, reactions and receipts on linked-device paths | P0-2, P1-10, P1-12 |
| 31 A restore resumes the account | Done | Archive format 1.1 carries the own list, transparency state and contacts' floors; the first start signs above anything seen before any send (`adr/0025`, R45) | P0-3, P1-8, the backup P2s |
| 32 Alarms only on signed evidence | Done | Owner banners need a list the account key signed; damaged vaults reconcile quietly (`adr/0026`, R46) | P1-7, P1-6's leftovers |
| 33 Linked devices as equals | Done; a contact-list fix landed, not released | A new device knows contacts as the phone does; requests, declines and blocks follow the account; and — landed after 4.2.0 — a contact's linked device is sent the account's list as soon as that contact's list names it, so two people who each have a linked device add each other without a false "update never arrived" | P1-5, the contact P2s |
| 34 Transparency log health | Done | Owned buffers, rebalanced publish gates, a repair tool that signs nothing, bounded mirror and witness | P1-17, the KT P2s |
| 35 Private transparency lookups | Done (4.1.0; hardening 4.2.0) | Refreshes ask by label-prefix bucket with a completeness proof, among decoys the app keeps, at random times (`adr/0023`, PROTOCOL §19.9); the hardening pads every entry fetch, sizes buckets from labels the app counted itself, and catches up after short sessions | P0-5 |

**Measured:**

- Store fill from one unauthenticated socket: 201 accepted 1 MB envelopes and
  every honest send refused, before; 5 accepted and honest sends unaffected,
  after (phase 29).
- A socket that stops reading: the relay aborted at 3.3 s before; it now holds
  at +24 MiB and drops the socket (phase 29).
- The transparency log at its live size (~22,000 entries): 376 MiB resident
  before, 187 MiB after. A 512 MiB instance now replays about 130,000 entries
  instead of about 38,000 (phase 34).

The relay and log operator steps — the authority list, `METRICS_TOKEN`,
`CLIENT_IP_HEADER`, and the log runbook (`KT_CLIENT_IP_HEADER`, `KT_MIN_SIZE`,
an off-box copy, a key rotation) — are in `docs/SELF_HOSTING.md`, not copied
here. No branch may edit the Blueprints, so they are yours to set.

### Phases 36–39 — handles and the public link

Handles are shape E′ of `adr/0015` revision 2: a handle resolves to an
introduction mailbox, never to the account key (PROTOCOL §21). The registry and
introduction mailboxes shipped in 4.0.1, the app in 4.1.0; handles stay
**dormant until you deploy a handle log**. An independent review of the handles
then broke four things in them; the fixes are landed for the next release.

| Phase | Status | What it builds |
|---|---|---|
| 36 Handles I: the registry | Done; hardening landed, not released | The protocol library and a separate log in handle mode (`KT_MODE=handles`) with the owner rule, recovery and the bucket query; Dart and Node refuse weak keys and huge versions alike |
| 37 Handles II: introduction mailboxes | Done; hardening landed, not released | The relay checks a proof of work on anything sent to an introduction mailbox, holds copies once, caps envelopes at 64 KiB; a lapsed flag keeps the mailbox guarded, and the stamp travels with the envelope |
| 38 Handles III: the app | Done (4.1.0); hardening landed, not released | Claim, find, request, accept, pause, rotate, retire, recover, in English and Spanish; handle requests capped apart from code requests, each stamp counted once, lookups hidden among decoys sized from counted labels |
| 39 The public introduction link | Planned | A link or QR carrying an introduction key directly, for people reachable from a public page without a registry (`adr/0009`'s deferred public invite) |

The revision fixed the proposal's flaws, each named in `adr/0015`:

| Flaw in the proposal | Fix |
|---|---|
| F1: the log has no owner rule | The first entry for a label fixes its owner key; later entries must be signed by it, or by the committed recovery key. The key and signature sit in the value, so every mirror and client checks the same rule (PROTOCOL §21.4) |
| F2: the operator can link a handle to its owner | The introduction mailbox is drained on its own connection, never registered for push, never claimed at setup. The IP the operator and Cloudflare see remains, stated as a residual (R47, R49) |
| F3: the spam bound is wrong | A request to an introduction mailbox carries a proof of work the relay checks before storing it; the owner sets the difficulty, can raise it, pause the handle or rotate the mailbox; the client caps pending requests (PROTOCOL §21.6) |
| F4: no return leg | The acceptance carries a signature by the introduction key over the requester's id and the owner's account (PROTOCOL §21.7) |
| F5: claiming at setup links the handle to the log history | Claims are offered only after setup, published after a random delay, with hour-granular timestamps |
| Enumeration | Labels are Argon2id of the handle with the vault's parameters, and handles carry digits (`finnian.42`): about a second a guess |
| Lookup privacy | Resolving asks for a prefix bucket with a completeness proof, the same query as phase 35 |
| No recovery | A recovery code shown once at claim can move the handle to a new owner key |
| Confusables | Lowercase ASCII letters, digits and underscore, 3–20 characters, then 2–6 digits; reserved names refused (PROTOCOL §21.1) |
| One key for two logs | A separate instance with its own key and head-context string, so heads cannot be swapped between logs |

The claims bill is paid: every "no directory" sentence now names the directory
Z has, and register rows R47–R50 state the residuals, the last being that the
handle log is unwitnessed (R50). Before a release ships handles live, the Play
listing's "no username" and its Data-safety answers must change, and a handle
log must be deployed — both yours.

### Phases 40–44 — invites, metadata, devices, releases, the PQ edges

| Phase | Status | What it builds | Closes |
|---|---|---|---|
| 40 Invites bound to their secret | Done | v2 links bind the secret into the commitment and channel key; links are held until you consent; requests have time bounds, a replay mark and a cap; old links keep working with a warning (`adr/0024`, PROTOCOL §20.8) | P1-9, the contact-request P2s/P3 |
| 41 Metadata: receipts, push, the CDN | Done (4.2.0) | A receipt leaves at a moment of its own, 5–60 s later and batched (`adr/0028`); push asks first and never registers when notifications are denied; Cloudflare kept and disclosed (R41, R44) | P1-15, P1-20 code half |
| 42 Device hardening | Done (4.2.0); the keyboard rule landed, not released | Screenshots and the recents card blocked while the vault is open (on by default; a setting turns it off); no picker copies left behind; refusals and unlock prompts in Spanish too; the sweep never queries a closed vault; release builds log nothing; every field that takes a secret asks the keyboard to learn nothing, and to suggest and correct nothing where its text can show | the device and localisation P2s |
| 43 Release integrity | Started; the deploy checklist, the `/latest.json` check and a bundle-aware content digest landed, not released | CI refuses to sign a release with the debug key; the APK signing fingerprint published; CI's macOS signing fixed before any signed build; reproducibility measured beyond the universal APK (landed: `tool/verify_reproducible.py --content-digest` reads a bundle, its upload signature left out, and the release dry run stages split APKs and a bundle; the measurement is the CI slots' to make); SLSA Build L3; CAA and HSTS; `/latest.json` set only once Play is current (landed: `tool/check_live_relay.py --play-version` fails while it announces a newer version than Play serves). Also the relay deploy checklist — list every authority name clients dial, the `www.` one too — which the 4.0.2 config fix and the 2026-10-15 login outage made plain: landed as a numbered checklist in `docs/SELF_HOSTING.md` ("Upgrading a relay to 4.0 or later"), with `tool/check_blueprints.py` refusing a public-relay Blueprint that leaves out an address the app dials (the relay already names an unknown authority and counts it, phase 29) | the release P2s/P3s |
| 44 PQ for the classical surfaces | Started; 44.2 built, not released | Hybrid keys for contact requests, the CONNECT ceremony, pairing enrolment and the sealed-sender outer layer; a plan for hybrid session authentication (`adr/0033`, accepted 2026-10-17, with addendum A: a relay-held introduction key). Built so far, and inert until clients use it: the relay treats `zs2.` as sealed (44.2). The client half and `zs2.` itself (44.7) wait on constant-time ML-KEM upstream | the §4.3 gaps, R43's companion work |

### Phases 45–50 — reach, resilience, and after GA

These follow from what handles and the analysis expose; each needs a design
before code. Calls (20), iOS (21) and federation (27) keep their numbers.

| Phase | Why / what it builds | Depends on |
|---|---|---|
| 45 Reach without spam | Proof of work slows a flood but a GPU pays it cheaply. Anonymous, rate-limited tokens (blind-signed, Privacy Pass style): the relay issues a few per account per day and accepts one with each first-contact send, without learning who spent it. Replaces proof of work for introduction mailboxes and caps first contact everywhere | needs an ADR |
| 46 A backup you cannot lose | `BACKUP.md` still says that if the only device is lost, the history is gone — the larger adoption cliff. Scheduled encrypted backups to a destination the user picks, restore on a new device, a recovery-code flow people can complete; builds on phase 31's format 1.1 | 31 |
| 47 Accessibility and languages | G8 and G9 pass on automated checks only. A screen-reader pass on real Android and desktop devices, large-text layouts, and more languages with native review | — |
| 48 Large groups | Pairwise fan-out costs one encryption per member per message. An ADR weighs keeping "no shared group key" at larger sizes against a group-key schedule such as MLS, with what each costs the threat model | 23 complete |
| 49 Protocol v4: retire the compatibility paths | Once the field has moved past the builds that need them, drop the dual paths in one versioned step: v1 device lists, unsigned PQ commitments, relay auth v1, classical fallbacks, unbound invites. New frozen vectors, a migration, a smaller codebase to audit | 18.6, 40, 44; old clients measurably gone |
| 50 Z without one operator | The relay, the transparency log, the handle registry and the witness each run by independent operators, and the client spreads trust across them (`adr/0008` in practice) | 19, 27, 36 |

### Every finding, and the phase that closes it

The 3 October analysis raised 5 P0s and 21 P1s. All but two are closed in code
and released; two wait on you in Play Console.

| Finding | Phase | Status |
|---|---|---|
| P0-1 Play shows honest pairs different safety numbers | Play promotion (yours); docs in 28 | Docs done; waiting on you |
| P0-2 Attachment ids are global | 30.1 | Done |
| P0-3 A restore raises a false "reset your identity" | 31 | Done |
| P0-4 One socket can fill the relay's store | 29 | Done |
| P0-5 Transparency lookups reveal the contact list | 35 | Done; hardening in 4.2.0 |
| P1-1 Linked-device channels never re-key | 26.2 | Done |
| P1-2 A same-version ratchet-key swap is invisible | 18.6 | Done (4.2.0) |
| P1-3 The v2-only gate cannot be measured | 18.5 | Done (4.2.0) |
| P1-4 A contact can claim another's device | 3.9.10; first-come in 18.7 | Done; first-come in 4.2.0, through the transparency log landed |
| P1-5 Linking drops contacts' account keys and commitments | 33 | Done |
| P1-6 Own-list signing race | 3.9.10; damaged vaults in 32 | Done |
| P1-7 Forged "reset your identity" / "device removed" | 32 | Done |
| P1-8 A linked device's backup restores as another account | 31 | Done |
| P1-9 Invites intercepted when digits are skipped | 40 | Done |
| P1-10 Poison envelopes block a mailbox | 30.2 | Done |
| P1-11 Group membership changes are not durable | 3.10.0 | Done |
| P1-12 Linked-device paths drop edits, timers, reactions, receipts | 30.3 | Done |
| P1-13 A slow reader exhausts relay memory | 29 | Done |
| P1-14 Public `/metrics` is a presence oracle | 29 | Done |
| P1-15 Receipt timing links senders | 41 | Done (4.2.0) |
| P1-16 Relay auth can be spliced | 29 | Done |
| P1-17 The log runs out of memory | 34 | Done |
| P1-18 Linux desktop does not start without libmpv | 24.1 | Done |
| P1-19 Cloudflare not disclosed | 28 | Done |
| P1-20 Push on by default, described as opt-in | 28 docs; code in 41 | Done (code in 4.2.0) |
| P1-21 Play "What's new" claims unbuilt features | Yours, in Play Console | Waiting on you |

The two independent reviews of 9 October tried to break the new handles and
lookups by running code against them; the second review (2026-10-10) tried to
break the fixes. The invite-binding cryptography of phase 40 held against
everything they tried. Their lookups findings are closed in 4.2.0, their
handles findings in the handles hardening landed for the next release — except
that the handle log's heads still show when a record arrived: hiding it would
hold a recovery back for up to an hour, so the docs state it instead (`adr/0015`
flaw F5; R49).

### Order of work

1. Ship the next release: 18.4 and the handles hardening, both landed on
   main.
2. Ship the witness pin (phase 19, G3) and engage an auditor (G1).
3. Decide the calls media path (`adr/0005`) and build phase 20.
4. Phase 43 release integrity, then 39 and 44–50 as their designs land.

### What waits on you

`docs/GA_CHECKLIST.md` is the live list of who must supply each open gate: a
check of G3's last condition, an auditor (G1), an outside rebuilder (G2), and a Mac
and signing certificates for iOS and desktop (G7, 24.2, 24.5). Operator steps
for the relay and the logs live in `docs/SELF_HOSTING.md`'s runbooks. Beyond
those:

- **Play Console:** delete the three false bullets in the older "What's new"
  (P1-21), promote a build at or past the post-quantum safety number (P0-1),
  and declare the FCM token in Data safety (P1-20).
- **Before a release ships handles live:** deploy a handle log
  (`KT_MODE=handles`, its own key and service), set the two defaults in
  `app/lib/core/handles.dart`, and change the Play listing's "no username" and
  Data-safety answers.
- **Decisions taken on a default**, any reversible before they ship: digits
  after a handle (`finnian.42`); proof of work as the handle spam control until
  phase 45; a recovery code shown once; delivery receipts on, batched 5–60 s
  later (`adr/0028`); push on Android on by default, now disclosed and asking
  first (phase 41); screenshots blocked by default (phase 42); Cloudflare kept
  and disclosed (R44); when to flip an account to v2-only device lists, per
  account once every reader can (`adr/0029`).

## How to run each milestone

Pick a milestone from this file (e.g. *Phase 0.2*), implement it, write the
test named in the DoD, run it, and commit. Because
every milestone's DoD is an artifact, you always end a session with proof it
landed — the same discipline that carried v1.0 → v1.1.
