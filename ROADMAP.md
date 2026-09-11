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

## Where things stand (updated 2026-09-11)

| Phase | Status | Evidence |
|---|---|---|
| 0 Foundation hardening | ✅ done | `durability_test.dart`, `docs/LOAD.md`, retry/delete affordances |
| 1 Push notifications | ✅ done (1.3 F-Droid flavour dropped with 3.2) | content-free FCM wake; relay push tests |
| 2 Signed builds | 2.1 + 2.4 ✅ · 2.2/2.3 ⛔ need paid certificates | signed AAB/APK + `SHA256SUMS.txt` on every release |
| 3 Store distribution | **3.1 ✅ live on Google Play** · 3.4 ✅ · 3.2 dropped · 3.3 ⏳ · **3.5 Play Console recommendations ✅** (16 KB pages, edge-to-edge; bitmap/PiP items assessed) | the Play listing, `app/tool/check_16k.sh` in CI, `zmessengers.com` landing + privacy page |
| 4 Scale & observability | 4.2/4.3/4.4 ✅ · 4.1 dropped (no telemetry by design) | `/metrics`, windowed paging, two-relay HA test in CI |
| 5 Independent audit | **5.1 ✅ done** · 5.2 scope ✅ (engagement ⛔ external) · 5.3 ⏳ | `docs/PROTOCOL.md` (frozen v1 + v2), `docs/vectors/`, three verifiers in CI, `docs/AUDIT_SCOPE.md` |
| 6 iOS | ⛔ needs a Mac + Apple developer account | — |
| 8 Message interactions | **✅ complete** — 8.1a replies · 8.1b reactions · 8.1c edit / delete-for-everyone / forward | `replies_test.dart` (13 cases incl. the group authorship abuse test), `docs/vectors/v1/inner_messages.json`, PROTOCOL §6.4–6.6 |
| 9–15 | see `docs/ROADMAP_8_15.md` — **9, 10, 11, 13, 14, 15 done** except the externally gated items; 11's log is built end to end and **waits on deployment** (`adr/0006` says what "live" means); 12 (calls) waits on ADR 0005 | `docs/GA_CHECKLIST.md` is the live GA answer |
| 16 | **✅ complete** — 16.1 sealed sender now holds against the relay process, not only its stored data (`adr/0007`, R21) · 16.2 pattern study: jitter and cover traffic measured against a relay that clusters by timing, and rejected with the numbers (`THREAT_MODEL.md` R18/R19) · 16.3 federation decided as client-to-many-relays and deferred (`adr/0008`) | `anonymous_sender_test.dart`, `server/test/sealed.test.js`, `server/bench/patterns.js` |
| 7 Feature depth | 7.1 sealed sender ✅ · 7.2 linked devices ✅ · 7.3 groups ✅ incl. attachments · **7.4 voice messages ✅** · 7.5 post-quantum hybrid ✅ + **7.5b PQ re-key ✅** · **7.7a device-list transparency ✅** (ADR 0001; 7.7b log: `adr/0006`, in progress) · 7.6 search + history sync + themes ✅ · **7.8 app lock (biometrics) ✅** + **7.8b hardware-bound pass key (Android) ✅** (7.8c macOS/Windows binding ⛔ needs those toolchains) | `sealed_test.dart`, `multidevice_*_test.dart`, `group_test.dart`, `pq_test.dart`, `pq_rekey_test.dart`, `devlist_transparency_test.dart`, `devlist_distribution_test.dart`, `voice_test.dart`, `search_test.dart`, `history_sync_test.dart`, `app_lock_test.dart`, `lock_screen_test.dart` |

**Next up:** the transparency log going live (a deployment — `adr/0006`
says what "live" means and `docs/SELF_HOSTING.md` how), then phase 12
(calls) once ADR 0005 is decided. The full plan for phases 8–15 — backup,
multi-device, key transparency, calls, PQ identity, verifiability, GA — is
`docs/ROADMAP_8_15.md`; the externally gated items (auditor engagement,
desktop certificates, iOS, 7.8c) are folded into phases 14 and 15 there, and
`docs/GA_CHECKLIST.md` says which are still open and why.

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

## Suggested near-term sprint (the next 3 sessions)

1. **Phase 9.1–9.2** — the archive format and export/import (see
   `docs/ROADMAP_8_15.md`).
2. **Phase 9.3–9.5** — destination, recovery ceremony, scheduled export.
3. **Phase 10.1** — promote the identity to an account key that signs device
   certificates.

Each is a clean working session: implement, test, screenshot/artifact, commit.

## How to run each milestone

Pick a milestone from this file (e.g. *Phase 0.2*), implement it, write the
test named in the DoD, run it, and commit. Because
every milestone's DoD is an artifact, you always end a session with proof it
landed — the same discipline that carried v1.0 → v1.1.
