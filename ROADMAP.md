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

## Phase 0 — Foundation hardening · ~1 week · *in progress*

Close the correctness gaps that a wider install base would expose fast.

- **0.1 Ratchet concurrency + durability** — ✅ done in v1.1 (per-conversation
  lock, rollback, regression test that fails without the fix).
- **0.2 Crash/restart fuzz of the vault + outbox.** Kill the app mid-send and
  mid-receive across 100 randomized iterations; assert no message loss, no
  duplication, no ratchet desync. **DoD:** a `flutter test` that survives
  induced failures at every await point in `_sendInner`/`_onInbound`.
- **0.3 Relay load + abuse test.** Script N concurrent clients, oversized
  frames, rapid reconnects, queue-cap overflow. **DoD:** relay stays up, memory
  bounded, metrics in `/health`; results in `docs/LOAD.md`.
- **0.4 Structured error surfacing.** Replace silent drops with a visible
  "couldn't decrypt / send failed — retry" state in the UI. **DoD:** each
  failure path renders a user-facing affordance; screenshot per case.

## Phase 1 — Push notifications (the make-or-break UX gap) · ~2–3 weeks

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

- **2.1 Android signing.** Release keystore, `key.properties` wiring, CI signs
  the AAB/APK from GitHub secrets. **DoD:** a signed AAB artifact out of CI.
- **2.2 Windows code signing.** Integrate a signing step (cert or Azure Trusted
  Signing) so SmartScreen stops warning. **DoD:** signed `zapp.exe`; signature
  verifies.
- **2.3 macOS sign + notarize.** Developer ID signing and notarization in CI.
  **DoD:** notarized `.app`/`.dmg` that opens without Gatekeeper override.
- **2.4 Reproducible/verifiable releases.** Publish SHA-256 sums and signed
  release notes. **DoD:** `SECURITY.md` + checksums on the GitHub Release.

## Phase 3 — Store distribution · ~2–3 weeks

- **3.1 Google Play** (internal → closed → open testing track). Data-safety
  form, privacy policy, listing assets. **DoD:** app live on an internal track.
- **3.2 F-Droid** — dropped: F-Droid requires an OSI-approved open-source
  license, which the proprietary license precludes. Android is covered by
  Play + the direct signed APK. ~~**DoD:** builds
  under F-Droid's reproducible pipeline; metadata merged.~~
- **3.3 Microsoft Store** (MSIX packaging of the Windows build). **DoD:** MSIX
  submitted to Partner Center.
- **3.4 Direct downloads** polished on the GitHub Releases page as the fallback
  channel. **DoD:** a simple download landing page.
- *(Apple App Store depends on Phase 6 iOS.)*

## Phase 4 — Reliability & observability at scale · ~2 weeks

- **4.1 Crash-free tracking.** Opt-in, privacy-preserving crash reporting
  (self-hosted, e.g. GlitchTip/Sentry-compatible). **DoD:** crashes visible in a
  dashboard; opt-in respected.
- **4.2 Delivery SLIs.** Instrument the relay for delivery latency and
  queue-depth (no content). **DoD:** a `/metrics` endpoint + a Grafana panel in
  `docs/`.
- **4.3 Message list paging.** Move chat history off full-in-memory to windowed
  DB paging. **DoD:** smooth scroll with 50k-message synthetic history.
- **4.4 Multi-instance relay** with shared presence so you can run more than one
  behind a load balancer. **DoD:** two relays, one conversation, no lost mail.

## Phase 5 — Independent security audit · ~3–4 weeks (mostly external)

The credibility gate for any encryption product.

- **5.1 Audit-prep pass.** Freeze the protocol, expand `PROTOCOL.md` to
  RFC-grade, add cross-implementation test vectors. **DoD:** published test
  vectors a third party can run.
- **5.2 Engage an auditor** (e.g. a firm like Cure53/Trail of Bits, or a
  well-scoped community review). **DoD:** signed engagement + scope.
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

- **7.1 Sealed sender** — hide the sender identity from the relay (biggest
  metadata win). Touches envelope format + relay auth only.
- **7.2 Linked devices** — use the same identity on phone + desktop. Builds on
  contact bundles + session machinery; needs a device-to-device key transfer
  and per-device sessions.
- **7.3 Group chats** — start with sender-keys for small groups. Meaningful
  key-management design; explicitly a post-audit item.
- **7.4 Voice messages & richer media** — reuse the attachment pipeline.
- **7.5 Post-quantum handshake** — add an ML-KEM (Kyber) hybrid layer to X3DH
  for harvest-now-decrypt-later resistance. Isolated to the handshake.
- **7.6 Message search, backups sync, themes** — quality-of-life.

---

## Suggested near-term sprint (the next 3 sessions)

1. **Reliability:** Phase 0.2 crash/restart fuzz test + 0.4 error surfacing.
2. **The UX unlock:** Phase 1.1 push ADR + 1.2 contentless wake prototype.
3. **Trust:** Phase 2.1 Android signing in CI (fastest "looks legit" win).

Each is a clean working session: implement, test, screenshot/artifact, commit.

## How to run each milestone

Pick a milestone from this file (e.g. *Phase 0.2*), implement it, write the
test named in the DoD, run it, and commit. Because
every milestone's DoD is an artifact, you always end a session with proof it
landed — the same discipline that carried v1.0 → v1.1.
