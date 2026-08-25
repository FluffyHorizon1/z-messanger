# Z — Application Review & Development Retrospective

*State of the codebase as of v1.1 (August 2026). This is the honest engineering
picture: what exists, how it was verified, what broke along the way and how it
was fixed, and where it stands against the bar of a public product.*

---

## 1. What Z is, in one paragraph

Z is a zero-trust 1:1 messenger: end-to-end encrypted with a Signal-style
Double Ratchet, no accounts or phone numbers (your address is a hash of a
public key), and no server storage of any kind — the relay holds ciphertext in
RAM only until the recipient's device confirms it has persisted the message,
then wipes it. Messages live exclusively in each device's encrypted local
vault. One Flutter codebase ships to Android, Windows, Linux, and macOS; a
~600-line Node.js relay is the only server component, deployable to Render's
free tier in one click.

## 2. Architecture

The system is three deliberately separated layers:

**`protocol/` — the cryptographic core (~1,400 lines of pure Dart, no Flutter
dependency).** This is where all security-critical logic lives: Ed25519/X25519
identities, signed contact codes, the X3DH-style handshake, the Double Ratchet
(HKDF-SHA256 root chain, HMAC-SHA256 message chains, XChaCha20-Poly1305 AEAD,
out-of-order tolerance via bounded skipped-key caching, transactional decrypt),
attachment encryption (per-file keys delivered inside the ratchet), safety
numbers, and the authenticated relay client. Keeping it pure Dart means the
exact code that ships in the app is testable headlessly — which is how the
whole suite runs in CI without an emulator.

**`server/` — the relay (~680 lines of Node.js including tests, one runtime
dependency: `ws`).** A WebSocket switchboard that authenticates clients by
Ed25519 challenge/response, queues encrypted envelopes per recipient in
process memory with TTL and size caps, and deletes them on device-confirmed
delivery. It has no database, no filesystem writes (a test asserts the source
contains no disk-write calls), stamps the authenticated sender onto every
envelope so senders cannot be spoofed, and runs happily with a read-only
filesystem — the shipped Docker Compose actually enforces `read_only: true`.

**`app/` — the Flutter application (~3,650 lines of Dart).** UI (onboarding
with live relay probing, chat list, chat screen, QR/paste contact exchange,
contact info with safety numbers, settings) plus the service layer: an
encrypted SQLite vault (cell-level XChaCha20-Poly1305 under a key in the OS
keystore, with a warned-about file fallback), a reconnecting transport, and
`ChatService` — the orchestrator that owns the crash-safety invariants:
ratchet state persists before ciphertext leaves the device, the relay is acked
only after a message is inside the vault, per-conversation locking serializes
all ratchet access, and plaintext never touches disk.

The trust story that falls out of this: the relay operator sees routing hashes,
sizes, and timing — never content, names, or keys. Full details and residual
risks (metadata, endpoint compromise, unverified first contact) are in
`THREAT_MODEL.md`; the wire-level spec precise enough to write an independent
client is in `PROTOCOL.md`.

## 3. Verification — what "it works" is based on

Nothing here is claimed on faith; every layer has executable evidence, all of
it wired into CI (`.github/workflows/build.yml`) so it re-runs on every push.

| Layer | Evidence | Count / result |
|---|---|---|
| Relay | Unit tests: challenge auth, bad-signature rejection, RAM queue + ack lifecycle, offline flush, oversize rejection, sender-spoofing impossibility, oversized-frame crash resistance, no-disk-writes source assertion | 8/8 passing |
| Protocol | Unit tests: contact-code tamper rejection, safety numbers, two-way ratchet, out-of-order within and across DH turns, tamper/replay rejection without state damage, serialization round-trip mid-conversation, simultaneous-initiation convergence, padding, attachment integrity | 19/19 passing |
| Full stack | Integration test that boots the real Node relay and drives two real protocol clients: handshake, live + offline delivery, delivered receipts, chunked attachment, and an assertion that no plaintext crossed the wire | passing |
| App | Concurrency regression: two full `ChatService` instances through the real relay firing 15 simultaneous messages each way; asserts zero loss, zero duplication, correct order. Verified to *fail* when the fix is removed | passing |
| Static | `flutter analyze` / `dart analyze` | 0 issues |
| Builds | Linux release compiled and run; Android release APKs built (all 3 ABIs); Windows/macOS built by CI on their native runners | ✓ |
| GUI | Scripted two-instance session under Xvfb: onboarding, QR/code exchange with signature verification, live conversation with delivered ticks, screenshots in `docs/` | ✓ |

## 4. Development history — what happened, in order

The build proceeded bottom-up so each layer verified the one below it.

**Round 1 (v1.0.0).** Relay first, with tests passing before anything depended
on it. Then the protocol package — the Double Ratchet and handshake passed
their 19 unit tests on the first run, but the *integration* test through the
real relay immediately earned its keep by exposing two genuine bugs: the relay
process crashed outright on an oversized WebSocket frame (missing `ws` error
handler — one hostile client could kill the server for everyone), and the
attachment chunk size ignored double-base64 expansion, producing 1.14 MB
frames against a 1 MB cap. Both fixed, both now covered by tests. The Flutter
app came next; its first GUI run exposed a provider-scoping bug (services
invisible to pushed routes) — fixed by restructuring the widget tree. The
Linux build surfaced a sandbox-environment issue (corrupted sqlite3 binary
downloads) solved by pinning to the compile-from-source package line. Finally,
a scripted two-instance GUI session proved the whole thing end to end, and
Android APKs were built after taming a Gradle/AGP version dance.

**Round 2 (v1.1).** An adversarial code review (a second, independent pass
with a brief to *refute* the implementation) confirmed one critical and two
high-severity bugs, all real:

*The ratchet race (critical).* Nothing serialized concurrent encrypt/decrypt
on the same conversation. An inbound decrypt cloning state while an outbound
encrypt advanced it could commit a stale clone back, rewinding the send chain
— the next message would reuse an index, fail authentication on the other
side, and be silently dropped. Fixed with a per-conversation async mutex
around every encrypt/decrypt-plus-persist, with rollback on persistence
failure. The concurrency regression test was written to fail without the lock
(verified) and pass with it.

*The durability gap (high).* Decrypt advanced the in-memory ratchet before the
database transaction; if that transaction failed, the message became
permanently undecryptable on redelivery. Fixed: state snapshots before
decrypt, rollback on failure, no ack until committed — the relay redelivers
and the retry now succeeds.

*macOS file access (high).* Both entitlements files lacked
`com.apple.security.files.user-selected.read-write`, which would have broken
attachments, saving, and backup restore under the App Sandbox. Fixed.

Round 2 also delivered the deployment story: `render.yaml` blueprint with a
one-click button, `DEPLOY.md` walkthrough, `deploy/` scripts for GitHub push,
Fly.io, and a TLS-automated VPS install, plus in-app relay URL normalization
(pasting the `https://` form just works) and a **Test connection** probe that
verifies the far end is actually a Z relay before you commit to it.

## 5. Honest assessment against a public-product bar

**Genuinely solid:** the layering (crypto core isolated and headless-tested);
the invariant discipline in `ChatService` (persist-before-send,
ack-after-persist, lock-per-conversation — each now regression-tested); the
relay's smallness (~600 lines, one dependency, memory-only — a tiny audit
surface); the honesty of the documentation (the threat model states plainly
what Z does *not* protect against); and the CI, which runs every suite and
produces installable artifacts for all four platforms on every push.

**Known gaps, deliberate for v1.1, that a public product must close:**
no push notifications (messages arrive only while the app is open — the
single biggest UX gap on Android, and solving it without leaking metadata to
Google is a real design problem); no iOS; unsigned binaries (SmartScreen and
"unknown sources" friction); no independent security audit — the cryptography
composes well-studied primitives faithfully to spec, but unaudited crypto
should not carry life-or-death threat models, and the docs say so; metadata
visibility to the relay operator (routing-pseudonym graph, sizes, timing) —
mitigations like sealed sender exist and are roadmapped; single-device
identities (no linked devices); no group chats; and a handful of accepted
implementation shortcuts (ratchet headers unencrypted — contents protected,
minor metadata; UI message lists fully in memory — fine to thousands of
messages, needs paging eventually; Argon2id in pure Dart is slow-ish on
low-end phones at backup time only).

None of these are architectural dead ends; the layering was chosen so each can
land without rework (e.g. sealed sender touches only the envelope format and
relay auth; linked devices build on the existing contact-bundle and session
machinery).

## 6. Where things stand operationally

A user today can: deploy the relay to Render in one click with a free `wss://`
URL, sideload the Android APK or run the Linux/Windows/macOS build, verify
their relay with the in-app connection test, exchange QR contact codes, and
message with E2E encryption, delivered/read ticks, encrypted attachments to
24 MB, per-chat disappearing timers, safety-number verification, encrypted
local storage, and passphrase-protected identity backup. The repo is a git
repository with clean history, MIT licensed, with CI that turns any push into
tested, installable artifacts.

The roadmap from here to a public launch is in [`ROADMAP.md`](../ROADMAP.md).
