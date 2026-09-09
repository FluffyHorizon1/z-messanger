# Z — Threat Model

This document is deliberately honest about what Z protects, what it does not,
and why. "Zero trust" here means **you do not have to trust the server** to
keep your message contents — or, since sealed sender, who you talk to —
private. It does *not* mean magic. Read this before relying on Z for anything
that matters. The normative wire format is `PROTOCOL.md`; the design
decisions that changed the model are in `adr/`.

## What Z is

An end‑to‑end encrypted messenger — 1:1 and small groups, text, attachments
and voice notes — across a user's several devices. Messages are encrypted on
your device and only ever decrypted on your contacts' devices (and your own
other devices). The server ("relay") is a dumb pipe that shuttles opaque
ciphertext between mailboxes and holds undelivered ciphertext in RAM only
until it is delivered or it restarts.

## Cryptographic design in one paragraph

Each **device** holds an Ed25519 signing key (relay authentication, routing
id = hash of the key) and an X25519 key (session establishment). An
**account** is an Ed25519 root key that signs *device certificates* and a
versioned, signed *device list*; a one‑device account is exactly the original
v1 identity. Two devices establish a session with an X3DH‑style handshake
(no server prekeys — the peer's long‑term X25519 key stands in) and then run
the **Double Ratchet** (Signal's construction): every message uses a fresh
single‑use key, giving forward secrecy and post‑compromise security on every
round trip. Since protocol v2, an **ML‑KEM‑768** (FIPS 203) shared secret
established inside the ratchet is mixed into every message key — a hybrid
that stays confidential against a future quantum adversary who breaks
X25519 — and is **rotated periodically** so a stolen device state does not
keep the quantum‑safe secret forever. Contents are sealed with
XChaCha20‑Poly1305 and padded to 256‑byte blocks. Attachments use a per‑file
key delivered inside the ratchet. Every envelope is **sealed** to the
recipient device so the relay does not learn who sent it.

## Trust boundaries

| Party | What they can do | What they **cannot** do |
|-------|------------------|--------------------------|
| The relay server | See that an opaque blob of a *padded* size was delivered to routing‑id R at time T; hold it in RAM until delivery; see which routing ids are online and when they read their mailbox | Read message text, names, file names or contents; learn **who sent** an envelope (sealed sender); forge or replay messages; recover anything after a restart; learn who is in a group |
| A network eavesdropper (with TLS) | See that you connected to a relay | Read anything (TLS + E2E) |
| A network eavesdropper (without TLS) | See destination routing ids, padded sizes and timing | Read contents or learn senders (still sealed + E2E) |
| Someone who steals your locked device | Hold encrypted bytes | Read messages without your OS user / keystore credentials (and app passphrase, if set) |
| Someone who steals your **identity backup** (`.zid`) and its passphrase | Impersonate your account: read *future* messages sent to a device they enrol, sign a new device list | Read *past* messages (backups hold identity and contacts, never messages); enrol a device **silently** — contacts and your honest devices are designed to notice (device‑list transparency, below) |
| Your contact | Read what you send them; screenshot it; keep it forever; add you to a group | Prove to a third party that *you specifically* wrote something (messages are repudiable); learn your other devices' keys beyond what the signed list states |
| A group admin | Decide membership; the invite is asserted over the admin's authenticated channel | Read messages sent before they were in the group; decrypt anything — there is no group key, every message is pairwise‑encrypted to each member |
| Your own linked device | Everything your primary device can do with messages (it is you) | Enrol further devices or sign a device list unless it was explicitly given the account root at pairing |

## What Z protects against

- **A malicious or compromised relay.** The relay never has keys or
  plaintext. It cannot read, alter, or forge messages, and — with sealed
  sender — it cannot tell who sent an envelope. This is the core guarantee
  and it holds even if the operator is hostile or hacked.
- **Server‑side data breaches / subpoenas of stored messages.** Nothing at
  rest to seize. Undelivered messages exist only in relay RAM and are wiped
  on delivery or restart. Delivered messages exist only on the devices.
- **Passive network surveillance of content.** Contents are end‑to‑end
  encrypted regardless of transport; `wss://` hides the routing metadata from
  the network as well.
- **Message tampering, replay and sender forgery.** Every message is
  authenticated (AEAD with the ratchet header as associated data); the relay
  no longer attributes a sender, so authenticity rests entirely on the inner
  layer — a forged sender simply fails decryption and is dropped.
- **Machine‑in‑the‑middle key substitution.** Each pair can compare a
  60‑digit **safety number** derived from the two *account* keys; it is stable
  across device changes. Device pairing shows a 6‑digit SAS on both screens
  for the same reason.
- **Forward secrecy and post‑compromise security** (Double Ratchet) —
  classical. **Post‑quantum confidentiality** of everything after the first
  round trip (ML‑KEM‑768 mixed into message keys), and post‑quantum
  post‑compromise security through periodic re‑keying (`PROTOCOL.md` §17.7).
- **Downgrade of the post‑quantum layer.** There is no unauthenticated
  capability flag; the offer is inside the ratchet and the ciphertext is in
  the authenticated header, so an active attacker can only cause a decryption
  failure, never a silent fallback.
- **Silent device enrolment, split views and silent removal** (someone
  holding your account root signs a device list you did not). No key server
  exists to trust, so Z makes these *detectable* instead: every message
  carries the sender's claim about its own device list and an echo of the
  recipient's; contacts and your own devices cross‑check them; a removed
  device is told by the contacts that stopped delivering to it; a root that
  regresses its list is itself a signal (`PROTOCOL.md` §3.6, `adr/0001`).
  Sends are never blocked — the user is shown what disagrees.
- **Plaintext on disk.** The vault is encrypted per cell; attachments are
  encrypted blobs; voice notes are captured into memory and never written
  unencrypted; search decrypts in memory only; history sync to a new device
  travels only over the self‑sync ratchet.

## What Z does **not** protect against (be honest with yourself)

- **Metadata against the relay operator.** The relay learns *which mailboxes
  receive* traffic, when, and in which of six padded size buckets. Sealed
  sender removes the *sender* from that view, and per‑device sealing means
  the relay cannot group a person's devices — but it can still observe that a
  mailbox is active and correlate timing across mailboxes. If you need
  metadata privacy against the operator, run the relay yourself and/or put it
  behind Tor.
- **A compromised endpoint.** Malware, spyware, or a physically unlocked
  device gives an attacker everything Z can decrypt — no E2E scheme prevents
  this. Z encrypts the local vault, but once your OS user (and passphrase)
  is unlocked the app can read it.
- **A stolen account root, in the window before detection.** Whoever holds
  your identity backup and its passphrase *is* you to the protocol. Device‑list
  transparency makes a rogue enrolment visible to you and your contacts
  within a message or two of it being used — it does not prevent it, and an
  attacker who also keeps your honest devices offline delays the alarm until
  they are back. The remedy is to reset your identity. Do not store the
  backup where the device itself is stored.
- **A malicious contact.** Anyone you message can screenshot, copy, or leak
  what you send. Disappearing messages are a courtesy against accidental
  retention, not an anti‑exfiltration control.
- **A malicious group admin** can add anyone to a group, and every member
  sees the member list; leaving is honoured by honest clients only.
- **Unverified first contact.** If an attacker intercepts the *initial*
  contact‑code exchange and swaps in their own keys, they can machine‑in‑the‑
  middle you until you compare safety numbers. Exchange codes over a channel
  you trust and verify the safety number for anything sensitive. No
  transparency mechanism fixes an exchange the attacker fully controls.
- **Traffic analysis / global passive adversary.** Z is not an anonymity
  network. Timing and volume correlations are possible for someone who can
  watch both ends.
- **Denial of service.** A hostile relay can refuse to deliver, or drop
  queued messages. It cannot read them, but availability depends on the relay
  you choose. A relay (or anyone) can also inject garbage that costs a
  recipient a failed decryption — sealed sender is deliberately
  unauthenticated at the outer layer.
- **Endpoint backups you make elsewhere.** A plaintext device backup to some
  cloud is outside Z's control.
- **Lost keys = lost identity.** There is no server account to recover.
  Losing every device without a `.zid` backup means a new identity and
  re‑verifying contacts. That is the cost of having no server custody.
- **The quantum layer's edges.** The session‑opening `hello`, the key offer
  itself and anything sent before the offer is answered are classical; the
  initial handshake secret stays classical (the mix is applied to message
  keys precisely so that this does not matter after the first round trip).
  ML‑KEM in pure Dart is best‑effort constant‑time; a timing leak there can at
  worst reduce security to v1, never below it.

## Residual risk register

The section above says what Z does not protect against. This says what is
*left over after everything currently built* — including the risks the recent
phases introduced or uncovered, which would otherwise be scattered across five
ADRs and findable only by someone who read all of them.

Two things this register is for. An auditor should be able to start here rather
than reconstruct it. And a claim like "post‑quantum secure" or "signed
releases" should be checkable against a specific line saying what that does and
does not cover — because the dangerous failure is not an unmitigated risk, it
is an unmitigated risk hidden behind a phrase that sounds like it was handled.

**Exposed to** is who actually gets the information or capability.
**Status** is one of: *accepted* (a deliberate trade), *deferred* (a plan
exists, gated on something), *open* (should be closed and is not yet).

| # | Residual risk | Exposed to | Why it remains | What reduces it | Status |
|---|---|---|---|---|---|
| R1 | Which mailbox receives traffic, when, and in which of six size buckets | Relay operator | Delivering a message requires knowing where to deliver it. Sealed sender removes the *sender*; the recipient cannot be removed without a mixnet | Self‑host (`SELF_HOSTING.md`), or front the relay with Tor | accepted |
| R2 | An occasional ~16 KB envelope marks an account as running a v3 client | Relay operator | A 3.3 KB post‑quantum signature does not fit the 1 024‑byte bucket ordinary chat shares, and no arrangement makes it fit (`adr/0004`) | Its *timing* is decorrelated from any device‑set change, and its size is constant regardless of device count, so it reveals nothing beyond "v3" | accepted |
| R3 | The post‑quantum device‑list signature can be dropped, leaving a list verified classically for ever | On‑path attacker | Not preventable at the network layer: it is the one large envelope in a conversation and therefore the easy one to drop | Detected and surfaced (§18.9) — the sender states inside the ratchet that it sent one, and a claim with nothing behind it is asked about and then reported | accepted |
| R4 | A contact code (QR) is authenticated classically end to end | A future quantum adversary present at the exchange | A hybrid identity is ~9× too large to scan (`adr/0003`). The commitment binds the post‑quantum key to the scan; it does not make the scan itself post‑quantum | Exchange codes in person; the commitment means the *in‑band* key cannot be substituted afterwards | accepted |
| R5 | The session‑opening `hello`, the key offer, and anything before the offer is answered are classical | A future quantum adversary recording now | The first round trip has no shared post‑quantum secret yet, by construction | The mix applies to message keys, so everything after the first round trip is covered; the exposure is bounded to the opening exchange | accepted |
| R6 | Whoever holds an identity backup and its passphrase *is* the account until noticed | Anyone with both | There is no server custody to appeal to — that is the product | Device‑list transparency (7.7a) makes a rogue enrolment visible within a message or two of use; the remedy is an identity reset | accepted |
| R7 | No key transparency: a first contact exchange the attacker fully controls cannot be detected later | An attacker controlling the initial exchange | `adr/0001` defers it: a transparency log is a separate service (Merkle log, HSM, mirrors, an independent witness) and real operational cost | Safety numbers, which catch it the moment two people compare | **deferred** — gated on the trigger in `adr/0001` |
| R8 | A desktop user can be served an older release, with valid provenance | Whoever serves the download | There is no in‑app updater, deliberately — an updater is a code‑execution channel into every install | Play refuses an older `versionCode` on Android. On desktop, the release page and the attestation both name the version, but only if the user looks | **open** — see `PROVENANCE.md` |
| R9 | Build provenance is SLSA **L2**, not L3: a compromised build step could forge provenance about itself | Anyone who can inject into the build | L3 needs the build isolated from the signing material, which is a restructure rather than a setting | Provenance is signed by the hosted build service and publicly logged, so a forged one is at least visible | **open** |
| R10 | Reproducibility is proven on one machine, not across machines | — | *Settled on 2026‑09‑09, and the answer was no.* The first run failed | **Superseded by R16**, which records what was actually measured. Kept here rather than deleted: this row said the first CI run would settle it, and a register that quietly removes a row once its answer turns out to be unwelcome is not a register | superseded |
| R11 | Google holds the Play app‑signing key and can sign an APK as Z | Google, or anyone who compels Google | Play App Signing is a condition of distributing through Play | Reproducible builds plus provenance let anyone compare what Play serves against what the source produces — the substitution is detectable, not preventable | accepted |
| R12 | A push notification tells Google (FCM) that *some* device should wake | Google | Waking a sleeping device requires the platform's push service | Notifications are **contentless** — no text, no sender; the device then fetches from the mailbox as usual, and tokens live in relay RAM and expire | accepted |
| R13 | A malicious contact can retain, screenshot or leak anything sent to them | Your contact | Nothing cryptographic can prevent it | Disappearing messages are a courtesy against accidental retention, and are described as exactly that | accepted |
| R14 | A hostile relay can refuse to deliver, or drop queued ciphertext | Relay operator | Availability depends on the relay you choose | Self‑host; the relay cannot read what it drops | accepted |
| R15 | Timing and volume correlation by someone watching both ends | A global passive adversary | Z is not an anonymity network and does not claim to be | Tor for the transport, if that is your threat model | accepted |
| R16 | **The APK is not reproducible across machines.** Two CI runners building the same commit produced APKs differing in all six `libapp.so`/`libdartjni.so` entries; every other entry matched | Anyone who wants to check the shipped binary against the source themselves — which is the whole point of publishing it | Measured on 2026-09-09 and not yet explained. The failing job varied the runner *and* the checkout path at once, so it cannot say which mattered; `libapp.so` is known to embed its absolute build directory, but the two APKs were exactly the same size, which that alone would not produce | Same‑machine, same‑path reproducibility does hold (14.1) and still catches a tampered build server. A three‑way CI experiment now separates machine from path, and each build publishes per‑library hashes and ELF build ids | **open** — and the most useful thing an external reviewer could hand back |

### What is NOT on this list, and why

* **Anything phase 13 closed.** A linked device inventing its own post‑quantum
  identity, a contact code naming a laptop rather than a person, a device list
  a quantum adversary could forge by exclusion — all fixed, all tested, none
  residual. They are in `ROADMAP_8_15.md`'s revision list rather than here.
* **A compromised endpoint.** Not a residual risk so much as the boundary of
  the whole exercise: an attacker who has your unlocked device has whatever you
  can see.

## Design decisions that follow from "zero trust"

- **No accounts, no phone numbers, no directory, no key server.** Nothing to
  correlate you to a real identity server‑side; nothing whose honesty you
  must assume. Your address is a hash of a key; your device set is a
  statement your own account key signs, and its consistency is checked by the
  people who receive it rather than vouched for by a server.
- **RAM‑only relay.** The reference relay never writes message data to disk
  and can run on a read‑only filesystem. A restart is a clean slate.
- **Sealed sender by default.** Every envelope is sealed to the recipient
  device; the relay matches acknowledgements by envelope id alone and emits
  no delivery receipts — delivery and read receipts are themselves
  end‑to‑end encrypted messages.
- **Authenticated queue draining.** Only the holder of a device's private
  key can receive that mailbox's queued messages (Ed25519
  challenge/response).
- **Pairwise groups.** No shared group key: each group message is encrypted
  separately to each member over the existing authenticated session, so
  removing a member needs no rekey and a member who was never sent a message
  cannot have it.
- **Per‑device sessions, one trust root.** Each of a contact's devices gets
  its own ratchet; the account key is the only thing you verify by hand.
- **Contentless push.** A push notification carries no content and no
  sender — only "you have mail"; the device then connects and drains its
  mailbox as usual. Push tokens live in relay RAM and expire.
- **Local encryption at rest.** The on‑device store is encrypted with
  XChaCha20‑Poly1305 under a key held in the OS keystore (Android Keystore,
  macOS/iOS Keychain, Windows credential store, Linux Secret Service),
  optionally wrapped by an app passphrase. If no keystore is available the
  app falls back to a permission‑restricted key file and warns you.
- **App lock (biometrics / device PIN).** Two optional features, both
  driven by the OS prompt (fingerprint, face, or the device credential as
  fallback):
  - *Screen lock* asks for the prompt when Z opens and again after a chosen
    time in the background. It is a **UI gate**, like the phone's own lock
    screen: the vault stays open underneath so messages keep arriving, and
    it does not change what is stored or how it is encrypted. Someone who
    can read the app's storage is not stopped by it.
  - *Unlock with biometrics* (only when an app passphrase is set) lets the
    prompt open the vault instead of typing the passphrase. To do that, Z
    keeps the Argon2id output for the current passphrase — never the
    passphrase — on the device, and deletes it when the feature is turned
    off or the passphrase is removed. How well that key is protected
    depends on the platform:
    - **Android (hardware‑bound).** The key is sealed under an Android
      Keystore key created with "user authentication required, for every
      use": the keystore itself will not run the decryption unless the user
      has just passed the system prompt, and the prompt is tied to that
      exact operation (`BiometricPrompt` + `CryptoObject`). Copying the
      app's data, or asking the keystore from inside the process, yields
      nothing; re‑enrolling a fingerprint or face permanently invalidates
      the key, and the app falls back to the passphrase. On Android 11+
      the device PIN is accepted as fallback; on 7–10 the key is
      biometric‑only. What remains is an attacker who controls the
      unlocked, running device (a compromised endpoint — see above).
    - **macOS / Windows (software‑gated).** The key is an ordinary keystore
      entry that Z reads only after its own prompt. **The trade‑off:**
      while it is on, the device secret and that key together unwrap the
      vault key, so on *that* machine an attacker who can extract keystore
      entries (an admin, a forensic image of an unlocked machine) no longer
      needs the passphrase. The passphrase becomes a UI gate there; it
      still protects the vault against anyone who does not have the
      keystore. Leave it off on those platforms if the passphrase is your
      defence against exactly that attacker. Binding the entry to the
      Keychain's / Windows Hello's own user‑presence check is planned once
      those builds can be verified.
    The settings screen says which of the two applies on the device in
    front of you.

## Recommendations for high‑risk users

1. Use `wss://` (TLS) always, and prefer a relay **you** control.
2. Verify the safety number in person or over a separately trusted channel,
   and compare the pairing SAS aloud when linking a device.
3. Keep the identity backup somewhere the device thief will not also find;
   treat a device‑list alert as an instruction to reset your identity unless
   you can explain it.
4. Enable disappearing messages for sensitive threads.
5. Keep your OS and device encryption on; use a strong device passcode and
   the app passphrase. Turn on the screen lock; on macOS / Windows leave
   "unlock with biometrics" off if you rely on the passphrase against
   someone who can image the machine (on Android it is hardware‑bound).
6. Understand that metadata (which mailbox, when, how much) is the residual
   risk — treat the relay operator accordingly.

## Cryptography caveat

Z composes well‑studied primitives (Ed25519, X25519, HKDF‑SHA256,
HMAC‑SHA256, XChaCha20‑Poly1305, ChaCha20‑Poly1305, ML‑KEM‑768) into a
Signal‑style Double Ratchet with a post‑quantum hybrid, implemented in Dart
on top of the `cryptography` and `pqcrypto` packages. The wire format is
frozen and specified (`PROTOCOL.md`), with test vectors reproduced by three
independent verifiers. It has **not yet** received an independent third‑party
security audit — see `AUDIT_SCOPE.md` for what one would cover. Do not bet
lives on unaudited software.
