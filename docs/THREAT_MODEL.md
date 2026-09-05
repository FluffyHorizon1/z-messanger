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

## Recommendations for high‑risk users

1. Use `wss://` (TLS) always, and prefer a relay **you** control.
2. Verify the safety number in person or over a separately trusted channel,
   and compare the pairing SAS aloud when linking a device.
3. Keep the identity backup somewhere the device thief will not also find;
   treat a device‑list alert as an instruction to reset your identity unless
   you can explain it.
4. Enable disappearing messages for sensitive threads.
5. Keep your OS and device encryption on; use a strong device passcode and
   the app passphrase.
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
