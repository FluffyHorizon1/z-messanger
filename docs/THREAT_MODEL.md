# Z — Threat Model

This document is deliberately honest about what Z protects, what it does not,
and why. "Zero trust" here means **you do not have to trust the server** to
keep your message contents private. It does *not* mean magic. Read this before
relying on Z for anything that matters.

## What Z is

A serverless‑by‑design, end‑to‑end encrypted 1:1 messenger. Messages are
encrypted on your device and only ever decrypted on your contact's device.
The server ("relay") is a dumb pipe that shuttles opaque ciphertext between
devices and holds undelivered ciphertext in RAM only until it is delivered.

## Cryptographic design in one paragraph

Each identity is an Ed25519 signing key plus an X25519 Diffie‑Hellman key,
generated on device. Contacts exchange public keys out‑of‑band as a signed
"contact code" (QR or text). A session is established with an X3DH‑style
handshake and then protected by the **Double Ratchet** (the same core
construction used by Signal): every message uses a fresh single‑use key,
giving **forward secrecy** (stealing today's keys does not decrypt yesterday's
messages) and **post‑compromise security** (a compromise heals after the next
round trip). Message contents are sealed with **XChaCha20‑Poly1305** AEAD.
Attachments are encrypted with a per‑file key that is itself delivered inside
the ratchet.

## Trust boundaries

| Party | What they can do | What they **cannot** do |
|-------|------------------|--------------------------|
| The relay server | See that *some routing‑ID* sent an opaque blob of size N to *another routing‑ID* at time T; hold that blob in RAM until delivery | Read message text, file names, or file contents; impersonate you; forge messages; recover anything after a restart |
| A network eavesdropper (with TLS) | See that you connected to a relay | Read anything (TLS + E2E) |
| A network eavesdropper (without TLS) | See routing IDs and ciphertext sizes/timing | Read message contents (still E2E encrypted) |
| Someone who steals your locked, powered‑off device | Hold encrypted bytes | Read messages without your OS user/keystore credentials |
| Your contact | Read what you send them; screenshot it; keep it forever | Prove to a third party that *you specifically* wrote it (messages are repudiable) |

## What Z protects against

- **A malicious or compromised server.** The server never has keys or
  plaintext. It cannot read, alter, or forge messages. This is the core
  guarantee and it holds even if the operator is hostile or hacked.
- **Server‑side data breaches / subpoenas of stored messages.** There is
  nothing at rest to seize. Undelivered messages exist only in server RAM and
  are wiped on delivery or restart. Delivered messages exist only on the two
  devices.
- **Passive network surveillance of content.** Contents are end‑to‑end
  encrypted regardless of transport. With `wss://` (TLS), even routing
  metadata is hidden from the network.
- **Message tampering & replay.** Every message is authenticated (AEAD +
  ratchet). Modified ciphertext, replayed envelopes, and forged senders are
  rejected. The relay stamps the authenticated sender, so a sender cannot be
  spoofed.
- **Machine‑in‑the‑middle key substitution.** Each pair can compare a 60‑digit
  **safety number**. If it matches, no one substituted keys.
- **Forward secrecy / post‑compromise.** Provided by the Double Ratchet.

## What Z does **not** protect against (be honest with yourself)

- **Metadata against the relay operator.** The relay learns routing IDs
  (hashes of public keys — stable pseudonyms), message sizes, and timing.
  It does not learn names, phone numbers, or content, but it *can* observe
  that two pseudonymous IDs talk, how much, and when. Padding blunts exact
  sizes; it does not hide the social graph. If you need metadata privacy
  against the operator, run the relay yourself and/or place it behind Tor.
- **A compromised endpoint.** If malware, spyware, or a physically unlocked
  device gives an attacker access while Z is unlocked, they can read your
  messages — no E2E scheme can prevent this. Z encrypts the local database,
  but once your OS user is unlocked the app can read it.
- **A malicious contact.** Anyone you message can screenshot, copy, or leak
  what you send. Disappearing messages are a courtesy against accidental
  retention, not an anti‑exfiltration control.
- **Unverified first contact.** If an attacker intercepts the *initial*
  contact‑code exchange and swaps in their own keys, they can machine‑in‑the‑
  middle you until you compare safety numbers. Exchange codes over a channel
  you trust and verify the safety number for anything sensitive.
- **Traffic analysis / global passive adversary.** Z is not an anonymity
  network. Timing and volume correlations are possible for someone who can
  watch both ends.
- **Denial of service.** A hostile relay can simply refuse to deliver, or
  drop queued messages. It cannot read them, but availability depends on the
  relay you choose.
- **Endpoint backups you make elsewhere.** If you back the device up in
  plaintext to some cloud, that is outside Z's control.
- **Lost keys = lost identity.** There is no server account to recover. Losing
  your device without a `.zid` backup means a new identity and re‑verifying
  contacts. That is the cost of having no server custody.

## Design decisions that follow from "zero trust"

- **No accounts, no phone numbers, no directory.** Nothing to correlate you to
  a real identity server‑side. Your address is a hash of a key.
- **RAM‑only relay.** The reference relay never writes message data to disk and
  is designed to run with a read‑only filesystem. A restart is a clean slate.
- **Authenticated queue draining.** Only the holder of an identity's private
  key can receive that identity's queued messages (Ed25519 challenge/response).
- **Local encryption at rest.** The on‑device store is encrypted with
  XChaCha20‑Poly1305 under a key held in the OS keystore (Android Keystore,
  macOS/iOS Keychain, Windows credential store, Linux Secret Service). If no
  keystore is available the app falls back to a permission‑restricted key file
  and warns you.

## Recommendations for high‑risk users

1. Use `wss://` (TLS) always, and prefer a relay **you** control.
2. Verify the safety number in person or over a separately trusted channel.
3. Enable disappearing messages for sensitive threads.
4. Keep your OS and device encryption on; use a strong device passcode.
5. Understand that metadata (who/when/how‑much) is the residual risk — treat
   the relay operator accordingly.

## Cryptography caveat

Z composes well‑studied primitives (Ed25519, X25519, HKDF‑SHA256, HMAC‑SHA256,
XChaCha20‑Poly1305) into a Signal‑style Double Ratchet, implemented in Dart on
top of the `cryptography` package. It has **not** received an independent
third‑party security audit. The protocol and code are open for review (see
`PROTOCOL.md`). Do not bet lives on unaudited software.
