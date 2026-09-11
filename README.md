# Z

**An end‑to‑end encrypted messenger with no accounts, no phone numbers and
no server that could read anything.** Messages exist only on the devices that
exchanged them. The relay in between passes opaque ciphertext and holds
undelivered messages in memory alone — it has no database, keeps no logs of
content, and cannot read, alter or forge a message. Your address is a hash
of a key you generate; nobody is registered anywhere.

<p align="center">
  <a href="https://play.google.com/store/apps/details?id=com.zmessenger.www"><img alt="Get it on Google Play" src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" height="72"></a>
</p>

**Android:** [Z on Google Play](https://play.google.com/store/apps/details?id=com.zmessenger.www).
**Windows, Linux, macOS:** the [latest release](https://github.com/FluffyHorizon1/z-messanger/releases/latest)
carries a build for each, with a `SHA256SUMS.txt` you can check against
[`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md).

![Two Z clients holding an encrypted conversation](docs/screenshot_conversation.png)

## What makes it different

- **Nothing to trust on the server.** The relay sees routing hashes and
  ciphertext in one of a few padded sizes. Sealed sender hides who sent
  each message even from the relay. There is no directory, no key server,
  no metadata store — and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
  says exactly what the relay *can* still observe.
- **Signal‑style cryptography, post‑quantum on top.** X3DH‑style handshake,
  the Double Ratchet (X25519, HKDF, HMAC) with XChaCha20‑Poly1305, and a
  hybrid ML‑KEM‑768 layer with periodic re‑keying so recorded traffic stays
  closed to a future quantum computer. Identities carry an ML‑DSA‑65 half.
- **Device lists you can check.** Linked devices are signed by your account
  key, your contacts cross‑check every list they are handed inside the
  encrypted channel, and the app checks each list against a public
  transparency log when one is configured — so a device quietly added to an
  account shows up on the screens of the people it talks to, and cannot stay
  hidden by being shown to only some of them.
- **Everything on the device is encrypted.** An on‑device vault with every
  sensitive cell sealed under a key in the OS keystore, an optional
  passphrase (Argon2id), biometric app lock, and encrypted backups you can
  restore onto a wiped phone with a recovery code.
- **The ordinary things, done carefully.** Groups, linked devices, voice
  messages, encrypted attachments, replies, reactions, edits,
  delete‑for‑everyone, disappearing messages, search — each specified and
  tested, several with a written argument for why they are safe.
- **Verifiable.** A frozen protocol specification with machine‑checked test
  vectors, independent verifiers in CI that share no code with the
  reference implementation, reproducible Android builds, and a security
  policy with safe harbour.

## How it works, briefly

1. Your device generates its identity. Nothing is registered anywhere.
2. You and a contact exchange signed contact codes out of band — a QR code
   or a pasted string.
3. A handshake derives a shared secret and the ratchet takes over: every
   message has its own key, and a compromised key today does not open
   yesterday's messages or tomorrow's.
4. Ciphertext goes to the relay addressed to a routing id. The relay holds it
   in memory until the recipient's device confirms it has it, then drops it.
5. Both devices keep their copy in an encrypted local vault.

The long version is [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md); the
normative one is [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Documentation

| Read this | If you want to know |
|---|---|
| [`docs/USING_Z.md`](docs/USING_Z.md) | how to use it: adding people, safety numbers, linked devices, groups, and what to do when something looks wrong |
| [`docs/WHAT_Z_CANNOT_DO.md`](docs/WHAT_Z_CANNOT_DO.md) | the limits, stated as plainly as the promises — read it before relying on Z for a particular risk |
| [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md) | the design and the security argument: each claim, the mechanism, the alternative not taken, and how to check it |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | who can learn what, and the residual‑risk register |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) · [`docs/vectors/`](docs/vectors/) | the wire format, frozen and pinned by test vectors |
| [`docs/adr/`](docs/adr/) | the decisions that shaped the security model, with their reasoning |
| [`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) | running your own relay, and your own transparency log |
| [`docs/BUILD.md`](docs/BUILD.md) · [`docs/WINDOWS.md`](docs/WINDOWS.md) | building from source |
| [`docs/REPRODUCIBLE_BUILDS.md`](docs/REPRODUCIBLE_BUILDS.md) · [`docs/PROVENANCE.md`](docs/PROVENANCE.md) | checking that a release is what the source says |
| [`docs/GA_CHECKLIST.md`](docs/GA_CHECKLIST.md) | what 1.0 requires and where each condition stands |
| [`SECURITY.md`](SECURITY.md) · [`docs/VDP.md`](docs/VDP.md) | reporting a vulnerability, and the safe harbour for looking |

## Repository layout

```
protocol/   The cryptographic core, pure Dart: identities, handshake, Double
            Ratchet, post-quantum hybrid, sealed sender, multi-device, groups,
            attachments — and the test suite, including an end-to-end
            conversation through the real relay.
server/     The relay: a zero-knowledge, RAM-only WebSocket server (Node.js),
            with a read-only-filesystem Dockerfile.
kt/         The key transparency log: an append-only Merkle log with signed
            heads, a mirror and witness tool, and the vectors generator.
app/        The Flutter application: Android, Windows, Linux, macOS.
docs/       Specification, threat model, whitepaper, guides, decision records.
tool/       Checks that keep the documents honest about the code; they run in CI.
```

## Building and testing

```bash
cd server && npm install && npm test      # the relay
cd protocol && dart pub get && dart test  # the protocol, incl. a real conversation through the relay
cd kt && npm test                         # the transparency log
cd app && flutter pub get && flutter test # the app
```

`flutter run -d linux` (or `windows`, `macos`, or an attached Android device)
starts the app from source; on first launch it asks for a display name and a
relay address. [`docs/BUILD.md`](docs/BUILD.md) has the toolchain versions
CI uses.

## Running your own relay

The app ships pointed at `wss://zmessengers.com`, and you can point it
anywhere. A relay is a single Node process that needs no storage, so it runs
on the smallest instance a host offers — plain Docker, a one‑command VPS
install with automatic TLS, or a free cloud tier.
[`docs/SELF_HOSTING.md`](docs/SELF_HOSTING.md) covers each, along with
running several relays behind a load balancer and running the transparency
log.

## Status

Z is a complete, working implementation built from well‑studied primitives,
with its specification, threat model and test vectors published for review.
It has **not yet had an independent security audit**;
[`docs/GA_CHECKLIST.md`](docs/GA_CHECKLIST.md) lists that and the other
conditions for calling it 1.0, with the honest status of each. Z is not
affiliated with Signal.

## License

Proprietary, source‑available — see [`LICENSE`](LICENSE). You may read,
audit, and self‑host for personal use; commercial use and redistribution
need written permission.
