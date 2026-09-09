# Z — design and security argument

**A messenger where the operator is not part of the trust model.**

`PROTOCOL.md` is the normative wire format: twelve thousand words of byte
layouts and MUSTs, with test vectors. This is the other document — the one for
someone deciding whether Z is worth trusting or worth auditing, who reasonably
will not read the wire format first.

It is organised around **claims**. Each says what is asserted, the mechanism,
why that mechanism and not the obvious alternative, **how you can check it**,
and what it does not cover. The last two matter most: a security claim you
cannot check is a request for faith, and a claim without a stated boundary will
be read as covering more than it does.

---

## 1. The shape of the thing

Three parts. A Flutter app for Android, Linux, Windows and macOS. A pure-Dart
protocol library, `z_protocol`, which holds every cryptographic decision. And a
relay: a small Node service that shuttles opaque ciphertext between mailboxes
and holds undelivered bytes **in RAM only**.

The relay is deliberately stupid. It has no database, no accounts, no user
table, and nothing to seize. It knows that a blob of one of six padded sizes
arrived for a routing id — a hash — at a time, and it forgets on restart.

There is no server-side account, so there is nothing to log into, nothing to
recover, and no password anywhere. An identity is a keypair on your device.
That is a real cost: lose every device without a backup and the identity is
gone. It is stated here rather than buried because it is the direct consequence
of the property the whole design exists for.

## 2. Claim: the operator cannot read messages

**Mechanism.** Devices establish a session with an X3DH-style handshake and
then run the Double Ratchet. Every message uses a fresh single-use key, giving
forward secrecy and post-compromise security on each round trip. Contents are
sealed with XChaCha20-Poly1305.

**Why this and not something simpler.** The obvious alternative is static
end-to-end encryption — one long-term key per pair. It is much easier and it
fails in the way that matters: a key compromised once decrypts everything ever
sent, past and future. The ratchet's forward secrecy bounds what a compromise
costs backwards, and its post-compromise security bounds it forwards. Given the
threat model includes device seizure, neither property is optional.

**Why no server prekeys.** X3DH normally uses prekeys the server hands out.
That makes the server a participant in key agreement, which is precisely the
role this design refuses to give it. Instead the peer's long-term X25519 key
stands in. The trade is real and worth naming: without one-time prekeys, the
very first message to a peer who has never been online has slightly weaker
forward secrecy than a full X3DH would give. Every subsequent message is
identical. Making the relay hold prekeys would buy that one message at the cost
of the relay mattering.

**How to check it.** `PROTOCOL.md` §4–5, with vectors in `docs/vectors/v1`
replayed by three independent implementations (§7 below).

**Not covered.** A compromised endpoint. If an attacker has your unlocked
device they have what you can see, and no messaging protocol changes that.

## 3. Claim: the operator cannot tell who is talking to whom

**Mechanism.** Sealed sender. Every envelope is sealed to the recipient device,
so the sender's identity is inside the ciphertext rather than in the routing
metadata. Each of an account's devices has its own routing id, so the relay
cannot group a person's devices either. Envelopes are padded into six size
buckets.

**Why buckets and not exact padding.** Padding every envelope to a single large
size would be cleaner and would cost far more bandwidth than a messenger can
spend. Six buckets is a compromise, and the compromise has a measurable edge —
see §6.

**How to check it.** The relay's source is small and readable; `/health`
reports `storage: 'ram-only'` and the only `fs` use in `server.js` reads TLS
material. `docs/DATA_MAP.md` inventories exactly what the relay holds.

**Not covered.** *Which mailbox receives traffic, when, and in which bucket.*
Delivering a message requires knowing where to deliver it. Sealed sender
removes the sender; the recipient cannot be removed without a mixnet, which is
a different product. If that is your threat model, self-host the relay or front
it with Tor. This is R1 in the residual-risk register and it is the most
important limitation in this document.

## 4. Claim: recording today does not pay off tomorrow

**Mechanism.** Since protocol v2, an ML-KEM-768 (FIPS 203) shared secret is
established *inside* the ratchet and mixed into every message key, and rotated
periodically. An adversary who records ciphertext now and breaks X25519 later
still faces ML-KEM.

**Why inside the ratchet, not in the handshake.** Putting the post-quantum
exchange in the handshake would mean a large, distinctive first packet and a
flag day. Mixing into message keys means the *initial* handshake secret stays
classical — which sounds worse and is not, because the mix applies from the
first round trip onwards, so the exposure is bounded to the opening exchange
rather than to the conversation.

**Why rotation.** A single post-quantum secret established once would mean a
stolen device state kept the quantum-safe secret for ever. Rotation bounds it.

**How to check it.** `PROTOCOL.md` §17, with vectors reproduced by `kyber-py` —
a third-party implementation that shares no code with this project.

**Not covered.** The opening `hello`, the key offer itself, and anything sent
before the offer is answered (R5). ML-KEM in pure Dart is best-effort
constant-time; a timing leak there reduces security to v1, never below it.

## 5. Claim: an identity cannot be forged, now or later

This is the part that took the longest and the part where the design changed
most under measurement.

**The problem.** v2 protects *confidentiality* against a future quantum
adversary. It does nothing for *authentication*: account keys, device keys and
certificates were all Ed25519. A quantum adversary could not read old traffic —
but could mint a device that appears to belong to your account, and read
everything from then on. That is the one attack available without touching a
single recorded ciphertext.

**Mechanism.** Hybrid signatures: Ed25519 **and** ML-DSA-65 (FIPS 204), both
required, verification failing if either half fails. A stripped half does not
parse, so a downgrade is not expressible.

**The obstacle, and what it forced.** A hybrid identity does not fit in a QR
code — measured at roughly nine times what scans reliably. Scanning a code is
the core onboarding flow, so the design had to change rather than the flow.
`adr/0003` settles it: **the QR carries a 32-byte commitment to the
post-quantum key, not the key.** The key travels in-band and is refused unless
it matches. Security is equivalent to putting the whole key in the code,
because substituting it requires a SHA-256 collision.

Three corrections came out of implementing that, each recorded because each was
a case of a design reading as settled when it was not:

* **A new `zc3.` prefix was the wrong vehicle.** A new optional JSON member is
  compatible evolution; a new prefix is a flag day that every build in the
  field rejects. The commitment rides in a `zc1.` code, and the compatibility
  window collapsed from three releases to none.
* **A contact code named the *device* showing it**, which was invisible while
  every account had one device and wrong the moment one did not: scanning
  someone's laptop added the laptop. A code may now name its account and carry
  that account's certificate for the device — and the check that carries the
  security is that the certificate must be *for* the keys in that same code,
  because certificates are public and travel in device lists.
* **Per-certificate post-quantum signatures do not authenticate the set.**
  Given a genuine hybrid device list, an adversary who can forge Ed25519 but
  not ML-DSA presents a *subset*: the list signature forged, every remaining
  certificate's post-quantum half genuine and copied. Every check passes and an
  honest device has been excluded. So the account signs the **list** — version
  and sorted device keys — which covers membership and version, and is one
  constant-size artefact whatever the device count (`adr/0004`).

**How to check it.** `PROTOCOL.md` §18, vectors in `docs/vectors/v3` reproduced
by `dilithium-py` and by a clean-room Node implementation, both of which rebuild
the device-list signing input from the list itself rather than trusting the
recorded bytes, and both of which confirm that an excluded device and a
rolled-back version fail.

**Not covered.** The QR itself is authenticated classically end to end (R4) —
the commitment binds the in-band key to the scan; it does not make the scan
post-quantum. And the post-quantum device-list signature can be *dropped* by an
on-path attacker, leaving a list verified classically (R3). That is not
preventable at the network layer; it is detected and surfaced instead.

## 6. Claim: verification means something, and a changed number is explained

**Mechanism.** A safety number derived from both parties' **account** keys —
never device keys, so it does not move when someone links a laptop. Under v3 it
covers both halves of both identities.

**Why the anchor matters.** Anchored to a device key, the number changes every
time a device is added, which makes a real key substitution indistinguishable
from someone opening the desktop app. A verification signal that fires on
ordinary use is one people learn to ignore, and then it is worth nothing when
it fires for real. That principle drove several decisions here, and it is worth
stating as a design rule: **an alarm that fires on ordinary use is not a
safety feature.**

**The one-time change, handled deliberately.** Moving to v3 changes every
existing user's safety number exactly once. An unexplained change looks exactly
like an attack — so the app records *which* number the user compared, not just
that they compared one, and can therefore say "this changed because their
identity gained a post-quantum key, which happens once" rather than silently
showing a different number. It claims "upgraded" only when the previously
compared number is demonstrably the v1 number for that pair; anything else is
reported as unexplained, because the reassuring account is the one an attacker
benefits from.

**The same rule, applied to suppression.** A dropped device-list signature
leaves a list classically verified for ever. Detecting that naively — "hybrid
identity but classical list" — would fire for every contact running an older
build, which is how an alarm stops being read. So a sender states, inside the
ratchet where whoever dropped the envelope cannot strip it, that it *sent* one;
only a claim with nothing behind it is a problem, and even then it is asked
about before anyone is told.

**How to check it.** `app/test/verification_ux_test.dart` asserts the words on
the screen, not just the state behind them.

## 7. Claim: the specification is implementable, and the implementation matches it

This is the claim that makes the others checkable, and it is the one most
projects skip.

Every construction has **test vectors**, and the vectors are replayed by
implementations that share no code:

| verifier | independence |
|---|---|
| Dart freeze test | the library itself — catches drift |
| Node clean-room (`server/test/vectors.test.js`) | every primitive re-implemented from `PROTOCOL.md` on Node's `crypto` alone |
| `kyber-py` | third-party ML-KEM |
| `dilithium-py` | third-party ML-DSA |

If the spec and a clean-room implementation agree on every vector, the document
is implementable from the document alone — which is what makes "read the spec"
a real answer rather than a deflection.

`docs/AUDIT_SCOPE.md` lists every claim with where it is specified and where it
is tested. It is the efficient starting point for anyone trying to break one.

## 8. Claim: the binary matches the source

**Mechanism.** Two release builds of the same commit, on one machine at one
path, are byte-for-byte identical, signature included. Release artefacts carry
SLSA build provenance, signed keyless through Sigstore and recorded in a public
transparency log.

Read that first sentence's qualifiers as load-bearing. **Across two machines
the builds are not identical**, which CI established on 2026-09-09, and the
cause is not yet known — see the last paragraph of this section. This is the
weakest claim in the document.

**Why the log matters more than the signature.** A signature you can check is
also one that can be issued quietly to a single person. An append-only public
log means the answer given to you is the answer given to everyone.

**What was found getting there.** The Dart and Android toolchains were already
deterministic. The only nondeterministic bytes in the APK were an Android
Gradle Plugin blob describing the app's dependency tree, encrypted to a Google
public key, with fresh randomness per build — which had no business in a
messenger claiming no third party learns anything, quite apart from blocking
reproducibility. Removing it made the builds identical.

**How to check it.** `docs/REPRODUCIBLE_BUILDS.md` has the procedure and
`tool/verify_reproducible.py` does the comparison — and it reports *what*
differs, because a verifier told only "different" has learned nothing and will
stop checking.

**Not covered.** Provenance is SLSA **L2**, not L3 (R9): a compromised build
step could forge provenance about itself. There is no in-app updater, so a
desktop user can be served an older release with valid provenance (R8).

And the big one: **cross-machine reproducibility failed on its first real run**
(R16). Two CI runners building the same commit produced APKs differing in all
six `libapp.so` / `libdartjni.so` entries, with every other entry identical and
both files exactly the same size. The failing job varied the runner and the
checkout path at the same time, so it cannot say which mattered; a three-way
experiment now separates them. Until that is understood, this section claims
only that a build can be checked *against another build on the same machine at
the same path*, which catches a tampered build server and does not give an
outsider what "reproducible build" normally promises.

## 9. What Z does not claim

Stated positively, because the gap between what a system does and what people
assume it does is where harm happens:

* **Not anonymity.** Z is not a mixnet. Someone who can watch both ends can
  correlate timing and volume.
* **Not protection from your contact.** Anyone you message can screenshot it.
  Disappearing messages are a courtesy against accidental retention and are
  described as exactly that.
* **Not availability.** A hostile relay can refuse to deliver. It cannot read
  what it refuses.
* **Not recovery.** No server custody means no password reset. Lose every
  device without a backup and the identity is gone.
* **Not audited.** No external cryptographic review has been performed yet.
  That is 14.3, and until it happens the honest statement is that this design
  has been reviewed by the people who wrote it.
* **Not independently rebuildable.** A verifier on their own machine will not
  currently reproduce the shipped APK byte for byte (R16). Same machine, same
  path, yes; that is a narrower property than the phrase "reproducible build"
  is normally taken to mean, and the difference is ours to close.

The full list, with severities and status, is the residual-risk register in
`docs/THREAT_MODEL.md`.

## 10. Where to start reading

| you want | read |
|---|---|
| the wire format, normatively | `PROTOCOL.md` |
| what is and is not protected, and what is left over | `THREAT_MODEL.md` |
| every claim, and where it is tested | `AUDIT_SCOPE.md` |
| what data exists and who sees it | `DATA_MAP.md` |
| why a design is what it is | `adr/` — 0001 key transparency, 0003 the QR problem, 0004 device-list signatures |
| how to check the binary | `REPRODUCIBLE_BUILDS.md`, `PROVENANCE.md` |
| how to report something | `VDP.md` — safe harbour, and no legal threats |

---

*This document describes Z at protocol v3. It is a summary and an argument; where
it and `PROTOCOL.md` disagree, `PROTOCOL.md` is correct and this file is a bug.*
