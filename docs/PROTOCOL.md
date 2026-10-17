# Z — Protocol Specification, version 1 (frozen) + version 2 (post‑quantum)

**Status:** v1 (§0–§16) is FROZEN — frozen on 2026‑09‑03 for external review
(roadmap Phase 5.1). Every construction in it is pinned by the machine‑checked
test vectors in [`vectors/v1/`](vectors/v1/) — the Dart reference
implementation (`protocol/`) must reproduce them bit‑for‑bit
(`protocol/test/vectors_test.dart`), and an independent implementation written
from this document alone, in Node.js with no shared code, must verify them
(`server/test/vectors.test.js`). Both run in CI. A change to anything normative
in v1 is a protocol version bump, not an edit (§14).

**v2** (§17) adds the post‑quantum hybrid on top of v1 as a negotiated,
backward‑compatible extension: a v2 client speaks exact v1 to a v1 peer. It
is pinned by [`vectors/v2/`](vectors/v2/), verified by the same Dart and Node
checks plus `protocol/tool/verify_mlkem.py` (kyber‑py, an independent FIPS 203
implementation).

**§19** specifies the public transparency log (`adr/0006`): a separate
service that commits to the device‑list versions and fingerprints §3.6
already gossips, and what a client does with its proofs. It is pinned by
[`vectors/kt/`](vectors/kt/), reproduced by the log's own tests and
re‑derived by `kt/tools/verify_vectors.py` from the text alone.

This document is written so that a competent implementer can build an
interoperable client without reading the Dart source. Where the reference
implementation makes a choice the wire format does not force (e.g. how ids are
generated) it is marked *implementation note*.

---

## 0. Conventions

* `a || b` — byte concatenation. `utf8(s)` — the UTF‑8 encoding of string `s`,
  no terminator. `len(x)` — length in bytes.
* `b64(x)` — RFC 4648 §4 base64 **with** padding. `b64url(x)` — RFC 4648 §5
  base64url **without** padding. `hex` is used only in the vector files.
* `SHA256`, `HMAC` (HMAC‑SHA256), `HKDF(ikm, salt, info, L)` (RFC 5869 with
  HMAC‑SHA256; an empty salt is equivalent to `HashLen` zero bytes).
* `X25519(priv, pub)` — RFC 7748 scalar multiplication, 32‑byte output, the
  32‑byte private key being the raw seed (clamped by the function).
  `X25519pub(priv)` — the corresponding public key.
* `Ed25519.sign(seed, msg)` / `Ed25519.verify(pub, msg, sig)` — RFC 8032
  (pure Ed25519, no prehash, no context), 32‑byte seed, 64‑byte signature.
* `ChaCha20Poly1305(key, nonce12, aad, plain)` — RFC 8439 AEAD; returns
  `(ct, tag16)`. `XChaCha20Poly1305(key, nonce24, aad, plain)` —
  draft‑irtf‑cfrg‑xchacha: `subkey = HChaCha20(key, nonce24[0..16])`,
  `nonce12 = 0x00000000 || nonce24[16..24]`, then ChaCha20Poly1305.
* Integers on the wire are JSON numbers unless a fixed binary encoding is
  named: `u32be` (4 bytes big‑endian) or `u64le` (8 bytes little‑endian).
* JSON is RFC 8259, UTF‑8, emitted compactly. **No signature or MAC in this
  protocol is computed over a JSON serialisation** — every signed or
  authenticated structure is a binary concatenation defined below — with a
  single exception, the ratchet header (§5.3), whose canonical byte string is
  fully specified. Parsers MUST ignore unknown JSON members.
* All randomness is drawn from the platform CSPRNG. Seeds and nonces are
  never reused; the only deterministic nonce is the attachment chunk nonce
  (§7), which is unique by construction.
* "Reject" means: discard the input, leave all local state untouched.

## 1. Primitives

| Purpose | Algorithm |
|---|---|
| Identity / account / device signing | Ed25519 |
| Key agreement (handshake, ratchet, sealed sender, pairing) | X25519 |
| KDF | HKDF‑SHA256 |
| Symmetric ratchet chains | HMAC‑SHA256 |
| Message, attachment, vault and backup AEAD | XChaCha20‑Poly1305 (24‑byte nonce) |
| Sealed‑sender and pairing‑channel AEAD | ChaCha20‑Poly1305 (12‑byte nonce) |
| Hashing, routing ids | SHA‑256 |
| Backup passphrase KDF (§13, informative) | Argon2id |
| Post‑quantum key encapsulation (v2, §17) | ML‑KEM‑768 (FIPS 203) |

## 2. Identity

### 2.1 Keys

An identity is two independent 32‑byte CSPRNG seeds:

```
edSeed → Ed25519 key pair (edPub, edPriv)     signing
xSeed  → X25519  key pair (xPub,  xPriv)      key agreement
```

Seeds never leave the device except inside an encrypted backup (§13) or the
sealed enrollment blob of a device pairing (§10).

### 2.2 Routing id

```
routingId = b64url( SHA256(edPub) )          // 43 characters
```

This is the only address the relay ever sees: a mailbox name that is a hash,
not a key, a name or a phone number.

### 2.3 Binding signature

Proves the X25519 key belongs to the Ed25519 identity:

```
bindingSig = Ed25519.sign(edSeed, utf8("z-bind-v1:") || xPub)
```

### 2.4 Contact code (`zc1.`)

The public identity, exchanged out‑of‑band (QR code / paste):

```
code = "zc1." || b64url( utf8( JSON{ "v":1, "ed":b64(edPub), "x":b64(xPub),
                                     "sig":b64(bindingSig), "name"?:string } ) )
```

`name` is omitted when empty. A decoder MUST reject the code unless: the prefix
matches, the JSON parses, `v == 1`, `ed` and `x` decode to exactly 32 bytes,
`x` is a strong X25519 key as §21.4 defines one — its top bit clear, below p,
and not a point of small order — and `bindingSig` verifies under §2.3.
(Multi‑device accounts use the `zc2.` code of §3.3; every implementation MUST
still accept `zc1.`.)

The key test is not the owner's to waive by signing. An envelope sealed to a
key of small order is open to whoever holds it (§8), so a code carrying one
would hand every person who writes to its owner to the relay; the same test
applies wherever a bundle is taken in rather than scanned — a contact request
(§8.1), a restored backup, a group's member list, a contact mirrored from one
of the account's own devices. An honest key always passes: X25519 makes it
as a clamped scalar times the base point. Builds from before 2026‑10‑16 did
not apply the test, and what they took in is not re‑checked (§8 says what a
send to such a key does).

### 2.5 Safety number

A 60‑digit string both parties can compare out‑of‑band. Symmetric by
construction (inputs are sorted):

```
(lo, hi) = the two Ed25519 public keys in lexicographic byte order
K        = HKDF( ikm = lo || hi, salt = utf8("z-safety-v1"),
                 info = utf8("display"), L = 60 )
group_i  = ( Σ_{j=0..4} K[5i+j] · 256^(4−j) ) mod 100000,  i = 0..11
display  = the 12 groups, zero‑padded to 5 digits, joined by single spaces
```

For accounts (§3) the inputs are the two **account** keys, so the number is
stable as devices are added and removed.

## 3. Accounts and devices

An identity is promoted to an **account** whose Ed25519 key is the trust root:
it signs device certificates and anchors the safety number, and it never runs
a ratchet. Each device has its own Ed25519 key (relay auth, routing id) and its
own X25519 key (ratchets). The relay is unaware of accounts: every device is
just another routing id.

Device #1 of an account uses the **account Ed25519 key as its device Ed25519
key**, so a one‑device account has the same routing id as the v1 identity it
was migrated from and its existing sessions keep working.

### 3.1 Device certificate

```
input = utf8("z-device-cert-v1:") || deviceEdPub || deviceXPub || utf8(deviceId)
sig   = Ed25519.sign(accountEdSeed, input)

JSON: { "ded":b64(deviceEdPub), "dx":b64(deviceXPub), "id":deviceId,
        "sig":b64(sig), "legacy"?:true }
```

`deviceId` is any UTF‑8 string (*implementation note:* `b64url` of 9 random
bytes). Verification against an account key `A` MUST check `len(ded) ==
len(dx) == len(A) == 32` and then:

* `legacy` absent/false: `Ed25519.verify(A, input, sig)`.
* `legacy == true`: the record must be exactly what a `zc1.` code decodes to
  (§3.5): `id == "legacy-v1"`, `ded == A`, and
  `Ed25519.verify(A, utf8("z-bind-v1:") || dx, sig)` — i.e. `sig` is the v1
  binding signature. The flag selects the rule; it never bypasses it.

**Proof of possession (ADR 0022).** `sig` proves that the account signed the
certificate, not that whoever holds the account holds the device key it
names: an account signs whatever public keys it is handed. A certificate MAY
carry the device's own signature, naming its account:

```
popInput = utf8("z-device-pop-v1:") || A || deviceEdPub || deviceXPub || utf8(deviceId)
pop      = Ed25519.sign(deviceEdSeed, popInput)        // by the DEVICE key

JSON: { "ded", "dx", "id", "sig", "legacy"?, "pop"?:b64(pop) }
```

`A` is the account key the certificate is for; the three keys are 32 bytes
each and the id is last, so the input needs no lengths. No signature the
account makes covers `pop` — `sig`, and a list's `sig`, `sig2` and `sig3`
(§3.4), are over inputs fixed before it existed — so a certificate, list or
`zc2.` code with it and the same without it have the same signatures and the
same fingerprint, and a reader that predates it, which ignores unknown members
(§0), admits both alike. A reader that knows it MUST, when `pop` is present,
check that it is a base64 string (any other value, `null` included, makes the
certificate malformed: it does not parse) and that
`Ed25519.verify(deviceEdPub, popInput, pop)` holds; one that does not verify
fails the certificate, and with it the list or code that carries it. A
certificate **proves possession** for `A` when it verifies and either `ded ==
A` — device #1 of an account and a `legacy` record, whose `sig` is the device
key's own signature — or it carries `pop`. The proof covers `dx` by the
device's Ed25519 key; it does not show possession of the X25519 key, and
does not need to: a device's routing id and mailbox are its Ed25519 key's
(§3.2, §12.1), and every session binds both devices' Ed25519 keys in its
`AD` (§4, §9), so a certificate that pairs someone else's X25519 key with
one's own Ed25519 key names a device nobody can talk to. What a receiver does
with a proof is §3.4's; how a device linked before proofs gets one into its
account's list is §9's (`dir:"pop"`).

### 3.2 Routing

A device's mailbox is `b64url(SHA256(deviceEdPub))` (§2.2 applied to the device
key). An account's stable id, used only locally, is
`b64url(SHA256(accountEdPub))`.

### 3.3 Account code (`zc2.`)

```
code = "zc2." || b64url( utf8( JSON{ "v":2, "acct":b64(accountEdPub),
                                     "devs":[ deviceCert... ], "name"?:string } ) )
```

Reject unless the prefix matches, `v == 2`, `acct` is 32 bytes, `devs` is
non‑empty, **every** certificate verifies under §3.1 against `acct`, and every
certificate's `dx` is a strong X25519 key (§2.4, §21.4).

### 3.4 Signed device list

The account's authenticated statement of its current device set, distributed
to contacts inside the ratchet (inner kind `devlist`, §6.2):

```
eds   = the deviceEdPub of every listed device, sorted lexicographically
input = utf8("z-devlist-v1:") || utf8(decimal(version) || ":") || eds[0] || eds[1] || …
sig   = Ed25519.sign(accountEdSeed, input)

// v2 (ADR 0010): also bind every field a certificate carries, in deviceEdPub order
content = utf8(decimal(version) || ":") ||
          for each device, ordered by deviceEdPub:
              deviceEdPub || deviceXPub || u16be(len(utf8(id))) || utf8(id)
input2  = utf8("z-devlist-v2:") || content
sig2    = Ed25519.sign(accountEdSeed, input2)   // beside sig, on a dual-signed list

// v2-only (ADR 0017 stage 2): the same content, under a context of its own
input3  = utf8("z-devlist-v3:") || content
sig3    = Ed25519.sign(accountEdSeed, input3)   // alone, on a v2-only list

JSON: { "acct":b64(accountEdPub), "ver":version, "devs":[deviceCert...],
        "sig":b64(sig), "sig2":b64(sig2), "sig3":b64(sig3) }
                                                // a member is omitted when that
                                                // signature is absent
```

A list has one of three shapes, and only three: `sig` alone (a list from before
ADR 0010), `sig` and `sig2` (dual‑signed: what every current client signs —
stage 1 of ADR 0017), or `sig3` alone (v2‑only: stage 2 of ADR 0017; see below).
Any other combination — no signature, `sig2` alone, `sig3` beside `sig` or
`sig2` — is malformed. A signature member that is present MUST be a base64
string: a list carrying `sig`, `sig2` or `sig3` with any other value — `null`
included — is malformed too, whatever the rest of it is. (Present‑but‑null is
not absent. Read as absent, `{sig, sig2, "sig3": null}` would be a dual‑signed
list and `{"sig": null, sig3}` a v2‑only one, while a reader going by the
members present refuses both; one rule, the strict one, keeps every reader at
one answer.)

A receiver MUST refuse a malformed list before it checks any signature. It MUST
check that `acct` is the account key it already holds for that contact, verify
every certificate (§3.1) and every signature the list carries, each over its own
input — `sig` over `input`, `sig2` over `input2`, `sig3` over `input3` — and
reject a list whose `ver` is lower than the highest verified version it already
holds (an equal version is a repeat and may be re‑applied). It then fans
messages out to exactly the listed devices (§9) and accepts messages only from
them.

**A device belongs to one account.** A certificate (§3.1) proves that the
account signed it, not that whoever holds the account holds the device key it
names, so any contact can put another person's public keys — from a contact
code, or a group's member list (§11) — in a list of their own. A receiver MUST
refuse a list, the whole list, that names a device whose routing id it already
holds for a **different account**: the device another contact was added from,
a device another contact's installed list names, or one of the receiver's own
devices. Accounts are compared, not contact records — the same account added
from two of its devices (§18.7) is two records naming each other's devices,
and that is not a collision. The rule holds for every list the receiver
installs: in‑band, from the log (§19), and lists it already held when it
starts. For a device that has proved nothing (below) it is **first come**: a
list that arrives before the receiver holds the real owner's device for anyone
takes it, and the owner's own list, arriving second, is the one refused. The
reference client tells the user, on the chat of the contact whose list was
refused, that the list named a device another contact's list also names (or
one of the user's own), naming both: it cannot tell which of the two accounts
is wrong, and the one refused may be the honest one.

**A device that has proved whose it is (ADR 0022).** A certificate that
proves possession (§3.1) settles what first come could not. A receiver MUST
record, for each device a list or a contact's code proves, the account it
proved itself in — the first proof standing — and MUST then:

* refuse, whole, any list from ANOTHER account that names that device —
  whether or not anyone holds the device now, and whatever the list carries;
* once a list from the account itself has carried the device's proof, refuse
  a later list from that account naming the device without one — the member
  taken off by whoever passed the list on, or a certificate the account
  re‑signed over another ratchet key, which the old proof does not cover. In
  band this refusal is silent, as the signature floor's is; from the log it is
  a conflict, as any list the rules refuse. (A proof seen only in a contact's
  code does not start this rule: it says what the device's build makes, not
  that the account's root carries proofs.) A receiver applies it to lists
  that arrive, not to the lists it already holds when it starts;
* install a list that proves a device which another account's installed list
  holds by the first‑come rule alone, and stop using that other list — whole,
  as a refused list is refused whole: its devices are no longer that
  contact's, and whatever was queued for them is not delivered. Nothing the
  other account signed removed those devices, so no removal notice (§3.6) is
  sent for them. The same applies when the receiver adds a contact from an
  account‑anchored code (§18.7) whose device proves the account it names: its
  certificate carries `pop`, or the code signs its post‑quantum commitment
  (§18.10), which is the device key's signature over the account key. A code
  that names no account proves nothing here, though its key is its identity:
  every identity makes a binding signature (§2.3) — a linked device on a build
  before §18.7 hands out such a code for its own key — and anyone can present
  one again;
* refuse to add a contact from an account‑anchored code that names that
  device for another account — the account's certificate in it is signed
  over whatever keys the account was handed, as a list's is. A contact added
  from such a code before the proof reached the receiver stays: its record IS
  the device's routing id, and no list moves a contact the user added, so
  against it the device's own account's list is first come.

A receiver's own account's list is the authority on the receiver's own
devices, proof or not: a contact's list that named a device of the receiver's
before the receiver knew it was its own is not used once the receiver's own
list names it. The reference client keeps what was proven for as long as it
holds a contact record of the account, and tells the user on the claimant's
chat that the device has proved it belongs to the other contact's account,
naming both — this time it can tell which list is wrong. A device that has
proved nothing to the receiver — its build predates proofs, its account's root
does not yet carry them, or it is an account's phone the receiver knows only
from its code — stays first come.

**A second signature (ADR 0010).** The v1 `input` covers the version and the
membership and nothing more; each device's `deviceXPub` and `id` are bound only
by that device's own certificate (§3.1), under Ed25519 alone. `input2` adds
every device's ratchet key and id — the keys contacts actually open ratchets to
— to what the account key commits to, and `sig2` is the account's Ed25519
signature over it. A current client signs both when it issues a list, so a
pre‑0010 contact still verifies it on `sig`; a legacy list carries only `sig`.
Ordering is by `deviceEdPub` as in v1, and within a device the id is
length‑prefixed with a big‑endian u16 because it is variable and is not the last
field of its element.

A receiver MUST also verify `sig2` whenever the list carries it, so a forged
`sig2` fails outright — on a dual‑signed list both signatures must verify.

**A sole signature over its own input (ADR 0017).** `sig2` is only ever made
beside `sig`. A v2‑only list's one signature is `sig3`, over `input3`: the
content of `input2` under the context `z-devlist-v3:`. The two differ because a
list with one signature must not be obtainable from a list with two by deleting
one. Every dual‑signed list carries a genuine `sig2`, and anyone who passes a
list on — the log's operator included, who can open a value and seal it again
(§19.1) — could otherwise delete `sig` and present what is left as a v2‑only
list: one the account never sent, fingerprinted over another input than every
other reader holds for that version. `{sig2}` is malformed, and a `sig2` moved
into `sig3` does not verify over `input3`. The three contexts share the
`z-devlist-vN:` form, so the inputs differ in one byte at the same offset and
none can equal another.

**What a list commits to (ADR 0017).** The list's fingerprint (§3.6) and the
input of its post‑quantum signature (§18.9) are taken over one of its inputs,
chosen by the list itself:

> The fingerprint and the ML‑DSA input follow the strongest signature that
> is *alone*: v1 while a v1 signature is produced; once it is not, the input
> of the one signature the list carries.

So a list that carries `sig` — alone or beside `sig2` — commits to `input`, and
a v2‑only list commits to `input3`. It is the v1 signature's presence that
decides because a client from before ADR 0010 admits a list on `sig`, knows only
`input`, and computes the fingerprint and checks the ML‑DSA over it; while lists
are still signed so that such a client can read them, every reader has to commit
to the same bytes it does, or the two would hold one list at one version and
disagree about its fingerprint. A list without `sig` is one that client cannot
read at all (it does not parse there), so committing to `input3` — which also
names each device's ratchet key — loses nothing. The rule reads only the list,
so two parties holding the same bytes always agree.

**The floor, per contact account, in three levels.** A receiver MUST record how
far each contact account's signing has moved, and MUST refuse a list below that
point:

| level | reached when | refused from then on |
|---|---|---|
| 0 | nothing yet | nothing (beyond the rules above) |
| 1 | a valid `sig2` or `sig3` has been seen (ADR 0010, ADR 0017); the receiver records the highest `ver` at which one was | a list that carries neither with a `ver` above that floor — a downgrade that strips the ratchet‑key signature cannot be replayed at a higher version. A list that carries neither at or below the floor is verified on `sig` alone |
| 2 | a v2‑only list (`sig3` alone) has been installed (ADR 0017 stage 2) | any list that carries `sig` — dual‑signed or v1‑only, at any version, the held one included |

At level 2 a downgrade cannot be expressed: the account has stopped producing v1
signatures, so a list from it that carries one is a forger putting back the
format whose fingerprint is blind to a ratchet key, or a build that went
backwards, and a receiver cannot tell those apart. (The reference client does
not store level 2 separately: an account is at level 2 exactly when the list
held for it is v2‑only, since nothing at that level can replace it with a list
carrying `sig` — and only the account can raise it, since only the account can
sign `sig3`.) In‑band, a refusal under the floor is silent, as a list that fails
to verify is: nothing is installed and nobody is told. That is also what keeps
it from accusing an innocent account — the gossip of §3.6 goes on comparing the
account's own claims with the list still held, and they agree. A list refused
when it comes from the log is not silent: the log check reports a conflict — the
log's list refused by the device‑list rules — which holds sends to the account,
as an entry that does not open does (§19, `adr/0006`).

**The v2‑only signer (ADR 0017 stage 2b), and when it signs (ADR 0029).** Every
current client reads all three shapes. A root signs `sig3` only once it has
moved its account, which it does when every device that reads the account's
lists has said it can read one (§3.7) — a client before the release that taught
readers the third shape cannot parse a list without `sig`. It then moves its
account's list once to the next version, signed with `sig3` alone, and
sends it to its own devices, its contacts and the log (§19.6); a v2‑only list is
therefore never at version 1, the baseline a contact computes for itself over
`input` (§3.6). A root that has signed v2‑only keeps signing `sig3` alone on
every build that can read it, whatever that build's constant
(`devlistSignV2Only`, now the kill switch for the move) says: re‑signing
its current version the other way would give the version a second fingerprint
(§19.8).

### 3.5 Legacy mapping

A `zc1.` code is read as a one‑device account: `accountEdPub = ed`, with the
single device `{ded: ed, dx: x, id: "legacy-v1", sig: bindingSig, legacy: true}`.
A code carrying `acct` says otherwise and is read under §18.7 instead — this
mapping is the default, not the only reading.

### 3.6 Device‑list transparency (gossip)

The signed device list (§3.4) is trustworthy only if whoever signed it is the
legitimate account. Whoever holds the account seed — a stolen backup, a
compromised or coerced root device — can sign a list that adds a rogue device
or removes an honest one. Nothing above makes that visible. Z makes it
*detectable*, with no new infrastructure, by having the parties that already
receive a device list cross‑check it inside the existing end‑to‑end channel.
All members here are compatible extensions (§14): optional inner‑message
members and one new inner kind, ignored by older clients. This is decision
7.7a of ADR 0001; a future public transparency log (7.7b) commits to exactly
the fingerprint defined here.

**Fingerprint.** For a signed device list at `version` over device set
`devs`:

```
fp = SHA-256( signingInput(version, devs) )[0..16]      // §3.4 input; 16 bytes
```

It commits to the exact `(version, sorted deviceEdPubs)`, so two parties
holding the same list compute the same 16 bytes however each obtained it. A
one‑device account's baseline is `fp` at `version = 1` over its single device.

Which input the fingerprint is over is decided by the list, by the rule in §3.4:
the strongest signature that is alone. A list that carries `sig` — every list a
client signs today, dual‑signed since ADR 0010 — has the v1 fingerprint above; a
v2‑only list (`sig3` alone, ADR 0017 stage 2) has `SHA-256(input3)[0..16]`, over
the v2 content under its own context. That one also commits to each device's
`deviceXPub` and `id`, and moves when a ratchet key does — which the v1
fingerprint is blind to. Because the rule reads only the list, two parties
holding the same list bytes compute the same 16 bytes; a client from before ADR
0010, which knows only the v1 input, agrees with a current one about every list
it can read; and a list already gossiped here or committed to the log (§19)
keeps the fingerprint it had, so no cross‑check raises a false conflict when
signing moves to v2‑only. Nothing can make a list report another list's
fingerprint by deleting a signature: a dual‑signed list with `sig` deleted is
malformed (§3.4). (Until ADR 0017 this paragraph said the fingerprint followed
`sig2` wherever it was present; that is what made a 3.5.7 client and a current
one disagree about the same dual‑signed list.)

The baseline is always the v1 fingerprint: a contact computes it itself, from
the one device in the code it scanned, and that code does not carry the device
id `input3` commits to. This is why a v2‑only list is never at version 1 (§3.4).

**Claim and echo.** Every inner message (§6.1) MAY carry:

```
"dl"  : { "v":version, "h":b64(fp) }   // sender's claim about ITS OWN account's current list
"pdl" : { "v":version, "h":b64(fp) }   // newest list the sender holds for the RECIPIENT's account (echo)
```

**Receiver rules**, kept per contact account (latest `(v,h)` per sending
device of that account):

* **Conflict** — two devices of the account claim the same `v` with different
  `h`, or a device's claimed `v` decreases (a rollback), or a device claims
  `v == held` with `h ≠ held.h`: surface *“their devices disagree — one may not
  be theirs.”* Sending is never blocked.
* **Unconfirmed** (after a short grace so a normal update in flight does not
  alarm): the highest version any of the account's devices claims is **below**
  the version the receiver was handed → the handed list is newer than the
  account's own devices admit (a split view to the receiver); or a device
  claims a version **above** the held one and the account's broadcast that
  would install it never arrives.

**Owner rule.** On each `pdl` a device receives about its *own* account, it
compares with the newest list it issued or learned by self‑sync (§9): an echo
`v` higher than known, or the same `v` with a different `h`, says a device
holding the account key issued a list this device never saw — the T1/T2
signal, actionable only by the owner, and surfaced loudly. But it only *says*
so (ADR 0026): an echo is two numbers any contact can type, so a receiver
MUST NOT raise anything on the echo itself. It MAY ask the echoing contact for
the list behind it — `pdlreq {v, h}` (§6.2) — and a device that receives a
`pdlreq` and holds a signed list for the asker's account answers with a
`devlist` carrying exactly that list; the asker tells the answer from the
contact's own list by its `acct`, and installs it nowhere. The signal is raised
only on **evidence**: a list for the account that verifies under its key
(§3.4) and that the device's own records do not explain — not its current
list; not one it signed, learned by self‑sync or reconciled (§19.8) at a
version it has reached; not one from before it knew the account; and, on a
device that cannot sign — which learns by self‑sync and may skip versions — not
a version below its own that it never saw. It is raised after the same short
grace as the receiver rules above, and a device that cannot sign asks its root
first (root discipline, below). An echo no list backs within that grace is
dropped (the reference client counts it and shows nothing). A receiver SHOULD
bound what one contact can make it do; the reference client asks one contact
at most three times in ten minutes and never about the same echo twice in that
window, weighs an answer only if it is the list one of that contact's echoes
named (asked about in that window, or still unexplained), verifies at most
eight lists from one contact in a window, and answers one account at most
three times in a window, whichever of its devices asks. A user's dismissal of
the signal holds for the evidence it was raised on — the same list, before or
after a restart, raises nothing — and new evidence raises it again. A contact
whose client predates ADR 0026 cannot answer, so its echo raises nothing at
all (`THREAT_MODEL.md` R46).

**Removal notice.** When a contact installs a verified list that *drops*
devices it previously held, it sends each dropped device one final inner
message of kind `dlrm` (§6.2) over the still‑known pairwise session before
forgetting it, carrying that list (`list`, ADR 0026). A rogue cannot suppress
it: it is sent by the contact, not the
account. It SHOULD be queued with the same durability as a message — the
reference client's outbox — since it is sent exactly once and a client whose
link happens to be down at that moment would otherwise never send it. And
whatever else was queued for the dropped device MUST be discarded at the same
moment: a durable queue must not deliver, after the list said otherwise, what
a down link happened to be holding. The same applies to a root removing one
of its own devices and the self‑sync traffic queued for it.

**Receiving a removal notice (ADR 0026).** A notice is a claim as well. A
device MUST NOT tell its user it was removed on a notice alone; it tells them
only on a list for its own account that verifies under the account key, does
not name the device, and is at a version above the one the device holds. The
version is what keeps the account's own lists from before the device was
linked — which omit it, and which anyone holding the account's public key can
read from the log (§19.1) — from counting; a device that has learned no list
for its account yet (one just linked, before its root's list reaches it) holds
no version, and is told nothing. The list is the notice's `list`, or
the account's latest entry in the log (§19), opened and verified (§19.3):
that is the same evidence wherever it is found, whether or not a contact sends
a notice. A notice without `list` — what clients before ADR 0026 send — is not
evidence; it MAY move the device's own check of the log forward (the reference
client does, at most once in ten minutes). A dismissal holds for the list it
was raised on, as above.

**Root discipline.** A root‑holding device MUST self‑sync every new signed
list to the account's own other devices (§9, envelope `dir:"acct"`) before or
with the contacts, so an honest update reaches them within the grace window
and only a rogue list stands out. It re‑asserts its newest list on every
reconnect and whenever one of its devices asks (`dir:"acctreq"`), and a
non‑root device asks before treating an inconsistent echo as an alarm — so a
device that merely missed an update is repaired, while an alert raised when
the root was unreachable clears itself once the root's answer explains the
echo. Conversely a root's list carrying a version **lower** than the device
already holds is itself an alert: an honest root never regresses, so the
newer list was signed by someone else holding the account key (the
split‑view attacker answering the device's request from the root's mailbox).

**Self‑healing distribution.** A root that receives an echo `pdl` for its own
account with `v` below its current version knows that contact never got the
list (added after a device was linked, or a broadcast lost) and sends it
again (cooldown‑limited); it also introduces its device set alongside the
contact‑add hello. A device that installs a contact's list naming a device it
has never sent its own list to sends its list then — to every device of the
contact, once per such list, not cooldown‑limited. The new device holds at
most the one‑device list its own device passed on when the contact was added
(§18.8's `cadd`), and every message it is sent claims a newer one; waiting
for its echo, which rides a receipt held 5 s to a minute (ADR 0028), lost
the race with the grace, and the re‑send that echo asked for could fall
inside the cooldown of one asked for before the device was known (until
2026‑10‑16, after 4.2.0: two people who each had a linked device added each
other, and a laptop raised "the update never arrived"). Distribution
therefore converges without user action.

### 3.7 Who can read a v2‑only list: the capability, and the move (ADR 0029)

```
"dlr" : 3     // on every inner message (§6.1), and beside "thread", "dir" and "inner"
              // on every self-sync envelope (§9): the newest device-list shape the
              // SENDING DEVICE reads — 3 = every shape of §3.4, the v2-only {sig3} included
```

A client from this release on MUST put `dlr` on every inner message it sends a
contact's device and on every self‑sync envelope it sends one of its own
devices, outside anything that can fail, so that nothing it sends goes without
it. It travels inside the ratchet; the relay never sees it. A receiver records
it per sending device, under that device's routing id: `dlr` of 3 or more
reads a v2‑only list; a message that carries the claim `dl` (§3.6) and no
`dlr` is from a build that decorates what it sends and does not say, and is
recorded as one that does not read one; a message that carries neither
teaches nothing. A device not heard from counts as one that does not read
one. Receivers compare with at‑least: a later shape raises the number, and
its readers still read `{sig3}`. Clients that predate the member ignore it
(§6.1, §9).

**The move.** An account's lists are read by every device of every contact —
the device the contact was added from and every device the contact's installed
list names — and by the account's own other devices. A root moves its account
(§3.4) the moment it holds at least one contact, has at least one linked
device, every one of those devices has said `dlr` of 3 or more, and its build
allows the move; it checks at start‑up and whenever one of those facts changes
in the move's favour, and asks nobody anything. A linked device MUST say it to
its own devices at least once a run and whenever it adopts a newer list for its
account, so that its root hears it even when it has nothing else to send. A
one‑device account is not moved: its contacts take its one device's ratchet
key from the code they scanned, so the v1 input hides nothing from them
(`THREAT_MODEL.md` R42).

**After the move.** A root that has moved does not move back (§3.4). A device
that reads its lists without having said `dlr` of 3 or more — a contact added
later, a device linked later — may be unable to parse them. A client whose own
account's list is v2‑only MUST NOT send the claim `dl` (§3.6) to a device that
has not said so, whether or not another device of the same contact has: a
client that cannot parse the list would read a claim above the list it holds
as an update that never arrived. The copy such a device is sent is otherwise
the same inner, its `ttl` included. A client sends a device the claim again
from the first message after that device says it, and never withholds it from
a device that has. What such a contact still sees, and what the account's user
is told, is in `adr/0029`.

## 4. Session establishment (X3DH‑style, no server prekeys)

Z has no server storage, so the responder's long‑term X25519 identity key
stands in for the signed prekey. Both identities were exchanged and verified
out‑of‑band (§2.4/§3.3). Initiator A → responder B:

```
EK_A     = fresh X25519 key pair (ekSeed, ekPub)
DH1      = X25519(IK_A_priv, IK_B_pub)
DH2      = X25519(EK_A_priv, IK_B_pub)
SK       = HKDF( ikm = 0xFF×32 || DH1 || DH2, salt = 0x00×32,
                 info = utf8("Z-X3DH-v1"), L = 32 )
AD       = SHA256( utf8("Z-AD-v1") || edPub_initiator || edPub_responder )
sid      = b64url( SHA256(ekPub) )[0..22]      // first 22 characters
```

B computes the mirror (`X25519(IK_B_priv, IK_A_pub)`, `X25519(IK_B_priv,
EK_A_pub)`) and obtains the same `SK` and `AD`. The initiator attaches `ekPub`
to every payload on the session until it has **received** one message on it
(§5.5), so the responder can bootstrap even if earlier packets are lost or
reordered; a payload for an unknown `sid` that carries no `ek` is an
*unknown session* (the receiver should open a fresh session and/or show a
"session reset" notice). The receiver MUST check `sid == b64url(SHA256(ek))[0..22]`.

**Convergence.** Either party may initiate. To avoid two live sessions after a
simultaneous start, both sides prefer the session whose initiator has the
lexicographically smaller routing id (the *designated initiator*), and the
designated side opens the session proactively with a `hello` (§6.2) at
contact‑add time. Sessions unused for 7 days may be pruned, never the current
outbound one.

**A peer that lost its state.** A device that reinstalls, or restores from a
backup (which deliberately carries no session state — `BACKUP.md`), opens a
brand‑new session while the peer still holds one that was carrying traffic in
*both* directions. Convergence alone cannot resolve this: it keeps preferring
whichever session the designated initiator opened, so unless the side that
restarted happens to be that initiator, every reply would go out on a session
the peer cannot decrypt. A receiver that accepts a new session while holding
another it has already *received on* therefore **pins** the new one as its
outbound session. The narrowness matters: a session it has never received on
is the simultaneous‑start case above, which convergence already settles, and
is left alone.

The pinned side is not dropped in favour of the new one, it is merely no
longer sent on. A receiver cannot distinguish a peer that lost its state from
a second device holding the same identity key (§3.6), so discarding the
replaced session would let either of them permanently cut the other off. Once
a peer has shown that it loses sessions, the receiver simply follows whichever
session it last heard them speak on. Both remain decryptable, each with its
own post‑quantum secret (§17.1).

**A session that has ended stays ended.** `SK` is a pure function of
`(IK_A, IK_B, ek)` (§4), so a session's *opening* envelope re‑derives the
same root key and the same first chain every time it is presented: accepting
one for an unknown `sid` is how a peer that lost its state is let back in, and
it is also how a captured envelope could be replayed indefinitely. A client
therefore **records the session ids it retires** — on an explicit "reset
secure session" and when a stale session is pruned — and refuses to create a
session for a recorded id, reporting the envelope as undecryptable rather than
as an unknown session (there is nothing for the peer to re‑open). Without it,
a relay holding a captured opener could make the plaintext of that first chain
arrive again after a reset — the receiver's own duplicate‑suppression window
(§6.7) is 30 days, so an older capture read as new messages — and could have a
pruned session re‑created and then *pinned* by the rule above, moving the
receiver's outbound traffic onto a session the peer had discarded. The record
is bounded (the oldest ids are dropped; the reference client keeps 64), which
is years of ordinary use and far longer than any envelope a relay still
holds (`QUEUE_TTL_HOURS`).

## 5. Double Ratchet

The Signal Double Ratchet with X25519, HKDF‑SHA256, HMAC‑SHA256 and
XChaCha20‑Poly1305.

### 5.1 Key derivation

```
KDF_RK(rk, dh) : out = HKDF(ikm = dh, salt = rk, info = utf8("Z-RK-v1"), L = 64)
                 → (rk' = out[0..32], ck = out[32..64])
KDF_CK(ck)     : → (mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02))
```

### 5.2 Initialisation

State: `rootKey, dhsSeed, dhsPub, dhrPub, cks, ckr, ns, nr, pn, ad, skipped`.

Initiator (after §4): `dhs = fresh X25519 pair; dhrPub = IK_B_pub;
(rootKey, cks) = KDF_RK(SK, X25519(dhsSeed, IK_B_pub)); ckr = ∅; ns = nr = pn = 0`.

Responder: `rootKey = SK; dhs = its identity X25519 pair (xSeed, xPub);
dhrPub = ∅; cks = ckr = ∅; ns = nr = pn = 0`. Its first DH ratchet step happens
on the first inbound message; it cannot send before receiving.

### 5.3 Encryption

```
(mk, cks) = KDF_CK(cks)
header    = { dh: b64(dhsPub), n: ns, pn: pn }
hdrBytes  = utf8( '{"dh":"' || b64(dhsPub) || '","n":' || decimal(ns) || ',"pn":' || decimal(pn) || '}' )
nonce     = 24 random bytes
plain'    = pad(plain)                      // ISO/IEC 7816‑4: append 0x80, then 0x00 to a multiple of 256; always adds ≥ 1 byte
(ct, mac) = XChaCha20Poly1305(mk, nonce, aad = AD || hdrBytes, plain')
ns       += 1
```

`hdrBytes` is the exact byte string shown (no spaces, that member order). The
sender MUST persist the advanced state before the ciphertext leaves the device
so a crash cannot reuse `mk`.

### 5.4 Decryption

All steps run on a copy of the state; the copy replaces the state only on
success (a failure leaves the state untouched).

1. If `skipped` holds a key under `b64(header.dh) || "|" || decimal(header.n)`,
   remove it and decrypt with it (aad as in §5.3, then unpad; reject on failure).
2. Else if `header.dh ≠ dhrPub`: **skip** to `header.pn` on the current
   receiving chain (step 4), then perform the DH ratchet step:
   ```
   pn = ns; ns = 0; nr = 0; dhrPub = header.dh
   (rootKey, ckr) = KDF_RK(rootKey, X25519(dhsSeed, dhrPub))
   dhs = fresh X25519 pair
   (rootKey, cks) = KDF_RK(rootKey, X25519(dhsSeed, dhrPub))
   ```
2b. Else if `header.n < nr` — the same chain, at a number this chain has
   already passed, and step 1 found no key for it — the message is one this
   session has consumed: the relay redelivering an envelope whose
   acknowledgement never arrived, or a replay. An implementation MUST report
   this **distinguishably** from a decryption failure and MUST NOT continue:
   deriving from `ckr` would produce the key for `nr`, not for `header.n`, and
   fail authentication indistinguishably from a chain that has genuinely
   diverged. The two want opposite answers from the client (§5.4a), which is
   why the wire carries no flag for it and the receiver decides.
3. Skip to `header.n` on the receiving chain (step 4), then
   `(mk, ckr) = KDF_CK(ckr); nr += 1`, decrypt, unpad.
4. *Skip(until)*: if `ckr = ∅`, do nothing. Reject if `until − nr > 512`.
   While `nr < until`: `(mk, ckr) = KDF_CK(ckr)`, store `mk` in `skipped` under
   `b64(dhrPub) || "|" || decimal(nr)`, `nr += 1`. `skipped` holds at most
   1536 keys; the oldest are evicted first.

### 5.4a What a client does when a decrypt fails

A receiver MUST distinguish three outcomes, because they are three different
things and were one until 2026‑09‑14:

* **An unknown session** — the peer is speaking on a session this device does
  not hold. Acknowledge the envelope (a redelivery would fail the same way),
  tell the user once per episode, and send a `hello`: it carries a fresh
  ratchet public key, the peer ratchets onto it, and their next message lands
  on a chain this side can derive.
* **A chain that no longer agrees** (step 3 fails to authenticate). The same
  answer. This is repairable and it is the case that, left silent, ends the
  conversation: nothing on screen, nothing sent, and a peer who believes every
  message arrived.
* **A message already consumed** (step 2b). Acknowledge it and say nothing.
  There is nothing to repair, and a phone killed between processing an
  envelope and acknowledging it is ordinary — a warning that fires then is a
  warning nobody believes.

The notice and the `hello` MUST be coalesced: one notice per episode carrying
a count, and at most one `hello` per interval (the reference client uses 10
seconds). Anything that can put an envelope in the mailbox can therefore cost
the receiver one row and one `hello` per interval, and no more.

### 5.5 Transport payload

```
payload = b64( utf8( JSON{ "v":1, "t":"r", "sid":sid, "ek"?:b64(ekPub),
                           "h":{ "dh":b64(dhsPub), "n":ns, "pn":pn },
                           "n":b64(nonce), "ct":b64(ct), "mac":b64(mac) } ) )
```

`ek` is present iff the sender is the session's initiator and has not yet
received a message on it. Reject if `v ≠ 1` or `t ≠ "r"`.

## 6. Inner messages

### 6.1 Envelope

The decrypted bytes are UTF‑8 JSON:

```
{ "k":kind, "mid":string, "ts":int, "ttl"?:int, ...kind‑specific members }
```

`mid` is a sender‑chosen id unique per sender (*implementation note:* `b64url`
of 16 random bytes); `ts` is the sender's clock in ms since the epoch; `ttl`
(seconds, omitted when 0) marks a disappearing message — the recipient deletes
it `ttl` seconds after receipt, the sender `ttl` seconds after sending.
Unknown kinds MUST be ignored.

### 6.2 Kinds

| kind | members | meaning |
|---|---|---|
| `hello` | — | silent session opener (§4); never shown |
| `text` | `body:string`, opt. `rt:string` | chat message; `rt` = the `mid` this replies to (§6.4) |
| `file` | `fid, name, size:int, mime, sha256:b64, fk:b64, fn:b64, chunks:int`, opt. `rt` | attachment offer (§7) |
| `timer` | `sec:int` | set the disappearing timer for the conversation (0 = off) |
| `read` | `mids:[string]` | read receipts |
| `dlv` | `mids:[string]` | end‑to‑end delivery receipts (§6.3) |
| `devlist` | `list:string` (the JSON of §3.4, as a string) | account device‑set update — or, answering a `pdlreq`, the list the sender holds for the RECEIVER's account (§3.6, ADR 0026), told apart by its `acct` and installed nowhere |
| `ginvite` | `gid, name, ver:int, members:[{ "b":ContactBundleJSON, "n":string }]`, opt. `owner:string, admins:[string], rv:int`, `tmr:int`; each member entry opt. `e:[int,int]` | group create/update (§11); `owner`/`admins` = who may issue lists, `rv` = the version of those roles — left out while the group's roles have never changed (§11.1); `tmr` = the group's disappearing-messages timer, in seconds, once it has had one, and an entry's `e` the position `[rv, ver]` of the list that added that member, for one added after the group was made (§11.2) |
| `gmsg` | `gid, body`, opt. `rt` | group text (§11) |
| `gfile` | `gid` + the `file` members, opt. `rt` | group attachment offer (§7, §11) |
| `gleave` | `gid`, opt. `e:[int,int]` | sender left the group (§11); `e` = the position of the membership it ends, `[0, 0]` included — absent only from a client before ADR 0030 (§11.2) |
| `gsync` | `gid` | "send me what you hold for this group": asked by a member that had to refuse a list, of the owner and of any admin it may have missed the leave of (§11.1); answered with the asked admin's `ginvite`, and its `gleave` if it has left |
| `pqek` | `alg:"ML-KEM-768", ek:b64` | v2 post‑quantum key offer (§17); consumed by the session layer, never shown |
| `pqid` | `alg:"ML-DSA-65", pk:b64`, opt. `ack:true` | v3 post‑quantum identity key (§18.2); checked against the commitment from the scanned code, or kept as a candidate when none is held. `ack` = the sender holds the receiver's key |
| `pqack` | — | the sender holds the receiver's post‑quantum key (§18.2); the `ack` above without a key, for when no `pqid` is going out to carry it |
| `dlrm` | `acct:b64, v:int, h:b64`, opt. `list:string` | device‑list removal notice (§3.6); tells a device it was dropped from account `acct`'s list. `list` (ADR 0026) is that list, the JSON of §3.4 as a string — the evidence a receiver acts on; a notice without it is a claim |
| `pdlreq` | `v:int, h:b64` | "send me the list you hold for my account" (ADR 0026): asked of a contact whose echo `pdl` (§3.6) named (`v`, `h`); answered with a `devlist` carrying that list. Keyless; ignored by clients that predate it |
| `react` | `rt:string, emo:string` | reaction to one message (§6.5); `emo:""` withdraws |
| `greact` | `gid` + the `react` members | reaction inside a group (§6.5, §11) |
| `edit` | `rt:string, body:string` | new text for one of the sender's own messages (§6.6) |
| `gedit` | `gid` + the `edit` members | the same inside a group (§6.6, §11) |
| `del` | `mids:[string]` | delete‑for‑everyone of the sender's own messages (§6.6) |
| `gdel` | `gid, mids:[string]` | the same inside a group (§6.6, §11) |
| `gjoin` | `t:string, go:int` | the answer to a group invite link (`adr/0020`, §20.6): the sender opened a connect invite of the receiver's whose message 3 carried the group bit, was told before the digits that it brings them into a group, and answered — `go` 1 to join, 0 to be a contact only. `t` is that ceremony's go‑ahead tag (§20.6), sixteen bytes as unpadded base64url: an answer counts for the one ceremony whose tag it carries, and for no other. It names no group — only the receiver knows which group its link was for. Each link is answered on its own; the sender says every answer it still owes the receiver again in answer to each `hello` from them — until the group arrives (when one answer is owed to them; with several, the list cannot say which link it settles, so each is said until its own window ends) or for 48 hours from the answer — so one join carries one to three of them (measured, `group_invite_link_test` 16); the receiver acts on one at most once. The smallest bucket: measured, 854 bytes of sealed plaintext in the 1 024 bucket, most of it the ratchet header and the §3.6 members every inner message carries |

`ContactBundleJSON` is `{ "ed", "x", "sig", "name" }` as in §2.4 (all `b64`);
every bundle in a `ginvite` MUST be verified (§2.3) before use.

Independently of kind, an inner message MAY also carry the device‑list
transparency members `dl` and `pdl` (§3.6), each `{ "v":int, "h":b64 }`;
clients that do not implement 7.7a ignore them. It MAY also carry `pqh:1`: the
sender holds the receiver's post‑quantum key — a `pqack`'s statement, restated
on every message so that one lost envelope cannot lose it (§18.2); clients that
predate it ignore the member. And `dlr`, the device‑list shape the sending
device reads (§3.7).

### 6.3 Receipts

On persisting an inbound `text`, `file`, `gmsg` or `gfile`, the recipient
sends `dlv{mids:[mid]}` back over the same pairwise session (best effort). This
replaces the relay's `delivered` frame, which sealed sender (§8) makes
impossible. `read` is sent for messages the user has viewed. Neither leaves
the moment it is owed: a receipt that goes back promptly lets a relay that
watches timing pair a sealed sender with the recipient (`THREAT_MODEL.md`
R41), which until phase 41 the reference client's 300 ms window did.

**When a receipt leaves (`adr/0028`).** A client SHOULD hold each receipt it
owes:

* no sooner than a floor F after the moment it became owed — the message
  stored, or viewed — nor sooner than F after the client last connected to
  the relay;
* at the latest at a moment drawn uniformly between F and a ceiling C after
  it became owed — drawn again, from the reconnection, when a reconnection's
  floor passes it;
* when one of a person's receipts leaves, every receipt owed to that person
  that is past its floor goes with it: one `dlv` and one `read`, each naming
  at most 64 mids, a larger batch as several at the same moment;
* a receipt past its floor MAY leave sooner, directly behind a message the
  user sends that person — never behind one the client sends on its own
  account (a `hello`, a key, a list).

The reference client uses F = 5 s and C = 60 s, keeps what it holds across a
restart, and has a switch that stops it sending either kind. None of this is
on the wire: a receipt held is the same message as one sent at once, and a
client that sends its receipts promptly is read exactly as before.

A receipt is a claim, and a sender MUST bound what each party may claim. A
`mid` is plaintext to everyone who received the message, so in a group every
member holds every member's ids; a sender that acts on a receipt without
checking the thread lets any contact mark any of its outgoing messages —
including one in a conversation that party is not in — delivered. So a receipt
from party P for message M counts only if M is outgoing in a thread P is a
party to: P's own pairwise thread, or a group P is currently in.

For a group message, "delivered" means **every** member, not the first to
answer: the sender records one confirmation per (message, member) and moves
the state only when the current membership has all confirmed. Membership
shrinks, so this is re-evaluated when a member is removed or leaves —
otherwise a message waits for ever on somebody who is gone, which is a worse
failure than the one it replaces because it never resolves.

### 6.4 Replies (8.1)

A content message (`text`, `file`, `gmsg`, `gfile`) MAY carry `rt`: the `mid`
of an earlier message **in the same conversation** that it replies to. That is
the whole wire format — the quoted text is never transmitted.

This is deliberate. A reply that carried its own copy of the quoted text could
show the recipient words the quoted sender never wrote; carrying only the id
means the quote a recipient sees is always what their own device stored for
that id. Consequences a receiver MUST handle:

- **Unknown id** (never received, already expired under §8, or deleted): show
  the reply with the quote marked unavailable. Never fetch it from anywhere.
- **Cross‑conversation id**: an `rt` naming a message outside the conversation
  it arrived in MUST be treated as unknown. Receivers look the id up scoped to
  the conversation, so a peer cannot use a reply to probe whether some id
  exists elsewhere in the vault.
- **Malformed or oversized** `rt` (not a string, empty, longer than 64 chars):
  ignore the member and render an ordinary message.

`rt` is one‑way: replying does not modify the quoted message, and a reply to a
message with a disappearing timer follows the timer of the conversation as it
stands when the reply is sent, not the quoted message's.

### 6.5 Reactions (8.1b)

`react` (and `greact` in a group) attaches one emoji to one earlier message:

```
{ "k":"react", "mid":<this message's id>, "ts":…, "rt":<target>, "emo":"👍" }
```

- `rt` is the same member replies use (§6.4) — "the message in this
  conversation that this one refers to" — and carries the same bounds. It is
  deliberately not called `mid`, which already names the inner message's own
  id. `emo` is the emoji, or `""` to withdraw. A sender has at most **one** reaction per message — a
  second `react` replaces the first, which is why no separate "remove" kind is
  needed.
- `emo` MUST be at most 32 UTF‑16 code units and MUST NOT contain control
  characters. A reaction is a badge, not a second text channel; receivers drop
  anything longer or containing control characters rather than storing it.
- The same conversation‑scoped lookup as §6.4 applies: a reaction whose target
  is unknown **in the conversation it arrived in** is dropped. Reactions are
  not messages — they never create a conversation, never count as unread, and
  never change a message's ordering.
- A reaction to a message that later disappears (§8) or is deleted (§6.6) goes
  with it.
- Reactions are stored under the reacting device's routing id, so a group
  member sees who reacted, and one member cannot overwrite another's. One of
  a contact's other devices reacts as the contact, so its reaction is stored
  under the contact's and replaces theirs (§9).

### 6.6 Edit and delete for everyone (8.1c)

`edit` replaces the text of a message; `del` removes messages. Both are
**requests about the sender's own messages**, and the receiver is what makes
that true:

> A receiver MUST apply an `edit` or `del` only to messages **that same sender
> wrote in that same conversation**. Anything else is dropped silently.

In a 1:1 conversation the ratchet already establishes who is speaking, so the
check is that the target is an *incoming* message of that conversation. In a
group this is the security-relevant case: membership is pairwise fan‑out, so
any member can send a `gdel` naming any id they have seen. Receivers therefore
record the **sender's routing id** alongside each stored group message and
require it to equal the sender of the edit/delete. A stored message with no
recorded sender (written before 8.1c) fails the check and is left alone —
fail‑closed, because the alternative is letting one member delete another's
message.

Further rules:

- `edit` applies to text kinds only (`text`, `gmsg`); an edit naming an
  attachment or a system notice is dropped. The original `ts` is kept, so
  editing cannot reorder a conversation, and the receiver marks the message as
  edited — an edit is never silent.
- `del` erases the body (and any attachment blob and its chunks, and any
  reactions) but keeps a **tombstone** row, so the conversation does not
  silently change shape and a later message replying to it still resolves as
  "unavailable" rather than pointing at a hole.
- Neither verb is a message: no unread bump, no ordering change. An
  edit/delete naming an unknown id is dropped — it is not an invitation to
  fetch anything.
- Deleting for everyone is best‑effort by nature: a recipient who has already
  read, screenshotted or copied the message is beyond the protocol's reach,
  and the UI says so rather than implying a guarantee.

A `file` or `gfile` offer MAY additionally carry `voice:true` and `dur:int`
(seconds): the attachment is a recorded voice message of that duration, and
clients render an inline player. The pipeline is unchanged — same keys,
chunks and limits (§7) — and a client that ignores the members shows an
ordinary audio file attachment.

### 6.7 Deduplication

Delivery is at‑least‑once (§12.5). Receivers MUST deduplicate on
`(senderRoutingId, mid)` after decryption; a duplicate is acknowledged to the
relay but not processed again.

### 6.8 What a receiver does with an inner message it cannot use

An envelope that decrypts has authenticated: the ratchet proved who sent it,
and the step cannot be un-taken. But the plaintext inside is still the
sender's say-so — a peer's own client, buggy or hostile toward its own
contact, can put anything in a validly-encrypted envelope — so a receiver
MUST decide every inner message's fate and acknowledge it **once that fate is
decided**, never leaving it for the relay to redeliver on every connect. An
envelope that is neither acknowledged nor stored is redelivered until the
queue TTL (§12.4) and, across a restart, fails the same way every time: a
single one wedges a mailbox slot for 72 h, and enough of them fill the byte
cap so that valid messages are refused.

Two outcomes, and the receiver MUST tell them apart:

* **Permanent** — the envelope can never be processed: an inner message whose
  members have the wrong type or a non-finite number, a shape no kind defines,
  or (at the session layer) an opener whose ephemeral or ratchet key is the
  wrong length. The receiver **validates every inner message against §6.2
  before acting on it** (`InnerMessage.fromBytes`: a wrong-typed member or a
  non-finite number is a parse error, not a raw exception that escapes the
  caller), and `Conversation.decrypt` raises its documented decrypt exception
  for a malformed payload or key rather than letting a library Error through.
  A permanent failure is **acknowledged and counted**. For a message that
  authenticated and whose content alone is unusable, the ratchet step is
  **kept** and only the content dropped; for an opener that never decrypts, no
  session is created (so a forged opener leaves nothing behind — it cannot
  accumulate dead sessions or displace a contact's genuine pending one).

* **Transient** — the operation can succeed on a later delivery: the vault
  busy, closing, full or erroring; a file-system error; a send held by a
  transparency conflict (§3.6/ADR 0006). The envelope is **left with the
  relay**, unacknowledged, and the advanced ratchet is rolled back so the
  redelivery decrypts. A receiver MUST NOT acknowledge a transient failure
  away: doing so loses a message it has not stored.

One classifier decides this for every receive path — the contact's, a
contact's additional device's, and self-sync — so a vault-write failure is
never acknowledged on one path while it is redelivered on another.

A held message a peer could not send while a transparency conflict stood
(an edit, delete, reaction or timer change, which apply locally at once) is
queued durably and sent when the hold lifts, not dropped.

## 7. Attachments

A file is encrypted once under a random per‑file key and relayed as chunks
outside the ratchet; the key travels inside the ratchet in the `file` offer.

```
fk  = 32 random bytes            fn = 16 random bytes
fid = b64url(12 random bytes)    // opaque chunk‑routing id (16 chars)
chunkNonce(i) = fn || u64le(i)                                       // 24 bytes
(ct_i, mac_i) = XChaCha20Poly1305(fk, chunkNonce(i), aad = utf8("z-file-v1:" || fid), chunk_i)
chunk payload = b64( utf8( JSON{ "v":1, "t":"f", "fid":fid, "idx":i, "ct":b64(ct_i), "mac":b64(mac_i) } ) )
```

Chunks are consecutive `chunkSize` slices of the file; the last may be
shorter; an empty file is one empty chunk. `chunkSize` is 140 KiB (143 360
bytes) — the largest raw chunk
whose payload, once sealed (§8), pads into the 262144 bucket, which is the
largest bucket whose base64url envelope stays under the relay's
1,000,000‑character frame cap (§12.2). Every chunk envelope is therefore the
same size on the wire. The offer carries the
file's `name`, `mime`, `size`, `chunks` and `sha256` (of the plaintext file,
`b64`). The receiver verifies every tag, reassembles in `idx` order, checks
`size` and the whole‑file SHA‑256, and only then surfaces the file. The
reference app caps attachments at 24 MiB.

A receiver **MUST** refuse an offer or a chunk whose `fid` is not exactly
sixteen characters of the base64url alphabet (`[A-Za-z0-9_-]{16}`), which is
what `b64url(12 random bytes)` produces and the only thing this protocol ever
produces. The `fid` is chosen by the **sender** and carried in an ordinary
field, so "it is one of ours" is an assumption about a peer rather than a
fact — and an implementation that uses it as a *name* (a filename, a
directory entry, a key in a store) is naming something on a contact's
instruction. `..`, a leading `/` and a drive letter are all valid strings and
none of them is a file id. The reference client refused nothing here until
2026‑09‑13 and used the value as `files/$fid.bin`, so a contact could choose
where on the device an attachment landed; the rule was already written above,
and only the receiver never read it.

An offer's numbers are the sender's say‑so too. A receiver **MUST** refuse an
offer whose `chunks` is not ⌈`size` / `chunkSize`⌉ (1 for an empty file), or
whose `fk`, `fn` or `sha256` is not 32, 16 or 32 bytes; and it MUST NOT store
a chunk whose `idx` is outside `[0, chunks)` or whose ciphertext is not that
index's share of `size` — `chunkSize`, or what is left for the last — which
it can check before decrypting anything, since the tag travels apart as
`mac`. So no chunk takes the place of the right one at its index, and nothing
assembles to more than the offer declared. The reference client also refuses
an offer larger than its 24 MiB limit, and holds a chunk that arrives before
its offer only if an offer it would accept could own it (an index below 176,
at most `chunkSize` bytes). Until 2026‑10‑04 it believed both numbers: an
offer declaring a million chunks was stored and every chunk sent for it kept,
and a file assembled to whatever its chunks added up to. *Compatibility:*
this section used to say a receiver MUST accept any chunk size. Every sender
since v1.2.0 uses 140 KiB; v1.0.x and v1.1.x used 480 KiB, so a file of more
than one chunk from either is refused now — and those two releases predate
sealed sender (§8), so they can open nothing a later build sends them.

A `fid` is unique per sender, but it is not secret from anyone the offer
reaches: in a group every member holds every member's. So a receiver keys an
attachment by **(conversation, sender, `fid`)** — the sender being the
account, whichever of its devices (§9) sent the offer — and binds it to the
message that carried it. A receiver **MUST** refuse an offer whose `fid` it
already holds for any other conversation, sender or message (the same offer
again, through another of the receiver's doors, is the one it holds and not a
second), and an offer whose `mid` that conversation already holds for
anything else. Chunks carry no sender; they are matched by `fid` to the one
offer holding it. Everything that reads, assembles, re‑sends, archives or
removes an attachment does so through the message it belongs to: a
`del`/`gdel` (§6.6) removes the attachment its target message brought, and
nothing another message merely names, and only where §6.6's authorship rule
holds — which a sender's linked devices satisfy as the sender. The reference
client keyed attachments by `fid` alone until 2026‑10‑04, so a group member
could offer another member's id as a message of their own, delete that
message — theirs, so the rule allowed it — and with it the other member's
file, then offer the id again with their own bytes, which the other member's
message then showed under the other member's name. What remains is a race: an
offer of an id that reaches a receiver before the genuine one is the one it
keeps, shown under its own sender's name (`THREAT_MODEL.md`).

## 8. Sealed sender

Without this layer the relay learns the sender of every envelope (from the
authenticated connection) and could reconstruct the social graph. A sealed
envelope removes the sender from the relay's view: the outer envelope names
only the destination mailbox; the sender's routing id is inside the ciphertext.

```
inner    = utf8( JSON{ "f":senderRoutingId, "p":payload } )     // payload = a §5.5 or §7 string
eph      = fresh X25519 pair (ephSeed, ephPub)                    // one per envelope
shared   = X25519(ephSeed, recipientXPub)
key      = HKDF( ikm = shared, salt = ∅, info = utf8("z-sealed-v1") || ephPub || recipientXPub, L = 32 )
padded   = u32be(len(inner)) || inner || 0x00…  to the smallest bucket ≥ len(inner)+4
           buckets: 1024, 4096, 16384, 65536, 262144, 1146880 (= 1120 KiB); larger: exact fit
nonce    = 12 random bytes
(ct, mac)= ChaCha20Poly1305(key, nonce, aad = utf8("z-sealed-v1"), padded)
envelope = "zs1." || b64url( ephPub || nonce || ct || mac )
```

A sender MUST refuse to seal when `shared` is all zeros (RFC 7748 §6.1),
checked in constant time, and MUST NOT send the payload unsealed in its
place. `recipientXPub` of small order — the zero point, or one of the few
points of order 2, 4 or 8, in any of their spellings (§21.4 lists the
canonical ones; X25519 also reads p and p + 1, and each with the top bit
set) — gives all zeros whatever `ephSeed` is, so `key` would be a function of
`ephPub` and `recipientXPub` alone, and the envelope, `f` included, would be
open to the relay and anyone else who holds it. No honest key is one, so
the refusal costs an honest send nothing. Codes and bundles carrying such a
key are refused when they are read (§2.4, §3.3); the refusal here is for a
key that arrived some other way — a device in a signed list (§3.4), or a
contact taken in by a build from before 2026‑10‑16 — and it is per device: a
client sends nothing to that device and goes on with every other, it does
not drop an inbound message because a reply to it could not be sealed, and
a send that is refused leaves the ratchet as it was, so the next one does not
go out past an index the peer never received. Opening needs no
such check: this layer has no authenticity (below), so a key anyone could
compute protects nothing a random one would.

Senders MUST keep an envelope under the relay's frame cap (§12.2) after
base64url: with the default cap only buckets up to 262144 are usable, which
is what sizes attachment chunks (§7). `recipientXPub` is the X25519 key of the
destination **device** (from its device certificate or `zc1.` bundle). Opening: check the prefix, decode, split
`ephPub(32) || nonce(12) || ct || mac(16)` (reject if shorter than 60 bytes),
recompute `key` with `X25519(myXSeed, ephPub)`, decrypt, unpad (reject if the
length prefix exceeds the data), parse, and route `p` through §5/§7 using `f`
as the sender. Any failure is a silent drop.

This layer provides no authenticity and needs none: `p` is ratchet
ciphertext (or a chunk sealed under a key that only the offer's recipient
holds) that only the claimed sender can produce; a forged `f` simply fails
inner decryption. The one `p` that is neither — a contact request (§8.1),
which by design arrives before any session exists — carries its own signature
instead. The relay stores and delivers `zs1.` payloads with **no
sender attribution** (§12), matches acks by envelope id alone, and emits no
`delivered` frames for them (§6.3 replaces those). Senders MUST seal every
envelope for which they know the recipient device's X25519 key; the unsealed
forms remain valid for backwards compatibility only.

A sealed envelope withholds the sender from the *frame*; the *connection*
it is sent on has whatever identity the client gave it. A client that wants
the relay not to know who sent what therefore sends sealed envelopes on a
connection that has not authenticated (§12.1), and receives on one that
has. The relay then holds an address and not an identity for each sealed
send; what an address is worth is `THREAT_MODEL.md` R21.

### 8.1 Contact request payload (`creq`, ADR 0011)

A contact request is a sealed `p` that is neither ratchet ciphertext nor a
chunk. Adding someone used to send them a `hello` they dropped as an unknown
sender — no session, so nothing to authenticate it against — which is why a
connection needed **both** people to add each other. A request is what the
receiver surfaces instead of that drop: *someone wants to connect*, to accept,
decline, or block. It rides sealed but **outside any ratchet**, because when it
arrives there is no session and the receiver drops unknown senders before it
would decrypt one.

```
creq     = b64( utf8( JSON{ "v":1, "t":"creq", "to":recipientRoutingId,
                            "ts":int, "bundle":ContactBundleJSON, "sig":b64 } ) )
sigInput = utf8("z-contact-request-v1:") || edPub || xPub
           || u16be(len(to)) || to || u64be(ts) || u16be(len(name)) || name
sig      = Ed25519.Sign( bundle.edSk, sigInput )      // name = bundle.displayName or ""
```

The sealed layer hides the sender from the relay but proves nothing to the
recipient — anyone can seal a `p` and set `f` to any routing id — so, unlike
ratchet ciphertext, a `creq` carries its own authenticity. A recipient MUST
verify, dropping silently on any failure: `to` is its own routing id; the
bundle self‑verifies (§2.3 — its X key is bound to its identity); the bundle's
routing id is `SHA‑256(edPub)` and equals the sealed sender `f`; and `sig`
verifies under `bundle.edPub` over `sigInput`. This makes a forged *X wants to
connect* impossible: an attacker holding X's public `zc1.` code cannot produce
X's signature, and cannot replay a genuine request at a different recipient
because `to` is signed in.

Accepting a request adds the contact from `bundle` at the **classical** floor,
exactly as scanning that `zc1.` code would — the account identity and
post‑quantum key follow in‑band (§18.2), and nothing here marks a contact
verified. A `creq` whose routing id is already a contact is that contact
accepting a request we sent (or the duplicate on a mutual add): it clears the
"requested" state and is not shown again. A blocked routing id's `creq` — and
its traffic — is dropped in silence. Older clients, which never send `creq`,
keep dropping the opening `hello` as before; nothing about the wire is
incompatible, and only a new client shows the request.

**A request from a linked device names its account (phase 33).** `bundle` is
the sending device's, so a request from someone's laptop added the laptop: its
key anchored the safety number, the account's lists were refused as not that
contact's, and nothing ever moved it. A device that does not hold its
account's root therefore adds three members, after the six every reader reads:

```
creq    += { "root":ContactBundleJSON, "cert":deviceCert, "asig":b64 }
asigIn   = utf8("z-contact-request-acct-v1:") || root.ed || u16be(len(to)) || to || u64be(ts)
asig     = Ed25519.Sign( bundle.edSk, asigIn )
```

`root` is the account's root device's bundle (§10 `hostbundle`), whose key IS
the account key; `cert` is the account's certificate for the sending device.
A recipient that reads them, after verifying the request as above, MUST check
that `cert` is not a `legacy` record and names exactly `bundle`'s two keys
(§18.7's rule 3), that `root` binds its own X25519 key and is not the sender,
that `cert` verifies under `root.ed`, and that `asig` verifies under
`bundle.edPub` — which ties the account to this request, so the anchor cannot
be carried to another request, or replaced by someone who passes the request
on (§18.8) with another account that certified the same device keys. All of it
holds, or none of it is used. When it holds, the request is the ACCOUNT's: it
is held, and accepted, under `root` and its routing id, exactly as a request
from the root itself would be, and the sender is one of the devices the
account's list will name. A request from anyone already held under another of
their account's devices is their answer, as one from the same device always
was. A client that does not read the three members reads the request as the
device's own, as it always did.

**Its time** (`adr/0024`). `ts` is signed, and a recipient MUST read it: it
drops a request whose `ts` is more than 30 days before its own clock or more
than one day after it, and one whose `ts` is not later than that of the last
request it took in from the same requester, still pending or declined — so a
copy the relay kept cannot put a declined request back in front of anyone,
while a new request, made later, is shown. Accepting the requester, blocking
them or deleting them ends that memory, and it need not outlive 30 days from
`ts`, after which the first rule refuses the request anyway. A recipient
holds at most 100 pending requests that came by a code or a link, and apart
from them at most 100 that came through its handle (§21.7); one more of
either kind pushes out the oldest of that kind its person has not been
shown, which is the new one when they have been shown every other — so a
flood through a public handle cannot push out a request made with the
code.

### 8.3 The introduction key (`adr/0033`, addendum A)

*Built in 44.9 (the library and `vectors/intro-key/`) and 44.10 (the relay,
§12.7). **No client publishes or fetches an introduction key before
44.11–44.12, emits `sk` before 44.11, or sends `zs2.` before 44.7**, which
waits for constant‑time ML‑KEM upstream: until then this section defines
values the library computes and the relay keeps, and nothing a client sends.*

A device's **introduction key** is its sealing key — `adr/0033` §1's
ML‑KEM‑768 pair, one per device for its life — kept at its relay so that a
sender who has never heard from the device can seal its first envelope to it
post‑quantum (`zs2.`, `adr/0033` §5), and signed by the device's own Ed25519
key:

```
sealEk, sealDk = the ML-KEM-768 pair of the device's 64-byte seal_seed      adr/0033 §1
iks   = Ed25519.Sign( edSeed, utf8("z-intro-key-v1:") || edPub || SHA-256(sealEk) )   64 bytes
sk    = SHA-256(sealEk)                                                               32 bytes
entry = sealEk || iks                                                                 1 248 bytes: what a relay keeps (§12.7)
code += { "sk": b64(sk) }                                                             zc1. and zc3., beside pqc only
```

`edPub` is the key whose SHA‑256 is the mailbox (§2.2): the account key on a
root device, `ded` on a linked one, `intro` for an introduction mailbox. The
two fields after the context are fixed‑width, so the concatenation is
unambiguous, and the context is a prefix of no other. There is no new key:
the introduction key is the sealing key, so a device has one decapsulation
key whoever writes to it. An introduction mailbox (§21.3) has its own, the
third key its introduction seed makes; rotating the seed rotates it, and it
is never in the handle record (§21.4 is unchanged):

```
kintroSeed = HKDF( ikm = introSeed, salt = utf8("z-handle-intro-k-v1"), info = ∅, L = 64 )   read as d || z: an ML-KEM-768 pair
iks        = Ed25519.Sign( introSeed, utf8("z-intro-key-v1:") || introPub || SHA-256(kintroEk) )
```

**`sk` in a contact code.** A device puts `sk` in its code only once its
relay holds its entry, so a code that carries `sk` promises a key. It is
unsigned, as a scan that adds someone is (`adr/0027`): whoever could alter a
code before its first scan could replace the whole identity in it, which the
safety number catches. A decoder refuses a code that carries `sk` and no
`pqc` — as it refuses `pqcs` with no `pqc`, and a `zc1.` code carrying `sk` is
read by the v3 decoder for that reason — and one whose `sk` is not the `b64`
of 32 bytes; a `null` member is an absent one, as for `pqcs`. A reader from
before the member reads the identity and ignores it (§14). In a code for
someone the client already holds, `sk` is ignored. Neither `iks` nor `sk` is
evidence about the device's account: a key they check is a sealing key, never
"post‑quantum, verified" (`adr/0033` §2).

**The acceptance rule.** A sender holds what a relay serves for mailbox `rid`
(§12.7) as that device's sealing key only if all of these hold, and refuses it
otherwise — recorded, said once, and never tried again:

```
len(ek) = 1184, and FIPS 203 §7.2's check: ByteEncode12(ByteDecode12(ek[0 : 1152])) = ek[0 : 1152]
len(iks) = 64
b64url(SHA-256(edPub)) = rid,  and  iks verifies under edPub over utf8("z-intro-key-v1:") || edPub || SHA-256(ek)   §21.4's one rule
when adding a contact from a code that carries sk:  SHA-256(ek) = sk, compared in constant time
```

ByteDecode12 reduces each 12‑bit coefficient modulo q = 3329, so the modulus
check refuses a key with any coefficient of t̂ at q or more; the last 32
bytes are ρ, a seed, and are not checked. `edPub` comes from the route: a
code's `ed`; the request being answered, its `bundle.ed`; a device in a
verified list or a group's member list, its `ded`; a handle record or a
`zi1.` link, its `intro`. An accepted key is held exactly as if `pqseal` had
brought it (`adr/0033` §1). Against an adversary who can forge Ed25519 at the
moment of the fetch, `iks` is no defence, as R4 is not; `sk` is, for a code
that carries it. When and where a sender fetches, how it waits for a promised
key, and what its person is told when a key is missing are `adr/0033`
addendum A, A3–A4, specified here with the client half (44.12).
*Implementation note:* `checkServedIntroKey`, `mlKemEncapsulationKeyValid`
and `handleIntroKem` in `protocol/lib/src/intro_key.dart`, where the first
check an answer fails names its refusal, in this order: the two lengths, the
modulus check, the mailbox, `iks`, `sk`. Vectors:
[`vectors/intro-key/`](vectors/intro-key/).

## 9. Multi‑device messaging and self‑sync

From one device's point of view, messaging an account is running one §5
session per **target device**: the contact's devices (their verified device
list, or the single device of a `zc1.` contact) plus the sender's own other
devices. Each session uses the two devices' Ed25519/X25519 keys in place of
identity keys — same handshake, same AD rule (initiator device key first) —
and each payload is sealed (§8) to that device and sent to its mailbox. The
designated initiator (§4) of each device pair opens the session with a `hello`
proactively (`openInitiatorSessions`) so establishment never races the first
real message.

**Self‑sync.** Messages the user sends or receives are mirrored to their other
devices over the same per‑device sessions, wrapped as:

```
utf8( JSON{ "thread":routingIdOrGid, "dir":"out"|"in"|"ping"|"acct"|"acctreq"|"pop"|"hist", "inner":b64(innerMessageBytes) } )
```

The wrapper also carries `dlr` (§3.7), the device‑list shape the sending device
reads; a receiver reads the three members above by name and passes any other by.

`dir = "ping"` with a `hello` inner is the proactive session opener and is
ignored on receipt; `"out"`/`"in"` insert the inner message into `thread` as
sent/received respectively; `"acct"` carries a `devlist` inner and updates the
receiving device's knowledge of its *own* account's current signed list (§3.6
root discipline) — from the root, with one optional member more, `rootb`, the
root's own contact bundle, which a linked device checks against that list's
root certificate and keeps for the requests it sends (§8.1, §10
`hostbundle`); `"acctreq"` (a `hello` inner) asks the root to send that
list — a root answers with `"acct"`, any other device ignores it; `"pop"`
(ADR 0022) carries an inner of kind `devpop` whose `pop` is the sending
device's own proof of possession (§3.1), which only that device can make: a
device sends it when the account's list it holds names it without one — once
per list version — and a root keeps it beside the certificate it holds for the
SENDING device if it verifies for that certificate and the account, and puts
it in every list it signs from then on; no new version is needed for it
in‑band, since it changes no signature and no fingerprint. The transparency
log, though, takes each version once (§19.5), and the copy it takes is what a
contact reading the list from the log learns: so a root holds back the log
publish of a version naming a device it has just linked until that device's
proof is in, for a bounded time, and a root whose log copy of its current
version lacks a proof it holds moves the list to the next version, which
carries it (ADR 0022, amended 2026‑10‑16). Any other device ignores it, and a
device that predates it drops it as an unknown kind (§6.2); `"hist"`
carries an inner of kind `hist` whose `items` replay recent history to a
device that was just linked: each item is
`{ "t":thread, "mid", "o":outgoing, "k":"text"|"gtext", "b":body, "ts", "sn"?, "x"? }`,
stored as an ordinary row (deduplicated on `mid`) and ignored for a thread the
receiving device does not hold. `x`, when present, is the absolute time in ms
at which the item disappears (§6.1's `ttl`, already applied by the sender):
the receiving device stores it as its own expiry, and an item whose `x` has
passed is not stored at all. A mirrored copy of any kind keeps its `ttl` the
same way a live one does — a disappearing message does not stop disappearing
because it reached a device through the self-sync or extra-device door. The reference app replays the newest 200 text
messages per chat in batches of 100, and only once that device's channel is
post‑quantum (§17.8); attachments are not replayed. Ahead of them, on the same
terms, `"hist"` carries each 1:1 chat's disappearing timer (30.3): an inner of
kind `timer` with that chat as `thread`, which the device takes without a
notice and only while its own timer for that chat is off — enrollment hands
it every contact with none, so without it what the device sent would never
disappear. A client that predates it reads an empty batch. Attachment
chunks are not re‑encrypted for sync: the chunk
payloads (§7) are forwarded verbatim to each of the user's other devices, which
decrypt them with the mirrored offer.

**What a person's other devices do (30.3).** A message from one of a
contact's other devices — one their signed list names (§3.4) — is the
contact's, and a receiver handles every kind exactly as it would from the
device the contact was added from: a message is stored, counted unread and
answered with `dlv` (and with `read` once read, §6.3); `edit`/`gedit`,
`del`/`gdel`, `react`/`greact`, `timer`, `read` and `dlv` apply with the
contact as their sender. So §6.6's authorship rule, §6.5's one reaction per
person and only from a member, and §6.3's scoping of receipts hold whichever
of the contact's devices a message came from, and a receipt or a reaction from
any of them counts as the person's: a group message waits for each member
once. Until 30.3 the reference client applied none of these from a contact's
other device but messages and (since 30.1) deletes, so an edit made on a
laptop left the old text on every other device, and a message sent from one
was never marked delivered.

What a user does on one of their devices, each of their other devices does
too, on a self-sync mirror with `dir:"out"`: `edit`/`gedit` replaces the text
of a message of the user's own — sent from any of their devices — that is
text and not deleted, and nothing else; `del`/`gdel` removes only the user's
own messages; `react`/`greact` is the user's one reaction to that message;
`timer` sets that chat's disappearing timer, which what the receiving device
sends from then on carries, and says so there as on the device it was set
on; and `read` — its `mids` the messages the user read on the sending device,
its `thread` the 1:1 chat or the group — makes the receiving device count
them read and send no receipt of its own for them. A group sends its members
no read receipts (§6.3), so this mirror is all that its read state travels
in. A contact's own edit, delete, reaction, timer or receipt is not mirrored:
it reaches each of the user's devices from the contact. A mirror that names
nothing the receiving device holds, or nothing that is the user's to change,
is dropped and acknowledged (§6.8). On both doors a receiver applies what one
device sent one envelope at a time, in the order it decrypted them, as the
conversation lock does on the contact's own door — so in a backlog delivered
in the order it was sent, an edit, a reaction or a receipt is applied after
the message it names. Every one of these is an existing kind on an existing
door, and a client that predates it ignores it, as it did.

**Device‑list distribution.** A root‑holding device signs the account's device
set (§3.4) whenever it changes and sends it to every contact as `devlist` and,
by self‑sync (`dir:"acct"`), to its own other devices (§3.6). Revocation is
removal from the list at a higher version.

## 10. Device pairing (enrollment)

A new device and an existing device meet at a one‑time rendezvous on the relay,
run an ephemeral X25519 exchange, and confirm a Short Authentication String
(SAS) on both screens; the existing device then signs the new device's
certificate and seals the enrollment payload to the channel.

```
secret        = 10 random bytes (the pairing code); displayed as RFC 4648 base32
                (alphabet A–Z2–7, no padding: 16 chars) in groups of 5 joined by "-"
rendezvous    = b64url( SHA256( utf8("z-pair-rendezvous-v1:") || secret ) )     // informative
relayIdentity(role) : okm = HKDF( ikm = secret, salt = ∅, info = utf8("z-pair-relay:" || role), L = 64 )
                       edSeed = okm[0..32], xSeed = okm[32..64];   role ∈ { "i" (new), "r" (existing) }
```

Each side connects to the relay as its throwaway `relayIdentity` and sends to
the other role's mailbox (`send` frames whose payload is a JSON string, not a
§5.5 payload; ids `z-pair-hello`, `z-pair-reply`, `z-pair-enroll`):

```
hello  (new → existing) : { "k":"hello", "ephx":b64(ephPub_N), "ded":b64(deviceEdPub), "dx":b64(deviceXPub), "id":deviceId }
reply  (existing → new) : { "k":"reply", "ephx":b64(ephPub_E) }
dh         = X25519(eph_N, ephPub_E) = X25519(eph_E, ephPub_N)
channelKey = HKDF( ikm = dh, salt = 0x00×32, info = utf8("z-pair-channel-v1"), L = 32 )
(lo, hi)   = ephPub_N, ephPub_E in lexicographic order
sasBytes   = HKDF( ikm = dh, salt = lo || hi, info = utf8("z-pair-sas-v1") || deviceEdPub, L = 8 )
n          = u32be(sasBytes[0..4]) AND 0x7FFFFFFF;   SAS = decimal(n mod 1000000) zero‑padded to 6, shown as "ddd ddd"
enroll (existing → new) : { "k":"enroll", "blob":b64(sealed) }
sealed     = nonce(12) || ct || mac(16)  where (ct, mac) = ChaCha20Poly1305(channelKey, nonce, aad = ∅, utf8(enrollment))
enrollment = JSON{ "acct":b64(accountEdPub), "root"?:b64(accountEdSeed), "name":string|null,
                   "pqpub"?:b64(accountMlDsaPub), "cert":deviceCert(new device),
                   "hostcert":deviceCert(existing device),
                   "contacts":[ AccountBundleJSON... ] }
```

Both users MUST compare the SAS before the existing device sends `enroll`; a
machine‑in‑the‑middle sees a different ephemeral on each leg and therefore a
different SAS on each screen. The new device MUST verify that `cert` carries
its own keys and verifies (§3.1) under `acct` before installing. `root` is
present only if the host chose to let the new device enroll further devices.
`pqpub` is the account's ML-DSA-65 **public** key (§18.1), present when the
host has one: it is public, so it travels even where the account root does
not, and without it the new device would have no account post-quantum
identity to speak for (§18.2). It is absent from an enrollment performed by a
build that predates v3, and a device that receives none MUST behave as a
classical identity rather than deriving a key of its own.
`AccountBundleJSON` is `{ "acct", "devs", "name" }` (§3.3 without the wrapper).

**Each contact as the host holds it (phase 33).** Two optional members follow
`contacts`, and are absent from an enrollment performed by a build that
predates them:

```
enrollment += { "cstate"?: [ ContactStateJSON... ], "hostbundle"?: ContactBundleJSON }
ContactStateJSON = { "rid", "bundle":ContactBundleJSON, "name", "ttl", "verified":0|1, "created",
                     "vsn"?, "pqc"?, "pqk"?, "pqcand"?, "pqack"?:1, "pqtold"?:1, "pqbad"?:1,
                     "acct"?, "cert"?, "addedby"?, "req"?:1,
                     "kv": { "pqcs_"?, "vpqc_"?, "pqcc_"?, "cdev_"?, "cdev_sigfloor_"?, "cdev_pq_"? } }
```

`contacts` names each contact's account and the device the host added them
from; a device that kept only that showed a different safety number for every
contact added from someone's linked device, and refused their account's lists
as not theirs. A receiver MUST keep each entry's account key and
certificate whether or not `cstate` is present: when `devs[0]` is a real
certificate that verifies under `acct` (not a `legacy` record), the contact is
anchored to `acct` with that certificate, as a §18.7 code anchors one.

`cstate` is the rest of what the host holds about each contact — the same
fields, under the same names, as a backup archive's contact record (§13,
`BACKUP.md`), without what a device keeps for itself: the scanned device's own
bundle (whose binding signature `devs[0]` does not carry), the tick and the
number it was given on (13.3), the post-quantum commitment, key or candidate
and the facts kept beside them (§18.2, ADR 0021, ADR 0027, 26.3), and the
contact's device list, its signature floor and its post-quantum signature
(§3.4, §18.9). A receiver MUST check each record against the `contacts` entry
for the same routing id — the same device keys, and for a `legacy` entry the
same binding signature — and each member as a restore checks an archive's: a
key of the right length, a key that matches the commitment beside it, a list
that verifies under the contact's account; a list's version is read from the
list. A record or member that fails is left out, and the contact is installed
from its `contacts` entry as above. The tick travels here and nowhere else: the
root sends it on the channel both users' screens just confirmed, to the device
that takes its whole account from the same payload, while the `cadd` any linked
device can send (§18.8) never carries one.

The whole enrollment is one relay frame (§12.4), and a host MUST keep it under
the relay's cap: the per-contact state goes in a fixed order of reductions, each
made good in-band — first each list's post-quantum signature (re-sent on
request, §18.9), then the lists (re-sent when the new device's echo of them is
behind, §3.6), then the keys, a key with no commitment beside it sent as its
commitment so the key the contact sends the new device is established against
it, and a tick given on the post-quantum number sent as the classical number
with the commitment that comparison covered (`vpqc_`, 26.3), so the new device
shows it verified on the number it can compute and moves it when the key
lands — and if even that is too large, `cstate` is left out.

`hostbundle` is the host's own contact bundle (§2.4): the root device's keys and
binding signature, which a linked device names in the requests it sends
(§8.1). The receiver MUST check that its `ed` is `acct` and its `x` is
`hostcert`'s ratchet key, and that it binds that key. A linked device enrolled
without it learns it from the root's next self-synced list (§9, `rootb`).

Both members are optional in each direction: a device from before them reads
`contacts` and ignores the rest, and one of this build linked by an older root
installs from `contacts` alone. Neither changes the frozen vectors, which are
of enrollments without them.

**Superseded by §10.1.** The ceremony above is what shipped through 2.8.4 and
is specified here unchanged, because its vectors are frozen (§14) and a device
that has not been updated still runs it. It has two weaknesses, and a current
client will not perform it: see §10.1.

### 10.1 Pairing v2 (current)

Same code, same rendezvous idea, same enrollment payload; a commitment round
in front, and a wider SAS over more of what is being agreed. Nothing in §10
computes anything differently — every context string here is new, so the two
ceremonies share no mailbox, no channel key and no SAS for one code.

Why, precisely. In §10 the existing device chooses its ephemeral **after**
seeing the new device's, and the two ephemerals are the whole input to the
SAS — so whoever speaks in the existing device's place can search ephemerals
until the six digits come out at a value already read aloud (about 2²⁰ tries).
And §10's SAS covers the ephemerals and `deviceEdPub` only, while the existing
device signs a certificate over the `dx` and `id` it read from an
*unauthenticated* rendezvous frame: a relay that rewrites nothing but `dx`
leaves **both screens showing the same six digits** while the host certifies
an X25519 key the attacker holds, at the real device's routing id. The new
device's own install then fails and the poisoned certificate stays in the
account's device list.

```
rendezvous    = b64url( SHA256( utf8("z-pair-rendezvous-v2:") || secret ) )     // informative
relayIdentityV2(role) : okm = HKDF( ikm = secret, salt = ∅, info = utf8("z-pair-relay-v2:" || role), L = 64 )
                        edSeed = okm[0..32], xSeed = okm[32..64];   role ∈ { "i" (new), "r" (existing) }

commit (new → existing) : { "k":"commit-v2", "c":b64(commitment) }
commitment = SHA256( utf8("z-pair-commit-v2:") || ephPub_N || deviceEdPub || deviceXPub || utf8(deviceId) )
reply  (existing → new) : { "k":"reply-v2", "ephx":b64(ephPub_E) }
open   (new → existing) : { "k":"open-v2", "ephx":b64(ephPub_N), "ded":b64(deviceEdPub), "dx":b64(deviceXPub), "id":deviceId }
dh         = X25519(eph_N, ephPub_E) = X25519(eph_E, ephPub_N)
channelKey = HKDF( ikm = dh, salt = 0x00×32, info = utf8("z-pair-channel-v2"), L = 32 )
sasBytes   = HKDF( ikm = dh, salt = ephPub_N || ephPub_E,
                   info = utf8("z-pair-sas-v2") || deviceEdPub || deviceXPub || utf8(deviceId), L = 8 )
n          = u56be(sasBytes[0..7]);   SAS = decimal(n mod 10^8) zero-padded to 8, shown as "dddd dddd"
enroll (existing → new) : { "k":"enroll-v2", "blob":b64(sealed) }      // sealed and enrollment exactly as §10
```

The salt is the two ephemerals in **role order** (new device first), not
lexicographic order: the commitment already fixes which side is which, so
there is no symmetric case left to canonicalise. `deviceId` is
variable-length and therefore last in the `info`, so the concatenation is
unambiguous — **provided every field before it is exactly 32 bytes**, which
rule 6 requires: without the check, moving the last byte of `deviceXPub` onto
the front of `deviceId` gives the same bytes, the same commitment and the
same SAS. `n` is taken from **seven** bytes because the modulo of a 31-bit
value by 10⁸ is visibly biased, and the extra width is the point.

Rules:

1. The existing device MUST refuse an `open-v2` whose recomputed commitment
   does not match the `c` it answered, and MUST abort — not continue at
   reduced assurance. Nothing but a substitution produces a mismatch.
2. Neither side may derive or display the SAS before the opening: the
   existing device has only a hash when it chooses its ephemeral.
3. Every field the certificate binds — `deviceEdPub`, `deviceXPub`,
   `deviceId` — is in the SAS input, so a substitution of any of them is
   visible as different digits on the two screens.
4. A v2 client transacts only on v2 mailboxes. It MAY hold its v1 mailbox
   open in order to *recognise* an older peer (a v1 `hello` arriving there)
   and say so, and MUST NOT answer it: detecting an old peer must not turn
   into completing the old ceremony.
5. Both users MUST compare the SAS before the existing device sends
   `enroll-v2`, and the new device MUST check the certificate as in §10.
6. Every fixed-width field of every frame — `c`, `ephx`, `ded`, `dx`, in
   both ceremonies — MUST decode to exactly 32 bytes, and `id` MUST be a
   non-empty string of at most 64 characters, or the receiver MUST abort
   before hashing anything. A 31-byte key and a one-byte-longer id
   concatenate to the same bytes as the honest opening; only the width tells
   them apart (a relay could shift that byte until 2026-09-17, and both
   screens agreed while the host certified a 31-byte ratchet key that every
   contact then refused).

Vectors: [`vectors/pair-v2/`](vectors/pair-v2/). §10's remain untouched.

## 11. Groups

A group is **pairwise fan‑out over the existing 1:1 sessions**: there is no
group key. Every group message is encrypted separately to each member (and
sealed to each of their devices), so group traffic inherits the forward secrecy,
post‑compromise healing and sender authenticity of §5, and the relay cannot
tell group messages from direct ones.

* `gid` is `"g" || b64url(12 random bytes)` — the letter `g` and exactly
  sixteen characters of the base64url alphabet. A receiver **MUST** refuse a
  `ginvite` whose `gid` is not that shape, because the id is chosen by the
  sender and is also the **thread key**: an implementation that files messages
  under it, and decides that a conversation is a group by looking it up, is
  letting a contact name the thread. A routing id is 43 base64url characters,
  so the two cannot collide — but only if the shape is checked. The reference
  client checked nothing here until 2026‑09‑13, and a contact could send a
  `ginvite` naming ANOTHER contact's routing id and take that conversation
  over: its title and membership became the inviter's to choose, and every
  warning drawn only for a 1:1 stopped being drawn. The creator is the
  group's first **owner** (§11.1).
* `ginvite` carries the full member list (verified `zc1.` bundles plus display
  names) at membership version `ver` — and, once the group's roles have ever
  changed, who may issue the next one (`owner`, `admins`, at roles version
  `rv`, §11.1). A member is an ACCOUNT: a receiver maps each bundle's
  routing id to the contact it holds for that account (any of its devices,
  as the device lists it has installed say — first come, §3.4) and to itself
  for any device of its own account, and the sender of a
  list is a member whether or not the list carries an entry for it — a
  linked device writes none for itself, since the binding signature of its
  account's root device is not its to make. A receiver applies a `ginvite`
  for a known group only under §11.1's rules; for an unknown group it
  creates it as the list describes, the sender being trusted by
  construction. Unknown members are auto‑added as contacts (unverified) so
  the receiver can decrypt from them — only once the list is accepted — and
  never one the receiver has blocked (§8.1, `adr/0024`), whom it holds as a
  member, sends nothing and takes nothing from. A
  list that no longer includes the receiver means they were removed.
* `gmsg` is accepted only from a current member of a known, not‑left group.
  With the group's timer on, it carries the timer as its `ttl` (§6.1,
  §11.2), as `gfile` does.
* `gfile` is a group attachment offer under the same rule: one file key and
  one set of chunks (§7), the offer sent to every member over their pairwise
  session and the chunks queued for every member's mailbox. A member removed
  before a send never receives the key.
* `gleave` removes the sender from the receiver's copy of the list and
  changes nothing else: not `ver`, not who issued the list held, not the
  roles (§11.1). (Before ADR 0019 the admin bumped `ver` here. With more than
  one admin that holds one list at two versions — ahead on admins' devices —
  and a co‑admin's change made before it heard of the leave is refused by
  every admin and taken by every member.) Since ADR 0030 the receiver also
  remembers it, so that a list issued before the leave reached its issuer
  does not put the leaver back; and a leave of a membership a list adding
  them back has since replaced on the receiver removes nobody (§11.2).
* A `ginvite` or `gleave` goes to each member like any other group message,
  and an implementation SHOULD record it for every recipient before sending
  any (the reference client queues it in `group_fanout`, §11's fan‑out,
  15.3): sent member by member with nothing written down, an interruption
  loses the remaining recipients, and with several admins a member that
  never gets a list can refuse every later list built on it (§11.1).
* `gsync` asks a member for what it holds for the group (§11.1). It is
  answered only to someone the answering device holds as a member (or held
  when it left), once per list it holds.
* A member may also arrive by a **group invite link** (`adr/0020`): a connect
  invite (§20) made by an admin, who adds the acceptor with an ordinary
  `ginvite` once the acceptor's go‑ahead for that ceremony (`gjoin`, §6.2,
  §20.6) arrives — and only if, at that moment, the admin may issue a list
  (§11.1). The acceptor is the
  account whose code the ceremony revealed, mapped like any member. Nothing in
  a list records how a member came, and a receiver applies it under the same
  rules as any other.

Consequences an implementer must preserve: membership authenticity rests on
the pairwise channel of an admin the receiver holds; a removed member keeps
the history they already received but every remaining member rejects anything
they send afterwards; a message reaches the members the sender's current list
names, so two members with different versions can briefly disagree — and an
admin's list issued before it heard of a leave still names the leaver, which
every device that has heard the leave reads without them, the leaver's own
staying out (§11.2; until ADR 0030 it put them back everywhere, THREAT_MODEL
R38).

### 11.1 Roles (ADR 0019)

A group has an **owner** and a set of **admins** that always includes the
owner. Any admin may add members, remove members who are not admins, and
rename. Only the owner may change `owner` or `admins` — promote, demote,
transfer ownership — or remove an admin, which takes their role in the same
list; and only from its device that holds the account root (below). Who holds
which role travels in the list itself:

* `owner` — the owner's routing id; `admins` — the routing ids of every
  admin, the owner included; `rv` — the **roles version**, which the owner
  moves on with every change to `owner` or `admins` and which nobody else
  may move. A sender names everyone else by the routing id it holds them
  under, and itself by the routing id of the device it sends from — the one
  id of it that every receiver able to take the list has already mapped,
  since it mapped the sender; its account's root id is known only to those
  holding its device list, and not to a member who adopted it from a list
  under another device's id (§18.7). A receiver maps each id in `owner` and
  `admins` as it maps member bundles (§11): to the contact it holds for
  that account, or to itself. Each MUST be 43 base64url characters, and a
  receiver MUST refuse a list in which one is not — an empty `owner`,
  mapped as an id of one's own, made every receiver its owner. All three
  are **optional** members of an existing inner kind (§14: no version
  bump). An invite carrying none is read as `owner = sender, admins =
  {sender}, rv = 0` — what it meant when a client before ADR 0019 sent it.
  A list whose `ver` or `rv` is not a whole number, or whose `name` or
  `members` is not the type §6.2 gives it, is refused too — refused, not
  failed on: a receiver that throws on it inside the step that acknowledges
  the envelope is handed it again for ever. So is a list with more than
  1 024 entries in `members` or in `admins`: more than the reference relay
  can carry at all (its frame cap admits a list in the 262 144‑byte bucket
  at most, fewer than 900 member entries even with empty names), and a
  bound on what one list costs a receiver — a signature check per entry,
  again for every list held back each time the held list changes.
* A sender therefore writes them only when they say something their absence
  does not: the **owner** of a group whose roles have never changed (it is
  the only admin and `rv` is 0) leaves all three out, so its lists are byte
  for byte what a client before ADR 0019 sends, and the relay sees the
  envelope it always saw — but for §11.2's timer and positions, which say
  something of their own. Every other list carries all three — the owner's
  too, once `rv` has moved, even if the admins are back to the owner alone,
  since an omission would read as `rv` 0. Receivers need no rule for this:
  anyone else who leaves them out is claiming "I own the group and am its
  only admin, at roles version 0", which the rules below refuse exactly as
  they refuse that claim written out — stale where `rv` has moved, held back
  where it has not, the sender not being in the admin set held.
* Lists are ordered by `(rv, ver, by)`, `by` being the sender. Within one
  `rv` the owner and the admins are fixed. At equal `rv` and `ver` the
  **owner**'s list outranks every other admin's; otherwise — two co‑admins
  changing the group at once, one admin on two of its devices before they
  have synced, the owner's own two lists — the one whose **digest** sorts
  first wins, whoever sent it. The
  digest is computed from the list as it travels, so every receiver
  computes the same one, however it holds the sender; the same list again
  has the same digest and changes nothing. Ranking two admins by their
  routing ids, as this section first did, could not be made to agree: a
  person's routing id is the device a receiver holds them under, and which
  ACCOUNT a contact is — what would make it agree — is known only for one
  added from a code that says so (§18.7), not for one adopted from a list.
  A co‑admin can shape a list (its name, say) so that its digest sorts
  first; that wins it a tie and nothing it could not get by issuing the
  next version. The digest is SHA‑256 over the UTF‑8 bytes of a canonical
  JSON text, written as the unpadded base64url of the 32 bytes; two compare
  as ASCII strings, in plain byte order. The text is pinned byte for byte:
  - the JSON array `[gid, name, ver, rv, owner, admins, members]`, in that
    order: each field as the list carries it, and `null` where the list
    leaves it out (a list without roles has `null` for `rv`, `owner` and
    `admins`);
  - `admins` is its strings, sorted; `members` is replaced by the `ed`
    string of each entry whose `b` is an object with a string `ed`, sorted
    — display names and the bundles' other fields are left out. Strings
    sort by UTF‑16 code unit, which for the ASCII an honest list carries is
    plain byte order;
  - no whitespace anywhere; `ver` and `rv` are JSON integers in plain
    decimal (a list whose versions are not whole numbers was refused
    above);
  - in a string, `"` and `\` are written `\"` and `\\`; U+0008, U+0009,
    U+000A, U+000C and U+000D are written `\b`, `\t`, `\n`, `\f` and `\r`;
    every other code point below U+0020, and every unpaired surrogate, is
    written `\u` and four lowercase hex digits; nothing else is escaped —
    not `/`, not U+007F, not U+2028, not anything beyond ASCII, which is
    written as itself.

  `docs/vectors/v1/inner_messages.json` (`group_list_digests`) records the
  text, its bytes and the digest for three lists, one of them needing every
  escape above; `server/test/vectors.test.js` re-derives all three from this
  section alone, in JavaScript, sharing no code with the client.
* The roles move on **one device per account**: the owner's device that holds
  the account root (§3), the one that links the others, alone promotes,
  demotes, transfers or removes an admin; the owner's other devices may
  still add, remove and rename. Two devices of one owner each opening the
  same `rv`, each with roles of its own, would leave the members holding one
  refusing every list built on the other, for good — the next roles version
  could only come from an owner the two halves no longer agree on. A
  receiver cannot tell which device of an account sent a list it was handed
  by its own other device, and does not try: an honest client never opens a
  roles version twice.
* A receiver holding the group applies a `ginvite` only if, in this order:
  1. **it is newer**, by that order;
  2. **its sender may issue one**: the sender is in the held list's `admins`
     AND a member of the held list (or is the receiver's own account, not
     having left). A demoted admin is not in the set, so a list they issue on
     the strength of an older one — including one putting themselves back —
     is refused wherever the demotion has arrived. An admin who left or was
     removed keeps the role in the list but cannot use it until an admin adds
     them back; an owner who leaves therefore freezes the admin set;
  3. **the roles are the owner's**: a list at a higher `rv` than the one held
     is accepted only from the held owner; a list at the held `rv` must name
     the same `owner` and the same `admins`, and keep every admin who is a
     member of the held list a member. The one exception is a list from the
     held list's own sender at the held list's own `(rv, ver)` when the held
     list opened that `rv`: it is that owner's other opening of the same
     roles version (two of its devices, or a modified client), ranked against
     its twin by digest rather than refused by the twin's roles — so every
     member keeps the same one of the two.
* A list failing 1 is discarded. A list failing 2 or 3 is not applied, but a
  receiver SHOULD keep it — across restarts; one per sender, that sender's
  newest; not at all from someone who is not in the group as the receiver
  holds it — and try it again whenever its held list changes: envelopes from
  different senders are not ordered, so the list it rests on — the owner's
  promotion of its sender, a leave it reflects — may simply not have
  arrived yet. Trying it later is what a later delivery would have done; a
  list that never passes is never applied. A list that passes replaces the
  held one wholesale. Nothing is merged and nothing rolled back.
* **Asking for what never arrived** (`gsync`, §6.2). Delivery is not
  guaranteed — the reference relay keeps an envelope 72 hours, in memory —
  and since roles a list that never arrives is not always healed by the
  next one: a member that missed an admin's leave holds that admin as an
  admin in the group, and refuses every list the others issue without them.
  So a receiver that refuses a list for check 2 or 3 SHOULD ask, once until
  its held list changes: the held owner — whose current list carries any
  promotion, transfer or demotion that never arrived — and every admin that
  is a member of its held list and missing from the refused one. A device
  asked answers someone it holds as a member (or held, when it left), once
  per list it holds: an admin, one that has left included, with the list it
  holds; and a device that has left with its `gleave`, after that list. The
  answer is an ordinary list from the answering account, judged like any
  other. A device never answers with a list that leaves out someone the
  list it held names: one that has since let go of someone in a group it is
  out of — the reference client does, for a contact deleted while out of
  the group or before leaving it — answers with its `gleave` alone. An
  admin that can never answer — it left, and is gone for good — leaves such
  a member where it is (THREAT_MODEL R38).
* Why `rv`, and not `(ver, by)` alone: an admin chooses whom it sends a list
  to. A co‑admin that sends its lists to everyone but the owner moves every
  member's `ver` ahead of the owner's, and the owner — never sent them — has
  no way to know. Under `(ver, by)` alone the owner's demotion of that
  co‑admin is then older than what every member holds, and is discarded
  everywhere. Ordered by `rv` first, an owner's change to the roles outranks
  any version a co‑admin has reached, and replaces what it sent.
* An admin whose own list is replaced — at any version — by one that undoes
  what its list did (a member it added is missing, one it removed is back,
  the name it gave is gone) learns that its change did not stand (the
  reference client says so in the chat) and makes it again on the list now
  held. A co‑admin's second quick change, built on its own first, is a
  version above the owner's and carries none of it: two admins are enough
  for that. Only the replacement of the admin's own list is checked: a
  change carried forward by one admin and then overtaken, at that same
  version, by a third admin's list that never saw it is not reported.
* A client from before ADR 0019 ignores `owner`, `admins` and `rv` and accepts
  lists only from whoever sent its first invite. Added by a co‑admin, it takes
  that co‑admin as its only admin and drops every list the owner sends; added
  by the owner, it drops every co‑admin's list and catches up at the owner's
  next one. This drift is accepted (ADR 0019); such builds are shown the
  version notice (ADR 0014). THREAT_MODEL R38.
* Size: a group whose roles have never changed sends exactly what it sent
  before ADR 0019. Otherwise the three members cost a fixed ~455 bytes of
  sealed envelope with three admins — one member entry — so an invite fits
  the 4 096‑byte bucket up to 6 members (7 for a group with no role changes)
  and needs the 16 384‑byte bucket from there;
  `app/test/group_roles_test.dart` 11 prints the table, for groups made with
  all their members. A member added later carries a position (§11.2), about
  ten bytes each — from five members, one 256‑byte padding block more than
  the same group made at once (`app/test/group_timers_test.dart` 9 prints
  that table too).

### 11.2 Group timers, and leaves remembered (ADR 0030)

**The group's timer.**

* `tmr`, an optional member of `ginvite`, is the group's disappearing‑messages
  timer in seconds: a whole number from 0 to 2³¹ − 1, and a list whose `tmr`
  is anything else is refused, as one whose version is not a whole number is
  (§11.1). It is part of the list, as `name` is. Whoever may issue a list may
  change it — the owner and the admins — and a change is a list at the next
  `ver`, ordered and applied by §11.1's rules like any other. A receiver
  holds the timer the list it accepts states, and a list without `tmr`
  states that it is off: every member that holds one list holds one timer.
* A sender writes `tmr` once its group has had a timer — `0` once it is
  turned off — and not before, so a group that never had one sends what it
  sent before ADR 0030.
* While the group's timer is on, every group message (`gmsg`, `gfile`) a
  client sends carries it as its `ttl` (§6.1) — on every device of every
  member, a linked device holding the list as its account does. The sender's
  copy, and its self‑sync mirror (§9), go `ttl` seconds after the message's
  `ts`; every other copy `ttl` seconds after it arrives. A receiver keeps the
  `ttl` a group message carries, whatever timer it holds itself: it is the
  sender's timer at the moment of sending, as in a 1:1 chat.
* A client from before ADR 0030 ignores `tmr`, and a group message's `ttl`.
  It keeps every group message, and what it sends carries no timer, so no
  receiver times it; and a list it issues as an admin carries no `tmr`, and
  so turns the timer off. A client SHOULD say so: in every notice of a timer
  (the reference client: "A member whose app is older than this version
  keeps the messages, and theirs do not disappear"), and of a timer turned
  off by a list without `tmr` as what happened, never as "turned off". That is the
  honest limit — the timer is a courtesy among clients that keep it
  (THREAT_MODEL R13).

**Positions, and leaves remembered.**

* A member entry MAY carry `e`, `[rv, ver]`: the **position** of the list
  that added that member — two whole numbers within a version's bounds,
  compared as `(rv, ver)` is; a list whose `e` is not that shape is refused.
  An entry without it names someone who has been a member since the group
  was made, position `[0, 0]`. A list that adds members after the group was
  made names each of them at its own `[rv, ver]`, and every later list names
  each member at the position its issuer holds for them.
* A `gleave` carries `e`: the position of the membership it ends, as the
  leaver's own device holds it. A client following ADR 0030 always writes
  it, `[0, 0]` included; a `gleave` without it is from a client before ADR
  0030, and ends the membership the receiver holds.
* A receiver **remembers** every leave it hears, per group and account, at
  the position of the membership it ends — never earlier than a leave it
  remembered before — across lists and restarts; for someone it holds in the
  group or has known in it, and for nobody else. A leave that states an
  earlier position than the one the receiver holds the leaver at ends a
  membership that a list adding them back has replaced there, the list
  having arrived first: the receiver remembers it, and keeps them in the
  group, as a receiver that read the two the other way round does.
* A list that names someone this device has heard leave, at the position the
  leave is remembered at or an earlier one, was issued before that leave
  reached its issuer: a list that adds them back names them at its own
  position, which is later — a list is accepted only above the one held, and
  the one held named them where they left. Such a list passes §11.1's checks
  as its issuer wrote it, and is then taken for everything else, **without
  them**. Every device that heard the leave reads it so, whichever of the two
  arrived first, and they hold the same members; a device that never heard
  the leave holds the leaver until a list without them, as every device did
  before ADR 0030 (THREAT_MODEL R38). Its own sender is never read so: the
  list was taken from them because the held list has them in the group.
* The leaver's own devices remember the leave too. A list naming the leaver
  at that position or earlier is taken there as on every other device,
  without them: the group stays left, nothing is said, and the list held
  ranks the next one as everywhere else, so a list adding the leaver back
  that ranks below it does not bring them back there either. A list naming
  them later adds them back, and says by whom. A list from one of the
  leaver's own other devices can only be of the first kind — a client never
  adds its own account back — and is not taken. A device added back after
  its leave that meets a newer list from before the leave is taken out of the
  group by it, as every other device that heard the leave takes that list
  without it. A copy of the leaver's own leave, from another of their
  devices, that states an earlier position than the one a device of theirs
  holds them at is a leave of an earlier membership, as above: that device
  remembers it and stays in the group.
* So the snapshot property (§11, 15.3) holds: the rule only ever leaves a
  member out, and what a device queues afterwards, snapshotted from the list
  it holds, reaches nobody who had left by the time it heard of it.
* Deleting a contact lets go of their leave with the rest of them
  (`DATA_MAP.md`); a list still naming them may then bring them back on that
  device.

**Ranking.** Two lists at one `(rv, ver)` whose §11.1 digests are equal — the
same list, or two that differ only in what that digest leaves out, the timer
and the positions — are ranked by a second digest, the **state digest**: the
one that sorts first wins, and the same one again changes nothing. Without
it, two admins setting two timers on one list at once left every member
holding whichever reached it first, for good. The state digest is SHA‑256 of
the UTF‑8 of the compact JSON text `[tmr, positions]`: `tmr` as the list has
it, `null` where it is absent; `positions` the strings `"<ed> <rv> <ver>"`,
one for each member entry that carries `e` — the entry's bundle `ed`, then the
two parts in plain decimal, a single space before each — sorted. It is
written as unpadded base64url, and two compare as ASCII strings. Everything
in the text is ASCII. A client from before ADR 0030 compares §11.1's digest
alone, and so ranks every pair it can tell apart exactly as a newer one does:
two lists it cannot tell apart are, to it, one list.
`docs/vectors/v1/group_state.json` records the text, its bytes and the digest
for four lists — two of them the tie the state digest exists for — and a
`ginvite`, a `gleave` and a `gmsg` that carry the new members.

**Compatibility.** `tmr`, `e` and a group message's `ttl` are optional
members of existing kinds (§14): no version bump. A client from before ADR
0030 reads every list as it always did, so it still puts a leaver back from
a list issued before the leave, and the lists it issues carry no positions:
an admin on such a build adds a leaver back on its own device and on other
older ones, and on no device that remembers the leave, until an admin on a
newer build adds them back; and since it names every member at no position,
any change it makes to the group is read, on every device that remembers a
member's leave, as a list from before that leave — a member who left and
was added back is taken out by it there, their own device included.

## 12. Relay protocol

One WebSocket per device. Frames are JSON text messages. The relay is
untrusted, keeps everything in RAM only, and never learns keys, plaintext,
names or (with §8) senders.

### 12.1 Connection and authentication

```
S→C  { "t":"challenge", "nonce":b64(32 random bytes), "auth":2, "ik":1 }  // first frame; ik: §12.7
C→S  { "t":"auth", "v":2, "pub":b64(edPub), "sig":b64( Ed25519.sign(edSeed, utf8("z-relay-auth-v2:") || utf8(authority) || nonce) ) }
S→C  { "t":"ready", "id":routingId, "ik"?:b64url(16 bytes) }      // then queued frames are flushed; ik: §12.7
```

`authority` is the relay as the client dialled it: the URL's host in lower
case, with the port only when it is not the scheme's default, an IPv6
literal in brackets — which is exactly the client's own `Host` header. The
relay verifies the signature against the names **it is configured to answer
to** (`RELAY_AUTHORITIES`, plus any name its platform supplies), and **never
against the `Host` header the connection carried** — the presenter chooses
that header, so a relay that verified against it would accept a signature a
victim had been induced to make for the presenter's own name (the splice).
A relay with no names configured trusts a dialled loopback/private/`.local`
name only, and only on a connection from a loopback or private address — the
case with no machine‑in‑the‑middle boundary — and refuses anything else until
its operator lists its names. The nonce MUST be exactly 32 bytes
and is the fixed‑width last field, so the concatenation is unambiguous; a
client MUST refuse a challenge whose nonce is any other length (every relay
has sent 32 since v1.0.0). **A signature is therefore good at one relay and
no other.** Until 2026‑09‑17 the signed message was
`utf8("z-relay-auth-v1:") || nonce` — the nonce alone — so a relay the user
was induced to connect to (a pasted address, an invite, a MITM on a `ws://`
address) could open its own socket to the honest relay, present the honest
relay's nonce as its own challenge, and replay the answer: authenticated as
that device, with the `ready` flush and everything queued from then on. A
client MUST sign only the bound form, whatever the challenge says, MUST
take `authority` from the address it dialled and never from anything the
relay sends (a relay that could name the authority could name the honest
one), and MUST refuse a relay whose challenge does not carry `auth:2` (with a reason: the
relay predates the bound form) rather than fall back — a client that would fall
back on request could be asked to by exactly the relay that wants the
signature. A relay MAY accept the v1 form for clients that predate it, and
SHOULD count each one (`z_auth_v1_total`) and stop accepting it once that
count stays at zero (`RELAY_AUTH_V1=off`); while it accepts v1, a device
running a client from before the bound form is exposed as before, and one
running a client that signs it is not, since that client never produces a v1
signature. Vectors:
[`vectors/relay-auth-v2/`](vectors/relay-auth-v2/); the v1 vectors in
`vectors/v1/identity.json` stay as they were.

On a bad signature the relay sends `error{bad_auth}` and closes with code
4001. A second connection for the same routing id replaces the first, which is
closed with code 4002. Since phase 29 a relay also closes a connection that
has not authenticated and has sent no frame for its idle timeout (120 s by
default; a `ping` counts, so an anonymous sender that pings is never closed)
with code 4003, refuses a connection past its connection caps with 1013, and
drops without a close frame one whose unread output passes its send‑buffer
caps; in every case what is queued stays queued for the next connection.
Before `ready`, `push-register`, `intro` (§21.6), `ikey` (§12.7) and a
`send` whose payload is not sealed are answered with `error{not_authed}`,
`recv` and `push-unregister` are ignored, and `ping` and `ikey_get` (§12.7)
are answered; a repeated `auth` is ignored.

**Anonymous connections** (2026‑09‑11, 16.1 — a relaxation, so a compatible
extension under §14: a client that authenticates first behaves as before). A
`send` whose payload begins with `zs1.` is accepted on a connection that has
never authenticated, rate‑limited like any other frame, and acknowledged
with `sent` as usual; such a connection owns no mailbox and receives nothing.
Since 44.2 the relay treats a payload beginning with `zs2.` — `adr/0033`
§5's hybrid outer layer — exactly as one beginning with `zs1.`, here and in
§12.2, and nothing else as either; it checks neither's length. No client
sends `zs2.` before 44.7.
That `sent` reports `queued:true`, whatever became of the envelope — as
every `sent` does, on every connection, since 2026‑09‑17. `queued:false`
would say whether a routing id is online **now**, to anyone who has ever
seen that contact code, for the price of one envelope a minute; until
2026‑09‑17 only the anonymous connection was refused the answer, on the
premise that an authenticated sender was asking about its own conversation,
and an identity costs one generated key, so the premise held for nobody. A
relay MUST NOT tell any sender whether the recipient was connected: presence
is the operator's (`THREAT_MODEL.md` R1), not the sender's, and a relay
cannot tell a relationship from a stranger — a sealed envelope names no
sender, and an attributed one from a stranger is acknowledged away by the
recipient's client like anything else.
Clients SHOULD send every sealed envelope on a connection of this kind and
receive on an authenticated one, and MUST NOT fall back to the authenticated
connection for a sealed envelope when the anonymous one is down — a sealed
envelope on an authenticated connection is attributable to that connection's
identity by the relay process (`THREAT_MODEL.md` R21). The relay's `/metrics`
counts sealed envelopes that arrived on anonymous connections
(`z_sealed_unattributable_total`).

### 12.2 Frames after authentication

```
C→S  { "t":"send", "to":routingId, "id":envelopeId, "payload":string, "pow"?:b64url(16 bytes) }   // pow: only to an introduction mailbox (§21.6)
S→C  { "t":"sent", "id":envelopeId, "queued":true }               // always true since 2026‑09‑17: held until acknowledged; whether a socket took it is not the sender's to know
S→C  { "t":"msg", "id":envelopeId, "from"?:routingId, "payload":string, "ts":int, "pow"?:b64url(16 bytes), "powDay"?:int }   // pow, powDay: a stamp the relay checked (§21.6)
C→S  { "t":"recv", "id":envelopeId, "from"?:routingId }           // "I persisted it" — drop it
S→C  { "t":"delivered", "id":envelopeId, "to":routingId, "ts":int }   // attributed envelopes only
C→S  { "t":"push-register", "token":string, "platform":string }   S→C { "t":"push-ok" }
C→S  { "t":"push-unregister" }                                     S→C { "t":"push-ok" }
C→S  { "t":"intro", "pow":int }                                    S→C { "t":"intro_ok" }      // §21.6
C→S  { "t":"ikey", "ek":b64(1184 bytes), "iks":b64(64 bytes) }     S→C { "t":"ikey_ok" }       // §12.7
C→S  { "t":"ikey_get", "to":routingId }                            S→C { "t":"ikey_for", "to":routingId, "ek"?:b64, "iks"?:b64 }   // §12.7: never authenticated only
C→S  { "t":"ping" }                                                S→C { "t":"pong", "ts":int }
S→C  { "t":"error", "code":string, "id"?:envelopeId, "bits"?:int, "day"?:int }  // bits, day: pow_required only
```

`envelopeId` is 1–64 characters, chosen by the sender (*implementation note:*
`b64url` of 16 random bytes). It MUST be **fresh for every envelope**, and in
particular MUST NOT be the `mid` of the message inside it. One inner message
addressed to several mailboxes — a group fan‑out, or a mirror to your own
devices — is several envelopes, and reusing one id across them hands the relay
the recipient set directly, with none of the timing analysis R18 describes;
worse, a `mid` is plaintext to every member, so any one of them could name a
message to the operator and be told who else received it. This was the rule
from the start and the client broke it until 2026‑09‑13. `payload` is an opaque
string ≤ `MAX_ENVELOPE_BYTES` (default 1,000,000) characters; the WebSocket
frame limit is that plus 4096. Only five error codes carry `id`, because only those five are refusals OF an
envelope: `too_large`, `bad_send`, `queue_full`, `store_full` and `pow_required`. The rest
refuse a frame before, or regardless of, what it names. A client MUST
therefore treat an error without an `id` as refusing whatever it has in
flight, rather than waiting for one it can match: a connection processes
frames in order, and a send left pending on an unmatched refusal stalls every
message behind it until its own timeout. Error codes: `rate_limited`,
`bad_json`, `internal`, `bad_auth`, `not_authed`, `bad_send`, `too_large`,
`bad_push`, `unknown_frame`, and — since 2026‑09‑11, compatible extensions
under §14 —
`queue_full` and `store_full` (§12.4), each carrying the `id` of the `send`
it answers, and — since phase 37, likewise — `pow_required`, carrying the
`id`, the `bits` the recipient asks for and the relay's `day`, `bad_intro`
and `push_refused` (§21.6), and `intro_full` (§21.6) since 2026‑10‑10 — a code a relay may answer and this one no longer does (2026‑10‑15) — and, since 44.10, likewise, `bad_ikey` and `anon_only` (§12.7). A `payload` over the cap is answered `too_large` whatever else
is wrong with the frame: it is the one refusal a client must not retry, so
it is decided before the recipient is looked at. A `to` that is not a
routing id (43 characters of `b64url`) is `bad_send` — the relay will not
create a mailbox under a name the protocol cannot have produced.

**Sealed handling.** A `payload` beginning with `zs1.` (or `zs2.`, §12.1) is stored and delivered
with **no** `from` member, is acknowledged with a `recv` that omits `from`,
and produces no `delivered` frame. Any other payload is stamped by the relay
with the authenticated sender's routing id (`from`), acknowledged with `recv
{id, from}`, and, once acknowledged, produces a `delivered` receipt routed to
the sender (queued if offline).

**What an `id` identifies.** An `id` is the sender's choice, so it names an
entry only together with the party the entry belongs to. Two senders may pick
one id for one recipient and both envelopes are kept and delivered; one group
message is one id sent to each member, and each member's acknowledgement
produces its own `delivered` receipt for the sender, so a sender in a group
of three receives three. A repeated `send` of an id the sender has already
used for that recipient is the same envelope arriving twice — a retry after a
lost `sent` — and is answered `sent` without being queued again. For a sealed
envelope the relay has nothing to tell a retry from a second envelope that
happens to share an id, so it keeps both (up to `ID_SLOTS`, 8, per id per
mailbox, after which a further one is refused `queue_full`) and the client
drops the duplicate on the inner `mid` (§6.7) — the safe side of a guess the
relay cannot make.

### 12.3 Push

`push-register` stores an opaque token (≤ 4096 chars) for the routing id for
`PUSH_TTL_DAYS` (30) days from its last registration, in every coordinator. When a `send` is queued because the
recipient is offline, the relay sends the token a **content‑free** wake signal
("you have mail"): no sender, no id, no payload. Retired tokens are deleted.
An introduction mailbox (§21.6) holds no token and is never woken.

The relay answers both push frames with the same `push-ok` and may handle
frames concurrently, so a client SHOULD keep one push frame in flight at a
time and count it done only on that answer; a withdrawal not yet answered is
said again on the next connection (phase 41). The reference client registers
only while the user allows notifications, and withdraws when that changes.

A relay that runs as several instances MUST NOT treat having handed an
envelope to another instance as a delivery: the publish says the message bus
accepted it, not that a socket received it, and the instance that sent it
cannot see the difference. The envelope is held until it is acknowledged
either way — which is what the wire now says in every case — and treating
it as held is what makes the wake signal fire in the case where the
recipient turns out not to be connected after all. Such a relay MUST also deliver again, on its own, to a
socket it holds whose mailbox has stopped emptying; without that, an envelope
whose live push was lost waits for the recipient to reconnect, which a
connected client has no reason to do, and the floor is `QUEUE_TTL_HOURS`.

### 12.4 Limits

Per connection: a token bucket of `RATE_PER_SEC` (80) frames/s with burst
`RATE_BURST` (240); excess frames get `error{rate_limited}`. A small `recv`
that **frees an envelope** is exempt (2026‑09‑11): a device draining a
backlog acknowledges as fast as it persists, such an acknowledgement costs
the relay one small read and one small removal while returning memory, and a
limited one was simply dropped — the entry it named stayed queued and a
mailbox of more than the burst could not be emptied in one connection. A
`recv` that matches nothing in the sender's own mailbox is charged like any
other frame (2026‑09‑12): it frees nothing, and the exemption had made a
flood of them free. The relay counts them (`z_ack_miss_total`). The charge
is applied after the lookup, so a burst that arrives in one read is charged
in arrears — the bucket goes into debt and the socket is refused until it
refills; what the limit bounds for acknowledgements is the rate, not the
burst — so a relay MUST ALSO bound how many exempt acknowledgements one
connection may have outstanding at once (`ACK_IN_FLIGHT`, 256) and charge
beyond that. Without it the rate is bounded and the burst is not: every
acknowledgement arriving in one read passes the gate before any of them is
charged, and one that matches nothing is the most expensive frame the relay
serves. The bound is well above what a device draining a paged flush has
outstanding (`FLUSH_PAGE`, 64), which is the case the exemption exists for.
Per recipient
queue: `MAX_QUEUE_MSGS_PER_USER` (5000) envelopes and `MAX_QUEUE_BYTES_PER_USER`
(64 MiB, each envelope charged at its payload length plus 256). A `send`
that would take the recipient's queue past either cap is **refused** with
`error{queue_full, id}` and nothing is queued for it; what the queue already
holds is never evicted to make room. The sender keeps the envelope and tries
again later — the queue empties when the recipient next drains it — and a
client that does not know the code treats it as it treats any transient
relay error, which is the right reading. (Until 2026‑09‑11 the relay
evicted the *oldest* queued envelope instead, silently and after having
acknowledged it with `sent`, so anyone holding a routing id could erase what
was queued for it by flooding; a flood now fills a queue and is refused from
then on, and `/metrics` counts the refusals, `z_refused_total`.) Multiple relay instances may share
queues and presence through Redis, where the byte cap is a counter kept
beside the list and settled in the same atomic script as every push and
removal; the frame protocol is identical.

**Expiry is per entry**, `QUEUE_TTL_HOURS` (72) from the moment the relay
accepted it, in both modes: the relay drops what has outlived it from the
head of each mailbox at every flush and from a sweep every
`SWEEP_INTERVAL_SECONDS`. In Redis mode until 2026‑09‑12 the lifetime sat on
the mailbox's keys instead and every new envelope refreshed it, so a mailbox
that kept *receiving* — an abandoned account whose contacts keep writing —
held its oldest envelopes for as long as anything arrived, up to the cap.
A mailbox nothing is pushed to still expires whole, as it did.

**The store itself full** (Redis mode; the reference deployment runs the
store with `noeviction`, so it refuses writes rather than evicting a queue
whose sender was told `sent`). A `send` the store has no room for is
answered `error{store_full, id}`, promptly; the sender keeps the envelope
and retries later, since the condition is temporary — it ends as mailboxes
are drained. Everything that reads or frees is still served: a client that
connects while the store is full still gets `ready` and its queued
envelopes, and its `recv`s still remove them (the relay's removal script
is flagged to run when memory is short, and its push script to be refused
up front — Redis 7 or Valkey). What such a login loses until the store has
room again is only its presence record, so envelopes for it from another
instance are queued rather than pushed live until the relay's next
successful heartbeat write; the instance it is on serves it live from its
own knowledge regardless. The relay counts refusals of this kind
(`z_store_full_total`) and reports sockets whose presence write is pending
(`z_presence_stale` on `/metrics`; until phase 29 `/health` `presenceStale`).

### 12.5 Delivery semantics

1. `send` → the relay enqueues the envelope in the recipient's RAM queue and,
   if the recipient is connected, pushes `msg` immediately; it replies `sent`.
2. The envelope stays queued until the recipient sends `recv` (meaning it is
   safely in the recipient's encrypted local store). On (re)connect the whole
   queue is flushed again, so delivery is **at‑least‑once** and receivers
   deduplicate (§6.7). A client MUST NOT `recv` before persisting. A `recv`
   that names nothing the mailbox holds is not an error — the relay may
   already have removed the entry — and is answered with no frame at all.
   A relay MUST apply to `recv` the same bounds it applies to `send` on the
   two fields that become store keys — `id` at 64 characters, `from` the
   shape of a routing id — and MUST refuse a frame that breaks them the same
   silent way, so a client cannot tell a refused acknowledgement from one
   whose entry had already gone.
   One case of at-least-once is worth naming because it is not obvious:
   `ready` is sent *before* the mailbox is flushed, so that a client is not
   kept waiting on a 64 MiB backlog to learn it is authenticated, and an
   envelope that arrives in that window may be both delivered live and
   picked up by the flush that is still starting. A client that begins
   sending the instant it is `ready` should therefore expect a duplicate,
   as it must for any other redelivery.
3. A `recv` of an attributed envelope produces a `delivered` receipt for
   its sender, once, and receipts are per acknowledger: they do not merge or
   displace one another, so a group message of one id acknowledged by three
   members gives the sender three `delivered` frames with three different
   `to` members (see §12.2, "What an `id` identifies"). A receipt for an
   offline sender is queued like any other entry, and is removed by the
   flush that delivers it rather than needing an acknowledgement of its own.
   A receipt the recipient's queue has no room for is dropped rather than
   refused: it is a tick, not mail.
4. A flush of a large backlog is **paged**: the relay sends at most
   `FLUSH_PAGE` (64) entries *or* `FLUSH_HIGH_WATER_BYTES` (1 MiB) of
   bodies, whichever comes first, and waits until the socket has drained
   below that mark before continuing — so what it holds for one slow reader
   is the mark plus the one envelope that crossed it, rather than the whole
   backlog (up to 64 MiB). Both bounds are needed: an envelope may be
   `MAX_ENVELOPE_BYTES`, so 64 of them are 64 MB, which is the backlog again
   (see PERFORMANCE, "What a reconnect costs the relay"). Two consequences
   for a client. A live `msg` may arrive *between* pages, so the flush is
   not ordered against traffic that
   arrives during it — which changes nothing a client may rely on, since
   delivery was already at‑least‑once and unordered across reconnects. And
   a flush that is interrupted (the socket closes) simply stops: nothing was
   acknowledged, so the next connection flushes the same queue again.
5. Undelivered envelopes vanish on expiry or on relay restart — never to
   make room for another envelope (§12.4). Availability is explicitly not a
   security property of the relay.

### 12.6 HTTP endpoints (informative)

`GET /health` (liveness only — `ok`, `coordinator`, `storage`, `push`, and no
counter or instance id), `GET /metrics` (Prometheus, aggregate only — no
per‑user data; requires `Authorization: Bearer <METRICS_TOKEN>`, and answers
404 when no token is configured, since even aggregate counters are a presence
oracle — P1‑14), `GET /` and `GET /privacy` (static pages).

### 12.7 Introduction keys at the relay (44.10; `adr/0033`, addendum A)

*Built in 44.10, and inert: **no client publishes or fetches an introduction
key before 44.11–44.12, and no client sends `zs2.` before 44.7**. A relay
that runs this keeps nothing until a client publishes, and an older one is
never sent these frames.*

A relay may keep, for each mailbox, the **introduction key** its device
publishes (§8.3): the device's sealing key `ek` and `iks`, its signature by
the key the mailbox is the hash of. It says so in every challenge, and names
the entry it holds for a connection's routing id in that connection's
`ready`:

```
S→C  { "t":"challenge", "nonce":…, "auth":2, "ik":1 }                       this relay keeps introduction keys
S→C  { "t":"ready", "id":rid, "ik"?:b64url( SHA-256(ek || iks)[0..16] ) }     the entry it holds for rid, if any
C→S  { "t":"ikey", "ek":b64(1184 bytes), "iks":b64(64 bytes) }              a connection authenticated with v2; its own routing id
S→C  { "t":"ikey_ok" }
C→S  { "t":"ikey_get", "to":rid }                                            a connection that never authenticated
S→C  { "t":"ikey_for", "to":rid, "ek"?:b64(1184 bytes), "iks"?:b64(64 bytes) }   both, or neither
S→C  { "t":"error", "code":"bad_ikey" | "anon_only" }                        neither carries an id
```

**Publishing.** A device sends `ikey` on its authenticated connection after a
login whose `ready` does not name its entry — the first time, and after the
relay has lost it — and only to a relay whose challenge said `ik:1`. The
frame names no routing id: the entry is for the routing id the connection
authenticated as, and only the bound form counts, so `ikey` on a connection
that has not authenticated, or that authenticated with v1 — a signature
another relay can have drawn out of the device (R33) — is answered
`error{not_authed}`. The relay checks that `ek` and `iks` are the canonical
`b64` of 1 184 and 64 bytes and that `iks` verifies under the key the
connection authenticated as, over `utf8("z-intro-key-v1:") || that key ||
SHA-256(ek)`; anything else is refused `error{bad_ikey}` and nothing is kept.
It checks nothing more of the key: the modulus check is the sender's (§8.3),
whatever the relay did. A taken entry is answered `ikey_ok`. One that
replaces the entry held for that routing id takes its place and renews
nothing. `ikey` frames are paced at `IKEY_PER_RID_PER_MIN` (6) a minute per
routing id, every frame counting, and — only where `CLIENT_IP_HEADER` names
the client's address — new entries at `IKEY_NEW_PER_IP_PER_MIN` (10) a minute
per address, a replacement not counting; past either the frame is answered
`error{rate_limited}` and the entry held stays as it was. A store with no
room for a new entry answers `internal`, and the device publishes again at its
next login.

**Fetching.** `ikey_get` is taken only on a connection that never
authenticated — the one the envelope it is for will be sent on, immediately
before it (§8.3) — and is answered `ikey_for`, carrying both halves of the
entry held for `to` or neither. The answer for a mailbox the relay has never
seen is the answer for an owned one that keeps no key. On an authenticated
connection `ikey_get` is answered `error{anon_only}` whatever it names, and
counted: asked there, the fetch would name the asking device beside the
mailbox (`adr/0007`). A `to` that is not a routing id (§12.2) is answered
`error{bad_ikey}`. The relay keeps no record of fetches — no address, no
routing id, no time — beyond the counts below; they are paced as any frame is
(§12.4).

**The store.** Public keys only, RAM only, and nothing about who asks:

```
RAM     ikeys: rid → (ek || iks, at)   a store of its own: IKEY_CAP (20 000) entries, the least recently authenticated forgotten first
Redis   ik:{rid} = ek || iks           1 248 bytes, raw; its TTL renewed with owned:{rid} at each login, and kept by a re-publish
        ik:epoch                       a random value an instance holding copies sets when it finds none; a store that comes back empty has none
```

A new entry lives `OWNED_TTL_DAYS` (30) from its publish, which follows the
login it rides on; each later login of its routing id renews it, as it renews
`owned:{rid}`; a re-publish renews nothing. So a device offline for days keeps
its key at the relay, and only a month without a login, the cap or a lost
store removes it. Past `IKEY_CAP` a new entry is taken and the one whose
routing id authenticated least recently is forgotten for it — in a shared
store, at the sweep, the entry with the least life left — never refused, so
whoever fills the store cannot keep a device's key out of it. In a shared
store each instance also keeps a copy of the entry of every socket it holds,
and its heartbeat puts those back — with the life each had left, and only
where the store holds none — when it finds `ik:epoch` gone or changed.

**What a restart does.**

| Event | Entries | First contacts meanwhile |
|---|---|---|
| A RAM relay restarts (every deploy, and a free plan's sleep) | all lost, with the queues | Every connected device logs in again, finds its entry unnamed in `ready` and publishes. A device that was offline publishes at its next login. Until then a promised route waits (§8.3, `adr/0033` A4) and the rest go classical, marked |
| An instance of several restarts (a rolling deploy) | kept, in the shared store | nothing changes |
| The shared store restarts (persistence off) | all lost | each instance's heartbeat puts back the entries of the sockets it holds; offline devices as above |
| Eviction past `IKEY_CAP` | the least recently authenticated | as an offline device after a restart |

Nothing is written to disk, and a seized machine holds no key and no list of
mailboxes. `/metrics` counts publishes taken (`z_ikey_published_total`),
answers with an entry and with none (`z_ikey_served_total`,
`z_ikey_missing_total`), entries forgotten past the cap
(`z_ikey_evicted_total`) and fetches refused on an authenticated connection
(`z_ikey_anon_only_total`), and reports how many entries are held (`z_ikeys`).

**What the relay learns.** At a publish, that a routing id holds a sealing
key — which says its build is current, as its login and its `zs2.` traffic
already do (R2); the key is public, and each device's entry is its own,
signed by its own key, so entries cannot be grouped into accounts. At a
fetch, that an anonymous socket — an address (R21) — is about to reach that
mailbox for the first time; the send writes the same thing a moment later, on
the same socket, and a fetch that finds nothing still shows that an address
meant to reach it. The frame names the mailbox and nothing else, and
Cloudflare sees the same (R44). The relay can withhold, refuse or delay a key,
which a promised route turns into a visible wait and any other into a
classical first contact the screens record (`adr/0033` A4); it can serve a
key that fails `iks` or `sk`, which the sender refuses, or a stale one, which
amounts to a dropped envelope (R14); it cannot serve a key of its own without
an Ed25519 forgery now. An entry says its device logged in within 30 days and
since the store last lost its data, so after a loss whoever polls learns when
the device came back. A fetch must name a routing id: there is no
enumeration.

## 13. Local storage and identity backup (informative)

The app keeps all state in a SQLite vault with per‑cell XChaCha20‑Poly1305
encryption under a 256‑bit master key held in the OS keystore (optionally
wrapped by an app passphrase). Attachments are stored as separate files sealed
under per‑file keys kept in encrypted cells. Disappearing messages are swept
every 20 s.

The master key is wrapped as `XChaCha20‑Poly1305(K_wrap, master)` with
`K_wrap = HKDF‑SHA256(deviceSecret ‖ passKey?, info "z-wrap-v1")`, where
`deviceSecret` is a 32‑byte keystore secret and `passKey =
Argon2id(passphrase, salt, m = 19456 KiB, t = 2, p = 1, L = 32)` is present
only while a passphrase is set. The optional *biometric unlock* keeps that
`passKey` (not the passphrase) on the device and releases it after the OS
prompt — on Android sealed as `AES‑256‑GCM(K_hw, passKey)` under a Keystore
key that requires user authentication for every use, elsewhere as a plain
keystore entry; a new salt on every passphrase change makes an old
`passKey` fail closed. The *screen lock* is a UI gate over the open vault
and changes nothing here. An identity backup (`.zid`) is:

```
inner = JSON{ "v":1, "identity":{ "edSeed":b64, "xSeed":b64 }, "name":string, "contacts":[...] }
key   = Argon2id(passphrase, salt = 16 random bytes, m = 19456 KiB, t = 2, p = 1, L = 32)
file  = JSON{ "z":"backup", "v":1, "kdf":"argon2id", "m":19456, "t":2, "p":1,
              "salt":b64, "nonce":b64(24 bytes), "ct":b64, "mac":b64 }      // XChaCha20Poly1305(key, nonce, ∅, inner)
```

A `.zid` contains identity and contacts only — never messages. The `.zbk`
archive that replaced it (`BACKUP.md`) contains every message and attachment
too, sealed under a recovery code, and since format 1.1 the state the account
needs to resume: its own device list and every (version, fingerprint) it knows
it issued, its linked devices, each contact's list and signature floor, the
log's head, and the ids — never the keys — of past sessions, which a restored
device holds as retired (§4) so a kept opening envelope cannot re‑create one.

What a restore looks like on the wire is a device‑list update, never a
rollback. The first start of a restored root, before it sends anything, asks
the log what the account has published (§19.5) and signs its list at
**max(the log's latest version, the archive's) + 1** over the devices the
archive knew that the newest list still names; versions in between that open
and verify as the account's list are recorded as its own (§19.8). A restored
linked device signs nothing: it adopts the account's newest list if that list
names it, and otherwise reports that it was removed (§3.6). Contacts see a
higher version from the same account, as after any link; the log sees the
next version. `adr/0025` records the decision.

## 14. Versioning and the v1 freeze

Every code (`zc1.`, `zc2.`), envelope (`zs1.`), payload (`v`) and context
string (`…-v1`) carries a version. Compatible evolution — new inner kinds, new
optional JSON members, new relay frames — is allowed without a bump: receivers
ignore what they do not know. Anything that changes bytes an existing
implementation would compute differently (a KDF label, a padding rule, a
signing input, a header encoding, an AEAD, a bucket list) is a **protocol
version bump**: it gets new context strings/prefixes, a new
`docs/vectors/v2/` directory generated alongside the untouched v1 vectors, and
a "v2" section in this document; v1 vectors are never edited. The freeze test
(`protocol/test/vectors_test.dart`) makes an accidental change fail CI.

## 15. Test vectors

`docs/vectors/v2/` holds the v2 suites `mlkem768` (ML‑KEM‑768 known answers,
including implicit rejection) and `pq_ratchet` (the §17 upgrade transcript);
`docs/vectors/v1/` holds one JSON file per v1 suite: `identity`, `handshake`,
`ratchet` (a complete two‑party transcript with three DH ratchet steps and an
out‑of‑order delivery), `sealed_sender`, `attachments`, `multidevice`,
`pairing`, `inner_messages`, and `device_pop` (§3.1's proof of possession, a
compatible extension in a file of its own). A suite may gain vectors for a compatible
extension (a new inner kind, say); existing vectors are never changed. Byte
strings are lowercase hex; wire strings
(codes, envelopes, payloads) are given verbatim; every random draw the
reference implementation made is recorded (`random_draws`, `*_seed`, `nonce`)
so any implementation can replay a vector exactly. `docs/vectors/kt/` pins
the transparency log (§19.11) on the same terms, and `docs/vectors/intro-key/`
the introduction key (§8.3, §12.7). See
[`vectors/README.md`](vectors/README.md) for the file layout and how to run
the verifiers. The vectors were produced by `protocol/tool/gen_vectors.dart`
with the library's RNG replaced by a seeded splitmix64 DRBG (the standard
known‑answer‑test technique); production builds have no such hook exposed.

## 16. Security considerations (summary — see THREAT_MODEL.md)

* **Trust is established out‑of‑band.** A contact code or account code
  substituted before it reaches the user substitutes the identity; safety
  numbers (§2.5) are the detection mechanism. There is no key directory to
  trust — and, as yet, no public key‑transparency log to catch a substituted
  one, though device‑list transparency by gossip (§3.6) already makes silent
  device enrolment, split views and silent removal detectable.
* **The relay sees transport metadata.** IP addresses, timing and padded
  sizes of envelopes and which mailboxes are read are visible transiently and
  are not stored. Sealed sender (§8) removes the sender; size buckets blunt
  length analysis; nothing here hides that a mailbox is active.
* **Sealed sender is unauthenticated by design** (§8); the inner layer
  authenticates. A relay can therefore inject garbage that costs the recipient
  a failed decryption — a denial‑of‑service, not a confidentiality issue.
* **Group membership is admin‑asserted** over an admin's authenticated
  channel (§11) — the owner's, or a co‑admin's the owner promoted (§11.1);
  there is no cryptographic group state, so no post‑compromise security
  beyond the pairwise sessions' own.
* **Device lists are account‑signed** (§3.4). A compromised account seed can
  enroll devices; revocation is a new list at a higher version and reaches
  contacts only when they next receive it.
* **Endpoints are trusted.** Disappearing messages and local encryption are
  conveniences against a lost device, not defences against a compromised one.
* **`legacy` records** (§3.1) are verified under the v1 binding rule; they
  cannot be used to introduce an unsigned device (this closed an audit‑prep
  finding in the pre‑freeze code, which accepted the flag at face value).

---

## 17. Protocol v2 — post‑quantum hybrid

### 17.1 Goal and shape

v1 rests entirely on X25519. An adversary that records traffic today and later
obtains a cryptographically relevant quantum computer recovers every `SK`,
every DH ratchet step, and therefore every message ("harvest now, decrypt
later"). v2 mixes an **ML‑KEM‑768** shared secret into the Double Ratchet's
message keys, established once per conversation during the first round trip:

```
offerer       : generates an ephemeral ML‑KEM‑768 key pair (seed d||z, 64 bytes) and sends ek
                INSIDE the ratchet as an inner message of kind `pqek` (§6.2)
encapsulator  : (c, K) = ML‑KEM.Encaps(ek); carries c in the ratchet header of its messages
                until the peer has shown it holds K
offerer       : K = ML‑KEM.Decaps(dk, c); erases dk
both          : for every message whose header carries `"pq":1`:
                    mk' = HKDF( ikm = mk, salt = K, info = utf8("Z-PQ-MK-v2"), L = 32 )
                and mk' replaces mk in §5.3 / §5.4 (nothing else in the ratchet changes)
```

Roles are fixed per pair, independent of who opened the DH session: the
**designated initiator** of §4 (the lower routing id) encapsulates; the other
party offers.

`K` belongs to the **session**, not to the pair. Two sessions of the same pair
can be alive at once — the double‑initiation race of §4, and a peer that
restored from backup and opened a fresh one — and their eras are independent:
a session negotiates its own `K` from generation 0, and a generation counter
shared across sessions could not describe both. Mixing one session's `K` into
another session's message keys makes those messages undecryptable, which is
exactly what a restore would otherwise cause. A newly opened session therefore
starts classical and re‑runs §17.3 on its own, while the session it replaced
keeps the secret of its own era for as long as it is retained.
`resetSessions` discards the sessions and their secrets together.

### 17.2 Header extension

The canonical header of §5.3 gains two optional members, appended in this
order **only when present**, so a header without them is byte‑identical to v1:

```
hdrBytes = utf8( '{"dh":"' || b64(dhsPub) || '","n":' || decimal(ns) || ',"pn":' || decimal(pn)
                 || [ ',"pq":1' ] || [ ',"pqg":' || decimal(g) ] || [ ',"pqct":"' || b64(c) || '"' ] || '}' )
JSON  h = { "dh", "n", "pn", "pq"?:1, "pqg"?:g, "pqct"?:b64(c) }
```

`pq:1` means "this message key is mixed with K". `pqg` (7.5b) is the
post‑quantum *generation* K belongs to; it is emitted only when `> 0`, so a
first‑generation header is byte‑identical to the original v2 encoding. `pqct`
is the 1088‑byte ML‑KEM‑768 ciphertext; being part of the header it is
authenticated by the AEAD, so it can be neither swapped nor stripped in
transit.

### 17.3 State machine

Per session: `dkSeed` (offerer, pending), `K`, `c` (encapsulator, until
acknowledged), `acked`, `offered`.

* **Offerer**, on the first successful decryption from the peer or before its
  own first send, and while `K` is unknown and no offer has been made:
  generate `(ek, dk)` from 64 random bytes, keep the seed, send
  `{"k":"pqek","mid":…,"ts":…,"alg":"ML-KEM-768","ek":b64(ek)}` as an ordinary
  inner message (encrypted, padded, authenticated like any other; a v1 peer
  ignores the unknown kind).
* **Encapsulator**, on decrypting a `pqek` while `K` is unknown: verify
  `alg`, `len(ek) == 1184`; `(c, K) = Encaps(ek)`; from now on every message
  it sends is mixed and carries `"pq":1`, plus `pqct` until `acked`.
* **Offerer**, on a header carrying `pqct` while `K` is unknown: if no
  `dkSeed` is pending → reject; else `K = Decaps(dk, c)`, erase `dkSeed`,
  then decrypt the message under the mixed key. A wrong or tampered `c`
  yields (by FIPS 203 implicit rejection) a pseudorandom `K` and the AEAD
  fails: reject, state untouched — including the pending `dkSeed`.
* **Either side**, on successfully decrypting a message with `"pq":1`:
  `acked = true` (the peer provably holds `K`); the encapsulator then stops
  attaching `pqct`.
* A message with `"pq":1` arriving whose generation's secret is unknown is
  rejected. Skipped‑key handling is unchanged: cached keys are classical `mk`;
  the mix is applied at use according to that message's own header (and its
  generation).

Generation 0 omits `pqg` and is the whole of the state machine above without
periodic re‑keying (§17.7).

### 17.4 Compatibility and negotiation

No unauthenticated capability flag exists. The offer is inside the ratchet
(a v1 peer discards it as an unknown kind and nothing else changes); the
ciphertext is sent only by a party that has received an offer, and `pq:1`
only by a party that holds `K`. Hence v2↔v1 in either direction stays exactly
v1, and an active network attacker cannot force a downgrade **by tampering**:
the offer is encrypted and authenticated, `pqct` is in the AAD, and stripping
either only produces an authentication failure.

Withholding is a different attack and this paragraph used to answer it as
though it were the same one. A relay need not modify anything to stop an
offer arriving — it can decline to deliver the envelope, which every relay can
always do and which is indistinguishable, from both ends, from a peer who was
briefly offline. The initial offer was made once per session and never again,
so one undelivered envelope left that conversation classical for its whole
life, on both sides, with nothing to show it. A client therefore MUST repeat
an unanswered initial offer after a bounded interval, and MUST repeat the
**same** encapsulation key (regenerated from the persisted seed) rather than a
fresh one, so that a late answer to the first copy still establishes. §18.2
already required this of the identity offer; it belongs here for the same
reason. The re-key offer of §17.7 is a different mechanism and is not a
substitute: it only runs once the secret is established. Both run on every
channel a client holds a ratchet on, not only its main chats (§17.8). A v2 implementation MAY be run with the
extension disabled; it then behaves as v1 (this is how the v1 vectors are
regenerated).

### 17.5 Security properties and limits

* Every message with `pq:1` is confidential against an adversary that breaks
  X25519 later but never learns `K`. `K` is protected by ML‑KEM‑768 against
  such an adversary, and `dk` never leaves the offerer and is erased on use.
* The first messages of a conversation (the session‑opening `hello`, the
  offer itself, and anything sent before the offer is answered) are
  classical. The reference app sends the contact‑add hello and answers it
  with the offer, so in the normal flow most of what the user types is mixed
  — but not all of it: a message typed before that round trip completes (to
  a peer who is offline, say) goes out before any offer exists, and the
  offerer's own messages are classical until the answer reaches it.
* Generation 0's `K` is established once. Left there it is static for the
  conversation's life; §17.7 adds periodic re‑encapsulation so a device state
  stolen at one generation does not keep the next generation's secret
  (post‑quantum post‑compromise security). Classical PCS from the DH ratchet
  is unchanged throughout.
* The initial `SK` (§4) stays classical; a quantum adversary recovers the
  classical `mk`s, which is why the mix is applied to message keys rather
  than relying on the root chain.
* ML‑KEM in pure Dart is best‑effort constant‑time. In this hybrid a timing
  leak in the KEM can at worst reduce security to v1, never below it.

### 17.6 Vectors

`vectors/v2/mlkem768.json` — ten seeded `(d, z, m)` known answers with
`ek, dk, c, K` and an implicit‑rejection pair; `vectors/v2/pq_ratchet.json`
— a nine‑step transcript (classical hello, offer, encapsulation, first mixed
message with `pqct`, mixed reply, steady state) with every random draw;
`vectors/v2/pq_rekey.json` — a fifteen‑step re‑key transcript (§17.7): the
generation‑0 establishment, a rotation to generation 1 (second offer,
encapsulation, `pqg:1`), a delayed generation‑0 message that still decrypts,
and the retained old secret. The KEM values are re‑derived by kyber‑py
(`protocol/tool/verify_mlkem.py`); each transcript, taking `K` and `c` from
the file, is replayed byte‑for‑byte by the Node verifier.

### 17.7 Periodic re‑key (post‑quantum PCS)

Left at generation 0, `K` is static, so a device state captured once protects
nothing sent afterward against a *quantum* adversary. The offering side
therefore rotates the ML‑KEM secret on an interval (the reference app: seven
days), giving the post‑quantum layer the post‑compromise healing the DH
ratchet already gives the classical layer.

A generation counter `g` starts at 0. The offerer, once established and the
interval has elapsed, makes a fresh offer carrying `"g":g+1`:
`{"k":"pqek",…,"alg":"ML-KEM-768","ek":…,"g":g+1}` (the `g` member is omitted
for the generation‑0 offer, keeping it byte‑unchanged). The encapsulator, on
a `pqek` whose `g == gen+1`, encapsulates a new `(c′, K′)`, **retains the
current `(gen, K)` as the previous generation**, sets `gen = g+1`, and from
then on sends `pqg:g+1` with `pqct = c′` until re‑acknowledged. The offerer,
on a header with `pqct` for a generation it does not yet hold, decapsulates,
likewise retains the outgoing generation, and advances. During the crossover
each side holds two secrets, so a message still in flight under the old
generation (identified by its own `pqg`) decrypts against the retained secret;
a message tagged with a generation neither current nor retained is rejected
(fail‑closed). One previous generation is retained, and only for as long as
reordering needs it (below). Everything is a compatible
extension: `pqg` is a new optional header member and `g` a new optional offer
member, both ignored by a generation‑0‑only implementation, no version bump.

**A re‑key offer nobody answers** (26.2). The next re‑key waits for an answer
to the one outstanding, and until 26.2 nothing ever made that one again — so a
single offer the relay did not deliver (the peer offline across the relay's 72
hours, or one drop) froze re‑keying for the life of the session. The offerer
therefore:

* says the outstanding offer again on the retry interval of §17.4, with the
  **same** key, regenerated from the persisted seed — not before the interval,
  and once per interval;
* **abandons** it once it has gone one whole re‑key interval unanswered while
  the peer has been heard on that session (at the old generation, or it would
  have been answered): it generates a fresh key and offers it for the **same**
  generation, since an encapsulator accepts only `g == gen+1` — every
  encapsulator ever shipped included. It keeps the abandoned key's seed: the
  peer encapsulates to whichever copy reaches it first and ignores the rest,
  so an answer to an abandoned key can still arrive. On a `pqct` for that
  generation that does not open under the pending key, the offerer tries each
  abandoned key, newest first (implicit rejection leaves only the AEAD to say
  which key was used), and erases every one of them with the pending key once
  the generation is established. At most 16 are kept, oldest dropped first,
  which is margin: a key is abandoned only while the peer is heard at the old
  generation, and a peer that has taken any copy answers on everything it
  sends from then on.

A peer that is silent is offered the same key again, never a fresh one — a
fresh key would not reach a peer that is not there either. Nothing here
changes the encapsulator, which takes the first offer for `gen+1` that reaches
it, so a peer of any version interoperates; an offerer from before 26.2 simply
never says its offer again, as before.

**How long the previous generation is kept** (26.2). It used to be kept until
the next re‑key overwrote it — a week, so a stolen state read up to two weeks
back. It is kept until the peer has been seen on the new generation (a message
mixed under it has been read), and then 72 hours: a peer's outbox sends in
order per mailbox, so whatever it sealed under the old secret reached the
relay before the first thing it sealed under the new one, and the relay drops
every envelope `QUEUE_TTL_HOURS` (72) after accepting it (§12.4). After that,
nothing sealed under the old secret can still arrive, so keeping it protects
no message and only widens what a stolen state reads. A relay configured to
hold mail longer can deliver one later; it is refused as undecryptable.

**A classical message after mixing** (26.2). Once the peer has been seen
mixing on a session (a message with `pq:1` read on it), a message without
`pq:1` can come only from a downgraded peer or from a party able to derive the
classical chain keys — a quantum adversary forging messages. It is refused,
with one exception: a straggler the peer sent before it started mixing, which
can only sit at a ratchet position already skipped when the peer's first mixed
message was read. A receiver records those positions at that moment and
accepts a classical message only at one of them, once, and for the same 72
hours. An honest peer of any version never sends a classical message on a
session after a mixed one — it mixes from the moment it holds `K` — so this
refuses nothing a peer sends. The check comes after the replay check (§5.4),
so a classical message already read that a relay delivers again is reported
as the replay it is.

### 17.8 Where the clocks run (26.2)

The offer retry (§17.4) and the re‑key interval (§17.7) are properties of every
conversation, not of the main chat. A client MUST run both on every channel it
holds a ratchet on — a contact's main device, a contact's other devices (§9),
and its own other devices (self‑sync, §9) — and on a conversation rebuilt from
a snapshot after a failed write, exactly as on one loaded from storage. Until
26.2 the reference client ran them on the main chat only: everything else it
built ran with neither, so one withheld offer kept a linked‑device channel
classical for good (self‑sync among them, which carries a copy of every
message), none of those channels ever re‑keyed, and one garbage envelope from
anyone holding a contact's code rolled that chat back onto neither until the
app restarted. The protocol library now requires both wherever a conversation
is built.

**On self‑sync an offer is answered at once.** Nothing else may be said on that
channel for a long time — a device just linked has nothing of its own to
mirror — so the side that encapsulates sends a `ping` (§9) straight away, on
the session the offer arrived on (right after linking it is not always the one
the side would otherwise send on), carrying the ciphertext. The side that
offers holds `K` one round trip after offering.

**History replay waits for the post‑quantum layer.** The replay to a newly
linked device (§9, `hist`) is up to 200 texts per chat, the most valuable
thing the channel ever carries. It used to go out at once, and whenever the
root was the side that offers it went out classical: it left before the
root's own offer did. A root now sends it only when the next message on that
device's channel would be mixed — making its offer at once if it is the side
that offers — and checks that again for every batch, in the same step that
encrypts it. If the channel is not post‑quantum within 72 hours — a device
that has not completed one round trip in that time has not been online to
take the replay anyway, since anything sent to it would have expired at the
relay — the replay is **dropped**, never sent classical, and the device keeps
what reaches it from then on. The wait survives a restart.

## 18. Protocol v3 — post‑quantum identity

v2 (§17) protects **confidentiality** against a future quantum adversary: a
recording made today is not readable once a CRQC exists, because every message
key is mixed with an ML‑KEM‑768 secret. It does nothing for
**authentication**. Account keys, device keys, device certificates and safety
numbers are all Ed25519, so the same adversary could forge a device
certificate — mint a device that appears to belong to an account — without
reading a word of what it recorded. v3 closes that.

Status: everything below is written, implemented and shipping, with its wire
forms vectored in `docs/vectors/v3/`. The device set gets its post‑quantum
signature from the account's whole‑list signature of §18.9; the per‑device
hybrid certificate §18.4 first reached for is retired (ADR 0031). Nothing in
v1 or v2 changes.

### 18.1 Hybrid signatures

Every v3 signature is a pair, over **identical bytes**:

```
sign(m)   = ( Ed25519.Sign(sk_ed, m), ML-DSA-65.Sign(sk_ml, m) )
verify(m) = Ed25519.Verify(...) AND ML-DSA-65.Verify(...)
```

Both must verify. A verifier MUST NOT accept a signature carrying one half,
and an implementation MUST NOT be able to represent one: a half‑signature is a
parse error, not a value that verification can be run against and return false
for. The attack this exists to stop is a downgrade — an adversary who can
forge the classical half strips the half they cannot forge — so "false" and
"unparseable" are meaningfully different outcomes, the first being something
callers retry.

Sizes (FIPS 204 Table 2, ML‑DSA‑65): public key 1 952 B, signature 3 309 B,
secret key 4 032 B. An identity persists the 32‑byte **seed**, not the secret
key: keygen is `ML-DSA.KeyGen_internal(ζ)`, deterministic in that seed, the
same relationship Ed25519 and X25519 already have to theirs. Production
signing is **hedged** (a fresh 32‑byte `rnd`), per FIPS 204; the deterministic
variant appears only in the known‑answer vectors, since a deterministic
signature is materially easier to attack by fault injection.

### 18.2 Contact code v3 (`zc3.`)

A hybrid identity does not fit in a QR code, and scanning is how trust is
established here. A v3 account code carrying hybrid keys and hybrid device
certificates is ~7.4 KB for a single device, against a 2 953‑byte absolute QR
ceiling and nearer 800 bytes for a symbol that scans reliably.

So the code carries a **commitment** to the post‑quantum half, not the half:

```
pq_commit = SHA-256( utf8("z-pqid-v3:") || ml_dsa_public_key )     32 bytes
```

`ed`, `x` and `sig` are exactly the v1 fields with the same meanings (§2.4),
so the classical view is a v1 bundle and every existing path — routing id,
handshake, sessions — consumes it unchanged. The encoded code is ~370 bytes,
and ~500 since it signs its commitment (§18.10).

**The commitment is carried as an optional member of a v1 code, and that is
what clients emit:**

```
zc1.<base64url(json)>
json = { "v":1, "ed":…, "x":…, "sig":…, "pqc":b64(pq_commit), "name"?:string }
```

The commitment is signed by the key the code names — `pqcs`, another optional
member (§18.10, ADR 0027) — since nothing else in the code covers it.

§14 is explicit that a new optional JSON member is compatible evolution and
does **not** warrant a version bump — only a change to bytes an existing
implementation would compute differently does. The commitment changes nothing
anyone computes; it is pure addition, and a client that predates v3 reads the
classical identity and ignores it. A distinct prefix, by contrast, is a flag
day: every such client rejects an unknown prefix outright, so emitting one
would hand out codes most people cannot scan in order to convey information
they would have ignored.

An explicit form also exists and MUST be accepted:

```
zc3.<base64url(json)>          json as above but "v":3, "pqc" REQUIRED
```

A `zc3.` code without `pqc` is a downgrade attempt — it announced a version
that requires one — and MUST be refused. A `zc1.` code without `pqc` is simply
a classical identity. Clients SHOULD emit the `zc1.` form; the `zc3.` form is
specified for the case where the prefix itself must eventually signal
something.

The ML‑DSA public key is delivered **inside the ratchet**, as an additive
inner message (§6):

```
{"k":"pqid","mid":…,"ts":…,"alg":"ML-DSA-65","pk":b64(ml_pub)[,"ack":true]}
```

`ack`, when present and true, says **the sender holds the receiver's
post‑quantum key** — established against its own commitment, or held as a
candidate (ADR 0021). It is omitted otherwise, so a message without it is
byte-for-byte what earlier clients send. The reading was narrower before ADR
0021 ("established, checked against my commitment"), and widening it is safe
in both directions: a client that predates the change sets `ack` only when it
has checked a key against a commitment, so it can only ever mean the narrower
thing, which the wider reading contains; and what `ack` is *used* for — the
§18.5 rule about which number to show — asks only whether the peer holds our
key at all.

The same statement also has a message of its own, carrying no key:

```
{"k":"pqack","mid":…,"ts":…}
```

A client SHOULD send it when inbound traffic finds it holding the sender's
post‑quantum key (established or candidate) without ever having said so, and
no `pqid` of its own is going out to carry the fact in an `ack` — because the
sender's key arrived *with* `ack`, which must not be answered with a `pqid`
(below), or because the key came to be held before either side kept
candidates. It MUST be sent
**at most once per contact**, gated by state that survives a restart rather
than by a flag in memory; a `pqid` sent with `ack` discharges the same
obligation and sets the same state, so only one of the two ever goes.

That state records that the envelope was *queued*: no sender can know one
arrived. Until 26.2 a `pqack` the relay never delivered — one expiring at the
72‑hour limit was enough — left the two screens on two different numbers for
good (§18.5), while the one still waiting said they would match. So a client
holding the peer's key (established or candidate) also says so on **every**
inner message it sends, as the optional member `pqh:1` (§6.2), and a receiver
treats it exactly as a `pqack`: the next thing said converges the pair. The
`pqack` stays, for a peer that predates `pqh`.

Unlike a `pqid`, it is cheap to send: a few dozen bytes pads into the
**1 024‑byte** bucket (§8), the one read receipts, reactions and short chat
occupy, so it is not the distinctive mark on the relay's view that a 16 384
envelope is (`THREAT_MODEL.md` R17). A client that predates it ignores the
unknown kind (§6.1).

The receiver MUST check `SHA-256("z-pqid-v3:" || pk)` against the `pqc` from
the scanned code, in constant time, and MUST refuse the identity on a
mismatch. It MUST NOT fall back to treating the contact as classical: a
mismatch means the key that arrived is not the key the person in front of you
committed to. A v2 peer ignores the unknown kind, as with `pqek`.

A key that arrives with **no** commitment to check it against is kept as a
**candidate**, and is used for the safety number (§18.5) and nothing else. It
MUST NOT be treated as an identity: it does not move the assurance state
(§18.3), MUST NOT be used to verify a device‑list signature (§18.9) or any
transparency claim, and MUST NOT be carried to the account's own other devices
as an established key. A client MUST NOT let a later, different key replace a
candidate it already holds, and MUST NOT install one for a contact whose key
has already been refused: nothing distinguishes a second arrival from the
first — the ratchet authenticated both as this contact — so a swap conveys
nothing while moving a number the user may be reading aloud. Volunteering the
key to every contact stays safe, which is what matters, because holding a
commitment is the *receiver's* state and the sender cannot know it.

Until 2026‑09‑20 (ADR 0021) such a key was discarded. Because a commitment is
one‑sided, that left the two sides of an ordinary pair showing different
numbers for ever — the side that scanned a `zc3.` code on the v2 number, the
side that added the other from a classical code, by accepting a contact
request (§8.1) or from a pre‑v3 record on the v1 number — with no way to
complete a comparison and no way out but deleting the contact.

Delivery follows the first traffic, as the v2 `pqek` offer does: nothing can
be exchanged before a session exists. An opening message can also be dropped
outright — if the peer has not added us yet there is no session to decrypt it
— so a side holding a commitment it cannot yet check SHOULD re-send its own
key on inbound traffic, bounded (the reference client: three attempts per
run), and a side receiving a `pqid` **without `ack`** SHOULD answer with its
own; one **with `ack`** MUST NOT be answered, because the peer has said it
holds ours. Between them the exchange completes whichever side spoke first
and whether or not the opening message survived. Two people who have added
each other and then said nothing stay classical, correctly and on both sides,
until one of them speaks.

A `pqid` is a 16 384‑bucket envelope (§8) — the one size ordinary chat almost
never has — so every one sent is a mark on the relay's view, and two mailboxes
that each receive one within seconds have told the relay they just met
(`THREAT_MODEL.md` R17). A client SHOULD therefore send it once per reason,
not once per trigger: the reference client folds every reason that arises
within half a second — volunteering on a hello, answering a key, re-sending for
an unmet commitment — into one send that carries `ack` if the peer's key has
landed by then, sends the opening key *with* the hello so the two arrive in
one batch, waits longer before a re-send (one second; ten on the side that
opened the session, whose key went with its hello — so two re-sends do not cross) and drops a re-send whose
commitment was met while it waited. Measured, a mutual add is one envelope
each way; before this it was two.

**Multi-device rules.** An account has ONE post-quantum identity, and every
device of it must reach the same view of every contact, or the safety number
(§18.5) differs between a person's own phone and laptop — a mismatch that
reads to the user exactly like a key substitution.

* The account's ML-DSA **public** key is part of enrollment (§10, `pqpub`),
  so a linked device holds the account's key rather than deriving one of its
  own. A device enrolled by a build that predates v3 has none; it MUST show
  the classical identity rather than invent one.
* A `pqid` MUST be offered to a contact again when that contact's device list
  gains a device (§3.4). The first offer went out before that device existed
  and cannot have reached it; without a re-offer it stays classical
  indefinitely while its siblings are hybrid.
* The exchange MUST run on the non-primary device path as well as the primary
  one: a contact's linked device runs its own sessions and holds its own
  commitment, so a `pqid` arriving from one is checked and answered like any
  other.
* A device emits a commitment only when the classical identity in the code it
  hands out is the account identity the commitment binds. Where it is not —
  a linked device, whose code names its own key (§2.4) — the code is emitted
  without `pqc`. Binding one identity's post-quantum key to another
  identity's classical key would produce a code whose `sig` does not verify,
  and is the substitution the commitment exists to prevent, self-inflicted.

This is a **commitment, not a reference**. A lookup identifier — a URL, a key
id — binds nothing, and a code carrying one degrades to trust‑on‑first‑use,
where an attacker present at the exchange supplies their own ML‑DSA key and
passes every hybrid check thereafter. Security here rests entirely on the
binding, whose strength is SHA‑256 collision resistance.

**The device list is deliberately not in the code.** One certificate — for the
device showing the code — is (§18.7); the *list* is not. `zc2.` carries one as
a convenience; under v3 each certificate would be 5 389 bytes. Device lists
already reach contacts in‑band, account‑signed and verified against the
account key (§3.4), including contacts who were offline for an entire
enrollment. The code establishes the account identity — the thing a human must
confirm by looking at a screen — and the rest follows from it.

### 18.3 Identity assurance states

A client MUST distinguish three states and MUST NOT present the second as the
third:

| state | meaning |
|---|---|
| `classical` | a `zc1.`/`zc2.` code: no post‑quantum key was promised. Nothing is missing, but a CRQC could forge this identity |
| `pendingPostQuantum` | a `zc3.` code was scanned; the key is committed to but has not arrived. Authentication is classical until it does |
| `hybrid` | the key arrived and matched the commitment — or a candidate was confirmed by comparing the post‑quantum safety number (§18.5, ADR 0021), which is the same evidence by a different route |

A key that arrives and does **not** match is a fourth situation, and it is not
a state of the identity: the identity stays `pendingPostQuantum`, because
nothing was upgraded. The refusal MUST be recorded durably and surfaced, and
it MUST be announced **once** — the offer is re-made on traffic (§18.2), so a
client that announces per arrival hands whoever is sending the bad key a way
to bury the warning under copies of itself.

A **candidate** (§18.2) does not move the assurance state either. A contact
holding one is `classical`: nothing has checked the key, so nothing may be
authenticated with it. What the candidate does change is which safety number
is displayed (§18.5), and a client MUST present that distinction rather than
letting the post‑quantum number read as a post‑quantum identity — the number
is the post‑quantum one, and confirming it is what has not happened yet. The
reference client shows it under a separate, non‑success label
("Post‑quantum, unconfirmed") for exactly this reason.

### 18.4 Device certificates under v3

A device certificate is the account's statement that a device belongs to it,
so forging one inserts a rogue device into every contact's fan‑out. It is the
one thing a quantum adversary could do to this design without touching a
single recorded ciphertext, and it is what §18.1 exists for.

Devices keep **classical** keys of their own, and certificates keep the
classical form of §3.2 — the same signing input, signed by the account's
Ed25519 key. A device's Ed25519 key authenticates it to the relay and fixes
its routing id; the relay is untrusted and its mailboxes hold only sealed
ciphertext, so a forged relay authentication gains nothing a quantum
adversary would not already have. What must be post‑quantum is the
**account's** attestation, and that attestation is one ML‑DSA‑65 signature
over the whole device list (§18.9), not one per certificate, for two reasons.

**A set of individually valid certificates does not authenticate the set.**
Given a genuine list whose certificates each carried a post‑quantum half, an
adversary who forges Ed25519 presents a subset — the classical list signature
forged, every surviving certificate genuine and untouched — and an honest
device is silently excluded (`adr/0004`). Only a signature over the set
refuses that.

**Distribution is constrained, and the constraint is not obvious.** A per‑certificate
post‑quantum half is ~3.4 KB. Sealed sender pads envelopes into buckets (§8) so the
relay cannot tell one kind of message from another, and today a device‑list
update sits in the 4 096‑byte bucket alongside ordinary chat of a few hundred
characters (measured through the whole pipeline; the 1 024 bucket this
paragraph first named holds only inner messages of ~250 bytes or less — see
`adr/0004`, addendum). Certificates of this size move it to 16 384 or 65 536
— buckets almost nothing else occupies —
which would tell the relay **when an account changes its device set and
roughly how many devices it has**, from envelope size alone. That is a new
leak running opposite to the threats `adr/0001` is about, and it would be
introduced by a phase whose purpose is to strengthen authentication.

This section first specified a per‑certificate hybrid form, `{ ed, x, id, sig,
mlsig }`, with both signatures over the §3.2 input. No client ever issued or
checked one, and it is **retired** (`adr/0031`): a certificate carries no
post‑quantum member, and a device list's post‑quantum assurance comes from
the list signature (§18.9). The one certificate a contact code carries for the
device showing it (§18.7) travels outside any list and is checked classically
— a contact code is authenticated classically end to end (`THREAT_MODEL.md`
R4).

### 18.5 Safety number v2

Derived from **both halves of both account keys**, ordered as in §2.5:

```
(lo, hi) = the two accounts, ordered by Ed25519 public key
K        = HKDF( ikm = lo.ed || lo.ml || hi.ed || hi.ml,
                 salt = utf8("z-safety-v2"), info = utf8("display"), L = 60 )
```

The display rule is unchanged (twelve five‑digit groups). The salt differs
from v1's, so a v1 and a v2 number for the same pair can never coincide —
which matters because the change is visible to every user exactly once, and a
client showing the new number MUST say why rather than letting it look like a
key substitution.

As in v1 the inputs are **account** keys, so the number does not move when
either side links or drops a device.

**Which number a client shows** (ADR 0021). Both sides decide independently,
from the same two facts, and must reach the same answer — a safety number that
differs between the two screens is worse than no safety number, because it
reads as a substitution. A client shows:

* the **v2** number when it holds an established post‑quantum key for the
  contact (§18.3 `hybrid`);
* the **v2** number when it holds a *candidate* (§18.2) **and** the contact has
  said it holds ours — `ack` on a `pqid`, a `pqack`, or `pqh` on any message;
* the **v1** number otherwise, including while a candidate is held that the
  contact has not yet acknowledged, and for a contact whose key was refused.

The second condition is what keeps a mixed‑version pair on one number. A
client that predates ADR 0021 discards a key it holds no commitment for and
never acknowledges one, so a current client facing such a peer never sees the
acknowledgement, keeps its candidate out of the number, and shows the v1
number — which is the number that peer is showing. Where the older peer *did*
scan a `zc3.` code it establishes the key and shows the v2 number regardless,
and whether the two screens agree turns on whether it ever set `ack`: such a
client can say so only on a `pqid`, computing the flag at each send, so it
tells us only if one of its sends falls after our key reached it — which its
opening volunteer usually does not, and which our answer then suppresses,
because a `pqid` carrying `ack` MUST NOT be answered. When it did, the v2 number appears
on both screens together; when it did not, the disagreement stands until that
side updates. A client MUST NOT try to close that case by withholding the v2
number over an *established* key until the peer acknowledges: a pre‑0021 peer
that already holds ours will never say so, so the rule would create a fresh
disagreement in the case that works today.

The paragraph above puts the older peer on the scanning side. A current
client can be the scanner instead: it scans the code of a peer still on a
build from before ADR 0021 — 3.9.1, which Google Play was still serving in
October 2026 — and that peer accepts the request (§8.1), which carries no
commitment. The current client holds the peer's commitment, so the peer's key
is established and the v2 number shown at once, acknowledged or not, for the
reason just given. The older peer holds no commitment, so it discards our key
as §18.2 once required, shows the v1 number, and tells its user that our app
has not published a post‑quantum key. The screens disagree, and nothing a
current client may do closes it. It ends when the peer that **accepted**
updates: holding no key of ours, an updated client re‑sends its own on our
traffic (the reference client once per run, and when its user opens the
contact), our answer to that `pqid` carries `ack` because we hold its key, it
keeps ours as a candidate, and both screens show the v2 number. A pair that
was stuck while both ran a build from before ADR 0021 heals the same way: the
side that accepted is the side that must update.

**Confirming a candidate‑derived number establishes the key.** A user's
confirmation that the digits matched is the statement that the key the number
was derived from is the contact's — the same fact a scanned commitment asserts,
obtained over the same kind of channel. A client MAY therefore promote the
candidate to an established key on confirmation, after which it is `hybrid`
and usable wherever an established key is (§18.9). A planted key does not
survive this: the number fails to match, which is the outcome the ceremony
exists to produce, and the same one a classical substitution produces.

**What a client must do about the change.** A user's confirmation that they
compared numbers is a statement about a *particular* number, so a client:

* MUST record **which** number was confirmed, not only that one was. A flag
  alone cannot tell a number that has moved from one that has not.
* MUST NOT present a contact as verified once the number differs from the one
  confirmed.
* MUST distinguish the upgrade from everything else. Claiming "upgraded" is
  only justified when the confirmed number is demonstrably the v1 number for
  that pair and the identity is now `hybrid`; any other difference MUST be
  presented as unexplained. The reassuring account is the one an attacker
  benefits from, so it has to be earned rather than assumed from "different".
* SHOULD say, before the number moves, that it will — a `pendingPostQuantum`
  identity is a warning the client already has and the user does not.
* MAY carry a confirmation made by the connect ceremony (§20.4) onto the
  post‑quantum number when the key that moves it matches the commitment the
  eight digits covered — the one exception to the rule two points above.
  Those digits bound both commitments, so that comparison already covered the
  key; asking for it again made every connect‑verified contact read "compare
  again" seconds after it was verified (ADR 0027). A key the digits did not
  cover is no exception: one that misses that commitment is refused (§18.2)
  and moves no tick, and a key after a ceremony that covered no commitment
  asks for a comparison like any other.

A client upgrading from a build that recorded no number MAY record the v1
number for its existing confirmations, since that is what any such build
displayed; the worst case is a contact already at `hybrid`, which then reads
as "upgraded, compare again" — asking for a comparison rather than asserting
one, which is the direction to be wrong in.

### 18.6 The compatibility window

Because the commitment rides in a v1 code (§18.2), there is **no flag day**:
a build in the field reads the emitted code as the v1 identity it also is.
Emission was therefore switched on in the same release that added acceptance,
rather than waiting a version for the population to catch up.

What an older client loses is only what it could never have used: it does not
see the commitment, so it treats the contact as classical — which is exactly
what it would have done anyway. Nothing it does breaks, and nothing it shows
is wrong.

The `zc3.` form remains accepted and unemitted. Switching to it later is a
deliberate flag day and should only be taken if the prefix itself needs to
carry meaning.

An account's post‑quantum half is a 32‑byte seed sealed in the vault and
carried in the backup archive (§9). A restore that lost it would derive a
*different* ML‑DSA key, and every contact holding a commitment to the old one
would see a mismatch — indistinguishable, to them, from an attack. The archive
therefore carries the seed, and a contact's commitment and established key
travel with it too, so a restore does not silently downgrade every verified
contact to classical.

### 18.7 An account-anchored contact code

A contact code has always described the **device** showing it: `ed` and `x`
are that device's keys, `sig` binds them, and the routing id is `SHA-256(ed)`.
With one device per account that is also the account's identity (§3.5). With
more than one it is not, and scanning someone's laptop added the **laptop** —
their device list then failed the "signed by this contact's account key" check
of §3.4, so multi-device delivery and every §7.7a transparency guarantee that
rides on the list silently stopped working for that contact, and their safety
number was computed against a per-device key, so two people could both verify
and read different numbers.

A code may therefore name the account it belongs to, and prove it:

```
zc1.<base64url(json)>
json = { "v":1, "ed":…, "x":…, "sig":…, "pqc":…,
         "acct":b64(accountEdPub), "cert":deviceCert, "name"?:string }
```

`acct` and `cert` are **one member in two parts** and MUST both be present or
both absent — a claim without a certificate is an assertion, and a certificate
without a claim proves nothing. A verifier MUST:

1. verify `sig` against `ed` as in §2.4 (the device owns its X25519 key);
2. verify `cert` against `acct` under §3.1 — and reject a `legacy` record,
   whose rule is "the device key IS the account key", which is precisely what
   an account-anchored code is not;
3. check that `cert.ded == ed` and `cert.dx == x`. **Without this a stranger
   holding any genuine certificate of that account — they are public, they
   travel in device lists — could present it beside their own keys and be
   scanned as that account.**

The code then means: talk to *this device*, whose identity is *that account*.
`ed`/`x` remain what a session is opened with and what the routing id is
derived from, because that is the mailbox that can be reached. Everything a
human confirms — the safety number (§18.5) and the post-quantum commitment
(§18.2) — is anchored to `acct`. A code with no `acct` means the device is the
account, exactly as §3.5 already said, so no existing code changes meaning and
no existing safety number moves.

A client SHOULD omit both members on a device that holds the account root,
where the two identities are the same key and saying so twice only makes the
QR bigger. Measured: ~500 bytes for a root device's code and ~870 for a
linked device's, each with the signature over its commitment (§18.10; 370 and
742 without it) — the second past the ~800 a symbol scans most reliably at,
and far inside what a QR code holds.

`acct` also implies `pqc`: a code that anchors to an account MUST carry the
commitment, and a decoder MUST refuse one that does not, rather than falling
back to the v1 reading. Otherwise stripping `pqc` would quietly turn the
person back into the device — the v1 decoder ignores members it does not
know, so nothing would fail.

**A linked device must be able to hand over its account's device list.** Since
a contact can now be added by scanning a linked device, that device is the
only one the contact can reach — the root has never heard of them. A device
that cannot sign a list MUST still forward the account-signed list it holds
(§7.7a rule 8 self-sync); this is not a privilege, because the recipient
verifies the signature against the account key they already hold. Without it
the contact holds a one-device list, sees a newer version claimed on every
message, and is told after the grace period that an update never arrived — a
transparency alarm raised by ordinary use, which is how a real one stops being
read.

Contacts added this way reach the account's other devices under §18.8.

**A device held as its own account learns its account in-band (phase 33).**
A contact added from a linked device's code from before this section, or from
a linked device's request from before §8.1's anchor, is held with no `acct`:
the device IS the account, its key anchors the safety number, and every list
its real account signs is refused as not this contact's. When a list arrives
over the session with that very device, signed by an account other than the
device's own key and naming the device — both its keys — under a certificate
that is not `legacy`, and the list verifies, a client SHOULD anchor the
contact to that account with that certificate, and then judge the list as any
other (§3.4). The account vouches for the device (the certificate) and the
device for the account (it sent the list, on a session only its key opens);
whoever holds that key could already sign lists for the record as it stood,
so nothing is handed to them, and what moves is the safety number — onto the
key the account's own devices show, with a tick given on the old one shown as
changed (13.3). A record that holds a commitment or a candidate commitment
(§18.2, §18.10) is not moved: each was taken over the identity as it stood.

### 18.8 Contacts across an account's own devices

Contacts travelled only at enrollment (§10, `contacts`), so one added
afterwards existed on exactly one device and the account's others dropped that
person's messages as an unknown sender. §18.7 made that reachable in ordinary
use, since a contact can now be added by scanning any device. A device that
adds a contact therefore announces it to its own devices over the self-sync
channel (§7.7a rule 8's transport), as `dir:"contact"` carrying:

```
{"k":"cadd","mid":…,"ts":…, "rid":…, "bundle":ContactBundleJSON, "name":string,
 "pqc"?:b64, "pqk"?:b64, "acct"?:b64, "cert"?:deviceCert }
```

A receiver MUST:

* **insert only, never update.** An rid it already holds is left exactly as it
  is. A linked device is already trusted to read this account's messages and
  send as it, but it holds no account root and so cannot enroll devices;
  letting it REPLACE a contact record would be strictly worse than either,
  silently re-pointing a name the user has already verified at keys of the
  sender's choosing, with no scan and nothing on screen to notice;
* check that `rid` is the routing id derived from `bundle` (§2.2) and that the
  bundle's binding signature verifies. Every honest path derives one from the
  other; a record where they disagree is not a sync but an assertion about who
  someone is;
* re-check `acct`/`cert` under §18.7 rather than trusting the sender's word
  for them;
* store the contact **unverified**, and record which device sent it. A tick
  records that the user compared a number while holding a particular device;
  it is not a fact one device can assert to another, and forwarding it would
  let a rogue device inject a contact that already looks checked. Enrollment
  is the one exception (§10 `cstate`, phase 33): the root hands the tick over
  on the channel both users' screens just confirmed, to the device that takes
  its whole account from the same payload.

What remains is that any of an account's devices can make a *new* chat appear
on the others. That is bounded rather than eliminated — any device can add a
contact, because the user scans on whichever one is in their hand — so a
client SHOULD show where such a contact came from, and MUST NOT present it as
something the user did on this device.

**Requests, declines and blocks follow the account (phase 33).** A request
(§8.1) reaches one device — the one whose code was scanned — and a decline or
a block was that device's alone, so a person blocked on the phone could reach
the laptop by scanning its code, and a request accepted on one device stayed
pending on another. They travel the same channel, as three more records, none
carrying a `bundle` — a receiver from before them, which takes any record with
one for a contact, passes them by:

```
{"k":"creq","mid":…,"ts":…, "req":<the request's transport payload, as it arrived>}
{"k":"cdecl","mid":…,"ts":…, "rid":…}
{"k":"cblock","mid":…,"ts":…, "rid":…}
```

A receiver MUST verify a passed-on `creq` as §8.1 does — addressed to another
of its own account's devices, signed by whoever asked — and hold it as pending,
under the routing id §8.1 gives it; one that came to the receiver itself
outranks one passed on. An accepted request travels as the contact (`cadd`),
which settles a request held for that routing id; the device it was sent to —
the one its sender holds — answers it then, as it answers one accepted on it,
and no other device does: to a client from before phase 33 an answer from a
device it never added is a second request. `cdecl` removes the request, and is
remembered with its time for 30 days — §8.1's bound, past which the request
is refused anyway — because the two records reach a third device in either
order, and a relay can hand a request over again long after its queue
lifetime: a request signed before the decline is dropped when it arrives. The
decline's time is also the receiver's §8.1 mark for that routing id, if it is
later than the one it holds, so a copy refused on the device that declined is
refused on every other. `cblock` blocks the routing id as the
user's own block does, unless the receiver holds it as a contact (`contacts`
and `blocked` never name one id, ADR 0011); a `cadd` lifts a block of its
routing id, as adding someone on the device does.

### 18.9 A post-quantum signature over the device list

The account signs its device list under ML‑DSA‑65 as well as Ed25519, over
**the input the list commits to** (§3.4) — the same input its fingerprint is
over, chosen by the same rule: the strongest signature that is alone (ADR
0017):

```
input  = the §3.4 commitment input for this list  // z-devlist-v1 while the list carries sig,
                                                  // z-devlist-v3 when it carries sig3 alone
sig    = Ed25519.Sign(account_ed_sk,  input)      carried in the list, as today
mlsig  = ML-DSA-65.Sign(account_ml_sk, input)     delivered separately
```

So the post‑quantum half covers the v1 input on every list that carries `sig`
— every list signed today, which a client from before ADR 0010 can therefore
still check (it verifies `mlsig` over the v1 input unconditionally, and a v2
input there was the false `pqSignatureMissing` of ADR 0017) — and `input3` on a
v2‑only list, where it covers what `sig3` covers: bytes no `mlsig` made for an
earlier list covers, the v2 input that clients between ADR 0010 and ADR 0017
signed under ML‑DSA included. A legacy v1 list is still covered over the v1
input without reissue. A verifier MUST refuse a malformed list (§3.4) before it
checks `mlsig`: deleting `sig` from a dual‑signed list leaves the v1 input as
it was, so that list's own `mlsig` would otherwise still verify over what is
left.

**Over the list, not over each certificate**, and that is the security
property rather than an economy. Consider the adversary phase 13 exists for:
one who can forge Ed25519 but not ML‑DSA. Given a genuine list for
`{phone, laptop, tablet}` whose certificates each carried a post‑quantum half,
they can present a list for `{phone, tablet}` — the classical list signature
forged, every remaining certificate's `mlsig` *genuine* and copied unchanged.
Every check passes and the honest device has been excluded, which is
`adr/0001`'s T2. A signature over the list covers the membership and the
version, so neither can be changed. See `adr/0004` for the measurements and
the options rejected.

**And, on a v2‑only list, over the ratchet keys.** Membership and version are
the coverage a v1 input already gave the post‑quantum half; they leave one
field open. Take a genuine hybrid list, keep every device Ed key so membership,
routing and the v1 fingerprint are untouched, replace one device's `deviceXPub`
with a key the adversary holds, forge the classical signatures, and replay the
genuine `mlsig` — which was made over a v1 input that never named `deviceXPub`,
so it still verifies. Contacts open ratchets to the adversary's key. The v2
input closes this: it adds each device's `deviceXPub` and `id`. On a
dual‑signed list it is closed by `sig2` alone, classically — the `mlsig` is held
at the v1 input there (ADR 0017), so against an adversary who has broken
Ed25519 the replay still passes the post‑quantum check while dual‑signing
lasts; on a v2‑only list (`sig3` alone) the `mlsig` is over the new ratchet
key as well, and the replayed one fails. That is the commitment ADR 0017's
stage 2 restores, and it takes effect when the v2‑only signer is switched on
(§3.4). The per‑certificate hybrid object whose post‑quantum half once covered
`deviceXPub` is retired (`adr/0031`); the coverage it offered is given to the
list signature instead (`adr/0004`, `adr/0010`).

The signature travels as its own inner message, and can be asked for:

```
{"k":"dlpq","mid":…,"ts":…,"sig":"{\"acct\":b64,\"ver\":n,\"mlsig\":b64}"}
{"k":"dlpqreq","mid":…,"ts":…,"v":n}
```

A sender MUST NOT send it with the list. A ~3.3 KB signature does not fit the
4 096‑byte bucket a device list and ordinary chat share, and no arrangement
makes it fit; what a separate message buys is that the 16 384‑byte envelope it
needs is **uncorrelated in time** with a device‑set change. Clients SHOULD
therefore delay it — the reference client by hours, jittered — and send it
once per contact per list version.

A receiver MUST:

* check that `acct` is the account key it holds for that contact;
* refuse a `ver` lower than one it has already accepted;
* **store it even when it cannot yet be verified.** The contact's account
  ML‑DSA key arrives on its own independent schedule (§18.2) and may not be
  here yet. Discarding an early signature would make the two schedules depend
  on each other, which is the coupling this design exists to avoid; it is held
  and re‑checked when the key lands;
* treat the list as `classical` until a signature over **this** version and
  **this** device set verifies, then `hybrid` (§18.4). A list whose version
  has since moved on is classical again until the signature for the new one
  arrives.

**Suppression, and how it is told apart from an old client.** The signature is
the single easiest thing on the wire to drop: it is the only ~16 KB envelope an
ordinary conversation produces. Dropping it leaves the list classically
verified — everything works, nothing fails, and the account never gets the
protection this section exists for. That cannot be prevented at the network
layer.

Detecting it naively does not work either. A client built before this section
has a post‑quantum identity (it emits `pqid`, so its contacts reach `hybrid`)
and simply never signs its lists. Alarming on "hybrid identity, classical
list" would fire for every such contact, and an alarm that fires on ordinary
use is one nobody reads.

So a sender that has **sent** the signature says so, in the claim it already
stamps on outgoing messages (§7.7a):

```
"pql": <version of the list whose signature has been sent to you>
```

It is stamped after delivery, never before, and it rides inside the ratchet —
so an attacker who drops the signature cannot also strip the evidence that it
was sent, short of dropping the conversation itself. A receiver then has three
distinguishable cases:

| what it sees | what it means | what to do |
|---|---|---|
| no `pql` | a client that does not sign its lists | report `classical`; accuse nobody |
| `pql` ≤ what it holds and verifies | nothing missing | clear any alert |
| `pql` > what it holds | it was lost or removed | ask, then alert |

A receiver MUST ask before alerting — most losses are a dropped connection,
and the sender answers a `dlpqreq` with the signature it already holds. Only
when asking (bounded; the reference client asks three times) has not produced
it within the grace period is the user told. The list stays `classical`
throughout: nothing is ever accepted on the strength of a claim.

### 18.10 The commitment's signature (`pqcs`)

`pqc` (§18.2) was covered by nothing: `sig` binds `x` to `ed` (§2.3) and
`cert` binds the device to `acct` (§18.7). Anyone holding a person's public
code — everyone they ever gave it to — could write any commitment into it, and
the code still decoded and verified. Pasted into a contact holding a candidate
key (ADR 0021), or no key yet, it had that contact's genuine key refused,
permanently. So the code signs its commitment (ADR 0027):

```
pqcs       = Ed25519.Sign(ed_sk, input)                     64 bytes, base64
input      = utf8("z-pqc-sig-v1:") || account_ed (32) || pq_commit (32)
account_ed = acct when the code carries it (§18.7), else ed
json       = { "v":1, "ed":…, "x":…, "sig":…, "pqc":…, "pqcs":…,
               ["acct":…, "cert":…,] "name"?:string }
```

The signer is the code's own `ed`: the key that signs `sig`, and the only one
a linked device holds — its authority over `acct` is the certificate in the
same code. The input names the account the commitment is about, so a
signature cannot be carried to a code that names another; it is fixed‑width,
so the concatenation is unambiguous. The `zc3.` form carries the member the
same way.

`pqcs` is an optional member (§14): a client that predates it ignores it, and
a code without it is what every code issued before looks like. A decoder:

* MUST refuse a code whose `pqcs` is present and is not a string, does not
  decode to 64 bytes, or does not verify over `input` under `ed` — checked
  after `sig` and `cert`, so the account `input` names is already proven;
* MUST refuse a `zc1.` code that carries `pqcs` and no `pqc`, rather than read
  it as a classical code: a signature over a commitment the code no longer
  carries is a commitment that was removed;
* MUST accept a code with `pqc` and no `pqcs`, as an **unsigned** commitment.

What a client does with the two:

* A **signed** commitment is evidence, and is treated as every commitment was
  (§18.2, ADR 0021): held, a delivered key checked against it, a key that
  misses it refused, a code for the same identity carrying a different one
  refused.
* An **unsigned** commitment in a code for someone the client ALREADY holds is
  not evidence — anyone could have written it — and MUST be treated as a
  candidate, as a key with no commitment is (§18.2): a key it matches is
  established, as ADR 0021's re‑scan always was, and a key it misses MUST NOT
  be refused on its strength. The code is refused instead, and nothing held
  changes. With nothing yet to check it against, it is held for the key and
  dropped if the key misses it.
* An unsigned commitment in a code that ADDS someone is held as before: there
  is nothing to poison, and someone able to alter a code before its first scan
  could replace the whole identity in it, which comparing the number catches.
* Once a client has seen a contact's commitment in a signed code — the one
  it holds, or one that established their key — it MUST refuse a later code
  for that contact that carries no `pqcs` — `pqc` present or not — and change
  nothing: it is an old code of theirs, or one somebody stripped.

The signature is Ed25519, because the ML‑DSA key is not in the code (ADR
0003): against the §18 adversary it is forgeable like anything classical, and
what it stops is everyone without the code owner's key. It costs 64 bytes,
~130 characters once encoded: a root device's code goes from ~370 characters to
~500 and a linked device's from ~740 to ~870 — at error correction L, QR
version 13 to 15 and 19 to 21 (ADR 0027).
Vectors: `v3/contact_code_pqc_sig.json`.

## 19. The transparency log (7.7b)

*Normative for the log service in `kt/` and for clients that read it. This
is the second source of the `(version, fingerprint)` facts §3.6 already
gossips; nothing in §3–§18 changes. Design and rationale: `adr/0006`.*

The log is a separate HTTPS service, not the relay. It commits, per account
label, to the version and fingerprint of every device list the account has
published, in an append‑only Merkle tree with a map that pins the latest
entry per label, under Ed25519‑signed tree heads. Clients verify proofs; they
never trust an answer. All byte strings in JSON are `b64`; labels in URL
paths are lowercase hex. Integers are JSON numbers and MUST be below 2⁵³.

### 19.1 Labels and values

```
label = SHA-256( utf8("z-kt-label-v1:") || accountEdPub )                    32 bytes
vk    = HKDF-SHA256( ikm = accountEdPub, salt = utf8("z-kt-value-v1"), info = utf8("value"), L = 32 )
value = nonce || ChaCha20-Poly1305( key = vk, nonce, aad = label, plaintext = listJSON )
```

`listJSON` is the signed device list of §3.4 in its JSON form; `nonce` is
12 random bytes; the AEAD tag (16 bytes) is included in `value`. Anyone who
holds an account's public key — its contacts, and the operator, who learns
it at publish (§19.6) — can derive `vk` and open the value; a mirror or a
reader of the log cannot. A value MUST be at least 28 bytes and at most
262 144 bytes. That maximum is a reader's obligation: a client MUST be able
to open a value of that size. A log MAY accept less — a signed device list
is about a kilobyte, and what a log accepts sets how many entries its disk
holds — and MUST refuse a larger one with `413 too_large` naming its own
cap, so a publisher can tell a log's policy from a malformed request. A log
MUST NOT accept more than the maximum.

### 19.2 The map tree

A sparse Merkle tree of depth 256 over labels. Depth 0 is the root; at depth
`d` the path branches on bit `d` of the label, bit 0 being the most
significant bit of byte 0; leaves sit at depth 256.

```
mapLeaf(label, index, version) = SHA-256( 0x10 || label || u64be(index) || u64be(version) )
mapNode(left, right)           = SHA-256( 0x11 || left || right )
empty(256)                     = SHA-256( 0x12 )
empty(d)                       = mapNode( empty(d+1), empty(d+1) )              for d < 256
```

The leaf for a label holds the index in the log tree of the label's latest
entry and that entry's version; a label with no entry is the empty leaf.
`u64be` is the unsigned 64‑bit big‑endian encoding.

**Map proof.** For a label, the 256 sibling hashes along its path,
compressed: a 32‑byte `bitmap` in which bit `d` (same bit order as labels)
is set when the sibling at depth `d` is not `empty(d+1)`, and `siblings`,
exactly the non‑empty siblings in increasing depth order. The proof carries
`leaf` = `{index, v}` or `null`. To verify against `mapRoot`:

```
h = leaf ? mapLeaf(label, leaf.index, leaf.v) : empty(256)
for d = 255 down to 0:
    sib = bit(bitmap, d) ? next sibling from the END of siblings : empty(d+1)
    h   = bit(label, d) == 0 ? mapNode(h, sib) : mapNode(sib, h)
accept iff h == mapRoot and the number of set bits in bitmap == len(siblings)
```

A proof with `leaf = null` that verifies is a proof of absence.

### 19.3 The log tree and its leaves

The log tree is RFC 9162 §2.1 over SHA‑256 without change: leaf hash
`SHA-256(0x00 || input)`, node hash `SHA-256(0x01 || left || right)`, the
empty tree `SHA-256("")`, the audit path `PATH(m, D[n])` of §2.1.3 and the
consistency proof `PROOF(m, D[n])` of §2.1.4, verified by the algorithms of
§2.1.3.2 and §2.1.4.2. `vectors/kt/log_tree.json` reproduces the
certificate‑transparency‑go reference data.

```
leafInput = utf8("z-kt-leaf-v1:") || label || u64be(version) || fp || SHA-256(value) || u64be(ts)
```

`fp` is the §3.6 fingerprint of the list in `value`; `ts` is the log's
clock at acceptance in milliseconds since the epoch. Entries are numbered
from 0 in acceptance order; an entry's `index` is its leaf index. Only a client
computes `fp` — the log, its mirrors and its witness treat it as sixteen opaque
bytes — and it computes it by §3.6's rule from the list it signed: over the v1
input for a list that carries `sig`, over `input3` for a v2‑only one (`sig3`
alone). A reader that opens `value` derives it the same way from the list
inside, and an entry whose list is malformed (§3.4), does not verify, or does
not give the entry's `fp` is not this account's list (the reference client
treats it as one that does not open, per `adr/0006`'s table). That matters
because the log's operator can open a value (§19.1): a dual‑signed list it
served with `sig` deleted, under any `fp`, is a conflict at every reader, not a
list.

### 19.4 Signed tree heads

```
sthInput = utf8("z-kt-sth-v1:") || u64be(size) || logRoot || mapRoot || u64be(ts)
sig      = Ed25519.sign(logSeed, sthInput)

JSON: { "size":n, "logRoot":b64, "mapRoot":b64, "ts":ms, "sig":b64 }
```

`size` is the number of entries, `logRoot` the log tree's root at that
size, `mapRoot` the map's root over the latest entry of every label at that
size. The log MUST sign a new head whenever it grows and SHOULD re‑sign an
unchanged head at least every ten minutes. The log's public key is
distributed out of band and pinned by clients; `GET /kt/v1/pub` exists for
a first look and MUST NOT be used as the pin.

### 19.5 Reading the log — client rules

A client keeps the last head it verified. On each check it MUST:

1. fetch `/kt/v1/sth` and verify `sig` with the pinned key; refuse a head
   whose `size` is below the held one;
2. if `size` exceeds the held size, fetch
   `/kt/v1/consistency?first=<held size>&second=<size>` and verify the proof
   between the held `logRoot` and the new one; if `size` equals the held
   size, require both roots to be equal;
3. if a witness is configured (§19.10), fetch its record, verify the log's
   signature and the witness's over it **against the witness key this client
   pinned**, and require it to be consistent with the head: equal roots at
   equal size, or a verifying consistency proof from the log between the two
   sizes in either direction. A witness is an address AND a key: a client
   holding one without the other MUST treat it as no witness and MUST NOT
   fetch the record, because a co‑signature checked against the key carried
   inside the record establishes only that whoever served it could sign it;
4. only then accept the new head and evaluate proofs under it.

A lookup response (§19.7) carries the head its proofs are relative to. A
client MUST verify the map proof against that head's `mapRoot` and, when an
entry is present, the entry's `leafInput` hash against `logRoot` through the
inclusion path at `inclusion.size == sth.size`, and MUST check that the
map leaf's `index` and `v` equal the entry's. It MUST NOT use an entry whose
proofs fail. A head served with a lookup that is not the client's held head
is checked by steps 1–3 before its proofs are used.

A head whose `ts` is more than 24 hours old, or no head at all, is
**unreachable**; a head or proof that fails any check above is a **log
fault**. What a client does in each state, per contact, is the table in
`adr/0006` ("What a client does with each answer") and is normative for the
reference client; other clients MUST at least refuse to treat an entry as
confirmed when its proofs fail and MUST NOT accept a head that does not
extend the one they hold.

A witness's record is held to the same clock. A record whose head's `ts` is
more than 24 hours old is still checked by step 3 — a different head at its
size, or a consistency proof that fails in either direction, is a log fault —
but it is not the witness agreeing: the log re‑signs its head at least every
ten minutes (§19.4) and a witness following it co‑signs what it verifies, so
a record that old is from a witness that has stopped, or is a replay. A witness
that cannot be fetched, or whose record does not verify, is no verdict. The
witness agrees when a record whose head is current meets step 3. A client
SHOULD say when its witness last agreed with a current record, and SHOULD say
when that was more than 24 hours ago, or, with no agreement yet, a day after
it began asking: a witness gone quiet is one the log is not being checked
against.

### 19.6 Publishing

```
POST /kt/v1/publish
{ "acct":b64(accountEdPub), "v":version, "fp":b64(fp), "value":b64(value), "sig":b64(sig) }

sig = Ed25519.sign( accountSeed, utf8("z-kt-publish-v1:") || label || u64be(v) || fp || SHA-256(value) )
```

The log MUST verify `sig` against `acct`, MUST refuse a `v` that does not
exceed the version it holds for the label (`409 stale_version`; a label's
first entry may carry any `v ≥ 1`), MUST refuse a bad signature
(`403 bad_signature`) and a malformed request (`400 bad_request`) or an
oversize value (`413 too_large`), and on success appends the entry, updates
the map, and answers `201 { "index":i, "sth":<head> }` with a head that
includes it. The log MUST keep `acct` **and `sig`** for replay validation
and MUST NOT serve either; it MUST re-verify `sig` against `acct` when it
replays an entry from its own store, and MUST NOT accept a stored entry with
no `sig` once it has accepted one that has a `sig`. A store that keeps only
the fields whoever wrote a record also chose can be appended to by anything
that can write it. The log does not open the value.

### 19.7 HTTP API

All responses are JSON; error responses are `{ "error":code, "message":text }`.

| method and path | response |
|---|---|
| `GET /kt/v1/sth` | the current head (§19.4), and `bucketBits` (§19.9) |
| `GET /kt/v1/consistency?first=m&second=n` | `{ "sth", "first":m, "second":n, "proof":[b64…] }` — `PROOF(m, D[n])`; `second` defaults to the head's size |
| `GET /kt/v1/lookup/<label hex>` | `{ "sth", "map":{ "leaf":{index,v}\|null, "bitmap":b64, "siblings":[b64…] }, "entry":<entry>\|null, "inclusion":{ "index", "size", "path":[b64…] }\|null }` |
| `GET /kt/v1/history/<label hex>?start=i&count=k` | `{ "sth", "start":i, "total":n, "entries":[ { "entry":<entry>, "inclusion":… } … ] }`, oldest first — `n` is how many versions the label has |
| `GET /kt/v1/entries?start=i&count=k` | `{ "sth", "start":i, "total":n, "entries":[<entry>…] }` — `k ≤ 1000`, clipped to the head's size (mirrors); `n` is the head's size |
| `POST /kt/v1/entries` | `{ "indexes":[i…] }` (1 to 1000, each below the head's size) → `{ "sth", "total":n, "entries":[ { "entry":<entry>, "inclusion":… } … ] }` — entries by index for a client (§19.9), in the order asked, as many as fit a page; `n` is how many were asked |
| `GET /kt/v1/bucket?prefix=p&bits=k` | `{ "sth", "bits":k, "prefix":p, "leaves":[…], "siblings":[b64…] }` — §19.9 |
| `POST /kt/v1/buckets` | `{ "buckets":[ { "prefix", "bits" } … ] }` (1 to 64) → `{ "sth", "buckets":[ { "bits", "prefix", "leaves", "siblings" } … ] }` under one head — §19.9 |
| `POST /kt/v1/publish` | §19.6 |
| `GET /kt/v1/pub` | `{ "pub":b64 }` — informative |
| `GET /health` | `{ "state", "size", "labels", "sthTs", "rssBytes", "memLimitBytes", "diskBytes", "diskFreeBytes", "full" }` — informative; while the log replays its entries at start, `503 { "state": "replaying", "replayed", "rssBytes", "memLimitBytes" }`, and every other route `503` |

An `<entry>` is `{ "index":i, "label":b64, "v":version, "fp":b64,
"valueHash":b64, "value":b64, "ts":ms }`; a reader MUST check
`SHA-256(value) == valueHash` before hashing the leaf. Every proof in a
response is relative to the `sth` in that response.

The two paging routes are bounded in bytes as well as by `count`, because a
value may be 256 KiB and the count alone therefore bounds nothing: a log MUST
NOT serve more than a stated budget in one response, MUST serve at least one
entry when the range it was asked for is non-empty, and MUST report `total`.
A reader that has not seen `total` entries MUST ask again from where the page
stopped rather than treat the page as the whole — and a log that stops short
is not by itself a fault, because §19.8's judgement of the authenticated
`latest` is what an incomplete history cannot defeat. `POST /kt/v1/entries`
pages the same way, at the bound of a label's history, and its `total` is the
number of indexes asked for.

A log MAY answer `429` with a `retry-after` header (delta‑seconds) on
`/kt/v1/entries` when a reader is over a byte budget, and a mirror MUST treat
that as "not yet" rather than as a failure of the sync: wait as long as it
says (bounded), then ask for the same page again. A log MUST NOT refuse the
routes a client's check depends on — the head, a consistency proof, a lookup,
a label's history — on a budget that other readers can spend, because behind
a front that sets no client address every reader shares one; those routes
are bounded by the size of one answer instead. The bucket routes and
`POST /kt/v1/entries` are such routes (§19.9). A page of entries below the
head and a consistency proof between two sizes are immutable and MAY carry
`cache-control: public`; a reader MUST NOT rely on the `sth` or `total`
carried in such a page being current, and a log MUST NOT mark an empty page
cacheable, since it is what a request past the head receives.

### 19.8 Self-monitoring by the account the entries are about

An account MUST check its own label, and MUST judge **the authenticated
`latest` from the lookup** by the same rule it applies to every history
entry: a `(version, fingerprint)` this account did not issue is an alert.

Judging only the history is not enough, and this is not hypothetical — it is
what the client did until 2026‑09‑13. The history response is a list the log
volunteers, an **empty one is not a fault** (an account that has never
published legitimately has one), and nothing else in the check raises an
alert. So a log that answers the head honestly, answers the lookup honestly
with a rogue `(version, fingerprint)` — signed, proved, and served to every
reader as current — and simply leaves that entry out of the history was
believed in full and said nothing to the account it was about. The lookup is
the one answer the log cannot shade: it is what the log is serving, under its
signature and its proof.

A device that does not hold the account root judges only versions it has
seen: it learns lists by self-sync and may skip versions, so a version it
never saw is not evidence. A version it HAS seen, carrying a different
fingerprint, is a contradiction on any device.

A change in how the account signs is not an exception to that, and needs
none. Both migrations so far move the fingerprint by publishing at a NEW
version — ADR 0010's dual-signed republish, and ADR 0017's v2-only one (§3.4),
which a root performs once when its v2-only signer is switched on — so the old
`(version, fingerprint)` stays what it was in the log and in the account's own
record, and the new one is a version the account issued. A version is never
re-signed into a second fingerprint.

A client has to hold itself to that mechanically. A root signs its list from
two values — the device set and the version — that linking or removing a
device changes one after the other, and it signs from paths that run when
they run: a re-send to a contact whose echo is behind, the hello, the
re-assertion on every reconnect, the log check's baseline. One caught between
the two writes signs a version with the next one's devices. So a root MUST
read, sign and record its list as one step that those writes cannot fall
inside, and a client MUST NOT record a second fingerprint for a version it
has recorded: the first stands. The reference client serialises the two
under one lock; a root that would sign a second fingerprint fails loudly in a
debug build and sends nothing in a release one; and a device that cannot sign
does not adopt a second list at a version it holds — the record it keeps is
what lets it see the other one in the log. Until 2026‑10‑02 it did none of
this, and the overwritten record turned the account's own genuine entry into
an alert at the next start.

**What raises it, and for how long (ADR 0026).** An entry is evidence of a
list the account did not issue only if it opens as the account's list,
verifies, and carries the entry's fingerprint (§19.3). One that does not was
signed by nobody the reader can name — the log never serves the publish
signature (§19.6), and its operator can put any value under any label, since
it can open values (§19.1) — so the account's own device raises nothing on it
(the reference client keeps it as a diagnostic, `kt_own_unverified`), while
the account's contacts still treat it as a conflict (`adr/0006`). A user's
dismissal of the alert holds for that entry's (version, fingerprint), across
restarts, and a different entry raises it again.

Vaults that the own‑list race above had already damaged — whose record of one
of their versions holds a second list the root signed at it, while the log
holds the first — are repaired by one rule, and only by it: a mismatch at
version `v` is reconciled quietly, kept beside the record and not over it,
when (1) the entry is inside the log head the device held when the repairing
build first ran on its vault and `v` was recorded then, (2) it opens and
verifies as the account's list, and (3) every device it names is one the
account is known to have held — the device's own records, and the devices of
every entry in the log that matches its record. Nothing can enter the set (1)
describes afterwards: the log takes no version at or below one it holds, and a
head that does not extend the held one is a fault — and a reset of the
history, which takes the next head as it comes, ends the repair. When the
reconciled entry is the log's latest and not the root's current list, the root
moves to the next version with its current devices, as the migrations above
did.

### 19.9 Lookups by bucket

*For this log and for the handle log (§21.5) alike. Design, the
alternatives and what it leaves: `adr/0023`.*

A lookup (§19.7) names its label, so the log — and whatever terminates its
TLS — learns which accounts a reader asks about: for a client checking its
contacts, its contact list. A bucket query names only the first `k` bits of
the label, and is answered with every label that has them and the proof
that none was left out:

```
GET  /kt/v1/bucket?prefix=<hex>&bits=<k>
POST /kt/v1/buckets   { "buckets":[ { "prefix":hex, "bits":k } … ] }        1 to 64 buckets, one head

k      = 0 … 24
prefix = the first k bits of a label, as ⌈k/4⌉ hex digits, the unused low bits zero ("" for k = 0)

GET  → { "sth":<head>, "bits":k, "prefix":hex, "leaves":[ <leaf>… ], "siblings":[ b64 × k ] }
POST → { "sth":<head>, "buckets":[ { "bits", "prefix", "leaves", "siblings" } … ] }      in the order asked
<leaf> = { "label":b64, "index":n, "version":v }                                          this log
         { "label", "index", "version", "value":b64, "ts":ms, "sig":b64, "audit":[b64…] }   the handle log
```

`leaves` are every label in the map whose first `k` bits are `prefix`, in
ascending label order, each with its map leaf's `(index, version)` — the
label's latest entry. `siblings` are the map siblings along the prefix's
path from depth `k−1` up to depth 0, uncompressed: an empty one is
`empty(d+1)`. A reader:

```
1. verifies sth under the pinned key (§19.4; for the handle log, its own context, §21.5);
2. checks that the bucket is the one it asked for, that it has at most 4096 leaves,
   that every label has the prefix, and that the labels strictly ascend;
3. computes h = subtree(leaves, k), the map's hash at depth k of the subtree holding exactly them:
       subtree([], d)   = empty(d)
       subtree([l], d)  = mapLeaf(l.label, l.index, l.version) hashed up to depth d through empty siblings
       subtree(ls, d)   = mapNode(subtree(ls with bit d = 0, d+1), subtree(ls with bit d = 1, d+1))
4. folds it: for i = 0 … k−1:  d = k−1−i;
       h = bit(prefix, d) == 0 ? mapNode(h, siblings[i]) : mapNode(siblings[i], h)
5. accepts iff h == sth.mapRoot.
```

A bucket that verifies is complete: a label left out or added, or given
another `(index, version)`, changes the subtree, and the fold no longer
reaches the root the log signed. So a label with the prefix that is not among
the leaves is a verified absence, as a map proof of absence is; a label
without the prefix is not answered by the bucket at all.

The handle log's leaves also carry the latest entry's record (`value`), its
`ts` and the owner's `sig` (§21.5), and `audit`, the RFC 9162 path of entry
`index` in the log tree at `sth.size`; there a reader also checks that `ts`
is a whole hour and the record at most 1 KiB, and that the handle leaf of
`(label, version, SHA-256(value), ts)` is included at `index` under `logRoot`
— so it reads a record without a second request that would name the label.
This log's leaves carry no value; a reader that needs one asks
`POST /kt/v1/entries {"indexes":[…]}` (§19.7), with decoys beside it
(§19.9.1 says which and how many).

A log MUST answer a bucket with every leaf it holds or refuse it, never with
part of it. It MUST refuse a malformed prefix, or a `k` past 24, with
`400 bad_request`; and a bucket of more than 4096 leaves — or the buckets of
one `POST` with more than 4096 between them — with `400 bucket_too_large`.
It MAY refuse an answer past a size it states with the same code (the
reference handle log refuses one past 256 KiB, the bound of a label's
history). The reader then asks with more bits, or for fewer buckets at once.
These are routes a client's check depends on: a log MUST NOT refuse them on
a budget other readers can spend (§19.7). `/kt/v1/sth` carries `bucketBits`,
the log's recommendation `max(0, ⌊log₂(labels / 32)⌋)`, at most 24 — 32 to 64
labels a bucket — and a bucket answer's head carries it too; it is advisory,
outside the signed bytes, and a log answers other buckets the same way.

What a bucket does not hide: which bucket — about one label in 2^k — and
when, and from which address; and how many buckets a reader asks for, so a
client that asks one per contact says how many contacts it has unless it
pads with decoys. `adr/0023` sets this against exact lookups, a full
snapshot, the anonymous path and PIR; §19.9.1 says how a client pads and
how often it asks. `vectors/kt/bucket.json` pins both logs' answers (§19.11).

#### 19.9.1 How a client asks about its contacts (phase 35)

*Not a wire change: the requests are §19.9's and §19.7's. Rationale and what
the log still learns: `adr/0023`, "The client's refresh policy".*

A client that checks its contacts against this log MUST NOT name a contact's
label to it — no `lookup` and no `history` of one — and asks by bucket. The
reference client:

1. maps every contact's label to its bucket at
   `k = min(bucketBits, ⌊log₂(sth.size / 32)⌋, c)`, where `c` is a ceiling
   its own counts of the log's labels set (below) — never finer than the log
   recommends, nor than the signed size allows, nor than the labels it
   counted fill to 16 a bucket: `bucketBits` is unsigned, and the size counts
   entries, which versions inflate;
2. adds decoys: 32‑byte values drawn at random, mapped to buckets as labels
   are, kept (sealed in the vault and in a backup) and asked again at every
   refresh, so that the buckets asked are a multiple of 16 and at least 16 —
   or every bucket where there are fewer. A bucket asked at the last refresh
   that no contact and no decoy now covers gets a decoy drawn inside it, so a
   removed contact's bucket stays; new decoys are drawn only to complete a
   block;
3. asks them, sorted by prefix, in one `POST /kt/v1/buckets` (64 at most a
   request), verifies the answer (§19.9) and adopts its head (§19.5); a
   bucket refused `bucket_too_large` is asked as both its halves at `k + 1`,
   a request of several as two halves;
4. fetches entry values with `POST /kt/v1/entries`: a contact's entry when its
   `(index, version)` is not the one last judged — a label's versions only
   rise (§19.6), so the same version is the same entry — among every entry
   in the asked buckets that it had not seen at its last refresh, made up to
   16 with others from them in an order its own key fixes, whether or not
   any contact needs one; every entry in the asked buckets instead when a
   needed one is in neither, and when it has no last refresh (a first
   refresh, a restore, another log); past 1024, the needed ones and a sample
   of the rest drawn in an order its key and the needed set fix. Each
   fetched entry MUST be the label's, at the version, that the bucket named
   for its index;
5. judges each contact by the table of `adr/0006` exactly as from a lookup;
6. sets `c = ⌊log₂(labels / 16)⌋` of a count of labels: before its first
   refresh, and after a change of log, from random buckets asked one at a
   time with `GET /kt/v1/bucket` and never again — from
   `⌊log₂(sth.size / 32)⌋`, coarser by what each fell short of 32 labels,
   until one holds 32 — and after each refresh from the mean of the buckets
   that hold no contact: lowering `c` to it at once when buckets at `c`
   would hold fewer than 16, raising it one bit when they would hold 64 or
   more, and leaving it otherwise;
7. runs once in each six‑hour window counted from the epoch, at a random
   moment in it kept across restarts — never at the instant the app starts
   or comes to the front, and never because a contact's list changed; a
   window's moment the app was not running for, and a whole window without
   a refresh, is caught up at a random moment 5 to 30 seconds after the app
   is next in front; and the screen where the user looks at a contact whose
   list has changed runs one then, of the same shape, as a check the user
   asks for in Settings does — that window's, when it has had none.

The account's own label is still asked by name for §19.8 (its `history` is
served no other way); that tells the log who asks, which a root's publishes
tell it anyway, and nothing of whom. A log that refuses the bucket routes is
unreachable to such a client; it MUST NOT fall back to `lookup`.

### 19.10 Mirrors and witnesses

A mirror holds every entry and the last head it verified. On each sync it
MUST verify the head's signature; require the head to extend the held one
(§19.5 steps 1–2); fetch the entries between the two sizes; and re‑derive
**both** `logRoot` and `mapRoot` from its own copy, refusing the head on any
mismatch and keeping the old one. A mirror that also publishes

```
witnessInput = utf8("z-kt-witness-v1:") || sthInput
{ "sth":<head>, "size":n, "verifiedAt":ms, "witness":{ "pub":b64, "sig":b64(Ed25519.sign(witnessSeed, witnessInput)) } }
```

is a witness; the record is static JSON and may be served from anywhere. A
client configured with a witness URL and its public key treats a witness
record that verifies but is inconsistent with the log's head as a log fault.
Both values or neither: the record names its own signer, so a client that
has not pinned the key is not checking a second opinion but the same one in
a second envelope, and the log's own operator can serve it.

A mirror MUST distinguish what the log SIGNED from what the network did.
Refusing a head is permanent — a witness that has refused stops following
the log — so it MUST be reached only on a signature, a consistency proof or
a root that fails. A response that is unreachable, malformed, or empty where
the head says entries exist is a transport failure: the mirror keeps its
head, records the error and retries; a `429` is a wait (§19.7), and only
becomes a transport failure after a bounded number of them. A mirror MUST NOT apply any part of a
fetch it has not completed and verified, and MUST NOT leave state beyond the
last head it accepted: after an incomplete sync its next one begins from
that head, and entries persisted without the head that covers them are
discarded on load.

### 19.11 Vectors and versioning

`vectors/kt/` pins §19: `log_tree.json` (RFC 9162 against the CT reference
data), `map_tree.json` (roots after each of fourteen sets, proofs of presence
and absence, four proofs that must fail), `kt_log.json` (labels, value keys,
sealed values, publish signatures, leaf inputs, every head, consistency
proofs, the lookup and history responses as served, a witness record, and
seven cases that must be refused, including a fork signed by the real log
key). Alice's first entry seals the §3 `multidevice` vector's real signed
list, so a client that opens it verifies a list it already knows how to
verify and must find its fingerprint equal to the entry's. Generated by
`kt/tools/gen_vectors.js`; reproduced bit‑for‑bit by `kt/test/vectors.test.js`
and re‑derived by `kt/tools/verify_vectors.py` from this section with no
shared code. The §14 rule applies: bytes an existing implementation would
compute differently mean new context strings (`…-v2`), new vector files
beside the untouched ones, and a new subsection here. `bucket.json` (36.2)
is such a file: both logs' bucket answers as served (k = 0, 1 and 8, an
empty bucket, a `POST` of three), entries by index, the handle log of §21.5
— its publishes byte for byte, its head, and the owner rule's refusals with
their codes — and the answers a reader must refuse; the three files above
are byte‑identical, and the Dart reader (`transparency_bucket.dart`) reads it
too.

## 20. Connecting without meeting (17)

*Normative. A fourth way to add a contact, beside the QR, the paste and the
device‑pairing ceremony of §10. Nothing in §3–§19 changes: no new frame type,
no relay change, and the contact this produces is the same `zc1.`/`zc3.`
bundle a scan produces. Design and the trust‑model decision: `adr/0009`. A
group invite link (`adr/0020`) is this ceremony with one optional sealed
member in each reveal (20.3) and one inner kind afterwards (§6.2, `gjoin`),
bound to the ceremony by a tag derived from its channel key (20.6). An invite
of version 2 (`adr/0024`) binds its secret into the ceremony's keys (20.8).*

In person, adding someone is a QR code and **the QR is the verification**: the
channel is your eyes. Remotely there was one path — copy your code, send it
over a channel you trust, they paste it — which is one‑directional, hands out
a permanent identifier, and ends unverified. Its security advice ("a channel
you trust") is exactly what someone who has only WhatsApp does not have.

This section specifies a **one‑time invite** and a four‑message ceremony that
assumes the channel carrying the invite is hostile. Both sides commit before
either reveals, the confirmation string is bound to the identities being
exchanged rather than only to the channel, and one run adds both people.

### 20.1 Context strings

All disjoint from `z-pair-*` (§10), so an invite can never address a pairing
rendezvous or the reverse:

```
z-connect-rendezvous-v1:   the code's own mailbox id (see 20.2)
z-connect-relay-v1:        the two per-role transport mailboxes (20.5)
z-connect-commit-v1:       what each side commits to (20.3)
z-connect-channel-v1       the channel key (20.3)
z-connect-sas-v1           the eight digits (20.4)
```

Version 2 (20.8) has one more, `z-connect-invite-v2`, and a `-v2` twin of
each of these.

### 20.2 The invite

Ten random bytes, in two renderings computed from one secret:

```
text  = base32Groups(secret)                    e.g. ABCDE-FGHIJ-KLMNO-P
link  = "https://" || host || "/i#" || base32(secret)     (no group dashes)
```

An invite of version 2 starts both renderings with `9` (20.8).

`host` defaults to `www.zmessengers.com` and is part of the deployment, not of the
protocol: a self‑hosted relay serves its own landing page and its links carry
its own host, and a client MUST accept an invite whatever host precedes the
fragment. It MUST NOT accept one on any path but `/i` (a trailing `/` and a
query are allowed, the scheme may be missing): a fragment that happens to read
as base32 on another page of a site — `/index.html`, `/info` — is not an
invite, and until 2026‑10‑16 any `/i` before the `#` made it one. Android's
filter for these links names the path `/i` exactly for the same reason. The
code lives in the URL **fragment**, which no browser transmits, so the site
serving that page never receives an invite and cannot know one exists.

A parser MUST accept the text with or without its group dashes, in either
case, and with spaces; it MUST reject anything containing a character that is
neither base32 nor a separator. (`base32Decode` skips what it does not
recognise, which is right for a code read aloud and wrong for deciding
whether a string *is* one: every URL has enough letters between its
punctuation to make ten bytes.)

`rendezvousRoutingId = b64url(SHA-256("z-connect-rendezvous-v1:" || secret))`
is the code's single identifier and is where **no traffic goes**; it exists so
that a connect code and a pairing code demonstrably name different mailboxes.
The transport splits the rendezvous in two — see 20.5.

### 20.3 The four messages

`me` is the party's own contact code (§2.4 / §18.7) and the display name it
will be labelled with. `eph` is a fresh X25519 key pair, per ceremony.

```
commit(me, eph) = SHA-256( "z-connect-commit-v1:" || eph.pub
                           || u16be(len(code)) || code || name )

1. inviter  -> acceptor : c  = commit(inviter,  ephI)
2. acceptor -> inviter  : ephA.pub , c = commit(acceptor, ephA)
3. inviter  -> acceptor : ephI.pub , seal(channelKey, inviter's code + name)
4. acceptor -> inviter  : seal(channelKey, acceptor's code + name)

dh          = X25519(ephI, ephA)
channelKey  = HKDF(secret = dh, salt = 32 zero bytes,
                   info = "z-connect-channel-v1", 32)
```

The commitment is length‑prefixed on the code because the code is variable and
is not last; the name is last.

```
seal(k, m) = nonce || ChaCha20-Poly1305(key = k, nonce = nonce, plaintext = m)
             nonce  = 12 random bytes; the AEAD's 16-byte tag is appended
             m      = UTF-8 JSON: {"code": "<zc1./zc3. code>", "name": "…"}
                      "name" is omitted when there is none;
                      optionally "grp": 0 | 1, the group bit (below)
```

On the wire each message is a JSON object with `k` naming which it is and
every byte string in `b64`:

```
x1  {"k":"x1","c":   <32 bytes>}
x2  {"k":"x2","ephx":<32 bytes>,"c":<32 bytes>}
x3  {"k":"x3","ephx":<32 bytes>,"blob":<sealed>}
x4  {"k":"x4","blob":<sealed>}
```

A field of the wrong length, missing, or not decodable is an abort, not a
value to work around.

Each side MUST abort if the `dh` it computes is all zeros (RFC 7748 §6.1),
checked in constant time. A peer ephemeral of small order — the zero point, or
any point of order 2, 4 or 8, in any encoding — makes X25519's output all
zeros whatever the other key is, and the channel key would then be a constant
anyone can compute: the same on every leg a machine in the middle runs that
way, with every value derived from it. An honest ephemeral is never one, so the
check costs an honest ceremony nothing; and because each side checks the value
it computes, a refusal on one side is a refusal on both (`connect_test` 11).

Each side MUST check the other's reveal against the commitment it received:
the acceptor checks message 3's identity and ephemeral against the commitment
in message 1, and the inviter checks message 4's against the commitment in
message 2. A mismatch MUST abort — not continue at reduced assurance. An abort is
final for that invite: a retry would meet whoever produced the mismatch.

Both sides commit before either reveals. §10's responder chose its ephemeral
after seeing the initiator's, which is why §10's six digits are grindable
(about 2²⁰ tries at a value already read aloud) and these eight are not: with
both sides committed, a machine in the middle gets one blind guess.

**The group bit (`adr/0020`).** A reveal MAY carry one more member, `"grp"`,
the integer `0` or `1` and nothing else:

```
message 3: {"code": …, "name": …, "grp": 1}    this invite also brings the
                                               acceptor into a group
message 4: {"code": …, "name": …, "grp": 1}    the acceptor read 1 in message 3
```

* In message 3 it is the inviter saying whether the invite is also a link to a
  group — not which group: no id, no name, no size. The acceptor learns those
  from the group's own `ginvite` (§11) once the two have a pairwise session. In
  message 4 it is the acceptor repeating what it read (`0` when message 3
  carried no bit), which also tells the inviter that the acceptor's client
  knows what the bit means.
* A client that implements the bit writes it in **every** reveal it sends, `0`
  as readily as `1`. Connect frames are not padded to a bucket (20.5: an
  attributed envelope with the JSON as its payload), so the relay sees each
  frame's exact length, and a member written only for group invites would mark
  them. Measured at the relay, one inviter's message 3 is the same length with
  the bit at `1` and at `0` (654 bytes for a v3 identity named `Alice`); a
  client that writes no bit sends twelve bytes fewer, which tells the relay at
  most which build sent it — display names vary by more.
* A reader that implements the bit MUST treat a `grp` that is not the integer
  `0` or `1` as a malformed reveal and abort, as for a malformed `name`. An
  inviter that wrote the bit and reads a message 4 repeating a different value
  MUST abort: the two sides disagree about what the ceremony is, and a
  disagreement is never continued at a lower assurance. A message 4 with no
  `grp` is a client from before `adr/0020` and is not an error. A client that
  does not implement the bit ignores the member, as §14 requires.
* The commitments cover the code and the name, not the bit. That is enough:
  the bit travels inside the AEAD under the channel key, so the only party
  besides the two ends that can write it is one that holds that key — a
  machine in the middle running both legs, whose two legs show different
  digits (20.4). Such a party could set or clear the bit on either leg.
  Cleared on the acceptor's leg, it means no notice and no go‑ahead (20.6), so
  nobody joins; set, it shows a notice nobody meant, and the go‑ahead finds no
  group waiting. It cannot send the acceptor's go‑ahead, which travels in the
  pairwise session that only the holder of the acceptor's keys can speak in.

### 20.4 The confirmation string

Eight digits, over **both identities and both ephemerals**, with the parties
in canonical order by account key so the string is a property of the pair
rather than of who invited whom:

```
lo, hi      = the two parties ordered by accountEdPub (lexicographic)
okm         = HKDF(secret = dh,
                   salt = ephLo.pub || ephHi.pub,
                   info = "z-connect-sas-v1" || lo.accountEdPub || lo.pqCommit
                                             || hi.accountEdPub || hi.pqCommit,
                   8)
digits      = (first 7 bytes of okm, big-endian) mod 10^8, zero-padded to 8
sas         = digits[0..4] || " " || digits[4..8]
```

`pqCommit` is the account's post‑quantum commitment (§18.2), or 32 zero bytes
for a classical identity that has none — zeroes rather than absence so the
input is fixed length, and so a classical identity and a post‑quantum one for
the same key read differently, which is correct: they are different identities
to confirm. Every field is fixed length, so the concatenation is unambiguous.

Seven bytes, not four: the modulo of a 31‑bit value by 10⁸ is visibly biased,
and the width is the point.

Because the string covers both account keys and both post‑quantum commitments,
a confirmed comparison establishes what a safety‑number comparison (§2.5,
§18.5) establishes. A client that records the confirmation therefore records
the pair's **safety number** as the verified value, so every reader of that
value treats a connect‑verified contact identically to a scanned one
(`adr/0009`).

### 20.5 Carrying it over the relay

The two people are not online together — an invite sent at lunchtime may be
opened at midnight — so the ceremony is store‑and‑forward, not a live
handshake. Each side derives **two** throwaway relay identities from the
invite secret, one per role, and posts to the other's:

```
okm         = HKDF(secret = invite secret, salt = "" (empty),
                   info = "z-connect-relay-v1:" || role, 64)
                   role = "i" (inviter) | "r" (acceptor)
edSeed      = okm[0..32]      xSeed = okm[32..64]
routingId   = b64url(SHA-256(edPub))          — as for any identity (§2.2)
```

An empty salt is RFC 5869's "not provided" case. Two mailboxes rather than
one so neither side is handed its own frames back on the relay's flush.
Nothing in the relay changes: a routing id is `SHA-256(ed25519 pub)`, so a key
pair derived from a shared secret is a mailbox both sides can hold, and these
queue and expire like any other (§12, `QUEUE_TTL_HOURS`).

Each message of 20.3 is one ordinary envelope, sent authenticated as the
sending mailbox, with the JSON object as its payload and an envelope id of
`z-connect-c1`..`c4` respectively. A side that has not yet had an answer MAY
re-post its message; the relay dedupes an attributed envelope on (id, sender),
so a retry costs nothing and leaves one envelope. Anyone holding the invite
holds both mailbox key pairs — that is what makes the invite a bearer token
(R23), and why it is one‑time and short‑lived. In the middle of an invite of
version 1 the relay needs neither: it writes into both mailboxes as the relay,
and completes both legs (20.8).

A client MUST acknowledge (§12.3) every ceremony envelope it has consumed, and
MUST acknowledge whatever remains in its mailbox once the ceremony completes.
Otherwise the transcript stays in relay RAM for the queue lifetime, where a
party who later obtains the code can replay it.

An invite's lifetime is **24 hours** and is enforced by the clients, not by
the relay: it is well inside `QUEUE_TTL_HOURS`, and the relay is never told.
A client MUST refuse to act on an invite past its lifetime even when the
mailbox still holds the envelope, and MUST refuse a second attempt on an
invite that has been spent — completed, abandoned, or aborted.

The relay therefore sees a pair of ephemeral mailboxes exchange four envelopes
and go quiet. Neither ties to an account; the pair and its timing are visible,
as R1/R17/R18 already describe for ordinary traffic (R24).

### 20.6 What a client must show

Normative for the user‑facing half, because the ceremony's value is entirely
in the comparison being done properly:

* both renderings of an invite MUST come from one secret, and a client MUST
  accept either back;
* a client MUST NOT treat "the ceremony completed" as "the contact is
  verified". A completed ceremony proves that whoever answered the invite
  holds the keys they revealed, and nothing about who that is;
* on a confirmed comparison the contact is added verified (20.4);
* skipping the comparison MUST add the contact **unverified** and say so —
  this is trust‑on‑first‑use over whatever channel carried the link (R25),
  and for an invite of version 1 over the relay as well (20.8);
* a **mismatch** MUST offer no path that ends with a contact, and MUST spend
  the invite.

For a group invite link (`adr/0020`, the group bit of 20.3):

* an acceptor whose message 3 carried the bit at `1` MUST say, before it shows
  the digits, that the invite also brings them into a group, and MUST NOT send
  an answer (`gjoin`, §6.2) except when its person then answers the
  comparison — confirms it or skips it — and then only the answer its person
  chose: `go` 1 to join, `go` 0 to be a contact only. A mismatch sends
  nothing;
* an answer MUST carry the ceremony's **go‑ahead tag**, `t`:
  `HKDF(secret = channelKey, salt = 32 zero bytes, info = "z-connect-gjoin-v1",
  16)` — a key of its own, derived from the channel key (20.3) rather than
  the sealing key used as an HMAC key. Only the two ends of one ceremony can
  compute it — a machine in the middle has one per leg, and neither is the
  other's — so an answer counts only for the ceremony it was given on: not an
  earlier link between the same two people, and not a later one;
* each link is awaited and answered on its own, by its tag: two links between
  the same two people are two waits and two answers, and neither replaces,
  or resets, the other. An acceptor answers every `hello` from an inviter with
  every answer it still owes them;
* stopping a ceremony — the digits do not match, or the invite is given up at
  them — MUST NOT touch an answer owed from another: the identity a stopped
  ceremony revealed is one nobody verified, and anyone holding a person's
  public contact code can make a ceremony reveal it. An owed answer keeps its
  own ceremony's tag, which no other link's wait accepts, until the group
  arrives or its window ends;
* an inviter MUST NOT add an acceptor to the group unless the acceptor's
  message 4 repeated the bit AND a `gjoin` with `go` 1 carrying THIS
  ceremony's tag (compared in constant time) has arrived over the pairwise
  session — within the invite's lifetime from when it was made, and only if
  the inviter may add members at that moment (§11.1). A completed ceremony is
  not the acceptor's consent: it completes before either person has looked at
  a screen. The add is an ordinary `ginvite` (§11); nothing in the group's
  lists says how a member came. A `gjoin` with `go` 0 and this ceremony's tag
  ends the wait, and the inviter's person SHOULD be told the acceptor chose to
  be a contact only;
* a side whose contact list already holds the identity the ceremony revealed
  MAY answer a group link with that contact as it is — not replaced, and not
  marked as compared, since 20.4's verification is a statement about contacts
  the ceremony adds — and the answer travels over the sessions that already
  exist with it. "Holds" includes another device of that contact's account:
  one the account's own signed device list, as this side holds it, names, under
  the account key the digits covered (§3.4). Its answer, and the inviter's
  `hello`, are read from whichever of the account's devices they come;
* an acceptor whose message 4 did not repeat the bit can be added as a contact
  only, and the inviter's person MUST be told so;
* until the group's own `ginvite` reaches the acceptor, the group is named
  only on the inviter's screen: neither rendering of the invite, and no frame
  of the ceremony, names it.

### 20.7 Vectors

`vectors/connect/` pins this section: `connect.json` (the code and both its
renderings, the rendezvous id, two v3 identities, both ephemerals, both
commitment inputs, all four frames, the DH, the channel key, the SAS salt,
info, okm and digits, and the canonical order), `group.json` (`adr/0020`: a
ceremony whose message 3 carries the group bit and whose message 4 repeats it,
with both reveals' plaintexts and seal nonces recorded, so the member's exact
bytes can be checked, and the ceremony's go‑ahead tag from its channel key)
and `mailboxes.json` (the two
per‑role transport mailboxes an invite derives, with the HKDF info and okm and
the resulting routing ids, and their distinctness from the code's rendezvous
id and from both pairing rendezvous). Generated by `protocol/tool/vectors.dart`
and replayed by `protocol/test/vectors_test.dart`. The §14 rule applies:
bytes an existing implementation would compute differently mean new context
strings (`…-v2`), new vector files beside the untouched ones, and a new
subsection here. Version 2 (20.8) is that: `invite_v2.json` beside the three,
which are byte for byte what they were.

### 20.8 Version 2: the invite bound to its secret (`adr/0024`)

In version 1 the secret names the two mailboxes and nothing else (20.5). The
frames are plaintext, a commitment is a hash of what it commits to, and the
channel key is a function of the two ephemerals alone — so whoever carries
the frames, the relay or a CDN in front of it, can substitute both
ephemerals, commit and reveal under identities of its own, and hold a
channel key for each leg, and only the digits show it. Version 2 binds the
secret into the keys, so that nobody without the invite can make a frame
either side will take:

```
inviteKey   = HKDF(secret = invite secret, salt = "" (empty),
                   info = "z-connect-invite-v2", 32)
commit(me, eph) = HMAC-SHA256(key = inviteKey, "z-connect-commit-v2:"
                     || eph.pub || u16be(len(code)) || code || name)
channelKey  = HKDF(secret = dh, salt = inviteKey,
                   info = "z-connect-channel-v2", 32)
okm (20.4)  = as 20.4, with info "z-connect-sas-v2" || lo… || hi…
mailboxes   = as 20.5, with info "z-connect-relay-v2:" || role
rendezvousRoutingId = b64url(SHA-256("z-connect-rendezvous-v2:" || secret))
```

Everything else is 20.1–20.6 as written: the four messages and their
members, the seal, the group bit, the all‑zero check, both commitment
checks, every abort, the lifetime, and the go‑ahead tag — still HKDF of the
channel key under `z-connect-gjoin-v1`, and so bound to the invite through
it. A version‑2 frame has the members and the length of a version‑1 frame
for the same two identities: the relay cannot tell the versions apart by what
it carries.

A party without the invite that substitutes an ephemeral holds a channel key
neither side derives. The reveal it seals does not open where it is sent,
and the reveal sealed to it does not open for it. The acceptor aborts at
message 3, before its own reveal, message 4, is sent; the inviter aborts at
message 4. No identity is exchanged. A keyed commitment also says nothing to
anyone without the invite, where a version‑1 commitment let anyone holding
the frames and a candidate contact code test it once message 3 had shown the
ephemeral.

**Renderings.** Both start with the marker `9`:

```
text  = "9" || base32(secret), grouped in fives by "-"     e.g. 9ABCD-EFGHI-JKLMN-OP
link  = "https://" || host || "/i#9" || base32(secret)
```

`9` is not in RFC 4648's base32 alphabet, so a parser of 20.2 alone refuses
either rendering as not a connect code. A parser of this section removes the
separators and folds the case as 20.2 does; a code whose first character is
then `9` is version 2, and MUST be refused unless the rest is exactly sixteen
base32 characters. Any other code is version 1, read by 20.2.

**Versions meeting.**

* A client of this section MUST mint version 2, and MUST NOT run version 1
  for an invite it made as version 2, whatever arrives: there is no
  fallback, because the party that would choose one is the one in the
  middle (`adr/0009`, Rejected).
* It MUST accept a version‑1 invite and run it by 20.1–20.6, on version 1's
  mailboxes; its comparison screen MUST say, for such an invite, that until
  the digits are compared the relay could be in the middle too.
* A client of 20.2 alone refuses a version‑2 invite and sends nothing; the
  invite waits until its inviter discards it or it expires.
* A stored ceremony keeps its version, and one stored without a version is
  version 1. The two versions name disjoint mailboxes, so a run of one never
  meets, or waits on, a run of the other.

**The joiner's yes.** A client MUST NOT send any message of a ceremony — nor
connect to the relay for it — for an invite that reached it without its
person's own action on its screen (a link handed to it by the platform, say)
until that person says yes there. Typing or pasting an invite and opening it
is that yes.

**A blocked identity.** A client that has blocked the identity a ceremony
reveals (§8.1) SHOULD end the ceremony the moment that reveal opens, as an
abort: the acceptor before it sends message 4, the inviter on reading it.
Nothing is added.

What remains is the bearer token (R23): whoever holds the invite is the one
the ceremony reaches, and a party that holds it AND carries the frames can
still run both legs, with two different strings — what the digits are for
(R25).

`vectors/connect/invite_v2.json` records every value this section changes —
the invite key, both mailboxes and the rendezvous, both keyed commitments
with their inputs, all four frames with both reveals' plaintexts and
nonces, the channel key, the digits — and, from the same inputs, what
version 1 computes instead.

## 21. Handles (36–38)

*Normative for clients that claim, resolve or reach a handle. Opt‑in: an
account that never claims one is untouched, and nothing in §1–§20 changes.
The handle log is §21.5, the relay's introduction mailboxes are §21.6, and
what the reference client does with all of it is §21.8.
Design, the flaws of the first design and what may still be vetoed:
`adr/0015` (revision 2).*

A handle is a name someone can be found by, `nick.digits`. It resolves to an
**introduction mailbox** and never to the account key: the handle log holds
an owner key and an introduction key made for the handle and unrelated to
the account root, so resolving `@alice.42` yields a pseudonymous mailbox and
not the input to §19.1's label — R20's premise, that only someone who holds
an account's key can compute its transparency label, survives a guessable
name. Reaching someone by handle is the contact request of §8.1, sent to that
mailbox with a proof‑of‑work stamp; the acceptance comes back from the
account, with an acknowledgement signed by the introduction key.

### 21.0 Overview and context strings

| | What | Where |
|---|---|---|
| 21.1 | what a person types → a canonical handle, or the reason it is not one | client |
| 21.2 | the label a handle log is keyed by | client |
| 21.3 | the owner, introduction and recovery keys | client |
| 21.4 | the record a handle log holds, and the owner rule over its history | client, log, mirrors |
| 21.5 | the handle log | `kt/` in handle mode |
| 21.6 | introduction mailboxes at the relay | relay |
| 21.7 | the request, its proof‑of‑work stamp, and the acknowledgement | client, relay |
| 21.8 | the client: configuration, schedules, caps, connections, what it stores | client |

Every context string is disjoint from every other in this document:

```
z-handle-label-v1          the Argon2id salt of a label            (21.2)
z-handle-intro-x-v1        the HKDF salt of the introduction X key (21.3)
z-handle-recovery-v1       the HKDF salt of a recovery key         (21.3)
z-handle-rc-v1:            the recovery commitment                 (21.3)
z-handle-publish-v1:       what an owner key signs                 (21.4)
z-handle-recover-v1:       what a recovery key signs               (21.4)
z-handle-leaf-v1:          a handle log's leaf                     (21.5)
z-handle-sth-v1:           a handle log's tree head                (21.5)
z-handle-witness-v1:       a witness's co-signature of that head   (21.5)
z-intro-pow-v1:            a proof-of-work stamp                   (21.7)
z-intro-ack-v1:            an introduction acknowledgement         (21.7)
```

Byte strings inside a record are `b64url` without padding; `u32be`/`u64be`
are big‑endian. `vectors/handles/handles.json` pins 21.1–21.4 and 21.7:
inputs that are and are not handles (Unicode look‑alikes and every reserved
nick among the refusals), labels at the production parameters and at small
ones, keys and recovery keys from seeds — each introduction seed with both
its halves — claim, update and recover entries with every signing input,
owner‑rule histories with their verdicts (versions that are not the next and
signatures only a lenient verifier takes among them), values that are not
records (keys of small order or at or above p among them), a
request sealed to `xintro`, stamps over that envelope with the relay's
refusals, and an acknowledgement with the requester's. Generated by
`protocol/tool/vectors.dart`, replayed by `protocol/test/vectors_test.dart`,
and re‑derived from this section alone by `server/test/vectors.test.js` —
the labels included, with an Argon2id and a BLAKE2b written there from RFC
9106 and RFC 7693 and checked against those RFCs' vectors first. The §14
rule applies.

### 21.1 Handle grammar

```
handle    = nick "." digits
nick      = 3–20 of [a-z0-9_]: a letter first, no "__", no "_" last, not reserved
digits    = 2–6 of [0-9], compared as a string: "07" ≠ "7" (and "7" is not a handle)
canonical = utf8(nick || "." || digits)          ASCII; the only form hashed, signed or stored
display   = "@" || canonical
```

Input is normalised before any rule is applied, in this order: remove
leading and trailing ASCII whitespace (U+0009–U+000D and U+0020, and nothing
else); remove **one** leading `@`; map `A`–`Z` to `a`–`z`. Nothing else is
trimmed, folded or mapped, and any other character — every non‑ASCII
character, every punctuation mark but `_` and the one `.` — makes the input
invalid. There is no Unicode case folding or normalisation at all: a
Unicode‑aware lower‑casing turns U+212A KELVIN SIGN into ASCII `k` and
U+0130 into `i` and a combining dot, so a look‑alike could be typed into a
real name. With no folding it cannot be expressed. That is the whole
confusables rule.

Reserved nicks. A client MUST refuse to claim them **and MUST NOT resolve
them**: the log sees labels, never names, so it cannot refuse one, and a
reserved name claimed by a modified client is then reachable by nobody.

```
z zm zmessenger zmessengers support help admin administrator official
security team staff mod moderator system root everyone here null
undefined abuse privacy legal info contact noreply verify verified
```

The checks, in order. The first that fails names the reason a client shows;
the order decides only which reason is named, never whether an input is
accepted.

| # | the normalised input… | otherwise |
|---|---|---|
| 1 | is not empty | `empty` |
| 2 | holds only `a`–`z`, `0`–`9`, `_` and `.` | `badCharacter` |
| 3 | has a `.` with something after it | `missingDigits` |
| 4 | has only `0`–`9` after the first `.` | `digitsNotDigits` |
| 5 | has a nick that is not reserved | `reserved` |
| 6, 7 | has a nick of 3–20 characters | `nickTooShort`, `nickTooLong` |
| 8 | has a nick starting with a letter | `nickStartsWithNonLetter` |
| 9 | has a nick without `__` | `nickDoubleUnderscore` |
| 10 | has a nick not ending in `_` | `nickEndsWithUnderscore` |
| 11, 12 | has 2–6 digits | `digitsTooShort`, `digitsTooLong` |

*Implementation note:* `Handle.parse` in `protocol/lib/src/handles.dart`,
whose `reservedHandleNicks` is the one copy of the list in code.

### 21.2 Label

```
label = Argon2id( password = canonical, salt = utf8("z-handle-label-v1"),
                  m = 19456 KiB, t = 2, p = 1, T = 32 )          RFC 9106, version 0x13,
                                                                 no secret, no associated data
```

The vault's parameters (§13). A label keys the handle log (§21.5) and is
never shown. It is memory‑hard so that guessing names against a downloaded
log costs work per guess: measured on one core of a 2.1 GHz Xeon, 21 ms with
a native Argon2id — about fifty guesses a second, where SHA‑256 would allow
two million — and 127 ms in the app's pure‑Dart build (AOT). A client
computes it off the UI thread.

### 21.3 Keys and recovery

```
ownerSeed, introSeed = fresh 32-byte CSPRNG seeds; Ed25519 → ownerPub, introPub
introRid             = b64url( SHA-256(introPub) )                 §2.2's routing id: the introduction mailbox
xintroSeed           = HKDF( ikm = introSeed, salt = utf8("z-handle-intro-x-v1"), info = ∅, L = 32 )
xintro               = X25519pub(xintroSeed)                       what a request is sealed to (21.7)

code         = 15 CSPRNG bytes, shown once
recoverySeed = HKDF( ikm = code's 15 bytes, salt = utf8("z-handle-recovery-v1"), info = label, L = 32 )
recoveryPub  = Ed25519 public key of recoverySeed
rc           = SHA-256( utf8("z-handle-rc-v1:") || recoveryPub )
```

Neither the owner key nor the introduction key is derived from the account,
and nothing in the handle log names the account. The introduction seed is
the whole introduction identity — `(introSeed, xintroSeed)` is a §2.1
identity whose X seed is derived rather than drawn — so the client that
drains the mailbox authenticates as `introPub` (§12.1) and opens envelopes
with `xintroSeed` (§8), and rotating the seed rotates both keys. Only the
owner can check that a record's `xintro` comes from its `intro`'s seed; the
log does not try, and nothing depends on it. The code is the backup
recovery code (`BACKUP.md` §3): Crockford's base32, 24 characters and a
checksum, grouped in fives, with the same tolerance on input — printed
behind `ZHR-` rather than `ZBK-`, and an input carrying `ZBK` is refused by
name, because it is a real code for something else. The label is the HKDF
info, so a code recovers one handle. A client stores `ownerSeed` and
`introSeed` (v1: on the account's root device only, the one that drains the
mailbox) and NEVER the code or `recoverySeed`; only `rc` is published.
Rotating the introduction keys is a new `introSeed` and an update (21.4).
*Implementation note:* `handleIntroIdentity(introSeed)` returns the pair as
a `ZIdentity`, which the relay client and the sealed‑envelope opener take
as they take any other.

### 21.4 The record and the owner rule

```
value = utf8( JSON{ "k":"claim"|"update"|"recover",
                    "owner":b64url(ownerPub),             the owner AFTER this entry
                    "intro":b64url(introPub) | null,      null: paused or retired — resolves, cannot be reached
                    "xintro":b64url(xintro) | null,       null exactly when intro is
                    "pow":16..28,                         leading zero bits a stamp needs (21.7)
                    "rc":b64url(rc),                      the commitment AFTER this entry
                    "rpub":b64url(recoveryPub),           recover only
                    "rsig":b64url(rsig) } )               recover only
```

The members appear in exactly this order with no whitespace, `intro` and
`xintro` always — both `null`, or neither (a record with one `null` and not
the other is refused) — and `rpub` and `rsig` only on a recover. **A record
has one encoding.** A reader parses the value, decodes every byte string,
re‑encodes the record from what it decoded and refuses the entry unless the
bytes are identical: whitespace, another order, an escape, a duplicated or
unknown member, `null` for an absent member, `20.0` for `20`, padded or
standard‑alphabet base64, and base64 with its unused bits set are all
refused, so `SHA‑256(value)` names one record. This is a deliberate
exception to §0 twice over: a signature covers a hash of these JSON bytes,
and an unknown member is refused rather than ignored, because an ignored
member would let two byte strings carry one signed record. The record
evolves by a new `k` or a new context string, never by a member an older
reader would drop. An insertion‑ordered `jsonEncode` and a `JSON.stringify`
of an object built in this order both produce these bytes.

```
POST /kt/v1/publish   { "label":b64url(label), "v":v, "value":b64(value), "sig":b64(sig) }   to a handle-mode log (§21.5)

sig  = Ed25519.sign( ownerSeed, utf8("z-handle-publish-v1:") || label || u64be(v) || SHA-256(value) )
rsig = Ed25519.sign( recoverySeed, utf8("z-handle-recover-v1:") || label || u64be(v) || owner || rc )
```

`sig` is by the owner the rule names (below): the claimant, the current
owner, or — on a recover — the new owner it installs. `rsig` covers the new
`owner` and `rc` at this version, so it authorises exactly one change.
`value` and `sig` are `b64` as the KT publish route takes them (§19.6).

**The owner rule** holds for every entry, and one copy of it is applied by
the log on the wire and on replay of its own file (§21.5), by every mirror
over what it replicates, and by a client over whatever history it holds — in
one order, so the three refuse the same entry for the same reason. The
checks, in order, the first that fails naming the refusal (the numbers are
the rule's): first everything the entry says about itself, then what it says
about the label's history, the version last of all.

| rule | the entry… | otherwise |
|---|---|---|
| — | has a 32‑byte label, 1 ≤ `v` ≤ 2⁵³ − 1 and a 64‑byte `sig` | `malformed` |
| 6 | has a value of at most 1 KiB — looked at before the value is read | `tooLarge` |
| — | has a value that is a record: its one encoding, every key in it strong (below) | `malformed` |
| 1, 3, 4 | has `sig` verifying under the `owner` the record names — the claimant, the current owner (an update must name it), or the new owner a recover installs | `badSignature` |
| 4 | recover: has `rsig` verifying under `rpub` over (label, `v`, `owner`, `rc`) | `badRecoverySignature` |
| — | is, inside one history, for that history's label | `otherLabel` |
| 1 | is a claim, if it is the label's first entry; the claim fixes `owner` and `rc` | `notClaimed` |
| 2 | is not a claim, if the label has an entry | `taken` |
| 3 | update: names the current `owner`… | `ownerChanged` |
| 3 | …and the current `rc` | `rcChanged` |
| 4 | recover: has `SHA‑256("z-handle-rc-v1:" ‖ rpub)` equal to the current `rc` | `wrongRecoveryKey` |
| 5 | has `v` the label's NEXT version: 1 for a claim, the current one + 1 after it | `staleVersion` |

Rule 5 is "next", not "higher". Under "higher", whoever held the owner key —
a thief of the vault or of a backup and its code, the case the recovery code
exists for — could publish one update at 2⁵³ − 1, and the recover that has to
follow it had no version left: the code could never take the handle back
(found 2026‑10‑09, fixed 2026‑10‑10). With "next" a label's version is the
number of entries it has, the ceiling is 2⁵³ − 1 publishes away, and a
recover follows whatever the owner key published, at the next version. The
version is checked last so that a refusal names the label's version only to
an entry its owner or its recovery key signed: anyone can sign a record
naming keys of their own.

**Strong keys.** Every key in a record — `owner`, `intro` and `rpub` (Ed25519),
`xintro` (X25519) — is strong: 32 bytes whose y (Ed25519, the sign bit
cleared) or u (X25519, whose top bit must be clear) is below p = 2²⁵⁵ − 19
and is not that of a point of small order. A key of small order is one any
signature verifies under — R the identity and S = 0 does, for every
message — so a record naming one could be "signed", and its `ia` forged, by
anyone; an encoding at or above p is a second spelling of a key, which a
record with one encoding cannot have. The values, little‑endian hex:

```
Ed25519 y   0100000000000000000000000000000000000000000000000000000000000000   the identity
            ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f   order 2
            0000000000000000000000000000000000000000000000000000000000000000   order 4 (both)
            26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05   order 8 (two)
            c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a   order 8 (two)
X25519 u    0000000000000000000000000000000000000000000000000000000000000000
            0100000000000000000000000000000000000000000000000000000000000000
            e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
            5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
            ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
```

Whether a strong key is a point at all is not checked here: a key that is
not one verifies nothing.

**One signature rule.** `sig`, `rsig` and the acknowledgement `ia` (§21.7)
verify under a strong key A iff S (the second half) is below L, R (the first
half) is strong as a key is, and the bytes of [S]B − [k]A, k =
SHA‑512(R ‖ A ‖ M) mod L, encoded, are R's bytes — RFC 8032's equation
without the cofactor, compared as bytes. This is OpenSSL's computation with
everything either side was lenient about refused first: OpenSSL reads a key
modulo p and accepts R the identity, and `package:cryptography`'s Dart
verifier compares the two points by their x coordinates alone, so before
2026‑10‑10 each accepted signatures the other refused — four of the seven
disagreements among 92 histories an independent review generated; the other
three were versions past 2⁵³ − 1, which the log's replay and its mirrors took.

An accepted entry makes `(v, record)` the label's state: its owner, its
`rc`, its introduction keys and its difficulty. The rule compares `owner`
and `rc`, never `intro` or `xintro`, which an update may change freely. Changing the owner is a
recover and nothing else — an update keeps the owner — so a lost or stolen
owner key is answered with the code. The code is therefore the stronger
secret: whoever holds it can install themselves and a commitment of their
own, which is why it is shown once and never stored. A history in which any
entry is refused is not one an honest log serves: a client treats the handle
as unresolvable, and a mirror reports the log.

*Implementation note:* `applyHandleEntry` and `checkHandleHistory` in
`protocol/lib/src/handles.dart`, its signatures by `ed25519VerifyStrict`
(`ed25519_strict.dart`); `kt/` applies the same rule (§21.5,
`kt/lib/handles.js`). `kt/test/handle_rule_cases.js` builds 128 histories —
encodings, weak keys, signatures only one side's leniency took, versions
skipped, stale, at the ceiling and past it — and `kt/test/handle_rule_diff.test.js`
and `protocol/test/handle_rule_diff_test.dart` hold the log on the wire, on
replay and in a mirror, and the Dart library, to the same verdict on each.

### 21.5 The handle log

*Normative for `kt/` run with `KT_MODE=handles`, for its mirrors and
witnesses, and for every client that resolves a handle. Built in 36.2.*

The registry is a log of its own: `kt/` in handle mode, a separate service
with its own key and its own data, never the key‑transparency log of §19 —
heads name no log, so two logs under one key would have interchangeable
heads. It has §19's two trees, heads, proofs and routes, the bucket query of
§19.9 among them, with these differences.

**Labels and values.** A label is 32 bytes the client derives from a handle
(Argon2id, `adr/0015`); the log never sees a handle and cannot compute a
label. A value is the handle's record — canonical JSON, members in exactly
this order, no whitespace, base64url without padding, at most 1 KiB:

```
{ "k":"claim"|"update"|"recover", "owner":b64url(ownerPub), "intro":b64url(introPub)|null,
  "xintro":b64url(xintroPub)|null, "pow":16…28, "rc":b64url(32)
  [, "rpub":b64url(recoveryPub), "rsig":b64url(64)] }                                rpub, rsig: recover only
```

`owner` and `rc` are the owner and recovery commitment AFTER the entry.
`intro` and `xintro` are the introduction mailbox's Ed25519 key and the
X25519 key a request to it is sealed to (§8): both 32‑byte keys, or both
null while the handle is paused or retired — a record with one and not the
other is refused. The owner derives both from one introduction seed, `xintro`
from `HKDF-SHA256(ikm = introSeed, salt = "z-handle-intro-x-v1", info = "",
L = 32)` as an X25519 private key; the log cannot check that relation and
does not try. Whoever reads a record — the log, a mirror, a client —
re‑encodes what it parsed and refuses it unless the bytes are identical, so a
record has one encoding and nothing in it is malleable.

**The bytes.**

```
leafInput = utf8("z-handle-leaf-v1:")    || label || u64be(v) || SHA-256(value) || u64be(tsHour)
sthInput  = utf8("z-handle-sth-v1:")     || u64be(size) || logRoot || mapRoot || u64be(ts)
witness   = utf8("z-handle-witness-v1:") || sthInput
sig       = Ed25519(owner the record names, utf8("z-handle-publish-v1:") || label || u64be(v) || SHA-256(value))
rsig      = Ed25519(recovery key, utf8("z-handle-recover-v1:") || label || u64be(v) || owner || rc)    owner, rc: the new ones
rc        = SHA-256( utf8("z-handle-rc-v1:") || recoveryPub )
tsHour    = ⌊acceptedMs / 3 600 000⌋ × 3 600 000
```

The map tree (§19.2), the RFC 9162 log tree (§19.3) and the head's JSON
(§19.4) are §19's. Every context differs from §19's, so a handle head never
verifies as a key‑transparency head under any key, nor the reverse. A head's
`ts` is when it was signed, as in §19.4 — it is what a reader judges
freshness by; an entry keeps only the hour it was accepted in. Heads are
signed as the log grows (and at least every ten minutes), so whoever polls
them learns when each record arrived, to how often they poll; what the log
stores, and serves for an entry, is the hour. Signing heads only on the hour
would hide that from pollers, and would serve every change — a recover and a
rotation included — up to an hour after the log accepted it, with no signed
head behind the `201` meanwhile (`adr/0015`, F5).

**Publishing.**

```
POST /kt/v1/publish  { "label":b64url(label), "v":version, "value":b64(record), "sig":b64(sig) }
```

(The reference log decodes either base64 alphabet in any of these fields, as
on every route of §19.) It refuses, the first that applies:

| status and code | when |
|---|---|
| `400 bad_request` | a field is missing, `label` is not 32 bytes, `v` not an integer 1 … 2⁵³ − 1, `sig` not 64 bytes |
| `413 too_large` | the record is over 1 KiB |
| `400 bad_record` | the record is not its canonical encoding, a member is out of range, one of `intro` and `xintro` is null and the other is not, or a key in it is not strong (§21.4) |
| `403 bad_signature` | `sig` is not, by §21.4's one rule, the signature of the owner the record names |
| `403 bad_recovery` | a recover's `rsig` is not the signature of the `rpub` it names |
| `409 taken` | a claim on a label that has an entry |
| `403 owner_rule` | an update or a recover on a label with no entry; an update whose `owner` or `rc` is not the current one |
| `403 bad_recovery` | a recover whose `rpub` is not the one the current `rc` commits to |
| `409 stale_version` | `v` is not the label's next version — 1 for a claim, the latest + 1 after it |

— §21.4's order, so the refusal is the one a mirror and a client name — and
answers a publish it accepts `201 { "index", "sth" }`, as §19.6. The
entry's `ts` is `tsHour`. The gates of `kt/server.js` count handles where
they count accounts: one handle's publishes a day, and first publishes —
claims — a minute; and one handle's recovers a day apart from its other
publishes, so that whoever holds the owner key cannot keep the recovery out
by spending the handle's day.

**The owner rule** — enforced by the log on the wire AND on replay of its own
file, by every mirror and witness, and by a client over whatever history it
holds:

1. the first entry for a label is a claim; it fixes `owner` and `rc`;
2. a claim on a label that has an entry is refused (`taken`);
3. an update is signed by the CURRENT owner and keeps `owner` and `rc` —
   changing either is a recover;
4. a recover carries `rpub` with `SHA-256("z-handle-rc-v1:" ‖ rpub)` equal to
   the current `rc` and a valid `rsig`, is signed (`sig`) by the NEW owner it
   names, and sets the new `owner` and `rc`;
5. each entry is the label's next version: a claim is 1, every later entry
   the latest + 1;
6. a record over 1 KiB is refused.

The log keeps the current `owner` and `rc` per LABEL — 64 bytes a label,
nothing on an entry — and replays its own file under the same rule, the
version's bounds included: a line it did not write (an update or recover the
history does not allow, a version that is not the next or is past 2⁵³ − 1, a
signature that is not the owner's, a time finer than an hour, a record in
any other encoding, an unsigned line, a key‑transparency log's line) refuses
the start and names the rule.

**Serving.** Handles are public by design, so the log serves values in the
clear, and it stores nothing it does not serve: an `<entry>` is
`{ "index", "label", "v", "valueHash", "value", "ts", "sig" }` — no `fp`, no
`acct`, and `sig`, because a mirror needs it to hold the log to the owner
rule. Every route of §19.7 answers in that form, and a bucket's leaves carry
the record, `ts`, `sig` and `audit` (§19.9). A resolver MUST resolve a handle
by bucket: `/kt/v1/lookup` and `/kt/v1/history` name the label. `/health`
says `"mode": "handles"`.

**Mirrors and witnesses.** A mirror of the handle log does §19.10's checks
under these contexts, and holds every entry it replicates to the owner rule.
An entry that breaks it, under a head whose roots the mirror reproduced, is
a divergence like a fork: the log signed it, and the record names the key
that should have — a log that accepted a foreign update is caught there. A
`sig` that is not 64 bytes of base64 is a transport failure (§19.10); one
that is, and does not verify, is the log's. A witness co‑signs with the
handle witness context, and a client verifies its record with it.

**Vectors.** `vectors/kt/bucket.json` pins this log's publishes byte for
byte, its head, its bucket answers and the owner rule's refusals with their
codes (§19.11).

### 21.6 Introduction mailboxes at the relay (phase 37)

A handle resolves to an **introduction mailbox**: the routing id (§2.2) of an
introduction key — an Ed25519 key of its own, unrelated to the account's —
whose holder, the account's primary device, drains it like any mailbox.
Anybody who resolves the handle can address it, so once its owner has flagged
it the relay treats it differently in four ways: a send to it needs a proof
of work, it takes neither a large envelope nor a second copy of one it holds,
it is never woken by push, and it has a byte cap of its own.

**Flagging.** On a connection authenticated with the bound form (`v:2`,
§12.1) as the introduction key, the owner sends

```
C→S  { "t":"intro", "pow":N }      // an integer, 16 ≤ N ≤ 28
S→C  { "t":"intro_ok" }
```

The relay records the difficulty N for **that connection's own routing id** —
the frame names none — and answers `intro_ok`. The flag lasts
`OWNED_TTL_DAYS` (30) from the frame that set it, the lifetime phase 29 gives
a mailbox's ownership, and the same frame renews that ownership, so a flagged
mailbox always has the owned caps; a later login renews the ownership and
not the flag. A client therefore sends `intro` after each authentication as
the introduction key. When the flag lapses it leaves its **shadow** for as
long again (since 2026‑10‑15): for another `OWNED_TTL_DAYS` the mailbox
still asks a stamp at the last N, is still held to `INTRO_MAILBOX_BYTES`, is
still never woken and still holds one copy of an envelope, while the owned
caps follow the owner list alone — the owner has not been seen for a month,
so the mailbox is held to the first‑contact caps like any other (§12.4) if
the owner's logins have lapsed too. An `intro` on a shadow renews it into a
flag. Without the shadow a handle's mailbox whose flag had lapsed, or whose
owner's `intro` had been refused, was an ordinary owned mailbox — no stamp
asked, the 64 MiB owned cap — which anyone who had resolved the handle
filled for free until an honest stamped request was refused `queue_full`
(the second review of the handles fixes, 2026‑10‑10). A handle nobody
drains any more thus stops being guarded two months on. Repeating the frame
changes nothing; a new N replaces the old. On a connection that has not
authenticated, or that authenticated with v1 — a signature another relay can
have drawn out of the device (§12.1) — `intro` is answered
`error{not_authed}`; an N that is not an integer from 16 to 28,
`error{bad_intro}`; neither flags anything. A relay
that predates this answers `error{unknown_frame}`, which tells a client that
its introduction mailbox is not guarded there. What the relay keeps is a
routing id and a number, in a store of flags of its own: a login does not
move a flag, so no number of logins pushes one out (until 2026‑10‑10 a relay
kept them in memory with the owners it remembers, and authenticating
`OWNED_CAP` throwaway identities stripped them, as an independent review of
handles found on 2026‑10‑09). The store holds at most `INTRO_CAP` (100 000)
entries, flags and shadows; when it is full a new flag is taken and the
entry least recently renewed is forgotten for it — a shadow before any flag
— and the relay counts the forgetting (`z_intro_evicted_total`). A renewal
is the owner's own `intro`, sent on every drain, which no login stands in
for; so flags nobody renews cycle out first, and what a flood of fresh keys
can do to an owner is bounded by the cap: the owner's flag goes only once
`INTRO_CAP` others have been set since its last renewal, and comes back at
the owner's next drain. (From 2026‑10‑10 to 2026‑10‑15 a full store refused
a new flag, `error{intro_full}`, and the second review of the handles fixes
showed what that cost: whoever filled the store once denied every owner the
new flag a restart made them need, for as long as its flags lived. A relay
MAY still answer `intro_full` when it cannot hold a flag; this one does not.)
The frames are paced: past `INTRO_PER_RID_PER_MIN` (6) a minute from one
routing id, or — only where `CLIENT_IP_HEADER` names the client's address —
`INTRO_NEW_PER_IP_PER_MIN` (10) new flags a minute from one address, renewing
a flag already held not counting, `intro` is answered `error{rate_limited}`
and the flag stays as it was. Behind a front with no such header every
client is one address, and a pace per address was then one bucket for
everyone, which whoever flagged fresh keys ten times a minute held against
every owner; with the header unset the relay paces new flags by nothing but
the cap. In memory the store is lost on a restart; with a shared store it is
the key `intro:{routingId}`, which survives a restart of the relay but not of
the store (below).

**Proof of work.** A `send` to a flagged routing id — the flag in force or
in its shadow — MUST carry `pow`, the `b64url` of a 16‑byte nonce — exactly
22 characters, the canonical encoding — such that

```
h = SHA256( utf8("z-intro-pow-v1:") || rid || u32be(day) || SHA256(utf8(payload)) || nonce )
```

has at least N leading zero bits, counted from the most significant bit of
`h[0]`. `rid` is the 32 bytes the `to` routing id encodes; `payload` is the
frame's `payload` exactly as sent — the sealed envelope, `zs1.` included (§8);
`day = floor(unixTimeMs / 86 400 000)`, UTC days since the epoch. The relay
takes `day` to be its own today or yesterday, so a stamp is good for one to
two days of the relay's clock; a client whose clock is ahead of the relay's
past midnight makes one the relay refuses, and the refusal names the relay's
day so that one stamp re‑made for it is taken. A send without such a stamp —
none, one that is not 22 `b64url` characters decoding to 16 bytes, one made
for another recipient, another payload or another day, or one with fewer
bits — is refused before anything is stored and before any limit or
allowance is charged:

```
S→C  { "t":"error", "code":"pow_required", "id":envelopeId, "bits":N, "day":D }   // D: the relay's day
```

The same frame cannot succeed: the sender makes a stamp — a search of about
2^N SHA‑256 operations; checking one costs the relay a SHA‑256 over the
envelope and two over 99 bytes — and sends again. The stamp binds the
recipient, the envelope and the day and **nothing about the sender**: a sealed
request on a connection that never authenticated (§12.1) carries one like any
other, and the relay logs nothing of it; it keeps the stamp with the envelope
and hands it to the owner (below).
A `pow` on a send to a mailbox nobody flagged is never refused: one worth at
least 16 bits is handed on as below, and any other is ignored. A receipt the
relay queues itself (§12.5) is asked for none. The relay counts the refusals
(`z_intro_pow_refused_total`) and the stamped sends it took
(`z_intro_accepted_total`); `z_intro_mailboxes` is how many mailboxes are
flagged, shadows included.

**The owner checks the stamp too.** The `msg` (§12.2) that delivers an
envelope the relay took into a flagged mailbox carries the stamp it was
taken on:

```
S→C  { "t":"msg", "id":envelopeId, "payload":string, "ts":int, "pow":b64url(16 bytes), "powDay":D }   // D: the day the relay checked the stamp under
```

`pow` is the 22 characters the `send` carried, and `powDay` the day the
relay checked it under — its today or yesterday when it took the envelope,
so always the day of the envelope's `ts` or the day before — so the owner
computes the same `h` from its own routing id, the `payload` as delivered,
`powDay` and the nonce, and counts the same bits. An envelope taken into a
mailbox nobody flagged carries the two as well when its `send` carried a
stamp worth at least 16 bits for the relay's today or yesterday, on an
envelope of at most 64 KiB (the relay hashes nothing larger for a stamp);
any other carries neither. The owner's client checks every envelope its
introduction mailbox delivers this way, and drops one with no `pow`, with
fewer bits than the difficulty it set, or with a `powDay` that is neither
the day of its `ts` nor the one before.

**What a restart does to the flags.** A relay that keeps them in memory
loses every one, shadows included, when its process restarts, which every
deploy does. A relay with a shared store loses them when the store loses its
data: Redis or Valkey run with persistence off — as both shipped
configurations run it (`render.ha.yaml`, `server/docker-compose.ha.yml`) —
comes back from its own restart empty. The shadow is no help here: it is
kept where the flag is. Either way a mailbox is unflagged until its owner's
next `intro`, which its client sends after each authentication as the
introduction key, so not before the owner's app next drains (§21.8); that
`intro` is a new flag, which nobody can deny the owner (above). Until then
the relay takes sends to it with no stamp, as it would for any mailbox,
holding them against that mailbox's caps — the first‑contact caps, since
its ownership went with the flag — and delivers them with no `pow`; the
owner's check above drops them. An honest request loses nothing: its client
stamps it at the record's difficulty (§21.7), and the stamp travels with it
to an unflagged mailbox as to a flagged one. The cost of a lost flag is the
unstamped junk the relay holds until the owner's app drains it and drops
it.

**Size, and copies.** A flagged mailbox refuses a `payload` larger than
64 KiB — 65 536, counted as the relay charges an envelope less its 256 of
overhead (§12.4): the payload's length, for any payload the protocol
produces, and more for one the relay would have to hold escaped — with
`error{too_large, id}`, before the stamp is
looked at and before anything is stored or charged, and a client does not
retry it. A contact request is a few KiB, and a stamp is priced per envelope:
at the frame cap five would fill the mailbox. And it holds an envelope once:
a send whose `payload` is byte‑identical to one the mailbox holds — a retry
under the same `id`, or the same envelope and stamp under another — is
answered `sent` as if it had been stored, and is neither stored nor delivered
again, so a retry stays idempotent and a stamp, which binds the envelope,
cannot be replayed into copies. It must carry its stamp like any send (a
retry does), and it is not refused at the mailbox's cap, since it adds
nothing. The relay recognises a copy by the payload's SHA‑256 — the hash the
stamp is made over — which it keeps beside each envelope it holds for an
introduction mailbox and drops with it, so once the held envelope is
acknowledged or expires the same payload is new again. Copies are counted
apart (`z_intro_duplicate_total`). The relay decides in this order: size,
stamp, copy, then the caps.

**No push, and a cap of its own.** A flagged routing id's `push-register` is
refused `error{push_refused}`, flagging deletes any token it had, and no send
to it fires a wake: a wake per request would tell the push provider when
strangers write to a handle, and let anyone who can make a stamp ring the
owner's phone. A flagged mailbox is also held to `INTRO_MAILBOX_BYTES`
(4 MiB) on top of the owned caps; a send past it is refused
`error{queue_full, id}`, as at any per‑mailbox cap.

### 21.7 Requests and the acknowledgement

**The request.** The requester parses what was typed (21.1), computes the
label (21.2), resolves it (§21.5), and checks the record (21.4); `intro:
null` means the handle is paused. It then sends an ordinary contact request
(§8.1, unchanged) with `to` = `introRid`, **sealed to `xintro`** (§8, with
`recipientXPub` = the record's `xintro`) and addressed to the introduction
mailbox `introRid`, carrying a stamp:

```
payload  = Seal( recipientXPub = xintro, f = the requester's routing id, p = creq )      §8: the "zs1." string
day      = floor( unixMs / 86 400 000 )                      UTC days since the epoch, by the sender's clock
ridBytes = the base64url decoding of the send's `to`         (= SHA-256(introPub), 32 bytes)
envelope = utf8( payload )                                   the send frame's payload string (§12.2) exactly as sent, "zs1." included
input    = utf8("z-intro-pow-v1:") || ridBytes || u32be(day) || SHA-256(envelope) || nonce      99 bytes
nonce    = 16 bytes such that SHA-256(input) starts with at least `pow` zero bits                 the record's pow
send     = { "t":"send", "to":introRid, "id":…, "payload":payload, "pow":b64url(nonce) }
```

Zero bits are counted from the most significant bit of the digest's first
byte. The stamp names the mailbox and the envelope and never the sender; the
relay checks it, for its own today or yesterday, before storing anything
(§21.6). A refusal is the relay's error frame with the envelope's `id`, the
bits it requires and its own day:

```
S→C  { "t":"error", "code":"pow_required", "id":envelopeId, "bits":N, "day":D }
```

and a client whose clock disagrees with the relay's near midnight re‑stamps
once with `day` = `D`, and no more. A contact request is a few KiB; an
introduction mailbox refuses an envelope over 64 KiB (§21.6). Expected work
is 2^`pow` hashes — measured on one core here (pure Dart, AOT): 46 ms at 16
bits, 0.8 s at 20, 12 s at 24, and any one stamp can take several times its
mean. *Implementation note:* `createIntroPowStamp` is pure and synchronous,
so a client runs it in an isolate.

**The owner.** The owner's root device holds `introSeed`, drains the
introduction mailbox as the introduction identity (21.3, §21.6), opens each
envelope with `xintroSeed`, and accepts a `creq` whose `to` is one of its
introduction routing ids — rather than dropping it for not naming its own
routing id — showing it as coming *via @nick.digits*. It files one only when
the stamp counts by its own reckoning, whatever the relay did: the `pow` and
`powDay` the relay hands on with the envelope (§21.6) give at least the
difficulty in force in `introPowInput`'s hash, and `powDay` is the relay's
day of the envelope's `ts` or the day before; anything else is acknowledged
and dropped. It decides each envelope once, however often it is sent (§21.8).
It caps pending handle requests at 100, apart from requests by code or link
(§8.1), dropping the oldest unseen beyond that.

**The acknowledgement.** Accepting sends a `creq` back to the requester
(ADR 0011's accept path). That `creq` carries one more member:

```
creqId   = SHA-256( sigInput )            §8.1's sigInput of the request being accepted
ackInput = utf8("z-intro-ack-v1:") || requesterRidBytes || ownerAccountEdPub || creqId     111 bytes
ia       = b64url( Ed25519.sign( introSeed, ackInput ) )

{ "v":1, "t":"creq", "to":requesterRid, "ts":int, "bundle":…, "sig":b64, "ia":ia }
```

`requesterRidBytes` is the 32 bytes of the request's sender — `SHA‑256` of
its bundle's `edPub`, the sealed `f`. `ownerAccountEdPub` is the accepting
account's key, which is the acceptance's own `bundle.ed`: v1 accepts only on
the root device, and the root device's key is the account key (§3).
`creqId` names one request: a `creq` has no id member (a client files a
pending request under its sender's routing id, one per sender, which
`ackInput` carries already), and the hash of the signed bytes is what both
ends hold identically — the requester built them, and the owner verified a
signature over them. It covers the requester's keys, the mailbox the request
went to, its timestamp and its name. `ia` is outside `sig`, whose input §8.1
fixes; it needs no cover, being a signature itself over the account that
signed the `creq` carrying it. A reader that predates handles ignores it
(§0) and sees an ordinary acceptance.

The requester verifies the `creq` as §8.1 says, then `ia` under the
introduction key it resolved for a pending outgoing handle request, with its
own routing id, the acceptance's `bundle.ed` and the `creqId` it kept when it
sent the request (it keeps the id, not the name it sent, which may have
changed since). On success it adds the owner as an unverified contact —
*@nick.digits accepted — compare safety numbers to verify*. An `ia` that does
not verify is ignored, and the acceptance is an ordinary request. The
acknowledgement proves that whoever holds this handle's introduction key
accepted this request for this account; it says nothing about who the
account is, which is what the safety number is for.

### 21.8 The client (phase 38)

*Normative for the reference client (`app/lib/core/handles.dart`). Another
client may choose other numbers; it must keep the property each one is
there for, which is said beside it.*

**Configuration.** A handle log is an address and a pinned Ed25519 key, set
as the transparency log's are (§19.5) — its own key, never the
transparency log's, and never one fetched from the log. A client with no
handle log configured says, wherever a handle could be claimed or looked
up, that handles are unavailable, and does nothing else; the reference
build's defaults are empty until a log is deployed. A request goes to the
requester's own relay: as for every envelope today (`adr/0008`, deferred),
the owner must use the same one.

**Claiming** is never offered during account setup (F5). The client parses
the handle (21.1) — two random digits by default, each draw checked free,
up to five draws; or 2 to 6 the person chooses — and checks it is free: a
lookup (below) whose bucket, verified, has no leaf for the
label. It draws `ownerSeed`, `introSeed` and the code (21.3), shows the code
once as `ZHR-…`, and keeps nothing until the code has been typed back;
then it keeps the claim, and neither the code nor `recoverySeed`. The claim
(`v` = 1, `pow` 20) is published at a moment drawn uniformly from **10 to 60
minutes** later: the log keeps only the hour, and its operator also sees
when the request arrives, so the delay puts the claim's moment apart from
the moment the person was using the app — the account's relay traffic and
transparency‑log publishes of that minute. A moment that passed while the
client was not running is drawn again, from **3 to 20 minutes** after the
next start, because a start is itself a burst. A pending claim can be
cancelled: nothing has been published. `409 taken`: the client reads the
label back, and a record naming its own owner key is its claim, published
by an earlier attempt whose answer was lost; any other is someone else's,
and the person picks other digits — a new claim, with a new code, since a
code's key depends on the label. `429`, `5xx` or no answer: five minutes
later. A restore never publishes a claim it carries (below).

**The introduction mailbox.** Only the account's root device holds
`ownerSeed` and `introSeed` and drains the mailbox (v1). A drain first
reads the account's own record from the log, as a lookup does: an answer
older than the version this device holds changes nothing; one naming another
owner key — the code was used — or an introduction key this device does not
hold — the inbox was moved, by another copy of the account restored from an
older backup or by whoever has its owner seed — makes the handle lost to
this device, which then neither flags nor reads the mailbox, until the code
brings it back on new keys; a paused one is read once more without `intro`;
a newer one is taken in, its difficulty with it; and a log that cannot be
asked changes nothing. Then a relay connection of its own, authenticated
(§12.1, v2) as the introduction identity — never one of the account's, so
the relay never sees the account's routing id and the introduction routing
id on one connection — sends `intro` with the record's `pow` (the newest
record it knows; the higher of the log's and its own when the two are the
same version) after it authenticates (§21.6), never registers a push token,
reads until nothing has arrived for 1.5 s (at most 20 s), acknowledges every
envelope whose fate is decided (§6.8), and closes. An `intro` answered
`unknown_frame`, `intro_full` or `rate_limited` leaves the mailbox read all
the same, and the handle screen says that the relay is not guarding it right
now and that the phone still checks every stamp. Drains run a uniformly
drawn **3 to 30 seconds** after
the app comes to the foreground — not in the second the account's own
connection reopens — then every **15 minutes, give or take a third**, while
it stays in front; never in the background; and at once after a publish
that changes the introduction keys or the difficulty. Every envelope's stamp
is counted before the envelope is opened, as the relay counted it (§21.6):
with no `pow` and `powDay`, with a `powDay` that is neither the relay's day of
the envelope's `ts` nor the day before, or with fewer bits than the
difficulty in force — the record's `pow`, or for **2 days** after a change the
previous one when that was lower, so a stamp made just before a raise still
counts — it is acknowledged and dropped, never filed, and counted on the
device and nowhere else. An envelope that does
not open with `xintroSeed`, is not a `creq`, is not addressed to the
mailbox (`to` = `introRid`), or is not signed by the identity that sealed
it is acknowledged and dropped; one that could not be filed for a reason
that passes (the vault busy) is left with the relay for the next drain —
so nothing can wedge the mailbox. A verified request is filed beside every
other pending request, marked as coming *via @nick.digits*, with its
`creqId`; one from a blocked routing id is dropped, and one from a contact
is that contact's answer (§8.1). It is held to §8.1's rules for its signed
`ts` and for the last request taken in from the same requester, so a stamped
request the relay hands over again after a drain, or one declined, is not
filed again. And a request is decided once, whoever sends its envelope
again: the drain remembers each envelope that opened as a request, whatever
became of it, by 6 bytes of a hash of its SHA‑256 — the hash its stamp
commits to — keyed with a salt of the device's own, under its stamp's day,
in the vault, and drops a copy before opening it. The digests are kept one
by one, exactly, so no flood changes what the ledger refuses: two envelopes
share a digest once in 2⁴⁸, and an envelope never seen is refused by
mistake once in a hundred million even with every kept day full (the second
review of the handles fixes, 2026‑10‑10, drove the Bloom filter of fixed
size the ledger had before to refuse 70 % of honest requests with 500 000
distinct stamped requests in a day — each refusal silent). A day holds at
most **524 288** — 4 MiB in memory, in rows of 512 in the vault, about what
the relay hands the owner in a day of drains (5 000 envelopes a drain, 96
drains); one more that day is filed without being remembered and counted,
and the handle screen warns that a copy of one of the rest of that day
could be filed again. A day is kept until the fifth day after it begins:
the relay takes a stamp for day D through D+1 and holds an envelope for up
to 72 hours (`QUEUE_TTL_HOURS`), so the last copy it could hand over comes
before the end of D+4. Stamped junk takes no room: it opens to nothing each
time it comes. What the drains dropped — envelopes with no stamp that
counts, copies refused, requests filed unremembered — is counted by day
beside the digests, kept as long, shown on the handle screen in both
languages, and sent nowhere; a refused copy is of a request this device
decided already, so nothing is set aside and nothing honest is lost. At
most **100**
pending requests that came through the handle are kept, counted apart from
those by code or link (§8.1), so a wave through a public handle cannot push
out a request from someone who had the code: past 100, the oldest the person
has not seen on the Requests screen goes, so a wave of stamped requests
cannot push out one already looked at — and when every older one has been
seen, the newcomer is the one dropped.

**Finding and asking.** Any device. The client parses what was typed
(reserved nicks refused), computes the label off the UI thread, and asks for
the label's bucket without naming it (`app/lib/core/handle_lookups.dart`):

- *k.* Not the log's `bucketBits` — it sits beside the signed head, outside
  it, so the operator (or whatever ends its TLS, R44) writes it — and not
  the signed size, which counts entries: whoever holds owner keys, the
  operator first, inflates it with versions for the price of a publish.
  Labels are what a bucket hides a handle among, so k is an estimate of the
  labels the client counted itself, in buckets it verified complete. First
  from buckets drawn at random, which say nothing about any lookup, as the
  transparency client makes its first count (§19.9.1): one at the finest k
  the signed size allows, ⌊log₂(size / 32)⌋, then coarser by as many bits as
  it fell short of 32 labels (five for an empty one), until one holds 32 or
  k is 0; its count times 2^k is the estimate, and k is
  ⌊log₂(estimate / 32)⌋. A bucket counts only under the head the lookup
  held when it was drawn — one signed after could hold labels minted into
  it on seeing it asked — so under a head that grew the bucket is not
  counted and another is drawn; a bucket refused as too large is asked one
  bit finer, with a fresh draw. Eight buckets at most, refusals and heads
  that moved counted; a log that has not ended the count by then is
  unreachable for that lookup. A bucket of fewer than 32 is an estimate
  only at k = 0, where it puts k at 0, so a log can put k nowhere by
  refusing or by moving its head — only deny the lookup — and minting into
  a bucket moves k only when it was minted before the bucket was drawn,
  which no bucket a client will draw can be told from any other. Then
  from each lookup's buckets: under 16 labels a bucket on average, k
  falls at once to what they bear out; at 64, it rises one
  bit, and no more in one lookup (minted into on seeing them asked or not:
  a lookup's four buckets count alike, the handle's among them, so what the
  log sees of this rule — the k of the next lookup — says nothing about
  which was the handle's). A lookup asks at the least of that,
  ⌊log₂(size / 32)⌋ and `bucketBits`. So a log is asked at buckets of 16 to
  64 labels on average, 32 to 64 once it has settled, whatever `bucketBits`
  it serves and however it inflates its size — but labels of its own make
  the buckets smaller than they look, and no count a client can make tells
  them from real ones.
- *The head.* A lookup holds the head it read first and takes a later one
  only as the transparency client takes a head (§19.5): the same roots, or
  a larger size with the log's consistency proof from the held size to it. A
  smaller size, the same size under other roots, or no proof is a bad
  answer: the log contradicted itself within one lookup. Nothing is held
  between lookups (R50).
- *Decoys.* The label's bucket is asked among three decoys': the buckets of
  SHA‑256(key ‖ "z-handle-decoy-v1:" ‖ label ‖ i), i = 0, 1, 2, under a key
  of 32 random bytes the install draws once and keeps. Each bucket once
  (some coincide at a small k), in prefix order, one `GET /kt/v1/bucket`
  each (four buckets of a large log can be more than the 256 KiB one `POST`
  may carry). A function of the label and the key: fresh decoys would leave
  the handle's bucket as what two lookups of it have in common, and one
  kept set as what lookups of two handles do not. So the same handle asks
  the same buckets again — at a finer k, a child of each — and another
  handle's share nothing with them but chance. Each install draws its own
  key, and a backup carries it: one handle looked up from two installs the
  log can link — an account's two devices, at one address; a reinstall
  without a backup — asks two sets that meet in exactly its bucket, and
  the log learns which bucket was the handle's.
- *Refusals.* A bucket refused as `bucket_too_large` is never narrowed to
  the half that holds the label: the estimate is made again from random
  buckets, once — a log that grew past it needs a finer one — and the
  lookup asked again at it; refused again, the log is unreachable. So k can
  move several bits in one lookup, but only to what a fresh count of 32
  labels bears out.
- *Answers.* Each verified under the pinned key (§19.9, §21.5) on a head
  signed no more than **24 hours** before the device's clock: the log
  re-signs at least every 10 minutes, so an older head is a log that
  stopped or an old answer served again, and nothing under it is used — the
  person is told the answer is stale and to check the device's date and
  time (a day, not minutes, as for the transparency log, because a phone's
  clock can be hours out). A leaf whose version exceeds its index + 1, or
  is 2^53 − 1 (no version follows it, so a change to the handle would fail
  as arithmetic), is a bad answer. The latest record is held to its one
  encoding (21.4), to its kind — a claim at version 1 and nothing else
  there — and to the leaf's `sig` under the record's own `owner` over 21.4's
  publish input — the owner a claim names, an update keeps and a recover
  installs alike — and, on a recover, `rsig` under `rpub`. A record that
  fails any of this is not used and nothing is sent.
- *What it remembers.* For each handle found, the account's own excepted:
  the owner key, the recovery commitment, the version and SHA‑256 of the
  record — at most **256**, the one found longest ago going first. A later
  lookup must find that record at that version, or a later version signed
  by the owner remembered — whatever came between — or the recover whose
  `rpub` opens the commitment remembered. Anything else is refused, nothing
  is sent, and the person is told which: another owner (an update naming
  one, which the rule forbids, or a recover after entries the client did not
  see: from one record the code's work cannot be told from the log's), or
  another history (an older version, another record at a version seen, or
  no record). The person may look it up as new, which forgets what was kept
  and takes what the log shows now. The owner rule over the label's whole
  history stays the log's and its mirrors' to hold (§21.5): a bucket carries
  each label's latest entry only, and the client fetches no history —
  earlier entries are reached by naming the label or by indexes it does not
  have — so a first lookup, or a log that goes on showing a reader the owner
  it remembers after the handle moved on, is caught only by a witness (R50).

`intro` null: the handle is paused, and nothing is sent. Otherwise the
client builds a `creq` to `introRid`, seals it to `xintro`, and keeps the
handle, its owner and introduction keys and the request's `creqId` — at most
**20** handles, the three latest ids for each — before sending, so an
acceptance that comes back can be matched. It stamps the envelope (21.7) at
the record's `pow` for its own day, off the UI thread, and sends it on an
anonymous connection **opened for that send alone** and closed after: not
the account's long‑lived anonymous link, which — once the request is
accepted — carries the account's envelopes to the account the handle
introduced, so that one connection would send to both the introduction
mailbox and that account. On `pow_required` it stamps once more, for the
relay's `day`, still at the record's `pow`, and stops after that.

**Accepting** is §8.1's accept, plus `ia` (21.7) signed with the
introduction seed of the mailbox the request reached — kept, after a
rotation or a retirement, for as long as a pending request needs it — on
the `creq` the acceptance sends, which is queued ahead of the session's
opening hello so that the requester holds the account before the hello
arrives. A request whose introduction seed is no longer held is accepted
without `ia`, and reaches the requester as an ordinary request.

**The requester's side.** A `creq` carrying `ia` is checked against every
request kept: its introduction key, the requester's own routing id, the
`creq`'s `bundle.ed` and each kept `creqId` — at most sixty signature checks,
which is what one forged acceptance can cost. A match adds the sender as a
contact at the classical floor, unverified; records the handle it came
through; puts *@nick.digits accepted — compare safety numbers to verify* in
the chat; forgets the kept request; and sends a `creq` back (§8.1), so that a
hello the owner sent before this device held them is sent again. No match —
no `ia`, a forged one, the genuine one carried by another account — and the
`creq` is an ordinary request.

**Managing** is the root device's. Each change reads the label's latest
record first and is refused when its owner is not this device's key (the
code was used: the handle is lost to this device); it then publishes at the
latest version + 1, at once — a change answers spam, and binds nothing new
to the account:

```
pause       intro, xintro = null; the mailbox is read once more, then not at all; the keys are kept
resume      the same introduction keys again
new inbox   a new introSeed; the old mailbox is read once more without `intro`, so its flag lapses
            with its ownership (§21.6); its seed is kept while a pending request still needs it
difficulty  16–28 (the reference client offers 16, 18, 20, 22 and 24)
give up     intro, xintro = null, and the device forgets the handle's keys; the label and its history
            stay (the log is append-only), and only the code brings the handle back
```

**Recovering** is the root device's, on the account that held the handle or
on one that never did: the handle and its code (a `ZBK` code refused by
name); the label's latest record read; the code's key must give the record's
`rc`; new owner and introduction seeds and a new code, shown once and typed
back; then a `recover` at the latest version + 1, published **at once** —
not after a delay like a claim, because `rsig` covers that version, which an
update made meanwhile would overtake, and the code is not kept to sign
again. A device whose handle is recovered elsewhere finds, the next time it
reads its record, an owner that is not its own, and manages it no more.

**What is stored**, sealed in the vault: the handle (canonical), its label,
`ownerSeed`, `introSeed`, `pow` — and for two days after a change the
previous one — `rc`, the version and where it stands
(pending with its moment, held, live, paused, taken by another, lost); the
digests of the requests decided and the counts of what the drains dropped,
as above; for
each pending request that came through the handle, the handle, the mailbox
it reached, its `creqId`, when it arrived and whether it has been seen; the
introduction seeds a pending request still needs; the requests kept for
matching an acceptance; the handle log's address and key; for lookups, the
decoy key, the estimate of k and what was found of each handle (above); and, for a
contact made through a handle, which handle. Never the code or
`recoverySeed`.

**Backup and restore.** The archive carries all of it but those digests
and counts in one record,
`{"t":"handle","keep":1,"v":1,"kv":{…}}` (`BACKUP.md` §5), which a build
that does not know it keeps and writes back. A restore drains the mailbox —
reading the record first, so re‑flagging it at the difficulty the record
asks, or leaving a mailbox the record no longer names — and publishes
nothing by itself: a claim that was pending
when the backup was made comes back held, published only when the person
asks, since the device it came from may have published it since or been
overtaken.

**Linked devices** hold no handle keys, drain nothing and manage nothing
(v1); they may look a handle up and send a request, and they see the
contacts the root device makes through the handle by self‑sync (§9).
