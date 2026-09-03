# Z — Protocol Specification, version 1 (frozen)

**Status:** FROZEN. Protocol v1 was frozen on 2026‑09‑03 for external review
(roadmap Phase 5.1). Every construction below is pinned by the machine‑checked
test vectors in [`vectors/v1/`](vectors/v1/) — the Dart reference
implementation (`protocol/`) must reproduce them bit‑for‑bit
(`protocol/test/vectors_test.dart`), and an independent implementation written
from this document alone, in Node.js with no shared code, must verify them
(`server/test/vectors.test.js`). Both run in CI. A change to anything normative
here is a protocol version bump, not an edit (§14).

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
and `bindingSig` verifies under §2.3. (Multi‑device accounts use the `zc2.`
code of §3.3; every implementation MUST still accept `zc1.`.)

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
non‑empty and **every** certificate verifies under §3.1 against `acct`.

### 3.4 Signed device list

The account's authenticated statement of its current device set, distributed
to contacts inside the ratchet (inner kind `devlist`, §6.2):

```
eds   = the deviceEdPub of every listed device, sorted lexicographically
input = utf8("z-devlist-v1:") || utf8(decimal(version) || ":") || eds[0] || eds[1] || …
sig   = Ed25519.sign(accountEdSeed, input)

JSON: { "acct":b64(accountEdPub), "ver":version, "devs":[deviceCert...], "sig":b64(sig) }
```

A receiver MUST check that `acct` is the account key it already holds for
that contact, verify every certificate (§3.1) and `sig`, and reject a list
whose `ver` is lower than the highest verified version it already holds (an
equal version is a repeat and may be re‑applied). It then fans messages out to
exactly the listed devices (§9) and accepts messages only from them.

### 3.5 Legacy mapping

A `zc1.` code is read as a one‑device account: `accountEdPub = ed`, with the
single device `{ded: ed, dx: x, id: "legacy-v1", sig: bindingSig, legacy: true}`.

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
3. Skip to `header.n` on the receiving chain (step 4), then
   `(mk, ckr) = KDF_CK(ckr); nr += 1`, decrypt, unpad.
4. *Skip(until)*: if `ckr = ∅`, do nothing. Reject if `until − nr > 512`.
   While `nr < until`: `(mk, ckr) = KDF_CK(ckr)`, store `mk` in `skipped` under
   `b64(dhrPub) || "|" || decimal(nr)`, `nr += 1`. `skipped` holds at most
   1536 keys; the oldest are evicted first.

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
| `text` | `body:string` | chat message |
| `file` | `fid, name, size:int, mime, sha256:b64, fk:b64, fn:b64, chunks:int` | attachment offer (§7) |
| `timer` | `sec:int` | set the disappearing timer for the conversation (0 = off) |
| `read` | `mids:[string]` | read receipts |
| `dlv` | `mids:[string]` | end‑to‑end delivery receipts (§6.3) |
| `devlist` | `list:string` (the JSON of §3.4, as a string) | account device‑set update |
| `ginvite` | `gid, name, ver:int, members:[{ "b":ContactBundleJSON, "n":string }]` | group create/update (§11) |
| `gmsg` | `gid, body` | group text (§11) |
| `gleave` | `gid` | sender left the group (§11) |

`ContactBundleJSON` is `{ "ed", "x", "sig", "name" }` as in §2.4 (all `b64`);
every bundle in a `ginvite` MUST be verified (§2.3) before use.

### 6.3 Receipts

On persisting an inbound `text`, `file` or `gmsg`, the recipient sends
`dlv{mids:[mid]}` back over the same pairwise session (best effort). This
replaces the relay's `delivered` frame, which sealed sender (§8) makes
impossible. `read` is sent when the user views the message.

### 6.4 Deduplication

Delivery is at‑least‑once (§12.5). Receivers MUST deduplicate on
`(senderRoutingId, mid)` after decryption; a duplicate is acknowledged to the
relay but not processed again.

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
shorter; an empty file is one empty chunk. `chunkSize` is 480 KiB in this
implementation (the relay's 1,000,000‑character frame cap, less the double
base64 expansion); a receiver MUST accept any chunk size. The offer carries the
file's `name`, `mime`, `size`, `chunks` and `sha256` (of the plaintext file,
`b64`). The receiver verifies every tag, reassembles in `idx` order, checks
`size` and the whole‑file SHA‑256, and only then surfaces the file. The
reference app caps attachments at 24 MiB.

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

`recipientXPub` is the X25519 key of the destination **device** (from its
device certificate or `zc1.` bundle). Opening: check the prefix, decode, split
`ephPub(32) || nonce(12) || ct || mac(16)` (reject if shorter than 60 bytes),
recompute `key` with `X25519(myXSeed, ephPub)`, decrypt, unpad (reject if the
length prefix exceeds the data), parse, and route `p` through §5/§7 using `f`
as the sender. Any failure is a silent drop.

This layer provides no authenticity and needs none: `p` is ratchet
ciphertext (or a chunk sealed under a key that only the offer's recipient
holds) that only the claimed sender can produce; a forged `f` simply fails
inner decryption. The relay stores and delivers `zs1.` payloads with **no
sender attribution** (§12), matches acks by envelope id alone, and emits no
`delivered` frames for them (§6.3 replaces those). Senders MUST seal every
envelope for which they know the recipient device's X25519 key; the unsealed
forms remain valid for backwards compatibility only.

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
utf8( JSON{ "thread":routingIdOrGid, "dir":"out"|"in"|"ping", "inner":b64(innerMessageBytes) } )
```

`dir = "ping"` with a `hello` inner is the proactive session opener and is
ignored on receipt; `"out"`/`"in"` insert the inner message into `thread` as
sent/received respectively. Attachment chunks are not re‑encrypted for sync:
the chunk payloads (§7) are forwarded verbatim to each of the user's other
devices, which decrypt them with the mirrored offer.

**Device‑list distribution.** A root‑holding device signs the account's device
set (§3.4) whenever it changes and sends it to every contact as `devlist`.
Revocation is removal from the list at a higher version.

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
                   "cert":deviceCert(new device), "hostcert":deviceCert(existing device),
                   "contacts":[ AccountBundleJSON... ] }
```

Both users MUST compare the SAS before the existing device sends `enroll`; a
machine‑in‑the‑middle sees a different ephemeral on each leg and therefore a
different SAS on each screen. The new device MUST verify that `cert` carries
its own keys and verifies (§3.1) under `acct` before installing. `root` is
present only if the host chose to let the new device enroll further devices.
`AccountBundleJSON` is `{ "acct", "devs", "name" }` (§3.3 without the wrapper).

## 11. Groups

A group is **pairwise fan‑out over the existing 1:1 sessions**: there is no
group key. Every group message is encrypted separately to each member (and
sealed to each of their devices), so group traffic inherits the forward secrecy,
post‑compromise healing and sender authenticity of §5, and the relay cannot
tell group messages from direct ones.

* `gid` is a string beginning with `g` (*implementation note:* `"g" ||
  b64url(12 random bytes)`). The creator is the **admin** for the group's life.
* `ginvite` carries the full member list (verified `zc1.` bundles plus display
  names) at membership version `ver`. A receiver accepts a `ginvite` for a
  known group only from the admin and only with `ver` strictly greater than
  its current version; for an unknown group it creates it with the sender as
  admin. Unknown members are auto‑added as contacts (unverified) so the
  receiver can decrypt from them. A list that no longer includes the receiver
  means they were removed.
* `gmsg` is accepted only from a current member of a known, not‑left group.
* `gleave` removes the sender from the receiver's copy of the list; the admin
  bumps `ver` so later invites exclude them.

Consequences an implementer must preserve: membership authenticity rests on
the admin's pairwise channel; a removed member keeps the history they already
received but every remaining member rejects anything they send afterwards; a
message reaches the members the sender's current list names, so two members
with different versions can briefly disagree.

## 12. Relay protocol

One WebSocket per device. Frames are JSON text messages. The relay is
untrusted, keeps everything in RAM only, and never learns keys, plaintext,
names or (with §8) senders.

### 12.1 Connection and authentication

```
S→C  { "t":"challenge", "nonce":b64(32 random bytes) }           // first frame
C→S  { "t":"auth", "pub":b64(edPub), "sig":b64( Ed25519.sign(edSeed, utf8("z-relay-auth-v1:") || nonce) ) }
S→C  { "t":"ready", "id":routingId }                              // then queued frames are flushed
```

On a bad signature the relay sends `error{bad_auth}` and closes with code
4001. A second connection for the same routing id replaces the first, which is
closed with code 4002. Before `ready`, `send` and `push-register` are answered
with `error{not_authed}`, `recv` and `push-unregister` are ignored, and `ping`
is answered; a repeated `auth` is ignored.

### 12.2 Frames after authentication

```
C→S  { "t":"send", "to":routingId, "id":envelopeId, "payload":string }
S→C  { "t":"sent", "id":envelopeId, "queued":bool }               // false = handed to a live socket, true = held in RAM
S→C  { "t":"msg", "id":envelopeId, "from"?:routingId, "payload":string, "ts":int }
C→S  { "t":"recv", "id":envelopeId, "from"?:routingId }           // "I persisted it" — drop it
S→C  { "t":"delivered", "id":envelopeId, "to":routingId, "ts":int }   // attributed envelopes only
C→S  { "t":"push-register", "token":string, "platform":string }   S→C { "t":"push-ok" }
C→S  { "t":"push-unregister" }                                     S→C { "t":"push-ok" }
C→S  { "t":"ping" }                                                S→C { "t":"pong", "ts":int }
S→C  { "t":"error", "code":string, "id"?:envelopeId }
```

`envelopeId` is 1–64 characters, chosen by the sender (*implementation note:*
`b64url` of 16 random bytes; it is unrelated to `mid`). `payload` is an opaque
string ≤ `MAX_ENVELOPE_BYTES` (default 1,000,000) characters; the WebSocket
frame limit is that plus 4096. Error codes: `rate_limited`, `bad_json`,
`internal`, `bad_auth`, `not_authed`, `bad_send`, `too_large`, `bad_push`,
`unknown_frame`.

**Sealed handling.** A `payload` beginning with `zs1.` is stored and delivered
with **no** `from` member, is acknowledged with a `recv` that omits `from`,
and produces no `delivered` frame. Any other payload is stamped by the relay
with the authenticated sender's routing id (`from`), acknowledged with `recv
{id, from}`, and, once acknowledged, produces a `delivered` receipt routed to
the sender (queued if offline).

### 12.3 Push

`push-register` stores an opaque token (≤ 4096 chars) for the routing id for
`PUSH_TTL_DAYS` (30) days from its last registration, in every coordinator. When a `send` is queued because the
recipient is offline, the relay sends the token a **content‑free** wake signal
("you have mail"): no sender, no id, no payload. Retired tokens are deleted.

### 12.4 Limits

Per connection: a token bucket of `RATE_PER_SEC` (80) frames/s with burst
`RATE_BURST` (240); excess frames get `error{rate_limited}`. Per recipient
queue: `MAX_QUEUE_MSGS_PER_USER` (5000) envelopes and `MAX_QUEUE_BYTES_PER_USER`
(64 MiB), oldest dropped first; every entry expires after `QUEUE_TTL_HOURS`
(72). Multiple relay instances may share queues and presence through Redis;
the frame protocol is identical.

### 12.5 Delivery semantics

1. `send` → the relay enqueues the envelope in the recipient's RAM queue and,
   if the recipient is connected, pushes `msg` immediately; it replies `sent`.
2. The envelope stays queued until the recipient sends `recv` (meaning it is
   safely in the recipient's encrypted local store). On (re)connect the whole
   queue is flushed again, so delivery is **at‑least‑once** and receivers
   deduplicate (§6.4). A client MUST NOT `recv` before persisting.
3. Undelivered envelopes vanish on expiry, on eviction, or on relay restart.
   Availability is explicitly not a security property of the relay.

### 12.6 HTTP endpoints (informative)

`GET /health` (liveness), `GET /metrics` (Prometheus, aggregate only — no
per‑user data), `GET /` and `GET /privacy` (static pages).

## 13. Local storage and identity backup (informative)

The app keeps all state in a SQLite vault with per‑cell XChaCha20‑Poly1305
encryption under a 256‑bit master key held in the OS keystore (optionally
wrapped by an app passphrase). Attachments are stored as separate files sealed
under per‑file keys kept in encrypted cells. Disappearing messages are swept
every 20 s. An identity backup (`.zid`) is:

```
inner = JSON{ "v":1, "identity":{ "edSeed":b64, "xSeed":b64 }, "name":string, "contacts":[...] }
key   = Argon2id(passphrase, salt = 16 random bytes, m = 19456 KiB, t = 2, p = 1, L = 32)
file  = JSON{ "z":"backup", "v":1, "kdf":"argon2id", "m":19456, "t":2, "p":1,
              "salt":b64, "nonce":b64(24 bytes), "ct":b64, "mac":b64 }      // XChaCha20Poly1305(key, nonce, ∅, inner)
```

Backups contain identity and contacts only — never messages.

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

`docs/vectors/v1/` holds one JSON file per suite: `identity`, `handshake`,
`ratchet` (a complete two‑party transcript with three DH ratchet steps and an
out‑of‑order delivery), `sealed_sender`, `attachments`, `multidevice`,
`pairing`, `inner_messages`. Byte strings are lowercase hex; wire strings
(codes, envelopes, payloads) are given verbatim; every random draw the
reference implementation made is recorded (`random_draws`, `*_seed`, `nonce`)
so any implementation can replay a vector exactly. See
[`vectors/README.md`](vectors/README.md) for the file layout and how to run
the two verifiers. The vectors were produced by `protocol/tool/gen_vectors.dart`
with the library's RNG replaced by a seeded splitmix64 DRBG (the standard
known‑answer‑test technique); production builds have no such hook exposed.

## 16. Security considerations (summary — see THREAT_MODEL.md)

* **Trust is established out‑of‑band.** A contact code or account code
  substituted before it reaches the user substitutes the identity; safety
  numbers (§2.5) are the detection mechanism. There is no key directory to
  trust — and, as yet, no key transparency log to catch a substituted one.
* **The relay sees transport metadata.** IP addresses, timing and padded
  sizes of envelopes and which mailboxes are read are visible transiently and
  are not stored. Sealed sender (§8) removes the sender; size buckets blunt
  length analysis; nothing here hides that a mailbox is active.
* **Sealed sender is unauthenticated by design** (§8); the inner layer
  authenticates. A relay can therefore inject garbage that costs the recipient
  a failed decryption — a denial‑of‑service, not a confidentiality issue.
* **Group membership is admin‑asserted** over the admin's authenticated
  channel (§11); there is no cryptographic group state, so no post‑compromise
  security beyond the pairwise sessions' own.
* **Device lists are account‑signed** (§3.4). A compromised account seed can
  enroll devices; revocation is a new list at a higher version and reaches
  contacts only when they next receive it.
* **Endpoints are trusted.** Disappearing messages and local encryption are
  conveniences against a lost device, not defences against a compromised one.
* **`legacy` records** (§3.1) are verified under the v1 binding rule; they
  cannot be used to introduce an unsigned device (this closed an audit‑prep
  finding in the pre‑freeze code, which accepted the flag at face value).
