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
`v` higher than known, or the same `v` with a different `h`, means a device
holding the account key issued a list this device never saw — surfaced loudly
(the T1/T2 signal, actionable only by the owner).

**Removal notice.** When a contact installs a verified list that *drops*
devices it previously held, it sends each dropped device one final inner
message of kind `dlrm` (§6.2) over the still‑known pairwise session before
forgetting it. A rogue cannot suppress it: it is sent by the contact, not the
account. It SHOULD be queued with the same durability as a message — the
reference client's outbox — since it is sent exactly once and a client whose
link happens to be down at that moment would otherwise never send it. And
whatever else was queued for the dropped device MUST be discarded at the same
moment: a durable queue must not deliver, after the list said otherwise, what
a down link happened to be holding. The same applies to a root removing one
of its own devices and the self‑sync traffic queued for it.

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
contact‑add hello. Distribution therefore converges without user action.

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
| `text` | `body:string`, opt. `rt:string` | chat message; `rt` = the `mid` this replies to (§6.4) |
| `file` | `fid, name, size:int, mime, sha256:b64, fk:b64, fn:b64, chunks:int`, opt. `rt` | attachment offer (§7) |
| `timer` | `sec:int` | set the disappearing timer for the conversation (0 = off) |
| `read` | `mids:[string]` | read receipts |
| `dlv` | `mids:[string]` | end‑to‑end delivery receipts (§6.3) |
| `devlist` | `list:string` (the JSON of §3.4, as a string) | account device‑set update |
| `ginvite` | `gid, name, ver:int, members:[{ "b":ContactBundleJSON, "n":string }]` | group create/update (§11) |
| `gmsg` | `gid, body`, opt. `rt` | group text (§11) |
| `gfile` | `gid` + the `file` members, opt. `rt` | group attachment offer (§7, §11) |
| `gleave` | `gid` | sender left the group (§11) |
| `pqek` | `alg:"ML-KEM-768", ek:b64` | v2 post‑quantum key offer (§17); consumed by the session layer, never shown |
| `dlrm` | `acct:b64, v:int, h:b64` | device‑list removal notice (§3.6); tells a device it was dropped from account `acct`'s list |
| `react` | `rt:string, emo:string` | reaction to one message (§6.5); `emo:""` withdraws |
| `greact` | `gid` + the `react` members | reaction inside a group (§6.5, §11) |
| `edit` | `rt:string, body:string` | new text for one of the sender's own messages (§6.6) |
| `gedit` | `gid` + the `edit` members | the same inside a group (§6.6, §11) |
| `del` | `mids:[string]` | delete‑for‑everyone of the sender's own messages (§6.6) |
| `gdel` | `gid, mids:[string]` | the same inside a group (§6.6, §11) |

`ContactBundleJSON` is `{ "ed", "x", "sig", "name" }` as in §2.4 (all `b64`);
every bundle in a `ginvite` MUST be verified (§2.3) before use.

Independently of kind, an inner message MAY also carry the device‑list
transparency members `dl` and `pdl` (§3.6), each `{ "v":int, "h":b64 }`;
clients that do not implement 7.7a ignore them.

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
  member sees who reacted, and one member cannot overwrite another's.

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

### 6.3 Receipts

On persisting an inbound `text`, `file`, `gmsg` or `gfile`, the recipient
sends `dlv{mids:[mid]}` back over the same pairwise session (best effort). This
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
shorter; an empty file is one empty chunk. A receiver MUST accept any chunk
size. *Implementation note:* `chunkSize` is 140 KiB — the largest raw chunk
whose payload, once sealed (§8), pads into the 262144 bucket, which is the
largest bucket whose base64url envelope stays under the relay's
1,000,000‑character frame cap (§12.2). Every chunk envelope is therefore the
same size on the wire. The offer carries the
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
inner decryption. The relay stores and delivers `zs1.` payloads with **no
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
utf8( JSON{ "thread":routingIdOrGid, "dir":"out"|"in"|"ping"|"acct"|"acctreq"|"hist", "inner":b64(innerMessageBytes) } )
```

`dir = "ping"` with a `hello` inner is the proactive session opener and is
ignored on receipt; `"out"`/`"in"` insert the inner message into `thread` as
sent/received respectively; `"acct"` carries a `devlist` inner and updates the
receiving device's knowledge of its *own* account's current signed list (§3.6
root discipline); `"acctreq"` (a `hello` inner) asks the root to send that
list — a root answers with `"acct"`, any other device ignores it; `"hist"`
carries an inner of kind `hist` whose `items` replay recent history to a
device that was just linked: each item is
`{ "t":thread, "mid", "o":outgoing, "k":"text"|"gtext", "b":body, "ts", "sn"? }`,
stored as an ordinary row (deduplicated on `mid`) and ignored for a thread the
receiving device does not hold. The reference app replays the newest 200 text
messages per chat in batches of 100; attachments are not replayed. Attachment
chunks are not re‑encrypted for sync: the chunk
payloads (§7) are forwarded verbatim to each of the user's other devices, which
decrypt them with the mirrored offer.

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
* `gfile` is a group attachment offer under the same rule: one file key and
  one set of chunks (§7), the offer sent to every member over their pairwise
  session and the chunks queued for every member's mailbox. A member removed
  before a send never receives the key.
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
closed with code 4002. Before `ready`, `push-register` and a `send` whose
payload is not sealed are answered with `error{not_authed}`, `recv` and
`push-unregister` are ignored, and `ping` is answered; a repeated `auth` is
ignored.

**Anonymous connections** (2026‑09‑11, 16.1 — a relaxation, so a compatible
extension under §14: a client that authenticates first behaves as before). A
`send` whose payload begins with `zs1.` is accepted on a connection that has
never authenticated, rate‑limited like any other frame, and acknowledged
with `sent` as usual; such a connection owns no mailbox and receives nothing.
Clients SHOULD send every sealed envelope on a connection of this kind and
receive on an authenticated one, and MUST NOT fall back to the authenticated
connection for a sealed envelope when the anonymous one is down — a sealed
envelope on an authenticated connection is attributable to that connection's
identity by the relay process (`THREAT_MODEL.md` R21). The relay's `/metrics`
counts sealed envelopes that arrived on anonymous connections
(`z_sealed_unattributable_total`).

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
`unknown_frame`, and — since 2026‑09‑11, compatible extensions under §14 —
`queue_full` and `store_full` (§12.4), each carrying the `id` of the `send`
it answers.

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
`RATE_BURST` (240); excess frames get `error{rate_limited}`. A `recv` is
exempt (2026‑09‑11): a device draining a backlog acknowledges as fast as
it persists, an acknowledgement costs the relay one small read and one
small removal, and a limited one was simply dropped — the entry it named
stayed queued and a mailbox of more than the burst could not be emptied in
one connection. Per recipient
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
(`/health` `presenceStale`).

### 12.5 Delivery semantics

1. `send` → the relay enqueues the envelope in the recipient's RAM queue and,
   if the recipient is connected, pushes `msg` immediately; it replies `sent`.
2. The envelope stays queued until the recipient sends `recv` (meaning it is
   safely in the recipient's encrypted local store). On (re)connect the whole
   queue is flushed again, so delivery is **at‑least‑once** and receivers
   deduplicate (§6.4). A client MUST NOT `recv` before persisting.
3. A flush of a large backlog is **paged**: the relay sends `FLUSH_PAGE`
   (64) entries and waits until the socket has drained below
   `FLUSH_HIGH_WATER_BYTES` (1 MiB) before the next page, so what it holds
   for one slow reader is a page plus that mark rather than the whole
   backlog (up to 64 MiB). Two consequences for a client. A live `msg` may
   arrive *between* pages, so the flush is not ordered against traffic that
   arrives during it — which changes nothing a client may rely on, since
   delivery was already at‑least‑once and unordered across reconnects. And
   a flush that is interrupted (the socket closes) simply stops: nothing was
   acknowledged, so the next connection flushes the same queue again.
4. Undelivered envelopes vanish on expiry or on relay restart — never to
   make room for another envelope (§12.4). Availability is explicitly not a
   security property of the relay.

### 12.6 HTTP endpoints (informative)

`GET /health` (liveness), `GET /metrics` (Prometheus, aggregate only — no
per‑user data), `GET /` and `GET /privacy` (static pages).

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

`docs/vectors/v2/` holds the v2 suites `mlkem768` (ML‑KEM‑768 known answers,
including implicit rejection) and `pq_ratchet` (the §17 upgrade transcript);
`docs/vectors/v1/` holds one JSON file per v1 suite: `identity`, `handshake`,
`ratchet` (a complete two‑party transcript with three DH ratchet steps and an
out‑of‑order delivery), `sealed_sender`, `attachments`, `multidevice`,
`pairing`, `inner_messages`. A suite may gain vectors for a compatible
extension (a new inner kind, say); existing vectors are never changed. Byte
strings are lowercase hex; wire strings
(codes, envelopes, payloads) are given verbatim; every random draw the
reference implementation made is recorded (`random_draws`, `*_seed`, `nonce`)
so any implementation can replay a vector exactly. `docs/vectors/kt/` pins
the transparency log (§19.9) on the same terms. See
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
v1, and an active network attacker cannot force a downgrade: the offer is
encrypted and authenticated, `pqct` is in the AAD, and stripping either only
produces an authentication failure. A v2 implementation MAY be run with the
extension disabled; it then behaves as v1 (this is how the v1 vectors are
regenerated).

### 17.5 Security properties and limits

* Every message with `pq:1` is confidential against an adversary that breaks
  X25519 later but never learns `K`. `K` is protected by ML‑KEM‑768 against
  such an adversary, and `dk` never leaves the offerer and is erased on use.
* The first messages of a conversation (the session‑opening `hello`, the
  offer itself, and anything sent before the offer is answered) are
  classical. The reference app sends the contact‑add hello and answers it
  with the offer, so in the normal flow everything the user types is mixed.
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
(fail‑closed). One previous generation is retained — ample for in‑flight
reordering given the interval dwarfs a round trip. Everything is a compatible
extension: `pqg` is a new optional header member and `g` a new optional offer
member, both ignored by a generation‑0‑only implementation, no version bump.

## 18. Protocol v3 — post‑quantum identity *(in progress)*

v2 (§17) protects **confidentiality** against a future quantum adversary: a
recording made today is not readable once a CRQC exists, because every message
key is mixed with an ML‑KEM‑768 secret. It does nothing for
**authentication**. Account keys, device keys, device certificates and safety
numbers are all Ed25519, so the same adversary could forge a device
certificate — mint a device that appears to belong to an account — without
reading a word of what it recorded. v3 closes that.

Status: §18.1 and §18.2 are implemented and vectored (`docs/vectors/v3/`);
device certificates, safety number v2 and the compatibility window are not yet
written. Nothing in v1 or v2 changes.

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
handshake, sessions — consumes it unchanged. The encoded code is ~370 bytes.

**The commitment is carried as an optional member of a v1 code, and that is
what clients emit:**

```
zc1.<base64url(json)>
json = { "v":1, "ed":…, "x":…, "sig":…, "pqc":b64(pq_commit), "name"?:string }
```

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

`ack`, when present and true, says the sender already holds the receiver's
key, checked against its own commitment. It is omitted otherwise, so a
message without it is byte-for-byte what earlier clients send.

The receiver MUST check `SHA-256("z-pqid-v3:" || pk)` against the `pqc` from
the scanned code, in constant time, and MUST refuse the identity on a
mismatch. It MUST NOT fall back to treating the contact as classical: a
mismatch means the key that arrived is not the key the person in front of you
committed to. A v2 peer ignores the unknown kind, as with `pqek`.

A key that arrives with **no** commitment to check it against is ignored, not
stored. That is what makes it safe to volunteer the key to every contact
rather than only to those known to hold a `zc3.` code — which the sender
cannot know anyway, since holding a commitment is the *receiver's* state.

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
| `hybrid` | the key arrived and matched the commitment |

A key that arrives and does **not** match is a fourth situation, and it is not
a state of the identity: the identity stays `pendingPostQuantum`, because
nothing was upgraded. The refusal MUST be recorded durably and surfaced, and
it MUST be announced **once** — the offer is re-made on traffic (§18.2), so a
client that announces per arrival hands whoever is sending the bad key a way
to bury the warning under copies of itself.

### 18.4 Hybrid device certificates

A device certificate is the account's statement that a device belongs to it,
so forging one inserts a rogue device into every contact's fan‑out. It is the
one thing a quantum adversary could do to this design without touching a
single recorded ciphertext, and it is what §18.1 exists for.

The signing input is **unchanged** from §3.2:

```
input  = utf8("z-device-cert-v1:") || device_ed_pub || device_x_pub || utf8(device_id)
cert   = { ed, x, id, sig, mlsig }
sig    = Ed25519.Sign(account_ed_sk,  input)
mlsig  = ML-DSA-65.Sign(account_ml_sk, input)
```

Both signatures cover identical bytes, so no valid pair can attest to
different devices. A verifier MUST require both. Dropping `mlsig` MUST be a
parse error, not a certificate that verifies classically — the classical half
of a forgery by a quantum adversary is genuine, so a classical‑only check can
no longer gate anything.

A **legacy** record (§3.3 — a v1 identity read as a device) has no hybrid
form: there is no account key distinct from the device key, so there is
nothing for a post‑quantum half to attest to. Attaching one MUST be rejected,
or a v1 identity could be presented as post‑quantum verified.

Devices keep **classical** keys of their own. A device's Ed25519 key
authenticates it to the relay and fixes its routing id; the relay is untrusted
and its mailboxes hold only sealed ciphertext, so a forged relay
authentication gains nothing a quantum adversary would not already have. What
must be hybrid is the account's attestation, and that is the certificate.

**Distribution is constrained, and the constraint is not obvious.** A hybrid
certificate is ~3.4 KB. Sealed sender pads envelopes into buckets (§8) so the
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

A device list therefore continues to carry classical certificates and keeps
its bucket, and the post‑quantum half travels separately. **What travels is
one signature over the list, not one per certificate — see §18.9**, which
supersedes what this paragraph originally implied. The certificate format
above is unchanged; it is what enrollment hands to the device it describes,
where size does not matter.

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
QR bigger. Measured: ~370 bytes for a root device's code, ~640 for a linked
device's, against a ceiling near 800 for a symbol that scans reliably.

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
  has always started every contact unverified for the same reason.

What remains is that any of an account's devices can make a *new* chat appear
on the others. That is bounded rather than eliminated — any device can add a
contact, because the user scans on whichever one is in their hand — so a
client SHOULD show where such a contact came from, and MUST NOT present it as
something the user did on this device.

### 18.9 A post-quantum signature over the device list

The account signs its device list under ML‑DSA‑65 as well as Ed25519, over
**exactly the bytes §3.4 already defines**:

```
input  = utf8("z-devlist-v1:") || utf8(decimal(version)) || ":" || eds[0] || eds[1] || …
sig    = Ed25519.Sign(account_ed_sk,  input)     carried in the list, as today
mlsig  = ML-DSA-65.Sign(account_ml_sk, input)    delivered separately
```

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
262 144 bytes.

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
from 0 in acceptance order; an entry's `index` is its leaf index.

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
3. if a witness is configured (§19.8), fetch its record, verify the log's
   signature and the witness's over it, and require it to be consistent with
   the head: equal roots at equal size, or a verifying consistency proof
   from the log between the two sizes in either direction;
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
includes it. The log MUST keep `acct` for replay validation and MUST NOT
serve it. The log does not open the value.

### 19.7 HTTP API

All responses are JSON; error responses are `{ "error":code, "message":text }`.

| method and path | response |
|---|---|
| `GET /kt/v1/sth` | the current head (§19.4) |
| `GET /kt/v1/consistency?first=m&second=n` | `{ "sth", "first":m, "second":n, "proof":[b64…] }` — `PROOF(m, D[n])`; `second` defaults to the head's size |
| `GET /kt/v1/lookup/<label hex>` | `{ "sth", "map":{ "leaf":{index,v}\|null, "bitmap":b64, "siblings":[b64…] }, "entry":<entry>\|null, "inclusion":{ "index", "size", "path":[b64…] }\|null }` |
| `GET /kt/v1/history/<label hex>` | `{ "sth", "entries":[ { "entry":<entry>, "inclusion":… } … ] }`, oldest first |
| `GET /kt/v1/entries?start=i&count=k` | `{ "sth", "start":i, "entries":[<entry>…] }` — `k ≤ 1000`, clipped to the head's size (mirrors) |
| `POST /kt/v1/publish` | §19.6 |
| `GET /kt/v1/pub` | `{ "pub":b64 }` — informative |
| `GET /health` | `{ "size", "labels", "sthTs" }` — informative |

An `<entry>` is `{ "index":i, "label":b64, "v":version, "fp":b64,
"valueHash":b64, "value":b64, "ts":ms }`; a reader MUST check
`SHA-256(value) == valueHash` before hashing the leaf. Every proof in a
response is relative to the `sth` in that response.

### 19.8 Mirrors and witnesses

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

### 19.9 Vectors and versioning

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
beside the untouched ones, and a new subsection here.
