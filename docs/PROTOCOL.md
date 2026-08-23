# Z — Protocol Specification (v1)

This is the wire‑ and crypto‑level specification of Z. It is precise enough to
write an interoperable client. All multi‑byte integers are little‑endian unless
noted. All binary blobs on the wire are base64 (standard, with padding) inside
JSON.

## 1. Primitives

| Purpose | Algorithm |
|--------|-----------|
| Identity signing | Ed25519 |
| Diffie‑Hellman | X25519 |
| KDF | HKDF‑SHA256 |
| Chain KDF / MAC | HMAC‑SHA256 |
| AEAD (messages, files, vault) | XChaCha20‑Poly1305 (24‑byte nonce) |
| Hash / routing id | SHA‑256 |
| Backup KDF | Argon2id (m=19 MiB, t=2, p=1) |

## 2. Identity

An identity is two key pairs generated from two independent 32‑byte seeds:

```
edSeed → Ed25519 (edPub, edPriv)      // signing
xSeed  → X25519  (xPub,  xPriv)       // key agreement
```

The **routing id** (the only address the relay sees) is:

```
routingId = base64url_nopad( SHA256(edPub) )
```

### 2.1 Contact code

Public identity shared out‑of‑band. `bindingSig` proves the X25519 key belongs
to the Ed25519 identity:

```
bindingSig = Ed25519_sign(edPriv, "z-bind-v1:" || xPub)

code = "zc1." || base64url_nopad( utf8(JSON({
  v:1, ed:b64(edPub), x:b64(xPub), sig:b64(bindingSig), name?:string
})))
```

A receiver MUST verify `bindingSig` before use and reject on failure.

### 2.2 Safety number

Both sides derive the same 60 decimal digits (12 groups of 5) to detect key
substitution. Inputs are the two Ed25519 public keys sorted lexicographically
so the result is symmetric:

```
(lo, hi) = sort(edPubA, edPubB)
K = HKDF-SHA256(secret = lo || hi, salt = "z-safety-v1",
                info = "display", L = 60)
group_i = ( Σ_{j=0..4} K[5i+j] · 256^(4-j) ) mod 100000   // 12 groups
```

## 3. Session establishment (X3DH‑style, no server prekeys)

Because Z has no server storage, the responder's long‑term X25519 identity key
serves as the (implicit) signed prekey. The initiator contributes a fresh
ephemeral `EK`.

Initiator A → responder B:

```
DH1 = X25519(IK_A_priv, IK_B_pub)      // identity ⋈ identity
DH2 = X25519(EK_A_priv, IK_B_pub)      // ephemeral ⋈ identity
SK  = HKDF-SHA256(secret = 0xFF*32 || DH1 || DH2,
                  salt = 0x00*32, info = "Z-X3DH-v1", L = 32)
```

Responder B computes the mirror (`X25519(IK_B_priv, IK_A_pub)` and
`X25519(IK_B_priv, EK_A_pub)`), obtaining the same `SK`.

Associated data bound into every AEAD operation of the session:

```
AD = SHA256("Z-AD-v1" || edPub_initiator || edPub_responder)
```

`sessionId = base64url_nopad(SHA256(EK_pub))[0:22]`.

The initiator attaches `EK_pub` on outbound messages until it has received one
message on the session (so a responder can bootstrap even after the first
packet is lost/reordered).

## 4. Double Ratchet

Standard Signal Double Ratchet.

```
KDF_RK(RK, dh)  = HKDF-SHA256(secret=dh, salt=RK, info="Z-RK-v1", L=64)
                   → (RK', CK)                    // 32 || 32
KDF_CK(CK)      = ( HMAC(CK, 0x01), HMAC(CK, 0x02) )  → (messageKey, CK')
```

- Initiator seeds the sending chain immediately using the responder's identity
  X25519 key as the first remote ratchet key.
- Responder initializes with `RK = SK` and performs its first DH ratchet step
  on the first inbound message.
- Skipped message keys are cached (keyed by `remoteRatchetPub || counter`) to
  allow out‑of‑order delivery, bounded to `maxSkipPerChain = 512` per chain and
  `maxSkippedStored = 1536` total (oldest evicted).
- Decryption is transactional: a failed attempt leaves ratchet state untouched.

### 4.1 Message header & encryption

```
header = { dh: b64(ratchetPub), pn: prevChainLen, n: msgIndex }
nonce  = 24 random bytes
plaintext' = pad(plaintext, block=256)          // 0x80 then 0x00* to a multiple
box    = XChaCha20Poly1305_seal(messageKey, nonce, plaintext',
                                aad = AD || utf8(canonical(header)))
```

`canonical(header)` is the exact string `{"dh":"<b64>","n":<n>,"pn":<pn>}`
(this byte sequence is what is fed as AAD, so it must be reproduced exactly).

### 4.2 Transport payload (ratchet message)

```
base64( utf8( JSON({
  v:1, t:"r", sid, ek?:b64,          // ek present until first reply received
  h: header, n:b64(nonce), ct:b64(cipherText), mac:b64(tag)
})))
```

## 5. Inner messages (plaintext model)

The decrypted bytes are JSON:

```
{ k:kind, mid:string, ts:int, ttl?:int, ...payload }
```

| kind | payload | meaning |
|------|---------|---------|
| `hello` | — | silent session opener |
| `text` | `body:string` | a chat message |
| `file` | `fid, name, size, mime, sha256, fk, fn, chunks` | attachment offer (see §6) |
| `timer`| `sec:int` | set disappearing timer (0 = off) |
| `read` | `mids:[string]` | read receipts |

`ttl` (seconds) marks a message as disappearing; the recipient deletes it
`ttl` seconds after receipt, the sender `ttl` seconds after send.

## 6. Attachments

A file is encrypted **once** under a random per‑file key and streamed as
chunks *outside* the ratchet (the key travels *inside* the ratchet in the
`file` offer, so it is E2E‑protected):

```
fk = 32 random bytes         // file key (sent inside ratchet)
fn = 16 random bytes         // nonce base
fid = random 12‑byte id      // opaque routing id for chunks
chunkNonce(i) = fn || little_endian_uint64(i)      // 24 bytes
chunk_i payload = base64(utf8(JSON({
  v:1, t:"f", fid, idx:i,
  ct:b64, mac:b64                 // XChaCha20Poly1305(fk, chunkNonce(i),
})))                               //   plaintextChunk, aad="z-file-v1:"||fid)
```

Chunk raw size ≤ 480 KiB (keeps the base64‑in‑JSON envelope under the relay's
1 MB frame cap). The receiver verifies each chunk's tag, reassembles in `idx`
order, and checks the whole‑file SHA‑256 against the offer's `sha256` before
surfacing the file.

## 7. Relay protocol (WebSocket, JSON frames)

The relay is untrusted and stores nothing on disk. Frames:

**Server → client**
```
{ t:"challenge", nonce:b64 }                 // sent on connect
{ t:"ready", id:routingId }                  // auth accepted
{ t:"msg", id, from:routingId, payload, ts } // inbound envelope
{ t:"sent", id, queued:bool }                // ack of your send (queued=RAM)
{ t:"delivered", id, to:routingId, ts }      // recipient device confirmed
{ t:"error", code, id? }
{ t:"pong", ts }
```

**Client → server**
```
{ t:"auth", pub:b64(edPub), sig:b64 }        // sig = Ed25519(edPriv,
                                             //   "z-relay-auth-v1:" || nonce)
{ t:"send", to:routingId, id, payload }      // "from" is NOT trusted/sent
{ t:"recv", id, from:routingId }             // I persisted this; drop it
{ t:"ping" }
```

### 7.1 Delivery semantics

1. `send` → the relay stores the envelope in a per‑recipient **RAM** queue and
   attempts live delivery. It replies `sent{queued}`.
2. The envelope stays in RAM until the recipient sends `recv` (confirming it is
   safely in the recipient's encrypted local store). Only then is it dropped
   and a `delivered` receipt routed to the sender. This survives a socket drop
   mid‑delivery (at‑least‑once; clients dedupe by `(from, mid)`).
3. Undelivered envelopes are wiped after `QUEUE_TTL_HOURS` (default 72) or on
   any relay restart. Per‑recipient caps bound memory (oldest dropped first).

### 7.2 What the relay can and cannot see

Sees: routing IDs, payload sizes, timing, connection liveness. Never sees:
keys, plaintext, names, or file contents. The authenticated sender id is
stamped by the relay from the signed session, so senders cannot be spoofed.

## 8. Local vault

SQLite with per‑cell XChaCha20‑Poly1305 encryption under a 256‑bit master key
kept in the OS keystore. Attachment blobs are stored as separate files, each
sealed under its own random key stored in an encrypted cell. Disappearing
messages are swept every 20 s. There is no plaintext at rest.

## 9. Identity backup (`.zid`)

```
inner = JSON({ v:1, identity:{edSeed,xSeed}, name, contacts:[...] })
key   = Argon2id(passphrase, salt=16B, m=19456KiB, t=2, p=1, L=32)
file  = JSON({ z:"backup", v:1, kdf:"argon2id", m,t,p,
               salt:b64, nonce:b64, ct:b64, mac:b64 })   // AEAD(inner)
```

Backups contain identity + contacts only — **never messages**, which by design
exist solely on the devices that exchanged them.

## 10. Versioning

Every envelope and code carries a `v` field. Unknown inner‑message kinds are
ignored (forward compatible). Breaking changes bump the top‑level `v` and the
`zc1.`/`Z-*-v1` context strings.
