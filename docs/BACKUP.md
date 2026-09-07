# Z — Encrypted backup (`.zbk`)

Z holds no copy of anything. The relay is RAM‑only and forgets an envelope the
moment it is delivered; there is no account on a server and no directory. That
is the point of the design, and it has one unavoidable consequence: **if the
only device is lost, the history is gone.** Nothing can be restored from
somewhere else, because there is no somewhere else.

A backup archive is the answer, and it has to be an answer that does not quietly
undo the rest of the design. This document is the normative description of the
format, what it deliberately leaves out and why, and how to verify it against
the test vectors.

Companion documents: [`PROTOCOL.md`](PROTOCOL.md) (wire format),
[`THREAT_MODEL.md`](THREAT_MODEL.md), [`vectors/README.md`](vectors/README.md).

---

## 1. What an archive is

One file, `*.zbk`, that the user holds. It is encrypted under a **recovery
code** the user also holds, and it is written and read entirely on the device.
The relay never stores, proxies or sees a backup — that is an explicit
anti‑goal, not an omission. A cloud destination, when one is offered, is
user‑supplied storage that the client writes finished ciphertext into.

| | |
|---|---|
| Unlock | 120‑bit recovery code → Argon2id → one 256‑bit archive key |
| Frames | XChaCha20‑Poly1305, one per record or attachment chunk |
| Streaming | Neither export nor import ever holds the archive, or a whole attachment, in memory |
| Integrity | Every frame is bound to its index and to this archive's header; the file ends with a terminator |
| Reference | `protocol/lib/src/archive.dart` (format), `app/lib/core/archive.dart` (contents) |
| Vectors | [`vectors/backup/archive.json`](vectors/backup/archive.json) |

---

## 2. What travels — and what does not

**In the archive:** the identity, contacts (with their verification state),
group state, every message with its phase‑8 structure (replies, reactions,
edits, deletions, forward marks), and attachment bytes.

**Deliberately not in the archive:**

* **Session state** (`conversations`). Those rows are live Double Ratchet
  state. Restoring them can put the same ratchet on two devices, which reuses
  chain keys and message indices — the one failure the whole construction
  exists to prevent. It would also start a fight over the mailbox, since the
  relay allows one socket per routing id and closes the older with
  `4002 replaced by new connection`. An archive therefore restores **history**;
  sessions re‑handshake on first use, which costs one round trip.

  This is not a limitation to be engineered away later. A backup that faithfully
  restored ratchet state would be a worse backup.

* **The outbox and the inbound dedupe table.** In‑flight state, not history.
  A message that was queued when the backup was taken is not resurrected onto a
  device the peer has never spoken to.

* **Anything device‑bound**: the vault's master key and device secret, the
  biometric pass key, the device id. A restore builds a **fresh vault** with
  fresh device keys, so two devices restored from one archive never share a
  vault key either.

### 2.1 What the peer sees when you restore

Nothing, until you speak. The restored device opens a new session with its
first message. The peer's conversation notices that a brand‑new session
arrived while it still held one that had been carrying traffic in both
directions — that only happens when the other side has lost its state — and
starts answering on the new one (`PROTOCOL.md` §4).

The peer does **not** throw the old session away. It cannot tell a restore
from a second device holding the same identity key, so discarding the replaced
session would let either of them cut the other off; the old session stays
readable, and if it speaks again the peer simply follows it back.

The post‑quantum secret follows the session rather than the pair
(`PROTOCOL.md` §17.1), which is what makes that possible: the new session
starts classical and re‑runs the ML‑KEM handshake on its own, while the
replaced session keeps the secret of its own era. So a restore is a
re‑handshake, not a silent permanent downgrade to classical crypto — and not a
way to strip the post‑quantum layer off a session that is still in use.

`protocol/test/protocol_test.dart` exercises both halves in both rid
orderings, because both the session pinning and the PQ roles are decided by
the rid comparison — a test that ran only one ordering would pass with either
bug present.

---

## 3. The recovery code

```
ZBK-CHG71-FQYAA-QTWRQ-ANY3N-X2HD2
```

120 random bits in 24 characters of Crockford's base32 alphabet
(`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), plus one checksum character, printed in
five groups of five behind a `ZBK-` prefix.

**Why characters rather than a word list.** A twelve‑word phrase is friendlier
to copy by hand, but it means shipping and pinning a 2048‑word list per
language and getting its provenance right, and a word list solves transcription
by adding a dictionary. Crockford's alphabet solves the same problem inside the
encoding: it omits `I`, `L`, `O` and `U`, so nothing collides with `1`, `0`, or
with itself; it is case‑insensitive; and on input `I` and `L` map to `1` and `O`
maps to `0`, which is exactly how people mis‑copy those characters. The
mangled form `zbk chg7l fqyaa qtwrq any3n x2hd2` parses back to the same code.

**The checksum character** is `alphabet[sha256(entropy)[0] & 0x1f]`. It catches
about 31 of every 32 single‑character typos immediately — before the slow key
derivation runs and before a decryption failure that could not say which of the
two went wrong. The vector records the exact numbers: of 775 single‑character
variants of the recorded code, 751 are rejected by the checksum, and the
remaining 24 decode to a *different* code, which then fails the archive's
authentication tag. There is no oracle either way.

**Canonical form.** The bytes fed to the KDF are the 25 characters with the
prefix and separators removed, upper‑cased — so how the code was written down
cannot change the key.

120 bits is already far beyond brute force. Argon2id on top costs nothing here
and covers a user who supplies a code from somewhere else.

---

## 4. File format

```
<header JSON>\n
[u32be len][ciphertext ‖ mac]      frame 0
[u32be len][ciphertext ‖ mac]      frame 1
…
[u32be len][ciphertext ‖ mac]      terminator
```

### 4.1 Header

A single line of plaintext JSON, then `\n`:

```json
{"z":"zbk","v":1,"app":"z","kdf":"argon2id","m":19456,"t":2,"p":1,
 "salt":"…base64…","np":"…base64…","schema":3,"created":1700000000000}
```

It is plaintext because a reader must be able to derive the key before it can
read anything, and it says nothing an observer does not already know from the
file's existence. `schema` records the vault schema the records were written
at. `np` is the 16‑byte nonce prefix.

### 4.2 Key derivation

```
key = Argon2id(password = canonical recovery code (25 ASCII chars),
               salt     = header.salt (16 bytes),
               m = 19456 KiB, t = 2, p = 1, tagLen = 32)
```

The parameters match the vault's (OWASP guidance). They are in the header
rather than hard‑coded so a future build can raise them without orphaning old
archives.

### 4.3 Frames

Each frame is XChaCha20‑Poly1305 under `key`:

```
nonce = np (16 bytes) ‖ uint64be(index)
aad   = header bytes (without the newline) ‖ uint64be(index)
plaintext = [kind byte] ‖ body
```

`kind` is `0` = record (UTF‑8 JSON), `1` = attachment chunk, `2` = terminator.

Putting the index in the nonce makes every frame's nonce unique **by
construction** rather than by luck, which is what allows a stream that never
holds the file in memory. Putting the header and the index in the associated
data pins each frame to its position *in this archive*: a frame cannot be
reordered, duplicated, dropped, or lifted into another file without the tag
failing.

An attachment chunk's body is `uint8 idLen ‖ fid ‖ bytes`, written in 256 KiB
pieces, so a large file never has to be materialised whole on either side.

### 4.4 Terminator

The last frame is `{"t":"end","records":N}` where `N` is the number of record
frames. An importer that reaches the end of the file without seeing it — or
that counted a different `N` — **refuses the archive**. Truncation is the most
likely way a backup goes wrong (a full disk, a cancelled sync, a half‑written
file on a stick), and it is the one failure that would otherwise restore
successfully and quietly, minus the messages that were not written.

---

## 5. Records

Records are JSON objects with a `t` discriminator. Bodies are decrypted out of
the vault and re‑sealed by the archive: the vault key is device‑bound and never
leaves the device.

| `t` | Carries |
|---|---|
| `meta` | display name, server URL, schema |
| `identity` | the identity key material |
| `contact` | routing id, contact bundle, name, TTL, verified flag |
| `groups` | the group list blob |
| `message` | mid, rid, direction, kind, body, timestamp, status, expiry, and the phase‑8 fields (`rt` reply target, `edited`, `deleted`, `fw`) |
| `reaction` | rid, mid, sender, emoji, timestamp |
| `file` | attachment metadata; the bytes follow in `kind = 1` frames |

**Forward and backward compatibility.** A reader skips record types it does not
know and fields it does not know, and missing fields take their column
defaults. So an archive written at schema 1 restores onto a current build (the
phase‑8 columns simply default), and an archive written by a *newer* build
restores onto this one, minus the parts it cannot represent — rather than
locking a user out of their own history because their install is a version
behind. `app/test/backup_test.dart` tests both directions on a hand‑built
archive.

Unreadable cells are skipped rather than aborting the whole backup: a single
corrupt row should cost one message, not the archive.

---

## 6. Failure modes, and what each one does

| Situation | Result |
|---|---|
| Mistyped code | Rejected by the checksum, before the KDF |
| Wrong (but well‑formed) code | Argon2id runs, the first frame's tag fails, `FormatException`. No oracle: nothing distinguishes a wrong code from a damaged file |
| Truncated file | `ArchiveIncompleteException` — the terminator is missing |
| Flipped byte anywhere | The containing frame's tag fails |
| Frame reordered or duplicated | The tag fails: the index is in both the nonce and the AAD |
| Frame from another archive spliced in | The tag fails: the header is in the AAD |
| Restoring over a vault that already has data | Not supported; import expects a fresh vault, since interleaving two histories is not a restore |

---

## 7. Verifying the format

The vector [`vectors/backup/archive.json`](vectors/backup/archive.json) records
a complete four‑frame archive: the recovery code and its entropy, the Argon2id
inputs *and* output, the header bytes, every frame's nonce, plaintext,
ciphertext and tag, the whole file's bytes and SHA‑256, and the two cases that
must fail.

Three independent checks run in CI:

* `protocol/test/vectors_test.dart` regenerates the vector in memory and
  requires it to be byte‑identical, then re‑reads the recorded file through the
  public API alone — code → key → header → frames — and checks that a moved
  frame and a wrong code both fail.
* `server/test/vectors.test.js` does the same from the recorded bytes with
  Node's own crypto and **no shared code**: it re‑derives each nonce and AAD,
  opens every frame, walks the base32 decoding and the checksum by hand, and
  asserts the two failures. Node has no Argon2id, so it takes the key from the
  vector — the KDF step is recorded as a standard RFC 9106 known‑answer test
  (password, salt, m/t/p, tag length, output) that any Argon2id implementation
  can reproduce.
* `app/test/backup_test.dart` runs the real thing end to end: an archive taken
  on one device restores onto a wiped one, which then talks to a contact who
  knows nothing about the restore.

---

## 8. Status

Phases 9.1 and 9.2 (format, export, import) are implemented and tested. Still
to come in phase 9:

* **9.3** destination — user‑chosen local file first.
* **9.4** recovery UX — code generation and confirmation ceremony, restore
  flow, and the honest framing: lose the code and the archive is gone, because
  there is no server‑side path to be compelled.
* **9.5** optional scheduled re‑export, off by default.
* **`.zid` folded into this format.** The existing identity‑only backup stays
  for now; it becomes a subset of `.zbk` when the restore UI lands in 9.4, so
  there is one archive format and one unlock ceremony rather than two artifacts
  a user could pick between in a crisis.
