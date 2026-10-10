'use strict';
/**
 * The key-transparency log itself: what a leaf is, what a tree head is, how a
 * publish is authenticated, and the proofs a reader is served. The two trees
 * come from merkle.js (the append-only log tree) and smt.js (the map from
 * label to latest entry); this file gives their bytes a meaning.
 *
 * What is logged. One entry per published device list:
 *
 *   label      = SHA-256("z-kt-label-v1:" || account_ed_pub)          32 bytes
 *   version    = the device-list version (7.7a's `v`)                   u64
 *   fp         = the device-list fingerprint (7.7a's `fp`)              16 bytes
 *   value      = nonce || ChaCha20-Poly1305(vk, nonce, aad = label, signed list JSON)
 *   valueHash  = SHA-256(value)                                         32 bytes
 *   ts         = when the log accepted it, ms since the epoch           u64
 *
 *   leafInput  = "z-kt-leaf-v1:" || label || u64be(version) || fp || valueHash || u64be(ts)
 *   leafHash   = SHA-256(0x00 || leafInput)                 (RFC 9162 leaf hash)
 *
 * The map holds, per label, (index of the latest entry, its version) —
 * smt.js's leaf — so one head commits both to the whole history and to which
 * entry is current for every label.
 *
 * The value key `vk = HKDF-SHA256(ikm = account_ed_pub, salt = "z-kt-value-v1",
 * info = "value", 32)` is derivable by anyone who knows the account's public
 * key — its contacts, and the operator, who learns it at publish — and by
 * nobody else: a mirror, a witness, or a passer-by reading the log sees
 * labels and ciphertext. Labels are hashes of 256-bit random keys, so there
 * is no dictionary to walk; that is why no VRF is needed here where a phone-
 * number directory would need one.
 *
 * Publishing. `POST /kt/v1/publish {acct, v, fp, value, sig}` with
 *   sig = Ed25519(account_sk, "z-kt-publish-v1:" || label || u64be(v) || fp || valueHash)
 * The log verifies the signature against `acct`, requires `v` to exceed the
 * label's current version (the first entry may carry any v ≥ 1: an account
 * that reached version 7 before the log existed publishes 7), and keeps
 * `acct` in its store but never serves it. It does not decrypt the value: a
 * value that disagrees with its own (v, fp) is detectable by every reader
 * who can decrypt it and harms only the account that signed it.
 *
 * Tree heads. Every response carries the head its proofs are relative to:
 *   sthInput = "z-kt-sth-v1:" || u64be(size) || logRoot || mapRoot || u64be(ts)
 *   sig      = Ed25519(log_sk, sthInput)
 * A head is re-signed when the log grows and, otherwise, when the last one
 * is older than `resignMs` — a client can therefore require a recent
 * timestamp and tell a frozen log from a quiet one.
 *
 * Storage: an append-only line-per-entry file, fsynced per publish, replayed
 * on start; a corrupted or shortened file fails the start rather than
 * serving a tree the previous head did not commit to.
 *
 * Memory: what the log holds is a function of the NUMBER of entries, not of
 * their size or the file's. Replay reads a fixed window at a time and an
 * entry keeps the byte range of its own line rather than its value, which is
 * read back when something serves it. Until 2026-09-13 neither was true —
 * the file arrived as one JavaScript string and every value stayed resident
 * for the life of the process — which put a 512 MB instance's ceiling at
 * tens of megabytes of file and made a file past V8's ~512 MB string limit
 * unreadable by the only code that reads it. `test/log_memory.test.js`.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { sha256, hashLeaf, MerkleLog, verifyInclusion } = require('./merkle.js');
const { SparseMerkleMap, u64be, prefixHex, parsePrefix, verifyBucket } = require('./smt.js');
const handles = require('./handles.js');

const LABEL_CONTEXT = Buffer.from('z-kt-label-v1:', 'utf8');
const LEAF_CONTEXT = Buffer.from('z-kt-leaf-v1:', 'utf8');
const STH_CONTEXT = Buffer.from('z-kt-sth-v1:', 'utf8');
const PUBLISH_CONTEXT = Buffer.from('z-kt-publish-v1:', 'utf8');
const WITNESS_CONTEXT = Buffer.from('z-kt-witness-v1:', 'utf8');
/** Local to the log's own head file: never on the wire, never a protocol input. */
const BOUNDARY_CONTEXT = Buffer.from('z-kt-signed-from-v1:', 'utf8');
const VALUE_SALT = Buffer.from('z-kt-value-v1', 'utf8');
const VALUE_INFO = Buffer.from('value', 'utf8');

/** The largest value accepted: a signed list with hybrid certificates for several devices is tens of KB. */
const MAX_VALUE_BYTES = 256 * 1024;
const MIN_VALUE_BYTES = 12 + 16; // nonce + tag, an empty plaintext

/**
 * Buckets (PROTOCOL §19.9). A bucket is asked for by its first `bits` bits,
 * at most MAX_BUCKET_BITS of them; one holding more than MAX_BUCKET_LEAVES
 * labels is refused `bucket_too_large` and the reader asks a narrower one;
 * one `POST /kt/v1/buckets` names at most MAX_BUCKETS.
 */
const MAX_BUCKET_BITS = 24;
const MAX_BUCKET_LEAVES = 4096;
const MAX_BUCKETS = 64;

/**
 * The bucket size a log recommends in `/kt/v1/sth`: max(0, ⌊log₂(labels / 32)⌋),
 * which puts 32 to 64 labels in a bucket on average — and never past what a
 * reader may ask for.
 */
function bucketBits(labels) {
  if (!(labels >= 64)) return 0;
  if (labels >= 2 ** (MAX_BUCKET_BITS + 5)) return MAX_BUCKET_BITS;
  return 31 - Math.clz32(labels) - 5;
}

// --- Ed25519 raw ↔ KeyObject -------------------------------------------------

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function privateKeyFromSeed(seed) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new Error('an Ed25519 seed is 32 bytes');
  return crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, seed]), format: 'der', type: 'pkcs8' });
}

function publicKeyFromRaw(pub) {
  if (!Buffer.isBuffer(pub) || pub.length !== 32) throw new Error('an Ed25519 public key is 32 bytes');
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: 'der', type: 'spki' });
}

function rawPublicKey(keyObject) {
  return crypto.createPublicKey(keyObject).export({ format: 'der', type: 'spki' }).subarray(-32);
}

function sign(privateKey, data) {
  return crypto.sign(null, data, privateKey);
}

function verify(rawPub, data, sig) {
  try {
    return crypto.verify(null, data, publicKeyFromRaw(rawPub), sig);
  } catch {
    return false;
  }
}

// --- The bytes -----------------------------------------------------------------

function labelFor(acctPub) {
  return sha256(LABEL_CONTEXT, acctPub);
}

function leafInput({ label, version, fp, valueHash, ts }) {
  return Buffer.concat([LEAF_CONTEXT, label, u64be(version), fp, valueHash, u64be(ts)]);
}

function leafHashOf(entry) {
  return hashLeaf(leafInput(entry));
}

/** What the log signs to record its own signature boundary in its head file. */
function boundaryInput(signedFrom) {
  return Buffer.concat([BOUNDARY_CONTEXT, u64be(signedFrom)]);
}

function sthInput({ size, logRoot, mapRoot, ts }) {
  return Buffer.concat([STH_CONTEXT, u64be(size), logRoot, mapRoot, u64be(ts)]);
}

function publishInput({ label, version, fp, valueHash }) {
  return Buffer.concat([PUBLISH_CONTEXT, label, u64be(version), fp, valueHash]);
}

function witnessInput(sth) {
  return Buffer.concat([WITNESS_CONTEXT, sthInput(sth)]);
}

/** Verify a tree head's signature against the log's pinned public key. */
function verifySth(sth, logPub) {
  if (!sth || !Buffer.isBuffer(sth.logRoot) || !Buffer.isBuffer(sth.mapRoot) || !Buffer.isBuffer(sth.sig)) return false;
  if (sth.logRoot.length !== 32 || sth.mapRoot.length !== 32) return false;
  if (!Number.isInteger(sth.size) || sth.size < 0 || !Number.isInteger(sth.ts) || sth.ts < 0) return false;
  return verify(logPub, sthInput(sth), sth.sig);
}

/**
 * The bytes each kind of log signs and hashes. The key-transparency log's
 * are this file's own functions, untouched; the handle log's are
 * `handles.js`'s, every one under a context of its own.
 */
const MODES = {
  kt: { sthInput, witnessInput, boundaryInput, leafHashOf },
  handles: {
    sthInput: handles.sthInput,
    witnessInput: handles.witnessInput,
    boundaryInput: handles.boundaryInput,
    leafHashOf: (e) => hashLeaf(handles.leafInput(e)),
  },
};

function modeOf(mode) {
  const m = MODES[mode];
  if (!m) throw new Error(`a log is "kt" or "handles", not ${JSON.stringify(mode)}`);
  return m;
}

/** `verifySth` for a log of either kind: a handle head never verifies as a KT head, nor the reverse. */
function verifySthFor(mode, sth, logPub) {
  if (mode === 'kt') return verifySth(sth, logPub);
  if (!sth || !Buffer.isBuffer(sth.logRoot) || !Buffer.isBuffer(sth.mapRoot) || !Buffer.isBuffer(sth.sig)) return false;
  if (sth.logRoot.length !== 32 || sth.mapRoot.length !== 32) return false;
  if (!Number.isInteger(sth.size) || sth.size < 0 || !Number.isInteger(sth.ts) || sth.ts < 0) return false;
  return verify(logPub, modeOf(mode).sthInput(sth), sth.sig);
}

// --- The value: what the account seals, what its contacts open ----------------

function valueKey(acctPub) {
  return Buffer.from(crypto.hkdfSync('sha256', acctPub, VALUE_SALT, VALUE_INFO, 32));
}

/** Seal a signed device list for the log. `plaintext` is the list's JSON bytes. */
function sealValue(acctPub, plaintext, nonce = crypto.randomBytes(12)) {
  const label = labelFor(acctPub);
  const cipher = crypto.createCipheriv('chacha20-poly1305', valueKey(acctPub), nonce, { authTagLength: 16 });
  cipher.setAAD(label, { plaintextLength: plaintext.length });
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([nonce, ct, cipher.getAuthTag()]);
}

/** Open a value; null if it was not sealed for this account (or was tampered with). */
function openValue(acctPub, value) {
  if (!Buffer.isBuffer(value) || value.length < MIN_VALUE_BYTES) return null;
  const label = labelFor(acctPub);
  const nonce = value.subarray(0, 12);
  const ct = value.subarray(12, value.length - 16);
  const tag = value.subarray(value.length - 16);
  try {
    const decipher = crypto.createDecipheriv('chacha20-poly1305', valueKey(acctPub), nonce, { authTagLength: 16 });
    decipher.setAAD(label, { plaintextLength: ct.length });
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    return null;
  }
}

/** What a client sends: the publish request for (version, fp, value), signed by the account key. */
function makePublish(acctPrivateKey, { version, fp, value }) {
  const acct = rawPublicKey(acctPrivateKey);
  const label = labelFor(acct);
  const valueHash = sha256(value);
  const sig = sign(acctPrivateKey, publishInput({ label, version, fp, valueHash }));
  return { acct, version, fp, value, sig };
}

// --- Memory the log keeps ----------------------------------------------------

/**
 * Copies of [bufs] in ONE allocation of exactly their total size — never a
 * slice of Node's shared buffer pool. A null passes through as null.
 *
 * `Buffer.from(string, 'base64')`, `Buffer.concat` and `Buffer.allocUnsafe`
 * hand out slices of a shared 8 KiB slab for anything under 4 KiB, and a slab
 * is freed only when every slice of it is. An entry keeps five small fields
 * (176 bytes) for the life of the process, decoded from base64 on replay and
 * on publish alike; and between one entry's fields and the next, the map
 * insert churns through ~16 KB of transient `Buffer.concat`s. So every entry
 * pinned about one slab of its own: measured on a replay of 22,094 entries
 * (the live log's size on 2026-10-03), 9.5 KB of the 11.6 KB each one
 * retained was slab, 376 MiB resident in all — and in a 512 MiB cgroup the
 * replay was killed at about 39,000 entries, on every start, because it runs
 * before the server listens. Owned, an entry retains 2.4 KB, the same log is
 * 187 MiB, and the same cgroup holds about 131,000 (`bench/memory.js`;
 * `test/log_memory.test.js` 5–7).
 *
 * One allocation rather than one per field: every ArrayBuffer carries its
 * own bookkeeping, which for 16- and 32-byte fields is more than the bytes.
 */
function owned(...bufs) {
  let n = 0;
  for (const b of bufs) if (b) n += b.length;
  const out = Buffer.allocUnsafeSlow(n);
  let at = 0;
  return bufs.map((b) => {
    if (!b) return b;
    b.copy(out, at);
    const view = out.subarray(at, at + b.length);
    at += b.length;
    return view;
  });
}

// --- Errors ------------------------------------------------------------------

class PublishError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** A handle-rule refusal (`handles.RuleError`) as the publish route answers it, keeping its reason. */
function handlePublishError(e) {
  const p = new PublishError(e.status, e.code, e.message);
  p.reason = e.reason;
  return p;
}

// --- Stores --------------------------------------------------------------------

/** Entries in memory only — tests, and the `kt/server.js --ephemeral` flag. */
class MemoryStore {
  *readAll() {}
  /** Nothing on any disk. */
  bytesOnDisk() {
    return 0;
  }
  dir() {
    return null;
  }
  /** Nothing to come back to, so nothing to check on the way in. */
  readHead() {
    return null;
  }
  writeHead() {}
  /** No file, so nothing can be re-read: a memory entry keeps its value. */
  append() {
    return null;
  }
  readValue() {
    throw new Error('a memory store has nothing to re-read');
  }
  close() {}
}

/** How much of the file is read at a time while replaying. */
const REPLAY_CHUNK = 1 << 20;

/** One JSON line per entry, appended and fsynced. */
class FileStore {
  /**
   * [chunkBytes] is how much of the file is read at a time while replaying.
   * It is a parameter only so that a test can make it small enough to put a
   * line either side of a window boundary, and one line across it, on a file
   * small enough to read: a value is capped at 256 KiB, so at the real
   * window no line can ever be longer than a chunk, and the case a carried
   * remainder exists for would otherwise never be exercised.
   */
  constructor(file, { chunkBytes = REPLAY_CHUNK } = {}) {
    this.file = file;
    this.headFile = `${file}.head.json`;
    this.chunkBytes = chunkBytes;
    this.fd = null;
    this.readFd = null;
  }

  /**
   * Every entry, in order, as a generator — and each one carries `valueAt`,
   * the byte range of its own line, so the log can drop the value and fetch
   * it again when somebody actually asks for it.
   *
   * This read the whole file into one JavaScript string until 2026-09-13.
   * Two things were wrong with that and both are fatal rather than untidy.
   * The string is a second copy of the file on the heap before a single
   * entry exists, on top of the array of parsed entries it becomes; and a
   * file past V8's ~512 MB string ceiling cannot be read at all, ever, by a
   * process that has no other way in — which made the 1 GB disk the log is
   * deployed on more than twice the largest file its own reader could open.
   *
   * A fixed window with a carried remainder has neither property: peak is
   * one chunk plus the longest line, whatever the file's size.
   *
   * [fromStored] reads one line's JSON as an entry: the key-transparency
   * log's form by default, the handle log's when the log says so.
   */
  *readAll(fromStored = entryFromStored) {
    let fd;
    try {
      fd = fs.openSync(this.file, 'r');
    } catch (e) {
      if (e.code === 'ENOENT') return;
      throw e;
    }
    try {
      const buf = Buffer.allocUnsafe(this.chunkBytes);
      let rest = Buffer.alloc(0);
      let restAt = 0; // byte offset of `rest` within the file
      let at = 0; // bytes consumed from the file
      let line = 0;
      let eof = false;
      while (!eof) {
        const n = fs.readSync(fd, buf, 0, this.chunkBytes, at);
        at += n;
        eof = n === 0;
        rest = rest.length === 0 ? buf.subarray(0, n) : Buffer.concat([rest, buf.subarray(0, n)]);
        let from = 0;
        for (;;) {
          const nl = rest.indexOf(0x0a, from);
          if (nl < 0) break;
          const off = restAt + from;
          const len = nl - from;
          line += 1;
          if (len === 0) throw new Error(`${this.file}: blank line ${line}`);
          yield this._parse(rest.subarray(from, nl), line, off, len, fromStored);
          from = nl + 1;
        }
        // Whatever follows the last newline is the start of the next line.
        rest = Buffer.from(rest.subarray(from));
        restAt += from;
        if (eof && rest.length !== 0) {
          // A final line with no newline is a torn write: the fsync that
          // would have followed it never happened.
          throw new Error(`${this.file}: line ${line + 1} has no newline (a torn write?)`);
        }
      }
    } finally {
      fs.closeSync(fd);
    }
  }

  _parse(bytes, line, off, len, fromStored = entryFromStored) {
    let j;
    try {
      j = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new Error(`${this.file}: line ${line} is not JSON (a torn write?)`);
    }
    const e = fromStored(j);
    e.valueAt = { off, len };
    return e;
  }

  /** The value of the entry whose line occupies [off, off + len). */
  readValue({ off, len }) {
    if (this.readFd === null) this.readFd = fs.openSync(this.file, 'r');
    const buf = Buffer.allocUnsafe(len);
    let got = 0;
    while (got < len) {
      const n = fs.readSync(this.readFd, buf, got, len - got, off + got);
      if (n === 0) throw new Error(`${this.file}: entry at ${off} is shorter than ${len} bytes`);
      got += n;
    }
    return Buffer.from(JSON.parse(buf.toString('utf8')).val, 'base64');
  }

  /**
   * Appends the entry and returns the byte range of the line it wrote — or
   * writes nothing at all and throws.
   *
   * `fs.writeSync` may write a PREFIX and return how much, without throwing.
   * Measured: a single 1 MiB write returned 65536. Until 2026-09-14 the
   * return value was ignored, and the consequences were the whole of it:
   * `append` returned a byte range for bytes that were never written, the
   * caller carried on and mutated both trees, the client was answered 201
   * with a head signed over an entry that is not on disk — and the NEXT
   * start died on "a torn write?" for ever, because the following append
   * took its offset from the file's size and spliced itself onto the
   * unterminated line. One short write, and the log never opens again.
   *
   * So: write until it is all written, and on anything short or throwing,
   * truncate back to where the file began and throw. `publish` appends
   * before it touches the trees, so a throw here leaves the log exactly as
   * it was and the sender is told 500 rather than 201.
   *
   * The clean ENOSPC path was always safe. It is the silent partial write
   * that was fatal, which is why the fix is the return value and not a
   * bigger try/catch.
   */
  /** What the entries file occupies: the number a disk alarm watches. */
  bytesOnDisk() {
    try {
      return fs.statSync(this.file).size;
    } catch (e) {
      if (e.code === 'ENOENT') return 0;
      throw e;
    }
  }

  /** The directory the file lives in, which is what free space is measured on. */
  dir() {
    return path.dirname(this.file);
  }

  append(entry, toStored = entryToStored) {
    const fresh = this.fd === null && !fs.existsSync(this.file);
    if (this.fd === null) this.fd = fs.openSync(this.file, 'a');
    const off = fs.fstatSync(this.fd).size;
    const line = Buffer.from(JSON.stringify(toStored(entry)) + '\n', 'utf8');
    let put = 0;
    try {
      while (put < line.length) {
        const n = fs.writeSync(this.fd, line, put, line.length - put);
        // A zero-byte write that does not throw would spin here for ever;
        // it is a broken fd, and saying so beats hanging the process.
        if (!(n > 0)) throw new Error(`${this.file}: wrote ${put + n} of ${line.length} bytes`);
        put += n;
      }
      fs.fsyncSync(this.fd);
    } catch (e) {
      // Leave the file as it was found. A half-written line is not a smaller
      // log, it is a log that cannot be opened.
      try {
        fs.ftruncateSync(this.fd, off);
        fs.fsyncSync(this.fd);
      } catch {}
      throw e;
    }
    // The first append is also the file's creation, and fsyncing a file does
    // not make the directory entry that names it durable. Without this, a
    // machine that lost power after the very first publish came back with no
    // file at all — and `readAll` reads a missing file as an empty log
    // (ENOENT returns nothing), so it would have started signing a fresh
    // history with the production key. Once per file, not once per append.
    if (fresh) this._syncDir();
    return { off, len: line.length - 1 };
  }

  /**
   * The last head this log signed, or null if it has never written one.
   *
   * It sits beside the entries and is what stops a log that has LOST some of
   * them from signing a smaller history as though it were the whole of it.
   * Read raw: it is checked against the replayed tree by `KtLog`, which is
   * the only thing that can say whether it is consistent.
   */
  readHead() {
    let text;
    try {
      text = fs.readFileSync(this.headFile, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      throw e;
    }
    let j;
    try {
      j = JSON.parse(text);
    } catch {
      throw new Error(`${this.headFile}: not JSON — the log will not start against a head it cannot read`);
    }
    const head = {
      size: j.size,
      logRoot: Buffer.from(j.logRoot, 'base64'),
      mapRoot: Buffer.from(j.mapRoot, 'base64'),
      ts: j.ts,
      sig: Buffer.from(j.sig, 'base64'),
    };
    // The boundary, if this head has one. Absent from heads written before
    // 2026-09-17; `KtLog` records one on the next start.
    if (j.signedFrom !== undefined) {
      head.signedFrom = j.signedFrom;
      head.signedFromSig = Buffer.from(j.signedFromSig || '', 'base64');
    }
    // How often the log that wrote this head re-records it while running;
    // absent from heads written before 2026-10-04 (`KtLog._checkResumed`).
    if (j.everyMs !== undefined) head.everyMs = j.everyMs;
    return head;
  }

  /**
   * Records a head, durably, by writing a new file and renaming it over the
   * old one — so a reader sees the old head or the new one and never half of
   * either. Called before the publish that produced it is acknowledged.
   */
  writeHead(head) {
    const tmp = `${this.headFile}.tmp`;
    const text = JSON.stringify(
      {
        size: head.size,
        logRoot: head.logRoot.toString('base64'),
        mapRoot: head.mapRoot.toString('base64'),
        ts: head.ts,
        sig: head.sig.toString('base64'),
        ...(head.signedFrom !== undefined
          ? { signedFrom: head.signedFrom, signedFromSig: head.signedFromSig.toString('base64') }
          : {}),
        ...(head.everyMs !== undefined ? { everyMs: head.everyMs } : {}),
      },
      null,
      2
    );
    const fd = fs.openSync(tmp, 'w');
    try {
      const buf = Buffer.from(text + '\n', 'utf8');
      let put = 0;
      while (put < buf.length) {
        const n = fs.writeSync(fd, buf, put, buf.length - put);
        if (!(n > 0)) throw new Error(`${tmp}: wrote ${put + n} of ${buf.length} bytes`);
        put += n;
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.headFile);
    this._syncDir();
  }

  /** fsync the directory holding the file, so its name is durable too. */
  _syncDir() {
    let dfd;
    try {
      dfd = fs.openSync(path.dirname(this.file), 'r');
    } catch {
      return; // not every platform lets a directory be opened; the file is still synced
    }
    try {
      fs.fsyncSync(dfd);
    } catch {
      // EINVAL on filesystems that do not support it — nothing to do about it here.
    } finally {
      fs.closeSync(dfd);
    }
  }

  close() {
    for (const f of ['fd', 'readFd']) {
      if (this[f] !== null) {
        fs.closeSync(this[f]);
        this[f] = null;
      }
    }
  }
}

function entryToStored(e) {
  return {
    i: e.index,
    label: e.label.toString('base64'),
    v: e.version,
    fp: e.fp.toString('base64'),
    vh: e.valueHash.toString('base64'),
    val: e.value.toString('base64'),
    acct: e.acct.toString('base64'),
    ts: e.ts,
    // The account's own signature over this publish. Kept for the same
    // reason `acct` is kept — to validate a replay — and never served, for
    // the same reason too (§19.6). Without it a replay could check only
    // things the writer of the line also chose, and "the log accepted this
    // under the account key" was a fact that existed for one moment in RAM.
    sig: e.sig.toString('base64'),
  };
}

function entryFromStored(j) {
  return {
    index: j.i,
    label: Buffer.from(j.label, 'base64'),
    version: j.v,
    fp: Buffer.from(j.fp, 'base64'),
    valueHash: Buffer.from(j.vh, 'base64'),
    value: Buffer.from(j.val, 'base64'),
    acct: Buffer.from(j.acct, 'base64'),
    ts: j.ts,
    // Explicitly null when absent rather than decoded: `Buffer.from(undefined,
    // 'base64')` is an empty buffer, not an error, so a line written before
    // signatures were stored would otherwise arrive as a signature of length
    // zero and be reported as a forgery instead of as what it is.
    sig: typeof j.sig === 'string' ? Buffer.from(j.sig, 'base64') : null,
  };
}

/**
 * A handle log's line: the key-transparency line without `fp` and `acct`.
 * There is no account — the owner is in the record, and the record is the
 * value — and every field here is one the log serves (PROTOCOL §21.5: a
 * handle log stores nothing it does not serve).
 */
function handleEntryToStored(e) {
  return {
    i: e.index,
    label: e.label.toString('base64'),
    v: e.version,
    vh: e.valueHash.toString('base64'),
    val: e.value.toString('base64'),
    ts: e.ts,
    sig: e.sig.toString('base64'),
  };
}

function handleEntryFromStored(j) {
  // The two logs' files must not be mistaken for each other: a line that
  // names an account is a key-transparency log's, and KT_MODE or KT_DATA
  // is pointing at the wrong service.
  if (j.acct !== undefined || j.fp !== undefined) {
    throw new Error(`entry ${j.i}: this line names an account and a fingerprint — it is a key-transparency log's, not a handle log's (KT_MODE and KT_DATA disagree)`);
  }
  for (const f of ['label', 'vh', 'val']) {
    if (typeof j[f] !== 'string') throw new Error(`entry ${j.i}: ${f} is missing`);
  }
  return {
    index: j.i,
    label: Buffer.from(j.label, 'base64'),
    version: j.v,
    valueHash: Buffer.from(j.vh, 'base64'),
    value: Buffer.from(j.val, 'base64'),
    ts: j.ts,
    // Null when absent, so a missing signature is reported as one (`_applyHandle`).
    sig: typeof j.sig === 'string' ? Buffer.from(j.sig, 'base64') : null,
  };
}

/**
 * Per-label state for the owner rule (`handles.js`): owner ‖ rc for every
 * label, 64 bytes a label in chunks of 1024 labels, and a slot number in a
 * map keyed by the label. What a label costs here is a map entry and 64
 * bytes, however many versions it has — an entry costs nothing. A Buffer per
 * label would have been ~300 bytes of bookkeeping for 64 of data, which is
 * the slab lesson of `owned` again (2026-10-03 analysis, P1-17).
 */
class OwnerTable {
  constructor() {
    /** label hex → slot */
    this.slots = new Map();
    this.chunks = [];
  }

  get size() {
    return this.slots.size;
  }

  /** {owner, rc} as views of the table, or null for a label it does not hold. */
  get(key) {
    const s = this.slots.get(key);
    if (s === undefined) return null;
    const c = this.chunks[s >> 10];
    const o = (s & 1023) * 64;
    return { owner: c.subarray(o, o + 32), rc: c.subarray(o + 32, o + 64) };
  }

  set(key, { owner, rc }) {
    let s = this.slots.get(key);
    if (s === undefined) {
      s = this.slots.size;
      if (s >> 10 >= this.chunks.length) this.chunks.push(Buffer.allocUnsafeSlow(1024 * 64));
      this.slots.set(key, s);
    }
    const c = this.chunks[s >> 10];
    const o = (s & 1023) * 64;
    owner.copy(c, o);
    rc.copy(c, o + 32);
  }

  /** What the table occupies besides its map: the chunks, whole. */
  get bytes() {
    return this.chunks.length * 1024 * 64;
  }
}

// --- The log -----------------------------------------------------------------

/** What a refusal says about an age in milliseconds: "45 minutes", "26.3 hours", "3.1 days". */
function describeAge(ms) {
  const min = ms / 60000;
  if (min < 120) return `${Math.round(min)} minutes`;
  const h = min / 60;
  if (h < 48) return `${h.toFixed(1)} hours`;
  return `${(h / 24).toFixed(1)} days`;
}

class KtLog {
  /**
   * @param {object} o
   * @param {MemoryStore|FileStore} o.store
   * @param {crypto.KeyObject|null} o.signingKey  the log's Ed25519 private key; null opens the
   *                                         file READ-ONLY — replayed and checked, never signed or written
   * @param {number} [o.resignMs]            how old an unchanged head may get before it is re-signed
   * @param {() => number} [o.now]           the clock (tests)
   * @param {number} [o.minSize]             KT_MIN_SIZE: refuse a replay shorter than this
   * @param {number} [o.maxHeadAgeMs]        refuse a start whose last recorded head is older than
   *                                         this, unless [o.confirmHead] names it (`_checkResumed`)
   * @param {{size: number, ts: number}|null} [o.confirmHead]  KT_CONFIRM_HEAD, parsed
   * @param {'kt'|'handles'} [o.mode]       which log this is (KT_MODE): the key-transparency log,
   *                                         or the handle log (`handles.js`, PROTOCOL §21.5)
   */
  constructor({
    store,
    signingKey,
    resignMs = 10 * 60 * 1000,
    now = Date.now,
    minSize = 0,
    maxHeadAgeMs = Infinity,
    confirmHead = null,
    deferReplay = false,
    mode = 'kt',
  }) {
    this.mode = mode;
    this._bytes = modeOf(mode);
    /**
     * The handle log's per-LABEL state for the owner rule; null in KT mode,
     * which has no owner but the account key the label is derived from.
     */
    this.owners = mode === 'handles' ? new OwnerTable() : null;
    this.store = store;
    /**
     * Null when the log was opened without its key: `tools/repair.js` asks
     * whether a file replays, and a tool that does not hold the log's key
     * must not be able to sign anything in its name. It used to open the
     * file with a throwaway key instead — and a file with no head beside it
     * got one, signed by `Buffer.alloc(32, 1)`, which the log then refused
     * to start against as a head somebody else wrote.
     */
    this.signingKey = signingKey === null ? null : signingKey;
    this.publicKey = signingKey === null ? null : rawPublicKey(signingKey);
    this.resignMs = resignMs;
    this.now = now;
    this.tree = new MerkleLog();
    this.map = new SparseMerkleMap();
    /** @type {object[]} entries by index */
    this.entries = [];
    /** label hex → indices, ascending */
    this.byLabel = new Map();
    this._sth = null;
    /** Index of the first entry that carried a signature, or null. */
    this._signedFrom = null;
    /** The `ts` of the last head written to the store, or null. */
    this._recordedTs = null;
    // When this start began — before the replay, which at a few hundred
    // thousand entries takes minutes and is not downtime.
    this._openedAt = now();
    this._open = { minSize, maxHeadAgeMs, confirmHead };
    if (deferReplay) return; // `KtLog.open` replays and finishes
    for (const e of store.readAll(this._fromStored())) this._apply(e, true);
    this._finishOpen();
  }

  /** How this log's lines read: `readAll`'s argument. */
  _fromStored() {
    return this.mode === 'handles' ? handleEntryFromStored : entryFromStored;
  }

  /**
   * The constructor's work, in slices: [onProgress] is told how many entries
   * have replayed every [every] of them, and the event loop runs in between
   * — which is what lets `server.js` answer `/health` while a large log
   * replays, instead of a port that is not bound until it is done. Same
   * entries, same checks, same refusals, in the same order.
   */
  static async open(opts, { onProgress = () => {}, every = 1000 } = {}) {
    const log = new KtLog({ ...opts, deferReplay: true });
    let n = 0;
    for (const e of log.store.readAll(log._fromStored())) {
      log._apply(e, true);
      n += 1;
      if (n % every === 0) {
        onProgress(n);
        await new Promise((resolve) => setImmediate(resolve));
      }
    }
    onProgress(n);
    log._finishOpen();
    return log;
  }

  /** True when opened without the log's key: nothing can be signed or written. */
  get readOnly() {
    return this.signingKey === null;
  }

  _finishOpen() {
    this._checkAgainstLastHead(this._open.minSize);
  }

  /**
   * Refuse to sign a history smaller than the one already signed.
   *
   * Replay used to believe whatever was on disk. Truncate the file at a line
   * boundary and the log starts cleanly and signs a valid head at the shorter
   * size — and the realistic way to do that is not an attacker. `KT_DATA`
   * pointing where the disk did not mount makes the log come up at size 0
   * with `/health` answering 200, and it begins signing a brand-new history
   * with the production key. Restoring yesterday's snapshot does the same
   * thing more quietly. Every client holding a head then enters permanent
   * log-fault, which is the state `adr/0006` reserves for a log caught
   * forking — correctly, since that is what this is.
   *
   * Two floors, because they fail differently.
   *
   * The head file catches a log that lost entries while keeping its data
   * directory: a truncation, a restored snapshot, a half-copied file. It is
   * exact — the replayed tree must reproduce the root that head committed to
   * at that size, so a file of the right length with the wrong contents is
   * caught too.
   *
   * `minSize` catches the case the head file cannot, which is the whole
   * directory going missing: an unmounted disk takes `head.json` with it, so
   * a floor that lives in the environment is the only one left standing. It
   * is a floor and not an expected size, so it stays true as the log grows
   * and an operator sets it once.
   */
  _checkAgainstLastHead(minSize) {
    const size = this.entries.length;
    if (size < minSize) {
      throw new Error(
        `the log replayed ${size} entries but KT_MIN_SIZE says at least ${minSize}: ` +
          'refusing to sign a smaller history than the one this deployment is known to have ' +
          '(a data directory that did not mount looks exactly like this)'
      );
    }
    const last = this.store.readHead();
    if (!last) {
      // No head: a new log, or a file from before the head existed
      // (2026-09-13), or a head somebody removed. KT_MIN_SIZE is the floor
      // for the last of those, as `head_floor.test.js` (5) has it; the
      // boundary below is adopted from the file — at its first signed entry
      // if it has one, else at its current size — and written down, so this
      // is the last start at which the file gets to say. What that leaves
      // is stated in C31: a file with NO signed entry and no head is one
      // start away from adopting whatever is in it. The first signed publish
      // closes that too, because the derived rule refuses an unsigned line
      // after a signed one whatever the head says.
      this._boundary = this._signedFrom === null ? size : this._signedFrom;
      // Opened without the key: there is nothing to check against, and the
      // head is the log's to write, with its own key, at its next start.
      if (this.readOnly) return;
      if (size > 0) {
        console.warn(`z-kt: ${size} entries and no head file — recording one; unsigned entries are accepted below ${this._boundary} only`);
      }
      // Written at size 0 too. A fresh deployment used to have no head until
      // its first publish, and until then a hand-written unsigned line was
      // adopted on the next start as though the log had made it. With a head
      // at size 0 the boundary is 0 from the first start, and nothing
      // unsigned is ever accepted.
      this._recordHead();
      return;
    }
    if (size < last.size) {
      throw new Error(
        `the log replayed ${size} entries but its last signed head covers ${last.size}: ` +
          'refusing to sign a smaller history than one it has already signed'
      );
    }
    if (!this.tree.rootAt(last.size).equals(last.logRoot)) {
      throw new Error(
        `the log's entries do not reproduce the root of its last signed head at size ${last.size}: ` +
          'the file is not a prefix of the history this key has already committed to'
      );
    }
    if (this.readOnly) {
      // A tool asking whether the file replays. The head's signatures are the
      // log's business, at its next start, and so is writing one.
      return;
    }
    // The head is this key's, or it is not a head. A root is something the
    // writer of the file can compute, so a head that matched the file's root
    // was not proof of anything until 2026-09-17: a head written by whoever
    // could write the file could lower the floor the head exists to hold.
    if (!verifySthFor(this.mode, last, this.publicKey)) {
      throw new Error(
        `the head beside this file is not signed by this log's key ` +
          '(a different KT_SEED, or a head somebody else wrote): refusing to start against it'
      );
    }
    // Before anything below writes a new head over the evidence of how long
    // ago this log last ran.
    const resumed = this._checkResumed(last, size);
    this._recordedTs = last.ts;
    // The boundary: the index from which every entry must carry a signature.
    // RECORDED in the head, under the log's key, rather than derived from
    // the file — because a boundary derived from the file being defended is
    // set by whoever can write that file. Until 2026-09-17 it was derived:
    // an unsigned line was accepted while no earlier line had a signature,
    // which held for any pre-3.4.1 file and for every fresh deployment until
    // its first real publish. Reproduced: a fresh log, one hand-written
    // unsigned line naming a victim's public account key, and `lookup`
    // served it as the victim's authenticated latest with proofs that
    // verified under a head signed by the real log key.
    if (last.signedFrom === undefined) {
      // A head from before the boundary existed. Adopt one now, at the first
      // signed entry if there is one, else at the current size — and write
      // it, so it is recorded before anything else can be appended.
      this._boundary = this._signedFrom === null ? size : this._signedFrom;
      this._recordHead();
    } else {
      if (!verify(rawPublicKey(this.signingKey), this._bytes.boundaryInput(last.signedFrom), last.signedFromSig)) {
        throw new Error(`${'head.json'}: the signature boundary is not signed by this log's key — refusing a boundary the log did not set`);
      }
      this._boundary = last.signedFrom;
      // Every unsigned entry sits below the boundary, or the file has a line
      // the log did not write.
      for (const e of this.entries) {
        if (!e.sig && e.index >= this._boundary) {
          throw new Error(
            `entry ${e.index}: no signature at or past the recorded boundary ${this._boundary} ` +
              '(this line was appended by something that is not the log)'
          );
        }
      }
    }
    // A confirmation is spent the moment it is used: the head on disk is now
    // this start's, and the old one it named is gone from it. (And a head an
    // older build wrote is replaced by one that promises to stay current.)
    if (resumed) this._recordHead();
  }

  /**
   * Refuse to sign on from a history that may not be the latest this key
   * signed — the one case the head beside the entries cannot catch.
   *
   * That head holds the log to what it has signed, but a whole-disk snapshot
   * brings the head back WITH the entries: the two agree with each other and
   * are both out of date. `KT_MIN_SIZE` sees it only if it was raised past
   * the snapshot's size, and on the reference deployment it is 1. So a
   * restored snapshot started, signed on from the snapshot's size, and every
   * client and witness that held a later head read the next one as a fork —
   * permanently, and rightly, because that is what it was.
   *
   * Nothing on the disk can tell a restored snapshot from a log that stopped
   * a minute ago: the snapshot IS the disk, and on a host like Render there is
   * no second place the log could write to that the restore leaves alone.
   * What tells them apart is the time. A running log re-records its head at
   * least every `resignMs` (`keepAlive`) and at a clean stop, so the head on
   * disk says when the log last ran, to within minutes; a snapshot is older
   * than the moment it is restored by at least the time it took somebody to
   * notice the disk was gone. A start whose head is older than
   * `maxHeadAgeMs` is refused until the operator has checked — a witness, a
   * mirror, the history of `/health`'s `size` — that nothing ever saw a
   * larger head, and says so by NAMING this one: KT_CONFIRM_HEAD=<size>@<ts>.
   * A name rather than a switch, so that a confirmation is good for one
   * start: left in the environment it matches no head the log writes later,
   * and cannot wave the next restore through unchecked.
   *
   * What this cannot see: a snapshot restored within `maxHeadAgeMs` of being
   * taken, and an operator who confirms without checking. A witness sees
   * both — it holds the larger head, and the first head signed on from the
   * snapshot does not extend it. `head_floor.test.js` (7, 8).
   *
   * Returns true when this start must record its head at once — a
   * confirmation was used, or the head came from a build that did not keep
   * it current — and false when nothing needs to be.
   */
  _checkResumed(last, size) {
    if (!(this._open.maxHeadAgeMs < Infinity)) return false;
    // A head written before 2026-10-04 was re-recorded only by a publish, so
    // its age is how long since the last publish — hours, on a quiet day —
    // and says nothing about when the log last ran. Judging it would refuse
    // the first start of this version on every quiet log. It is not judged;
    // this start records one at once, and the check holds from there on. A
    // snapshot taken before the upgrade is the one it cannot catch.
    if (!(last.everyMs > 0)) {
      console.warn('z-kt: the head on disk was written by an older build that did not keep it current; recording a current one, and the restored-snapshot check holds from this start on');
      return true;
    }
    const age = this._openedAt - last.ts;
    // Never tighter than twice the interval the head was promised at.
    if (age <= Math.max(this._open.maxHeadAgeMs, 2 * last.everyMs)) return false;
    const c = this._open.confirmHead;
    if (c && c.size === size && c.ts === last.ts) {
      console.warn(`z-kt: resuming at size ${size} from a head ${describeAge(age)} old, as KT_CONFIRM_HEAD says`);
      return true;
    }
    throw new Error(
      `the last head this log recorded is ${describeAge(age)} old (size ${last.size}, ts ${last.ts}), and a ` +
        'restored disk snapshot looks exactly like that: signing on from one signs a fork that every client ' +
        'and witness holding a later head reads as one, permanently. ' +
        (c ? `KT_CONFIRM_HEAD=${c.size}@${c.ts} names a different head. ` : '') +
        `If no witness, mirror or client has ever seen a head larger than ${size}, start once with ` +
        `KT_CONFIRM_HEAD=${size}@${last.ts}; if one has, do not — SELF_HOSTING.md, "If the log will not start"`
    );
  }

  /**
   * Re-sign the head and record it, when the one on disk is older than
   * `resignMs` — or now, with [force]. The server calls it on a timer and at
   * a clean stop, so that the head on disk always says when the log last ran
   * (`_checkResumed`). Returns whether it wrote.
   */
  keepAlive({ force = false } = {}) {
    if (this.readOnly) return false;
    if (!force && this._recordedTs !== null && this.now() - this._recordedTs < this.resignMs) return false;
    this._sth = null;
    this._recordHead();
    return true;
  }

  /**
   * The publish signature, re-checked on the way in — from the file as well
   * as from the wire.
   *
   * Until 2026-09-14 the signature was verified once, at HTTP time, and then
   * dropped: the stored line kept `acct` but not `sig`, and a replay checked
   * only `labelFor(acct) == label` and `sha256(value) == valueHash`. Both of
   * those are computed from fields the writer of the line also chose, so
   * anything that could write the file could forge an entry for any account
   * — take a victim's `acct` out of the file, seal a device list under
   * `HKDF(acctPub)`, append one line at a higher version, and the log starts
   * normally and serves the forgery as that account's latest, with a valid
   * map proof. Nothing downstream could tell, because `acct` and `sig` are
   * never served.
   *
   * It costs one Ed25519 verify per entry at replay and no extra I/O at all:
   * the signed bytes are `label ‖ version ‖ fp ‖ valueHash`, every one of
   * them already in the line, and none of them the value — so this does not
   * undo the work that stopped replay from holding values.
   *
   * The boundary for lines written before signatures were stored is DERIVED
   * rather than recorded, which is better than a number in a file that can
   * be edited by whoever is being defended against. The rule is that a log
   * never goes back: an entry without a signature is accepted only while no
   * earlier entry had one. So a log whose file predates this build replays
   * exactly as before, the first signed publish closes the door behind it,
   * and appending an unsigned line after that — the forgery — is refused by
   * the entry that precedes it rather than by anything about itself.
   */
  _checkSignature(entry) {
    if (!entry.sig) {
      if (this._boundary !== undefined && entry.index >= this._boundary) {
        throw new Error(`entry ${entry.index}: no signature at or past the recorded boundary ${this._boundary}`);
      }
      if (this._signedFrom !== null) {
        throw new Error(
          `entry ${entry.index}: no signature, though entry ${this._signedFrom} and every one after it has one ` +
            '(a log does not go back to unsigned entries; this line was appended by something that is not the log)'
        );
      }
      return;
    }
    const ok = verify(entry.acct, publishInput(entry), entry.sig);
    if (!ok) throw new Error(`entry ${entry.index}: the signature is not the account key's over this publish`);
    if (this._signedFrom === null) this._signedFrom = entry.index;
  }

  /**
   * Signs a head and records it, before the publish that produced it is
   * acknowledged. On the way back up this is what a later start is held to,
   * so it has to reach the disk before the sender is told `201` — a head
   * promised to a client and not written down is exactly the gap the check
   * above exists to close.
   */
  _recordHead() {
    const head = { ...this.sth() };
    if (this._boundary === undefined) this._boundary = this._signedFrom === null ? this.entries.length : this._signedFrom;
    head.signedFrom = this._boundary;
    head.signedFromSig = sign(this.signingKey, this._bytes.boundaryInput(this._boundary));
    // The promise `keepAlive` keeps: re-recorded at least this often while
    // the log runs, so the head's age is how long ago it last ran.
    head.everyMs = this.resignMs;
    this.store.writeHead(head);
    this._recordedTs = head.ts;
  }

  get size() {
    return this.entries.length;
  }

  /**
   * The entry with its value, read back from the store if it is not resident.
   *
   * Everything that SERVES an entry goes through this; everything that
   * verifies one uses the hash, which is resident. A memory-backed log keeps
   * its values and this is a no-op for it.
   */
  withValue(entry) {
    if (!entry || entry.value) return entry;
    return { ...entry, value: this.store.readValue(entry.valueAt) };
  }

  /** The latest entry for a label, or null. */
  latest(label) {
    const idx = this.byLabel.get(label.toString('hex'));
    return idx ? this.entries[idx[idx.length - 1]] : null;
  }

  _apply(entry, replaying) {
    if (this.mode === 'handles') return this._applyHandle(entry, replaying);
    if (entry.index !== this.entries.length) {
      throw new Error(`entry ${entry.index} where ${this.entries.length} was expected`);
    }
    if (!labelFor(entry.acct).equals(entry.label)) throw new Error(`entry ${entry.index}: label does not match account`);
    if (!sha256(entry.value).equals(entry.valueHash)) throw new Error(`entry ${entry.index}: value hash does not match value`);
    this._checkSignature(entry);
    const prev = this.latest(entry.label);
    if (prev && !(entry.version > prev.version)) {
      throw new Error(`entry ${entry.index}: version ${entry.version} does not exceed ${prev.version}`);
    }
    if (!replaying) entry.valueAt = this.store.append(entry);
    // The value has done its work: it has been hashed, checked against the
    // hash the signature covers, and written down. Holding it is what made
    // the resident set a multiple of the file rather than a function of the
    // number of entries — at the 256 KiB cap, one entry was 256 KiB of heap
    // for the life of the process, and the trees need none of it. What stays
    // is where to find it again.
    if (entry.valueAt) entry.value = null;
    else entry.value = owned(entry.value)[0];
    // And what stays is the log's own, whatever it arrived in — slices of
    // the shared pool from the file and from the wire alike (`owned`). Before
    // the map is told, because its leaf keeps the label.
    [entry.label, entry.fp, entry.valueHash, entry.acct, entry.sig] = owned(
      entry.label,
      entry.fp,
      entry.valueHash,
      entry.acct,
      entry.sig
    );
    this.tree.append(leafHashOf(entry));
    this.map.set(entry.label, entry.index, entry.version);
    this.entries.push(entry);
    const key = entry.label.toString('hex');
    const list = this.byLabel.get(key);
    if (list) list.push(entry.index);
    else this.byLabel.set(key, [entry.index]);
    this._sth = null;
  }

  /**
   * `_apply` for the handle log: the same order — check everything, write,
   * then tell the trees — with the owner rule where KT mode checks the
   * account signature, and on the way back from the file as on the way in
   * from the wire. A line appended to the file by anything but this log is
   * refused at the next start by whichever rule it breaks: an update or a
   * recover the record's history does not allow, a signature that is not the
   * owner's, a time finer than an hour, a record in any encoding but the one.
   */
  _applyHandle(entry, replaying) {
    const i = entry.index;
    if (i !== this.entries.length) throw new Error(`entry ${i} where ${this.entries.length} was expected`);
    if (!Buffer.isBuffer(entry.label)) throw new Error(`entry ${i}: no label`);
    if (!Buffer.isBuffer(entry.value) || !sha256(entry.value).equals(entry.valueHash)) throw new Error(`entry ${i}: value hash does not match value`);
    if (!Number.isInteger(entry.ts) || entry.ts < 0 || entry.ts % handles.HOUR !== 0) {
      throw new Error(`entry ${i}: ts ${entry.ts} is not a whole hour — a handle log keeps no finer time than that`);
    }
    if (!Buffer.isBuffer(entry.sig) || entry.sig.length !== 64) {
      throw new Error(`entry ${i}: no owner's signature — every entry in a handle log carries one`);
    }
    // Everything else — the version's bounds and that it is the label's
    // next, the record, the signatures, the history — is the owner rule's,
    // in its one order, exactly as on the wire.
    const key = entry.label.toString('hex');
    let state;
    try {
      state = this._ownerRule(this._ruleState(entry.label), entry);
    } catch (e) {
      if (e instanceof handles.RuleError) {
        const err = new Error(`entry ${i}: ${e.message} (${e.code})`);
        err.code = e.code;
        err.reason = e.reason;
        throw err;
      }
      throw e;
    }
    // Every handle entry is signed, from the first: the boundary the head
    // records for KT mode's legacy lines is 0 here, always.
    if (this._signedFrom === null) this._signedFrom = i;
    if (!replaying) entry.valueAt = this.store.append(entry, handleEntryToStored);
    if (entry.valueAt) entry.value = null;
    else entry.value = owned(entry.value)[0];
    [entry.label, entry.valueHash, entry.sig] = owned(entry.label, entry.valueHash, entry.sig);
    this.tree.append(this._bytes.leafHashOf(entry));
    this.map.set(entry.label, i, entry.version);
    this.entries.push(entry);
    const list = this.byLabel.get(key);
    if (list) list.push(i);
    else this.byLabel.set(key, [i]);
    this.owners.set(key, state);
    this._sth = null;
  }

  /**
   * The owner rule for one entry, given its label's state before it:
   * `handles.ownerRuleStep`, and nothing else. A method rather than a call
   * written into `_applyHandle` so that a test can stand in for a log whose
   * operator removed it — the log a mirror has to catch
   * (`handle_mode.test.js`).
   */
  _ownerRule(prev, entry) {
    return handles.ownerRuleStep(prev, entry);
  }

  /**
   * [label]'s state as the owner rule reads it — {owner, rc, version} — or
   * null for a label with no entry: the owner and commitment from the
   * per-label table, the version from the label's latest entry.
   */
  _ruleState(label) {
    const latest = this.latest(label);
    if (!latest) return null;
    const s = this.owners.get(label.toString('hex'));
    return { owner: s.owner, rc: s.rc, version: latest.version };
  }

  /**
   * Everything [publish] refuses, without accepting anything.
   *
   * Separated so a caller can find out whether a request is genuine before
   * spending anything on it — the per-account rate limit in `server.js` is
   * charged here, and charging it any earlier would let an unsigned request
   * naming somebody else's account spend that account's budget.
   */
  checkPublish(req) {
    if (this.mode === 'handles') return this._checkHandlePublish(req);
    const { acct, version, fp, value, sig } = req;
    if (!Buffer.isBuffer(acct) || acct.length !== 32) throw new PublishError(400, 'bad_request', 'acct must be a 32-byte Ed25519 public key');
    if (!Number.isInteger(version) || version < 1 || version > Number.MAX_SAFE_INTEGER) throw new PublishError(400, 'bad_request', 'v must be a positive integer');
    if (!Buffer.isBuffer(fp) || fp.length !== 16) throw new PublishError(400, 'bad_request', 'fp must be 16 bytes');
    if (!Buffer.isBuffer(value) || value.length < MIN_VALUE_BYTES) throw new PublishError(400, 'bad_request', 'value is too short to be a sealed list');
    if (value.length > MAX_VALUE_BYTES) throw new PublishError(413, 'too_large', `value exceeds ${MAX_VALUE_BYTES} bytes`);
    if (!Buffer.isBuffer(sig) || sig.length !== 64) throw new PublishError(400, 'bad_request', 'sig must be a 64-byte Ed25519 signature');
    const label = labelFor(acct);
    const valueHash = sha256(value);
    if (!verify(acct, publishInput({ label, version, fp, valueHash }), sig)) {
      throw new PublishError(403, 'bad_signature', 'the publish is not signed by the account key');
    }
    return { label, valueHash };
  }

  /**
   * `checkPublish` for the handle log: `{label, version, value, sig}`, and
   * everything that does not depend on the label's history
   * (`handles.checkEntry`) — the shape, the 1 KiB cap, the record's one
   * encoding and strong keys, `sig` under the owner the record names, and a
   * recover's `rsig` under the recovery key it names. What does depend on
   * history is `publish`'s.
   */
  _checkHandlePublish({ label, version, value, sig }) {
    let record;
    try {
      record = handles.checkEntry({ label, version, value, sig });
    } catch (e) {
      if (e instanceof handles.RuleError) throw handlePublishError(e);
      throw e;
    }
    return { label, valueHash: sha256(value), record };
  }

  /**
   * `publish` for the handle log: the history half of the owner rule
   * (`handles.ownerRuleTransition`), in its one order — taken, not claimed,
   * the owner, the commitment, and the version last — against the same
   * state replay reads (`_ruleState`).
   */
  _publishHandle(req) {
    const { label, valueHash, record } = this.checkPublish(req);
    const { version, value, sig } = req;
    try {
      handles.ownerRuleTransition(this._ruleState(label), record, version);
    } catch (e) {
      if (e instanceof handles.RuleError) throw handlePublishError(e);
      throw e;
    }
    // The leaf keeps the hour and no finer (PROTOCOL §21.5). It is not all
    // the log says about when: the head signed for this publish says when
    // the log grew, to anyone polling `/kt/v1/sth`, so that a recovery or a
    // rotation takes effect the moment it is accepted.
    const entry = { index: this.entries.length, label, version, valueHash, value, sig, ts: handles.hourOf(this.now()) };
    this._apply(entry, false);
    this._recordHead();
    return entry;
  }

  /**
   * Accept a publish request (buffers, not base64: the server decodes).
   * Returns the new entry. Throws PublishError with an HTTP status.
   */
  publish(req) {
    if (this.readOnly) throw new Error('this log was opened without its key: it accepts nothing');
    if (this.mode === 'handles') return this._publishHandle(req);
    const { label, valueHash } = this.checkPublish(req);
    const { acct, version, fp, value } = req;
    const prev = this.latest(label);
    if (prev && !(version > prev.version)) {
      throw new PublishError(409, 'stale_version', `the log holds version ${prev.version} for this label; ${version} does not exceed it`);
    }
    const entry = { index: this.entries.length, label, version, fp, valueHash, value, acct, sig: req.sig, ts: this.now() };
    this._apply(entry, false);
    this._recordHead();
    return entry;
  }

  /** The current signed tree head; re-signed after growth or when older than resignMs. */
  sth() {
    if (this.readOnly) throw new Error('this log was opened without its key: it signs nothing');
    const now = this.now();
    if (this._sth && this._sth.size === this.entries.length && now - this._sth.ts < this.resignMs) return this._sth;
    const head = { size: this.entries.length, logRoot: this.tree.root, mapRoot: this.map.root, ts: now };
    head.sig = sign(this.signingKey, this._bytes.sthInput(head));
    this._sth = head;
    return head;
  }

  /** PROOF(first, D[second]) — for a client extending its last head to the current one. */
  consistency(first, second) {
    if (!Number.isInteger(first) || !Number.isInteger(second) || first < 0 || second > this.size || first > second) {
      throw new PublishError(400, 'bad_request', 'first and second must satisfy 0 <= first <= second <= size');
    }
    return this.tree.consistencyProof(first, second);
  }

  _inclusion(index, size) {
    return { index, size, path: this.tree.inclusionProof(index, size) };
  }

  /**
   * Everything a client needs to learn a label's latest entry under one head:
   * the head, the map proof (of the (index, version) or of absence), and when
   * present the entry with its inclusion proof at the head's size.
   */
  /**
   * Whether the log holds any entry for [label]. Exact and free — it is the
   * index every lookup uses — which makes it the right thing for a gate on
   * NEW accounts to ask: an account enters this index only by a publish that
   * was accepted, so "first publish for this label" cannot be faked by a
   * publish that was refused.
   */
  hasLabel(label) {
    return this.byLabel.has(label.toString('hex'));
  }

  lookup(label) {
    const sth = this.sth();
    const map = this.map.proof(label);
    const entry = map.leaf ? this.withValue(this.entries[map.leaf.index]) : null;
    return {
      sth,
      map,
      entry,
      inclusion: entry ? this._inclusion(entry.index, sth.size) : null,
    };
  }

  /**
   * How many of `indices`, taken in order from the front, fit in `maxBytes` —
   * at least one, so a page is never empty while there is something to serve.
   *
   * The estimate costs nothing: `valueAt.len` is the length of the line the
   * entry was written as, which is the served form plus `acct` and minus the
   * proof, and both of those are small beside a sealed list. So the number of
   * entries is decided BEFORE any value is read back, and the ones that do not
   * fit are never fetched from disk at all. Reading them first and trimming
   * afterwards would have done the expensive half of the work anyway, which is
   * the half that hurts: `withValue` is a synchronous read per entry.
   *
   * A memory store keeps its values, so there is nothing to estimate from and
   * nothing to save; the value's own length is exact there.
   */
  _fit(indices, maxBytes) {
    if (!Number.isFinite(maxBytes)) return indices.length;
    let bytes = 0;
    for (let n = 0; n < indices.length; n++) {
      const e = this.entries[indices[n]];
      bytes += e.valueAt ? e.valueAt.len : servedBytes(e);
      if (bytes > maxBytes) return Math.max(1, n);
    }
    return indices.length;
  }

  /**
   * A page of a label's history, oldest first, each entry with its inclusion
   * proof under the returned head, and `total` — how many the label has.
   *
   * `total` is the point of the paging rather than a convenience. This route
   * is what an account's own device walks to find a version it did not issue
   * (`adr/0006`), so a page that simply stopped would be a log able to hide an
   * entry by being too big to serve — the same failure as an empty `entries`,
   * reached by a different road. A reader that can see `total` can tell a page
   * from the whole, and ask for the rest.
   */
  history(label, { start = 0, count = Infinity, maxBytes = Infinity } = {}) {
    const sth = this.sth();
    const all = this.byLabel.get(label.toString('hex')) || [];
    if (!Number.isInteger(start) || start < 0) {
      throw new PublishError(400, 'bad_request', 'start must be >= 0');
    }
    if (count !== Infinity && (!Number.isInteger(count) || count < 1)) {
      throw new PublishError(400, 'bad_request', 'count must be >= 1');
    }
    const wanted = all.slice(start, count === Infinity ? undefined : start + count);
    const idx = wanted.slice(0, this._fit(wanted, maxBytes));
    return {
      sth,
      start,
      total: all.length,
      entries: idx.map((i) => ({ entry: this.withValue(this.entries[i]), inclusion: this._inclusion(i, sth.size) })),
    };
  }

  /** An entry as this log serves it: `entryToJson`, or the handle log's form with `sig` and no `fp`. */
  entryJson(e) {
    return this.mode === 'handles' ? handleEntryToJson(e) : entryToJson(e);
  }

  /**
   * Buckets under ONE head (PROTOCOL §19.9): for each {prefix, bits}, every
   * label whose first `bits` bits are the prefix's, with the map siblings
   * that prove nothing was left out. In the handle log each leaf also
   * carries its entry's value, ts, sig and audit path, so a resolver reads
   * the record it was looking for without a second request that names it.
   *
   * Bounded before anything is read: the leaves of all the buckets together
   * at MAX_BUCKET_LEAVES — found by stopping one past it — and, in the handle
   * log, where a leaf is a record and an audit path rather than eighty bytes,
   * the estimated answer at [maxBytes]. Past either it is `bucket_too_large`,
   * and the reader asks for narrower buckets or fewer of them. A bucket is
   * never cut short: a partial bucket is one whose proof fails.
   */
  buckets(queries, { maxLeaves = MAX_BUCKET_LEAVES, maxBytes = Infinity } = {}) {
    const sth = this.sth();
    const out = [];
    let total = 0;
    for (const { prefix, bits } of queries) {
      const b = this.map.bucket(prefix, bits, maxLeaves - total);
      if (b === null) {
        throw new PublishError(
          400,
          'bucket_too_large',
          queries.length === 1
            ? `this bucket holds more than ${maxLeaves} labels: ask for more bits`
            : `these buckets hold more than ${maxLeaves} labels between them: ask for more bits, or fewer buckets at once`
        );
      }
      total += b.leaves.length;
      out.push({ bits, prefix, leaves: b.leaves, siblings: b.siblings });
    }
    if (this.mode === 'handles' && total > 0) {
      const all = [];
      for (const b of out) for (const l of b.leaves) all.push(l);
      // An audit path is ⌈log₂ size⌉ hashes of 47 bytes in JSON; a stored
      // line is the served form, near enough (`_fit`).
      const auditBytes = 47 * Math.ceil(Math.log2(Math.max(2, sth.size)));
      let bytes = 0;
      for (const l of all) {
        const e = this.entries[l.index];
        bytes += (e.valueAt ? e.valueAt.len : servedBytes(e)) + auditBytes;
      }
      if (bytes > maxBytes) {
        throw new PublishError(400, 'bucket_too_large', `the records in ${queries.length === 1 ? 'this bucket' : 'these buckets'} come to more than ${maxBytes} bytes: ask for more bits, or fewer buckets at once`);
      }
      const audits = this.tree.inclusionProofs(all.map((l) => l.index), sth.size);
      all.forEach((l, n) => {
        const e = this.withValue(this.entries[l.index]);
        l.value = e.value;
        l.ts = e.ts;
        l.sig = e.sig;
        l.audit = audits[n];
      });
    }
    return { sth, buckets: out };
  }

  /**
   * Entries by index, each with its inclusion proof under the returned head
   * — `POST /kt/v1/entries`, how a client reads the value of an entry a
   * bucket named without naming the label (with decoys beside it: phase 35).
   * In request order; as many as fit in [maxBytes] (at least one), decided
   * before any value is read, and `total` says how many were asked for.
   */
  entriesAt(indexes, { maxBytes = Infinity } = {}) {
    const sth = this.sth();
    for (const i of indexes) {
      if (!Number.isInteger(i) || i < 0 || i >= sth.size) {
        throw new PublishError(400, 'bad_request', `indexes must be integers 0 <= i < ${sth.size}, the head's size`);
      }
    }
    const idx = indexes.slice(0, this._fit(indexes, maxBytes));
    const proofs = this.tree.inclusionProofs(idx, sth.size);
    return {
      sth,
      total: indexes.length,
      entries: idx.map((i, n) => ({ entry: this.withValue(this.entries[i]), inclusion: { index: i, size: sth.size, path: proofs[n] } })),
    };
  }

  /** A page of entries for a mirror; [start, start + count) clipped to the head's size. */
  range(start, count, { maxBytes = Infinity } = {}) {
    const sth = this.sth();
    if (!Number.isInteger(start) || start < 0 || !Number.isInteger(count) || count < 1) {
      throw new PublishError(400, 'bad_request', 'start must be >= 0 and count >= 1');
    }
    const end = Math.min(sth.size, start + count);
    const wanted = [];
    for (let i = start; i < end; i++) wanted.push(i);
    const idx = wanted.slice(0, this._fit(wanted, maxBytes));
    return {
      sth,
      total: sth.size,
      entries: idx.map((i) => this.withValue(this.entries[i])),
    };
  }

  close() {
    this.store.close();
  }
}

// --- JSON encodings shared by the server, the mirror and the tests --------------

/**
 * Roughly what an entry costs in a response: the sealed value in base64 plus
 * the fixed fields around it. Only used where there is no stored line to
 * measure — a memory store — and only to decide how many to serve, so a close
 * estimate is enough and an estimate that errs large is the safe direction.
 */
function servedBytes(e) {
  return Math.ceil((e.value ? e.value.length : 0) / 3) * 4 + 256;
}

/** The public form of an entry: never `acct`. */
function entryToJson(e) {
  return {
    index: e.index,
    label: e.label.toString('base64'),
    v: e.version,
    fp: e.fp.toString('base64'),
    valueHash: e.valueHash.toString('base64'),
    value: e.value.toString('base64'),
    ts: e.ts,
  };
}

/**
 * An entry whose SHAPE is wrong: a field missing, the wrong type, the wrong
 * length. Distinct from an entry whose content is wrong, because a caller
 * that follows a log has to treat the two differently — a malformed element
 * is what a cache, a proxy or an error page produces, and says nothing about
 * what the log signed; a value that does not hash to its commitment is
 * content the log is answerable for. `kt/lib/mirror.js` poisoned itself
 * permanently on both until 2026-09-17 because this function threw one
 * kind of Error for either.
 */
class EntryShapeError extends Error {}

function entryFromJson(j) {
  if (!j || typeof j !== 'object') throw new EntryShapeError('entry: not an object');
  let e;
  try {
    e = {
      index: j.index,
      label: b64(j.label, 32),
      version: j.v,
      fp: b64(j.fp, 16),
      valueHash: b64(j.valueHash, 32),
      value: b64(j.value),
      ts: j.ts,
    };
  } catch (err) {
    throw new EntryShapeError(`entry: ${err.message}`);
  }
  if (!Number.isInteger(e.index) || !Number.isInteger(e.version) || !Number.isInteger(e.ts)) {
    throw new EntryShapeError('entry: bad integers');
  }
  // Shape is right; this is the content check, and it is the log's fault.
  if (!sha256(e.value).equals(e.valueHash)) throw new Error('entry: value hash does not match value');
  return e;
}

/**
 * The handle log's public form of an entry: the KT form without `fp`, with
 * `sig` — the owner's signature over the publish, which every mirror needs
 * to hold the log to the owner rule and which the log therefore serves
 * (PROTOCOL §21.5). The record itself is `value`, in the clear.
 */
function handleEntryToJson(e) {
  return {
    index: e.index,
    label: e.label.toString('base64'),
    v: e.version,
    valueHash: e.valueHash.toString('base64'),
    value: e.value.toString('base64'),
    ts: e.ts,
    sig: e.sig.toString('base64'),
  };
}

/** `entryFromJson` for the handle log's form; the same split between shape and content. */
function handleEntryFromJson(j) {
  if (!j || typeof j !== 'object') throw new EntryShapeError('entry: not an object');
  let e;
  try {
    e = {
      index: j.index,
      label: b64(j.label, 32),
      version: j.v,
      valueHash: b64(j.valueHash, 32),
      value: b64(j.value),
      ts: j.ts,
      sig: b64(j.sig, 64),
    };
  } catch (err) {
    throw new EntryShapeError(`entry: ${err.message}`);
  }
  if (!Number.isInteger(e.index) || !Number.isInteger(e.version) || !Number.isInteger(e.ts)) {
    throw new EntryShapeError('entry: bad integers');
  }
  if (!sha256(e.value).equals(e.valueHash)) throw new Error('entry: value hash does not match value');
  return e;
}

function sthToJson(s) {
  return {
    size: s.size,
    logRoot: s.logRoot.toString('base64'),
    mapRoot: s.mapRoot.toString('base64'),
    ts: s.ts,
    sig: s.sig.toString('base64'),
  };
}

function sthFromJson(j) {
  const s = { size: j.size, logRoot: b64(j.logRoot, 32), mapRoot: b64(j.mapRoot, 32), ts: j.ts, sig: b64(j.sig, 64) };
  if (!Number.isInteger(s.size) || !Number.isInteger(s.ts)) throw new Error('sth: bad integers');
  return s;
}

function mapProofToJson(p) {
  return {
    leaf: p.leaf ? { index: p.leaf.index, v: p.leaf.version } : null,
    bitmap: p.bitmap.toString('base64'),
    siblings: p.siblings.map((s) => s.toString('base64')),
  };
}

function mapProofFromJson(j) {
  if (!j || typeof j !== 'object') throw new Error('map proof: not an object');
  const leaf = j.leaf == null ? null : { index: j.leaf.index, version: j.leaf.v };
  if (leaf && (!Number.isInteger(leaf.index) || !Number.isInteger(leaf.version))) throw new Error('map proof: bad leaf');
  if (!Array.isArray(j.siblings)) throw new Error('map proof: siblings');
  return { leaf, bitmap: b64(j.bitmap, 32), siblings: j.siblings.map((s) => b64(s, 32)) };
}

function inclusionToJson(p) {
  return { index: p.index, size: p.size, path: p.path.map((h) => h.toString('base64')) };
}

function inclusionFromJson(j) {
  if (!j || !Number.isInteger(j.index) || !Number.isInteger(j.size) || !Array.isArray(j.path)) throw new Error('inclusion: shape');
  return { index: j.index, size: j.size, path: j.path.map((h) => b64(h, 32)) };
}

function b64(s, len) {
  if (typeof s !== 'string') throw new Error('expected base64');
  const b = Buffer.from(s, 'base64');
  if (len !== undefined && b.length !== len) throw new Error(`expected ${len} bytes, got ${b.length}`);
  return b;
}

// --- Buckets on the wire (PROTOCOL §19.9) ----------------------------------------

/** One bucket as served: `{bits, prefix, leaves, siblings}`; a handle leaf adds value, ts, sig, audit. */
function bucketToJson(b) {
  return {
    bits: b.bits,
    prefix: prefixHex(b.prefix, b.bits),
    leaves: b.leaves.map((l) => {
      const j = { label: l.label.toString('base64'), index: l.index, version: l.version };
      if (l.value !== undefined) {
        j.value = l.value.toString('base64');
        j.ts = l.ts;
        j.sig = l.sig.toString('base64');
        j.audit = l.audit.map((h) => h.toString('base64'));
      }
      return j;
    }),
    siblings: b.siblings.map((h) => h.toString('base64')),
  };
}

/**
 * What a reader does with a bucket answer — the Node twin of the Dart
 * verifier (`transparency_bucket.dart`), used by the tests and by
 * `tools/gen_vectors.js` to check what it writes. [asked] is the
 * `{prefix (hex), bits}` list in the order asked; [json] the response, either
 * form (`GET /kt/v1/bucket` or `POST /kt/v1/buckets`). Returns
 * `{sth, buckets: [{bits, prefix, leaves}]}` with every leaf proved, or
 * throws saying what failed:
 *   - the head verifies under [logPub] with [mode]'s context;
 *   - each bucket is the one asked for, holds at most MAX_BUCKET_LEAVES,
 *     and its leaves fold to the head's mapRoot (`verifyBucket`) — so none
 *     is missing, none is extra, and each (index, version) is the map's;
 *   - in the handle log, each leaf's record is the entry at `index`: its
 *     leaf (label, version, SHA-256(value), ts on a whole hour) is included
 *     at that index under the head's logRoot, by its audit path.
 */
function verifyBucketAnswer({ mode, logPub, asked, json }) {
  if (!json || typeof json !== 'object') throw new Error('bucket answer: not an object');
  const sth = sthFromJson(json.sth);
  if (!verifySthFor(mode, sth, logPub)) throw new Error('bucket answer: the head is not signed by the pinned key in this log\'s context');
  const served = Array.isArray(json.buckets) ? json.buckets : [json];
  if (served.length !== asked.length) throw new Error(`bucket answer: ${served.length} buckets for ${asked.length} asked`);
  const buckets = served.map((b, n) => {
    const want = asked[n];
    const prefix = parsePrefix(want.prefix, want.bits);
    if (!prefix) throw new Error(`bucket ${n}: asked for a malformed prefix`);
    if (b.bits !== want.bits || typeof b.prefix !== 'string' || b.prefix.toLowerCase() !== want.prefix.toLowerCase()) {
      throw new Error(`bucket ${n}: not the bucket asked for`);
    }
    if (!Array.isArray(b.leaves) || !Array.isArray(b.siblings)) throw new Error(`bucket ${n}: leaves and siblings are required`);
    if (b.leaves.length > MAX_BUCKET_LEAVES) throw new Error(`bucket ${n}: more than ${MAX_BUCKET_LEAVES} leaves`);
    const leaves = b.leaves.map((l) => {
      const leaf = { label: b64(l.label, 32), index: l.index, version: l.version };
      if (mode === 'handles') {
        leaf.value = b64(l.value);
        leaf.ts = l.ts;
        leaf.sig = b64(l.sig, 64);
        if (!Array.isArray(l.audit)) throw new Error(`bucket ${n}: a handle leaf carries its audit path`);
        leaf.audit = l.audit.map((h) => b64(h, 32));
      }
      return leaf;
    });
    const siblings = b.siblings.map((h) => b64(h, 32));
    if (!verifyBucket({ root: sth.mapRoot, prefix, bits: want.bits, leaves, siblings })) {
      throw new Error(`bucket ${n}: the leaves and siblings do not fold to the head's mapRoot — a label was left out, added, or changed`);
    }
    if (mode === 'handles') {
      for (const l of leaves) {
        if (!Number.isInteger(l.ts) || l.ts < 0 || l.ts % handles.HOUR !== 0) throw new Error(`bucket ${n}: a ts that is not a whole hour`);
        if (l.value.length > handles.MAX_RECORD_BYTES) throw new Error(`bucket ${n}: a record over ${handles.MAX_RECORD_BYTES} bytes`);
        const leafHash = hashLeaf(handles.leafInput({ label: l.label, version: l.version, valueHash: sha256(l.value), ts: l.ts }));
        if (!verifyInclusion({ leafHash, index: l.index, size: sth.size, root: sth.logRoot, path: l.audit })) {
          throw new Error(`bucket ${n}: the record at index ${l.index} is not the one the log tree holds there`);
        }
      }
    }
    return { bits: want.bits, prefix, leaves };
  });
  return { sth, buckets };
}

module.exports = {
  EntryShapeError,
  MAX_VALUE_BYTES,
  MAX_BUCKET_BITS,
  MAX_BUCKET_LEAVES,
  MAX_BUCKETS,
  bucketBits,
  bucketToJson,
  verifyBucketAnswer,
  verifySthFor,
  witnessInputFor: (mode, sth) => modeOf(mode).witnessInput(sth),
  leafHashFor: (mode, e) => modeOf(mode).leafHashOf(e),
  handleEntryToJson,
  handleEntryFromJson,
  OwnerTable,
  owned,
  KtLog,
  PublishError,
  MemoryStore,
  FileStore,
  labelFor,
  leafInput,
  leafHashOf,
  sthInput,
  publishInput,
  witnessInput,
  verifySth,
  valueKey,
  sealValue,
  openValue,
  makePublish,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  sign,
  verify,
  entryToJson,
  entryFromJson,
  sthToJson,
  sthFromJson,
  mapProofToJson,
  mapProofFromJson,
  inclusionToJson,
  inclusionFromJson,
};
