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

const { sha256, hashLeaf, MerkleLog } = require('./merkle.js');
const { SparseMerkleMap, u64be } = require('./smt.js');

const LABEL_CONTEXT = Buffer.from('z-kt-label-v1:', 'utf8');
const LEAF_CONTEXT = Buffer.from('z-kt-leaf-v1:', 'utf8');
const STH_CONTEXT = Buffer.from('z-kt-sth-v1:', 'utf8');
const PUBLISH_CONTEXT = Buffer.from('z-kt-publish-v1:', 'utf8');
const WITNESS_CONTEXT = Buffer.from('z-kt-witness-v1:', 'utf8');
const VALUE_SALT = Buffer.from('z-kt-value-v1', 'utf8');
const VALUE_INFO = Buffer.from('value', 'utf8');

/** The largest value accepted: a signed list with hybrid certificates for several devices is tens of KB. */
const MAX_VALUE_BYTES = 256 * 1024;
const MIN_VALUE_BYTES = 12 + 16; // nonce + tag, an empty plaintext

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

// --- Errors ------------------------------------------------------------------

class PublishError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// --- Stores --------------------------------------------------------------------

/** Entries in memory only — tests, and the `kt/server.js --ephemeral` flag. */
class MemoryStore {
  *readAll() {}
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
   */
  *readAll() {
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
          yield this._parse(rest.subarray(from, nl), line, off, len);
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

  _parse(bytes, line, off, len) {
    let j;
    try {
      j = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new Error(`${this.file}: line ${line} is not JSON (a torn write?)`);
    }
    const e = entryFromStored(j);
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
  append(entry) {
    const fresh = this.fd === null && !fs.existsSync(this.file);
    if (this.fd === null) this.fd = fs.openSync(this.file, 'a');
    const off = fs.fstatSync(this.fd).size;
    const line = Buffer.from(JSON.stringify(entryToStored(entry)) + '\n', 'utf8');
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
    return {
      size: j.size,
      logRoot: Buffer.from(j.logRoot, 'base64'),
      mapRoot: Buffer.from(j.mapRoot, 'base64'),
      ts: j.ts,
      sig: Buffer.from(j.sig, 'base64'),
    };
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

// --- The log -----------------------------------------------------------------

class KtLog {
  /**
   * @param {object} o
   * @param {MemoryStore|FileStore} o.store
   * @param {crypto.KeyObject} o.signingKey  the log's Ed25519 private key
   * @param {number} [o.resignMs]            how old an unchanged head may get before it is re-signed
   * @param {() => number} [o.now]           the clock (tests)
   */
  constructor({ store, signingKey, resignMs = 10 * 60 * 1000, now = Date.now, minSize = 0 }) {
    this.store = store;
    this.signingKey = signingKey;
    this.publicKey = rawPublicKey(signingKey);
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
    for (const e of store.readAll()) this._apply(e, true);
    this._checkAgainstLastHead(minSize);
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
    if (!last) return;
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
    this.store.writeHead(this.sth());
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
   * Everything [publish] refuses, without accepting anything.
   *
   * Separated so a caller can find out whether a request is genuine before
   * spending anything on it — the per-account rate limit in `server.js` is
   * charged here, and charging it any earlier would let an unsigned request
   * naming somebody else's account spend that account's budget.
   */
  checkPublish({ acct, version, fp, value, sig }) {
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
   * Accept a publish request (buffers, not base64: the server decodes).
   * Returns the new entry. Throws PublishError with an HTTP status.
   */
  publish(req) {
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
    const now = this.now();
    if (this._sth && this._sth.size === this.entries.length && now - this._sth.ts < this.resignMs) return this._sth;
    const head = { size: this.entries.length, logRoot: this.tree.root, mapRoot: this.map.root, ts: now };
    head.sig = sign(this.signingKey, sthInput(head));
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

function entryFromJson(j) {
  const e = {
    index: j.index,
    label: b64(j.label, 32),
    version: j.v,
    fp: b64(j.fp, 16),
    valueHash: b64(j.valueHash, 32),
    value: b64(j.value),
    ts: j.ts,
  };
  if (!Number.isInteger(e.index) || !Number.isInteger(e.version) || !Number.isInteger(e.ts)) throw new Error('entry: bad integers');
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

module.exports = {
  MAX_VALUE_BYTES,
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
