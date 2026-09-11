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
 */

const crypto = require('crypto');
const fs = require('fs');

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
  readAll() {
    return [];
  }
  append() {}
  close() {}
}

/** One JSON line per entry, appended and fsynced. */
class FileStore {
  constructor(file) {
    this.file = file;
    this.fd = null;
  }

  readAll() {
    let text;
    try {
      text = fs.readFileSync(this.file, 'utf8');
    } catch (e) {
      if (e.code === 'ENOENT') return [];
      throw e;
    }
    const entries = [];
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line === '') {
        // Only the final newline may be missing content; a blank line inside
        // the file is a torn write.
        if (i !== lines.length - 1) throw new Error(`${this.file}: blank line ${i + 1}`);
        continue;
      }
      let j;
      try {
        j = JSON.parse(line);
      } catch {
        throw new Error(`${this.file}: line ${i + 1} is not JSON (a torn write?)`);
      }
      entries.push(entryFromStored(j));
    }
    return entries;
  }

  append(entry) {
    if (this.fd === null) this.fd = fs.openSync(this.file, 'a');
    fs.writeSync(this.fd, JSON.stringify(entryToStored(entry)) + '\n');
    fs.fsyncSync(this.fd);
  }

  close() {
    if (this.fd !== null) {
      fs.closeSync(this.fd);
      this.fd = null;
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
  constructor({ store, signingKey, resignMs = 10 * 60 * 1000, now = Date.now }) {
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
    for (const e of store.readAll()) this._apply(e, true);
  }

  get size() {
    return this.entries.length;
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
    const prev = this.latest(entry.label);
    if (prev && !(entry.version > prev.version)) {
      throw new Error(`entry ${entry.index}: version ${entry.version} does not exceed ${prev.version}`);
    }
    if (!replaying) this.store.append(entry);
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
   * Accept a publish request (buffers, not base64: the server decodes).
   * Returns the new entry. Throws PublishError with an HTTP status.
   */
  publish({ acct, version, fp, value, sig }) {
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
    const prev = this.latest(label);
    if (prev && !(version > prev.version)) {
      throw new PublishError(409, 'stale_version', `the log holds version ${prev.version} for this label; ${version} does not exceed it`);
    }
    const entry = { index: this.entries.length, label, version, fp, valueHash, value, acct, ts: this.now() };
    this._apply(entry, false);
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
    const entry = map.leaf ? this.entries[map.leaf.index] : null;
    return {
      sth,
      map,
      entry,
      inclusion: entry ? this._inclusion(entry.index, sth.size) : null,
    };
  }

  /** Every entry for a label, oldest first, each with its inclusion proof under the returned head. */
  history(label) {
    const sth = this.sth();
    const idx = this.byLabel.get(label.toString('hex')) || [];
    return {
      sth,
      entries: idx.map((i) => ({ entry: this.entries[i], inclusion: this._inclusion(i, sth.size) })),
    };
  }

  /** A page of entries for a mirror; [start, start + count) clipped to the head's size. */
  range(start, count) {
    const sth = this.sth();
    if (!Number.isInteger(start) || start < 0 || !Number.isInteger(count) || count < 1) {
      throw new PublishError(400, 'bad_request', 'start must be >= 0 and count >= 1');
    }
    const end = Math.min(sth.size, start + count);
    return { sth, entries: this.entries.slice(start, Math.max(start, end)) };
  }

  close() {
    this.store.close();
  }
}

// --- JSON encodings shared by the server, the mirror and the tests --------------

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
