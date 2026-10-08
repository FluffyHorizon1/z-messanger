'use strict';
/**
 * The handle log: what `kt/` is when it runs with KT_MODE=handles (PROTOCOL
 * §21.5, ADR 0015 revision 2). The same two trees and the same routes as
 * the key-transparency log, a different meaning for a leaf, and one rule the
 * key-transparency log does not have: a label belongs to whoever claimed it.
 *
 * A label is Argon2id of a canonical handle (`nick.digits`), computed by the
 * client; this file never sees a handle and could not compute one. The value
 * is the handle's RECORD — canonical JSON, members in exactly this order, no
 * whitespace:
 *
 *   { "k": "claim" | "update" | "recover",
 *     "owner":  b64url(ownerPub),          the owner AFTER this entry
 *     "intro":  b64url(introPub) | null,   the introduction mailbox's Ed25519 key; null: paused or retired
 *     "xintro": b64url(xintroPub) | null,  its X25519 key, which a request is sealed to; null exactly when intro is
 *     "pow":    16..28,                    the proof of work the relay demands
 *     "rc":     b64url(32),                the recovery commitment AFTER this entry
 *     "rpub":   b64url(recoveryPub),       recover only
 *     "rsig":   b64url(64) }               recover only
 *
 * (b64url without padding), at most 1 KiB. A reader re-encodes what it parsed
 * and refuses the entry unless the bytes are identical, so a record has
 * exactly one encoding and nothing about it is malleable. `xintro` is derived
 * by the owner from the introduction seed (SPEC amendment 1:
 * HKDF-SHA256(introSeed, salt "z-handle-intro-x-v1", info "", 32) as an
 * X25519 private key); nothing here can check that relation, and nothing
 * tries — the log holds the pair to its shape: two keys, or two nulls.
 *
 *   publish  sig  = Ed25519(owner named in the record, "z-handle-publish-v1:" ‖ label ‖ u64be(v) ‖ SHA-256(value))
 *   recover  rsig = Ed25519(recovery key, "z-handle-recover-v1:" ‖ label ‖ u64be(v) ‖ owner ‖ rc)   (the new ones)
 *            rc   = SHA-256("z-handle-rc-v1:" ‖ recoveryPub)
 *   leaf     "z-handle-leaf-v1:" ‖ label ‖ u64be(v) ‖ SHA-256(value) ‖ u64be(tsHour)
 *   head     "z-handle-sth-v1:" ‖ u64be(size) ‖ logRoot ‖ mapRoot ‖ u64be(ts)      (the KT head's layout)
 *   witness  "z-handle-witness-v1:" ‖ head input
 *
 * Every context differs from the key-transparency log's, so nothing one log
 * signs is anything the other signs — a handle head never verifies as a KT
 * head, under any key — and the handle log is a separate instance with its
 * own key besides (heads name no log, so two logs under one key would have
 * interchangeable heads).
 *
 * The owner rule (`ownerRuleStep`), enforced by the log on the wire AND on
 * replay of its own file, by every mirror and witness, and by any client
 * over whatever history it holds:
 *   1. the first entry for a label is a claim, which fixes `owner` and `rc`;
 *   2. a claim on a label that exists is refused (`taken`);
 *   3. an update is signed by the CURRENT owner and keeps `owner` and `rc`;
 *   4. a recover carries `rpub` whose commitment is the current `rc`, a
 *      valid `rsig`, and is signed (`sig`) by the NEW owner it names;
 *   5. versions strictly increase (as in KT mode);
 *   6. a value over 1 KiB is refused.
 */

const crypto = require('crypto');

const { sha256 } = require('./merkle.js');
const { u64be } = require('./smt.js');

const LEAF_CONTEXT = Buffer.from('z-handle-leaf-v1:', 'utf8');
const STH_CONTEXT = Buffer.from('z-handle-sth-v1:', 'utf8');
const WITNESS_CONTEXT = Buffer.from('z-handle-witness-v1:', 'utf8');
const PUBLISH_CONTEXT = Buffer.from('z-handle-publish-v1:', 'utf8');
const RECOVER_CONTEXT = Buffer.from('z-handle-recover-v1:', 'utf8');
const RC_CONTEXT = Buffer.from('z-handle-rc-v1:', 'utf8');
/** Local to the log's own head file, like KT mode's `z-kt-signed-from-v1:`; never on the wire. */
const BOUNDARY_CONTEXT = Buffer.from('z-handle-signed-from-v1:', 'utf8');

/** Rule 6: a record is small, and a log that holds handles holds nothing else. */
const MAX_RECORD_BYTES = 1024;
const MIN_POW = 16;
const MAX_POW = 28;
/** `tsHour = floor(acceptedMs / HOUR) × HOUR`: the log keeps no finer time than this. */
const HOUR = 3_600_000;

const KINDS = new Set(['claim', 'update', 'recover']);

/** A refusal with the HTTP status and code the publish route answers with. */
class RuleError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function hourOf(ms) {
  return Math.floor(ms / HOUR) * HOUR;
}

function leafInput({ label, version, valueHash, ts }) {
  return Buffer.concat([LEAF_CONTEXT, label, u64be(version), valueHash, u64be(ts)]);
}

function sthInput({ size, logRoot, mapRoot, ts }) {
  return Buffer.concat([STH_CONTEXT, u64be(size), logRoot, mapRoot, u64be(ts)]);
}

function witnessInput(sth) {
  return Buffer.concat([WITNESS_CONTEXT, sthInput(sth)]);
}

function boundaryInput(signedFrom) {
  return Buffer.concat([BOUNDARY_CONTEXT, u64be(signedFrom)]);
}

function publishInput({ label, version, valueHash }) {
  return Buffer.concat([PUBLISH_CONTEXT, label, u64be(version), valueHash]);
}

function recoverInput({ label, version, owner, rc }) {
  return Buffer.concat([RECOVER_CONTEXT, label, u64be(version), owner, rc]);
}

/** rc = SHA-256("z-handle-rc-v1:" ‖ recoveryPub). */
function rcOf(recoveryPub) {
  return sha256(RC_CONTEXT, recoveryPub);
}

const B64URL = /^[A-Za-z0-9_-]+$/;

/**
 * [s] as exactly [n] bytes of unpadded base64url, in its one canonical
 * spelling. Node's decoder skips characters it does not know and ignores the
 * unused low bits of the last character, so a decode alone would accept many
 * strings for one key; the record would then not be the only encoding of
 * itself, which is the property the re-encode check exists to hold.
 */
function b64urlExact(s, n, what) {
  if (typeof s !== 'string' || s.length !== Math.ceil((n * 4) / 3) || !B64URL.test(s)) {
    throw new RuleError(400, 'bad_record', `${what} must be ${n} bytes of unpadded base64url`);
  }
  const b = Buffer.from(s, 'base64url');
  if (b.length !== n || b.toString('base64url') !== s) {
    throw new RuleError(400, 'bad_record', `${what} is not the canonical base64url of ${n} bytes`);
  }
  return b;
}

/**
 * The record in [value], or a RuleError: 413 `too_large` past 1 KiB, 400
 * `bad_record` for anything that is not exactly the canonical encoding of a
 * record whose members are in range.
 */
function parseRecord(value) {
  if (!Buffer.isBuffer(value)) throw new RuleError(400, 'bad_request', 'value must be bytes');
  if (value.length > MAX_RECORD_BYTES) throw new RuleError(413, 'too_large', `a record is at most ${MAX_RECORD_BYTES} bytes`);
  let j;
  try {
    j = JSON.parse(value.toString('utf8'));
  } catch {
    throw new RuleError(400, 'bad_record', 'the value is not JSON');
  }
  if (!j || typeof j !== 'object' || Array.isArray(j)) throw new RuleError(400, 'bad_record', 'the value is not a JSON object');
  if (!KINDS.has(j.k)) throw new RuleError(400, 'bad_record', 'k must be "claim", "update" or "recover"');
  const owner = b64urlExact(j.owner, 32, 'owner');
  // Present and null, or a key: absent is not a spelling of null.
  if (!Object.prototype.hasOwnProperty.call(j, 'intro')) throw new RuleError(400, 'bad_record', 'intro is required (null for none)');
  const intro = j.intro === null ? null : b64urlExact(j.intro, 32, 'intro');
  if (!Object.prototype.hasOwnProperty.call(j, 'xintro')) throw new RuleError(400, 'bad_record', 'xintro is required (null for none)');
  const xintro = j.xintro === null ? null : b64urlExact(j.xintro, 32, 'xintro');
  // A mailbox is reached with both keys or not at all: one without the
  // other is a record a requester could not act on, or one that says it is
  // paused while naming a key.
  if ((intro === null) !== (xintro === null)) {
    throw new RuleError(400, 'bad_record', 'intro and xintro are both keys or both null');
  }
  if (!Number.isInteger(j.pow) || j.pow < MIN_POW || j.pow > MAX_POW) {
    throw new RuleError(400, 'bad_record', `pow must be an integer ${MIN_POW}..${MAX_POW}`);
  }
  const rc = b64urlExact(j.rc, 32, 'rc');
  const canonical = { k: j.k, owner: j.owner, intro: j.intro, xintro: j.xintro, pow: j.pow, rc: j.rc };
  let rpub = null;
  let rsig = null;
  if (j.k === 'recover') {
    rpub = b64urlExact(j.rpub, 32, 'rpub');
    rsig = b64urlExact(j.rsig, 64, 'rsig');
    canonical.rpub = j.rpub;
    canonical.rsig = j.rsig;
  }
  // Order, whitespace, escapes, number spellings, duplicate or extra members:
  // anything but the one encoding comes out different here.
  if (!Buffer.from(JSON.stringify(canonical), 'utf8').equals(value)) {
    throw new RuleError(400, 'bad_record', 'the record is not in its canonical encoding (member order, no whitespace, no other members)');
  }
  return { k: j.k, owner, intro, xintro, pow: j.pow, rc, rpub, rsig };
}

/** The canonical bytes of a record — what a client publishes and a test builds. */
function encodeRecord({ k, owner, intro, xintro, pow, rc, rpub, rsig }) {
  const o = {
    k,
    owner: owner.toString('base64url'),
    intro: intro ? intro.toString('base64url') : null,
    xintro: xintro ? xintro.toString('base64url') : null,
    pow,
    rc: rc.toString('base64url'),
  };
  if (k === 'recover') {
    o.rpub = rpub.toString('base64url');
    o.rsig = rsig.toString('base64url');
  }
  return Buffer.from(JSON.stringify(o), 'utf8');
}

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function verify(rawPub, data, sig) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, rawPub]), format: 'der', type: 'spki' });
    return crypto.verify(null, data, key, sig);
  } catch {
    return false;
  }
}

/**
 * Everything about one publish that does not depend on the label's history:
 * the record's encoding, and the signatures it carries — `sig` under the
 * owner it names, and for a recover `rsig` under the recovery key it names.
 * Returns the parsed record. Throws RuleError.
 */
function checkEntry({ label, version, value, sig }) {
  const rec = parseRecord(value);
  const valueHash = sha256(value);
  if (!verify(rec.owner, publishInput({ label, version, valueHash }), sig)) {
    throw new RuleError(403, 'bad_signature', 'sig is not the signature of the owner this record names');
  }
  if (rec.k === 'recover' && !verify(rec.rpub, recoverInput({ label, version, owner: rec.owner, rc: rec.rc }), rec.rsig)) {
    throw new RuleError(403, 'bad_recovery', 'rsig is not the signature of the recovery key this record names');
  }
  return rec;
}

/**
 * The owner rule's verdict on [rec] given the label's state before it —
 * [prev] = {owner, rc} or null for a label with no entry — and the state
 * after it. Versions are the caller's (they live in the map already).
 */
function ownerRuleTransition(prev, rec) {
  if (rec.k === 'claim') {
    if (prev) throw new RuleError(409, 'taken', 'this label has been claimed');
  } else {
    if (!prev) throw new RuleError(403, 'owner_rule', `the first entry for a label must be a claim, not ${rec.k === 'update' ? 'an update' : 'a recover'}`);
    if (rec.k === 'update') {
      if (!rec.owner.equals(prev.owner)) {
        throw new RuleError(403, 'owner_rule', 'an update must be signed by the current owner and keep it — changing the owner is a recover');
      }
      if (!rec.rc.equals(prev.rc)) {
        throw new RuleError(403, 'owner_rule', 'an update must keep the recovery commitment — changing it is a recover');
      }
    } else if (!rcOf(rec.rpub).equals(prev.rc)) {
      throw new RuleError(403, 'bad_recovery', 'rpub is not the recovery key the current commitment names');
    }
  }
  return { owner: rec.owner, rc: rec.rc };
}

/** Both halves, for an entry whose history is known: replay, a mirror, a client. */
function ownerRuleStep(prev, entry) {
  return ownerRuleTransition(prev, checkEntry(entry));
}

function rawPub(key) {
  return crypto.createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
}

const ED_PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const X_PKCS8 = Buffer.from('302e020100300506032b656e04220420', 'hex');
const INTRO_X_SALT = Buffer.from('z-handle-intro-x-v1', 'utf8');

/**
 * The introduction mailbox's two public keys from its seed, as the owner
 * derives them (SPEC amendment 1): `intro` the Ed25519 key of the seed, and
 * `xintro` the X25519 key of HKDF-SHA256(seed, salt "z-handle-intro-x-v1",
 * info "", 32). For the tests, the vectors and the bench — the log never
 * sees a seed and does not check the relation.
 */
function introKeys(introSeed) {
  const ed = crypto.createPrivateKey({ key: Buffer.concat([ED_PKCS8, introSeed]), format: 'der', type: 'pkcs8' });
  const xSeed = Buffer.from(crypto.hkdfSync('sha256', introSeed, INTRO_X_SALT, Buffer.alloc(0), 32));
  const x = crypto.createPrivateKey({ key: Buffer.concat([X_PKCS8, xSeed]), format: 'der', type: 'pkcs8' });
  return { intro: rawPub(ed), xintro: rawPub(x) };
}

/**
 * What a client sends — for the tests, the vectors and the bench; the app's
 * is the Dart handle library's. A publish of the record {k, intro, xintro,
 * pow, rc} at [version] for [label], signed by [ownerKey] (a KeyObject: the
 * owner the record names). The introduction keys come from [introSeed]
 * (`introKeys`), or are given as [intro] and [xintro] — both null, the
 * default, for a paused handle. A recover names [recoveryKey] too and
 * carries its `rsig`. Returns {label, version, value, sig}, buffers, as
 * `KtLog.publish` takes it.
 */
function makeHandlePublish({ label, version, ownerKey, k, introSeed = null, intro = null, xintro = null, pow = 20, rc, recoveryKey = null }) {
  if (introSeed) ({ intro, xintro } = introKeys(introSeed));
  const owner = rawPub(ownerKey);
  const rec = { k, owner, intro, xintro, pow, rc };
  if (k === 'recover') {
    rec.rpub = rawPub(recoveryKey);
    rec.rsig = crypto.sign(null, recoverInput({ label, version, owner, rc }), recoveryKey);
  }
  const value = encodeRecord(rec);
  const sig = crypto.sign(null, publishInput({ label, version, valueHash: sha256(value) }), ownerKey);
  return { label, version, value, sig };
}

/** The `POST /kt/v1/publish` body for [p]: label b64url as PROTOCOL §21.5 writes it, value and sig base64. */
function handlePublishJson(p) {
  return { label: p.label.toString('base64url'), v: p.version, value: p.value.toString('base64'), sig: p.sig.toString('base64') };
}

/**
 * KT_MODE, parsed: unset, empty or `kt` is the key-transparency log, exactly
 * as it was; `handles` is the handle log. Anything else refuses to start —
 * a typo must not quietly run the other log under this key.
 */
function modeFromEnv(v) {
  const s = (v || '').trim();
  if (s === '' || s === 'kt') return 'kt';
  if (s === 'handles') return 'handles';
  throw new Error(`KT_MODE must be "handles" or unset (the key-transparency log); got ${JSON.stringify(s)}`);
}

module.exports = {
  HOUR,
  MAX_RECORD_BYTES,
  MIN_POW,
  MAX_POW,
  RuleError,
  hourOf,
  leafInput,
  sthInput,
  witnessInput,
  boundaryInput,
  publishInput,
  recoverInput,
  rcOf,
  parseRecord,
  encodeRecord,
  checkEntry,
  ownerRuleTransition,
  ownerRuleStep,
  introKeys,
  makeHandlePublish,
  handlePublishJson,
  modeFromEnv,
};
