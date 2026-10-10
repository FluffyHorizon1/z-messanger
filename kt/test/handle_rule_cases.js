'use strict';
// The owner rule's edge cases, with the log's own verdicts on each — the
// corpus `handle_rule_diff.test.js` holds the log's three paths to, and that
// `protocol/test/handle_rule_diff_test.dart` holds the Dart library to.
//
// Built from an independent review's differential probe (2026-10-09), which
// found the two implementations disagreeing on 7 of 92 such histories and
// naming one refusal differently: small-order and non-canonical keys that
// "anyone can sign" for, versions at and past 2^53 that the log's replay and
// its mirrors took and its wire refused, and a taken claim with a bad
// signature named `taken` by one and `bad_signature` by the other. Every
// history is run here through the log's REAL code, three ways:
//
//   wire   — `KtLog.publish`, what the live log answers;
//   replay — `KtLog._apply(entry, true)`, the line-by-line replay of the
//            log's own file at a start (`_applyHandle`);
//   mirror — `Mirror._holdToRule` + `_append`, what a mirror does with each
//            entry it loads or replicates;
//
// and the first refused entry's index, code and reason (the Dart
// `HandleRefusal` name) are recorded.
//
// Run as a program it writes the corpus as JSON for the Dart side:
//   node test/handle_rule_cases.js <out.json>

const crypto = require('crypto');
const fs = require('fs');

const h = require('../lib/handles.js');
const { sha256 } = require('../lib/merkle.js');
const { KtLog, MemoryStore, privateKeyFromSeed, rawPublicKey } = require('../lib/log.js');
const { Mirror } = require('../lib/mirror.js');

// --- Ed25519 by hand, for building what no honest signer makes ---------------
// Test-only arithmetic (RFC 8032 §5.1): affine twisted Edwards, BigInt.

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => ((a % m) + m) % m;
function powm(b, e, m = P) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
const inv = (a) => powm(a, P - 2n);
const D = mod(-121665n * inv(121666n));
const SQRT_M1 = powm(2n, (P - 1n) / 4n);
const leInt = (b) => {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
};
const intLe = (n, len = 32) => {
  const b = Buffer.alloc(len);
  for (let i = 0; i < len; i++) {
    b[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return b;
};
const add = ([x1, y1], [x2, y2]) => {
  const t = mod(D * x1 * x2 * y1 * y2);
  return [mod((x1 * y2 + y1 * x2) * inv(1n + t)), mod((y1 * y2 + x1 * x2) * inv(1n - t))];
};
const mul = (k, pt) => {
  let r = [0n, 1n];
  let q = pt;
  for (; k > 0n; k >>= 1n) {
    if (k & 1n) r = add(r, q);
    q = add(q, q);
  }
  return r;
};
const encode = ([x, y]) => {
  const b = intLe(y);
  if (x & 1n) b[31] |= 0x80;
  return b;
};
function decode(b) {
  const y = leInt(b) & ((1n << 255n) - 1n);
  const sign = b[31] >> 7;
  if (y >= P) return null;
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * powm(v, 3n) * powm(u * powm(v, 7n), (P - 5n) / 8n));
  if (mod(v * x * x - u) !== 0n) {
    if (mod(v * x * x + u) !== 0n) return null;
    x = mod(x * SQRT_M1);
  }
  if (x === 0n && sign) return null;
  if (Number(x & 1n) !== sign) x = P - x;
  return [x, y];
}
const BASE = decode(intLe(mod(4n * inv(5n))));
const T2 = [0n, P - 1n]; // the point of order 2
const sha512 = (...parts) => crypto.createHash('sha512').update(Buffer.concat(parts)).digest();
/** The secret scalar of a seed, as RFC 8032 derives it. */
function scalarOf(seed) {
  const a = Buffer.from(sha512(seed).subarray(0, 32));
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
  return leInt(a);
}
const kOf = (R, A, msg) => mod(leInt(sha512(R, A, msg)), L);

// --- Keys and records ------------------------------------------------------------

const seed = (s) => crypto.createHash('sha256').update(`handle rule cases: ${s}`).digest();
const key = (s) => privateKeyFromSeed(seed(s));
const label = seed('label');
const A = key('owner A');
const B = key('stranger B');
const N = key('new owner N');
const R = key('recovery R');
const R2 = key('recovery R2');
const W = key('wrong recovery W');
const rc = h.rcOf(rawPublicKey(R));
const rc2 = h.rcOf(rawPublicKey(R2));
const MAX = Number.MAX_SAFE_INTEGER;

const claim = (o = {}) => h.makeHandlePublish({ label, version: 1, ownerKey: A, k: 'claim', introSeed: seed('intro'), rc, ...o });
const update = (version, o = {}) => h.makeHandlePublish({ label, version, ownerKey: A, k: 'update', introSeed: seed(`intro ${version}`), rc, ...o });
const recover = (version, o = {}) =>
  h.makeHandlePublish({ label, version, ownerKey: N, k: 'recover', introSeed: seed('intro rec'), rc: rc2, recoveryKey: R, ...o });

const publishInputOf = (p) => h.publishInput({ label: p.label, version: p.version, valueHash: sha256(p.value) });
const signRaw = (k, p) => crypto.sign(null, publishInputOf(p), k);
/** [p] with its value replaced by [bytes] and re-signed by [signer], so only the encoding is in question. */
const withValue = (p, bytes, signer = A) => {
  const q = { ...p, value: Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8') };
  return { ...q, sig: signRaw(signer, q) };
};
/** S + L: the same signature, malleated. */
const malleate = (sig) => Buffer.concat([sig.subarray(0, 32), intLe(leInt(sig.subarray(32)) + L)]);

/** Small-order and non-canonical Ed25519 encodings. */
const ED = {
  identity: Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex'),
  order2: Buffer.from('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'),
  order4: Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
  order4neg: Buffer.from('0000000000000000000000000000000000000000000000000000000000000080', 'hex'),
  order8: Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'hex'),
  order8b: Buffer.from('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85', 'hex'),
  identityNegZero: Buffer.from('0100000000000000000000000000000000000000000000000000000000000080', 'hex'),
  // y = p + 1 ≡ 1: the identity, non-canonically encoded
  identityNonCanonical: Buffer.from('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'),
  // y = p ≡ 0: a point of order 4, non-canonically encoded
  order4NonCanonical: Buffer.from('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'),
};
const ZERO_SIG_ID = Buffer.concat([ED.identity, Buffer.alloc(32)]); // R = identity, S = 0

/** Small-order and non-canonical X25519 encodings. */
const XU = {
  zero: Buffer.alloc(32),
  one: Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex'),
  order8: Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex'),
  minusOne: Buffer.from('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'),
  p: Buffer.from('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'),
};

/** A record from raw keys, signed with a raw `sig` (or by [signer]). */
function rawEntry({ version = 1, k = 'claim', owner, intro, xintro, introSeed = seed('intro'), rcv = rc, rpub, rsig, sig, signer }) {
  const keys = h.introKeys(introSeed);
  const value = h.encodeRecord({
    k,
    owner,
    intro: intro === undefined ? keys.intro : intro,
    xintro: xintro === undefined ? keys.xintro : xintro,
    pow: 20,
    rc: rcv,
    rpub,
    rsig,
  });
  const e = { label, version, value };
  return { ...e, sig: sig || crypto.sign(null, publishInputOf(e), signer) };
}

/** A signature by [k]'s owner with R = the identity: S = k·a. OpenSSL alone accepts it. */
function identityRSig(ownerSeed, msg) {
  const a = scalarOf(ownerSeed);
  const Abytes = encode(mul(a, BASE));
  const k = kOf(ED.identity, Abytes, msg);
  return Buffer.concat([ED.identity, intLe(mod(k * a, L))]);
}

/**
 * A signature by [ownerSeed]'s key whose R carries the point of order 2:
 * R = rB + T2 and S = −(r + k·a). Then R + [k]A = −[S]B + T2, which has the
 * same x as [S]B — a comparison of points by x alone accepts it; R's bytes
 * are not those of [S]B − [k]A, so OpenSSL does not.
 */
function mixedRSig(ownerSeed, msg) {
  const a = scalarOf(ownerSeed);
  const Abytes = encode(mul(a, BASE));
  const r = mod(leInt(sha512(Buffer.from('mixed r'), msg)), L);
  const Rbytes = encode(add(mul(r, BASE), T2));
  const k = kOf(Rbytes, Abytes, msg);
  return Buffer.concat([Rbytes, intLe(mod(-(r + k * a), L))]);
}

/** A key with a component of order 2: aB + T2, for the seed's a; and a signature under it with R = rB. */
function mixedOwner(ownerSeed) {
  const a = scalarOf(ownerSeed);
  return { pub: encode(add(mul(a, BASE), T2)), a };
}
function signUnderMixed(a, pub, msg, tag) {
  const r = mod(leInt(sha512(Buffer.from(tag), msg)), L);
  const Rbytes = encode(mul(r, BASE));
  const k = kOf(Rbytes, pub, msg);
  return { sig: Buffer.concat([Rbytes, intLe(mod(r + k * a, L))]), kOdd: (k & 1n) === 1n };
}

/** An owner key whose y has no x: not a point at all. */
function offCurve() {
  for (let i = 0; ; i++) {
    const b = seed(`off curve ${i}`);
    b[31] &= 0x7f;
    if (leInt(b) < P && decode(b) === null) return b;
  }
}

// --- The cases ---------------------------------------------------------------------

function buildCases() {
  const cases = [];
  const add_ = (name, entries) => cases.push({ name, entries });

  // 1. Encodings of a claim.
  const good = claim().value.toString('utf8');
  const j = JSON.parse(good);
  add_('valid claim', [claim()]);
  add_('valid paused claim (intro and xintro null)', [h.makeHandlePublish({ label, version: 1, ownerKey: A, k: 'claim', rc })]);
  const enc = [
    ['whitespace after a comma', good.replace(',"intro"', ', "intro"')],
    ['leading space', ' ' + good],
    ['trailing newline', good + '\n'],
    ['member order', JSON.stringify({ owner: j.owner, k: j.k, intro: j.intro, xintro: j.xintro, pow: j.pow, rc: j.rc })],
    ['xintro before intro', JSON.stringify({ k: j.k, owner: j.owner, xintro: j.xintro, intro: j.intro, pow: j.pow, rc: j.rc })],
    ['an extra member', good.replace('}', ',"x":1}')],
    ['a __proto__ member', good.replace('}', ',"__proto__":{"k":"claim"}}')],
    ['no intro', JSON.stringify({ k: j.k, owner: j.owner, xintro: j.xintro, pow: j.pow, rc: j.rc })],
    ['no xintro', JSON.stringify({ k: j.k, owner: j.owner, intro: j.intro, pow: j.pow, rc: j.rc })],
    ['intro key, xintro null', good.replace(`"xintro":"${j.xintro}"`, '"xintro":null')],
    ['intro null, xintro key', good.replace(`"intro":"${j.intro}"`, '"intro":null')],
    ['pow 15', good.replace('"pow":20', '"pow":15')],
    ['pow 29', good.replace('"pow":20', '"pow":29')],
    ['pow 16 (min)', good.replace('"pow":20', '"pow":16')],
    ['pow 28 (max)', good.replace('"pow":20', '"pow":28')],
    ['pow 20.0', good.replace('"pow":20', '"pow":20.0')],
    ['pow 2e1', good.replace('"pow":20', '"pow":2e1')],
    ['pow 2E1', good.replace('"pow":20', '"pow":2E1')],
    ['pow -0', good.replace('"pow":20', '"pow":-0')],
    ['pow 020', good.replace('"pow":20', '"pow":020')],
    ['pow huge', good.replace('"pow":20', '"pow":20000000000000000000001')],
    ['pow "20"', good.replace('"pow":20', '"pow":"20"')],
    ['pow null', good.replace('"pow":20', '"pow":null')],
    ['pow true', good.replace('"pow":20', '"pow":true')],
    ['k "Claim"', good.replace('"claim"', '"Claim"')],
    ['k escaped', good.replace('"claim"', '"\\u0063laim"')],
    ['k duplicated, last wins', good.replace('{"k":"claim"', '{"k":"update","k":"claim"')],
    ['pow duplicated', good.replace('"pow":20', '"pow":20,"pow":20')],
    ['owner escaped first char', good.replace(`"owner":"${j.owner}"`, `"owner":"\\u00${j.owner.charCodeAt(0).toString(16)}${j.owner.slice(1)}"`)],
    ['owner padded', good.replace(j.owner, j.owner + '=')],
    ['owner standard alphabet', good.replace(j.owner, '+' + j.owner.slice(1))],
    ['owner unused bits set', good.replace(j.owner, j.owner.slice(0, 42) + String.fromCharCode(j.owner.charCodeAt(42) + 1))],
    ['owner 31 bytes', good.replace(j.owner, Buffer.alloc(31, 1).toString('base64url'))],
    ['owner 33 bytes', good.replace(j.owner, Buffer.alloc(33, 1).toString('base64url'))],
    ['owner empty', good.replace(j.owner, '')],
    ['owner a number', good.replace(`"${j.owner}"`, '12')],
    ['owner an object', good.replace(`"${j.owner}"`, '{"a":1}')],
    ['rc padded', good.replace(j.rc, j.rc + '=')],
    ['rpub on a claim', good.replace('}', `,"rpub":"${j.owner}"}`)],
    ['rpub null on a claim', good.replace('}', ',"rpub":null}')],
    ['a byte-order mark', '﻿' + good],
    ['not JSON (truncated)', good.slice(0, -1)],
    ['an array', `[${good}]`],
    ['JSON null', 'null'],
    ['empty string value', ''],
    ['over 1 KiB of whitespace', good + ' '.repeat(1100)],
    ['exactly 1024 bytes (non-canonical padding)', good + ' '.repeat(1024 - good.length)],
  ];
  for (const [name, text] of enc) add_(`claim: ${name}`, [withValue(claim(), text)]);
  const badUtf8 = Buffer.from(good, 'utf8');
  badUtf8[good.indexOf(j.owner) + 3] = 0xff;
  add_('claim: invalid UTF-8 inside owner', [withValue(claim(), badUtf8)]);
  const overlong = Buffer.concat([Buffer.from('{"k":', 'utf8'), Buffer.from([0xc0, 0xa2]), Buffer.from(good.slice(6), 'utf8')]);
  add_('claim: overlong UTF-8 quote', [withValue(claim(), overlong)]);

  // 2. Signatures.
  add_('claim signed by a stranger', [{ ...claim(), sig: signRaw(B, claim()) }]);
  add_('claim with S+L (malleated) signature', [{ ...claim(), sig: malleate(claim().sig) }]);
  add_('claim with an all-zero signature', [{ ...claim(), sig: Buffer.alloc(64) }]);
  add_('claim, then update with S+L signature', [claim(), (() => { const u = update(2); return { ...u, sig: malleate(u.sig) }; })()]);
  add_('taken claim with an S+L signature', [claim(), (() => { const c = claim({ version: 2, ownerKey: B }); return { ...c, sig: malleate(c.sig) }; })()]);
  // Owner keys any signature verifies under — R the identity, S = 0 — and
  // encodings at or above p.
  for (const [pname, pt] of Object.entries(ED)) {
    add_(`claim: owner ${pname}, sig (R=identity, S=0)`, [rawEntry({ owner: pt, sig: ZERO_SIG_ID })]);
    add_(`claim+update: owner ${pname}, both sigs (R=identity, S=0)`, [
      rawEntry({ owner: pt, sig: ZERO_SIG_ID }),
      rawEntry({ version: 2, k: 'update', owner: pt, sig: ZERO_SIG_ID, introSeed: seed('anyone') }),
    ]);
  }
  add_('claim: owner identity, sig (R=identity non-canonical, S=0)', [rawEntry({ owner: ED.identity, sig: Buffer.concat([ED.identityNonCanonical, Buffer.alloc(32)]) })]);
  // Weak introduction and recovery keys in a record its genuine owner signed.
  for (const [pname, pt] of Object.entries({ identity: ED.identity, order8: ED.order8, nonCanonical: ED.order4NonCanonical })) {
    add_(`claim: intro ${pname}, signed by its owner`, [rawEntry({ owner: rawPublicKey(A), intro: pt, signer: A })]);
  }
  for (const [uname, u] of Object.entries(XU)) {
    add_(`claim: xintro ${uname}, signed by its owner`, [rawEntry({ owner: rawPublicKey(A), xintro: u, signer: A })]);
  }
  const topBit = Buffer.from(h.introKeys(seed('intro')).xintro);
  topBit[31] |= 0x80;
  add_('claim: xintro with its top bit set, signed by its owner', [rawEntry({ owner: rawPublicKey(A), xintro: topBit, signer: A })]);
  {
    // A recover whose rpub is the identity: rsig (R=identity, S=0) "verifies"
    // for any owner and rc — and rc committed to it, so it would open.
    const rcWeak = h.rcOf(ED.identity);
    const weakClaim = rawEntry({ owner: rawPublicKey(A), rcv: rcWeak, signer: A });
    const weakRecover = rawEntry({ version: 2, k: 'recover', owner: rawPublicKey(N), rcv: rc2, rpub: ED.identity, rsig: ZERO_SIG_ID, introSeed: seed('thief'), signer: N });
    add_('claim committing to the identity as recovery key, then anyone recovers with it', [weakClaim, weakRecover]);
  }
  // Signatures only their owner could make, that one implementation's
  // leniency would take and another's would not.
  {
    const c = claim();
    add_('claim: sig with R = the identity, made by the owner (S = k·a)', [{ ...c, sig: identityRSig(seed('owner A'), publishInputOf(c)) }]);
    add_('claim: sig with R = rB + T2, made by the owner so that x(R + kA) = x(SB)', [{ ...c, sig: mixedRSig(seed('owner A'), publishInputOf(c)) }]);
    add_('claim: sig with R of order 8 and S = 0', [{ ...c, sig: Buffer.concat([ED.order8, Buffer.alloc(32)]) }]);
    const nonCanonicalR = identityRSig(seed('owner A'), publishInputOf(c));
    ED.identityNonCanonical.copy(nonCanonicalR, 0);
    add_('claim: sig with R the identity non-canonically encoded, S = k·a', [{ ...c, sig: nonCanonicalR }]);
    const u = update(2);
    add_('claim, then update whose sig has R = the identity, made by the owner', [c, { ...u, sig: identityRSig(seed('owner A'), publishInputOf(u)) }]);
  }
  {
    // An owner key that is a point plus the point of order 2: no implementation
    // that refuses only small-order keys refuses it, and with one equation
    // computed the same way on both sides, whether a signature verifies under
    // it depends on k's parity alone — the same answer everywhere.
    const m = mixedOwner(seed('mixed owner'));
    const found = {};
    for (let pow = 16; pow <= 28 && Object.keys(found).length < 2; pow++) {
      const e = rawEntry({ owner: m.pub, sig: Buffer.alloc(64), introSeed: seed(`mixed ${pow}`) });
      const value = Buffer.from(e.value.toString().replace('"pow":20', `"pow":${pow}`));
      const q = { label, version: 1, value };
      const s = signUnderMixed(m.a, m.pub, publishInputOf(q), `mixed ${pow}`);
      const tag = s.kOdd ? 'k odd' : 'k even';
      if (!found[tag]) found[tag] = { ...q, sig: s.sig };
    }
    for (const [tag, e] of Object.entries(found)) add_(`claim: owner aB + T2, signed with R = rB, ${tag}`, [e]);
  }
  add_('claim: owner not a point (no x for its y)', [rawEntry({ owner: offCurve(), sig: ZERO_SIG_ID })]);

  // 3. Histories.
  add_('claim, update v2', [claim(), update(2)]);
  add_('claim, update v1 (stale)', [claim(), update(1)]);
  add_('claim, update v3 (a version skipped)', [claim(), update(3)]);
  add_('claim, update v2 paused (intro null)', [claim(), h.makeHandlePublish({ label, version: 2, ownerKey: A, k: 'update', rc })]);
  add_('claim, update v2 by a stranger naming the owner', [claim(), { ...update(2), sig: signRaw(B, update(2)) }]);
  add_('claim, update v2 naming the stranger, signed by the stranger', [claim(), update(2, { ownerKey: B })]);
  add_('claim, update v9 naming the stranger, signed by the stranger', [claim(), update(9, { ownerKey: B })]);
  add_('claim, update v2 changing rc', [claim(), update(2, { rc: rc2 })]);
  add_('claim, claim (taken)', [claim(), claim({ version: 2 })]);
  add_('claim, claim by the stranger (taken)', [claim(), claim({ version: 2, ownerKey: B })]);
  add_('claim, taken claim with a bad signature', [claim(), { ...claim({ version: 2, ownerKey: B }), sig: Buffer.alloc(64, 7) }]);
  add_('claim, recover v2', [claim(), recover(2)]);
  add_('claim, recover v3 (a version skipped)', [claim(), recover(3)]);
  add_('claim, recover v2 with the wrong recovery key', [claim(), recover(2, { recoveryKey: W })]);
  add_('claim, recover v2 whose rsig is over another version', [
    claim(),
    (() => {
      const r = recover(3);
      return withValue({ ...r, version: 2 }, r.value, N);
    })(),
  ]);
  add_('claim, recover v2 signed by the old owner', [claim(), { ...recover(2), sig: signRaw(A, recover(2)) }]);
  add_('claim, recover v2, recover v3 with the spent recovery key', [claim(), recover(2), h.makeHandlePublish({ label, version: 3, ownerKey: B, k: 'recover', introSeed: seed('x'), rc: rc2, recoveryKey: R })]);
  add_('claim, recover v2, update v3 by the old owner', [claim(), recover(2), update(3)]);
  add_('claim, recover v2, update v3 by the new owner', [claim(), recover(2), h.makeHandlePublish({ label, version: 3, ownerKey: N, k: 'update', introSeed: seed('n3'), rc: rc2 })]);
  add_('claim, recover v2 keeping the same rc', [claim(), recover(2, { rc })]);
  add_('claim, recover v2, the same recover again (replay)', [claim(), recover(2), recover(2)]);
  add_('a recover first (not claimed)', [recover(1)]);
  add_('an update first (not claimed)', [update(1)]);
  add_('an update first at v2 (not claimed)', [update(2)]);
  add_('claim v0', [claim({ version: 0 })]);
  add_('claim at v2 (a claim is version 1)', [claim({ version: 2 })]);
  add_('claim at v = 2^53-1', [claim({ version: MAX })]);
  // The theft review A's finding 1 was about: the owner key's holder
  // publishes an update at the last version, and the code cannot follow.
  add_('claim, update at v = 2^53-1 (the theft at the ceiling)', [claim(), update(MAX)]);
  add_('claim, update at v = 2^53-1, recover at v = 2^53', [claim(), update(MAX), recover(MAX + 1)]);
  add_('claim, update at v = 2^53', [claim(), update(MAX + 1)]);
  add_('claim, update at v = 2^60', [claim(), update(2 ** 60)]);
  // And what the code CAN do after a theft: recover at the next version.
  add_('claim, theft v2, recover v3', [claim(), update(2, { introSeed: seed('thief') }), recover(3)]);
  add_('claim, theft v2, theft v3, recover v4', [claim(), update(2, { introSeed: seed('thief') }), update(3, { introSeed: seed('thief 2') }), recover(4)]);
  add_('claim, theft v2, recover v2 (beaten to it)', [claim(), update(2, { introSeed: seed('thief') }), recover(2)]);
  add_('a 31-byte label', [{ ...claim(), label: label.subarray(0, 31) }]);
  return cases;
}

// --- The log's verdicts, three ways ----------------------------------------------------

const logKey = key('the log');
const T = 1_800_000_000_000;

function verdictOf(err, i) {
  return { refusedAt: i, code: err.code || null, reason: err.reason || null, message: String(err.message).slice(0, 160) };
}
const ACCEPTED = { refusedAt: null, code: null, reason: null };

/** `KtLog.publish`, entry by entry, on a fresh handle log. */
function wireVerdict(entries) {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, mode: 'handles', now: () => T });
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    try {
      log.publish({ label: e.label, version: e.version, value: e.value, sig: e.sig });
    } catch (err) {
      return verdictOf(err, i);
    }
  }
  return ACCEPTED;
}

/** The replay of the log's own file: each entry as `_applyHandle` reads a line. */
function replayVerdict(entries) {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, mode: 'handles', now: () => T, deferReplay: true });
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    try {
      log._apply({ index: i, label: e.label, version: e.version, valueHash: sha256(e.value), value: e.value, sig: e.sig, ts: T }, true);
    } catch (err) {
      return verdictOf(err, i);
    }
  }
  return ACCEPTED;
}

/** A mirror loading or replicating the entries: the rule, then its own trees — as `Mirror.load` does each line. */
function mirrorVerdict(entries) {
  const m = new Mirror({ dir: '/nonexistent/handle-rule-cases', logUrl: 'http://127.0.0.1:1', logPub: rawPublicKey(logKey), mode: 'handles' });
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    try {
      m._holdToRule(e, m._ownState(), (msg, why) => Object.assign(new Error(msg), { code: why.code, reason: why.reason }));
      m._append({ index: i, label: e.label, version: e.version, valueHash: sha256(e.value), ts: T });
    } catch (err) {
      return verdictOf(err, i);
    }
  }
  return ACCEPTED;
}

function verdicts(entries) {
  return { wire: wireVerdict(entries), replay: replayVerdict(entries), mirror: mirrorVerdict(entries) };
}

function corpus() {
  return buildCases().map((c) => ({
    name: c.name,
    entries: c.entries.map((e) => ({
      label: e.label.toString('hex'),
      // A string, so 2^53 and beyond reach Dart exactly.
      v: BigInt(e.version).toString(),
      value: e.value.toString('base64'),
      sig: e.sig.toString('base64'),
    })),
    ...verdicts(c.entries),
  }));
}

module.exports = { buildCases, verdicts, corpus, ED, XU };

if (require.main === module) {
  const out = process.argv[2];
  if (!out) {
    console.error('usage: node test/handle_rule_cases.js <out.json>');
    process.exit(2);
  }
  const c = corpus();
  fs.writeFileSync(out, JSON.stringify({ cases: c }, null, 1));
  console.log(`${c.length} cases written to ${out}`);
}
