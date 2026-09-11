'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  DEPTH,
  EMPTY,
  mapLeafHash,
  mapNodeHash,
  SparseMerkleMap,
  verifyMapProof,
} = require('../lib/smt.js');

function label(seed) {
  return crypto.createHash('sha256').update(`label:${seed}`).digest();
}

// A reference root computed the slow way: 2^256 is out of reach, but a tree
// over a handful of labels can be hashed by recursing on the label set at
// every depth with no memo, no chains and no sorted-range trick. If the fast
// implementation and this agree on random sets, the tricks are sound.
function slowRoot(entries) {
  const bit = (l, d) => (l[d >> 3] >> (7 - (d & 7))) & 1;
  const rec = (depth, set) => {
    if (set.length === 0) return EMPTY[depth];
    if (depth === DEPTH) {
      assert.equal(set.length, 1);
      return mapLeafHash(set[0].label, set[0].index, set[0].version);
    }
    const left = set.filter((e) => bit(e.label, depth) === 0);
    const right = set.filter((e) => bit(e.label, depth) === 1);
    return mapNodeHash(rec(depth + 1, left), rec(depth + 1, right));
  };
  return rec(0, entries);
}

test('the empty map has the precomputed empty root', () => {
  const m = new SparseMerkleMap();
  assert.equal(m.size, 0);
  assert.ok(m.root.equals(EMPTY[0]));
  // EMPTY is built bottom-up from the empty leaf.
  assert.ok(EMPTY[DEPTH - 1].equals(mapNodeHash(EMPTY[DEPTH], EMPTY[DEPTH])));
});

test('one label: the root is its chain, and the proof has no siblings', () => {
  const m = new SparseMerkleMap();
  const l = label(1);
  m.set(l, 0, 1);
  assert.ok(m.root.equals(slowRoot([{ label: l, index: 0, version: 1 }])));
  const p = m.proof(l);
  assert.deepEqual(p.leaf, { index: 0, version: 1 });
  assert.equal(p.siblings.length, 0);
  assert.ok(p.bitmap.equals(Buffer.alloc(32)));
  assert.ok(verifyMapProof({ root: m.root, label: l, ...p }));
});

test('the fast root equals the slow root for random label sets, whatever the insertion order', () => {
  for (let trial = 0; trial < 20; trial++) {
    const n = 1 + (trial % 9);
    const entries = [];
    for (let i = 0; i < n; i++) {
      entries.push({ label: label(`${trial}-${i}`), index: trial * 100 + i, version: 1 + (i % 3) });
    }
    const forward = new SparseMerkleMap();
    for (const e of entries) forward.set(e.label, e.index, e.version);
    const backward = new SparseMerkleMap();
    for (const e of [...entries].reverse()) backward.set(e.label, e.index, e.version);
    const expected = slowRoot(entries);
    assert.ok(forward.root.equals(expected), `trial ${trial} forward`);
    assert.ok(backward.root.equals(expected), `trial ${trial} backward`);
    assert.equal(forward.size, n);
  }
});

test('an update changes the root to what a fresh map with the new value has', () => {
  const m = new SparseMerkleMap();
  const l1 = label('u1');
  const l2 = label('u2');
  m.set(l1, 0, 1);
  m.set(l2, 1, 1);
  const before = m.root;
  m.set(l1, 2, 2);
  assert.ok(!m.root.equals(before));
  assert.equal(m.size, 2);
  assert.deepEqual(m.get(l1), { index: 2, version: 2 });
  const fresh = new SparseMerkleMap();
  fresh.set(l2, 1, 1);
  fresh.set(l1, 2, 2);
  assert.ok(m.root.equals(fresh.root));
});

test('inclusion proofs verify, and fail for a wrong leaf, label, root, bitmap or sibling', () => {
  const m = new SparseMerkleMap();
  const labels = [];
  for (let i = 0; i < 40; i++) {
    const l = label(`inc-${i}`);
    labels.push(l);
    m.set(l, i, 1 + (i % 4));
  }
  const root = m.root;
  for (let i = 0; i < labels.length; i++) {
    const p = m.proof(labels[i]);
    assert.deepEqual(p.leaf, { index: i, version: 1 + (i % 4) });
    // Bitmap population equals the sibling count.
    let pop = 0;
    for (const b of p.bitmap) pop += ((b >> 7) & 1) + ((b >> 6) & 1) + ((b >> 5) & 1) + ((b >> 4) & 1) + ((b >> 3) & 1) + ((b >> 2) & 1) + ((b >> 1) & 1) + (b & 1);
    assert.equal(pop, p.siblings.length);
    // Forty random labels share at most a few leading bits, so proofs are short.
    assert.ok(p.siblings.length <= 12, `proof of ${p.siblings.length} siblings`);
    assert.ok(verifyMapProof({ root, label: labels[i], ...p }));
    // Wrong version.
    assert.ok(!verifyMapProof({ root, label: labels[i], leaf: { index: i, version: p.leaf.version + 1 }, bitmap: p.bitmap, siblings: p.siblings }));
    // Wrong index.
    assert.ok(!verifyMapProof({ root, label: labels[i], leaf: { index: i + 1, version: p.leaf.version }, bitmap: p.bitmap, siblings: p.siblings }));
    // Claimed absent.
    assert.ok(!verifyMapProof({ root, label: labels[i], leaf: null, bitmap: p.bitmap, siblings: p.siblings }));
    // Another label with this proof.
    assert.ok(!verifyMapProof({ root, label: labels[(i + 1) % labels.length], ...p }));
    // Another root.
    assert.ok(!verifyMapProof({ root: EMPTY[0], label: labels[i], ...p }));
    if (p.siblings.length > 0) {
      // A flipped sibling byte.
      const bad = p.siblings.map((s) => Buffer.from(s));
      bad[0][0] ^= 1;
      assert.ok(!verifyMapProof({ root, label: labels[i], leaf: p.leaf, bitmap: p.bitmap, siblings: bad }));
      // A sibling dropped: bitmap and count disagree.
      assert.ok(!verifyMapProof({ root, label: labels[i], leaf: p.leaf, bitmap: p.bitmap, siblings: p.siblings.slice(1) }));
      // A bitmap bit moved: count agrees, hashing does not.
      const bm = Buffer.from(p.bitmap);
      let d = 0;
      while (!((bm[d >> 3] >> (7 - (d & 7))) & 1)) d++;
      bm[d >> 3] ^= 1 << (7 - (d & 7));
      let e = d + 1;
      while ((bm[e >> 3] >> (7 - (e & 7))) & 1) e++;
      bm[e >> 3] |= 1 << (7 - (e & 7));
      assert.ok(!verifyMapProof({ root, label: labels[i], leaf: p.leaf, bitmap: bm, siblings: p.siblings }));
    }
  }
});

test('absence proofs verify for labels not in the map, and fail once the label is added', () => {
  const m = new SparseMerkleMap();
  for (let i = 0; i < 25; i++) m.set(label(`abs-${i}`), i, 1);
  const root = m.root;
  for (let i = 0; i < 25; i++) {
    const l = label(`missing-${i}`);
    const p = m.proof(l);
    assert.equal(p.leaf, null);
    assert.ok(verifyMapProof({ root, label: l, ...p }));
    // The same proof cannot claim a value.
    assert.ok(!verifyMapProof({ root, label: l, leaf: { index: 0, version: 1 }, bitmap: p.bitmap, siblings: p.siblings }));
  }
  const l = label('missing-0');
  const stale = m.proof(l);
  m.set(l, 25, 1);
  assert.ok(!verifyMapProof({ root: m.root, label: l, ...stale }));
  const p = m.proof(l);
  assert.deepEqual(p.leaf, { index: 25, version: 1 });
  assert.ok(verifyMapProof({ root: m.root, label: l, ...p }));
  // Absent under the empty root: no siblings at all.
  const e = new SparseMerkleMap();
  const pe = e.proof(l);
  assert.equal(pe.siblings.length, 0);
  assert.ok(verifyMapProof({ root: EMPTY[0], label: l, ...pe }));
});

test('a proof stays valid against the root it was made for, not the next one', () => {
  const m = new SparseMerkleMap();
  const l = label('pin');
  m.set(l, 0, 1);
  for (let i = 0; i < 10; i++) m.set(label(`fill-${i}`), i + 1, 1);
  const root = m.root;
  const p = m.proof(l);
  m.set(label('one-more'), 11, 1);
  assert.ok(verifyMapProof({ root, label: l, ...p }));
  assert.ok(!verifyMapProof({ root: m.root, label: l, ...p }));
});

test('labels must be 32 bytes', () => {
  const m = new SparseMerkleMap();
  assert.throws(() => m.set(Buffer.alloc(31), 0, 1), /32 bytes/);
  assert.equal(verifyMapProof({ root: EMPTY[0], label: Buffer.alloc(16), leaf: null, bitmap: Buffer.alloc(32), siblings: [] }), false);
  assert.equal(verifyMapProof({ root: EMPTY[0], label: Buffer.alloc(32), leaf: null, bitmap: Buffer.alloc(31), siblings: [] }), false);
});
