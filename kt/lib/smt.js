'use strict';
/**
 * The map tree: a sparse Merkle tree of depth 256 over 32-byte labels, whose
 * root — carried in every signed tree head — pins, for every label, WHICH log
 * entry is its latest. Without it a log could serve one client an old entry
 * for a label and another the new one, both with valid inclusion proofs; with
 * it, two clients holding the same head must be shown the same latest entry,
 * or a proof fails.
 *
 * Hashing, domain-separated from the log tree:
 *   leaf(label, index, version) = SHA-256(0x10 || label || u64be(index) || u64be(version))
 *   node(left, right)           = SHA-256(0x11 || left || right)
 *   empty leaf                  = SHA-256(0x12)
 *   empty subtree at depth d    = node(empty(d+1), empty(d+1))   (precomputed)
 * Depth 0 is the root; at depth d the path branches on bit d of the label
 * (bit 0 = the most significant bit of byte 0); leaves sit at depth 256.
 *
 * A proof is the 256 siblings along the label's path, compressed: a 32-byte
 * bitmap (bit d set when the sibling at depth d is not the empty subtree)
 * plus only those siblings, in depth order. A proof of absence is the same
 * thing with an empty leaf at the end. With N random labels a path meets
 * about log2(N) + 1 non-empty siblings, so a proof is ~15 hashes at a
 * hundred thousand labels, not 256.
 *
 * Implementation: the tree is stored compactly — an internal node exists only
 * where two or more labels share the path, and a subtree holding one label
 * is a single record whose hash is that label's "chain" (its leaf hashed up
 * through empty siblings to the record's depth). A set walks ~log2(N)
 * internal nodes, computes at most two chains (≤ 256 hashes each: the new
 * or updated label's, and a displaced neighbour's), and re-hashes the path.
 * The root is then already known: nothing is memoised and nothing is
 * invalidated, and the cost of a publish does not grow with the map. A
 * first version kept a sorted array and a range memo cleared on every set,
 * which made each head after a publish cost O(N) hashes — 100 ms at ten
 * thousand labels; bench/proofs.js is what caught it.
 */

const crypto = require('crypto');

const DEPTH = 256;

function sha256(...parts) {
  // The one-shot API: a quarter cheaper than createHash per call, and a
  // publish is a few hundred calls.
  return crypto.hash('sha256', parts.length === 1 ? parts[0] : Buffer.concat(parts), 'buffer');
}

function u64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}

const MAP_LEAF = Buffer.from([0x10]);
const MAP_NODE = Buffer.from([0x11]);
const MAP_EMPTY = Buffer.from([0x12]);

function mapLeafHash(label, index, version) {
  return sha256(MAP_LEAF, label, u64be(index), u64be(version));
}

function mapNodeHash(left, right) {
  return sha256(MAP_NODE, left, right);
}

/** EMPTY[d] = hash of an empty subtree rooted at depth d; EMPTY[256] is the empty leaf. */
const EMPTY = new Array(DEPTH + 1);
EMPTY[DEPTH] = sha256(MAP_EMPTY);
for (let d = DEPTH - 1; d >= 0; d--) EMPTY[d] = mapNodeHash(EMPTY[d + 1], EMPTY[d + 1]);

function bit(label, d) {
  return (label[d >> 3] >> (7 - (d & 7))) & 1;
}

/** The hash, at `depth`, of a subtree that contains only this label. */
function chainHash(label, index, version, depth) {
  let h = mapLeafHash(label, index, version);
  for (let d = DEPTH - 1; d >= depth; d--) {
    h = bit(label, d) === 0 ? mapNodeHash(h, EMPTY[d + 1]) : mapNodeHash(EMPTY[d + 1], h);
  }
  return h;
}

/** A subtree with exactly one label below it; `hash` is its hash at the depth where it sits. */
class Single {
  constructor(label, index, version, depth) {
    this.label = label;
    this.index = index;
    this.version = version;
    this.hash = chainHash(label, index, version, depth);
  }
}

/** A subtree with two or more labels below it; a null child is an empty subtree. */
class Internal {
  constructor(left, right, depth) {
    this.left = left;
    this.right = right;
    this.hash = mapNodeHash(left ? left.hash : EMPTY[depth + 1], right ? right.hash : EMPTY[depth + 1]);
  }
}

class SparseMerkleMap {
  constructor() {
    /** label hex → { index, version } */
    this.values = new Map();
    /** @type {Single|Internal|null} */
    this._root = null;
  }

  get size() {
    return this.values.size;
  }

  get(label) {
    return this.values.get(label.toString('hex')) || null;
  }

  get root() {
    return this._root ? this._root.hash : EMPTY[0];
  }

  /** Set the latest (index, version) for a label — an insert or an update. */
  set(label, index, version) {
    if (!Buffer.isBuffer(label) || label.length !== 32) throw new Error('a label is 32 bytes');
    this.values.set(label.toString('hex'), { index, version });
    this._root = insert(this._root, 0, label, index, version);
  }

  /**
   * The compressed proof for a label — of its (index, version) if present,
   * of its absence if not. Returns { leaf: {index, version} | null, bitmap: Buffer(32), siblings: Buffer[] }.
   */
  proof(label) {
    const bitmap = Buffer.alloc(32);
    const siblings = [];
    const take = (d, h) => {
      bitmap[d >> 3] |= 1 << (7 - (d & 7));
      siblings.push(h);
    };
    let node = this._root;
    let d = 0;
    while (node !== null && d < DEPTH) {
      if (node instanceof Single) {
        if (!node.label.equals(label)) {
          // Their paths run together while the bits agree (empty siblings),
          // then part: at the first differing depth the sibling is the whole
          // subtree holding the other label, and below that everything on our
          // side is empty.
          while (d < DEPTH && bit(label, d) === bit(node.label, d)) d++;
          if (d < DEPTH) take(d, chainHash(node.label, node.index, node.version, d + 1));
        }
        break;
      }
      const b = bit(label, d);
      const sib = b === 0 ? node.right : node.left;
      if (sib !== null) take(d, sib.hash);
      node = b === 0 ? node.left : node.right;
      d++;
    }
    return { leaf: this.get(label), bitmap, siblings };
  }

  /**
   * The bucket of every label whose first [bits] bits are [prefix]'s
   * (PROTOCOL §19.9): its leaves in label order, the hash of the subtree
   * that holds exactly them (at depth [bits]), and the siblings that fold
   * that hash to the root, from depth bits−1 up to depth 0. [prefix] is a
   * 32‑byte buffer whose bits past [bits] are ignored (`parsePrefix`).
   *
   * Returns null when the bucket holds more than [max] leaves — found by
   * stopping at max + 1, so a bucket too large to serve costs what a bucket
   * of [max] does and never what the whole map does.
   *
   * Everything comes out of the tree as it stands: the path to depth [bits]
   * is ~log₂ N internal nodes whose hashes are already known, and the only
   * hashing is a chain, when one label sits alone above depth [bits].
   */
  bucket(prefix, bits, max = Infinity) {
    if (!Number.isInteger(bits) || bits < 0 || bits > DEPTH) throw new Error('bits is 0..256');
    const sibs = new Array(bits);
    let node = this._root;
    let hash = null;
    let d = 0;
    while (d < bits) {
      if (node === null) {
        for (; d < bits; d++) sibs[d] = EMPTY[d + 1];
        break;
      }
      if (node instanceof Single) {
        // One label below depth d. It is in the bucket if it agrees with the
        // prefix down to depth [bits]; if not, they part at depth e, where
        // the sibling is the label's own subtree and everything else is
        // empty — and so is the bucket.
        const one = node;
        let e = d;
        while (e < bits && bit(one.label, e) === bit(prefix, e)) e++;
        for (; d < bits; d++) {
          sibs[d] = d === e ? chainHash(one.label, one.index, one.version, e + 1) : EMPTY[d + 1];
        }
        if (e === bits) {
          hash = chainHash(one.label, one.index, one.version, bits);
        } else {
          node = null;
        }
        break;
      }
      const b = bit(prefix, d);
      const sib = b === 0 ? node.right : node.left;
      sibs[d] = sib ? sib.hash : EMPTY[d + 1];
      node = b === 0 ? node.left : node.right;
      d++;
    }
    const leaves = [];
    if (!collect(node, leaves, max)) return null;
    if (hash === null) hash = node === null ? EMPTY[bits] : node.hash;
    const siblings = [];
    for (let k = bits - 1; k >= 0; k--) siblings.push(sibs[k]);
    return { leaves, hash, siblings };
  }
}

/**
 * Every label under [node], in label order, into [out] — or false as soon as
 * there are more than [max]. A left‑first walk visits labels in ascending
 * byte order, because bit 0 is the most significant bit of byte 0.
 */
function collect(node, out, max) {
  if (node === null) return true;
  if (node instanceof Single) {
    if (out.length >= max) return false;
    out.push({ label: node.label, index: node.index, version: node.version });
    return true;
  }
  return collect(node.left, out, max) && collect(node.right, out, max);
}

/** Insert or update `label` in the subtree `node` rooted at `depth`; returns the new subtree. */
function insert(node, depth, label, index, version) {
  if (node === null) return new Single(label, index, version, depth);
  if (node instanceof Single) {
    if (node.label.equals(label)) return new Single(label, index, version, depth);
    // Two labels under one subtree: internal nodes down to where they part.
    let d = depth;
    while (bit(label, d) === bit(node.label, d)) d++; // they differ somewhere: labels are distinct
    const mine = new Single(label, index, version, d + 1);
    const theirs = new Single(node.label, node.index, node.version, d + 1);
    let sub = bit(label, d) === 0 ? new Internal(mine, theirs, d) : new Internal(theirs, mine, d);
    for (let k = d - 1; k >= depth; k--) {
      sub = bit(label, k) === 0 ? new Internal(sub, null, k) : new Internal(null, sub, k);
    }
    return sub;
  }
  if (bit(label, depth) === 0) {
    return new Internal(insert(node.left, depth + 1, label, index, version), node.right, depth);
  }
  return new Internal(node.left, insert(node.right, depth + 1, label, index, version), depth);
}

/**
 * Verify a compressed proof against a map root. `leaf` is {index, version}
 * or null for absence. The same text the Dart and Python verifiers implement.
 */
function verifyMapProof({ root, label, leaf, bitmap, siblings }) {
  if (!Buffer.isBuffer(label) || label.length !== 32) return false;
  if (!Buffer.isBuffer(bitmap) || bitmap.length !== 32) return false;
  let expectedSiblings = 0;
  for (let d = 0; d < DEPTH; d++) if (bit(bitmap, d)) expectedSiblings++;
  if (siblings.length !== expectedSiblings) return false;
  let h = leaf ? mapLeafHash(label, leaf.index, leaf.version) : EMPTY[DEPTH];
  let s = siblings.length - 1;
  for (let d = DEPTH - 1; d >= 0; d--) {
    const sib = bit(bitmap, d) ? siblings[s--] : EMPTY[d + 1];
    h = bit(label, d) === 0 ? mapNodeHash(h, sib) : mapNodeHash(sib, h);
  }
  return h.equals(root);
}

// --- Buckets (PROTOCOL §19.9) ---------------------------------------------------

/**
 * A bucket's prefix as the protocol writes it: the first [bits] bits of a
 * label as ⌈bits/4⌉ lowercase hex digits, the unused low bits zero ("" for
 * bits = 0).
 */
function prefixHex(label, bits) {
  const digits = Math.ceil(bits / 4);
  const b = Buffer.alloc(32);
  for (let d = 0; d < bits; d++) if (bit(label, d)) b[d >> 3] |= 1 << (7 - (d & 7));
  return b.toString('hex').slice(0, digits);
}

/**
 * The prefix [hex] names at [bits], as a 32‑byte buffer with every later bit
 * zero — or null unless it is exactly ⌈bits/4⌉ hex digits with the unused
 * low bits zero, so that every bucket has one spelling (either case is read).
 */
function parsePrefix(hex, bits) {
  if (!Number.isInteger(bits) || bits < 0 || bits > DEPTH) return null;
  if (typeof hex !== 'string' || hex.length !== Math.ceil(bits / 4) || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  const b = Buffer.alloc(32);
  Buffer.from(hex.length % 2 ? hex + '0' : hex, 'hex').copy(b);
  for (let d = bits; d < hex.length * 4; d++) if (bit(b, d)) return null;
  return b;
}

/** Whether [label]'s first [bits] bits are [prefix]'s. */
function hasPrefix(label, prefix, bits) {
  for (let d = 0; d < bits; d++) if (bit(label, d) !== bit(prefix, d)) return false;
  return true;
}

/**
 * The hash, at [depth], of the subtree holding exactly [leaves] — labels in
 * strictly ascending order that share their first [depth] bits — with every
 * other position empty. No leaves is EMPTY[depth]; one is its chain. What a
 * reader recomputes from a bucket, and what makes the bucket complete: a
 * label left out changes it.
 */
function bucketRoot(leaves, depth) {
  if (leaves.length === 0) return EMPTY[depth];
  if (leaves.length === 1) return chainHash(leaves[0].label, leaves[0].index, leaves[0].version, depth);
  if (depth >= DEPTH) throw new Error('two leaves for one label');
  let split = 0;
  while (split < leaves.length && bit(leaves[split].label, depth) === 0) split++;
  return mapNodeHash(bucketRoot(leaves.slice(0, split), depth + 1), bucketRoot(leaves.slice(split), depth + 1));
}

/**
 * Verify a bucket against a map root: every leaf has the prefix, the labels
 * are strictly ascending, there are exactly [bits] siblings (depth bits−1 up
 * to 0), and the subtree the leaves make, folded up through the siblings by
 * the prefix's bits, is [root]. The same text the Dart and Python verifiers
 * implement. `leaves` are {label, index, version}.
 */
function verifyBucket({ root, prefix, bits, leaves, siblings }) {
  if (!Buffer.isBuffer(root) || root.length !== 32) return false;
  if (!Buffer.isBuffer(prefix) || prefix.length !== 32) return false;
  if (!Number.isInteger(bits) || bits < 0 || bits > DEPTH) return false;
  if (!Array.isArray(leaves) || !Array.isArray(siblings) || siblings.length !== bits) return false;
  for (let i = 0; i < leaves.length; i++) {
    const l = leaves[i];
    if (!Buffer.isBuffer(l.label) || l.label.length !== 32) return false;
    if (!Number.isInteger(l.index) || l.index < 0 || !Number.isInteger(l.version) || l.version < 0) return false;
    if (!hasPrefix(l.label, prefix, bits)) return false;
    if (i > 0 && Buffer.compare(leaves[i - 1].label, l.label) >= 0) return false;
  }
  for (const s of siblings) if (!Buffer.isBuffer(s) || s.length !== 32) return false;
  let h = bucketRoot(leaves, bits);
  for (let i = 0; i < bits; i++) {
    const d = bits - 1 - i;
    h = bit(prefix, d) === 0 ? mapNodeHash(h, siblings[i]) : mapNodeHash(siblings[i], h);
  }
  return h.equals(root);
}

module.exports = {
  DEPTH,
  EMPTY,
  mapLeafHash,
  mapNodeHash,
  chainHash,
  SparseMerkleMap,
  verifyMapProof,
  u64be,
  prefixHex,
  parsePrefix,
  hasPrefix,
  bucketRoot,
  verifyBucket,
};
