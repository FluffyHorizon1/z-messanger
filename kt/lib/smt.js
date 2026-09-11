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

module.exports = {
  DEPTH,
  EMPTY,
  mapLeafHash,
  mapNodeHash,
  chainHash,
  SparseMerkleMap,
  verifyMapProof,
  u64be,
};
