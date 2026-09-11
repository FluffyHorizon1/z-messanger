'use strict';
/**
 * The append-only log tree: RFC 9162 (Certificate Transparency v2) Merkle
 * hashing over SHA-256, exactly — leaf hash `SHA-256(0x00 || input)`, node
 * hash `SHA-256(0x01 || left || right)`, the empty tree `SHA-256("")`,
 * inclusion (audit) paths per §2.1.3 and consistency proofs per §2.1.4. The
 * reference algorithms are transcribed from the RFC with its variable names,
 * so a reader can check this file against the RFC line by line, and the
 * Dart and Python verifiers (docs/vectors/kt) implement the same text.
 *
 * Nothing here knows what a leaf means; `log.js` builds leaf inputs.
 */

const crypto = require('crypto');

function sha256(...parts) {
  // The one-shot API: a quarter cheaper than createHash per call, and a
  // publish is a few hundred calls.
  return crypto.hash('sha256', parts.length === 1 ? parts[0] : Buffer.concat(parts), 'buffer');
}

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

function hashLeaf(input) {
  return sha256(LEAF_PREFIX, input);
}

function hashNode(left, right) {
  return sha256(NODE_PREFIX, left, right);
}

/** Largest power of two strictly less than n (n >= 2). */
function largestPowerOfTwoBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

class MerkleLog {
  constructor() {
    /** @type {Buffer[]} leaf hashes, in order */
    this.leaves = [];
    /** perfect-subtree hash memo: `${lo}:${hi}` → Buffer */
    this._memo = new Map();
  }

  get size() {
    return this.leaves.length;
  }

  append(leafHash) {
    if (!Buffer.isBuffer(leafHash) || leafHash.length !== 32) {
      throw new Error('a leaf hash is 32 bytes');
    }
    this.leaves.push(leafHash);
    return this.leaves.length - 1;
  }

  /** MTH(D[lo:hi]) — the RFC's Merkle Tree Hash of a range. */
  hashRange(lo, hi) {
    const n = hi - lo;
    if (n === 0) return sha256();
    if (n === 1) return this.leaves[lo];
    // Leaves are never rewritten, so the hash of any range is fixed for ever
    // and an append invalidates nothing. Only perfect subtrees (a power-of-two
    // length at an aligned offset) are kept, though: those are the ranges
    // every later root, proof and consistency proof is built from, one per
    // internal node of the final tree. The ragged right-hand ranges of a
    // particular size are never asked for again once the log has grown past
    // it, and remembering them too made the memo grow as N log N.
    const perfect = (n & (n - 1)) === 0 && lo % n === 0;
    const key = perfect ? `${lo}:${hi}` : null;
    if (key !== null) {
      const cached = this._memo.get(key);
      if (cached) return cached;
    }
    const k = largestPowerOfTwoBelow(n);
    const h = hashNode(this.hashRange(lo, lo + k), this.hashRange(lo + k, hi));
    if (key !== null) this._memo.set(key, h);
    return h;
  }

  /** MTH(D[n]) for a prefix of the log — the root at size n. */
  rootAt(n) {
    if (n < 0 || n > this.leaves.length) throw new Error('size out of range');
    return this.hashRange(0, n);
  }

  get root() {
    return this.rootAt(this.leaves.length);
  }

  /** PATH(m, D[n]) — RFC 9162 §2.1.3.1, the audit path for leaf m at size n. */
  inclusionProof(m, n) {
    if (!(m >= 0 && m < n && n <= this.leaves.length)) {
      throw new Error('inclusion proof out of range');
    }
    const path = (lo, hi, idx) => {
      const len = hi - lo;
      if (len === 1) return [];
      const k = largestPowerOfTwoBelow(len);
      if (idx < k) return [...path(lo, lo + k, idx), this.hashRange(lo + k, hi)];
      return [...path(lo + k, hi, idx - k), this.hashRange(lo, lo + k)];
    };
    return path(0, n, m);
  }

  /** PROOF(m, D[n]) — RFC 9162 §2.1.4.1, consistency between sizes m and n. */
  consistencyProof(m, n) {
    if (!(m >= 0 && m <= n && n <= this.leaves.length)) {
      throw new Error('consistency proof out of range');
    }
    if (m === 0 || m === n) return [];
    const subproof = (lo, hi, mm, b) => {
      // SUBPROOF(m, D[lo:hi], b) with m relative to lo.
      const len = hi - lo;
      if (mm === len) return b ? [] : [this.hashRange(lo, hi)];
      const k = largestPowerOfTwoBelow(len);
      if (mm <= k) return [...subproof(lo, lo + k, mm, b), this.hashRange(lo + k, hi)];
      return [...subproof(lo + k, hi, mm - k, false), this.hashRange(lo, lo + k)];
    };
    return subproof(0, n, m, true);
  }
}

// ---------------------------------------------------------------------------
// Verification — pure functions, the same text the Dart and Python verifiers
// implement.
// ---------------------------------------------------------------------------

/** RFC 9162 §2.1.3.2. Returns true if `path` proves `leafHash` at `index` in a tree of `size` with `root`. */
function verifyInclusion({ leafHash, index, size, root, path }) {
  if (!(index >= 0 && index < size)) return false;
  let fn = index;
  let sn = size - 1;
  let r = leafHash;
  for (const p of path) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = hashNode(p, r);
      if ((fn & 1) === 0) {
        while (!((fn & 1) === 1 || fn === 0)) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = hashNode(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && r.equals(root);
}

/** RFC 9162 §2.1.4.2. Returns true if `proof` shows the tree of `first` (root `firstRoot`) is a prefix of the tree of `second` (root `secondRoot`). */
function verifyConsistency({ first, second, firstRoot, secondRoot, proof }) {
  if (first > second) return false;
  if (first === second) return proof.length === 0 && firstRoot.equals(secondRoot);
  if (first === 0) return proof.length === 0; // any tree extends the empty tree
  if (proof.length === 0) return false;
  let p = proof;
  if ((first & (first - 1)) === 0) p = [firstRoot, ...proof]; // first is a power of two
  let fn = first - 1;
  let sn = second - 1;
  if ((fn & 1) === 1) {
    while ((fn & 1) === 1) {
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }
  }
  let fr = p[0];
  let sr = p[0];
  for (const c of p.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = hashNode(c, fr);
      sr = hashNode(c, sr);
      if ((fn & 1) === 0) {
        while (!((fn & 1) === 1 || fn === 0)) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      sr = hashNode(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return fr.equals(firstRoot) && sr.equals(secondRoot) && sn === 0;
}

module.exports = {
  sha256,
  hashLeaf,
  hashNode,
  MerkleLog,
  verifyInclusion,
  verifyConsistency,
};
