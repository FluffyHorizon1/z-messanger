'use strict';
// The log tree against RFC 9162, exhaustively for small sizes: every leaf's
// inclusion proof verifies at every size that contains it, every pair of
// sizes has a consistency proof that verifies, and a proof for the wrong
// leaf, index, size or root does not.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const {
  sha256,
  hashLeaf,
  hashNode,
  MerkleLog,
  verifyInclusion,
  verifyConsistency,
} = require('../lib/merkle.js');

function leafInput(i) {
  return Buffer.from(`leaf-${i}`);
}

test('the empty tree hashes to SHA-256 of nothing, one leaf to its leaf hash', () => {
  const log = new MerkleLog();
  assert.ok(log.root.equals(sha256()));
  log.append(hashLeaf(leafInput(0)));
  assert.ok(log.root.equals(hashLeaf(leafInput(0))));
  log.append(hashLeaf(leafInput(1)));
  assert.ok(log.root.equals(hashNode(hashLeaf(leafInput(0)), hashLeaf(leafInput(1)))));
});

test('RFC 9162 worked example: the 7-leaf tree root and proofs', () => {
  // Structure from RFC 9162 §2.1.1: MTH(D[7]) = h(h(h(a,b),h(c,d)), h(h(e,f),g)).
  const log = new MerkleLog();
  const L = [];
  for (let i = 0; i < 7; i++) {
    L.push(hashLeaf(leafInput(i)));
    log.append(L[i]);
  }
  const expected = hashNode(
    hashNode(hashNode(L[0], L[1]), hashNode(L[2], L[3])),
    hashNode(hashNode(L[4], L[5]), L[6])
  );
  assert.ok(log.root.equals(expected));
  // §2.1.3.1 examples: PATH(0, D[7]) = [b, h(c,d), h(h(e,f),g)]; PATH(6, D[7]) = [h(e,f), h(h(a,b),h(c,d))].
  const p0 = log.inclusionProof(0, 7);
  assert.deepStrictEqual(
    p0.map((b) => b.toString('hex')),
    [L[1], hashNode(L[2], L[3]), hashNode(hashNode(L[4], L[5]), L[6])].map((b) => b.toString('hex'))
  );
  const p6 = log.inclusionProof(6, 7);
  assert.deepStrictEqual(
    p6.map((b) => b.toString('hex')),
    [hashNode(L[4], L[5]), hashNode(hashNode(L[0], L[1]), hashNode(L[2], L[3]))].map((b) => b.toString('hex'))
  );
  // §2.1.4.1 examples: PROOF(3, D[7]) = [c, d, h(a,b), h(h(e,f),g)]; PROOF(4, D[7]) = [h(h(e,f),g)]; PROOF(6, D[7]) = [h(e,f), g, h(h(a,b),h(c,d))].
  assert.deepStrictEqual(
    log.consistencyProof(3, 7).map((b) => b.toString('hex')),
    [L[2], L[3], hashNode(L[0], L[1]), hashNode(hashNode(L[4], L[5]), L[6])].map((b) => b.toString('hex'))
  );
  assert.deepStrictEqual(
    log.consistencyProof(4, 7).map((b) => b.toString('hex')),
    [hashNode(hashNode(L[4], L[5]), L[6])].map((b) => b.toString('hex'))
  );
  assert.deepStrictEqual(
    log.consistencyProof(6, 7).map((b) => b.toString('hex')),
    [hashNode(L[4], L[5]), L[6], hashNode(hashNode(L[0], L[1]), hashNode(L[2], L[3]))].map((b) => b.toString('hex'))
  );
});

test('every inclusion proof verifies, and only for its own leaf, index, size and root', () => {
  const log = new MerkleLog();
  const N = 70;
  const leaves = [];
  for (let i = 0; i < N; i++) {
    leaves.push(hashLeaf(leafInput(i)));
    log.append(leaves[i]);
  }
  for (let n = 1; n <= N; n++) {
    const root = log.rootAt(n);
    for (let m = 0; m < n; m++) {
      const path = log.inclusionProof(m, n);
      assert.ok(verifyInclusion({ leafHash: leaves[m], index: m, size: n, root, path }), `m=${m} n=${n}`);
      // Wrong leaf, wrong index, wrong root: refused.
      assert.ok(!verifyInclusion({ leafHash: leaves[(m + 1) % N], index: m, size: n, root, path }));
      if (n > 1) assert.ok(!verifyInclusion({ leafHash: leaves[m], index: (m + 1) % n, size: n, root, path }));
      assert.ok(!verifyInclusion({ leafHash: leaves[m], index: m, size: n, root: sha256('x'), path }));
    }
  }
});

test('every consistency proof verifies, and a forked history does not', () => {
  const log = new MerkleLog();
  const N = 70;
  for (let i = 0; i < N; i++) log.append(hashLeaf(leafInput(i)));
  for (let m = 0; m <= N; m++) {
    for (let n = m; n <= N; n++) {
      const proof = log.consistencyProof(m, n);
      assert.ok(
        verifyConsistency({ first: m, second: n, firstRoot: log.rootAt(m), secondRoot: log.rootAt(n), proof }),
        `m=${m} n=${n}`
      );
    }
  }
  // A fork: the same size-40 prefix, then a different leaf 40 — the honest
  // proof from 41 to 70 does not connect the forked root.
  const fork = new MerkleLog();
  for (let i = 0; i < 40; i++) fork.append(hashLeaf(leafInput(i)));
  fork.append(hashLeaf(Buffer.from('rewritten')));
  assert.ok(
    !verifyConsistency({
      first: 41,
      second: 70,
      firstRoot: fork.rootAt(41),
      secondRoot: log.rootAt(70),
      proof: log.consistencyProof(41, 70),
    })
  );
  // And a proof cannot be reused between sizes.
  assert.ok(
    !verifyConsistency({ first: 41, second: 69, firstRoot: log.rootAt(41), secondRoot: log.rootAt(69), proof: log.consistencyProof(41, 70) })
  );
});

test('the root is a pure function of the leaves, whatever was asked in between', () => {
  const a = new MerkleLog();
  const b = new MerkleLog();
  for (let i = 0; i < 33; i++) {
    const h = hashLeaf(crypto.randomBytes(16));
    a.append(h);
    b.append(h);
    if (i % 5 === 0) a.inclusionProof(0, i + 1); // warm a's memo along the way
    if (i % 7 === 0) a.consistencyProof(Math.floor(i / 2), i + 1);
  }
  assert.ok(a.root.equals(b.root));
  assert.ok(a.rootAt(17).equals(b.rootAt(17)));
});

test('the reference vectors of certificate-transparency-go (merkle/rfc6962): roots at every size, a path and a consistency proof', () => {
  // The Go implementation's test data: eight leaves, and the root after each
  // append. Matching all eight (and the empty root, SHA-256 of nothing) is the
  // check that this file hashes exactly as every CT log does.
  const leaves = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'];
  const roots = [
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
    'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
    'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
    '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
    'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
    '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
  ];
  const log = new MerkleLog();
  assert.equal(log.root.toString('hex'), roots[0]);
  leaves.forEach((h, i) => {
    log.append(hashLeaf(Buffer.from(h, 'hex')));
    assert.equal(log.rootAt(i + 1).toString('hex'), roots[i + 1], `root at size ${i + 1}`);
  });
  // PATH(0, D[8]) and PROOF(2, D[8]) from the same test data.
  assert.deepEqual(
    log.inclusionProof(0, 8).map((h) => h.toString('hex')),
    ['96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7', '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e', '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4']
  );
  assert.deepEqual(
    log.consistencyProof(2, 8).map((h) => h.toString('hex')),
    ['5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e', '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4']
  );
  assert.ok(verifyConsistency({ first: 2, second: 8, firstRoot: Buffer.from(roots[2], 'hex'), secondRoot: Buffer.from(roots[8], 'hex'), proof: log.consistencyProof(2, 8) }));
});
