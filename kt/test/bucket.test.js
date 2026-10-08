'use strict';

// Lookups by bucket (PROTOCOL §19.9, ADR 0023): a reader asks for every label
// that shares the first k bits of the one it wants, and is answered with all
// of them and the map siblings that fold their subtree to the head's
// mapRoot — so the log learns a bucket and not a label, and the reader can
// tell that nothing in the bucket was left out. The same query for both
// logs: the key-transparency log's leaves are (label, index, version), the
// handle log's carry the record, its time, its signature and its audit path
// as well, so a resolver needs no second request that would name the label.
//
// What is asserted below:
//   1. the map's bucket — its leaves, the subtree hash and the siblings —
//      is what a slow reference computes from the definition on random
//      sets, at every k from 0 to 24 and for prefixes inside and outside the
//      set, and the pure verifier accepts it and recomputes the same subtree;
//   2. over HTTP, buckets at k = 0, 1 and 8 from the key-transparency log
//      are complete and verify under the pinned key, a label absent from
//      the log is a verified absence, and a label omitted, a label added, a
//      leaf reordered, a version changed or a sibling dropped each make
//      verification fail;
//   3. the handle log's buckets carry each label's latest record, ts on a
//      whole hour, signature and audit path, all verified under the head —
//      and a changed record, a time finer than an hour or the other log's
//      context each fail;
//   4. `POST /kt/v1/buckets` answers several buckets under one head, and
//      every malformed query — k past 24, a prefix of the wrong length or
//      with its unused bits set, not hex, too many buckets — is refused;
//   5. a bucket over 4096 labels is refused `bucket_too_large` while one of
//      4096 is served, a POST's buckets are held to 4096 between them, and
//      the handle log's are held to a byte bound as well;
//   6. `/kt/v1/sth` carries `bucketBits`, max(0, ⌊log₂(labels / 32)⌋),
//      capped at the largest k a reader may ask for;
//   7. `POST /kt/v1/entries` serves entries by index, in the order asked,
//      each with an inclusion proof that verifies under the head served,
//      bounded in count and in bytes with `total` saying how many were
//      asked, and refuses an index past the head;
//   8. the budget that protects the mirrors' page protects it still, and the
//      routes a client's check depends on — the bucket query and entries by
//      index — are not charged to it and are answered while it is spent;
//   9. a read route's body is bounded, must be a JSON object, and is counted
//      apart from the publishes being read.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { verifyInclusion } = require('../lib/merkle.js');
const {
  DEPTH,
  EMPTY,
  mapLeafHash,
  mapNodeHash,
  SparseMerkleMap,
  prefixHex,
  parsePrefix,
  bucketRoot,
  verifyBucket,
} = require('../lib/smt.js');
const {
  KtLog,
  MemoryStore,
  FileStore,
  labelFor,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  leafHashOf,
  bucketBits,
  verifyBucketAnswer,
  sthFromJson,
  verifySth,
  entryFromJson,
  inclusionFromJson,
  MAX_BUCKET_LEAVES,
} = require('../lib/log.js');
const { rcOf, makeHandlePublish } = require('../lib/handles.js');
const { createServer, MAX_HISTORY_PAGE_BYTES, MAX_READ_BODY } = require('../server.js');

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const logKey = privateKeyFromSeed(sha('bucket test log'));
const handleLogKey = privateKeyFromSeed(sha('bucket test handle log'));
const bit = (l, d) => (l[d >> 3] >> (7 - (d & 7))) & 1;

function account(name) {
  const key = privateKeyFromSeed(sha(`acct:${name}`));
  const pub = rawPublicKey(key);
  return { key, pub, label: labelFor(pub) };
}

function ktPublish(a, v) {
  const value = sealValue(a.pub, Buffer.from(`list ${v}`), sha(`nonce:${v}`).subarray(0, 12));
  return makePublish(a.key, { version: v, fp: sha(`fp:${v}`).subarray(0, 16), value });
}

const OPEN = {
  publishPerMinute: 1e9,
  publishPerMinuteTotal: 1e9,
  publishPerAccountPerDay: 1e9,
  newAccountsPerMinute: 1e9,
};

async function serve(log, opts = {}) {
  const { httpServer } = createServer({ log, ...OPEN, ...opts });
  await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  const get = async (p) => {
    const r = await fetch(base + p);
    return { status: r.status, body: await r.json() };
  };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body) });
    return { status: r.status, body: await r.json() };
  };
  return {
    base,
    get,
    post,
    stop: async () => {
      httpServer.closeAllConnections();
      await new Promise((r) => httpServer.close(r));
    },
  };
}

/** A log of [names.length] accounts, a few of them republished. */
function ktLog(names) {
  let t = 1_800_000_000_000;
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now: () => (t += 1000) });
  const accts = names.map(account);
  for (const a of accts) log.publish(ktPublish(a, 1));
  for (const a of accts.slice(0, 5)) log.publish(ktPublish(a, 2));
  return { log, accts };
}

// --- 1 ------------------------------------------------------------------------

/**
 * The map by definition, as `smt.test.js`'s slow root computes it: recurse
 * on the label set at every depth, no chains, no compact nodes. The subtree
 * for a k-bit prefix is the same recursion over the labels that have it; a
 * sibling at depth d is the subtree over those that agree to depth d and
 * differ at d.
 */
function slowSubtree(entries, prefix, depth) {
  const rec = (d, set) => {
    if (set.length === 0) return EMPTY[d];
    if (d === DEPTH) return mapLeafHash(set[0].label, set[0].index, set[0].version);
    return mapNodeHash(rec(d + 1, set.filter((e) => bit(e.label, d) === 0)), rec(d + 1, set.filter((e) => bit(e.label, d) === 1)));
  };
  const agree = (e, n) => {
    for (let i = 0; i < n; i++) if (bit(e.label, i) !== bit(prefix, i)) return false;
    return true;
  };
  return rec(depth, entries.filter((e) => agree(e, depth)));
}

function slowBucket(entries, prefix, k) {
  const inside = entries.filter((e) => {
    for (let i = 0; i < k; i++) if (bit(e.label, i) !== bit(prefix, i)) return false;
    return true;
  });
  inside.sort((a, b) => Buffer.compare(a.label, b.label));
  const siblings = [];
  for (let d = k - 1; d >= 0; d--) {
    // The sibling at depth d: the prefix's first d bits, then the other bit.
    const other = Buffer.from(prefix);
    other[d >> 3] ^= 1 << (7 - (d & 7));
    siblings.push(slowSubtree(entries, other, d + 1));
  }
  return { leaves: inside, hash: slowSubtree(entries, prefix, k), siblings };
}

test('1. the map\'s bucket is the reference bucket at every k, and verifies', () => {
  const rnd = (seed) => sha(`random label ${seed}`);
  // Labels that share their first 24 bits, so that the deepest buckets a
  // reader may ask for still split, beside random ones.
  const close = (i) => Buffer.concat([Buffer.from('a5c3e1', 'hex'), sha(`close ${i}`).subarray(3)]);
  const sets = [[], [rnd(0)], [rnd(1), rnd(2)], [1, 2, 3, 4, 5].map((i) => rnd(`five ${i}`)), [0, 1, 2, 3, 4, 5].map(close).concat([rnd('x'), rnd('y')])];
  let checked = 0;
  for (const [s, labels] of sets.entries()) {
    const map = new SparseMerkleMap();
    const entries = labels.map((label, i) => ({ label, index: 10 * s + i, version: 1 + (i % 3) }));
    for (const e of entries) map.set(e.label, e.index, e.version);
    const probes = [...labels.slice(0, 2), rnd(`outside ${s}`)];
    if (labels.length === 0) probes.push(Buffer.alloc(32));
    for (const probe of probes) {
      for (let k = 0; k <= 24; k++) {
        const hex = prefixHex(probe, k);
        const prefix = parsePrefix(hex, k);
        assert.ok(prefix, `prefix ${hex} at ${k}`);
        const fast = map.bucket(prefix, k);
        const slow = slowBucket(entries, prefix, k);
        const what = `set ${s}, prefix ${JSON.stringify(hex)}, k ${k}`;
        assert.deepEqual(
          fast.leaves.map((l) => [l.label.toString('hex'), l.index, l.version]),
          slow.leaves.map((l) => [l.label.toString('hex'), l.index, l.version]),
          `${what}: leaves`
        );
        assert.ok(fast.hash.equals(slow.hash), `${what}: subtree hash`);
        assert.ok(bucketRoot(fast.leaves, k).equals(slow.hash), `${what}: recomputed from the leaves`);
        assert.equal(fast.siblings.length, k);
        fast.siblings.forEach((h, i) => assert.ok(h.equals(slow.siblings[i]), `${what}: sibling at depth ${k - 1 - i}`));
        assert.ok(verifyBucket({ root: map.root, prefix, bits: k, leaves: fast.leaves, siblings: fast.siblings }), `${what}: verifies`);
        if (fast.leaves.length > 0) {
          assert.ok(!verifyBucket({ root: map.root, prefix, bits: k, leaves: fast.leaves.slice(1), siblings: fast.siblings }), `${what}: one left out`);
        }
        checked++;
      }
    }
    // And the slow root is the map's root: depth 0 is the whole map.
    assert.ok(slowSubtree(entries, Buffer.alloc(32), 0).equals(map.root));
  }
  assert.equal(checked, 25 * 13, 'thirteen probes, every k');
  // The bound stops at one past it and never walks the rest.
  const big = new SparseMerkleMap();
  for (let i = 0; i < 40; i++) big.set(rnd(`big ${i}`), i, 1);
  assert.equal(big.bucket(Buffer.alloc(32), 0, 39), null);
  assert.equal(big.bucket(Buffer.alloc(32), 0, 40).leaves.length, 40);
});

// --- 2 ------------------------------------------------------------------------

/** What a client does: ask, verify, return the verified bucket. */
async function askOne(s, mode, pub, prefix, bits) {
  const r = await s.get(`/kt/v1/bucket?prefix=${prefix}&bits=${bits}`);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return { json: r.body, v: verifyBucketAnswer({ mode, logPub: pub, asked: [{ prefix, bits }], json: r.body }) };
}

function refuses(mode, pub, prefix, bits, json, what) {
  assert.throws(() => verifyBucketAnswer({ mode, logPub: pub, asked: [{ prefix, bits }], json }), Error, what);
}

test('2. key-transparency buckets at k = 0, 1 and 8 are complete, verify, and fail when anything is left out', async () => {
  const { log, accts } = ktLog(Array.from({ length: 40 }, (_, i) => `two-${i}`));
  const s = await serve(log);
  try {
    const target = accts[3].label;
    for (const k of [0, 1, 8]) {
      const prefix = prefixHex(target, k);
      const { json, v } = await askOne(s, 'kt', log.publicKey, prefix, k);
      const b = v.buckets[0];
      // Complete: every label in the log with this prefix, and nothing else.
      const want = accts.filter((a) => prefixHex(a.label, k) === prefix).map((a) => a.label.toString('hex')).sort();
      assert.deepEqual(b.leaves.map((l) => l.label.toString('hex')), want, `k ${k}`);
      // Each (index, version) is the map's: the latest entry.
      for (const l of b.leaves) {
        const latest = log.latest(l.label);
        assert.deepEqual([l.index, l.version], [latest.index, latest.version]);
      }
      // No values in this log's buckets.
      assert.equal(json.leaves[0].value, undefined);
      assert.deepEqual(Object.keys(json.leaves[0]), ['label', 'index', 'version']);
      assert.equal(json.siblings.length, k);
      assert.equal(json.prefix, prefix);
      assert.equal(json.bits, k);
      if (k === 0) assert.equal(b.leaves.length, 40);
      // Tampered, five ways — each must fail.
      const L = json.leaves;
      if (L.length > 1) {
        refuses('kt', log.publicKey, prefix, k, { ...json, leaves: L.filter((_, i) => i !== 1) }, `k ${k}: a label omitted`);
        refuses('kt', log.publicKey, prefix, k, { ...json, leaves: [L[1], L[0], ...L.slice(2)] }, `k ${k}: reordered`);
      }
      refuses('kt', log.publicKey, prefix, k, { ...json, leaves: L.slice(1) }, `k ${k}: the first omitted`);
      const forged = { label: Buffer.concat([parsePrefix(prefix, k).subarray(0, 1), sha('forged').subarray(1)]), index: 0, version: 1 };
      if (k <= 8) {
        const withForged = [...L, { label: forged.label.toString('base64'), index: 0, version: 1 }].sort((a, b) =>
          Buffer.compare(Buffer.from(a.label, 'base64'), Buffer.from(b.label, 'base64'))
        );
        refuses('kt', log.publicKey, prefix, k, { ...json, leaves: withForged }, `k ${k}: a label added`);
      }
      refuses('kt', log.publicKey, prefix, k, { ...json, leaves: [{ ...L[0], version: L[0].version + 1 }, ...L.slice(1)] }, `k ${k}: a version changed`);
      if (k > 0) refuses('kt', log.publicKey, prefix, k, { ...json, siblings: json.siblings.slice(1) }, `k ${k}: a sibling dropped`);
      // Another bucket's answer is not this one.
      if (k > 0) {
        const other = prefixHex(Buffer.from(parsePrefix(prefix, k).map((x, i) => (i === 0 ? x ^ 0x80 : x))), k);
        refuses('kt', log.publicKey, other, k, json, `k ${k}: answered for another prefix`);
      }
    }
    // A label the log does not hold, in a bucket the log answered: absent, provably.
    const absent = account('never published').label;
    const { v } = await askOne(s, 'kt', log.publicKey, prefixHex(absent, 8), 8);
    assert.ok(!v.buckets[0].leaves.some((l) => l.label.equals(absent)), 'a verified absence');
    // A head under another key is not this log's.
    const { json } = await askOne(s, 'kt', log.publicKey, '', 0);
    assert.throws(() => verifyBucketAnswer({ mode: 'kt', logPub: rawPublicKey(handleLogKey), asked: [{ prefix: '', bits: 0 }], json }), /not signed/);
  } finally {
    await s.stop();
  }
});

// --- 3 ------------------------------------------------------------------------

/** A handle log with [n] claims, two of them updated and one recovered. */
function handleLog(n, { now } = {}) {
  let t = 1_800_000_123_456;
  const log = new KtLog({ store: new MemoryStore(), signingKey: handleLogKey, mode: 'handles', now: now || (() => (t += 600_000)) });
  const owner = privateKeyFromSeed(sha('owner'));
  const recovery = privateKeyFromSeed(sha('recovery'));
  const rc = rcOf(rawPublicKey(recovery));
  const labels = Array.from({ length: n }, (_, i) => sha(`handle label ${i}`));
  const latest = new Map();
  const put = (p) => {
    log.publish(p);
    latest.set(p.label.toString('hex'), p.value);
  };
  for (const label of labels) put(makeHandlePublish({ label, version: 1, ownerKey: owner, k: 'claim', introSeed: sha(`intro ${label.toString('hex')}`), rc }));
  put(makeHandlePublish({ label: labels[0], version: 2, ownerKey: owner, k: 'update', intro: null, rc }));
  put(makeHandlePublish({ label: labels[1], version: 5, ownerKey: owner, k: 'update', pow: 24, rc }));
  const owner2 = privateKeyFromSeed(sha('owner 2'));
  put(makeHandlePublish({ label: labels[2], version: 2, ownerKey: owner2, k: 'recover', rc: rcOf(rawPublicKey(privateKeyFromSeed(sha('recovery 2')))), recoveryKey: recovery }));
  return { log, labels, latest };
}

test('3. handle-log buckets carry the latest record, its hour, its signature and its audit path, all verified', async () => {
  const { log, labels, latest } = handleLog(24);
  const s = await serve(log);
  try {
    for (const k of [0, 1, 8]) {
      const prefix = prefixHex(labels[2], k);
      const { json, v } = await askOne(s, 'handles', log.publicKey, prefix, k);
      assert.deepEqual(Object.keys(json.leaves[0]), ['label', 'index', 'version', 'value', 'ts', 'sig', 'audit']);
      for (const l of v.buckets[0].leaves) {
        const want = latest.get(l.label.toString('hex'));
        assert.ok(l.value.equals(want), `k ${k}: the latest record`);
        assert.equal(l.ts % 3_600_000, 0, 'a whole hour');
        assert.ok(l.sig.equals(log.entries[l.index].sig), 'the owner\'s signature, served');
      }
      if (k === 0) assert.equal(v.buckets[0].leaves.length, 24);
      // The recovered label's record is the recover.
      const mine = v.buckets[0].leaves.find((l) => l.label.equals(labels[2]));
      assert.equal(JSON.parse(mine.value.toString()).k, 'recover');
      // A record changed, a time finer than an hour, the other log's context.
      const L = json.leaves;
      const at = L.findIndex((l) => Buffer.from(l.label, 'base64').equals(labels[2]));
      const changed = JSON.parse(Buffer.from(L[at].value, 'base64').toString());
      changed.pow = 28;
      const swap = (leaf) => ({ ...json, leaves: L.map((l, i) => (i === at ? leaf : l)) });
      refuses('handles', log.publicKey, prefix, k, swap({ ...L[at], value: Buffer.from(JSON.stringify(changed)).toString('base64') }), `k ${k}: a changed record`);
      refuses('handles', log.publicKey, prefix, k, swap({ ...L[at], ts: L[at].ts + 1 }), `k ${k}: a ts finer than an hour`);
      refuses('handles', log.publicKey, prefix, k, swap({ ...L[at], audit: L[at].audit.slice(1) }), `k ${k}: an audit path cut short`);
      refuses('handles', log.publicKey, prefix, k, swap({ ...L[at], index: (L[at].index + 1) % log.size }), `k ${k}: another entry's index`);
      assert.throws(() => verifyBucketAnswer({ mode: 'kt', logPub: log.publicKey, asked: [{ prefix, bits: k }], json }), /not signed/, 'a handle head is no KT head');
    }
  } finally {
    await s.stop();
  }
});

// --- 4 ------------------------------------------------------------------------

test('4. POST /kt/v1/buckets answers several under one head; malformed queries are refused', async () => {
  const { log, accts } = ktLog(Array.from({ length: 30 }, (_, i) => `four-${i}`));
  const s = await serve(log);
  try {
    const asked = [
      { prefix: prefixHex(accts[0].label, 4), bits: 4 },
      { prefix: prefixHex(accts[1].label, 2), bits: 2 },
      { prefix: prefixHex(accts[2].label, 0), bits: 0 },
      { prefix: prefixHex(accts[0].label, 4), bits: 4 },
    ];
    const r = await s.post('/kt/v1/buckets', { buckets: asked });
    assert.equal(r.status, 200);
    const v = verifyBucketAnswer({ mode: 'kt', logPub: log.publicKey, asked, json: r.body });
    assert.equal(v.buckets.length, 4);
    assert.equal(v.buckets[2].leaves.length, 30);
    assert.equal(r.body.sth.bucketBits, 0);
    // Upper-case hex names the same bucket and is answered in lower case.
    const up = await s.get(`/kt/v1/bucket?prefix=${prefixHex(accts[5].label, 8).toUpperCase()}&bits=8`);
    assert.equal(up.status, 200);
    assert.equal(up.body.prefix, prefixHex(accts[5].label, 8));
    const bad = [
      ['/kt/v1/bucket?prefix=000000a&bits=25', 'k past 24'],
      ['/kt/v1/bucket?prefix=00&bits=4', 'two digits for four bits'],
      ['/kt/v1/bucket?prefix=0&bits=8', 'one digit for eight bits'],
      ['/kt/v1/bucket?prefix=1&bits=3', 'an unused bit set'],
      ['/kt/v1/bucket?prefix=c&bits=1', 'an unused bit set at k = 1'],
      ['/kt/v1/bucket?prefix=zz&bits=8', 'not hex'],
      ['/kt/v1/bucket?prefix=00', 'no bits'],
      ['/kt/v1/bucket?prefix=00&bits=-8', 'negative bits'],
      ['/kt/v1/bucket?prefix=00&bits=8.0', 'bits not an integer'],
      ['/kt/v1/bucket?bits=4', 'no prefix past k = 0'],
    ];
    for (const [p, what] of bad) {
      const x = await s.get(p);
      assert.equal(x.status, 400, what);
      assert.equal(x.body.error, 'bad_request', what);
    }
    assert.equal((await s.get('/kt/v1/bucket?bits=0')).status, 200, 'k = 0 needs no prefix');
    const badPosts = [
      [{ buckets: [] }, 'no buckets'],
      [{ buckets: Array.from({ length: 65 }, () => ({ prefix: '', bits: 0 })) }, '65 buckets'],
      [{ buckets: [{ prefix: '0', bits: '1' }] }, 'bits a string'],
      [{ buckets: [{ prefix: 0, bits: 0 }] }, 'prefix a number'],
      [{ buckets: [null] }, 'a null bucket'],
      [{ bucket: [{ prefix: '', bits: 0 }] }, 'no buckets member'],
    ];
    for (const [body, what] of badPosts) {
      const x = await s.post('/kt/v1/buckets', body);
      assert.equal(x.status, 400, what);
    }
    assert.equal((await s.post('/kt/v1/buckets', { buckets: Array.from({ length: 64 }, () => ({ prefix: '', bits: 0 })) })).status, 200, '64 is allowed');
  } finally {
    await s.stop();
  }
});

// --- 5 ------------------------------------------------------------------------

/** [n] correctly signed KT entries written as the log writes its lines, tiny values. */
function writeKtLines(file, n) {
  const lines = [];
  for (let i = 0; i < n; i++) {
    const a = account(`many-${i}`);
    const value = sealValue(a.pub, Buffer.alloc(0), Buffer.alloc(12));
    const fp = Buffer.alloc(16, 7);
    const p = makePublish(a.key, { version: 1, fp, value });
    lines.push(
      JSON.stringify({
        i,
        label: a.label.toString('base64'),
        v: 1,
        fp: fp.toString('base64'),
        vh: crypto.createHash('sha256').update(value).digest('base64'),
        val: value.toString('base64'),
        acct: a.pub.toString('base64'),
        ts: 1_800_000_000_000 + i,
        sig: p.sig.toString('base64'),
      })
    );
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
}

test('5. 4096 labels in a bucket are served, 4097 are bucket_too_large, and the handle log is held to bytes as well', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-bucket-'));
  const file = path.join(dir, 'entries.jsonl');
  writeKtLines(file, MAX_BUCKET_LEAVES);
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  const s = await serve(log);
  try {
    assert.equal(log.map.size, 4096);
    const full = await s.get('/kt/v1/bucket?prefix=&bits=0');
    assert.equal(full.status, 200);
    assert.equal(full.body.leaves.length, 4096, 'every label');
    const seen = new Set(full.body.leaves.map((l) => l.label));
    assert.equal(seen.size, 4096);
    // One more label, and the same bucket is past the bound.
    log.publish(ktPublish(account('the 4097th'), 1));
    const over = await s.get('/kt/v1/bucket?prefix=&bits=0');
    assert.equal(over.status, 400);
    assert.equal(over.body.error, 'bucket_too_large');
    // Its halves are served; asked for together they are the same 4097.
    const halves = [{ prefix: '0', bits: 1 }, { prefix: '8', bits: 1 }];
    for (const h of halves) assert.equal((await s.get(`/kt/v1/bucket?prefix=${h.prefix}&bits=1`)).status, 200);
    const both = await s.post('/kt/v1/buckets', { buckets: halves });
    assert.equal(both.status, 400);
    assert.equal(both.body.error, 'bucket_too_large');
    const one = await s.post('/kt/v1/buckets', { buckets: [halves[0], { prefix: '00', bits: 8 }] });
    assert.equal(one.status, 200);
  } finally {
    await s.stop();
    log.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }

  // The handle log: a leaf is a record and an audit path, so an answer is
  // held to the bound a label's history is held to, in bytes, as well.
  const { log: hlog } = handleLog(400);
  const h = await serve(hlog);
  try {
    const all = await h.get('/kt/v1/bucket?prefix=&bits=0');
    assert.equal(all.status, 400, 'four hundred records is more than one answer may carry');
    assert.equal(all.body.error, 'bucket_too_large');
    for (const p of ['0', '4', '8', 'c']) {
      const q = await h.get(`/kt/v1/bucket?prefix=${p}&bits=2`);
      assert.equal(q.status, 200);
      assert.ok(Buffer.byteLength(JSON.stringify(q.body)) <= MAX_HISTORY_PAGE_BYTES);
      verifyBucketAnswer({ mode: 'handles', logPub: hlog.publicKey, asked: [{ prefix: p, bits: 2 }], json: q.body });
    }
  } finally {
    await h.stop();
  }
});

// --- 6 ------------------------------------------------------------------------

test('6. /kt/v1/sth recommends bucketBits = max(0, ⌊log₂(labels / 32)⌋), at most 24', async () => {
  const cases = [[0, 0], [1, 0], [63, 0], [64, 1], [127, 1], [128, 2], [1000, 4], [22_094, 9], [1 << 20, 15], [2 ** 29, 24], [2 ** 30, 24], [2 ** 32 - 1, 24]];
  for (const [labels, k] of cases) {
    assert.equal(bucketBits(labels), k, `${labels} labels`);
    if (labels > 0 && labels < 2 ** 29) assert.equal(bucketBits(labels), Math.max(0, Math.floor(Math.log2(labels / 32))));
  }
  const { log, accts } = ktLog(Array.from({ length: 63 }, (_, i) => `six-${i}`));
  const s = await serve(log);
  try {
    let head = await s.get('/kt/v1/sth');
    assert.equal(head.body.bucketBits, 0);
    // The member is advisory, not signed: the head verifies without it.
    const { bucketBits: _b, ...signed } = head.body;
    assert.ok(verifySth(sthFromJson(signed), log.publicKey));
    // A republish adds no label; a sixty-fourth does.
    log.publish(ktPublish(accts[7], 3));
    assert.equal((await s.get('/kt/v1/sth')).body.bucketBits, 0);
    log.publish(ktPublish(account('the 64th'), 1));
    head = await s.get('/kt/v1/sth');
    assert.equal(head.body.bucketBits, 1);
    assert.equal((await s.get('/kt/v1/bucket?prefix=&bits=0')).body.sth.bucketBits, 1, 'and the same in a bucket answer');
  } finally {
    await s.stop();
  }
});

// --- 7 ------------------------------------------------------------------------

test('7. POST /kt/v1/entries serves entries by index with inclusion proofs, bounded, with total', async () => {
  const { log, accts } = ktLog(Array.from({ length: 12 }, (_, i) => `seven-${i}`));
  const s = await serve(log);
  try {
    const want = [9, 2, 14, 2, 0];
    const r = await s.post('/kt/v1/entries', { indexes: want });
    assert.equal(r.status, 200);
    assert.equal(r.body.total, 5);
    const sth = sthFromJson(r.body.sth);
    assert.ok(verifySth(sth, log.publicKey));
    assert.deepEqual(r.body.entries.map((x) => x.entry.index), want, 'in the order asked, a repeat served again');
    for (const x of r.body.entries) {
      const e = entryFromJson(x.entry);
      const inc = inclusionFromJson(x.inclusion);
      assert.equal(inc.size, sth.size);
      assert.ok(verifyInclusion({ leafHash: leafHashOf(e), index: inc.index, size: inc.size, root: sth.logRoot, path: inc.path }));
      assert.equal(x.entry.acct, undefined, 'acct is never served');
      assert.equal(x.entry.sig, undefined, 'nor sig, in this log');
    }
    // The value opens to what its account published.
    const twelve = r.body.entries[2].entry;
    assert.equal(twelve.index, 14);
    assert.ok(Buffer.from(twelve.label, 'base64').equals(accts[2].label));
    for (const [body, what] of [
      [{ indexes: [] }, 'none'],
      [{ indexes: [log.size] }, 'past the head'],
      [{ indexes: [-1] }, 'negative'],
      [{ indexes: [1.5] }, 'not an integer'],
      [{ indexes: ['1'] }, 'a string'],
      [{ indexes: Array.from({ length: 1001 }, () => 0) }, 'a thousand and one'],
      [{ index: [0] }, 'no indexes member'],
    ]) {
      const x = await s.post('/kt/v1/entries', body);
      assert.equal(x.status, 400, what);
    }
    assert.equal((await s.post('/kt/v1/entries', { indexes: Array.from({ length: 1000 }, (_, i) => i % log.size) })).status, 200, 'a thousand is allowed');
  } finally {
    await s.stop();
  }
  // Bounded in bytes, as a label's history is: large values, a short answer,
  // `total` saying how many were asked for.
  const big = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  for (let i = 0; i < 12; i++) {
    const a = account(`big-${i}`);
    big.publish(makePublish(a.key, { version: 1, fp: Buffer.alloc(16), value: sealValue(a.pub, crypto.randomBytes(30 * 1024)) }));
  }
  const b = await serve(big);
  try {
    const r = await b.post('/kt/v1/entries', { indexes: Array.from({ length: 12 }, (_, i) => 11 - i) });
    assert.equal(r.status, 200);
    assert.equal(r.body.total, 12);
    assert.ok(r.body.entries.length >= 1 && r.body.entries.length < 12, `${r.body.entries.length} of 12`);
    assert.deepEqual(r.body.entries.map((x) => x.entry.index), Array.from({ length: r.body.entries.length }, (_, i) => 11 - i));
    assert.ok(Buffer.byteLength(JSON.stringify(r.body)) <= MAX_HISTORY_PAGE_BYTES + 64 * 1024);
  } finally {
    await b.stop();
  }
});

// --- 8 ------------------------------------------------------------------------

test('8. the mirrors\' budget still binds their page, and never the bucket query or entries by index', async () => {
  const { log, accts } = ktLog(Array.from({ length: 20 }, (_, i) => `eight-${i}`));
  // A budget one page empties.
  const s = await serve(log, { readBytesPerMinute: 2000, readBytesPerMinuteTotal: 1e9 });
  try {
    // Entries by index and buckets, many times: none of it is charged.
    for (let i = 0; i < 20; i++) {
      assert.equal((await s.post('/kt/v1/entries', { indexes: [0, 1, 2, 3] })).status, 200);
      assert.equal((await s.get('/kt/v1/bucket?prefix=&bits=0')).status, 200);
      assert.equal((await s.post('/kt/v1/buckets', { buckets: [{ prefix: '', bits: 0 }] })).status, 200);
    }
    // So the mirrors' budget is whole: the first page is served...
    assert.equal((await s.get('/kt/v1/entries?start=0&count=20')).status, 200);
    // ...and spends it, and the next is refused until it refills.
    const refused = await s.get('/kt/v1/entries?start=0&count=20');
    assert.equal(refused.status, 429);
    // While it is spent, a client's check is answered.
    assert.equal((await s.get(`/kt/v1/bucket?prefix=${prefixHex(accts[0].label, 3)}&bits=3`)).status, 200);
    assert.equal((await s.post('/kt/v1/buckets', { buckets: [{ prefix: '', bits: 0 }, { prefix: '8', bits: 1 }] })).status, 200);
    assert.equal((await s.post('/kt/v1/entries', { indexes: [5] })).status, 200);
  } finally {
    await s.stop();
  }
});

// --- 9 ------------------------------------------------------------------------

/** A request whose headers say 1000 bytes of body and which sends one: held open, being read. */
function hold(base, p) {
  const net = require('net');
  return new Promise((resolve) => {
    const sock = net.connect(Number(new URL(base).port), '127.0.0.1', () => {
      sock.write(`POST ${p} HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n{`);
      resolve(sock);
    });
  });
}

/** Ask [p] until it answers 503 — the server has counted the held body — or give up after [tries]. */
async function untilBusy(s, p, body, what, tries = 100) {
  let r;
  for (let i = 0; i < tries; i++) {
    r = await s.post(p, body);
    if (r.status === 503) return r;
  }
  assert.fail(`${what}: never busy (last ${r.status})`);
}

test('9. a read route\'s body is bounded, must be a JSON object, and is counted apart from publishes', async () => {
  const { log } = ktLog(['nine-a', 'nine-b']);
  const s = await serve(log, { maxPublishInFlight: 1 });
  try {
    for (const p of ['/kt/v1/buckets', '/kt/v1/entries']) {
      assert.equal((await s.post(p, 'not json')).status, 400);
      assert.equal((await s.post(p, '[1,2]')).status, 400);
      assert.equal((await s.post(p, 'null')).status, 400);
      const huge = JSON.stringify({ indexes: [0], pad: 'x'.repeat(MAX_READ_BODY) });
      const r = await fetch(s.base + p, { method: 'POST', body: huge }).catch((e) => e);
      // Refused while it arrives: 413, or the socket closed under it.
      if (!(r instanceof Error)) assert.equal(r.status, 413);
    }
    // A publish body held open: publishing is busy, reading is not.
    const held = await hold(s.base, '/kt/v1/publish');
    await untilBusy(s, '/kt/v1/publish', { acct: 'x' }, 'the publish slot');
    assert.equal((await s.post('/kt/v1/buckets', { buckets: [{ prefix: '', bits: 0 }] })).status, 200, 'the read slot is free');
    held.destroy();
  } finally {
    await s.stop();
  }
  // And the reverse, on a server of its own so that the slot released above
  // cannot decide it.
  const t = await serve(ktLog(['nine-c']).log, { maxPublishInFlight: 1 });
  try {
    const held = await hold(t.base, '/kt/v1/entries');
    await untilBusy(t, '/kt/v1/entries', { indexes: [0] }, 'the read slot');
    const pub = await t.post('/kt/v1/publish', { acct: 'x' });
    assert.equal(pub.status, 400, 'a publish is read — and refused for what it says — not busy');
    held.destroy();
  } finally {
    await t.stop();
  }
});
