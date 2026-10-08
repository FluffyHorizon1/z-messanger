'use strict';
// The freeze: docs/vectors/kt/*.json must be exactly what tools/gen_vectors.js
// produces from this code, and the cases they mark must_refuse must be
// refused by the verifiers here. A diff means the construction changed, and
// PROTOCOL.md §19 says what that costs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { generate, OUT } = require('../tools/gen_vectors.js');
const { verifyInclusion, verifyConsistency, hashLeaf } = require('../lib/merkle.js');
const { verifyMapProof } = require('../lib/smt.js');
const { verifySth, sthFromJson, mapProofFromJson, entryFromJson, inclusionFromJson, leafHashOf, labelFor, openValue, verifyBucketAnswer, KtLog, MemoryStore, privateKeyFromSeed } = require('../lib/log.js');
const handles = require('../lib/handles.js');

const hexb = (h) => Buffer.from(h, 'hex');

test('the committed vectors are reproduced exactly', () => {
  const files = generate();
  for (const [name, obj] of Object.entries(files)) {
    const onDisk = fs.readFileSync(path.join(OUT, name), 'utf8');
    assert.equal(onDisk, JSON.stringify(obj, null, 1) + '\n', `${name} differs from what the code produces — if the change is intended, regenerate with node tools/gen_vectors.js and say so in PROTOCOL.md §19`);
  }
});

test('log_tree.json: every proof verifies against its root and against no other', () => {
  const v = JSON.parse(fs.readFileSync(path.join(OUT, 'log_tree.json'), 'utf8'));
  const roots = v.roots_by_size.map(hexb);
  const leafHashes = v.leaf_hashes.map(hexb);
  v.leaf_inputs.forEach((l, i) => assert.ok(hashLeaf(hexb(l)).equals(leafHashes[i])));
  for (const p of v.inclusion) {
    const path = p.path.map(hexb);
    assert.ok(verifyInclusion({ leafHash: leafHashes[p.index], index: p.index, size: p.size, root: roots[p.size], path }));
    if (p.size > 1) {
      assert.ok(!verifyInclusion({ leafHash: leafHashes[p.index], index: p.index, size: p.size, root: roots[p.size - 1], path }));
      assert.ok(!verifyInclusion({ leafHash: leafHashes[(p.index + 1) % p.size], index: p.index, size: p.size, root: roots[p.size], path }));
    }
  }
  for (const c of v.consistency) {
    const proof = c.proof.map(hexb);
    assert.ok(verifyConsistency({ first: c.first, second: c.second, firstRoot: roots[c.first], secondRoot: roots[c.second], proof }));
    if (c.first > 0 && c.first < c.second) {
      assert.ok(!verifyConsistency({ first: c.first, second: c.second, firstRoot: roots[c.first - 1], secondRoot: roots[c.second], proof }));
    }
  }
});

test('map_tree.json: the proofs verify under the final root and must_refuse does not', () => {
  const v = JSON.parse(fs.readFileSync(path.join(OUT, 'map_tree.json'), 'utf8'));
  const root = hexb(v.final_root);
  const toProof = (p) => ({ label: hexb(p.label), leaf: p.leaf, bitmap: hexb(p.bitmap), siblings: p.siblings.map(hexb) });
  let present = 0;
  for (const p of v.proofs) {
    assert.ok(verifyMapProof({ root, ...toProof(p) }), p.label);
    if (p.leaf) present++;
  }
  assert.equal(present, 12);
  assert.equal(v.proofs.length, 14);
  for (const p of v.must_refuse) assert.ok(!verifyMapProof({ root, ...toProof(p) }), p.why);
});

test('kt_log.json: heads, lookups, history, the witness, and must_refuse', () => {
  const v = JSON.parse(fs.readFileSync(path.join(OUT, 'kt_log.json'), 'utf8'));
  const logPub = hexb(v.log.pub);
  for (const h of v.heads_by_size) assert.ok(verifySth(sthFromJson(h), logPub));
  assert.ok(verifySth(sthFromJson(v.resigned_head.head), logPub));
  const heads = v.heads_by_size.map(sthFromJson);
  for (const c of v.consistency) {
    assert.ok(verifyConsistency({ first: c.first, second: c.second, firstRoot: heads[c.first].logRoot, secondRoot: heads[c.second].logRoot, proof: c.proof.map((h) => Buffer.from(h, 'base64')) }));
  }
  for (const [name, l] of Object.entries(v.lookups)) {
    const r = JSON.parse(l.response_json);
    const sth = sthFromJson(r.sth);
    assert.ok(verifySth(sth, logPub));
    const label = name === 'nobody' ? hexb(l.label) : hexb(v.accounts[name].label);
    const map = mapProofFromJson(r.map);
    assert.ok(verifyMapProof({ root: sth.mapRoot, label, ...map }));
    if (l.expect.absent) {
      assert.equal(map.leaf, null);
      continue;
    }
    assert.deepEqual(map.leaf, { index: l.expect.index, version: l.expect.version });
    const entry = entryFromJson(r.entry);
    const inc = inclusionFromJson(r.inclusion);
    assert.ok(verifyInclusion({ leafHash: leafHashOf(entry), index: inc.index, size: inc.size, root: sth.logRoot, path: inc.path }));
    // The value opens with the account's public key, to the list in the vector.
    const pub = hexb(v.accounts[name].account_ed_pub);
    assert.ok(labelFor(pub).equals(label));
    const pub_ = v.publishes.filter((p) => p.account === name).pop();
    assert.equal(openValue(pub, entry.value).toString('utf8'), pub_.plaintext_json);
  }
  const h = JSON.parse(v.history_alice.response_json);
  assert.deepEqual(h.entries.map((x) => x.entry.v), v.history_alice.expect_versions);
  const w = JSON.parse(v.witness.record_json);
  assert.ok(verifySth(sthFromJson(w.sth), logPub));
  for (const m of v.must_refuse) {
    if (m.head_json && !m.client_holds) assert.ok(!verifySth(sthFromJson(JSON.parse(m.head_json)), logPub), m.why);
    if (m.response_json) {
      const r = JSON.parse(m.response_json);
      assert.ok(!verifyMapProof({ root: sthFromJson(r.sth).mapRoot, label: hexb(v.accounts.alice.label), ...mapProofFromJson(r.map) }), m.why);
    }
    if (m.client_holds) {
      const held = sthFromJson(m.client_holds);
      const forkHead = sthFromJson(JSON.parse(m.head_json));
      assert.ok(verifySth(forkHead, logPub), 'the fork is signed by the real key');
      if (forkHead.size === held.size) {
        assert.ok(!forkHead.logRoot.equals(held.logRoot) && !forkHead.mapRoot.equals(held.mapRoot), m.why);
      } else {
        assert.ok(!verifyConsistency({ first: held.size, second: forkHead.size, firstRoot: held.logRoot, secondRoot: forkHead.logRoot, proof: m.consistency_from_fork.map((x) => Buffer.from(x, 'base64')) }), m.why);
      }
    }
  }
});

test('bucket.json: every answer verifies, every must_refuse fails, and the handle log\'s publishes and refusals reproduce', () => {
  const v = JSON.parse(fs.readFileSync(path.join(OUT, 'bucket.json'), 'utf8'));
  for (const [mode, part] of [['kt', v.kt], ['handles', v.handles]]) {
    const logPub = hexb(part.log.pub);
    for (const b of part.buckets) {
      const r = verifyBucketAnswer({ mode, logPub, asked: [b.asked], json: JSON.parse(b.response_json) });
      assert.deepEqual(r.buckets[0].leaves.map((l) => l.label.toString('hex')), b.expect_labels);
    }
    for (const m of part.must_refuse) {
      assert.throws(() => verifyBucketAnswer({ mode, logPub, asked: m.asked, json: JSON.parse(m.response_json) }), Error, m.why);
    }
  }
  const ktPub = hexb(v.kt.log.pub);
  const empty = verifyBucketAnswer({ mode: 'kt', logPub: ktPub, asked: [v.kt.empty_bucket.asked], json: JSON.parse(v.kt.empty_bucket.response_json) });
  assert.equal(empty.buckets[0].leaves.length, 0, 'a verified empty bucket: absence for every label in it');
  const post = JSON.parse(v.kt.post_buckets.request_json).buckets;
  assert.equal(verifyBucketAnswer({ mode: 'kt', logPub: ktPub, asked: post, json: JSON.parse(v.kt.post_buckets.response_json) }).buckets.length, 3);
  const byIndex = JSON.parse(v.kt.entries_by_index.response_json);
  const sth = sthFromJson(byIndex.sth);
  assert.ok(verifySth(sth, ktPub));
  assert.deepEqual(byIndex.entries.map((x) => x.entry.index), JSON.parse(v.kt.entries_by_index.request_json).indexes);
  for (const x of byIndex.entries) {
    const inc = inclusionFromJson(x.inclusion);
    assert.ok(verifyInclusion({ leafHash: leafHashOf(entryFromJson(x.entry)), index: inc.index, size: inc.size, root: sth.logRoot, path: inc.path }));
  }
  // The handle log's publishes, replayed into a log of the same key and
  // clock, give the same entries and the same head; and every refusal is
  // refused with the status and code recorded.
  let t = v.handles.publishes[0].accepted_ms;
  const h = new KtLog({ store: new MemoryStore(), signingKey: privateKeyFromSeed(hexb(v.handles.log.seed)), mode: 'handles', now: () => t });
  const body = (j) => ({ label: Buffer.from(j.label, 'base64'), version: j.v, value: Buffer.from(j.value, 'base64'), sig: Buffer.from(j.sig, 'base64') });
  for (const p of v.handles.publishes) {
    t = p.accepted_ms;
    const e = h.publish(body(JSON.parse(p.request_json)));
    assert.equal(h.withValue(e).value.toString('utf8'), p.record_json);
    assert.deepEqual(h.entryJson(h.withValue(e)), p.entry.json);
    assert.equal(handles.parseRecord(Buffer.from(p.record_json)).k, p.k);
  }
  assert.ok(h.tree.root.equals(Buffer.from(v.handles.head.logRoot, 'base64')));
  assert.ok(h.map.root.equals(Buffer.from(v.handles.head.mapRoot, 'base64')));
  for (const r of v.handles.owner_rule_refusals) {
    assert.throws(() => h.publish(body(JSON.parse(r.request_json))), (e) => e.status === r.http && e.code === r.code, r.why);
  }
});
