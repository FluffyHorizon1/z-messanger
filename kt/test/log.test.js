'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { verifyInclusion, verifyConsistency, sha256 } = require('../lib/merkle.js');
const { verifyMapProof } = require('../lib/smt.js');
const {
  KtLog,
  PublishError,
  MemoryStore,
  FileStore,
  labelFor,
  leafHashOf,
  sthInput,
  verifySth,
  sealValue,
  openValue,
  valueKey,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  verify,
  entryToJson,
  entryFromJson,
  sthToJson,
  sthFromJson,
  mapProofToJson,
  mapProofFromJson,
  inclusionToJson,
  inclusionFromJson,
  MAX_VALUE_BYTES,
} = require('../lib/log.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('log seed').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

function fpOf(name, v) {
  return crypto.createHash('sha256').update(`fp:${name}:${v}`).digest().subarray(0, 16);
}

/** A publish for `acct` at version v, sealed from a stand-in list. */
function publishFor(acct, v, listText = `{"acct":"${acct.pub.toString('base64')}","ver":${v}}`) {
  const value = sealValue(acct.pub, Buffer.from(listText, 'utf8'));
  return makePublish(acct.key, { version: v, fp: fpOf(acct.pub.toString('hex'), v), value });
}

function fresh(opts = {}) {
  let t = 1_700_000_000_000;
  const now = () => t;
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, now, ...opts });
  return { log, tick: (ms) => (t += ms) };
}

test('the value: sealed for an account, opened with its public key, closed to everyone else', () => {
  const a = account('alice');
  const list = Buffer.from('{"devs":[]}', 'utf8');
  const value = sealValue(a.pub, list);
  assert.equal(value.length, 12 + list.length + 16);
  assert.ok(openValue(a.pub, value).equals(list));
  // Another account's key opens nothing; the label is bound as AAD.
  assert.equal(openValue(account('bob').pub, value), null);
  const tampered = Buffer.from(value);
  tampered[12] ^= 1;
  assert.equal(openValue(a.pub, tampered), null);
  assert.equal(openValue(a.pub, value.subarray(0, 20)), null);
  // The key is derived from the public key alone — a contact can derive it.
  assert.ok(valueKey(a.pub).equals(valueKey(Buffer.from(a.pub))));
  assert.ok(!valueKey(a.pub).equals(valueKey(account('bob').pub)));
  // Two seals of one list differ (fresh nonce), both open.
  assert.ok(!sealValue(a.pub, list).equals(value));
});

test('publish: signed by the account key, versions strictly increasing per label, first version free', () => {
  const { log } = fresh();
  const a = account('alice');
  const b = account('bob');
  assert.equal(log.size, 0);
  const e0 = log.publish(publishFor(a, 7)); // reached v7 before the log existed
  assert.equal(e0.index, 0);
  assert.equal(log.size, 1);
  assert.deepEqual(log.latest(a.label).version, 7);
  // Same version again, and a lower one: refused with 409.
  assert.throws(() => log.publish(publishFor(a, 7)), (e) => e instanceof PublishError && e.status === 409 && e.code === 'stale_version');
  assert.throws(() => log.publish(publishFor(a, 3)), (e) => e.status === 409);
  assert.equal(log.size, 1);
  log.publish(publishFor(a, 8));
  log.publish(publishFor(b, 1));
  assert.equal(log.size, 3);
  assert.equal(log.map.size, 2);
  // A publish whose signature was made by another key.
  const forged = publishFor(a, 9);
  forged.sig = makePublish(b.key, { version: 9, fp: forged.fp, value: forged.value }).sig;
  assert.throws(() => log.publish(forged), (e) => e.status === 403 && e.code === 'bad_signature');
  // A publish whose fp was changed after signing.
  const edited = publishFor(a, 9);
  edited.fp = Buffer.from(edited.fp);
  edited.fp[0] ^= 1;
  assert.throws(() => log.publish(edited), (e) => e.status === 403);
  // A publish whose value was changed after signing.
  const swapped = publishFor(a, 9);
  swapped.value = Buffer.from(swapped.value);
  swapped.value[swapped.value.length - 1] ^= 1;
  assert.throws(() => log.publish(swapped), (e) => e.status === 403);
  // Shapes.
  assert.throws(() => log.publish({ ...publishFor(a, 9), acct: Buffer.alloc(31) }), (e) => e.status === 400);
  assert.throws(() => log.publish({ ...publishFor(a, 9), fp: Buffer.alloc(15) }), (e) => e.status === 400);
  assert.throws(() => log.publish({ ...publishFor(a, 9), version: 0 }), (e) => e.status === 400);
  assert.throws(() => log.publish({ ...publishFor(a, 9), version: 1.5 }), (e) => e.status === 400);
  assert.throws(() => log.publish({ ...publishFor(a, 9), value: Buffer.alloc(27) }), (e) => e.status === 400);
  assert.throws(() => log.publish({ ...publishFor(a, 9), sig: Buffer.alloc(63) }), (e) => e.status === 400);
  const big = makePublish(a.key, { version: 9, fp: fpOf('x', 9), value: crypto.randomBytes(MAX_VALUE_BYTES + 1) });
  assert.throws(() => log.publish(big), (e) => e.status === 413 && e.code === 'too_large');
  assert.equal(log.size, 3, 'nothing refused was appended');
});

test('the head: signed by the log key, re-signed on growth and on age, not otherwise', () => {
  const { log, tick } = fresh({ resignMs: 60_000 });
  const a = account('alice');
  const s0 = log.sth();
  assert.equal(s0.size, 0);
  assert.ok(verifySth(s0, log.publicKey));
  assert.ok(!verifySth(s0, rawPublicKey(account('mallory').key)), 'another key does not verify it');
  const wrong = { ...s0, size: 1 };
  assert.ok(!verifySth(wrong, log.publicKey), 'a changed field breaks the signature');
  assert.equal(log.sth(), s0, 'unchanged log, fresh head: the same object');
  tick(30_000);
  assert.equal(log.sth(), s0);
  tick(31_000);
  const s1 = log.sth();
  assert.notEqual(s1, s0);
  assert.equal(s1.size, 0);
  assert.ok(s1.logRoot.equals(s0.logRoot) && s1.mapRoot.equals(s0.mapRoot));
  assert.ok(s1.ts > s0.ts);
  assert.ok(verifySth(s1, log.publicKey));
  log.publish(publishFor(a, 1));
  const s2 = log.sth();
  assert.equal(s2.size, 1);
  assert.ok(!s2.logRoot.equals(s1.logRoot));
  assert.ok(!s2.mapRoot.equals(s1.mapRoot));
  // The signed bytes are exactly the documented input.
  assert.ok(verify(log.publicKey, sthInput(s2), s2.sig));
});

test('lookup: map proof and inclusion proof verify against the returned head; absence for an unknown label', () => {
  const { log } = fresh();
  const accts = [];
  for (let i = 0; i < 30; i++) {
    const acct = account(`acct-${i}`);
    accts.push(acct);
    log.publish(publishFor(acct, 1));
  }
  // Alice publishes twice more; her latest must be the last.
  const alice = accts[3];
  log.publish(publishFor(alice, 2));
  log.publish(publishFor(alice, 5));
  const r = log.lookup(alice.label);
  assert.ok(verifySth(r.sth, log.publicKey));
  assert.equal(r.sth.size, 32);
  assert.deepEqual(r.map.leaf, { index: 31, version: 5 });
  assert.ok(verifyMapProof({ root: r.sth.mapRoot, label: alice.label, ...r.map }));
  assert.equal(r.entry.version, 5);
  assert.ok(r.entry.label.equals(alice.label));
  assert.ok(r.entry.fp.equals(fpOf(alice.pub.toString('hex'), 5)));
  assert.equal(r.entry.acct.length, 32, 'the log keeps acct');
  assert.ok(verifyInclusion({ leafHash: leafHashOf(r.entry), index: r.inclusion.index, size: r.inclusion.size, root: r.sth.logRoot, path: r.inclusion.path }));
  assert.equal(r.inclusion.size, r.sth.size, 'proved at the head served');
  // The public JSON form never carries acct, and round-trips.
  const j = entryToJson(r.entry);
  assert.equal(j.acct, undefined);
  const back = entryFromJson(JSON.parse(JSON.stringify(j)));
  assert.ok(leafHashOf(back).equals(leafHashOf(r.entry)));
  assert.ok(verifyMapProof({ root: r.sth.mapRoot, label: alice.label, ...mapProofFromJson(JSON.parse(JSON.stringify(mapProofToJson(r.map)))) }));
  const inc = inclusionFromJson(JSON.parse(JSON.stringify(inclusionToJson(r.inclusion))));
  assert.ok(verifyInclusion({ leafHash: leafHashOf(back), index: inc.index, size: inc.size, root: r.sth.logRoot, path: inc.path }));
  const sth = sthFromJson(JSON.parse(JSON.stringify(sthToJson(r.sth))));
  assert.ok(verifySth(sth, log.publicKey));
  // The contact opens the value with Alice's public key.
  assert.equal(openValue(alice.pub, r.entry.value).toString('utf8'), `{"acct":"${alice.pub.toString('base64')}","ver":5}`);
  // A label nobody published.
  const nobody = account('nobody');
  const abs = log.lookup(nobody.label);
  assert.equal(abs.map.leaf, null);
  assert.equal(abs.entry, null);
  assert.equal(abs.inclusion, null);
  assert.ok(verifyMapProof({ root: abs.sth.mapRoot, label: nobody.label, ...abs.map }));
  // The old entry (v2) is in the log but not in the map: a lookup can never return it as latest.
  assert.ok(!verifyMapProof({ root: r.sth.mapRoot, label: alice.label, leaf: { index: 30, version: 2 }, bitmap: r.map.bitmap, siblings: r.map.siblings }));
});

test('history: every version for a label, each included under the same head', () => {
  const { log } = fresh();
  const a = account('alice');
  const b = account('bob');
  log.publish(publishFor(a, 1));
  log.publish(publishFor(b, 1));
  log.publish(publishFor(a, 2));
  log.publish(publishFor(b, 4));
  log.publish(publishFor(a, 3));
  const h = log.history(a.label);
  assert.deepEqual(h.entries.map((x) => x.entry.version), [1, 2, 3]);
  assert.deepEqual(h.entries.map((x) => x.entry.index), [0, 2, 4]);
  for (const x of h.entries) {
    assert.ok(verifyInclusion({ leafHash: leafHashOf(x.entry), index: x.inclusion.index, size: h.sth.size, root: h.sth.logRoot, path: x.inclusion.path }));
  }
  assert.deepEqual(log.history(account('nobody').label).entries, []);
  const page = log.range(1, 3);
  assert.deepEqual(page.entries.map((e) => e.index), [1, 2, 3]);
  assert.deepEqual(log.range(4, 10).entries.map((e) => e.index), [4]);
  assert.deepEqual(log.range(5, 10).entries, []);
  assert.throws(() => log.range(-1, 1), (e) => e.status === 400);
  assert.throws(() => log.range(0, 0), (e) => e.status === 400);
});

test('consistency: a later head extends an earlier one; a forked log does not', () => {
  const { log } = fresh();
  const a = account('alice');
  const heads = [log.sth()];
  const publishes = [];
  for (let v = 1; v <= 9; v++) {
    publishes.push(publishFor(a, v));
    log.publish(publishes[v - 1]);
    heads.push(log.sth());
  }
  for (let i = 0; i <= 9; i++) {
    for (let j = i; j <= 9; j++) {
      const proof = log.consistency(i, j);
      assert.ok(verifyConsistency({ first: i, second: j, firstRoot: heads[i].logRoot, secondRoot: heads[j].logRoot, proof }), `${i}→${j}`);
    }
  }
  assert.throws(() => log.consistency(5, 3), (e) => e.status === 400);
  assert.throws(() => log.consistency(0, 10), (e) => e.status === 400);
  // A second log, same key, same first five entries, then a different sixth:
  // its head at 6 does not extend this log's head at 6, and this log's proof
  // from 5 to 6 does not carry a client from our head at 5 to the fork's.
  const fork = fresh().log; // the same clock start, the same publishes: the same leaves
  for (let v = 1; v <= 5; v++) fork.publish(publishes[v - 1]);
  assert.ok(fork.sth().logRoot.equals(heads[5].logRoot), 'identical prefix, identical root');
  fork.publish(publishFor(a, 60)); // a different entry at index 5
  const forkHead = fork.sth();
  assert.ok(verifySth(forkHead, log.publicKey), 'the fork is signed by the same key — signatures alone catch nothing');
  assert.ok(!verifyConsistency({ first: 5, second: 6, firstRoot: heads[5].logRoot, secondRoot: forkHead.logRoot, proof: log.consistency(5, 6) }));
  assert.ok(!verifyConsistency({ first: 5, second: 6, firstRoot: heads[5].logRoot, secondRoot: heads[6].logRoot, proof: fork.consistency(5, 6) }));
  assert.ok(!verifyConsistency({ first: 6, second: 9, firstRoot: forkHead.logRoot, secondRoot: heads[9].logRoot, proof: log.consistency(6, 9) }));
});

test('the file store: replayed on start to the same heads; a torn or shortened file refuses to start', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-'));
  const file = path.join(dir, 'entries.jsonl');
  let t = 1_700_000_000_000;
  const now = () => t;
  const a = account('alice');
  const b = account('bob');
  const first = new KtLog({ store: new FileStore(file), signingKey: logKey, now });
  first.publish(publishFor(a, 1));
  t += 1000;
  first.publish(publishFor(b, 3));
  t += 1000;
  first.publish(publishFor(a, 2));
  const head = first.sth();
  first.close();
  const text = fs.readFileSync(file, 'utf8');
  assert.equal(text.split('\n').length, 4, 'three lines and a trailing newline');
  // The store holds acct (needed to validate a replay) — it is the log's private file.
  assert.ok(JSON.parse(text.split('\n')[0]).acct);

  const again = new KtLog({ store: new FileStore(file), signingKey: logKey, now });
  assert.equal(again.size, 3);
  const h2 = again.sth();
  assert.ok(h2.logRoot.equals(head.logRoot) && h2.mapRoot.equals(head.mapRoot));
  assert.equal(again.latest(a.label).version, 2);
  assert.equal(again.latest(b.label).version, 3);
  // It carries on from where the file ends.
  again.publish(publishFor(b, 4));
  again.close();
  assert.equal(new KtLog({ store: new FileStore(file), signingKey: logKey, now }).size, 4);

  // A torn last line.
  fs.writeFileSync(file, text + '{"i":3,"label":"ab');
  assert.throws(() => new KtLog({ store: new FileStore(file), signingKey: logKey, now }), /torn write/);
  // A line edited after the fact: the value no longer matches its hash.
  const lines = text.split('\n');
  const j = JSON.parse(lines[1]);
  j.val = Buffer.from(crypto.randomBytes(40)).toString('base64');
  fs.writeFileSync(file, [lines[0], JSON.stringify(j), lines[2], ''].join('\n'));
  assert.throws(() => new KtLog({ store: new FileStore(file), signingKey: logKey, now }), /value hash/);
  // A line removed: indices no longer sequential.
  fs.writeFileSync(file, [lines[0], lines[2], ''].join('\n'));
  assert.throws(() => new KtLog({ store: new FileStore(file), signingKey: logKey, now }), /where 1 was expected/);
  // A version that went backwards.
  const k = JSON.parse(lines[2]);
  k.v = 1;
  fs.writeFileSync(file, [lines[0], lines[1], JSON.stringify(k), ''].join('\n'));
  assert.throws(() => new KtLog({ store: new FileStore(file), signingKey: logKey, now }), /does not exceed/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the leaf commits to everything a reader relies on', () => {
  const { log, tick } = fresh();
  const a = account('alice');
  const e = log.publish(publishFor(a, 1));
  const h = leafHashOf(e);
  assert.ok(!leafHashOf({ ...e, version: 2 }).equals(h));
  assert.ok(!leafHashOf({ ...e, fp: Buffer.alloc(16) }).equals(h));
  assert.ok(!leafHashOf({ ...e, valueHash: sha256(Buffer.from('x')) }).equals(h));
  assert.ok(!leafHashOf({ ...e, ts: e.ts + 1 }).equals(h));
  assert.ok(!leafHashOf({ ...e, label: account('bob').label }).equals(h));
  // ts is the log's clock at acceptance.
  tick(5000);
  const e2 = log.publish(publishFor(a, 2));
  assert.equal(e2.ts - e.ts, 5000);
});
