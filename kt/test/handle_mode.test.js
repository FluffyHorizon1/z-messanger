'use strict';

// The handle log: `kt/` with KT_MODE=handles (PROTOCOL §21.5, ADR 0015
// revision 2). A label is Argon2id of a handle, computed by the client; the
// value is the handle's record, served in the clear; and a label belongs to
// whoever claimed it — which is the rule the key-transparency log has no need
// of, because there a label is the hash of the key that signs for it, and
// here it is the hash of a name anyone can type. Without the rule, anyone
// could publish version 2 of somebody else's handle under their own key
// (finding F1 of the 2026-10-03 analysis), and a mirror that checks only
// version order would not object.
//
// What is asserted below:
//   1. every case of the owner rule, on the wire: a claim is accepted and a
//      claim on a held label is `taken`; an update by the owner is accepted,
//      and one that names another owner, is signed by another key, changes
//      the recovery commitment, comes before any claim, or is not the label's
//      next version — the same or a lower one, one that skips, one at
//      2^53 − 1, the theft that left a recovery no version to recover at —
//      is refused, as is a claim at any version but 1; a recover with the
//      committed recovery key is accepted at the next version after a theft
//      and moves the label to its new owner — after which the old owner, the
//      spent recovery key, a wrong one, a bad `rsig` and a recover signed by
//      anyone but the new owner are refused; and a record over 1 KiB, in any
//      encoding but its one canonical form — an introduction key without its
//      X25519 key, or the reverse, among them (SPEC amendment 1) — or naming
//      a key of small order that any signature verifies under, is refused;
//   2. the same rule on the way back from the log's own file: a line
//      appended by anything but the log — each of those refusals written in
//      as an entry, a version that skips one or lies past 2^53 − 1 (bounded
//      on replay exactly as on the wire), a time finer than an hour, an
//      unsigned line, a key-transparency log's line — refuses the start,
//      naming why, and the file without it opens;
//   3. timestamps are hour-granular: an entry's ts is the hour it was
//      accepted in, whatever the clock said within it — and a head's is when
//      it was signed, as the log grew;
//   4. contexts: a handle head never verifies as a key-transparency head nor
//      the reverse — under the same key — and the leaf and the witness's
//      co-signature are the handle log's own;
//   5. the handle log serves what it stores — the record in the clear and
//      the owner's signature, nothing else — and the key-transparency log,
//      KT_MODE unset, serves exactly what it did;
//   6. the owner rule's state costs memory per LABEL, not per entry: one
//      64-byte slot a label in a table of 1024-label chunks, nothing on an
//      entry, an entry's own fields in one allocation, and a replay retaining
//      a few kilobytes an entry as the key-transparency log's does;
//   7. KT_MODE: unset is the key-transparency log, `handles` the handle log,
//      anything else refuses to start; and neither log opens the other's
//      file;
//   8. a mirror of the handle log follows it under the handle contexts and
//      co-signs as its witness — and a log that accepted a foreign update is
//      caught, whether the record names the stranger or the stranger signed
//      a record naming the owner, and so is one that accepted the owner's
//      update at a version that is not the next, the ceiling theft among
//      them: the mirror diverges and keeps its head; while a signature
//      mangled in transit is an ordinary error, and a mirror's own file that
//      breaks the rule does not load;
//   9. whoever holds the owner key cannot keep the recovery out by spending
//      the handle's day of publishes: a recover has a day's budget of its
//      own, which only a recover — only the recovery key — spends.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const { sha256 } = require('../lib/merkle.js');
const {
  KtLog,
  MemoryStore,
  FileStore,
  privateKeyFromSeed,
  rawPublicKey,
  verifySth,
  verifySthFor,
  witnessInputFor,
  witnessInput,
  leafHashFor,
  sthFromJson,
  sealValue,
  makePublish,
  verify,
} = require('../lib/log.js');
const h = require('../lib/handles.js');
const { createServer } = require('../server.js');
const { Mirror, Divergence, makeFetchJson } = require('../lib/mirror.js');

const seed = (s) => crypto.createHash('sha256').update(`handle mode: ${s}`).digest();
const key = (s) => privateKeyFromSeed(seed(s));
const logKey = key('the handle log');
const witnessKey = key('the witness');

const owner = key('owner');
const owner2 = key('owner after recovery');
const evil = key('a stranger');
const recovery = key('recovery');
const recovery2 = key('recovery after recovery');
const wrongRecovery = key('a recovery key nobody committed to');
const rc = h.rcOf(rawPublicKey(recovery));
const rc2 = h.rcOf(rawPublicKey(recovery2));
const label = seed('the label of finnian.07');
const other = seed('the label of nobody.42');

const OPEN = { publishPerMinute: 1e9, publishPerMinuteTotal: 1e9, publishPerAccountPerDay: 1e9, newAccountsPerMinute: 1e9 };

const T0 = 1_800_000_123_456; // 34 s past the hour 1_800_000_000_000
let t = T0;
const now = () => t;

function handleLog(store = new MemoryStore()) {
  return new KtLog({ store, signingKey: logKey, mode: 'handles', now });
}

async function serve(log) {
  const { httpServer } = createServer({ log, ...OPEN });
  await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  return {
    base,
    get: async (p) => {
      const r = await fetch(base + p);
      return { status: r.status, body: await r.json() };
    },
    publish: async (p) => {
      const body = typeof p === 'string' ? p : JSON.stringify(h.handlePublishJson(p));
      const r = await fetch(base + '/kt/v1/publish', { method: 'POST', body });
      return { status: r.status, body: await r.json() };
    },
    stop: async () => {
      httpServer.closeAllConnections();
      await new Promise((r) => httpServer.close(r));
    },
  };
}

const claim = (o = {}) => h.makeHandlePublish({ label, version: 1, ownerKey: owner, k: 'claim', introSeed: seed('intro'), rc, ...o });
const update = (version, o = {}) => h.makeHandlePublish({ label, version, ownerKey: owner, k: 'update', introSeed: seed(`intro ${version}`), rc, ...o });
const recover = (version, o = {}) =>
  h.makeHandlePublish({ label, version, ownerKey: owner2, k: 'recover', introSeed: seed('intro recovered'), rc: rc2, recoveryKey: recovery, ...o });

/** [p] with its record replaced by [bytes], re-signed by [signer] so that only the encoding is wrong. */
function withRecord(p, bytes, signer = owner) {
  const sig = crypto.sign(null, h.publishInput({ label: p.label, version: p.version, valueHash: sha256(bytes) }), signer);
  return { ...p, value: bytes, sig };
}

/** An update naming the owner, whose `sig` is the stranger's: the forgery a log without the rule would accept. */
function signedByStranger(version) {
  const p = update(version);
  return { ...p, sig: crypto.sign(null, h.publishInput({ label, version, valueHash: sha256(p.value) }), evil) };
}

/** Every record that is not its one canonical encoding, built from a good one. */
function nonCanonical() {
  const good = claim().value.toString();
  const j = JSON.parse(good);
  const reorder = JSON.stringify({ owner: j.owner, k: j.k, intro: j.intro, xintro: j.xintro, pow: j.pow, rc: j.rc });
  const swapped = JSON.stringify({ k: j.k, owner: j.owner, xintro: j.xintro, intro: j.intro, pow: j.pow, rc: j.rc });
  const padded = j.owner + '=';
  return [
    ['whitespace', good.replace(',"intro"', ', "intro"')],
    ['member order', reorder],
    ['xintro before intro', swapped],
    ['an extra member', good.replace('}', ',"x":1}')],
    ['no intro', JSON.stringify({ k: j.k, owner: j.owner, xintro: j.xintro, pow: j.pow, rc: j.rc })],
    ['no xintro', JSON.stringify({ k: j.k, owner: j.owner, intro: j.intro, pow: j.pow, rc: j.rc })],
    ['intro without xintro (xintro null)', good.replace(`"xintro":"${j.xintro}"`, '"xintro":null')],
    ['xintro without intro (intro null)', good.replace(`"intro":"${j.intro}"`, '"intro":null')],
    ['xintro 31 bytes', good.replace(j.xintro, Buffer.alloc(31, 2).toString('base64url'))],
    ['xintro 33 bytes', good.replace(j.xintro, Buffer.alloc(33, 2).toString('base64url'))],
    ['pow 15', good.replace('"pow":20', '"pow":15')],
    ['pow 29', good.replace('"pow":20', '"pow":29')],
    ['pow 20.0', good.replace('"pow":20', '"pow":20.0')],
    ['pow "20"', good.replace('"pow":20', '"pow":"20"')],
    ['k "Claim"', good.replace('"claim"', '"Claim"')],
    ['k escaped', good.replace('"claim"', '"\\u0063laim"')],
    ['owner padded', good.replace(j.owner, padded)],
    ['owner with a standard-alphabet character', good.replace(j.owner, '+' + j.owner.slice(1))],
    ['owner with its unused bits set', good.replace(j.owner, j.owner.slice(0, 42) + String.fromCharCode(j.owner.charCodeAt(42) + 1))],
    ['owner 31 bytes', good.replace(j.owner, Buffer.alloc(31, 1).toString('base64url'))],
    ['rpub on a claim', good.replace('}', `,"rpub":"${j.owner}"`) + '}'],
    ['a duplicate member', good.replace('"pow":20', '"pow":20,"pow":20')],
    ['a byte-order mark', '﻿' + good],
    ['not JSON', good.slice(0, -1)],
    ['an array', `[${good}]`],
  ];
}

// --- 1 ------------------------------------------------------------------------

test('1. every case of the owner rule, on the wire', async () => {
  t = T0;
  const log = handleLog();
  const s = await serve(log);
  try {
    const expect = async (p, status, code, what) => {
      const r = await s.publish(p);
      assert.equal(r.status, status, `${what}: ${JSON.stringify(r.body)}`);
      if (code) assert.equal(r.body.error, code, what);
      return r;
    };
    // Before any claim, nothing but a claim — and a claim is version 1.
    await expect(update(2), 403, 'owner_rule', 'an update before the claim');
    await expect(recover(2), 403, 'owner_rule', 'a recover before the claim');
    await expect(claim({ version: 2 }), 409, 'stale_version', 'a claim at version 2');
    await expect(claim({ version: Number.MAX_SAFE_INTEGER }), 409, 'stale_version', 'a claim at 2^53 − 1');
    await expect(claim(), 201, null, 'the claim');
    assert.equal(log.size, 1);
    await expect(claim({ ownerKey: evil, version: 7 }), 409, 'taken', 'a claim on a held label, at any version');
    await expect(claim(), 409, 'taken', 'the same claim again');
    await expect(update(2), 201, null, 'an update by the owner');
    await expect(update(2, { introSeed: null }), 409, 'stale_version', 'the same version again');
    await expect(update(1), 409, 'stale_version', 'a version below');
    await expect(update(4), 409, 'stale_version', 'a version that skips one');
    // The owner key's holder — a thief, as far as the log can tell — at the
    // ceiling: once accepted, no version was left for the recovery code.
    const ceiling = await expect(update(Number.MAX_SAFE_INTEGER), 409, 'stale_version', 'an update at 2^53 − 1');
    assert.match(ceiling.body.message, /the next entry is 3/);
    await expect(update(Number.MAX_SAFE_INTEGER + 1), 400, 'bad_request', 'an update past 2^53 − 1');
    // A stranger learns nothing about the version: what it signed is refused
    // for who signed it, whatever version it names.
    const stranger = await expect(update(9, { ownerKey: evil }), 403, 'owner_rule', 'a stranger\'s update at a version that is not next');
    assert.doesNotMatch(stranger.body.message, /version/);
    // Keys of small order: a record naming one is no record, whoever signs.
    const weak = h.encodeRecord({ k: 'claim', owner: Buffer.from('01' + '00'.repeat(31), 'hex'), intro: null, xintro: null, pow: 20, rc });
    await expect(
      { label: other, version: 1, value: weak, sig: Buffer.concat([Buffer.from('01' + '00'.repeat(31), 'hex'), Buffer.alloc(32)]) },
      400,
      'bad_record',
      'an owner key of small order, "signed" by R = the identity and S = 0'
    );
    // The stranger, three ways.
    await expect(update(3, { ownerKey: evil }), 403, 'owner_rule', 'an update naming the stranger as owner');
    await expect(signedByStranger(3), 403, 'bad_signature', 'an update naming the owner, signed by the stranger');
    await expect(update(3, { rc: h.rcOf(rawPublicKey(evil)) }), 403, 'owner_rule', 'an update changing the recovery commitment');
    // Pause, and change the proof of work: updates.
    await expect(update(3, { introSeed: null, pow: 28 }), 201, null, 'paused, pow 28');
    // Recovery.
    await expect(recover(4, { recoveryKey: wrongRecovery }), 403, 'bad_recovery', 'a recovery key nobody committed to');
    const badRsig = recover(4);
    const rec = JSON.parse(badRsig.value.toString());
    rec.rsig = Buffer.from(crypto.sign(null, Buffer.from('something else'), recovery)).toString('base64url');
    await expect(withRecord(badRsig, Buffer.from(JSON.stringify(rec)), owner2), 403, 'bad_recovery', 'an rsig over other bytes');
    const byOld = recover(4);
    await expect({ ...byOld, sig: crypto.sign(null, h.publishInput({ label, version: 4, valueHash: sha256(byOld.value) }), owner) }, 403, 'bad_signature', 'a recover signed by the old owner');
    await expect(recover(4), 201, null, 'the recover');
    assert.ok(log.owners.get(label.toString('hex')).owner.equals(rawPublicKey(owner2)), 'the new owner');
    assert.ok(log.owners.get(label.toString('hex')).rc.equals(rc2), 'the new commitment');
    await expect(update(5), 403, 'owner_rule', 'the old owner, after the recover');
    await expect(recover(5, { ownerKey: evil }), 403, 'bad_recovery', 'the spent recovery key');
    await expect(update(5, { ownerKey: owner2, rc: rc2 }), 201, null, 'the new owner\'s update');
    // Size and encoding.
    const big = { k: 'claim', owner: rawPublicKey(owner).toString('base64url'), intro: null, xintro: null, pow: 20, rc: rc.toString('base64url'), x: 'y'.repeat(1000) };
    await expect(withRecord(h.makeHandlePublish({ label: other, version: 1, ownerKey: owner, k: 'claim', rc }), Buffer.from(JSON.stringify(big))), 413, 'too_large', 'a record over 1 KiB');
    for (const [what, text] of nonCanonical()) {
      await expect(withRecord(h.makeHandlePublish({ label: other, version: 1, ownerKey: owner, k: 'claim', rc }), Buffer.from(text)), 400, 'bad_record', what);
    }
    // The request itself.
    const good = h.handlePublishJson(h.makeHandlePublish({ label: other, version: 1, ownerKey: owner, k: 'claim', rc }));
    for (const [what, body] of [
      ['a short label', { ...good, label: Buffer.alloc(31).toString('base64url') }],
      ['no label', { ...good, label: undefined }],
      ['an account instead of a label', { acct: good.label, v: 1, fp: 'AAAA', value: good.value, sig: good.sig }],
      ['v 0', { ...good, v: 0 }],
      ['a short sig', { ...good, sig: Buffer.alloc(63).toString('base64') }],
    ]) {
      await expect(JSON.stringify(body), 400, 'bad_request', what);
    }
    // The label in standard base64 is the same label.
    await expect(JSON.stringify({ ...good, label: other.toString('base64') }), 201, null, 'the label in standard base64');
    assert.equal(log.size, 6, 'claim, update, update, recover, update, and the other claim — nothing refused was written');
  } finally {
    await s.stop();
  }
});

// --- 2 ------------------------------------------------------------------------

/** An entry as the log would write it, for [p], at the next index and a whole hour. */
function line(index, p, o = {}) {
  return JSON.stringify({
    i: index,
    label: p.label.toString('base64'),
    v: p.version,
    vh: sha256(p.value).toString('base64'),
    val: p.value.toString('base64'),
    ts: 1_800_000_000_000,
    sig: p.sig.toString('base64'),
    ...o,
  });
}

test('2. a line the log did not write refuses the start, by the rule it breaks', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-handles-'));
  const file = path.join(dir, 'entries.jsonl');
  try {
    t = T0;
    {
      const log = handleLog(new FileStore(file));
      log.publish(claim());
      log.publish(update(2));
      log.close();
    }
    const good = fs.readFileSync(file, 'utf8');
    const head = fs.readFileSync(`${file}.head.json`, 'utf8');
    const open = () => {
      const log = handleLog(new FileStore(file));
      const n = log.size;
      log.close();
      return n;
    };
    const big = Buffer.from(JSON.stringify({ k: 'update', owner: rawPublicKey(owner).toString('base64url'), intro: null, xintro: null, pow: 20, rc: rc.toString('base64url'), x: 'y'.repeat(1000) }));
    const ktLine = (() => {
      const a = key('an account');
      const p = makePublish(a, { version: 1, fp: Buffer.alloc(16), value: sealValue(rawPublicKey(a), Buffer.from('{}')) });
      return JSON.stringify({ i: 2, label: crypto.randomBytes(32).toString('base64'), v: 1, fp: p.fp.toString('base64'), vh: sha256(p.value).toString('base64'), val: p.value.toString('base64'), acct: p.acct.toString('base64'), ts: 1_800_000_000_000, sig: p.sig.toString('base64') });
    })();
    const forged = [
      ['an update naming the stranger', line(2, update(3, { ownerKey: evil })), /owner_rule/],
      ['an update signed by the stranger', line(2, signedByStranger(3)), /bad_signature/],
      ['a claim on the held label', line(2, claim({ ownerKey: evil, version: 3 })), /taken/],
      ['an update changing rc', line(2, update(3, { rc: rc2 })), /owner_rule/],
      ['a recover with the wrong recovery key', line(2, recover(3, { recoveryKey: wrongRecovery })), /bad_recovery/],
      ['a recover signed by the old owner', line(2, { ...recover(3), sig: crypto.sign(null, h.publishInput({ label, version: 3, valueHash: sha256(recover(3).value) }), owner) }), /bad_signature/],
      ['an update before any claim', line(2, h.makeHandlePublish({ label: other, version: 1, ownerKey: evil, k: 'update', rc })), /owner_rule/],
      ['the same version again', line(2, update(2, { introSeed: null })), /next entry is 3, not 2 \(stale_version\)/],
      ['a version that skips one', line(2, update(4)), /next entry is 3, not 4 \(stale_version\)/],
      ['the theft at 2^53 − 1', line(2, update(Number.MAX_SAFE_INTEGER)), /stale_version/],
      ['a version past 2^53 − 1', line(2, update(Number.MAX_SAFE_INTEGER + 1)), /v must be an integer 1\.\.9007199254740991 \(bad_request\)/],
      ['an owner key of small order', line(2, (() => {
        const id = Buffer.from('01' + '00'.repeat(31), 'hex');
        return { label, version: 3, value: h.encodeRecord({ k: 'update', owner: id, intro: null, xintro: null, pow: 20, rc }), sig: Buffer.concat([id, Buffer.alloc(32)]) };
      })()), /not a strong Ed25519 key.*\(bad_record\)/],
      ['a record over 1 KiB', line(2, withRecord(update(3), big)), /too_large/],
      ['a record with whitespace', line(2, withRecord(update(3), Buffer.from(update(3).value.toString().replace(',"pow"', ', "pow"')))), /bad_record/],
      ['a time finer than an hour', line(2, update(3), { ts: 1_800_000_123_456 }), /not a whole hour/],
      ['no signature', line(2, update(3), { sig: undefined }), /no owner's signature/],
      ['a value that does not hash to vh', line(2, update(3), { vh: sha256(Buffer.from('x')).toString('base64') }), /value hash/],
      ['a key-transparency log\'s line', ktLine, /key-transparency log's/],
    ];
    for (const [what, l, why] of forged) {
      fs.writeFileSync(file, good + l + '\n');
      fs.writeFileSync(`${file}.head.json`, head);
      assert.throws(open, why, what);
    }
    // And the genuine next entry, written the same way, opens: the refusals
    // were the rule, not the hand that wrote the line.
    fs.writeFileSync(file, good + line(2, update(3)) + '\n');
    fs.writeFileSync(`${file}.head.json`, head);
    assert.equal(open(), 3);
    fs.writeFileSync(file, good);
    fs.writeFileSync(`${file}.head.json`, head);
    assert.equal(open(), 2);
    // And through `KtLog.open`, the replay a server's start makes.
    fs.writeFileSync(file, good + line(2, update(3, { ownerKey: evil })) + '\n');
    fs.writeFileSync(`${file}.head.json`, head);
    await assert.rejects(KtLog.open({ store: new FileStore(file), signingKey: logKey, mode: 'handles', now }), /owner_rule/);
    fs.writeFileSync(file, good);
    const reopened = await KtLog.open({ store: new FileStore(file), signingKey: logKey, mode: 'handles', now });
    assert.equal(reopened.size, 2);
    assert.ok(reopened.owners.get(label.toString('hex')).owner.equals(rawPublicKey(owner)));
    reopened.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- 3 ------------------------------------------------------------------------

test('3. an entry keeps the hour it was accepted in, and nothing finer', async () => {
  const log = handleLog();
  const s = await serve(log);
  try {
    const hour = 1_800_000_000_000;
    for (const [at, version] of [[hour + 1, 1], [hour + 3_599_999, 2], [hour + 3_600_000, 3], [hour + 7_199_000, 4]]) {
      t = at;
      const p = version === 1 ? claim() : update(version);
      assert.equal((await s.publish(p)).status, 201);
    }
    assert.deepEqual(log.entries.map((e) => e.ts), [hour, hour, hour + 3_600_000, hour + 3_600_000]);
    // As served, and as the leaf commits to it.
    const r = await s.get(`/kt/v1/history/${label.toString('hex')}`);
    assert.deepEqual(r.body.entries.map((x) => x.entry.ts), [hour, hour, hour + 3_600_000, hour + 3_600_000]);
    const e = log.entries[1];
    assert.ok(log.tree.leaves[1].equals(leafHashFor('handles', { label: e.label, version: e.version, valueHash: e.valueHash, ts: hour })));
    // The head's own ts is when it was signed, as in the key-transparency
    // log: it is what a reader judges freshness by. And it is signed as the
    // log grows, so a poller learns when each record arrived — PROTOCOL
    // §21.5 says so, and why heads are not held back to the hour.
    assert.equal(log.sth().ts, t);
    assert.equal(log.sth().size, 4);
  } finally {
    await s.stop();
  }
});

// --- 4 ------------------------------------------------------------------------

test('4. a handle head is never a key-transparency head, nor the reverse — under the same key', () => {
  t = T0;
  const handles = new KtLog({ store: new MemoryStore(), signingKey: logKey, mode: 'handles', now });
  handles.publish(claim());
  const kt = new KtLog({ store: new MemoryStore(), signingKey: logKey, now });
  const a = key('an account');
  kt.publish(makePublish(a, { version: 1, fp: Buffer.alloc(16), value: sealValue(rawPublicKey(a), Buffer.from('{}')) }));
  const pub = rawPublicKey(logKey);
  for (const [log, mine, theirs] of [[handles, 'handles', 'kt'], [kt, 'kt', 'handles']]) {
    const head = log.sth();
    assert.ok(verifySthFor(mine, head, pub), `${mine} head in its own context`);
    assert.ok(!verifySthFor(theirs, head, pub), `${mine} head as a ${theirs} head`);
  }
  assert.ok(!verifySth(handles.sth(), pub), 'and the KT verifier everyone already has refuses it');
  // The contexts, pinned.
  const head = handles.sth();
  assert.equal(h.sthInput(head).subarray(0, 16).toString(), 'z-handle-sth-v1:');
  assert.equal(h.witnessInput(head).subarray(0, 20).toString(), 'z-handle-witness-v1:');
  assert.ok(h.witnessInput(head).subarray(20).equals(h.sthInput(head)));
  const e = handles.entries[0];
  assert.equal(h.leafInput({ label: e.label, version: 1, valueHash: e.valueHash, ts: e.ts }).subarray(0, 17).toString(), 'z-handle-leaf-v1:');
  assert.equal(h.publishInput({ label, version: 1, valueHash: e.valueHash }).subarray(0, 20).toString(), 'z-handle-publish-v1:');
  assert.equal(h.recoverInput({ label, version: 1, owner: label, rc }).subarray(0, 20).toString(), 'z-handle-recover-v1:');
  assert.ok(h.rcOf(rawPublicKey(recovery)).equals(sha256(Buffer.from('z-handle-rc-v1:'), rawPublicKey(recovery))));
  // A witness's co-signature over a handle head is the handle context's.
  const sig = crypto.sign(null, witnessInputFor('handles', head), witnessKey);
  assert.ok(verify(rawPublicKey(witnessKey), witnessInputFor('handles', head), sig));
  assert.ok(!verify(rawPublicKey(witnessKey), witnessInput(head), sig), 'not the KT witness context');
});

// --- 5 ------------------------------------------------------------------------

test('5. the handle log serves the record and the owner\'s signature — what it stores, and nothing it does not', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-handles-'));
  const file = path.join(dir, 'entries.jsonl');
  t = T0;
  const log = handleLog(new FileStore(file));
  const s = await serve(log);
  try {
    const p1 = claim();
    const p2 = update(2, { introSeed: null });
    await s.publish(p1);
    await s.publish(p2);
    const served = ['index', 'label', 'v', 'valueHash', 'value', 'ts', 'sig'];
    const lookup = await s.get(`/kt/v1/lookup/${label.toString('hex')}`);
    assert.deepEqual(Object.keys(lookup.body.entry), served);
    assert.equal(Buffer.from(lookup.body.entry.value, 'base64').toString(), p2.value.toString(), 'the record in the clear');
    assert.ok(Buffer.from(lookup.body.entry.sig, 'base64').equals(p2.sig));
    const page = await s.get('/kt/v1/entries?start=0&count=10');
    assert.deepEqual(page.body.entries.map((e) => Object.keys(e)), [served, served]);
    const hist = await s.get(`/kt/v1/history/${label.toString('hex')}`);
    assert.deepEqual(hist.body.entries.map((x) => Buffer.from(x.entry.value, 'base64').toString()), [p1.value.toString(), p2.value.toString()]);
    // Stored: the same fields under their stored names, and no others.
    const stored = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => Object.keys(JSON.parse(l)));
    const rename = { i: 'index', vh: 'valueHash', val: 'value' };
    for (const keys of stored) assert.deepEqual(keys.map((k) => rename[k] || k).sort(), [...served].sort());
    const health = await s.get('/health');
    assert.equal(health.body.mode, 'handles');
  } finally {
    await s.stop();
    log.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // KT_MODE unset: the key-transparency log, serving exactly what it did.
  const kt = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  assert.equal(kt.mode, 'kt');
  const a = key('an account');
  kt.publish(makePublish(a, { version: 1, fp: Buffer.alloc(16), value: sealValue(rawPublicKey(a), Buffer.from('{}')) }));
  const k = await serve(kt);
  try {
    const page = await k.get('/kt/v1/entries?start=0&count=1');
    assert.deepEqual(Object.keys(page.body.entries[0]), ['index', 'label', 'v', 'fp', 'valueHash', 'value', 'ts']);
    assert.equal((await k.get('/health')).body.mode, undefined);
  } finally {
    await k.stop();
  }
});

// --- 6 ------------------------------------------------------------------------

const v8 = require('node:v8');
const vm = require('node:vm');
v8.setFlagsFromString('--expose_gc');
const gc = vm.runInNewContext('gc');
v8.setFlagsFromString('--no-expose_gc');

function retained() {
  gc();
  gc();
  const m = process.memoryUsage();
  return m.heapUsed + m.external;
}

test('6. the owner rule costs memory per label, not per entry', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-handles-'));
  const file = path.join(dir, 'entries.jsonl');
  try {
    // 1100 labels: 1080 claimed once, 20 updated 25 times — 1600 entries.
    const lines = [];
    const labels = Array.from({ length: 1100 }, (_, i) => seed(`memory label ${i}`));
    let i = 0;
    for (const l of labels) lines.push(line(i++, h.makeHandlePublish({ label: l, version: 1, ownerKey: owner, k: 'claim', introSeed: seed(`i${i}`), rc })));
    for (let v = 2; v <= 26; v++) {
      for (const l of labels.slice(0, 20)) lines.push(line(i++, h.makeHandlePublish({ label: l, version: v, ownerKey: owner, k: 'update', introSeed: seed(`i${i}`), rc })));
    }
    fs.writeFileSync(file, lines.join('\n') + '\n');
    const before = retained();
    const log = new KtLog({ store: new FileStore(file), signingKey: logKey, mode: 'handles' });
    const per = (retained() - before) / log.size;
    console.log(`        ${log.size} handle entries over ${log.map.size} labels replayed: ${(per / 1024).toFixed(2)} KB retained per entry`);
    assert.equal(log.size, 1600);
    // Per label: one slot each, in chunks of 1024.
    assert.equal(log.owners.size, 1100);
    assert.equal(log.owners.chunks.length, 2);
    assert.equal(log.owners.bytes, 2 * 1024 * 64);
    for (const c of log.owners.chunks) assert.equal(c.buffer.byteLength, 1024 * 64, 'a chunk is its own allocation');
    // Per entry: nothing of the rule, and the entry's own fields in one allocation.
    for (const e of log.entries) {
      assert.equal(e.owner, undefined);
      assert.equal(e.rc, undefined);
      const ab = e.label.buffer;
      assert.equal(e.valueHash.buffer, ab);
      assert.equal(e.sig.buffer, ab);
      assert.equal(ab.byteLength, 32 + 32 + 64, `entry ${e.index}: its fields sit in ${ab.byteLength} bytes`);
    }
    // The twenty labels updated twenty-five times hold the state of their
    // latest record: what a hundred updates more would not add to.
    const s = log.owners.get(labels[0].toString('hex'));
    assert.ok(s.owner.equals(rawPublicKey(owner)) && s.rc.equals(rc));
    // And a replay retains what the key-transparency log's does: a few
    // kilobytes an entry, the trees' share (log_memory.test.js 5).
    assert.ok(per < 5 * 1024, `a replay retained ${(per / 1024).toFixed(2)} KB an entry`);
    log.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- 7 ------------------------------------------------------------------------

function startServer(env) {
  return spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: { ...process.env, KT_SEED: seed('process').toString('hex'), KT_EPHEMERAL: '1', KT_PORT: '0', KT_HOST: '127.0.0.1', ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

/** Resolves with the server's port once it says it is listening, or rejects with what it said instead. */
function listening(child) {
  return new Promise((resolve, reject) => {
    let out = '';
    const on = (b) => {
      out += b.toString();
      const m = /listening on http:\/\/127\.0\.0\.1:(\d+)/.exec(out);
      if (m) resolve({ port: Number(m[1]), out });
    };
    child.stdout.on('data', on);
    child.stderr.on('data', on);
    child.on('exit', (code) => reject(new Error(`exited ${code}: ${out}`)));
  });
}

test('7. KT_MODE chooses the log, refuses what it does not know, and neither log opens the other\'s file', async () => {
  assert.equal(h.modeFromEnv(undefined), 'kt');
  assert.equal(h.modeFromEnv(''), 'kt');
  assert.equal(h.modeFromEnv('kt'), 'kt');
  assert.equal(h.modeFromEnv(' handles '), 'handles');
  for (const bad of ['handle', 'HANDLES', 'kt,handles', '1']) assert.throws(() => h.modeFromEnv(bad), /KT_MODE must be/, bad);
  // The process: a typo refuses to start, before any key is read.
  const typo = spawnSync(process.execPath, ['server.js'], { cwd: path.join(__dirname, '..'), env: { ...process.env, KT_MODE: 'handle', KT_SEED: 'not even a seed' }, encoding: 'utf8' });
  assert.equal(typo.status, 1);
  assert.match(typo.stderr, /KT_MODE must be "handles" or unset/);
  // `handles` starts the handle log — on a disk, as it runs: published to,
  // stopped, and started again, so the replay a start makes (`KtLog.open`)
  // rebuilds the owner rule's state from the file.
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-handles-data-'));
  const run = async (body) => {
    const child = startServer({ KT_MODE: 'handles', KT_EPHEMERAL: '', KT_DATA: data });
    const exited = new Promise((r) => child.on('exit', r));
    try {
      const { port, out } = await listening(child);
      await body(`http://127.0.0.1:${port}`, out);
    } finally {
      child.kill();
      await exited;
    }
  };
  const publishTo = async (base, p) => (await fetch(`${base}/kt/v1/publish`, { method: 'POST', body: JSON.stringify(h.handlePublishJson(p)) })).status;
  try {
    await run(async (base, out) => {
      assert.match(out, /the HANDLE log/);
      const health = await (await fetch(`${base}/health`)).json();
      assert.equal(health.mode, 'handles');
      assert.equal(await publishTo(base, claim()), 201);
      assert.equal(await publishTo(base, update(2)), 201);
      const sth = sthFromJson(await (await fetch(`${base}/kt/v1/sth`)).json());
      assert.ok(verifySthFor('handles', sth, rawPublicKey(privateKeyFromSeed(seed('process')))));
    });
    await run(async (base, out) => {
      assert.match(out, /handle log, 2 entries, 1 labels/, 'replayed from its file');
      const hist = await (await fetch(`${base}/kt/v1/history/${label.toString('hex')}`)).json();
      assert.deepEqual(hist.entries.map((x) => x.entry.v), [1, 2]);
      // The owner is the claimant's still: the replay rebuilt it.
      const r = await fetch(`${base}/kt/v1/publish`, { method: 'POST', body: JSON.stringify(h.handlePublishJson(update(3, { ownerKey: evil }))) });
      assert.equal(r.status, 403);
      assert.equal((await r.json()).error, 'owner_rule');
      assert.equal(await publishTo(base, update(3)), 201);
    });
  } finally {
    fs.rmSync(data, { recursive: true, force: true });
  }
  // The two logs' files are not each other's.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-handles-'));
  try {
    const hfile = path.join(dir, 'handles.jsonl');
    const hlog = handleLog(new FileStore(hfile));
    hlog.publish(claim());
    hlog.close();
    assert.throws(() => new KtLog({ store: new FileStore(hfile), signingKey: logKey }), Error, 'a handle log\'s file is no KT log\'s');
    const kfile = path.join(dir, 'kt.jsonl');
    const klog = new KtLog({ store: new FileStore(kfile), signingKey: logKey });
    const a = key('an account');
    klog.publish(makePublish(a, { version: 1, fp: Buffer.alloc(16), value: sealValue(rawPublicKey(a), Buffer.from('{}')) }));
    klog.close();
    assert.throws(() => handleLog(new FileStore(kfile)), /key-transparency log's, not a handle log's/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// --- 8 ------------------------------------------------------------------------

/**
 * A log whose operator removed the owner rule: it takes any well-formed,
 * self-signed record, as `kt/` did before this phase for a label that was
 * not derived from its signer — the log a mirror exists to catch.
 */
function withoutTheRule(log) {
  log._ownerRule = (_prev, e) => {
    const rec = h.parseRecord(e.value);
    return { owner: rec.owner, rc: rec.rc };
  };
  return (p) => {
    log._apply({ index: log.entries.length, label: p.label, version: p.version, valueHash: sha256(p.value), value: p.value, sig: p.sig, ts: h.hourOf(t) }, false);
    log._recordHead();
  };
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-handles-mirror-'));
}

test('8. a mirror follows the handle log and its witness co-signs — and a log that accepted a foreign update is caught', async () => {
  t = T0;
  const log = handleLog();
  log.publish(claim());
  log.publish(update(2));
  log.publish(h.makeHandlePublish({ label: other, version: 1, ownerKey: evil, k: 'claim', rc: h.rcOf(rawPublicKey(evil)) }));
  log.publish(recover(3));
  const s = await serve(log);
  const dir = tmpdir();
  try {
    const m = new Mirror({ dir, logUrl: s.base, logPub: log.publicKey, witnessKey, pageSize: 2, now, mode: 'handles' }).load();
    const r = await m.sync();
    assert.deepEqual([r.from, r.to], [0, 4]);
    assert.ok(m.tree.root.equals(log.tree.root) && m.map.root.equals(log.map.root));
    assert.equal(m.owners.size, 2);
    assert.ok(m.owners.get(label.toString('hex')).owner.equals(rawPublicKey(owner2)), 'the mirror followed the recover');
    const rec = m.record();
    const sth = sthFromJson(rec.sth);
    assert.ok(verifySthFor('handles', sth, log.publicKey));
    assert.ok(verify(rawPublicKey(witnessKey), witnessInputFor('handles', sth), Buffer.from(rec.witness.sig, 'base64')), 'co-signed in the handle context');
    assert.ok(!verify(rawPublicKey(witnessKey), witnessInput(sth), Buffer.from(rec.witness.sig, 'base64')), 'and not in the KT one');
    // A mirror of the wrong kind refuses the head: it is not a head of its log.
    const wrong = new Mirror({ dir: tmpdir(), logUrl: s.base, logPub: log.publicKey, now });
    await assert.rejects(wrong.sync(), Divergence);
    fs.rmSync(wrong.dir, { recursive: true, force: true });
    // It grows; the mirror extends and reloads from its own directory.
    log.publish(update(4, { ownerKey: owner2, rc: rc2 }));
    assert.deepEqual(await m.sync().then((x) => [x.from, x.to]), [4, 5]);
    const again = new Mirror({ dir, logUrl: s.base, logPub: log.publicKey, now, mode: 'handles' }).load();
    assert.equal(again.entries.length, 5);
    assert.equal(again.owners.size, 2);

    // A signature mangled in transit is the network's, not the log's: an
    // ordinary error, the mirror not poisoned, and the next sync fine.
    const mangled = makeFetchJson({
      fetch: async (url, opts) => {
        const res = await fetch(url, opts);
        if (!url.includes('/kt/v1/entries')) return res;
        const j = await res.json();
        for (const e of j.entries) e.sig = Buffer.alloc(63).toString('base64');
        return new Response(JSON.stringify(j), { status: 200, headers: { 'content-type': 'application/json' } });
      },
    });
    log.publish(update(5, { ownerKey: owner2, rc: rc2 }));
    const flaky = new Mirror({ dir, logUrl: s.base, logPub: log.publicKey, now, mode: 'handles', fetchJson: mangled }).load();
    await assert.rejects(flaky.sync(), (e) => !(e instanceof Divergence) && /malformed/.test(e.message));
    assert.equal(flaky.poisoned, false);
    assert.deepEqual(await m.sync().then((x) => [x.from, x.to]), [5, 6]);

    // The foreign update, two ways, and the owner's own update at a version
    // that is not the next — one skipped, and the ceiling theft — each from a
    // log that took it.
    for (const [what, forge, why] of [
      ['a record naming the stranger as owner', (v) => update(v, { ownerKey: evil, rc: rc2 }), /owner rule refuses.*owner_rule/],
      ['the owner named, the stranger signing', (v) => ({ ...update(v, { ownerKey: owner2, rc: rc2 }), sig: crypto.sign(null, h.publishInput({ label, version: v, valueHash: sha256(update(v, { ownerKey: owner2, rc: rc2 }).value) }), evil) }), /owner rule refuses.*bad_signature/],
      ['the owner\'s update skipping a version', (v) => update(v + 1, { ownerKey: owner2, rc: rc2 }), /owner rule refuses.*next entry is \d+, not \d+ \(stale_version\)/],
      ['the owner\'s update at 2^53 − 1', () => update(Number.MAX_SAFE_INTEGER, { ownerKey: owner2, rc: rc2 }), /owner rule refuses.*\(stale_version\)/],
    ]) {
      t = T0;
      const lax = handleLog();
      for (const e of log.entries) {
        // The same honest history, so the mirror has a head to hold it to.
        const x = log.withValue(e);
        lax.publish({ label: x.label, version: x.version, value: x.value, sig: x.sig });
      }
      const take = withoutTheRule(lax);
      const ls = await serve(lax);
      const ldir = tmpdir();
      try {
        const lm = new Mirror({ dir: ldir, logUrl: ls.base, logPub: lax.publicKey, now, mode: 'handles' }).load();
        await lm.sync();
        const held = lm.record().size;
        take(forge(lax.latest(label).version + 1));
        lax.publish(h.makeHandlePublish({ label: seed('an innocent claim after it'), version: 1, ownerKey: owner, k: 'claim', rc }));
        await assert.rejects(lm.sync(), (e) => e instanceof Divergence && why.test(e.message), what);
        assert.ok(lm.poisoned, `${what}: the mirror stops following`);
        assert.equal(lm.record().size, held, `${what}: and keeps the head it verified`);
        // A mirror starting fresh from the log is caught the same way.
        const fresh = new Mirror({ dir: tmpdir(), logUrl: ls.base, logPub: lax.publicKey, now, mode: 'handles' }).load();
        await assert.rejects(fresh.sync(), Divergence, `${what}: a first sync`);
        fs.rmSync(fresh.dir, { recursive: true, force: true });
      } finally {
        await ls.stop();
        fs.rmSync(ldir, { recursive: true, force: true });
      }
    }

    // And a mirror's own directory with a line the rule refuses does not load.
    const file = path.join(dir, 'entries.jsonl');
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    const last = JSON.parse(lines[lines.length - 1]);
    const forged = update(last.v, { ownerKey: evil, rc: rc2 });
    // Swapped in for the last entry, with the head left as it was: the rule
    // is what refuses it, before the roots are compared.
    lines[lines.length - 1] = JSON.stringify({ ...last, value: forged.value.toString('base64'), valueHash: sha256(forged.value).toString('base64'), sig: forged.sig.toString('base64') });
    fs.writeFileSync(file, lines.join('\n') + '\n');
    assert.throws(() => new Mirror({ dir, logUrl: s.base, logPub: log.publicKey, now, mode: 'handles' }).load(), /owner_rule/);
  } finally {
    await s.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // The command line: --mode handles mirrors the handle log; anything else is refused.
  const log2 = handleLog();
  t = T0;
  log2.publish(claim());
  const s2 = await serve(log2);
  const dirs = [tmpdir(), tmpdir(), tmpdir()];
  try {
    const run = (dir, extra) =>
      new Promise((resolve) => {
        const c = spawn(process.execPath, ['tools/mirror.js', '--log', s2.base, '--pub', log2.publicKey.toString('base64'), '--dir', dir, ...extra], { cwd: path.join(__dirname, '..') });
        let out = '';
        c.stdout.on('data', (b) => (out += b));
        c.stderr.on('data', (b) => (out += b));
        c.on('exit', (code) => resolve({ code, out }));
      });
    const ok = await run(dirs[0], ['--mode', 'handles']);
    assert.equal(ok.code, 0, ok.out);
    const asKt = await run(dirs[1], []);
    assert.equal(asKt.code, 2, `a KT mirror of a handle log diverges at its first head: ${asKt.out}`);
    const bad = await run(dirs[2], ['--mode', 'handle']);
    assert.equal(bad.code, 1);
    assert.match(bad.out, /KT_MODE must be/);
  } finally {
    await s2.stop();
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  }
});

// --- 9 ------------------------------------------------------------------------

test('9. whoever holds the owner key cannot spend the handle\'s publishes to keep its recovery out', async () => {
  t = T0;
  const log = handleLog();
  // Three publishes a day for one handle, so a thief spends it in three.
  const { httpServer } = createServer({ log, ...OPEN, publishPerAccountPerDay: 3, now });
  await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  const publish = async (p) => {
    const r = await fetch(base + '/kt/v1/publish', { method: 'POST', body: JSON.stringify(h.handlePublishJson(p)) });
    return { status: r.status, body: await r.json() };
  };
  try {
    assert.equal((await publish(claim())).status, 201);
    // The thief, holding the owner seed, spends the rest of the day — and
    // would again the moment a token came back, for as long as it liked.
    assert.equal((await publish(update(2, { introSeed: seed('thief 2') }))).status, 201);
    assert.equal((await publish(update(3, { introSeed: seed('thief 3') }))).status, 201);
    const spent = await publish(update(4, { introSeed: seed('thief 4') }));
    assert.equal(spent.status, 429, 'the handle\'s updates are spent for the day');
    // The genuine code still recovers: its own budget.
    const r = await publish(recover(4));
    assert.equal(r.status, 201, `the recovery: ${JSON.stringify(r.body)}`);
    assert.ok(log.owners.get(label.toString('hex')).owner.equals(rawPublicKey(owner2)));
    // And the thief's key is nobody's now, budget or not.
    const after = await publish(update(5, { introSeed: seed('thief 5') }));
    assert.ok(after.status === 403 || after.status === 429, `the old owner: ${after.status}`);
    // A stranger's recover — its own rpub, its own rsig — is refused by the
    // rule and spends nothing; only an accepted recover spends the budget.
    const strangers = h.makeHandlePublish({ label, version: 5, ownerKey: evil, k: 'recover', rc, recoveryKey: wrongRecovery });
    for (let i = 0; i < 5; i++) assert.equal((await publish(strangers)).status, 403);
  } finally {
    httpServer.closeAllConnections();
    await new Promise((r) => httpServer.close(r));
  }
});
