'use strict';

// The publish signature was verified once, in RAM, and then dropped.
//
// `entryToStored` kept `acct` and not `sig`, so a replay could check only
// `labelFor(acct) == label` and `sha256(value) == valueHash` — both computed
// from fields whoever wrote the line also chose. So anything that could write
// the file could forge an entry for any account: take a victim's `acct` out
// of the file, seal a device list under `HKDF(acctPub)`, append one line at a
// higher version, and the log starts normally and serves it as that account's
// latest with a valid map proof. Nothing downstream can tell, because §19.6
// says `acct` is never served — and neither is `sig`.
//
// It also made `SELF_HOSTING.md`'s "refuses to start on a torn or edited
// file" false in the way that matters, which is the sentence an operator
// reads before deciding the file is safe to copy around.
//
// The boundary for lines written before signatures were stored was DERIVED,
// not recorded: a log never goes back, so an entry with no signature was
// accepted only while no earlier entry had one — on the reasoning that a
// number in a file would be a number editable by whoever is being defended
// against. The 2026-09-14 review's finding 15 showed what that left open: a
// boundary derived from the file is set by the file, so a FRESH deployment,
// and a pre-3.4.1 file until its first signed publish, accepted a
// hand-written unsigned line naming a victim's public account key and served
// it as their authenticated latest under a head signed by the real log key.
// The boundary is now recorded in the head file, signed under the log's key
// with its own context, and a head is written at the very first start — so a
// fresh log's boundary is 0 before anything can be appended. The derived
// rule stays as a second check.
//
// What is asserted below:
//   1. the forgery the reviewer performed, performed again — and refused;
//   2. a signature that is real but over a different publish is refused, so
//      the check is over these bytes rather than over any bytes;
//   3. a file written before signatures were stored still opens, and the
//      first signed publish closes the door behind it;
//   4. `sig` is never served, like `acct`;
//   5. and the leaf is unchanged, so no root, head or vector moves;
//   6. the fresh-deployment forgery: an unsigned line hand-appended to a log
//      that has never published is refused at the next start, because the
//      first start recorded a boundary of 0;
//   7. a legacy file adopts its boundary at its first start and writes it
//      down, so an unsigned line appended AFTER that start is refused even
//      though no signed entry precedes it — the case the derived rule could
//      not see;
//   8. the boundary cannot be moved by editing the head: a rewritten
//      `signedFrom` fails its signature, and a head signed by another key is
//      not this log's head at all.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { sha256 } = require('../lib/merkle.js');
const {
  KtLog,
  FileStore,
  labelFor,
  leafHashOf,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  entryToJson,
} = require('../lib/log.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('stored signature').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

function publishFor(acct, v) {
  const value = sealValue(acct.pub, Buffer.from(`{"list":${v}}`, 'utf8'));
  const fp = crypto.createHash('sha256').update(`fp:${acct.label.toString('hex')}:${v}`).digest().subarray(0, 16);
  return makePublish(acct.key, { version: v, fp, value });
}

function tmpdir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kt-sig-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** A stored line, built by hand the way somebody with the file would. */
function storedLine({ index, acct, version, fp, value, ts = 1, sig = null }) {
  const j = {
    i: index,
    label: labelFor(acct).toString('base64'),
    v: version,
    fp: fp.toString('base64'),
    vh: sha256(value).toString('base64'),
    val: value.toString('base64'),
    acct: acct.toString('base64'),
    ts,
  };
  if (sig) j.sig = sig.toString('base64');
  return JSON.stringify(j);
}

const open = (file) => () => new KtLog({ store: new FileStore(file), signingKey: logKey });

test('1. an entry forged for somebody else\'s account is refused', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const victim = account('victim');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  log.publish(publishFor(victim, 1));
  log.publish(publishFor(account('bystander'), 1));
  log.close();
  const text = fs.readFileSync(file, 'utf8');

  // The forgery, exactly as the review performed it: the victim's `acct` is
  // in the file, the value seals under a key derived from their PUBLIC key,
  // and the version only has to exceed the one the log holds.
  const acctB64 = JSON.parse(text.split('\n')[0]).acct;
  const acct = Buffer.from(acctB64, 'base64');
  assert.ok(acct.equals(victim.pub), 'the file hands the forger the account key');
  const forgedValue = sealValue(acct, Buffer.from('{"devices":["the forger\'s"]}', 'utf8'));
  const forged = storedLine({ index: 2, acct, version: 999, fp: Buffer.alloc(16, 0xaa), value: forgedValue });

  fs.writeFileSync(file, text + forged + '\n');
  // Every check that existed before this passes on that line: the label
  // matches the account, the hash matches the value, the version exceeds.
  assert.throws(open(file), /no signature/);

  // And with the head file removed as well — the one it cannot be refused by
  // — it is still refused, because the refusal is the entry before it.
  fs.rmSync(`${file}.head.json`);
  assert.throws(open(file), /no signature/);
});

test('2. a real signature over a different publish is refused', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const victim = account('victim');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  log.publish(publishFor(victim, 1));
  log.close();
  const text = fs.readFileSync(file, 'utf8');

  // The forger has one genuine signature of the victim's — the one in the
  // file — and tries it on a line of their own. It is a real Ed25519
  // signature by the right key; it is over other bytes.
  const real = JSON.parse(text.split('\n')[0]);
  const value = sealValue(victim.pub, Buffer.from('{"devices":["theirs"]}', 'utf8'));
  const line = storedLine({
    index: 1,
    acct: victim.pub,
    version: 5,
    fp: Buffer.alloc(16, 0xbb),
    value,
    sig: Buffer.from(real.sig, 'base64'),
  });
  fs.writeFileSync(file, text + line + '\n');
  assert.throws(open(file), /signature is not the account key's over this publish/);

  // Nor does re-using the whole of an earlier line help: that is the same
  // entry again, and the version rule has always caught it.
  fs.writeFileSync(file, text + JSON.stringify({ ...real, i: 1 }) + '\n');
  assert.throws(open(file), /does not exceed/);
});

test('3. a file written before signatures were stored still opens, and the door shuts behind it', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const a = account('old');
  const b = account('older');
  // Two lines as an older build wrote them: no `sig` at all.
  const p1 = publishFor(a, 1);
  const p2 = publishFor(b, 1);
  fs.writeFileSync(
    file,
    storedLine({ index: 0, acct: p1.acct, version: 1, fp: p1.fp, value: p1.value }) +
      '\n' +
      storedLine({ index: 1, acct: p2.acct, version: 1, fp: p2.fp, value: p2.value }) +
      '\n'
  );

  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  assert.equal(log.size, 2, 'the live log keeps working across the change');

  // The first signed publish sets the boundary, and nothing recorded it.
  log.publish(publishFor(a, 2));
  log.close();
  const withSigned = fs.readFileSync(file, 'utf8');
  assert.equal(JSON.parse(withSigned.split('\n')[0]).sig, undefined);
  assert.ok(JSON.parse(withSigned.split('\n')[2]).sig, 'and the new one carries it');

  const again = new KtLog({ store: new FileStore(file), signingKey: logKey });
  assert.equal(again.size, 3, 'a mixed file replays');
  again.close();

  // Now the forgery, appended after the boundary: refused by the entry
  // before it rather than by anything about itself.
  const value = sealValue(a.pub, Buffer.from('{"devices":["mine now"]}', 'utf8'));
  fs.writeFileSync(
    file,
    withSigned + storedLine({ index: 3, acct: a.pub, version: 900, fp: Buffer.alloc(16, 0xcc), value }) + '\n'
  );
  assert.throws(open(file), /no signature, though entry 2 and every one after it has one/);
});

test('4. the signature is kept and never served; 5. the leaf does not move', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const a = account('alice');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  t.after(() => log.close());
  const entry = log.publish(publishFor(a, 1));

  // 4. `acct` and `sig` are the two the log keeps for replay and serves to
  // nobody (§19.6). A mirror cannot re-check the signature — it has no
  // account key to check it against, by design — so this is tamper evidence
  // on the operator's own disk and the documents say only that.
  const served = entryToJson(log.withValue(entry));
  assert.equal(served.acct, undefined);
  assert.equal(served.sig, undefined);
  assert.deepEqual(Object.keys(served).sort(), ['fp', 'index', 'label', 'ts', 'v', 'value', 'valueHash']);

  // 5. The leaf covers label, version, fp, valueHash and ts — not `sig` —
  // so storing one changes no leaf, no root, no head and no vector.
  const withSig = leafHashOf(entry);
  const withoutSig = leafHashOf({ ...entry, sig: null });
  assert.ok(withSig.equals(withoutSig), 'the leaf is what it was');
});

test('6. a fresh deployment refuses a hand-written unsigned line', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  // The first start of a log that has never published. It used to leave no
  // head behind, and until its first real publish the boundary came from the
  // file — the reviewer's case A, reproduced: the forgery served as the
  // victim's latest with proofs that verified under the real log key.
  const fresh = open(file)();
  assert.equal(fresh.size, 0);
  fresh.close();
  assert.equal(JSON.parse(fs.readFileSync(`${file}.head.json`, 'utf8')).signedFrom, 0);

  const victim = account('victim');
  const value = sealValue(victim.pub, Buffer.from('{"devices":["ATTACKER"]}', 'utf8'));
  fs.writeFileSync(file, storedLine({ index: 0, acct: victim.pub, version: 9999, fp: Buffer.alloc(16, 0xaa), value }) + '\n');
  assert.throws(open(file), /no signature at or past the recorded boundary 0/);
});

test('7. a legacy file adopts its boundary once and then holds it', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const a = account('legacy');
  const p1 = publishFor(a, 1);
  fs.writeFileSync(file, storedLine({ index: 0, acct: p1.acct, version: 1, fp: p1.fp, value: p1.value }) + '\n');

  // Its first start after the upgrade: opens, adopts a boundary at its
  // current size, and writes the head. The same thing the previous build did
  // for the live log on 2026-09-17.
  const first = open(file)();
  assert.equal(first.size, 1);
  first.close();
  const head = JSON.parse(fs.readFileSync(`${file}.head.json`, 'utf8'));
  assert.equal(head.signedFrom, 1, 'the one unsigned line is below the boundary; nothing else may be');

  // The reviewer's case B: no signed entry precedes the forgery, so the
  // derived rule has nothing to refuse it with. The recorded one does.
  const value = sealValue(a.pub, Buffer.from('{"devices":["ATTACKER"]}', 'utf8'));
  fs.appendFileSync(file, storedLine({ index: 1, acct: a.pub, version: 8, fp: Buffer.alloc(16, 0xbb), value }) + '\n');
  assert.throws(open(file), /no signature at or past the recorded boundary 1/);
});

test('8. the boundary cannot be moved by editing the head', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const log = open(file)();
  log.publish(publishFor(account('a'), 1));
  log.close();
  const headFile = `${file}.head.json`;
  const good = JSON.parse(fs.readFileSync(headFile, 'utf8'));

  // Moving the boundary up would let unsigned lines below it in. The number
  // is signed under the log's key with its own context, so a moved number
  // fails its signature.
  fs.writeFileSync(headFile, JSON.stringify({ ...good, signedFrom: 5 }));
  assert.throws(open(file), /boundary is not signed by this log's key/);

  // And a whole head somebody else signed — same size, same roots, their key
  // — is not this log's head. Until 2026-09-17 a head only had to match the
  // file's root, which whoever wrote the file could compute, so the floor
  // it holds could be lowered by rewriting it.
  const other = privateKeyFromSeed(crypto.createHash('sha256').update('somebody else').digest());
  const forgedLog = new KtLog({ store: new FileStore(file), signingKey: other, verifyHead: false });
  forgedLog.close();
  const theirs = forgedLog.sth();
  fs.writeFileSync(
    headFile,
    JSON.stringify({
      ...good,
      sig: theirs.sig.toString('base64'),
      ts: theirs.ts,
      signedFromSig: good.signedFromSig,
    })
  );
  assert.throws(open(file), /not signed by this log's key/);
});
