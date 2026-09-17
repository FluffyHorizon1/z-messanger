'use strict';

// Replay believed whatever was on disk, and signed a head over it.
//
// Truncate `entries.jsonl` at a line boundary and the log starts cleanly and
// `sth()` returns a valid signed head at the shorter size. Nothing in the
// file says how long it ought to be, so a shorter file is not a damaged log
// — it is a smaller one, signed by the real key.
//
// The realistic trigger is not an attacker. `KT_DATA` pointing where the
// disk did not mount makes the log come up at size 0 with `/health`
// answering 200, and it begins signing a brand-new history with the
// production key. Restoring yesterday's snapshot does the same thing more
// quietly. Every client holding a head then enters permanent log-fault,
// which is the state `adr/0006` reserves for a log caught forking —
// correctly, because that is what this is.
//
// Two floors, because they fail differently: the head file catches a log
// that lost entries while keeping its directory, and `KT_MIN_SIZE` catches
// the directory going missing, which takes the head file with it.
//
// What is asserted below:
//   1. the head is on disk before the publish that produced it is answered;
//   2. a truncated file is refused, and refused by the head it already
//      signed rather than by anything in the file itself;
//   3. a file of the right LENGTH with the wrong contents is refused too —
//      the check is the root at that size, not the count;
//   4. an empty directory with a head file is refused, which is the restored
//      snapshot and the half-copied file;
//   5. and `KT_MIN_SIZE` refuses an empty log when the head file went with
//      the disk, which is the one the head file cannot see.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  KtLog,
  FileStore,
  MemoryStore,
  labelFor,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  verifySth,
} = require('../lib/log.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('head floor').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

function publishFor(acct, v) {
  const value = sealValue(acct.pub, Buffer.from(`list ${v}`, 'utf8'));
  const fp = crypto.createHash('sha256').update(`fp:${acct.label.toString('hex')}:${v}`).digest().subarray(0, 16);
  return makePublish(acct.key, { version: v, fp, value });
}

function tmpdir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kt-head-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Three entries, closed cleanly; returns the paths and the file's text. */
function threeEntries(t) {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  const a = account('alice');
  const b = account('bob');
  log.publish(publishFor(a, 1));
  log.publish(publishFor(b, 1));
  log.publish(publishFor(a, 2));
  const head = log.sth();
  log.close();
  return { dir, file, headFile: `${file}.head.json`, text: fs.readFileSync(file, 'utf8'), head };
}

const open = (file, opts = {}) => () => new KtLog({ store: new FileStore(file), signingKey: logKey, ...opts });

test('1. the head reaches the disk before the publish is answered', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  t.after(() => log.close());
  // A head from the very first start, at size 0. This used to be "nothing
  // signed, nothing recorded", and the gap it left was the window in which a
  // fresh deployment accepted a hand-written unsigned line (review 2026-09-14,
  // finding 15): with no head, the boundary was taken from the file. The
  // empty head records a boundary of 0 before anything can be appended.
  const first = JSON.parse(fs.readFileSync(`${file}.head.json`, 'utf8'));
  assert.equal(first.size, 0);
  assert.equal(first.signedFrom, 0, 'every entry must be signed, from the first');

  log.publish(publishFor(account('alice'), 1));
  const rec = JSON.parse(fs.readFileSync(`${file}.head.json`, 'utf8'));
  assert.equal(rec.size, 1);
  // It is the same head the log is serving, and it verifies under the log's
  // key — the record is a head, not a note about one.
  const head = log.sth();
  assert.equal(Buffer.from(rec.logRoot, 'base64').toString('hex'), head.logRoot.toString('hex'));
  assert.ok(
    verifySth(
      {
        size: rec.size,
        logRoot: Buffer.from(rec.logRoot, 'base64'),
        mapRoot: Buffer.from(rec.mapRoot, 'base64'),
        ts: rec.ts,
        sig: Buffer.from(rec.sig, 'base64'),
      },
      log.publicKey
    )
  );

  log.publish(publishFor(account('bob'), 1));
  assert.equal(JSON.parse(fs.readFileSync(`${file}.head.json`, 'utf8')).size, 2, 'and it moves with the log');
});

test('2. a truncated file is refused by the head it already signed', (t) => {
  const { file, text } = threeEntries(t);
  // Intact, it opens.
  const ok = open(file)();
  assert.equal(ok.size, 3);
  ok.close();

  // Truncated at a line boundary: nothing in the file is malformed, and
  // before the head file this started cleanly and signed a head at size 2.
  const lines = text.split('\n');
  fs.writeFileSync(file, [lines[0], lines[1], ''].join('\n'));
  assert.throws(open(file), /already signed|covers 3/);

  // Put back: it opens again. The refusal is about the size, not damage.
  fs.writeFileSync(file, text);
  const back = open(file)();
  assert.equal(back.size, 3);
  back.close();
});

test('3. the right length with the wrong contents is refused too', (t) => {
  const { file, text, dir } = threeEntries(t);
  // A different third entry, from a different account: the file still has
  // three lines and replays without complaint — every self-consistency check
  // passes, because they are all about the line rather than the history.
  const other = path.join(dir, 'other.jsonl');
  const fresh = new KtLog({ store: new FileStore(other), signingKey: logKey });
  const a = account('alice');
  const b = account('bob');
  fresh.publish(publishFor(a, 1));
  fresh.publish(publishFor(b, 1));
  fresh.publish(publishFor(account('mallory'), 1));
  fresh.close();
  const swapped = fs.readFileSync(other, 'utf8').split('\n');
  const lines = text.split('\n');
  fs.writeFileSync(file, [lines[0], lines[1], swapped[2], ''].join('\n'));

  assert.throws(open(file), /do not reproduce the root/);
});

test('4. an empty directory with a head file is refused', (t) => {
  const { file } = threeEntries(t);
  // The restored snapshot, and the half-finished copy: the head is there and
  // the entries are not.
  fs.rmSync(file);
  assert.throws(open(file), /replayed 0 entries but its last signed head covers 3/);
  // And the same one entry short.
  assert.throws(open(file), /refusing to sign a smaller history/);
});

test('5. KT_MIN_SIZE refuses what a lost disk takes with it', (t) => {
  const { file, headFile } = threeEntries(t);
  // An unmounted disk: the whole directory is gone, head file included, so
  // there is nothing on disk left to be held to.
  fs.rmSync(file);
  fs.rmSync(headFile);
  // Without a floor this is indistinguishable from a brand-new log, and it
  // starts — which is the bug, and is why the floor is not on the disk.
  const empty = open(file)();
  assert.equal(empty.size, 0);
  empty.close();

  assert.throws(open(file, { minSize: 3 }), /KT_MIN_SIZE says at least 3/);
  // A floor, not an expected size: a log past it is fine.
  fs.writeFileSync(file, threeEntries(t).text);
  const fine = open(file, { minSize: 2 })();
  assert.equal(fine.size, 3);
  fine.close();
});

test('a memory store has nothing to come back to, and says so by being quiet', () => {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  log.publish(publishFor(account('alice'), 1));
  assert.equal(log.size, 1);
  // No head file, no floor, no throw: ephemeral mode is development only and
  // the server already warns about it.
  assert.equal(log.store.readHead(), null);
});
