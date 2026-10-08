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
//
// And three more, from the 2026-10-03 analysis, about the two ways a head
// came to be wrong without anybody deciding it should be:
//   6. `tools/repair.js` signs nothing. It opened the file with a throwaway
//      key, and a file with no head beside it was given one — signed by
//      `Buffer.alloc(32, 1)` — which the log then refused to start against
//      as a head somebody else wrote. Now a repaired file with no head gets
//      none, and the log records its own, with its own key, at its next
//      start; a file with a head keeps it byte for byte;
//   7. a WHOLE-disk snapshot, restored, is refused. Criterion 4's snapshot
//      lost the entries and kept the head; a whole-disk one brings the head
//      back with the entries, the two consistent and both out of date, and
//      under KT_MIN_SIZE=1 the log signed on from it — a fork for every
//      client and witness holding a later head. A start whose last recorded
//      head is older than `maxHeadAgeMs` is refused, says what to check, and
//      starts only when KT_CONFIRM_HEAD names exactly that head; a
//      confirmation names one head, so it does not wave through a later one;
//   8. and a log that runs keeps that evidence current, so the ordinary
//      restart is never refused: the head is re-recorded every `resignMs`
//      and at a clean stop. Nor is the first start after the upgrade, whose
//      head an older build wrote at its last publish, hours ago on a quiet
//      day, without the promise to keep it current: that start records one
//      that carries the promise, and the check holds from there on.

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
const { verifyConsistency } = require('../lib/merkle.js');
const repair = require('../tools/repair.js');

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

/** A head file's record, as the log's own types. */
function headOf(rec) {
  return {
    size: rec.size,
    logRoot: Buffer.from(rec.logRoot, 'base64'),
    mapRoot: Buffer.from(rec.mapRoot, 'base64'),
    ts: rec.ts,
    sig: Buffer.from(rec.sig, 'base64'),
  };
}

/** tools/repair.js, quietly; its exit code. */
function runRepair(args) {
  const out = console.log;
  const err = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    return repair.main(['node', 'repair.js', ...args]);
  } finally {
    console.log = out;
    console.error = err;
  }
}

test('6. a repair signs nothing: no head is planted, and one that is there is left alone', (t) => {
  const { file, headFile, text } = threeEntries(t);
  // A file with no head beside it — an older build's, or one whose head went
  // missing — ending in the torn line an older build left.
  fs.rmSync(headFile);
  fs.writeFileSync(file, text + '{"i":3,"label":"ab');
  assert.equal(runRepair([file, '--write']), 0, 'the tail is dropped and the file replays');
  assert.equal(fs.readFileSync(file, 'utf8'), text);
  assert.ok(!fs.existsSync(headFile), 'and no head was written: the tool holds none of the log\'s keys');

  // The log starts — it used to refuse, against the head the repair had
  // signed with `Buffer.alloc(32, 1)` — and the head it records is its own.
  const log = open(file)();
  assert.equal(log.size, 3);
  log.close();
  const rec = JSON.parse(fs.readFileSync(headFile, 'utf8'));
  assert.ok(verifySth(headOf(rec), rawPublicKey(logKey)), 'the only head on disk is one the log signed');

  // With a head beside it, a repair leaves the head exactly as it found it.
  const before = fs.readFileSync(headFile);
  fs.appendFileSync(file, '{"i":3,"lab');
  assert.equal(runRepair([file, '--write']), 0);
  assert.deepEqual(fs.readFileSync(headFile), before, 'byte for byte');
  const again = open(file)();
  assert.equal(again.size, 3);
  again.close();

  // And a log opened without its key cannot be made to sign or accept.
  const ro = new KtLog({ store: new FileStore(file), signingKey: null });
  assert.equal(ro.size, 3, 'it replays and checks everything');
  assert.throws(() => ro.sth(), /without its key/);
  assert.throws(() => ro.publish(publishFor(account('carol'), 1)), /without its key/);
  assert.equal(ro.keepAlive({ force: true }), false);
  ro.close();
  assert.deepEqual(fs.readFileSync(headFile), before, 'still byte for byte');
});

test('7. a whole-disk snapshot, restored, is refused until the head it brought back is named', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const headFile = `${file}.head.json`;
  const HOUR = 3_600_000;
  let clock = Date.now() - 5 * HOUR;
  const now = () => clock;
  // KT_MIN_SIZE=1, as the reference Blueprint ships, and the server's default
  // KT_MAX_HEAD_AGE_MIN.
  const opts = { minSize: 1, maxHeadAgeMs: 30 * 60_000, now };
  const start = (extra = {}) => new KtLog({ store: new FileStore(file), signingKey: logKey, ...opts, ...extra });

  // A deployment's first start (the floor is set after it), three publishes,
  // and the platform's nightly snapshot of the whole disk.
  const first = new KtLog({ store: new FileStore(file), signingKey: logKey, now });
  const alice = account('alice');
  for (let v = 1; v <= 3; v++) first.publish(publishFor(alice, v));
  const snapshot = { entries: fs.readFileSync(file), head: fs.readFileSync(headFile) };
  const snapTs = JSON.parse(snapshot.head.toString('utf8')).ts;
  // An hour on, two more, and a client — or a witness — holds the head that
  // covers them.
  clock += HOUR;
  const bob = account('bob');
  first.publish(publishFor(bob, 1));
  first.publish(publishFor(bob, 2));
  const held = first.sth();
  assert.equal(held.size, 5);
  first.close();

  // The disk is lost; the snapshot comes back, head file and all.
  clock += HOUR;
  fs.writeFileSync(file, snapshot.entries);
  fs.writeFileSync(headFile, snapshot.head);

  // What every start was until 2026-10-04, on a copy: every floor passes —
  // the head matches the entries, there are more than KT_MIN_SIZE — and the
  // next head it signs is a fork of the one the client holds.
  {
    const copy = tmpdir(t);
    const cfile = path.join(copy, 'entries.jsonl');
    fs.writeFileSync(cfile, snapshot.entries);
    fs.writeFileSync(`${cfile}.head.json`, snapshot.head);
    const unchecked = new KtLog({ store: new FileStore(cfile), signingKey: logKey, minSize: 1, now });
    for (let v = 1; v <= 3; v++) unchecked.publish(publishFor(account('carol'), v));
    const next = unchecked.sth();
    assert.ok(next.size > held.size);
    const proof = unchecked.consistency(held.size, next.size);
    assert.equal(
      verifyConsistency({ first: held.size, second: next.size, firstRoot: held.logRoot, secondRoot: next.logRoot, proof }),
      false,
      'a head under the real key that does not extend the one the client holds'
    );
    unchecked.close();
  }

  // Now: what gives a whole-disk snapshot away is the time.
  assert.throws(
    () => start(),
    (e) =>
      /recorded is .* old \(size 3, ts \d+\)/.test(e.message) &&
      e.message.includes(`KT_CONFIRM_HEAD=3@${snapTs}`) &&
      /restored disk snapshot/.test(e.message)
  );
  assert.deepEqual(fs.readFileSync(headFile), snapshot.head, 'and the refusal wrote nothing over the evidence');

  // A confirmation naming any other head confirms nothing.
  assert.throws(() => start({ confirmHead: { size: 3, ts: snapTs + 1 } }), /names a different head/);
  assert.throws(() => start({ confirmHead: { size: 5, ts: snapTs } }), /names a different head/);

  // Naming exactly this one — once somebody has checked that nothing ever saw
  // more than 3 — starts it, and the head on disk is then this start's.
  const resumed = start({ confirmHead: { size: 3, ts: snapTs } });
  assert.equal(resumed.size, 3);
  assert.equal(JSON.parse(fs.readFileSync(headFile, 'utf8')).ts, clock, 'recorded at this start');
  resumed.close();

  // Which is why a confirmation left in the environment is harmless: hours
  // later the log is stopped long enough to need one again, and the old one
  // names a head that is no longer there.
  clock += 3 * HOUR;
  assert.throws(() => start({ confirmHead: { size: 3, ts: snapTs } }), /names a different head/);
});

test('8. a log that runs keeps that evidence current, so an ordinary restart is never refused', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const headFile = `${file}.head.json`;
  let clock = Date.now();
  const now = () => clock;
  const opts = { maxHeadAgeMs: 30 * 60_000, resignMs: 10 * 60_000, now };
  const headTs = () => JSON.parse(fs.readFileSync(headFile, 'utf8')).ts;

  const log = new KtLog({ store: new FileStore(file), signingKey: logKey, ...opts });
  log.publish(publishFor(account('alice'), 1));
  // Two quiet hours, the server's timer asking every minute: the head is
  // re-recorded once it is `resignMs` old, and not before.
  let writes = 0;
  let last = headTs();
  for (let m = 1; m <= 120; m++) {
    clock += 60_000;
    log.keepAlive();
    const ts = headTs();
    if (ts !== last) writes += 1;
    last = ts;
    assert.ok(clock - ts < opts.resignMs, `minute ${m}: the head on disk is under resignMs old`);
  }
  assert.ok(writes >= 11 && writes <= 13, `${writes} writes in two hours, not one a minute`);

  // A crash: no clean stop (closing the store records nothing). The restart,
  // minutes later, is within reach of the last record and starts without a
  // word.
  log.close();
  clock += 5 * 60_000;
  const restarted = new KtLog({ store: new FileStore(file), signingKey: logKey, ...opts });
  assert.equal(restarted.size, 1);

  // A clean stop records the head whatever its age, so a deploy's restart is
  // measured from the moment the old process stopped.
  clock += 3 * 60_000;
  assert.equal(restarted.keepAlive({ force: true }), true);
  assert.equal(headTs(), clock);
  restarted.close();
  clock += 20 * 60_000;
  const deployed = new KtLog({ store: new FileStore(file), signingKey: logKey, ...opts });
  assert.equal(deployed.size, 1, 'twenty minutes after a clean stop: not refused');
  deployed.close();

  // The upgrade. The build before this one wrote its head only at a publish,
  // and wrote no `everyMs`: on a quiet day the live log's head is hours old
  // when this version first starts, and that age says nothing.
  const upgraded = tmpdir(t);
  const ufile = path.join(upgraded, 'entries.jsonl');
  const uhead = `${ufile}.head.json`;
  const quiet = clock - 6 * 3_600_000;
  const before = new KtLog({ store: new FileStore(ufile), signingKey: logKey, now: () => quiet });
  before.publish(publishFor(account('quiet'), 1));
  before.close();
  const older = JSON.parse(fs.readFileSync(uhead, 'utf8'));
  delete older.everyMs; // what the older build wrote
  fs.writeFileSync(uhead, JSON.stringify(older));
  const first = new KtLog({ store: new FileStore(ufile), signingKey: logKey, ...opts });
  assert.equal(first.size, 1, 'a six-hour-old head from the older build is not refused');
  first.close();
  const current = JSON.parse(fs.readFileSync(uhead, 'utf8'));
  assert.equal(current.ts, clock, 'it recorded a current head at once');
  assert.equal(current.everyMs, opts.resignMs, 'carrying the promise the check relies on');
  // And from there the check holds: the same six hours, on a head that made
  // the promise, is refused.
  clock += 6 * 3_600_000;
  assert.throws(() => new KtLog({ store: new FileStore(ufile), signingKey: logKey, ...opts }), /KT_CONFIRM_HEAD=1@/);
});

test('a memory store has nothing to come back to, and says so by being quiet', () => {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  log.publish(publishFor(account('alice'), 1));
  assert.equal(log.size, 1);
  // No head file, no floor, no throw: ephemeral mode is development only and
  // the server already warns about it.
  assert.equal(log.store.readHead(), null);
});
