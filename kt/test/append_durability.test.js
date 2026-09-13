'use strict';

// `fs.writeSync` may write a PREFIX and return how much, without throwing.
//
// Measured on this machine before anything was changed: one `writeSync` of a
// 1 MiB buffer to a pipe returned 65536 and raised nothing. The log's append
// ignored that number. So the line on disk ended mid-JSON, `append` returned
// a byte range for bytes that were never written, `publish` carried on and
// mutated both trees, and the client was answered 201 with a signed head
// committing to an entry the log does not hold. The next start then died on
// "a torn write?" — for ever, because the following append takes its offset
// from the file's size and splices itself onto the unterminated line.
//
// One short write, and the log never opens again. That is the whole bug: the
// clean ENOSPC path always threw and was always safe.
//
// What is asserted below:
//   1. a write that only partly lands leaves the file exactly as it was, and
//      throws — so the trees are never mutated and no head is signed over an
//      entry that is not on disk;
//   2. the log carries on afterwards: the next publish writes a whole line
//      and the file replays to the same heads, which is what says the
//      rollback was a rollback and not a second kind of damage;
//   3. a file damaged by an older build is repairable, and the repair drops
//      only the trailing partial line;
//   4. and a repair refuses a file whose damage is inside a complete line,
//      because dropping whole entries to make a log start is a rewrite of
//      the history rather than a repair.

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
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
} = require('../lib/log.js');
const repair = require('../tools/repair.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('append durability').digest());

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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kt-append-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('a write that only partly lands writes nothing and throws', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  t.after(() => log.close());

  const a = account('alice');
  const b = account('bob');
  log.publish(publishFor(a, 1));
  log.publish(publishFor(b, 1));
  const before = fs.readFileSync(file);
  const head = log.sth();
  assert.equal(log.size, 2);

  // The real failure, not a file rewritten afterwards. `writeSync` lands only
  // its first 32 bytes and says so — exactly as the measured 1 MiB write
  // returned 65536, raising nothing — and then the disk fills, which is when
  // a partial write actually happens.
  const real = fs.writeSync;
  let calls = 0;
  fs.writeSync = (fd, buf, off, len, ...rest) => {
    if (!Buffer.isBuffer(buf) || buf.length <= 64) return real(fd, buf, off, len, ...rest);
    calls += 1;
    if (calls === 1) return real(fd, buf, off ?? 0, 32, ...rest);
    const e = new Error('no space left on device');
    e.code = 'ENOSPC';
    throw e;
  };
  t.after(() => {
    fs.writeSync = real;
  });

  assert.throws(() => log.publish(publishFor(a, 2)), /ENOSPC|no space/);
  assert.equal(calls, 2, 'it wrote what it could, then met the failure');
  fs.writeSync = real;

  // 1. The file is byte-for-byte what it was.
  assert.deepEqual(fs.readFileSync(file), before, 'the partial line was rolled back');
  // And nothing in memory moved either: no third leaf, no new head.
  assert.equal(log.size, 2, 'the trees were never told');
  const after = log.sth();
  assert.equal(after.size, 2);
  assert.ok(after.logRoot.equals(head.logRoot), 'the head still commits to two entries');
  assert.equal(log.latest(a.label).version, 1, 'and the refused version was not recorded');

  // 2. The log carries on, and the file it leaves behind opens.
  const ok = log.publish(publishFor(a, 2));
  assert.equal(ok.index, 2);
  log.close();
  const again = new KtLog({ store: new FileStore(file), signingKey: logKey });
  t.after(() => again.close());
  assert.equal(again.size, 3, 'three whole lines, no torn one between them');
  assert.equal(again.latest(a.label).version, 2);
  assert.ok(again.sth().logRoot.equals(log.sth().logRoot));
});

test('a short write that can be finished is finished', (t) => {
  // The other half, and the common one: the kernel took 32 bytes and will
  // take the rest on the next call. Before the loop this line went to disk
  // with its tail missing and the log never opened again; the right answer
  // is not to refuse it but to write the rest.
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  t.after(() => log.close());
  const a = account('alice');
  log.publish(publishFor(a, 1));

  const real = fs.writeSync;
  let chunks = 0;
  fs.writeSync = (fd, buf, off, len, ...rest) => {
    if (Buffer.isBuffer(buf) && buf.length > 64 && len > 32) {
      chunks += 1;
      return real(fd, buf, off ?? 0, 32, ...rest);
    }
    return real(fd, buf, off, len, ...rest);
  };
  t.after(() => {
    fs.writeSync = real;
  });
  const e = log.publish(publishFor(a, 2));
  fs.writeSync = real;
  assert.equal(e.index, 1);
  assert.ok(chunks > 1, `the line took ${chunks} writes`);

  log.close();
  const again = new KtLog({ store: new FileStore(file), signingKey: logKey });
  t.after(() => again.close());
  assert.equal(again.size, 2, 'and every line is whole');
  assert.equal(again.latest(a.label).version, 2);
});

test('the first line is durable by its name as well as its bytes', (t) => {
  // fsyncing a file does not make the directory entry naming it durable, and
  // the first append is also the file's creation. A log that lost that entry
  // came back with no file — which `readAll` reads as an empty log (ENOENT
  // yields nothing), so it would have begun signing a fresh history with the
  // production key rather than refusing.
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  // Driven against the store rather than through `publish`, because
  // recording a head writes a second file and syncs the directory for that
  // too — which is right, and would hide what this is about: whether
  // APPENDING syncs the directory, and whether it does it once.
  const store = new FileStore(file);
  t.after(() => store.close());
  const real = FileStore.prototype._syncDir;
  let dirSyncs = 0;
  FileStore.prototype._syncDir = function patched() {
    dirSyncs += 1;
    return real.call(this);
  };
  t.after(() => {
    FileStore.prototype._syncDir = real;
  });

  const entry = (name, v, i) => {
    const acct = account(name);
    const p = publishFor(acct, v);
    return { index: i, label: labelFor(p.acct), version: v, fp: p.fp, valueHash: sha256(p.value), value: p.value, acct: p.acct, sig: p.sig, ts: 1 };
  };
  store.append(entry('first', 1, 0));
  assert.equal(dirSyncs, 1, 'the file was created, so its name was made durable');
  store.append(entry('second', 1, 1));
  assert.equal(dirSyncs, 1, 'and only then — not once per append');
  FileStore.prototype._syncDir = real;
});

test('a file an older build tore is repairable, and only at the tail', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  const a = account('alice');
  log.publish(publishFor(a, 1));
  log.publish(publishFor(a, 2));
  const whole = fs.readFileSync(file, 'utf8');
  log.close();

  // What an older build left behind: a line that starts and never finishes.
  fs.writeFileSync(file, whole + '{"i":2,"label":"ab');
  assert.throws(() => new KtLog({ store: new FileStore(file), signingKey: logKey }), /torn write/);

  // 3. Reported without --write, and nothing touched.
  const sizeBefore = fs.statSync(file).size;
  assert.equal(repair.main(['node', 'repair.js', file]), 0);
  assert.equal(fs.statSync(file).size, sizeBefore, 'a report writes nothing');

  assert.equal(repair.main(['node', 'repair.js', file, '--write']), 0);
  assert.equal(fs.readFileSync(file, 'utf8'), whole, 'exactly the partial line went');
  const back = new KtLog({ store: new FileStore(file), signingKey: logKey });
  t.after(() => back.close());
  assert.equal(back.size, 2);
  // The dropped bytes were kept, so the repair is not the only copy of them.
  const kept = fs.readdirSync(dir).filter((f) => f.includes('.partial-'));
  assert.equal(kept.length, 1);
  assert.equal(fs.readFileSync(path.join(dir, kept[0]), 'utf8'), '{"i":2,"label":"ab');
});

test('a repair refuses damage that is inside a complete line', (t) => {
  const dir = tmpdir(t);
  const file = path.join(dir, 'entries.jsonl');
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  const a = account('alice');
  log.publish(publishFor(a, 1));
  log.publish(publishFor(a, 2));
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  log.close();

  // A whole line, edited: the value no longer matches its hash. The log
  // refuses to open, and it should stay refusing — dropping the line would
  // make it start by forgetting an entry it committed to.
  const j = JSON.parse(lines[1]);
  j.val = crypto.randomBytes(40).toString('base64');
  fs.writeFileSync(file, [lines[0], JSON.stringify(j), ''].join('\n'));
  assert.throws(() => new KtLog({ store: new FileStore(file), signingKey: logKey }), /value hash/);

  const size = fs.statSync(file).size;
  // 4. Non-zero: it did not repair anything, and says why.
  assert.equal(repair.main(['node', 'repair.js', file, '--write']), 1);
  assert.equal(fs.statSync(file).size, size, 'and it changed nothing');
  assert.throws(() => new KtLog({ store: new FileStore(file), signingKey: logKey }), /value hash/);
});
