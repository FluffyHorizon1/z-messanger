// The log used to hold the whole of itself, twice.
//
// `FileStore.readAll` read `entries.jsonl` into one JavaScript string, and
// `KtLog._apply` kept every entry — `value` included — in `this.entries` for
// the life of the process. So a replay's peak was the file plus the parsed
// copy of it, and the resident set afterwards was a multiple of the file
// rather than a function of the number of entries. At the 256 KiB value cap
// one entry was 256 KiB of heap for ever, and the trees need none of it:
// they commit to `leafHash`, and the hash is 32 bytes.
//
// Two ways that ends a live log. On a 512 MB instance the ceiling is tens of
// megabytes of file, after which the process OOMs during replay on EVERY
// start — permanently, because the file it cannot read is the file it must
// read to start. And a file past V8's ~512 MB string limit cannot be read at
// all by this reader, which made the 1 GB disk it is deployed on more than
// twice the largest file its own code could open.
//
// The fix is not a bigger instance. A fixed read window with a carried
// remainder has a peak of one chunk plus the longest line whatever the file
// weighs, and an entry keeps the byte range of its own line instead of its
// value, so serving one is a read rather than a residency.
//
// What is asserted below:
//   1. replaying a file of many large values costs far less than the file —
//      the number the old code could not produce;
//   2. the values come back byte for byte anyway, through every route that
//      serves one, after a restart that never held them;
//   3. lines that straddle the read window are not lost or joined — the one
//      thing a chunked reader gets wrong;
//   4. and every corruption the file reader is supposed to refuse is still
//      refused, including a last line with no newline.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  KtLog,
  FileStore,
  labelFor,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  sealValue,
} = require('../lib/log.js');
const { sha256 } = require('../lib/merkle.js');

const logKey = privateKeyFromSeed(Buffer.alloc(32, 7));

function account(seed) {
  const key = privateKeyFromSeed(sha256(Buffer.from(seed, 'utf8')));
  const pub = rawPublicKey(key);
  return { key, pub, label: labelFor(pub) };
}

/** A publish whose sealed value is `bytes` long — up to the 256 KiB cap. */
function bigPublish(acct, version, bytes) {
  const plaintext = crypto.randomBytes(bytes - 28); // nonce + tag
  const value = sealValue(acct.pub, plaintext);
  const p = makePublish(acct.key, { version, fp: crypto.randomBytes(16), value });
  return { acct: acct.pub, version: p.version, fp: p.fp, value: p.value, sig: p.sig };
}

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'z-ktmem-'));
}

// Collect before measuring. `heapUsed` counts floating garbage, and parsing
// sixteen megabytes of JSON makes a great deal of it — enough to swamp the
// difference between holding the values and not. What is being asked here is
// what the log RETAINS, which is exactly what survives a collection.
const v8 = require('node:v8');
const vm = require('node:vm');
v8.setFlagsFromString('--expose_gc');
const gc = vm.runInNewContext('gc');
v8.setFlagsFromString('--no-expose_gc');

function retained() {
  gc();
  gc();
  // heap AND external: a `value` is a Buffer, and a Buffer over a few
  // kilobytes lives outside V8's heap. `heapUsed` alone reports 0.1 MiB
  // whether the values are retained or not, which is a measurement that
  // cannot fail — and this is the number the whole patch is about.
  const m = process.memoryUsage();
  return m.heapUsed + m.external;
}

test('a replay costs a fraction of the file, and serves it anyway', () => {
  const dir = tempDir();
  const file = path.join(dir, 'entries.jsonl');
  const t = 1_700_000_000_000;
  const now = () => t;

  // 64 entries of 192 KiB: about 16 MB of values, in a file of about 17 MB
  // once base64 and JSON are paid for. Deliberately lopsided — the old code
  // held all of it and then some, the new code holds none of it, and no
  // measurement this blunt has to be precise to tell those apart.
  const COUNT = 64;
  const VALUE_BYTES = 192 * 1024;
  const written = [];
  {
    const log = new KtLog({ store: new FileStore(file), signingKey: logKey, now });
    for (let i = 0; i < COUNT; i++) {
      const a = account(`filler-${i}`);
      const p = bigPublish(a, 1, VALUE_BYTES);
      log.publish(p);
      written.push({ label: a.label, value: p.value });
    }
    log.close();
  }
  const fileBytes = fs.statSync(file).size;
  assert.ok(fileBytes > COUNT * VALUE_BYTES, `the fixture is ${fileBytes} bytes`);

  // 1a. The first entry arrives without the file having been read. This is
  // the half that a measurement of what replay LEAVES cannot see: a reader
  // that materialises the file and then hands back small entries retains
  // little and is still the reader that cannot open a file past V8's string
  // ceiling. Pulling one entry is the cheapest way to ask which one this is.
  {
    const store = new FileStore(file);
    const at = retained();
    const it = store.readAll();
    const first = it.next().value;
    const cost = retained() - at;
    assert.equal(first.index, 0);
    assert.ok(
      cost < fileBytes / 4,
      `reading one entry cost ${(cost / 1048576).toFixed(1)} MiB of a ` +
        `${(fileBytes / 1048576).toFixed(1)} MiB file`
    );
    it.return();
    store.close();
  }

  // 1b. Replay, and measure what it left behind.
  const before = retained();
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey, now });
  const grew = retained() - before;
  assert.equal(log.size, COUNT);
  // Printed whether it passes or not: when a bound like this fails, the
  // numbers are the whole diagnosis.
  console.log(
    `        file ${(fileBytes / 1048576).toFixed(1)} MiB, ` +
      `values ${((COUNT * VALUE_BYTES) / 1048576).toFixed(1)} MiB, ` +
      `retained after replay +${(grew / 1048576).toFixed(1)} MiB`
  );
  assert.ok(
    grew < (COUNT * VALUE_BYTES) / 4,
    `replaying a ${(fileBytes / 1048576).toFixed(1)} MiB file retained ` +
      `${(grew / 1048576).toFixed(1)} MiB; holding the values would be at least ` +
      `${((COUNT * VALUE_BYTES) / 1048576).toFixed(1)}`
  );

  // 2. And the values are still there, through every route that serves one.
  for (const w of written) {
    const got = log.lookup(w.label);
    assert.ok(got.entry.value.equals(w.value), 'lookup');
    assert.ok(sha256(got.entry.value).equals(got.entry.valueHash));
    const hist = log.history(w.label);
    assert.ok(hist.entries[0].entry.value.equals(w.value), 'history');
  }
  const page = log.range(0, COUNT);
  assert.equal(page.entries.length, COUNT);
  for (let i = 0; i < COUNT; i++) {
    assert.ok(page.entries[i].value.equals(written[i].value), `range ${i}`);
  }
  log.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('lines that straddle the read window are read whole', () => {
  const dir = tempDir();
  const file = path.join(dir, 'entries.jsonl');
  const now = () => 1_700_000_000_000;

  // A 512-byte window, and sizes chosen so that lines land on both sides of
  // one and a line spans it — a line longer than the whole window included,
  // which is the case a carried remainder exists for. A chunked reader that
  // gets this wrong either loses an entry or joins two.
  //
  // The window has to be shrunk to reach it: a value is capped at 256 KiB, so
  // at the real 1 MiB window no line can be longer than a chunk and this
  // would be a test of nothing.
  const chunk = { chunkBytes: 512 };
  const sizes = [100, 300, 40, 900, 100, 2000, 60, 100];
  const written = [];
  {
    const log = new KtLog({ store: new FileStore(file, chunk), signingKey: logKey, now });
    for (let i = 0; i < sizes.length; i++) {
      const a = account(`straddle-${i}`);
      const p = bigPublish(a, 1, sizes[i]);
      log.publish(p);
      written.push({ label: a.label, value: p.value, index: i });
    }
    log.close();
  }

  const log = new KtLog({ store: new FileStore(file, chunk), signingKey: logKey, now });
  assert.equal(log.size, sizes.length);
  for (const w of written) {
    const got = log.lookup(w.label);
    assert.equal(got.entry.index, w.index);
    assert.ok(got.entry.value.equals(w.value), `entry ${w.index} came back different`);
  }
  log.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a file the reader must refuse is still refused', () => {
  const dir = tempDir();
  const file = path.join(dir, 'entries.jsonl');
  const now = () => 1_700_000_000_000;
  const a = account('alice');
  const b = account('bob');
  {
    const log = new KtLog({ store: new FileStore(file), signingKey: logKey, now });
    log.publish(bigPublish(a, 1, 400));
    log.publish(bigPublish(b, 1, 400));
    log.close();
  }
  const text = fs.readFileSync(file, 'utf8');
  const lines = text.split('\n');
  const open = () => new KtLog({ store: new FileStore(file), signingKey: logKey, now });

  fs.writeFileSync(file, text + '{"i":2,"label":"ab');
  assert.throws(open, /torn write/, 'a last line with no newline');
  fs.writeFileSync(file, [lines[0], '', lines[1], ''].join('\n'));
  assert.throws(open, /blank line/, 'a blank line inside the file');
  fs.writeFileSync(file, [lines[0], 'not json at all', ''].join('\n'));
  assert.throws(open, /not JSON/, 'a line that is not JSON');
  fs.writeFileSync(file, [lines[1], ''].join('\n'));
  assert.throws(open, /where 0 was expected/, 'a missing first entry');
  fs.writeFileSync(file, text);
  assert.equal(open().size, 2, 'and the intact file still opens');
  fs.rmSync(dir, { recursive: true, force: true });
});
