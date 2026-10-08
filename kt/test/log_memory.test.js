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
//
// And what DOES stay, from the 2026-10-03 analysis (P1-17). An entry keeps
// five small fields for the life of the process, decoded from base64 — and
// `Buffer.from(string, 'base64')` hands out slices of Node's shared 8 KiB
// pool, a slab that lives while any slice of it does. Between one entry's
// fields and the next, the map insert churns ~16 KB of transient pool, so
// every entry pinned about a slab of its own: 11.6 KB an entry, 9.5 of it
// slab; 376 MiB resident for the live log's 22,094 entries; a 512 MiB
// instance killed during the replay at ~39,000 — and on every restart.
// With the fields copied into an allocation of their own: 2.4 KB, 187 MiB,
// and the same instance reaches ~131,000 (bench/memory.js; measured in a
// real 512 MiB cgroup).
//   5. what replay keeps of an entry is its own — its five fields share one
//      allocation of exactly their size — and an entry costs a bounded few
//      kilobytes, which pinned slabs cannot meet;
//   6. the same for an entry that arrives over HTTP, whose fields the server
//      decodes from base64 into the same pool; and the value a memory store
//      keeps is its own too;
//   7. and the same for a mirror, on a sync and on a load, which decodes
//      what it keeps the same way.
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
  MemoryStore,
  labelFor,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  sealValue,
} = require('../lib/log.js');
const { sha256 } = require('../lib/merkle.js');
const { Mirror } = require('../lib/mirror.js');
const { createServer } = require('../server.js');

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

/**
 * [n] correctly signed entries with a real three-device list's sealed size,
 * written as the log writes its lines and with no head beside them: the log
 * records its own at its first start.
 */
function writeLines(file, n) {
  const lines = [];
  for (let i = 0; i < n; i++) {
    const a = account(`slab-${i}`);
    const value = sealValue(a.pub, crypto.randomBytes(1100 - 28));
    const fp = crypto.randomBytes(16);
    const p = makePublish(a.key, { version: 1, fp, value });
    lines.push(
      JSON.stringify({
        i,
        label: a.label.toString('base64'),
        v: 1,
        fp: fp.toString('base64'),
        vh: sha256(value).toString('base64'),
        val: value.toString('base64'),
        acct: a.pub.toString('base64'),
        ts: 1_700_000_000_000 + i,
        sig: p.sig.toString('base64'),
      })
    );
  }
  fs.writeFileSync(file, lines.join('\n') + '\n');
}

/**
 * The [fields] of [e] share one allocation of exactly their total size. A
 * slice of the shared pool sits in an 8 KiB slab, and keeps all of it.
 */
function assertOwned(e, fields, what) {
  const ab = e[fields[0]].buffer;
  const total = fields.reduce((n, f) => n + e[f].length, 0);
  for (const f of fields) assert.equal(e[f].buffer, ab, `${what}: ${f} is not in the entry's own allocation`);
  assert.equal(ab.byteLength, total, `${what}: its fields sit in ${ab.byteLength} bytes, not their own ${total}`);
}

const FIELDS = ['label', 'fp', 'valueHash', 'acct', 'sig'];

async function serve(log) {
  const { httpServer } = createServer({
    log,
    publishPerMinute: 1e6,
    publishPerMinuteTotal: 1e6,
    publishPerAccountPerDay: 1e6,
    newAccountsPerMinute: 1e6,
  });
  await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
  return {
    base: `http://127.0.0.1:${httpServer.address().port}`,
    stop: async () => {
      httpServer.closeAllConnections();
      await new Promise((r) => httpServer.close(r));
    },
  };
}

test('5. what a replay keeps of an entry is its own, and an entry costs a few kilobytes', () => {
  const dir = tempDir();
  const file = path.join(dir, 'entries.jsonl');
  const N = 1500;
  writeLines(file, N);
  const before = retained();
  const log = new KtLog({ store: new FileStore(file), signingKey: logKey });
  const per = (retained() - before) / N;
  assert.equal(log.size, N);
  // Printed whether it passes or not, like the replay above.
  console.log(`        ${N} entries replayed: ${(per / 1024).toFixed(2)} KB retained per entry`);
  for (const e of log.entries) assertOwned(e, FIELDS, `entry ${e.index}`);
  // The trees' share — every node's hash, the label's two map keys — is
  // ~2.1 KB of heap an entry and stays; the pinned slabs were ~9.5 KB more.
  assert.ok(per < 5 * 1024, `a replay retained ${(per / 1024).toFixed(2)} KB an entry; a slab pinned per entry is 8 KiB on its own`);
  log.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

/** POST a publish the way a client does: every field base64 in a JSON body. */
async function post(base, p) {
  const r = await fetch(`${base}/kt/v1/publish`, {
    method: 'POST',
    body: JSON.stringify({
      acct: p.acct.toString('base64'),
      v: p.version,
      fp: p.fp.toString('base64'),
      value: p.value.toString('base64'),
      sig: p.sig.toString('base64'),
    }),
  });
  return r.status;
}

test('6. so is what a publish over HTTP keeps, though the server decodes it into the shared pool', async () => {
  const dir = tempDir();
  const log = new KtLog({ store: new FileStore(path.join(dir, 'entries.jsonl')), signingKey: logKey });
  const s = await serve(log);
  try {
    for (let i = 0; i < 40; i++) assert.equal(await post(s.base, bigPublish(account(`http-${i}`), 1, 1100)), 201);
    for (const e of log.entries) assertOwned(e, FIELDS, `published entry ${e.index}`);
  } finally {
    await s.stop();
    log.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // A memory store keeps the value as well (development only), and that is
  // the log's own too.
  const mem = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  const m = await serve(mem);
  try {
    for (let i = 0; i < 5; i++) assert.equal(await post(m.base, bigPublish(account(`mem-${i}`), 1, 1100)), 201);
    for (const e of mem.entries) {
      assertOwned(e, FIELDS, `memory entry ${e.index}`);
      assert.equal(e.value.buffer.byteLength, e.value.length, `memory entry ${e.index}: the value is a slice of something larger`);
    }
  } finally {
    await m.stop();
  }
});

test('7. and so is what a mirror keeps, on a sync and on a load', async () => {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  for (let i = 0; i < 30; i++) log.publish(bigPublish(account(`mirror-${i}`), 1, 1100));
  const s = await serve(log);
  const dir = tempDir();
  try {
    const m = new Mirror({ dir, logUrl: s.base, logPub: log.publicKey, pageSize: 7 }).load();
    await m.sync();
    assert.equal(m.entries.length, 30);
    for (const e of m.entries) assertOwned(e, ['label', 'fp', 'valueHash'], `synced entry ${e.index}`);
    const again = new Mirror({ dir, logUrl: s.base, logPub: log.publicKey }).load();
    assert.equal(again.entries.length, 30);
    for (const e of again.entries) assertOwned(e, ['label', 'fp', 'valueHash'], `loaded entry ${e.index}`);
  } finally {
    await s.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
