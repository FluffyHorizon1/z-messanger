'use strict';

// A read route with no byte cap is a permanent way to ask for the whole log.
//
// `count` never bounded these. A value may be 256 KiB, so `?count=1000` is
// ~333 MB built as one `JSON.stringify` string, and `/kt/v1/history/<label>`
// took no count at all: every version a label had ever published, at a fixed
// URL, repeatable by anyone, behind `cache-control: no-store` so nothing in
// front absorbs a repeat. That is the second half of a publish flood — the
// flood does not only grow the log, it mints a permanent way to pull all of
// it back out.
//
// The bound has to be in BYTES rather than entries, because an entry's size
// is chosen by whoever published it, and it has to be decided before any
// value is read back: `withValue` is a synchronous read per entry, so a cap
// applied after assembly would have already done the expensive half.
//
// What is asserted below:
//   1. a page of large entries is bounded by bytes, not by the count asked
//      for, and the entries it does carry are whole and in order;
//   2. `total` says how many there are, so a reader can tell a page from the
//      whole and ask for the rest — without it a short page is a log able to
//      hide an entry by being too big to serve;
//   3. a page is never empty while there is something to serve, because the
//      mirror treats an empty page as divergence and poisons itself;
//   4. and `/history` pages the same way, with `start`.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const {
  KtLog,
  MemoryStore,
  FileStore,
  labelFor,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  MAX_VALUE_BYTES,
} = require('../lib/log.js');
const { createServer, MAX_PAGE_BYTES } = require('../server.js');

const fs = require('fs');
const os = require('os');
const path = require('path');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('read limits').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

/** A publish whose sealed value is `bytes` long, near the permitted maximum. */
function bigPublish(acct, v, bytes) {
  const value = sealValue(acct.pub, crypto.randomBytes(bytes));
  const fp = crypto.createHash('sha256').update(`fp:${v}`).digest().subarray(0, 16);
  return makePublish(acct.key, { version: v, fp, value });
}

async function start(log) {
  const { httpServer } = createServer({ log });
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  return {
    get: async (p) => {
      const r = await fetch(base + p);
      return { status: r.status, bytes: Buffer.byteLength(await r.clone().text()), body: await r.json() };
    },
    stop: async () => {
      httpServer.closeAllConnections();
      await new Promise((res) => httpServer.close(res));
    },
  };
}

// A file store, because that is where the saving is: the size of an entry is
// read from the length of the line it was written as, so the entries that do
// not fit are never fetched off disk at all.
function fileLog(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kt-read-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const log = new KtLog({ store: new FileStore(path.join(dir, 'entries.jsonl')), signingKey: logKey });
  t.after(() => log.close());
  return log;
}

test('a page of big entries is bounded by bytes, not by the count asked for', async (t) => {
  const log = fileLog(t);
  // Twenty near-maximum values: ~6.8 MB of value, comfortably past the 4 MiB
  // budget and nowhere near the count cap.
  const size = MAX_VALUE_BYTES - 1024;
  for (let i = 0; i < 20; i++) log.publish(bigPublish(account(`big${i}`), 1, size));
  assert.equal(log.size, 20);

  const s = await start(log);
  try {
    const page = await s.get('/kt/v1/entries?count=1000');
    assert.equal(page.status, 200);
    // 1. bounded, and bounded in bytes.
    assert.ok(page.bytes <= MAX_PAGE_BYTES + 512 * 1024, `${page.bytes} bytes`);
    assert.ok(page.body.entries.length < 20, `${page.body.entries.length} of 20 entries`);
    assert.ok(page.body.entries.length >= 1, 'and not nothing');
    // Whole and in order: a short page is a prefix, never a sample.
    assert.deepEqual(
      page.body.entries.map((e) => e.index),
      page.body.entries.map((_, i) => i)
    );
    for (const e of page.body.entries) {
      assert.equal(Buffer.from(e.value, 'base64').length, size + 12 + 16, 'the value is not truncated');
    }
    // 2. and the reader is told there is more.
    assert.equal(page.body.total, 20);

    // The rest is reachable by asking from where the page stopped.
    const seen = new Set();
    for (let at = 0; at < 20; ) {
      const p = await s.get(`/kt/v1/entries?start=${at}&count=1000`);
      assert.ok(p.body.entries.length >= 1, `no progress at ${at}`);
      for (const e of p.body.entries) seen.add(e.index);
      at += p.body.entries.length;
    }
    assert.equal(seen.size, 20, 'every entry is reachable a page at a time');
  } finally {
    await s.stop();
  }
});

test('a single entry over the budget is still served, because an empty page is a fork to a mirror', async (t) => {
  const log = fileLog(t);
  // One value larger than the whole budget would be, if the budget could
  // refuse. `kt/lib/mirror.js` treats a page with no entries as divergence
  // and poisons itself permanently, so "too big to serve" must never be the
  // answer while the head says there is something there.
  const s0 = await start(log);
  try {
    log.publish(bigPublish(account('one'), 1, MAX_VALUE_BYTES - 1024));
    log.publish(bigPublish(account('two'), 1, MAX_VALUE_BYTES - 1024));
    const p = await s0.get('/kt/v1/entries?start=0&count=1');
    assert.equal(p.body.entries.length, 1);

    // The floor, asserted where it can actually be reached: a value is capped
    // at 256 KiB and the budget is 4 MiB, so no single entry can cross the
    // budget over HTTP — which is exactly why this is checked against the
    // library with a budget smaller than one entry. It is the invariant that
    // keeps the cap from becoming a fork the day either constant moves.
    assert.equal(log.range(0, 10, { maxBytes: 1 }).entries.length, 1, 'a page is never empty');
    assert.equal(log.range(1, 10, { maxBytes: 1 }).entries[0].index, 1, 'and it is the one asked for');
    const lbl = account('one').label;
    assert.equal(log.history(lbl, { maxBytes: 1 }).entries.length, 1, 'nor is a history page');
    assert.equal(log.range(0, 10, { maxBytes: 0 }).entries.length, 1, 'not even at zero');
    // 3. and past the end is still an empty page rather than an error, which
    // is what a mirror at the head's size reads.
    const past = await s0.get('/kt/v1/entries?start=9&count=10');
    assert.equal(past.status, 200);
    assert.deepEqual(past.body.entries, []);
  } finally {
    await s0.stop();
  }
});

test('history pages too, and says how many versions it has', async (t) => {
  const log = fileLog(t);
  const alice = account('history');
  const size = MAX_VALUE_BYTES - 1024;
  for (let v = 1; v <= 20; v++) log.publish(bigPublish(alice, v, size));
  // A second label, to prove `total` counts this label's versions and not
  // the log's size.
  log.publish(bigPublish(account('other'), 1, 1024));

  const s = await start(log);
  try {
    const hex = alice.label.toString('hex');
    const first = await s.get(`/kt/v1/history/${hex}`);
    assert.equal(first.status, 200);
    // 4. bounded, and the reader can tell.
    assert.ok(first.bytes <= MAX_PAGE_BYTES + 512 * 1024, `${first.bytes} bytes`);
    assert.equal(first.body.total, 20, "the label's versions, not the log's size");
    assert.equal(first.body.start, 0);
    assert.ok(first.body.entries.length < 20 && first.body.entries.length >= 1);
    assert.deepEqual(
      first.body.entries.map((x) => x.entry.v),
      first.body.entries.map((_, i) => i + 1),
      'oldest first, and contiguous'
    );

    // Walked to the end, a page at a time, every version is seen exactly once.
    const versions = [];
    for (let at = 0; at < first.body.total; ) {
      const p = await s.get(`/kt/v1/history/${hex}?start=${at}`);
      assert.ok(p.body.entries.length >= 1, `no progress at ${at}`);
      for (const x of p.body.entries) versions.push(x.entry.v);
      at += p.body.entries.length;
    }
    assert.deepEqual(versions, Array.from({ length: 20 }, (_, i) => i + 1));

    // An inclusion proof still verifies: paging changed which entries are in
    // the response, not what the head commits to.
    const { verifyInclusion } = require('../lib/merkle.js');
    const { entryFromJson, sthFromJson, inclusionFromJson, leafHashOf } = require('../lib/log.js');
    const sth = sthFromJson(first.body.sth);
    for (const x of first.body.entries) {
      const e = entryFromJson(x.entry);
      const i = inclusionFromJson(x.inclusion);
      assert.ok(verifyInclusion({ leafHash: leafHashOf(e), index: i.index, size: i.size, root: sth.logRoot, path: i.path }));
    }

    assert.equal((await s.get(`/kt/v1/history/${hex}?start=x`)).status, 400);
    assert.equal((await s.get(`/kt/v1/history/${hex}?count=0`)).status, 400);
    // Past the end: empty, not an error — an account that has never published
    // has an empty history and that is not a fault.
    assert.deepEqual((await s.get(`/kt/v1/history/${hex}?start=99`)).body.entries, []);
  } finally {
    await s.stop();
  }
});

test('a memory store is bounded too, where there is no line to measure', async (t) => {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  const size = MAX_VALUE_BYTES - 1024;
  for (let i = 0; i < 20; i++) log.publish(bigPublish(account(`mem${i}`), 1, size));
  const s = await start(log);
  try {
    const page = await s.get('/kt/v1/entries?count=1000');
    assert.ok(page.body.entries.length < 20, `${page.body.entries.length} of 20`);
    assert.ok(page.body.entries.length >= 1);
    assert.ok(page.bytes <= MAX_PAGE_BYTES + 512 * 1024, `${page.bytes} bytes`);
  } finally {
    await s.stop();
  }
});
