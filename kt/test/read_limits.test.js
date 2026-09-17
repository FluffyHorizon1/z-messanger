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
//   4. and `/history` pages the same way, with `start` — at a quarter of the
//      size, because it is the page every client walks for its own label;
//   5. and — the 2026-09-14 review's finding 18 — the RATE at which the
//      mirrors' page can be asked for is bounded too, in bytes a minute per
//      address and in total, because a page bounded at four megabytes that
//      could be asked for at will was a 46-byte request returning 3.9 MiB
//      (measured, 89,000:1) with nothing in front able to absorb a repeat. A
//      reader over the budget is told 429 with `retry-after` before anything
//      is built. What is NOT charged is as much the point: the head, the
//      key, health, a consistency proof, a lookup and a label's history are
//      never refused by a budget, because behind a front that sets no
//      client-address header every reader is one address, and a budget an
//      attacker can spend on a route a client's check depends on is a
//      cheaper denial than the one being fixed;
//   6. the two answers that never change — a page below the head, a
//      consistency proof — say a cache may hold them; an empty page, a
//      lookup, a history and the head do not;
//   7. and the mirror's fetch waits out a 429 for as long as `retry-after`
//      says and asks again, so a first sync of a large log paces itself at
//      the budget instead of failing every five minutes for ever.

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
const { createServer, MAX_PAGE_BYTES, MAX_HISTORY_PAGE_BYTES } = require('../server.js');
const { makeFetchJson, retryAfterMs } = require('../lib/mirror.js');

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

async function start(log, opts = {}) {
  const { httpServer } = createServer({ log, ...opts });
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  return {
    port: httpServer.address().port,
    get: async (p) => {
      const r = await fetch(base + p);
      return {
        status: r.status,
        bytes: Buffer.byteLength(await r.clone().text()),
        body: await r.json(),
        cache: r.headers.get('cache-control'),
        retryAfter: r.headers.get('retry-after'),
      };
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
    // 4. bounded — at the history page's own, smaller, size, plus the one
    // entry that is always served — and the reader can tell.
    assert.ok(MAX_HISTORY_PAGE_BYTES < MAX_PAGE_BYTES / 4, 'a history page is a fraction of an entries page');
    assert.ok(first.bytes <= MAX_HISTORY_PAGE_BYTES + 512 * 1024, `${first.bytes} bytes`);
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

test('5. the entries page is budgeted in bytes a minute, per address and in total; nothing a client needs is', async (t) => {
  const log = fileLog(t);
  const a = account('reader');
  for (let v = 1; v <= 12; v++) log.publish(bigPublish(a, v, 8 * 1024));
  const hex = a.label.toString('hex');
  // A budget three and a half pages deep at this page size. The fourth
  // page is served — the request that crosses zero is, by design, because
  // the size is only known once the response is built — and leaves the
  // bucket half a page in debt; the fifth is refused, and told how long
  // until the debt has refilled. The clock is frozen so the arithmetic is
  // exact, and then moved by hand to check that `retry-after` was honest.
  const probe = await start(log);
  const pageBytes = (await probe.get('/kt/v1/entries?start=0&count=4')).bytes;
  await probe.stop();
  const budget = Math.round(pageBytes * 3.5);
  const debt = 4 * pageBytes - budget;
  const waitMs = Math.ceil(((1 + debt) / budget) * 60_000);
  const retryAfter = Math.ceil(waitMs / 1000);
  assert.ok(retryAfter >= 8 && retryAfter <= 9, `half a page of a 3.5-page minute is ${retryAfter} s`);
  let frozen = Date.now();
  const s = await start(log, { readBytesPerMinute: budget, now: () => frozen });
  try {
    let served = 0;
    let refused = null;
    for (let i = 0; i < 8; i++) {
      const r = await s.get('/kt/v1/entries?start=0&count=4');
      if (r.status === 200) served += 1;
      else {
        assert.equal(r.status, 429);
        assert.equal(r.body.error, 'rate_limited');
        assert.equal(Number(r.retryAfter), retryAfter, 'told exactly how long the debt takes to refill');
        refused = i;
        break;
      }
    }
    assert.equal(served, 4, 'the budget is what it says, and the crossing request is served');
    assert.equal(refused, 4, 'and the one after it is refused before it is built');

    // Everything a client's check touches still answers, with the entries
    // budget spent: the head, the key, health, a consistency proof, a
    // lookup, and the label's history. This is the property that makes the
    // budget safe to ship behind a front that sets no client-address header
    // — where every reader is one address and the budget is one budget.
    assert.equal((await s.get('/kt/v1/sth')).status, 200);
    assert.equal((await s.get('/kt/v1/pub')).status, 200);
    assert.equal((await s.get('/health')).status, 200);
    assert.equal((await s.get('/kt/v1/consistency?first=2&second=12')).status, 200);
    assert.equal((await s.get(`/kt/v1/lookup/${hex}`)).status, 200);
    const h = await s.get(`/kt/v1/history/${hex}`);
    assert.equal(h.status, 200);
    assert.equal(h.body.total, 12, 'the whole history is reachable while the page budget is spent');

    // The budget refills with the clock, and `retry-after` was honest: a
    // second short is still refused, the second it named is served.
    frozen += (retryAfter - 1) * 1000;
    assert.equal((await s.get('/kt/v1/entries?start=0&count=4')).status, 429, 'a second early is still in debt');
    frozen += 1000;
    assert.equal((await s.get('/kt/v1/entries?start=0&count=4')).status, 200, 'served again once the debt has refilled');
  } finally {
    await s.stop();
  }

  // The total: a second address does not get a budget of its own past it.
  // Addresses are told apart by a header here, as they are behind a proxy
  // that sets one; without the header the two below would be one address
  // anyway, which is the point the doc makes.
  const t2 = await start(log, {
    readBytesPerMinute: pageBytes * 100,
    readBytesPerMinuteTotal: pageBytes * 2,
    clientIpHeader: 'x-test-ip',
    now: () => frozen,
  });
  try {
    const port = t2.port;
    const as = async (ip) => (await fetch(`http://127.0.0.1:${port}/kt/v1/entries?start=0&count=4`, { headers: { 'x-test-ip': ip } })).status;
    assert.equal(await as('10.0.0.1'), 200);
    assert.equal(await as('10.0.0.2'), 200);
    assert.equal(await as('10.0.0.3'), 429, 'the log has served what it will this minute, whoever asks');
    assert.equal(await as('10.0.0.1'), 429);
    assert.equal((await t2.get(`/kt/v1/lookup/${hex}`)).status, 200, 'and a lookup is still not what it bounds');
  } finally {
    await t2.stop();
  }
});

test('6. what a cache in front may hold: a page below the head and a consistency proof, nothing that moves', async (t) => {
  const log = fileLog(t);
  const a = account('cached');
  for (let v = 1; v <= 12; v++) log.publish(bigPublish(a, v, 1024));
  const hex = a.label.toString('hex');
  const c = await start(log);
  try {
    assert.equal((await c.get('/kt/v1/entries?start=0&count=2')).cache, 'public, max-age=60', 'a page below the head is the same page for ever');
    assert.equal((await c.get('/kt/v1/entries?start=10&count=100')).cache, 'public, max-age=60', 'a short page at the head is a prefix of every later one');
    assert.equal((await c.get('/kt/v1/entries?start=12&count=100')).cache, 'no-store', 'an empty page is what the next request past the head must not be handed');
    assert.equal((await c.get('/kt/v1/consistency?first=2&second=12')).cache, 'public, max-age=60');
    assert.equal((await c.get('/kt/v1/sth')).cache, 'no-store', 'the head moves');
    assert.equal((await c.get(`/kt/v1/lookup/${hex}`)).cache, 'no-store', 'a lookup is relative to the head it was served under');
    assert.equal((await c.get(`/kt/v1/history/${hex}`)).cache, 'no-store', 'so is a history');
    assert.equal((await c.get('/kt/v1/entries?start=x')).cache, 'no-store', 'an error is never cached');
  } finally {
    await c.stop();
  }
});

test("7. the mirror's fetch waits out a 429 for as long as retry-after says, and gives up after a bounded number", async () => {
  // A log that says "not yet" twice, then answers.
  const waits = [];
  const sleep = async (ms) => waits.push(ms);
  const answers = [
    { ok: false, status: 429, headers: new Headers({ 'retry-after': '7' }) },
    { ok: false, status: 429, headers: new Headers({ 'retry-after': '3' }) },
    { ok: true, status: 200, headers: new Headers(), json: async () => ({ entries: [1] }) },
  ];
  let calls = 0;
  const fetchImpl = async () => answers[calls++];
  const fetchJson = makeFetchJson({ fetch: fetchImpl, sleep });
  assert.deepEqual(await fetchJson('http://log/kt/v1/entries?start=0&count=500'), { entries: [1] });
  assert.equal(calls, 3, 'asked until answered');
  assert.deepEqual(waits, [7000, 3000], 'and waited exactly what it was told, each time');

  // A retry-after it cannot read is a second; a huge one is bounded; nothing
  // waits less than a second, so a log that says 0 is not polled in a loop.
  assert.equal(retryAfterMs(null), 1000);
  assert.equal(retryAfterMs('soon'), 1000);
  assert.equal(retryAfterMs('0'), 1000);
  assert.equal(retryAfterMs('2.2'), 3000);
  assert.equal(retryAfterMs('86400'), 60_000);

  // Any other status is the error it always was, at once.
  const notFound = makeFetchJson({ fetch: async () => ({ ok: false, status: 404, headers: new Headers() }), sleep });
  await assert.rejects(notFound('http://log/x'), /HTTP 404/);

  // And a 429 that never lifts is given up on after `retries` waits — the
  // sync fails as a transport error and the next scheduled one starts over,
  // rather than a socket held open for ever.
  let asked = 0;
  const never = makeFetchJson({
    fetch: async () => (asked++, { ok: false, status: 429, headers: new Headers({ 'retry-after': '1' }) }),
    sleep: async () => {},
    retries: 3,
  });
  await assert.rejects(never('http://log/x'), /HTTP 429/);
  assert.equal(asked, 4, 'the first ask and three retries');
});
