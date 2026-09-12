'use strict';

// What the relay holds for one reconnecting device. A device that has been
// away collects a backlog — up to `MAX_QUEUE_BYTES_PER_USER`, 64 MB — and on
// reconnect the relay used to read all of it and write all of it into that
// one socket in a single pass: on a 512 MB instance (render.ha.yaml runs two
// of those) a handful of such reconnects at once is the whole machine, and a
// device on a slow link holds its whole backlog in the relay's memory for as
// long as it takes to read. The flush now goes out in pages of `FLUSH_PAGE`
// and waits between them until the socket has drained below
// `FLUSH_HIGH_WATER_BYTES`, so what the relay holds is the mark plus the one
// envelope that crossed it — whatever the backlog.
//
// Criteria 1 to 3 were written with 64 KB envelopes, and passed for the wrong
// reason: FLUSH_PAGE alone kept a page of those small, so they never tested
// the byte bound they claimed. `MAX_ENVELOPE_BYTES` is 1 MB, and against
// envelopes that size the relay buffered 58 MB of a 64 MB backlog — a page
// counted entries, not bytes (roadmap revision 45). Criteria 4 and 5 use
// envelopes large enough that the count bound alone cannot save them.
//
// The caps are lowered here so the bound is small and the test is quick;
// everything else is the relay's default. The client stops reading by pausing
// its TCP socket, which is what a slow link does to the relay.
//
// Criteria, each asserted below:
//  1. RAM mode: against a reader that has stopped reading, the relay's
//     buffered output for that socket stays at the bound rather than growing
//     to the backlog, and when the reader resumes it receives every envelope,
//     in order;
//  2. Redis mode: the same, and the relay reads the entries from the store a
//     page at a time rather than all at once;
//  3. a socket that goes away mid-flush ends the flush (nothing is queued
//     into a dead socket, and the entries stay for the next connection);
//  4. RAM mode, envelopes at the envelope cap: the bound still holds, so it
//     is the bytes that bound a page and not the entry count;
//  5. Redis mode: the same, where the sizes are not known until the bodies
//     are read.

process.env.FLUSH_PAGE = process.env.FLUSH_PAGE || '8';
process.env.FLUSH_HIGH_WATER_BYTES = process.env.FLUSH_HIGH_WATER_BYTES || '65536';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, CFG, routingIdFromPub } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');
// 64 KB payloads: a backlog of 300 is ~19 MB, against a bound of
// 8 × 64 KB + 64 KB ≈ 590 KB.
const KB64 = 'zs1.' + 'x'.repeat(64 * 1024 - 4); // sealed-looking: acked by id alone
const BACKLOG = 300;
const BOUND = CFG.flushHighWaterBytes + CFG.flushPage * 70 * 1024;
// Criteria 4 and 5: envelopes at `MAX_ENVELOPE_BYTES`, the size the finding
// was measured at, and a backlog several times larger than a loopback socket
// can swallow — otherwise the kernel absorbs the whole flush and no bound is
// exercised at all. A page of FLUSH_PAGE of these is 8 MB: measured here,
// the count-only bound leaves 4.8 MB in the relay's socket and the byte
// bound 1.0 MB.
const BIG = 'zs1.' + 'x'.repeat(CFG.maxEnvelopeBytes - 4);
const BIG_N = 16;
const BIG_BOUND = CFG.flushHighWaterBytes + CFG.maxEnvelopeBytes + 64 * 1024;

function hasRedisServer() {
  return spawnSync('redis-server', ['--version']).status === 0;
}
function hasIoredis() {
  try {
    require.resolve('ioredis');
    return true;
  } catch {
    return false;
  }
}
const SKIP_REDIS = !hasRedisServer() || !hasIoredis();

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}
function freePort() {
  return new Promise((res, rej) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const p = srv.address().port;
      srv.close(() => res(p));
    });
    srv.on('error', rej);
  });
}
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

class Client {
  constructor(port, identity) {
    this.identity = identity;
    this.frames = [];
    this.waiters = [];
    this.msgs = [];
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('error', () => {});
    this.ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
      if (f.t === 'msg') this.msgs.push(f);
      const i = this.waiters.findIndex((w) => w.pred(f));
      if (i !== -1) this.waiters.splice(i, 1)[0].resolve(f);
      else this.frames.push(f);
    });
  }
  next(pred, timeoutMs = 5000) {
    const i = this.frames.findIndex(pred);
    if (i !== -1) return Promise.resolve(this.frames.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout')), timeoutMs);
      this.waiters.push({ pred, resolve: (f) => (clearTimeout(t), resolve(f)) });
    });
  }
  send(o) {
    this.ws.send(JSON.stringify(o));
  }
  async auth() {
    const ch = await this.next((f) => f.t === 'challenge');
    const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, Buffer.from(ch.nonce, 'base64')]), this.identity.privateKey);
    this.send({ t: 'auth', pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    await this.next((f) => f.t === 'ready');
    return this;
  }
  async deliver(id, to, payload) {
    this.send({ t: 'send', id, to, payload });
    return this.next((f) => (f.t === 'sent' || f.t === 'error') && f.id === id);
  }
  /** Stop reading from the wire, the way a slow link does. */
  pause() {
    this.ws._socket.pause();
  }
  resume() {
    this.ws._socket.resume();
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

/** Fills `rid`'s mailbox with `n` copies of `payload`, from enough senders to stay under the rate limit. */
async function fillWith(port, rid, payload, n) {
  const senders = [];
  for (let i = 0; i < Math.ceil(n / 200); i++) senders.push(await new Client(port, makeIdentity()).auth());
  for (let i = 0; i < n; i++) {
    const r = await senders[i % senders.length].deliver(`m${i}`, rid, payload);
    assert.strictEqual(r.t, 'sent', JSON.stringify(r));
  }
  return senders;
}

/** Fills `rid`'s mailbox with BACKLOG envelopes of 64 KB. */
function fill(port, rid) {
  return fillWith(port, rid, KB64, BACKLOG);
}

/**
 * Watches the relay's buffered bytes for `rid`'s socket while `settled`
 * resolves; returns the peak seen. `wss` is the relay's own server, so this
 * is the relay's memory, not the test's.
 */
async function peakBuffered(wss, until) {
  let peak = 0;
  let done = false;
  until.then(() => (done = true));
  while (!done) {
    for (const ws of wss.clients) peak = Math.max(peak, ws.bufferedAmount);
    await sleep(10);
  }
  return peak;
}

test('1. RAM: a reader that stops reading costs the relay one page, not its backlog', async (t) => {
  const srv = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(() => {
    for (const ws of srv.wss.clients) ws.terminate();
    srv.httpServer.close();
  });

  const bob = makeIdentity();
  const senders = await fill(port, bob.rid);

  // Bob connects and immediately stops reading. The flush starts; the relay
  // must stop filling the socket once the buffer is over the mark.
  const b = new Client(port, bob);
  await b.auth();
  b.pause();
  const peak = await peakBuffered(srv.wss, sleep(2500));
  assert.ok(
    peak < BOUND,
    `the relay buffered ${(peak / 1048576).toFixed(1)} MB for one paused reader; the bound is ${(BOUND / 1048576).toFixed(1)} MB and the backlog ${(BACKLOG * 64) / 1024} MB`
  );
  assert.ok(peak > 0, 'the flush did start');
  t.diagnostic(`peak buffered ${(peak / 1024).toFixed(0)} KB of a ${(BACKLOG * 64) / 1024} MB backlog`);

  // Reading again finishes the flush, in order, with nothing missing.
  b.resume();
  const deadline = Date.now() + 30_000;
  while (b.msgs.length < BACKLOG && Date.now() < deadline) await sleep(50);
  assert.strictEqual(b.msgs.length, BACKLOG, 'every envelope arrived once the reader resumed');
  assert.deepStrictEqual(
    b.msgs.map((f) => f.id),
    Array.from({ length: BACKLOG }, (_, i) => `m${i}`),
    'in order'
  );
  senders.forEach((s) => s.close());
  b.close();
});

test('2. Redis: the same bound, and the store is read a page at a time', { skip: SKIP_REDIS && 'redis-server/ioredis unavailable' }, async (t) => {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  await sleep(700);
  const url = `redis://127.0.0.1:${redisPort}`;
  const IORedis = require('ioredis');
  const raw = new IORedis(url);
  const coord = new RedisCoordinator(url, 'instA');
  const srv = createServer({ coordinator: coord, pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(async () => {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
    await coord.close();
    try {
      await raw.quit();
    } catch {}
    redis.kill('SIGKILL');
  });

  const bob = makeIdentity();
  const senders = await fill(port, bob.rid);
  const outBefore = +/total_net_output_bytes:(\d+)/.exec(await raw.info('stats'))[1];

  const b = new Client(port, bob);
  await b.auth();
  b.pause();
  const peak = await peakBuffered(srv.wss, sleep(2500));
  assert.ok(peak < BOUND, `the relay buffered ${(peak / 1048576).toFixed(1)} MB; the bound is ${(BOUND / 1048576).toFixed(1)} MB`);
  // The store has not been asked for the whole backlog either: a paused
  // reader stops the pages, so the bytes read so far are a fraction of it.
  const readSoFar = +/total_net_output_bytes:(\d+)/.exec(await raw.info('stats'))[1] - outBefore;
  const backlogBytes = BACKLOG * 64 * 1024;
  assert.ok(
    readSoFar < backlogBytes / 2,
    `read ${(readSoFar / 1048576).toFixed(1)} MB from the store for a paused reader with a ${(backlogBytes / 1048576).toFixed(0)} MB backlog`
  );
  t.diagnostic(`paused reader: relay buffered ${(peak / 1024).toFixed(0)} KB, read ${(readSoFar / 1048576).toFixed(1)} MB of ${(backlogBytes / 1048576).toFixed(0)} MB from the store`);

  b.resume();
  const deadline = Date.now() + 60_000;
  while (b.msgs.length < BACKLOG && Date.now() < deadline) await sleep(50);
  assert.strictEqual(b.msgs.length, BACKLOG);
  assert.deepStrictEqual(b.msgs.map((f) => f.id), Array.from({ length: BACKLOG }, (_, i) => `m${i}`), 'in order');
  senders.forEach((s) => s.close());
  b.close();
});

test('3. a socket that goes away mid-flush ends the flush, and its envelopes wait for the next connection', async (t) => {
  const srv = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  const { _internal } = require('../server.js');
  t.after(() => {
    for (const ws of srv.wss.clients) ws.terminate();
    srv.httpServer.close();
  });

  const bob = makeIdentity();
  const senders = await fill(port, bob.rid);
  const b = new Client(port, bob);
  await b.auth();
  b.pause();
  await sleep(300); // a page or two out, the rest waiting on the mark
  b.ws.terminate();
  await sleep(500);
  // Nothing was acked, so the mailbox is intact for the next connection —
  // at-least-once delivery, as §12.5 says.
  assert.strictEqual(_internal.queues.get(bob.rid).entries.length, BACKLOG);
  const sockets = [...srv.wss.clients].filter((ws) => ws.readyState === ws.OPEN);
  assert.ok(
    sockets.every((ws) => ws.bufferedAmount < BOUND),
    'no socket is still being filled'
  );

  // And the next connection gets everything.
  const b2 = new Client(port, bob);
  await b2.auth();
  const deadline = Date.now() + 30_000;
  while (b2.msgs.length < BACKLOG && Date.now() < deadline) await sleep(50);
  assert.strictEqual(b2.msgs.length, BACKLOG);
  senders.forEach((s) => s.close());
  b2.close();
});

test('4. RAM: envelopes the size of the cap are bounded by bytes, not by the count', async (t) => {
  const srv = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(() => {
    for (const ws of srv.wss.clients) ws.terminate();
    srv.httpServer.close();
  });

  const bob = makeIdentity();
  const senders = await fillWith(port, bob.rid, BIG, BIG_N);

  const b = new Client(port, bob);
  await b.auth();
  b.pause();
  const peak = await peakBuffered(srv.wss, sleep(2500));
  assert.ok(
    peak < BIG_BOUND,
    `the relay buffered ${(peak / 1048576).toFixed(1)} MB of a ${((BIG_N * BIG.length) / 1048576).toFixed(0)} MB backlog; the bound is ${(BIG_BOUND / 1048576).toFixed(1)} MB and a page of ${CFG.flushPage} of these would be ${((CFG.flushPage * BIG.length) / 1048576).toFixed(0)} MB`
  );
  assert.ok(peak > 0, 'the flush did start');
  t.diagnostic(`peak buffered ${(peak / 1024).toFixed(0)} KB of a ${((BIG_N * BIG.length) / 1048576).toFixed(0)} MB backlog`);

  b.resume();
  const deadline = Date.now() + 30_000;
  while (b.msgs.length < BIG_N && Date.now() < deadline) await sleep(50);
  assert.strictEqual(b.msgs.length, BIG_N, 'every envelope arrived once the reader resumed');
  assert.deepStrictEqual(
    b.msgs.map((f) => f.id),
    Array.from({ length: BIG_N }, (_, i) => `m${i}`),
    'in order'
  );
  senders.forEach((s) => s.close());
  b.close();
});

test('5. Redis: the same, where a body’s size is not known until it is read', { skip: SKIP_REDIS && 'redis-server/ioredis unavailable' }, async (t) => {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  await sleep(700);
  const url = `redis://127.0.0.1:${redisPort}`;
  const coord = new RedisCoordinator(url, 'instA');
  const srv = createServer({ coordinator: coord, pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(async () => {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
    await coord.close();
    redis.kill('SIGKILL');
  });

  const bob = makeIdentity();
  const senders = await fillWith(port, bob.rid, BIG, BIG_N);

  const b = new Client(port, bob);
  await b.auth();
  b.pause();
  const peak = await peakBuffered(srv.wss, sleep(2500));
  assert.ok(
    peak < BIG_BOUND,
    `the relay buffered ${(peak / 1048576).toFixed(1)} MB of a ${((BIG_N * BIG.length) / 1048576).toFixed(0)} MB backlog; the bound is ${(BIG_BOUND / 1048576).toFixed(1)} MB`
  );
  assert.ok(peak > 0, 'the flush did start');
  t.diagnostic(`peak buffered ${(peak / 1024).toFixed(0)} KB of a ${((BIG_N * BIG.length) / 1048576).toFixed(0)} MB backlog`);

  b.resume();
  const deadline = Date.now() + 60_000;
  while (b.msgs.length < BIG_N && Date.now() < deadline) await sleep(50);
  assert.strictEqual(b.msgs.length, BIG_N);
  assert.deepStrictEqual(b.msgs.map((f) => f.id), Array.from({ length: BIG_N }, (_, i) => `m${i}`), 'in order');
  senders.forEach((s) => s.close());
  b.close();
});
