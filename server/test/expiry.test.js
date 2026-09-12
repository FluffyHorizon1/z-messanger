'use strict';

// `QUEUE_TTL_HOURS` (72) is a promise the documents make per envelope:
// "undelivered envelopes vanish on expiry" (PROTOCOL §12.5), "until
// delivered, until TTL, or until the store restarts" (DATA_MAP). In RAM mode
// that was true and untested. In Redis mode it was not true: the TTL sat on
// the mailbox's keys and every new push refreshed it, so a mailbox that kept
// receiving — a deleted account whose contacts keep writing — held its
// OLDEST envelopes for as long as anything arrived, up to the cap. Expiry is
// now per entry, from the head of the queue, at every flush and from a
// periodic sweep.
//
// Criteria, each asserted below:
//  1. Redis mode: a mailbox that keeps receiving still loses the envelopes
//     that have outlived the TTL, and keeps the fresh ones — by the sweep,
//     and by the flush, with the byte counter settled and the keys removed
//     when nothing is left;
//  2. Redis mode: entries a relay before 2.7.9 queued expire the same way, a
//     key whose body is gone is dropped, and the walk stops at the first
//     fresh entry rather than reordering the queue;
//  3. RAM mode: the sweep expires per entry and the byte count follows.
//
// The Redis halves skip themselves where `redis-server` or `ioredis` is
// missing, as ha.test.js does.

process.env.QUEUE_TTL_HOURS = process.env.QUEUE_TTL_HOURS || '1';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, MemoryCoordinator, CFG, routingIdFromPub } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

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
const SKIP = !hasRedisServer() || !hasIoredis();

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
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

async function redisHarness(t) {
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
  return { raw, port, coord };
}

/** An entry as the relay stores it, stamped `ageMs` in the past. */
function entryAged(id, from, payload, ageMs) {
  return JSON.stringify({ kind: 'msg', id, from, payload, ts: Date.now() - ageMs, size: payload.length + 256 });
}

test('1. Redis: a mailbox that keeps receiving still expires what has outlived the TTL', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, port, coord } = await redisHarness(t);
  const alice = await new Client(port, makeIdentity()).auth();
  const bob = makeIdentity();
  const stale = CFG.queueTtlMs + 60_000;

  // Three envelopes that have outlived the TTL, written as the relay writes
  // them, then two fresh ones through the relay itself — which refreshes the
  // keys' own TTL, the thing that used to keep the old ones alive.
  const old = ['o1', 'o2', 'o3'];
  for (const id of old) {
    await raw.rpush(`q:${bob.rid}`, `m:${id}`);
    await raw.hset(`qe:${bob.rid}`, `m:${id}`, entryAged(id, alice.identity.rid, 'b2xk', stale));
    await raw.incrby(`qb:${bob.rid}`, 4 + 256);
  }
  await raw.expire(`q:${bob.rid}`, CFG.queueTtlHours * 3600);
  assert.strictEqual((await alice.deliver('n1', bob.rid, 'bmV3')).t, 'sent');
  assert.strictEqual((await alice.deliver('n2', bob.rid, 'bmV3Mg==')).t, 'sent');
  assert.strictEqual(await raw.llen(`q:${bob.rid}`), 5);
  const bytesBefore = Number(await raw.get(`qb:${bob.rid}`));
  assert.strictEqual(bytesBefore, 3 * 260 + (4 + 256) + (8 + 256));

  // ---- the sweep: the three old ones go, the two fresh ones stay ----
  await coord.sweep();
  assert.deepStrictEqual(await raw.lrange(`q:${bob.rid}`, 0, -1), ['m:n1', 'm:n2']);
  assert.deepStrictEqual((await raw.hkeys(`qe:${bob.rid}`)).sort(), ['m:n1', 'm:n2']);
  assert.strictEqual(Number(await raw.get(`qb:${bob.rid}`)), bytesBefore - 3 * 260, 'the counter lost exactly the expired bytes');

  // ---- the flush: Bob receives only what is still fresh ----
  const b = await new Client(port, bob).auth();
  const got = [await b.next((f) => f.t === 'msg'), await b.next((f) => f.t === 'msg')];
  assert.deepStrictEqual(got.map((f) => f.id), ['n1', 'n2']);
  await assert.rejects(b.next((f) => f.t === 'msg', 300), /timeout/, 'nothing expired was delivered');

  // ---- a mailbox with nothing but expired entries loses its keys ----
  const carol = makeIdentity();
  await raw.rpush(`q:${carol.rid}`, 'm:x1');
  await raw.hset(`qe:${carol.rid}`, 'm:x1', entryAged('x1', alice.identity.rid, 'eA==', stale));
  await raw.incrby(`qb:${carol.rid}`, 260);
  await raw.expire(`q:${carol.rid}`, CFG.queueTtlHours * 3600);
  const c = await new Client(port, carol).auth(); // the flush expires first
  await assert.rejects(c.next((f) => f.t === 'msg', 300), /timeout/);
  assert.strictEqual(await raw.exists(`q:${carol.rid}`, `qe:${carol.rid}`, `qb:${carol.rid}`), 0);

  alice.close();
  b.close();
  c.close();
});

test('2. Redis: old-shape entries expire too, a body-less key is dropped, and the walk stops at the first fresh entry', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, port, coord } = await redisHarness(t);
  const alice = await new Client(port, makeIdentity()).auth();
  const bob = makeIdentity();
  const stale = CFG.queueTtlMs + 60_000;

  // In order: an entry a relay before 2.7.9 queued (the JSON itself in the
  // list, no hash, uncounted), a key whose body is missing, an expired
  // new-shape entry, then a FRESH old-shape entry, then an expired one
  // behind it. The walk must stop at the fresh one: a queue is in arrival
  // order and expiry must not reorder it.
  await raw.rpush(`q:${bob.rid}`, entryAged('legacy-old', alice.identity.rid, 'bDE=', stale));
  await raw.rpush(`q:${bob.rid}`, 'm:ghost');
  await raw.rpush(`q:${bob.rid}`, 'm:expired');
  await raw.hset(`qe:${bob.rid}`, 'm:expired', entryAged('expired', alice.identity.rid, 'ZXhw', stale));
  await raw.incrby(`qb:${bob.rid}`, 4 + 256);
  await raw.rpush(`q:${bob.rid}`, entryAged('legacy-fresh', alice.identity.rid, 'bDI=', 0));
  await raw.rpush(`q:${bob.rid}`, 'm:behind');
  await raw.hset(`qe:${bob.rid}`, 'm:behind', entryAged('behind', alice.identity.rid, 'YmVo', stale));
  await raw.incrby(`qb:${bob.rid}`, 4 + 256);
  await raw.expire(`q:${bob.rid}`, CFG.queueTtlHours * 3600);

  await coord.sweep();
  assert.deepStrictEqual(
    (await raw.lrange(`q:${bob.rid}`, 0, -1)).map((x) => (x.startsWith('{') ? JSON.parse(x).id : x)),
    ['legacy-fresh', 'm:behind'],
    'three head entries expired; the walk stopped at the fresh one and left what was behind it'
  );
  assert.strictEqual(Number(await raw.get(`qb:${bob.rid}`)), 4 + 256, 'only the counted expired entry came off the counter');
  assert.strictEqual(await raw.hexists(`qe:${bob.rid}`, 'm:expired'), 0, 'its body went with it');

  // The fresh old-shape entry is still delivered, and the one behind it
  // expires on the next sweep once it is at the head.
  const b = await new Client(port, bob).auth();
  const first = await b.next((f) => f.t === 'msg');
  assert.strictEqual(first.id, 'legacy-fresh');
  b.send({ t: 'recv', id: 'legacy-fresh', from: alice.identity.rid });
  await sleep(150);
  await coord.sweep();
  assert.strictEqual(await raw.exists(`q:${bob.rid}`), 0, 'the mailbox is empty and its keys are gone');

  alice.close();
  b.close();
});

test('3. RAM: the sweep expires per entry and the byte count follows', () => {
  const coord = new MemoryCoordinator();
  const rid = 'rid-ram';
  assert.strictEqual(coord._enqueue(rid, { seq: 1, kind: 'msg', id: 'a', from: null, payload: 'x', ts: Date.now() - CFG.queueTtlMs - 1000, size: 300 }), true);
  assert.strictEqual(coord._enqueue(rid, { seq: 2, kind: 'msg', id: 'b', from: null, payload: 'y', ts: Date.now(), size: 400 }), true);
  assert.strictEqual(coord.queues.get(rid).bytes, 700);
  coord.sweep();
  assert.deepStrictEqual(coord.queues.get(rid).entries.map((e) => e.id), ['b']);
  assert.strictEqual(coord.queues.get(rid).bytes, 400, 'the count is recomputed from what is left');
  // A mailbox with nothing fresh left is forgotten entirely.
  coord.queues.get(rid).entries[0].ts = Date.now() - CFG.queueTtlMs - 1000;
  coord.sweep();
  assert.strictEqual(coord.queues.has(rid), false);
});
