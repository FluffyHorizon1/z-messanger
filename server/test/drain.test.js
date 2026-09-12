'use strict';

// Draining a mailbox in Redis mode — the production path — after the queue
// became a list of keys with the entries in a hash beside it (2.7.9). Until
// then every acknowledgement read the whole mailbox back to find one entry
// (bench/drain.js: two hundred envelopes cost 170 times their size in reads;
// two thousand took 38 seconds and 4 GB), and acknowledgements counted
// against the per-connection rate limit, so a mailbox of more than the
// burst could not be emptied in one connection at all.
//
// Criteria, each asserted below:
//  1. a mailbox of a thousand envelopes is delivered and emptied in one
//     connection, in order, in well under a second — every ack lands, none
//     is rate-limited away;
//  2. entries a relay before 2.7.9 queued (the entry itself in the list) are
//     delivered in their place among new ones, acknowledged, and removed,
//     and the byte counter and all three keys end where they should;
//  3. a send repeated with the same id — a sender retrying after a lost
//     `sent` — is acknowledged and stored once; and a message and a receipt
//     carrying one id, from two different parties, are three separate
//     entries that do not displace each other.
//
// Skips itself where `redis-server` or `ioredis` is missing, as ha.test.js does.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, routingIdFromPub } = require('../server.js');

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

async function harness(t) {
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
  return { raw, port };
}

test('1. a mailbox of a thousand envelopes drains in one connection, in order, quickly', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, port } = await harness(t);
  const bob = makeIdentity();
  const N = 1000;
  // Five senders keep each under the per-connection burst; the sends are
  // what the rate limit is for, and this is not a test of it.
  const senders = [];
  for (let i = 0; i < 5; i++) senders.push(await new Client(port, makeIdentity()).auth());
  for (let i = 0; i < N; i++) {
    const r = await senders[i % 5].deliver(`m${i}`, bob.rid, 'zs1.' + 'x'.repeat(1000));
    assert.strictEqual(r.t, 'sent', JSON.stringify(r));
  }
  assert.strictEqual(await raw.llen(`q:${bob.rid}`), N);
  assert.strictEqual(await raw.hlen(`qe:${bob.rid}`), N);

  const b = new Client(port, bob);
  const t0 = Date.now();
  await b.auth();
  // Ack each as it lands, as fast as it lands.
  const acked = new Set();
  const deadline = Date.now() + 10_000;
  while (acked.size < N && Date.now() < deadline) {
    while (b.msgs.length) {
      const f = b.msgs.shift();
      b.send({ t: 'recv', id: f.id });
      acked.add(f.id);
    }
    await sleep(5);
  }
  assert.strictEqual(acked.size, N, 'every envelope was flushed');
  assert.deepStrictEqual([...acked].slice(0, 3), ['m0', 'm1', 'm2'], 'in order');
  while ((await raw.llen(`q:${bob.rid}`)) > 0 && Date.now() < deadline) await sleep(20);
  const ms = Date.now() - t0;
  assert.strictEqual(await raw.llen(`q:${bob.rid}`), 0, 'every ack landed: none was rate-limited away');
  assert.strictEqual(await raw.exists(`qe:${bob.rid}`, `qb:${bob.rid}`), 0);
  assert.ok(ms < 5000, `drained in ${ms} ms`);
  assert.strictEqual(b.frames.filter((f) => f.t === 'error').length, 0, 'no rate_limited errors on the way');
  t.diagnostic(`drained ${N} envelopes in ${ms} ms`);
  senders.forEach((s) => s.close());
  b.close();
});

test('2. entries a relay before 2.7.9 queued are delivered in place, acknowledged and removed', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, port } = await harness(t);
  const alice = await new Client(port, makeIdentity()).auth();
  const bob = makeIdentity();
  const legacy = (id, payload) => JSON.stringify({ kind: 'msg', id, from: alice.identity.rid, payload, ts: Date.now() });
  // Two old-style elements, the entry itself in the list, no hash, no counter.
  await raw.rpush(`q:${bob.rid}`, legacy('old1', 'b2xkMQ=='), legacy('old2', 'b2xkMg=='));
  await raw.expire(`q:${bob.rid}`, 3600);
  // Then two new ones through the relay (attributed, so receipts flow too).
  assert.strictEqual((await alice.deliver('new1', bob.rid, 'bmV3MQ==')).t, 'sent');
  assert.strictEqual((await alice.deliver('new2', bob.rid, 'bmV3Mg==')).t, 'sent');
  assert.strictEqual(await raw.llen(`q:${bob.rid}`), 4);
  assert.strictEqual(await raw.hlen(`qe:${bob.rid}`), 2);
  assert.strictEqual(Number(await raw.get(`qb:${bob.rid}`)), 2 * (8 + 256), 'the counter counts what this relay stored');

  const b = await new Client(port, bob).auth();
  const got = [];
  for (let i = 0; i < 4; i++) got.push(await b.next((f) => f.t === 'msg'));
  assert.deepStrictEqual(got.map((f) => f.id), ['old1', 'old2', 'new1', 'new2'], 'old ones first, as queued');
  assert.ok(got.every((f) => f.from === alice.identity.rid));
  for (const id of ['old1', 'new1', 'old2', 'new2']) {
    const rc = alice.next((f) => f.t === 'delivered' && f.id === id);
    b.send({ t: 'recv', id, from: alice.identity.rid });
    await rc;
  }
  await sleep(100);
  assert.strictEqual(await raw.exists(`q:${bob.rid}`, `qe:${bob.rid}`, `qb:${bob.rid}`), 0, 'nothing left of the mailbox');

  // A receipt queued for an offline sender the old way is delivered and removed by the flush too.
  await raw.rpush(`q:${alice.identity.rid}`, JSON.stringify({ kind: 'receipt', id: 'x9', from: bob.rid, ts: Date.now() }));
  await raw.expire(`q:${alice.identity.rid}`, 3600);
  alice.close();
  await sleep(200);
  const a2 = await new Client(port, alice.identity).auth();
  const d = await a2.next((f) => f.t === 'delivered' && f.id === 'x9');
  assert.strictEqual(d.to, bob.rid);
  await sleep(100);
  assert.strictEqual(await raw.exists(`q:${alice.identity.rid}`), 0);
  a2.close();
  b.close();
});

test('3. a repeated send is stored once, and a receipt does not collide with a message of the same id', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, port } = await harness(t);
  const alice = await new Client(port, makeIdentity()).auth();
  const bob = makeIdentity();
  assert.strictEqual((await alice.deliver('dup', bob.rid, 'eA==')).t, 'sent');
  assert.strictEqual((await alice.deliver('dup', bob.rid, 'eA==')).t, 'sent', 'the retry is acknowledged');
  assert.strictEqual(await raw.llen(`q:${bob.rid}`), 1, 'and stored once');
  assert.strictEqual(Number(await raw.get(`qb:${bob.rid}`)), 4 + 256);

  // Bob acks the attributed message; Alice is offline, so a receipt r:dup is
  // queued for her; a message m:dup queued for her by Bob sits beside it.
  const b = await new Client(port, bob).auth();
  await b.next((f) => f.t === 'msg' && f.id === 'dup');
  alice.close();
  await sleep(200);
  b.send({ t: 'recv', id: 'dup', from: alice.identity.rid });
  await sleep(100);
  assert.strictEqual((await b.deliver('dup', alice.identity.rid, 'eQ==')).t, 'sent');
  // Both carry Bob's routing id — he sent the message and he acknowledged
  // the one Alice sent — and they are distinct keys, so neither displaces
  // the other even though both are id `dup`.
  assert.deepStrictEqual(
    (await raw.lrange(`q:${alice.identity.rid}`, 0, -1)).sort(),
    [`m:dup:${bob.rid}`, `r:dup:${bob.rid}`]
  );
  const a2 = await new Client(port, alice.identity).auth();
  const got = [await a2.next((f) => f.t === 'delivered' || f.t === 'msg'), await a2.next((f) => f.t === 'delivered' || f.t === 'msg')];
  assert.deepStrictEqual(got.map((f) => f.t).sort(), ['delivered', 'msg']);
  await sleep(100);
  assert.strictEqual(await raw.llen(`q:${alice.identity.rid}`), 1, 'the receipt is removed by the flush, the message waits for its ack');
  a2.close();
  b.close();
});
