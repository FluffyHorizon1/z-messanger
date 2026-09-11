'use strict';

// A recipient's queue has two caps, MAX_QUEUE_MSGS_PER_USER and
// MAX_QUEUE_BYTES_PER_USER, and this file pins what happens at them: the
// envelope that would cross a cap is REFUSED — the sender gets
// `error{queue_full, id}` and no `sent` — and everything accepted before it
// stays queued. Nothing is evicted. The same holds in RAM mode and across two
// relay instances sharing one Redis, where the byte cap used to be unenforced
// (a Redis LIST has a length, not a size) and is now a counter kept beside the
// list and settled in the same script as every push and removal.
//
// Both caps are lowered here so the cases are small; the relay is otherwise
// at its defaults. The Redis half skips itself where `redis-server` or
// `ioredis` is missing, as ha.test.js does.

process.env.MAX_QUEUE_BYTES_PER_USER = '5000';
process.env.MAX_QUEUE_MSGS_PER_USER = '4';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, routingIdFromPub, _internal } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');
const BIG = 'x'.repeat(2000); // charged at 2 256 bytes: two fit under 5 000, a third does not
const SMALL = 'eA=='; // charged at 260

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

function get(port, path) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port, path }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve(body));
      })
      .on('error', reject);
  });
}

function metric(body, name) {
  const m = body.match(new RegExp(`^${name} (\\d+)$`, 'm'));
  return m ? Number(m[1]) : null;
}

class Client {
  constructor(port, identity) {
    this.identity = identity;
    this.frames = [];
    this.waiters = [];
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('error', () => {});
    this.ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
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
    const sig = crypto.sign(
      null,
      Buffer.concat([AUTH_CONTEXT, Buffer.from(ch.nonce, 'base64')]),
      this.identity.privateKey
    );
    this.send({
      t: 'auth',
      pub: this.identity.rawPub.toString('base64'),
      sig: sig.toString('base64'),
    });
    await this.next((f) => f.t === 'ready');
    return this;
  }
  /** Sends and resolves to the relay's answer for that id: `sent` or `error`. */
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

// ---------------------------------------------------------------------------
// RAM mode
// ---------------------------------------------------------------------------
test('RAM: the envelope that would cross a cap is refused, and nothing queued before it is lost', async (t) => {
  const { httpServer, wss } = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => httpServer.listen(port, '127.0.0.1', r));
  t.after(() => {
    for (const ws of wss.clients) ws.terminate(); // a failed assertion must not hang the run
    httpServer.close();
  });

  const alice = makeIdentity();
  const bob = makeIdentity(); // offline until later
  const carol = makeIdentity(); // never connects
  const a = await new Client(port, alice).auth();
  const refusedBefore = metric(await get(port, '/metrics'), 'z_refused_total');

  // Byte cap: two big envelopes fit, the third is refused, the two stay.
  assert.strictEqual((await a.deliver('m1', bob.rid, BIG)).t, 'sent');
  assert.strictEqual((await a.deliver('m2', bob.rid, BIG)).t, 'sent');
  const refused = await a.deliver('m3', bob.rid, BIG);
  assert.deepStrictEqual(refused, { t: 'error', code: 'queue_full', id: 'm3' });
  assert.deepStrictEqual(
    _internal.queues.get(bob.rid).entries.map((e) => e.id),
    ['m1', 'm2'],
    'the accepted envelopes are exactly what is queued'
  );
  assert.strictEqual(_internal.queues.get(bob.rid).bytes, 2 * (2000 + 256));

  // Count cap, independently: four small envelopes, the fifth refused.
  for (let i = 1; i <= 4; i++) {
    assert.strictEqual((await a.deliver(`c${i}`, carol.rid, SMALL)).t, 'sent');
  }
  assert.deepStrictEqual(await a.deliver('c5', carol.rid, SMALL), {
    t: 'error',
    code: 'queue_full',
    id: 'c5',
  });
  assert.deepStrictEqual(
    _internal.queues.get(carol.rid).entries.map((e) => e.id),
    ['c1', 'c2', 'c3', 'c4']
  );
  assert.strictEqual(metric(await get(port, '/metrics'), 'z_refused_total'), refusedBefore + 2);

  // An envelope no queue could hold is refused on an empty queue, and the
  // refusal leaves no queue behind — a flood of refusals cannot grow the map.
  const dave = makeIdentity();
  assert.deepStrictEqual(await a.deliver('d1', dave.rid, 'x'.repeat(4800)), {
    t: 'error',
    code: 'queue_full',
    id: 'd1',
  });
  assert.strictEqual(_internal.queues.has(dave.rid), false);

  // Bob drains: both queued envelopes arrive; an ack frees room, and the
  // next big envelope is accepted.
  const b = new Client(port, bob);
  await b.auth();
  const got = [await b.next((f) => f.t === 'msg'), await b.next((f) => f.t === 'msg')];
  assert.deepStrictEqual(got.map((f) => f.id).sort(), ['m1', 'm2']);
  const delivered = a.next((f) => f.t === 'delivered' && f.id === 'm1');
  b.send({ t: 'recv', id: 'm1', from: alice.rid });
  await delivered;
  assert.strictEqual(_internal.queues.get(bob.rid).bytes, 2000 + 256);
  const m4 = await a.deliver('m4', bob.rid, BIG);
  assert.strictEqual(m4.t, 'sent');
  assert.strictEqual(m4.queued, false); // Bob is online: handed to his socket
  assert.strictEqual((await b.next((f) => f.t === 'msg' && f.id === 'm4')).id, 'm4');

  a.close();
  b.close();
});

// ---------------------------------------------------------------------------
// Redis mode, two instances
// ---------------------------------------------------------------------------
test(
  'Redis: the byte cap holds across two instances, the counter follows every push and removal, and old entries cannot break it',
  { skip: SKIP_REDIS && 'redis-server/ioredis unavailable' },
  async (t) => {
    const redisPort = await freePort();
    const redis = spawn(
      'redis-server',
      ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'],
      { stdio: 'ignore' }
    );
    await sleep(700);
    const url = `redis://127.0.0.1:${redisPort}`;
    const IORedis = require('ioredis');
    const raw = new IORedis(url);

    const coordA = new RedisCoordinator(url, 'instA');
    const coordB = new RedisCoordinator(url, 'instB');
    const srvA = createServer({ coordinator: coordA, pushSender: null });
    const srvB = createServer({ coordinator: coordB, pushSender: null });
    const portA = await freePort();
    const portB = await freePort();
    await new Promise((r) => srvA.httpServer.listen(portA, '127.0.0.1', r));
    await new Promise((r) => srvB.httpServer.listen(portB, '127.0.0.1', r));
    t.after(async () => {
      for (const srv of [srvA, srvB]) {
        for (const ws of srv.wss.clients) ws.terminate();
        try {
          srv.httpServer.close();
        } catch {}
      }
      await coordA.close();
      await coordB.close();
      try {
        await raw.quit();
      } catch {}
      redis.kill('SIGKILL');
    });

    const alice = makeIdentity();
    const bob = makeIdentity();
    const a = await new Client(portA, alice).auth();
    const qb = async (rid) => {
      const v = await raw.get(`qb:${rid}`);
      return v == null ? null : Number(v);
    };

    // ---- byte cap: two fit, the third is refused; the counter is exact ----
    assert.strictEqual((await a.deliver('m1', bob.rid, BIG)).t, 'sent');
    assert.strictEqual((await a.deliver('m2', bob.rid, BIG)).t, 'sent');
    assert.deepStrictEqual(await a.deliver('m3', bob.rid, BIG), {
      t: 'error',
      code: 'queue_full',
      id: 'm3',
    });
    assert.strictEqual(await raw.llen(`q:${bob.rid}`), 2);
    assert.strictEqual(await qb(bob.rid), 2 * 2256);
    const ttlQ = await raw.ttl(`q:${bob.rid}`);
    const ttlB = await raw.ttl(`qb:${bob.rid}`);
    assert.ok(ttlQ > 0 && Math.abs(ttlQ - ttlB) <= 1, `list and counter expire together (${ttlQ}, ${ttlB})`);

    // ---- Bob drains on the OTHER instance; acks settle the counter ----
    const b = await new Client(portB, bob).auth();
    const got = [await b.next((f) => f.t === 'msg'), await b.next((f) => f.t === 'msg')];
    assert.deepStrictEqual(got.map((f) => f.id).sort(), ['m1', 'm2']);
    const delivered = a.next((f) => f.t === 'delivered' && f.id === 'm1');
    b.send({ t: 'recv', id: 'm1', from: alice.rid });
    await delivered;
    assert.strictEqual(await qb(bob.rid), 2256);
    assert.strictEqual((await a.deliver('m4', bob.rid, BIG)).t, 'sent'); // room again
    assert.strictEqual(await qb(bob.rid), 2 * 2256);
    await sleep(100);
    b.send({ t: 'recv', id: 'm2', from: alice.rid });
    b.send({ t: 'recv', id: 'm4', from: alice.rid });
    await a.next((f) => f.t === 'delivered' && f.id === 'm4');
    await sleep(100);
    assert.strictEqual(await raw.llen(`q:${bob.rid}`), 0);
    assert.strictEqual(await raw.exists(`qb:${bob.rid}`), 0, 'an emptied list takes its counter with it');

    // ---- a queued receipt is counted (192) and removed by the flush ----
    assert.strictEqual((await a.deliver('m5', bob.rid, SMALL)).t, 'sent');
    await b.next((f) => f.t === 'msg' && f.id === 'm5');
    a.close();
    await sleep(300); // presence gone
    b.send({ t: 'recv', id: 'm5', from: alice.rid });
    await sleep(200);
    assert.strictEqual(await raw.llen(`q:${alice.rid}`), 1);
    assert.strictEqual(await qb(alice.rid), 192);
    const a2 = new Client(portB, alice);
    await a2.auth();
    await a2.next((f) => f.t === 'delivered' && f.id === 'm5');
    await sleep(200);
    assert.strictEqual(await raw.exists(`q:${alice.rid}`), 0);
    assert.strictEqual(await raw.exists(`qb:${alice.rid}`), 0);

    // ---- entries queued by a relay older than this: no size, no counter ----
    // Two such entries sit in Carol's list. A new push counts only itself;
    // removing the old ones cannot take the counter below zero; emptying the
    // list resets it. The cap is under-enforced only while those entries
    // remain, which is the transition the store lives through on deploy.
    const carol = makeIdentity();
    const old = (id) => JSON.stringify({ kind: 'msg', id, from: alice.rid, payload: BIG, ts: Date.now() });
    await raw.rpush(`q:${carol.rid}`, old('old1'), old('old2'));
    await raw.expire(`q:${carol.rid}`, 3600);
    assert.strictEqual((await a2.deliver('n1', carol.rid, SMALL)).t, 'sent');
    assert.strictEqual(await qb(carol.rid), 260);
    const c = await new Client(portA, carol).auth();
    for (let i = 0; i < 3; i++) await c.next((f) => f.t === 'msg');
    c.send({ t: 'recv', id: 'old1', from: alice.rid });
    await a2.next((f) => f.t === 'delivered' && f.id === 'old1');
    assert.ok((await qb(carol.rid)) >= 0, 'never negative');
    c.send({ t: 'recv', id: 'old2', from: alice.rid });
    await a2.next((f) => f.t === 'delivered' && f.id === 'old2');
    assert.ok((await qb(carol.rid)) >= 0, 'never negative');
    c.send({ t: 'recv', id: 'n1', from: alice.rid });
    await a2.next((f) => f.t === 'delivered' && f.id === 'n1');
    await sleep(100);
    assert.strictEqual(await raw.exists(`qb:${carol.rid}`), 0);

    // ---- the count cap is decided atomically across instances ----
    // Eight sends race from two senders on two instances at an offline
    // mailbox whose cap is four: exactly four are accepted, whatever the
    // interleaving, because the decision and the append are one script.
    const dave = makeIdentity();
    const erin = makeIdentity();
    const e = await new Client(portB, erin).auth();
    const answers = await Promise.all([
      ...[1, 2, 3, 4].map((i) => a2.deliver(`a${i}`, dave.rid, SMALL)),
      ...[1, 2, 3, 4].map((i) => e.deliver(`e${i}`, dave.rid, SMALL)),
    ]);
    const accepted = answers.filter((f) => f.t === 'sent');
    const refused = answers.filter((f) => f.t === 'error');
    assert.strictEqual(accepted.length, 4);
    assert.strictEqual(refused.length, 4);
    assert.ok(refused.every((f) => f.code === 'queue_full'));
    assert.strictEqual(await raw.llen(`q:${dave.rid}`), 4);
    assert.strictEqual(await qb(dave.rid), 4 * 260);

    b.close();
    a2.close();
    c.close();
    e.close();
  }
);
