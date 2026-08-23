'use strict';

// HA test: two relay instances sharing one Redis. Proves a message sent to an
// instance the recipient is NOT connected to still gets delivered (cross-
// instance routing), and that messages sent while the recipient is offline are
// flushed from the shared queue when they reconnect to EITHER instance.
//
// Skips automatically if `redis-server` or `ioredis` aren't available so the
// suite still passes on machines without Redis (CI installs it).

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const net = require('net');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, routingIdFromPub } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

function hasRedisServer() {
  const r = spawnSync('redis-server', ['--version']);
  return r.status === 0;
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

class Client {
  constructor(port, identity) {
    this.identity = identity;
    this.frames = [];
    this.waiters = [];
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
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
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

test('HA: cross-instance delivery + offline queue via Redis', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const redisPort = await freePort();
  const redis = spawn('redis-server', [
    '--port', String(redisPort),
    '--save', '',
    '--appendonly', 'no',
    '--bind', '127.0.0.1',
  ], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 700)); // let redis boot
  const url = `redis://127.0.0.1:${redisPort}`;

  const coordA = new RedisCoordinator(url, 'instA');
  const coordB = new RedisCoordinator(url, 'instB');
  const srvA = createServer({ coordinator: coordA });
  const srvB = createServer({ coordinator: coordB });
  const portA = await freePort();
  const portB = await freePort();
  await new Promise((r) => srvA.httpServer.listen(portA, '127.0.0.1', r));
  await new Promise((r) => srvB.httpServer.listen(portB, '127.0.0.1', r));

  t.after(async () => {
    try { srvA.httpServer.close(); } catch {}
    try { srvB.httpServer.close(); } catch {}
    await coordA.close();
    await coordB.close();
    redis.kill('SIGKILL');
  });

  const alice = makeIdentity();
  const bob = makeIdentity();

  // Alice on instance A, Bob on instance B.
  const a = new Client(portA, alice);
  const b = new Client(portB, bob);
  await a.auth();
  await b.auth();
  await new Promise((r) => setTimeout(r, 200)); // presence propagate

  // ---- cross-instance live delivery: A -> (redis) -> B ----
  const p1 = Buffer.from('cross-instance-1').toString('base64');
  a.send({ t: 'send', id: 'm1', to: bob.rid, payload: p1 });
  const got1 = await b.next((f) => f.t === 'msg' && f.id === 'm1');
  assert.strictEqual(got1.from, alice.rid);
  assert.strictEqual(got1.payload, p1);

  // Bob acks -> Alice (on A) gets the delivered receipt routed back via redis.
  const delivered = a.next((f) => f.t === 'delivered' && f.id === 'm1');
  b.send({ t: 'recv', id: 'm1', from: alice.rid });
  const rc = await delivered;
  assert.strictEqual(rc.to, bob.rid);

  // ---- offline queue: Bob leaves, Alice sends, Bob returns (to B) ----
  b.close();
  await new Promise((r) => setTimeout(r, 300));

  const ids = ['o0', 'o1', 'o2'];
  for (const id of ids) {
    a.send({ t: 'send', id, to: bob.rid, payload: Buffer.from(id).toString('base64') });
    const sent = await a.next((f) => f.t === 'sent' && f.id === id);
    assert.strictEqual(sent.queued, true); // nobody connected for Bob
  }

  const b2 = new Client(portB, bob);
  const flushed = [];
  b2.ws.on('message', (d) => {
    const f = JSON.parse(d.toString());
    if (f.t === 'msg') flushed.push(f.id);
  });
  await b2.auth();
  // wait for all three to flush from the shared Redis queue
  const deadline = Date.now() + 6000;
  while (flushed.length < 3 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.deepStrictEqual(flushed.sort(), ids);

  a.close();
  b2.close();
});
