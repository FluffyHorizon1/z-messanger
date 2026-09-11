'use strict';

// The shared store at its memory limit (Redis mode — render.ha.yaml runs the
// Key Value instance with `noeviction`, so a full store refuses writes rather
// than evicting a queue whose sender was already told `sent`). This file pins
// what the relay does while that is the case, which used to be: every send
// timed out (the error carried no id) and nobody could log in (the presence
// write failed the login) — including the one person who could have made
// room by draining their mailbox.
//
// Criteria, each asserted below:
//  1. a send the store cannot hold is answered promptly with
//     `error{store_full, id}`, and counted;
//  2. a login while the store is full still gets `ready`, still receives
//     what was queued for it, and can acknowledge it — reads and removals are
//     allowed when the store is full, and the relay leans on exactly that;
//  3. an instance's own sockets are served live whatever the store says
//     about presence, and the heartbeat repairs presence once there is room;
//  4. after the full mailbox is drained, sends succeed again — the store
//     heals without anyone restarting anything.
//
// Skips itself where `redis-server` or `ioredis` is missing, as ha.test.js does.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, routingIdFromPub } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');
const BIG = 'x'.repeat(100_000);

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
    this.send({ t: 'auth', pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    return this.next((f) => f.t === 'ready' || f.t === 'error');
  }
  async deliver(id, to, payload) {
    this.send({ t: 'send', id, to, payload });
    return this.next((f) => (f.t === 'sent' || f.t === 'error') && f.id === id, 25_000);
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

test('the relay under a full store: prompt refusals, logins that still drain, live delivery from local knowledge, and healing', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const redisPort = await freePort();
  const redis = spawn(
    'redis-server',
    ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1', '--maxmemory', '4mb', '--maxmemory-policy', 'noeviction'],
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
  const bob = makeIdentity(); // offline; his mailbox is what fills the store
  const carol = makeIdentity(); // offline with one queued envelope; logs in while full
  const dave = makeIdentity(); // logs in while full, on the sender's instance
  const a = new Client(portA, alice);
  assert.strictEqual((await a.auth()).t, 'ready');

  // Something queued for Carol before the store fills.
  assert.strictEqual((await a.deliver('c1', carol.rid, 'Y2Fyb2w=')).t, 'sent');

  // ---- 1. fill until the store refuses; the refusal is prompt and named ----
  let accepted = 0;
  let refusal = null;
  let refusalMs = 0;
  for (let i = 0; i < 200 && !refusal; i++) {
    const t0 = Date.now();
    const r = await a.deliver(`b${i}`, bob.rid, BIG);
    if (r.t === 'sent') accepted++;
    else {
      refusal = r;
      refusalMs = Date.now() - t0;
    }
  }
  assert.ok(refusal, 'the store filled');
  assert.ok(accepted >= 10, `enough accepted to be sure the store is the limit (${accepted})`);
  assert.strictEqual(refusal.code, 'store_full');
  assert.strictEqual(refusal.id, `b${accepted}`);
  assert.ok(refusalMs < 2000, `refused in ${refusalMs} ms, not a timeout`);
  // A store that has just refused a 100 KB push is at the edge, not over it:
  // a small write may still fit. Lower the limit under what is held so the
  // store is unambiguously full for the rest of the test, until Bob drains.
  await raw.config('SET', 'maxmemory', '3mb');
  assert.deepStrictEqual(await a.deliver('c-while-full', carol.rid, 'eA=='), { t: 'error', code: 'store_full', id: 'c-while-full' });
  assert.ok(metric(await get(portA, '/metrics'), 'z_store_full_total') >= 2);

  // ---- 2. Carol logs in on the other instance while the store is full ----
  const c = new Client(portB, carol);
  const ready = await c.auth();
  assert.strictEqual(ready.t, 'ready', `login must survive a full store: ${JSON.stringify(ready)}`);
  const got = await c.next((f) => f.t === 'msg' && f.id === 'c1');
  assert.strictEqual(got.from, alice.rid);
  assert.strictEqual(await raw.get(`presence:${carol.rid}`), null, 'the presence write was refused');
  assert.strictEqual(JSON.parse(await get(portB, '/health')).presenceStale, 1);
  const delivered = a.next((f) => f.t === 'delivered' && f.id === 'c1');
  c.send({ t: 'recv', id: 'c1', from: alice.rid });
  await delivered; // the ack removed the entry (allowed when full) and reached Alice live
  assert.strictEqual(await raw.llen(`q:${carol.rid}`), 0);

  // Dave logs in on the sender's instance, also with stale presence.
  const d = new Client(portA, dave);
  assert.strictEqual((await d.auth()).t, 'ready');

  // ---- 4. Bob drains his mailbox: the store heals ----
  const b = new Client(portA, bob);
  assert.strictEqual((await b.auth()).t, 'ready');
  const flushed = [];
  const deadline = Date.now() + 20_000;
  while (flushed.length < accepted && Date.now() < deadline) {
    const f = await b.next((x) => x.t === 'msg', 5000);
    flushed.push(f.id);
    b.send({ t: 'recv', id: f.id, from: alice.rid });
  }
  assert.strictEqual(flushed.length, accepted, 'every accepted envelope was flushed to Bob');
  const drainStart = Date.now();
  while ((await raw.llen(`q:${bob.rid}`)) > 0 && Date.now() - drainStart < 20_000) await sleep(50);
  assert.strictEqual(await raw.llen(`q:${bob.rid}`), 0, 'every ack landed');
  t.diagnostic(`drained ${accepted} envelopes of 100 KB in ${Date.now() - drainStart} ms after the last ack was sent`);
  assert.strictEqual((await a.deliver('after', bob.rid, 'eA==')).t, 'sent', 'room again');

  // ---- 3. local sockets are served live; the heartbeat repairs presence ----
  // Dave is on instance A with no presence written; a send from A reaches
  // him live from A's own knowledge of the socket.
  assert.strictEqual(await raw.get(`presence:${dave.rid}`), null);
  a.send({ t: 'send', id: 'd1', to: dave.rid, payload: 'ZGF2ZQ==' });
  const d1 = await d.next((f) => f.t === 'msg' && f.id === 'd1');
  assert.strictEqual(d1.from, alice.rid);
  // Carol is on instance B; until B's heartbeat writes her presence, a send
  // from A is queued (not lost). After the heartbeat it is pushed live.
  await coordB.heartbeat();
  assert.strictEqual(await raw.get(`presence:${carol.rid}`), 'instB');
  assert.strictEqual(JSON.parse(await get(portB, '/health')).presenceStale, 0);
  a.send({ t: 'send', id: 'c2', to: carol.rid, payload: 'Y2Fyb2wy' });
  const c2 = await c.next((f) => f.t === 'msg' && f.id === 'c2');
  assert.strictEqual(c2.from, alice.rid);

  a.close();
  b.close();
  c.close();
  d.close();
});
