'use strict';

// A message the relay said it had delivered, that nobody had.
//
// Three defects compound into one outage, and the review found them from
// two ends:
//
//   * the presence refresh rethrew anything that was not an out-of-memory
//     error out of its loop, and the call site swallows it — so one reset
//     connection left every remaining socket's presence unrefreshed, with
//     nothing said. Presence expires at 60 s against a 25 s refresh.
//
//   * a cross-instance delivery was counted live because the PUBLISH
//     resolved. That says Redis accepted it and nothing about whether the
//     instance named by `presence:` still holds a socket; the receiving
//     side drops the frame silently when it does not, and answers nobody.
//     So the sender was told `queued: false`, and the wake push — which is
//     gated on `queued` — did not fire either.
//
//   * and `flush` was called from exactly one place, the `auth` case. So
//     the only recovery was the recipient reconnecting, which a healthy
//     client has no reason to do. The floor was QUEUE_TTL_HOURS: three
//     days of mail that the sender, the relay and the recipient all
//     believed had arrived.
//
// What is asserted below:
//   1. a cross-instance send reports `queued: true` — it is held until it
//      is acknowledged, and this instance cannot see whether the live push
//      landed;
//   2. a live push that goes nowhere is recovered, by the mailbox not
//      moving rather than by the mailbox being full;
//   3. a mailbox that IS being drained is not re-flushed, because a device
//      working through a backlog is not a device with a problem;
//   4. and one rid whose presence write fails costs that rid, not the pass.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');
const net = require('net');
const http = require('http');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, routingIdFromPub } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

const NO_REDIS =
  spawnSync('redis-server', ['--version']).status !== 0 ||
  (() => {
    try {
      require.resolve('ioredis');
      return false;
    } catch {
      return true;
    }
  })();

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
      const w = { pred, resolve: (f) => (clearTimeout(t), resolve(f)) };
      // A timed-out waiter has to LEAVE the queue. The harness this is
      // adapted from never removes one, which is harmless when no test
      // expects a timeout — and wrong here, where one does: the dead waiter
      // stays in front, matches the frame when it finally arrives, and
      // resolves a promise nobody holds, so the frame is consumed and the
      // next `next()` for it waits for ever.
      const t = setTimeout(() => {
        const at = this.waiters.indexOf(w);
        if (at !== -1) this.waiters.splice(at, 1);
        reject(new Error('timeout'));
      }, timeoutMs);
      this.waiters.push(w);
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
    await this.next((f) => f.t === 'ready');
    return this;
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

/** Two instances over one Redis, as `z-relay-ha` runs them. */
async function twoInstances(t) {
  const redisPort = await freePort();
  const redis = spawn(
    'redis-server',
    ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'],
    { stdio: 'ignore' }
  );
  await sleep(700);
  const url = `redis://127.0.0.1:${redisPort}`;
  const coordA = new RedisCoordinator(url, 'instA');
  const coordB = new RedisCoordinator(url, 'instB');
  const srvA = createServer({ coordinator: coordA, pushSender: null });
  const srvB = createServer({ coordinator: coordB, pushSender: null });
  const portA = await freePort();
  const portB = await freePort();
  await new Promise((r) => srvA.httpServer.listen(portA, '127.0.0.1', r));
  await new Promise((r) => srvB.httpServer.listen(portB, '127.0.0.1', r));
  t.after(async () => {
    for (const s of [srvA, srvB]) {
      for (const ws of s.wss.clients) ws.terminate();
      try {
        s.httpServer.close();
      } catch {}
    }
    await coordA.close();
    await coordB.close();
    redis.kill('SIGKILL');
  });
  return { coordA, coordB, portA, portB };
}

test(
  '1 & 2. a live push that goes nowhere is recovered, and was never called delivered',
  { skip: NO_REDIS && 'redis-server/ioredis unavailable' },
  async (t) => {
    const { coordA, coordB, portA, portB } = await twoInstances(t);
    const alice = makeIdentity();
    const bob = makeIdentity();
    const a = await new Client(portA, alice).auth();
    const b = await new Client(portB, bob).auth();
    await sleep(200); // presence propagates

    // Bob is connected to instance B and instance A knows it. This is the
    // cross-instance path: A pushes over pub/sub and cannot see the socket.
    a.send({ t: 'send', id: 'x1', to: bob.rid, payload: Buffer.from('one').toString('base64') });
    const sent = await a.next((f) => f.t === 'sent' && f.id === 'x1');
    // 1. Held until acknowledged. It may also have been pushed live — and
    // it was, below — but this instance has no way to know that, and the
    // old answer of `false` was a guess presented as a fact.
    assert.strictEqual(sent.queued, true, 'a publish is not a delivery');
    assert.strictEqual((await b.next((f) => f.t === 'msg' && f.id === 'x1')).id, 'x1');
    assert.ok(metric(await get(portA, '/metrics'), 'z_cross_instance_total') >= 1);

    // Now the failure the old code could not see: the live push goes
    // nowhere. Bob's socket is still connected to B and B still holds it —
    // but the frame is lost between the instances, which is what a stale
    // presence record, or an instance restarting, looks like from A.
    const realOnPub = coordB._onPub.bind(coordB);
    let dropped = 0;
    coordB._onPub = (msg) => {
      const m = JSON.parse(msg);
      if (m.op === 'deliver' && m.frame && m.frame.id === 'x2') {
        dropped += 1;
        return; // the push lands nowhere, and nobody is told
      }
      return realOnPub(msg);
    };

    a.send({ t: 'send', id: 'x2', to: bob.rid, payload: Buffer.from('two').toString('base64') });
    assert.strictEqual((await a.next((f) => f.t === 'sent' && f.id === 'x2')).queued, true);
    assert.strictEqual(dropped, 1, 'the live push was lost');
    await assert.rejects(
      b.next((f) => f.t === 'msg' && f.id === 'x2', 600),
      /timeout/,
      'and Bob does not have it'
    );

    // 2. Two passes: the first records the length, the second sees it has
    // not moved and delivers again. Before this, Bob's only route to that
    // envelope was reconnecting — for up to QUEUE_TTL_HOURS.
    coordB._onPub = realOnPub;
    const flushTo = (rid, ws) => coordB.flush(rid, ws);
    await coordB.reflushStalled(flushTo);
    await coordB.reflushStalled(flushTo);
    assert.strictEqual((await b.next((f) => f.t === 'msg' && f.id === 'x2')).id, 'x2', 'it arrives');
    assert.ok(metric(await get(portB, '/metrics'), 'z_reflushed_total') >= 1);
    a.close();
    b.close();
  }
);

test(
  '3. a mailbox that is being drained is left alone',
  { skip: NO_REDIS && 'redis-server/ioredis unavailable' },
  async (t) => {
    const { coordA, coordB, portA, portB } = await twoInstances(t);
    const alice = makeIdentity();
    const bob = makeIdentity();
    const a = await new Client(portA, alice).auth();
    const b = await new Client(portB, bob).auth();
    await sleep(200);

    for (const id of ['d1', 'd2', 'd3']) {
      a.send({ t: 'send', id, to: bob.rid, payload: Buffer.from(id).toString('base64') });
      await a.next((f) => f.t === 'sent' && f.id === id);
      await b.next((f) => f.t === 'msg' && f.id === id);
    }
    const flushTo = (rid, ws) => coordB.flush(rid, ws);
    const before = metric(await get(portB, '/metrics'), 'z_reflushed_total');

    // Three envelopes held, and Bob acknowledging them one pass at a time:
    // the length moves every pass, so nothing is re-flushed. A device
    // working through a backlog is not a device with a problem, and the
    // signal has to tell those apart or every busy mailbox pays.
    await coordB.reflushStalled(flushTo);
    b.send({ t: 'recv', id: 'd1', from: alice.rid });
    await sleep(150);
    await coordB.reflushStalled(flushTo);
    b.send({ t: 'recv', id: 'd2', from: alice.rid });
    await sleep(150);
    await coordB.reflushStalled(flushTo);
    assert.strictEqual(
      metric(await get(portB, '/metrics'), 'z_reflushed_total'),
      before,
      'a mailbox that is emptying is never re-flushed'
    );

    // An empty one is not re-flushed either, and is forgotten.
    b.send({ t: 'recv', id: 'd3', from: alice.rid });
    await sleep(150);
    await coordB.reflushStalled(flushTo);
    await coordB.reflushStalled(flushTo);
    assert.strictEqual(metric(await get(portB, '/metrics'), 'z_reflushed_total'), before);
    assert.strictEqual(coordB.lastMailboxLen.size, 0, 'and nothing is remembered about it');
    a.close();
    b.close();
  }
);

test(
  '4. one rid whose presence write fails costs that rid, not the pass',
  { skip: NO_REDIS && 'redis-server/ioredis unavailable' },
  async (t) => {
    const { coordB, portB } = await twoInstances(t);
    const ids = [makeIdentity(), makeIdentity(), makeIdentity()];
    const clients = [];
    for (const id of ids) clients.push(await new Client(portB, id).auth());
    await sleep(200);
    assert.strictEqual(coordB.local.size, 3);

    // The second write fails the way a reset connection fails — not an
    // out-of-memory error, which is the only kind the old loop tolerated.
    // Presence is written at `auth` as well as by the refresh, so the keys
    // exist already and a failed REFRESH cannot be seen in their values —
    // only in a TTL that stopped being extended. Clearing them first makes
    // the pass the only writer, so what it did and did not do is visible.
    for (const id of ids) await coordB.cmd.del(`presence:${id.rid}`);

    const realSet = coordB.cmd.set.bind(coordB.cmd);
    let n = 0;
    coordB.cmd.set = async (...args) => {
      n += 1;
      if (n === 2) throw new Error('Connection is closed.');
      return realSet(...args);
    };
    const before = metric(await get(portB, '/metrics'), 'z_presence_refresh_failed_total');
    await coordB.heartbeat();
    coordB.cmd.set = realSet;

    assert.strictEqual(n, 3, 'all three were attempted: the pass did not abort at the failure');
    assert.strictEqual(
      metric(await get(portB, '/metrics'), 'z_presence_refresh_failed_total'),
      before + 1,
      'and the failure is counted rather than swallowed'
    );
    // The two that worked are present; the one that failed is named.
    const present = [];
    for (const id of ids) present.push(await coordB.cmd.get(`presence:${id.rid}`));
    assert.strictEqual(present.filter((v) => v === 'instB').length, 2, 'the other two were refreshed');
    assert.strictEqual(present.filter((v) => v === null).length, 1, 'and the failing one was not');
    assert.strictEqual(coordB.presenceStale.size, 1);

    // And the next pass repairs it, which is why one failure need not be loud.
    await coordB.heartbeat();
    for (const id of ids) assert.strictEqual(await coordB.cmd.get(`presence:${id.rid}`), 'instB');
    assert.strictEqual(coordB.presenceStale.size, 0);
    for (const c of clients) c.close();
  }
);
