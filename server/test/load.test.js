'use strict';

// Relay load + abuse test (roadmap Phase 0.3).
//
// Drives the relay with the things a hostile or just-busy internet throws at
// it — a swarm of concurrent clients, oversized envelopes, oversized raw
// frames, a message flood past the rate limit, a reconnect storm, and a queue
// overflow — and asserts the relay stays up, keeps serving /health, bounds its
// memory, and never lets one abusive socket harm another.
//
// The queue cap is lowered here so the overflow case is fast; everything else
// runs against the real defaults. Results are summarized to docs/LOAD.md.

process.env.MAX_QUEUE_MSGS_PER_USER =
  process.env.MAX_QUEUE_MSGS_PER_USER || '100';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');

const { createServer, routingIdFromPub, _internal } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');
const QUEUE_CAP = 100;
const MAX_ENVELOPE = 1_000_000; // must match server default
const allClients = [];

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}

class Client {
  constructor(port, identity) {
    this.identity = identity;
    this.frames = [];
    this.waiters = [];
    this.closed = false;
    allClients.push(this);
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('close', () => (this.closed = true));
    this.ws.on('error', () => {});
    this.ws.on('message', (d) => {
      let f;
      try {
        f = JSON.parse(d.toString());
      } catch {
        return;
      }
      const w = this.waiters.findIndex((x) => x.pred(f));
      if (w !== -1) {
        const [waiter] = this.waiters.splice(w, 1);
        waiter.resolve(f);
      } else {
        this.frames.push(f);
      }
    });
  }
  next(pred, timeoutMs = 4000) {
    const idx = this.frames.findIndex(pred);
    if (idx !== -1) return Promise.resolve(this.frames.splice(idx, 1)[0]);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(
        () => reject(new Error('timeout waiting for frame')),
        timeoutMs
      );
      this.waiters.push({
        pred,
        resolve: (f) => {
          clearTimeout(timer);
          resolve(f);
        },
      });
    });
  }
  send(obj) {
    this.ws.send(JSON.stringify(obj));
  }
  raw(buf) {
    this.ws.send(buf);
  }
  async open() {
    await new Promise((res, rej) => {
      this.ws.once('open', res);
      this.ws.once('error', rej);
    });
    return this;
  }
  async auth() {
    const challenge = await this.next((f) => f.t === 'challenge');
    const nonce = Buffer.from(challenge.nonce, 'base64');
    const sig = crypto.sign(
      null,
      Buffer.concat([AUTH_CONTEXT, nonce]),
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
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

function health(port) {
  return new Promise((resolve, reject) => {
    http
      .get(`http://127.0.0.1:${port}/health`, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () =>
          resolve({ status: res.statusCode, json: JSON.parse(body) })
        );
      })
      .on('error', reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let httpServer, port;
const summary = {};

test.before(async () => {
  ({ httpServer } = createServer({ pushSender: null }));
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  port = httpServer.address().port;
});

test.after(async () => {
  for (const c of allClients) {
    try {
      c.ws.terminate();
    } catch {}
  }
  if (httpServer.closeAllConnections) httpServer.closeAllConnections();
  await new Promise((res) => httpServer.close(res));
  // eslint-disable-next-line no-console
  console.log('LOAD SUMMARY ' + JSON.stringify(summary));
});

test('/health serves 200 with RAM-only stats', async () => {
  const h = await health(port);
  assert.strictEqual(h.status, 200);
  assert.strictEqual(h.json.ok, true);
  assert.strictEqual(h.json.storage, 'ram-only');
});

test('a swarm of concurrent clients all authenticate', async () => {
  const N = 60;
  const rssBefore = process.memoryUsage().rss;
  const clients = await Promise.all(
    Array.from({ length: N }, () =>
      new Client(port, makeIdentity()).open().then((c) => c.auth())
    )
  );
  const h = await health(port);
  assert.ok(h.json.connections >= N, `only ${h.json.connections} online`);
  summary.concurrentClients = N;
  summary.connectionsAtPeak = h.json.connections;
  clients.forEach((c) => c.close());
  await sleep(200);
  summary.rssDeltaAfterSwarmMB =
    Math.round(((process.memoryUsage().rss - rssBefore) / 1048576) * 10) / 10;
});

test('oversize envelope is rejected but the socket survives', async () => {
  const a = await new Client(port, makeIdentity()).open().then((c) => c.auth());
  const b = await new Client(port, makeIdentity()).open().then((c) => c.auth());
  // A base64 string just past the envelope limit — over the app cap, but the
  // whole frame still fits under the ws maxPayload so it reaches the app check.
  const big = 'A'.repeat(MAX_ENVELOPE + 1);
  a.send({ t: 'send', id: 'big', to: b.identity.rid, payload: big });
  const err = await a.next((f) => f.t === 'error');
  assert.strictEqual(err.code, 'too_large');
  // The socket is still usable for a normal message right after.
  a.send({ t: 'send', id: 'ok', to: b.identity.rid, payload: 'aGVsbG8=' });
  const msg = await b.next((f) => f.t === 'msg' && f.id === 'ok');
  assert.strictEqual(msg.from, a.identity.rid);
  a.close();
  b.close();
});

test('an oversized raw frame closes only the offender', async () => {
  const bystander = await new Client(port, makeIdentity())
    .open()
    .then((c) => c.auth());
  const abuser = await new Client(port, makeIdentity())
    .open()
    .then((c) => c.auth());
  abuser.raw(Buffer.alloc(2_000_000, 0x42)); // beyond ws maxPayload → drop
  await sleep(300);
  assert.ok(abuser.closed, 'abusing socket should be closed');
  // Bystander is unharmed and the relay still serves health.
  const self = makeIdentity();
  const me = await new Client(port, self).open().then((c) => c.auth());
  me.send({ t: 'send', id: 'liv', to: bystander.identity.rid, payload: 'aGk=' });
  const got = await bystander.next((f) => f.t === 'msg' && f.id === 'liv');
  assert.strictEqual(got.from, self.rid);
  const h = await health(port);
  assert.strictEqual(h.status, 200);
  bystander.close();
  me.close();
});

test('a message flood is rate-limited, not crash-inducing', async () => {
  const a = await new Client(port, makeIdentity()).open().then((c) => c.auth());
  const b = await new Client(port, makeIdentity()).open().then((c) => c.auth());
  let limited = 0;
  a.ws.on('message', (d) => {
    try {
      if (JSON.parse(d.toString()).code === 'rate_limited') limited++;
    } catch {}
  });
  for (let i = 0; i < 600; i++) {
    a.send({ t: 'send', id: 'f' + i, to: b.identity.rid, payload: 'eA==' });
  }
  await sleep(500);
  assert.ok(limited > 0, 'flood past the burst should be rate-limited');
  // The connection is NOT killed — it recovers once tokens refill.
  assert.ok(!a.closed, 'rate-limited client should stay connected');
  summary.rateLimitedOfFlood = limited;
  a.close();
  b.close();
});

test('a reconnect storm leaves the relay healthy', async () => {
  const rssBefore = process.memoryUsage().rss;
  for (let i = 0; i < 100; i++) {
    const c = await new Client(port, makeIdentity()).open().then((x) => x.auth());
    c.close();
  }
  await sleep(300);
  const h = await health(port);
  assert.strictEqual(h.status, 200);
  summary.reconnectCycles = 100;
  summary.rssDeltaAfterStormMB =
    Math.round(((process.memoryUsage().rss - rssBefore) / 1048576) * 10) / 10;
});

test('an offline recipient queue is bounded by the cap', async () => {
  const sender = await new Client(port, makeIdentity())
    .open()
    .then((c) => c.auth());
  const offline = makeIdentity(); // never connects
  // Stay within one rate-limit burst (240) so nothing is rate-limited away.
  for (let i = 0; i < 180; i++) {
    sender.send({ t: 'send', id: 'q' + i, to: offline.rid, payload: 'eA==' });
  }
  await sleep(400);
  const q = _internal.queues.get(offline.rid);
  assert.ok(q, 'queue should exist for the offline recipient');
  assert.ok(
    q.entries.length <= QUEUE_CAP,
    `queue grew unbounded: ${q.entries.length} > ${QUEUE_CAP}`
  );
  summary.queueCap = QUEUE_CAP;
  summary.queueLenAfter180Sends = q.entries.length;
  sender.close();
});
