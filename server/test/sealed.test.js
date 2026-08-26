'use strict';

// Sealed-sender delivery at the relay (the zero-knowledge upgrade) and the
// /metrics endpoint (Phase 4 delivery SLIs).
//
// A payload with the 'zs1.' prefix is a sealed envelope: the relay must store
// and deliver it with NO sender attribution, accept an ack by id alone, and
// generate no relay-level receipt (receipts travel E2E instead). Legacy
// payloads keep the old attributed behaviour, so old and new clients coexist.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');

const { createServer, routingIdFromPub, _internal } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

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
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('error', () => {});
    this.ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
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

function get(port, path) {
  return new Promise((resolve, reject) => {
    http
      .get(`http://127.0.0.1:${port}${path}`, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      })
      .on('error', reject);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const metric = (body, name) => {
  const m = body.match(new RegExp(`^${name} (\\d+)$`, 'm'));
  return m ? parseInt(m[1], 10) : null;
};

let httpServer, port;
const clients = [];
const mk = async () => {
  const c = await new Client(port, makeIdentity()).open().then((x) => x.auth());
  clients.push(c);
  return c;
};

test.before(async () => {
  ({ httpServer } = createServer({ pushSender: null }));
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  port = httpServer.address().port;
});

test.after(async () => {
  clients.forEach((c) => {
    try {
      c.ws.terminate();
    } catch {}
  });
  if (httpServer.closeAllConnections) httpServer.closeAllConnections();
  await new Promise((res) => httpServer.close(res));
});

test('a sealed envelope is delivered with NO sender', async () => {
  const a = await mk();
  const b = await mk();
  a.send({ t: 'send', id: 's1', to: b.identity.rid, payload: 'zs1.AAAA' });
  const msg = await b.next((f) => f.t === 'msg' && f.id === 's1');
  assert.strictEqual(msg.from, undefined, 'sealed msg must carry no from');
  assert.strictEqual(msg.payload, 'zs1.AAAA');
});

test('sealed queue entries store no sender and ack by id alone', async () => {
  const a = await mk();
  const offline = makeIdentity();
  a.send({ t: 'send', id: 's2', to: offline.rid, payload: 'zs1.BBBB' });
  await a.next((f) => f.t === 'sent' && f.id === 's2');
  const q = _internal.queues.get(offline.rid);
  assert.ok(q && q.entries.length === 1);
  assert.strictEqual(q.entries[0].from, null, 'no sender stored in RAM');

  // Recipient connects, gets it, acks WITHOUT naming a sender.
  const b = new Client(port, offline);
  clients.push(b);
  await b.open();
  await b.auth();
  const msg = await b.next((f) => f.t === 'msg' && f.id === 's2');
  assert.strictEqual(msg.from, undefined);
  b.send({ t: 'recv', id: 's2' });
  await sleep(150);
  assert.ok(!_internal.queues.get(offline.rid), 'queue emptied by id-only ack');
});

test('no relay receipt is generated for sealed envelopes', async () => {
  const a = await mk();
  const b = await mk();
  a.send({ t: 'send', id: 's3', to: b.identity.rid, payload: 'zs1.CCCC' });
  await b.next((f) => f.t === 'msg' && f.id === 's3');
  b.send({ t: 'recv', id: 's3' });
  await sleep(200);
  assert.ok(
    !a.frames.some((f) => f.t === 'delivered' && f.id === 's3'),
    'relay must not know whom to receipt for a sealed send'
  );
});

test('legacy attributed sends still work exactly as before', async () => {
  const a = await mk();
  const b = await mk();
  a.send({ t: 'send', id: 'l1', to: b.identity.rid, payload: 'legacy-blob' });
  const msg = await b.next((f) => f.t === 'msg' && f.id === 'l1');
  assert.strictEqual(msg.from, a.identity.rid);
  b.send({ t: 'recv', id: 'l1', from: a.identity.rid });
  const rc = await a.next((f) => f.t === 'delivered' && f.id === 'l1');
  assert.strictEqual(rc.to, b.identity.rid);
});

test('/metrics reports delivery SLIs and counts sealed traffic', async () => {
  const before = (await get(port, '/metrics')).body;
  const a = await mk();
  const b = await mk();
  a.send({ t: 'send', id: 'm1', to: b.identity.rid, payload: 'zs1.DDDD' });
  await b.next((f) => f.t === 'msg' && f.id === 'm1');
  b.send({ t: 'recv', id: 'm1' });
  await sleep(150);
  const res = await get(port, '/metrics');
  assert.strictEqual(res.status, 200);
  for (const name of [
    'z_connections',
    'z_queued_envelopes',
    'z_enqueued_total',
    'z_sealed_total',
    'z_acked_total',
  ]) {
    assert.ok(metric(res.body, name) !== null, `${name} missing`);
  }
  assert.ok(
    metric(res.body, 'z_sealed_total') > (metric(before, 'z_sealed_total') ?? 0),
    'sealed counter must increase'
  );
  assert.ok(
    metric(res.body, 'z_acked_total') > (metric(before, 'z_acked_total') ?? 0),
    'ack counter must increase'
  );
  assert.ok(res.body.includes('z_delivery_latency_ms_bucket{le="+Inf"}'));
});
