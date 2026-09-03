'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const WebSocket = require('ws');

const { createServer, routingIdFromPub, _internal } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}

/** Minimal test client speaking the relay wire protocol. */
class Client {
  constructor(port, identity) {
    this.identity = identity;
    this.frames = [];
    this.waiters = [];
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
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
    const ready = await this.next((f) => f.t === 'ready');
    assert.strictEqual(ready.id, this.identity.rid);
    return ready;
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

let httpServer, port;

test.before(async () => {
  ({ httpServer } = createServer());
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  port = httpServer.address().port;
});

test.after(async () => {
  await new Promise((res) => httpServer.close(res));
});

test('rejects sends before authentication', async () => {
  const c = new Client(port, makeIdentity());
  await c.next((f) => f.t === 'challenge');
  c.send({ t: 'send', id: 'x', to: 'nobody', payload: 'AAAA' });
  const err = await c.next((f) => f.t === 'error');
  assert.strictEqual(err.code, 'not_authed');
  c.close();
});

test('rejects bad signatures', async () => {
  const c = new Client(port, makeIdentity());
  await c.next((f) => f.t === 'challenge');
  c.send({
    t: 'auth',
    pub: c.identity.rawPub.toString('base64'),
    sig: Buffer.alloc(64).toString('base64'),
  });
  const err = await c.next((f) => f.t === 'error');
  assert.strictEqual(err.code, 'bad_auth');
  c.close();
});

test('live delivery, recv ack empties RAM queue, sender gets delivered receipt', async () => {
  const alice = new Client(port, makeIdentity());
  const bob = new Client(port, makeIdentity());
  await alice.auth();
  await bob.auth();

  const payload = Buffer.from('opaque-encrypted-bytes').toString('base64');
  alice.send({ t: 'send', id: 'm1', to: bob.identity.rid, payload });

  const got = await bob.next((f) => f.t === 'msg' && f.id === 'm1');
  assert.strictEqual(got.from, alice.identity.rid);
  assert.strictEqual(got.payload, payload);

  // Until Bob acks, the envelope is retained in RAM (crash-safe delivery).
  assert.ok(_internal.queues.has(bob.identity.rid));

  bob.send({ t: 'recv', id: 'm1', from: alice.identity.rid });
  const delivered = await alice.next((f) => f.t === 'delivered' && f.id === 'm1');
  assert.strictEqual(delivered.to, bob.identity.rid);

  // After the ack, nothing about this message remains anywhere on the server.
  assert.ok(!_internal.queues.has(bob.identity.rid));

  alice.close();
  bob.close();
});

test('offline recipient: queued in RAM, flushed on connect, wiped after ack', async () => {
  const alice = new Client(port, makeIdentity());
  await alice.auth();
  const bobIdentity = makeIdentity();

  const payload = Buffer.from('for-later').toString('base64');
  alice.send({ t: 'send', id: 'm2', to: bobIdentity.rid, payload });
  const sent = await alice.next((f) => f.t === 'sent' && f.id === 'm2');
  assert.strictEqual(sent.queued, true);
  assert.strictEqual(_internal.queues.get(bobIdentity.rid).entries.length, 1);

  const bob = new Client(port, bobIdentity);
  await bob.auth();
  const got = await bob.next((f) => f.t === 'msg' && f.id === 'm2');
  assert.strictEqual(got.payload, payload);

  bob.send({ t: 'recv', id: 'm2', from: alice.identity.rid });
  await alice.next((f) => f.t === 'delivered' && f.id === 'm2');
  assert.ok(!_internal.queues.has(bobIdentity.rid));

  alice.close();
  bob.close();
});

test('oversize envelopes are rejected', async () => {
  const alice = new Client(port, makeIdentity());
  await alice.auth();
  const big = 'A'.repeat(1_000_001);
  alice.send({ t: 'send', id: 'big', to: 'whoever', payload: big });
  const err = await alice.next((f) => f.t === 'error' && f.id === 'big');
  assert.strictEqual(err.code, 'too_large');
  alice.close();
});

test('sender spoofing is impossible: "from" is server-authenticated', async () => {
  const alice = new Client(port, makeIdentity());
  const bob = new Client(port, makeIdentity());
  const mallory = new Client(port, makeIdentity());
  await alice.auth();
  await bob.auth();
  await mallory.auth();

  // Mallory tries to claim the frame came from Alice — the wire protocol has
  // no "from" field on send at all; the server stamps the authenticated rid.
  mallory.send({
    t: 'send',
    id: 'spoof',
    to: bob.identity.rid,
    from: alice.identity.rid, // ignored by server
    payload: Buffer.from('hi').toString('base64'),
  });
  const got = await bob.next((f) => f.t === 'msg' && f.id === 'spoof');
  assert.strictEqual(got.from, mallory.identity.rid);
  assert.notStrictEqual(got.from, alice.identity.rid);

  alice.close();
  bob.close();
  mallory.close();
});

test('a client blasting an oversized ws frame kills only its own socket', async () => {
  const alice = new Client(port, makeIdentity());
  const bob = new Client(port, makeIdentity());
  await alice.auth();
  await bob.auth();

  // Raw frame far beyond maxPayload: ws kills the offending socket with 1009.
  const rogue = new Client(port, makeIdentity());
  await rogue.auth();
  rogue.ws.send('X'.repeat(3_000_000));
  await new Promise((res) => rogue.ws.on('close', res));

  // The server must still be alive and other clients unaffected.
  const payload = Buffer.from('still-works').toString('base64');
  alice.send({ t: 'send', id: 'alive', to: bob.identity.rid, payload });
  const got = await bob.next((f) => f.t === 'msg' && f.id === 'alive');
  assert.strictEqual(got.payload, payload);

  alice.close();
  bob.close();
});

test('server code contains no disk-write calls', async () => {
  const fs = require('fs');
  const src = fs.readFileSync(require.resolve('../server.js'), 'utf8');
  for (const forbidden of [
    'writeFile',
    'appendFile',
    'createWriteStream',
    'writeSync(',
    "require('sqlite",
    "require('level",
    "require('redis",
  ]) {
    assert.ok(
      !src.includes(forbidden),
      `server.js must not contain "${forbidden}"`
    );
  }
});

test('push tokens expire from RAM after PUSH_TTL_DAYS (privacy-policy claim)', () => {
  const { MemoryCoordinator, CFG } = require('../server.js');
  const coord = new MemoryCoordinator();
  coord.registerPush('rid-a', 'tok-a', 'android');
  coord.registerPush('rid-b', 'tok-b', 'android');
  // Backdate one registration past the TTL; the other stays fresh.
  coord.pushTokens.get('rid-a').ts = Date.now() - CFG.pushTtlMs - 1000;
  coord.sweep();
  assert.strictEqual(coord.getPush('rid-a'), null);
  assert.strictEqual(coord.getPush('rid-b').token, 'tok-b');
  // Re-registering refreshes the clock.
  coord.pushTokens.get('rid-b').ts = Date.now() - CFG.pushTtlMs - 1000;
  coord.registerPush('rid-b', 'tok-b2', 'android');
  coord.sweep();
  assert.strictEqual(coord.getPush('rid-b').token, 'tok-b2');
});
