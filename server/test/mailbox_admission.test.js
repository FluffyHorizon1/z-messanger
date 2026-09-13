'use strict';

// Anyone could fill the store with mailboxes nobody would ever drain.
//
// `to` is checked for the SHAPE of a routing id — 43 base64url characters —
// and nothing else, because the relay has no way to know which hashes name a
// real identity and is not supposed to. A sealed envelope may be sent on a
// connection that never authenticated (PROTOCOL §12.1), by design. So four
// hundred random strings and a few seconds filled a 256 MB `noeviction`
// store, every real `send` afterwards got `store_full`, and it did NOT heal
// the way THREAT_MODEL R22 promises: healing there means the owner connects
// and drains their mailbox, and nobody owns these. The floor was
// QUEUE_TTL_HOURS — three days.
//
// The per-mailbox caps cannot express this. They bound what one recipient can
// be made to hold; the attack is in how many recipients there are, and the
// cheap variant is many TINY mailboxes, which also defeats the sweeper (one
// round trip each).
//
// Creating a mailbox is the asymmetry: an honest one belongs to somebody who
// will connect and empty it, and a flood's never drain. So creations are
// rate-limited across all senders, and the single-instance store — which had
// no refusal at all and answered the same flood with an OOM kill — has a
// ceiling it can refuse against.
//
// What is asserted below:
//   1. a flood of fresh mailboxes is refused, and refused as `store_full`,
//      which is the code a client retries on rather than treating as final;
//   2. conversations that already exist keep working through it — the bound
//      is on creating mailboxes, not on using them;
//   3. the RAM store refuses when it is full instead of growing without
//      limit, and says so with the id;
//   4. and none of it is charged to a recipient who has done nothing: what is
//      refused is the SEND, the mailbox is not created, and nothing already
//      queued is evicted to make room;
//   5. all of it again against Redis, which is what the HA relay runs.

process.env.NEW_MAILBOX_PER_MIN = '5';
process.env.MAX_STORE_BYTES = '20000';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const WebSocket = require('ws');

const { createServer, routingIdFromPub, _internal } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');
const SEALED = `zs1.${'x'.repeat(200)}`; // a sealed envelope: no auth needed

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}

/** A routing id's shape, with nothing behind it — which is all `to` checks. */
function randomRid() {
  return crypto.randomBytes(32).toString('base64url');
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
  async open() {
    await new Promise((r) => this.ws.once('open', r));
    return this;
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

async function relay(t) {
  const { httpServer, wss } = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => httpServer.listen(port, '127.0.0.1', r));
  t.after(() => {
    for (const ws of wss.clients) ws.terminate();
    httpServer.close();
  });
  return port;
}

test('a flood of fresh mailboxes is refused, and existing ones keep working', async (t) => {
  const port = await relay(t);
  const alice = makeIdentity();
  const bob = makeIdentity();
  const a = await new Client(port, alice).auth();

  // One real conversation, established before the flood.
  assert.strictEqual((await a.deliver('real-1', bob.rid, 'aGk=')).t, 'sent');

  // 2. A flood from an anonymous socket — which §12.1 allows, and which is
  // exactly the position an attacker is in: no identity, no relationship,
  // just routing ids that are the right shape.
  const anon = await new Client(port, makeIdentity()).open();
  const refusals = [];
  let accepted = 0;
  for (let i = 0; i < 25; i++) {
    const r = await anon.deliver(`flood-${i}`, randomRid(), SEALED);
    if (r.t === 'sent') accepted += 1;
    else refusals.push(r);
  }
  assert.ok(accepted <= 5, `${accepted} fresh mailboxes were created`);
  assert.ok(refusals.length >= 20, `${refusals.length} refusals`);
  // 1. `store_full`, which PROTOCOL §12.4 says a client pauses and retries
  // on — not `queue_full`, which is about one recipient being at their cap
  // and would be a lie about a mailbox that does not exist.
  for (const r of refusals) {
    assert.strictEqual(r.code, 'store_full', JSON.stringify(r));
    assert.ok(r.id.startsWith('flood-'), 'the refusal names the envelope');
  }

  // 2. The conversation that already exists is untouched by all of it.
  assert.strictEqual((await a.deliver('real-2', bob.rid, 'aGk=')).t, 'sent');
  assert.strictEqual((await a.deliver('real-3', bob.rid, 'aGk=')).t, 'sent');

  // 4. Nothing was created for the refused sends, and Bob kept everything.
  assert.strictEqual(
    _internal.queues.get(bob.rid).entries.map((e) => e.id).join(','),
    'real-1,real-2,real-3'
  );
  assert.ok(
    _internal.queues.size <= 6,
    `${_internal.queues.size} mailboxes exist: the refused sends made none`
  );
  const m = await get(port, '/metrics');
  assert.ok(metric(m, 'z_new_mailbox_refused_total') >= 20);
  a.close();
  anon.close();
});

test('the RAM store refuses when it is full rather than growing', async (t) => {
  const port = await relay(t);
  const alice = makeIdentity();
  const bob = makeIdentity();
  const a = await new Client(port, alice).auth();

  // MAX_STORE_BYTES is 20 000 here and an envelope is charged its length plus
  // 256, so a few of these reach the ceiling. The per-mailbox caps are at
  // their defaults and nowhere near it: this is the GLOBAL bound, which did
  // not exist in RAM mode at all.
  const big = 'y'.repeat(4000);
  let sent = 0;
  let full = null;
  for (let i = 0; i < 12 && !full; i++) {
    const r = await a.deliver(`big-${i}`, bob.rid, big);
    if (r.t === 'sent') sent += 1;
    else full = r;
  }
  assert.ok(full, 'the store refused before twelve envelopes of four kilobytes');
  assert.strictEqual(full.code, 'store_full');
  assert.ok(full.id.startsWith('big-'), 'and it names the envelope');
  // 4. Nothing accepted was evicted to make room for what was refused.
  assert.strictEqual(_internal.queues.get(bob.rid).entries.length, sent);
  assert.ok(metric(await get(port, '/metrics'), 'z_store_full_total') >= 1);
  a.close();
});

// 5. And the same bound in the HA path, which is where this actually
// happened: `z-relay-ha` runs the Redis coordinator, and its Lua push is
// where the decision has to live — asking `EXISTS` first and pushing second
// would let two instances both find a mailbox absent and both create it, and
// would cost a round trip on every send forever to catch a flood that lasts
// seconds. The script already knows whether the list is empty.
const { spawn, spawnSync } = require('child_process');
const { RedisCoordinator } = require('../server.js');

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

test(
  'the store behind the HA relay is bounded the same way, in the push itself',
  { skip: NO_REDIS && 'redis-server/ioredis unavailable' },
  async (t) => {
    const redisPort = await freePort();
    const redis = spawn(
      'redis-server',
      ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'],
      { stdio: 'ignore' }
    );
    await new Promise((r) => setTimeout(r, 700));
    const coord = new RedisCoordinator(`redis://127.0.0.1:${redisPort}`, 'instA');
    const { httpServer, wss } = createServer({ coordinator: coord, pushSender: null });
    const port = await freePort();
    await new Promise((r) => httpServer.listen(port, '127.0.0.1', r));
    t.after(async () => {
      for (const ws of wss.clients) ws.terminate();
      httpServer.close();
      await coord.close();
      redis.kill('SIGKILL');
    });

    const bob = makeIdentity();
    const carol = makeIdentity();
    const a = await new Client(port, makeIdentity()).auth();
    assert.strictEqual((await a.deliver('real-1', bob.rid, 'aGk=')).t, 'sent');

    // 2. Ordinary traffic must not spend the allowance for creating
    // mailboxes. Here the allowance is five a minute and this is eight sends
    // into a mailbox that already exists; if each of them were charged, the
    // budget would be gone and the next person to start a conversation would
    // be refused — a relay that stopped anyone making a new contact whenever
    // it was busy. The push says which case it was and the token is given
    // back for the other one.
    for (let i = 0; i < 8; i++) {
      assert.strictEqual((await a.deliver(`chat-${i}`, bob.rid, 'aGk=')).t, 'sent');
    }
    assert.strictEqual(
      (await a.deliver('new-contact', carol.rid, 'aGk=')).t,
      'sent',
      'a new conversation after a busy minute of an old one'
    );

    const anon = await new Client(port, makeIdentity()).open();
    let accepted = 0;
    let refused = 0;
    for (let i = 0; i < 25; i++) {
      const r = await anon.deliver(`flood-${i}`, randomRid(), SEALED);
      if (r.t === 'sent') accepted += 1;
      else {
        assert.strictEqual(r.code, 'store_full', JSON.stringify(r));
        refused += 1;
      }
    }
    assert.ok(accepted <= 5, `${accepted} fresh mailboxes were created`);
    assert.ok(refused >= 20, `${refused} refusals`);

    // 2. An existing conversation still works — and the allowance it did not
    // spend is still there, which is the half a lookup-then-push would get
    // wrong: sending into a mailbox that exists must not consume the budget
    // for creating one.
    for (const id of ['real-2', 'real-3', 'real-4']) {
      assert.strictEqual((await a.deliver(id, bob.rid, 'aGk=')).t, 'sent');
    }

    // 4. Nothing was created for the refused sends: Redis holds Bob's mailbox
    // and at most the handful the gate let through, not twenty-five.
    const keys = await coord.cmd.keys('q:*');
    assert.ok(keys.length <= 8, `${keys.length} mailboxes exist in the store`);
    assert.strictEqual(
      (await coord.cmd.lrange(`q:${bob.rid}`, 0, -1)).length,
      12,
      'and the mailbox that did exist kept everything it was sent'
    );
    a.close();
    anon.close();
  }
);
