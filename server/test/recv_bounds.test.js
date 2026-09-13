'use strict';

// `send` bounds the two fields that become store keys. `recv` bounded
// neither, and it reaches the same store.
//
// `send` caps `id` at 64 characters and requires `to` to be the shape of a
// routing id. `recv` checked only that the socket was authenticated — so a
// throwaway keypair and 1 MB `id`s made the acknowledgement script build
// nine ~1 MB keys and issue nine HGETs inside one blocking Lua call, about
// 9 MB of hashing per frame, at 80 frames a second, on the store every
// mailbox shares. An unbounded `from` was worse in kind than in size: in RAM
// mode it names the mailbox a receipt is enqueued to, so it could create one
// under any string at all.
//
// The refusal has to be silence. §12.5.2 says an acknowledgement that names
// nothing the mailbox holds is answered with no frame, because the relay may
// simply have removed the entry already — so a client must not be able to
// tell a refused frame from an ordinary miss.
//
// And the rate-limit exemption for small acknowledgements bounded the RATE
// and not the number in flight: the debit happens after the lookup, so every
// acknowledgement arriving in one read passed the gate before any was
// charged.
//
// What is asserted below:
//   1. an oversized `id` never reaches the store, and is answered with
//      nothing — same as any other miss;
//   2. a `from` that is not a routing id never reaches the store either, and
//      creates no mailbox under a name the protocol could not have produced;
//   3. an honest acknowledgement still works and is still free, because a
//      device draining its own backlog is what the exemption is for;
//   4. and a burst past the in-flight cap is charged, so the gate refuses
//      the rest unread instead of letting them all into the store first.

process.env.ACK_IN_FLIGHT = '8';
// A small burst with a fast refill, so "more acknowledgements than the
// burst" is a handful rather than hundreds — and so the SENDER filling the
// mailbox is never the thing being limited, which is what makes this about
// the acknowledgement exemption rather than about sending.
process.env.RATE_BURST = '20';
process.env.RATE_PER_SEC = '500';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const WebSocket = require('ws');

const { createServer, routingIdFromPub, _internal, CFG } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  next(pred, timeoutMs = 4000) {
    const i = this.frames.findIndex(pred);
    if (i !== -1) return Promise.resolve(this.frames.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const w = { pred, resolve: (f) => (clearTimeout(t), resolve(f)) };
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

test('1 & 2. an unbounded id or from never reaches the store', async (t) => {
  const port = await relay(t);
  const alice = makeIdentity();
  const bob = makeIdentity();
  const a = await new Client(port, alice).auth();
  const b = await new Client(port, bob).auth();

  a.send({ t: 'send', id: 'real', to: bob.rid, payload: 'aGk=' });
  await b.next((f) => f.t === 'msg' && f.id === 'real');
  const missBefore = metric(await get(port, '/metrics'), 'z_ack_miss_total');
  const mailboxes = _internal.queues.size;

  // 1. A hundred kilobytes of `id`. `send` would refuse this at 64
  // characters. Not a megabyte: the WebSocket layer's own `maxPayload`
  // closes the socket above MAX_ENVELOPE_BYTES + 4096, which would be a
  // different mechanism refusing a different thing — what is under test is
  // the relay's own bound on a frame it has agreed to read.
  b.send({ t: 'recv', id: 'x'.repeat(100_000) });
  // 2. A `from` that is not a routing id — in RAM mode this names the
  // mailbox a receipt is enqueued to.
  b.send({ t: 'recv', id: 'real', from: 'not-a-routing-id' });
  b.send({ t: 'recv', id: 'real', from: 'y'.repeat(4096) });
  b.send({ t: 'recv', id: '' });
  await sleep(300);

  // Answered with nothing at all, like any other miss (§12.5.2) — a client
  // must not be able to tell a refused frame from an entry already gone.
  assert.deepStrictEqual(
    b.frames.filter((f) => f.t === 'error'),
    [],
    'no error frame tells the sender which of its frames was refused'
  );
  // And none of them reached the store: no lookup, so no miss counted.
  assert.strictEqual(
    metric(await get(port, '/metrics'), 'z_ack_miss_total'),
    missBefore,
    'refused before the lookup, not after it'
  );
  assert.strictEqual(_internal.queues.size, mailboxes, 'and no mailbox under a name the protocol cannot produce');

  // 3. The honest one still works, and the entry goes.
  b.send({ t: 'recv', id: 'real', from: alice.rid });
  await sleep(200);
  assert.strictEqual(_internal.queues.has(bob.rid), false, 'the real acknowledgement freed the mailbox');
  a.close();
  b.close();
});

test('3 & 4. draining stays free; a burst past the cap is charged', async (t) => {
  const port = await relay(t);
  const alice = makeIdentity();
  const bob = makeIdentity();
  const a = await new Client(port, alice).auth();
  const b = await new Client(port, bob).auth();

  // 3. Far more acknowledgements than the burst, each freeing an envelope,
  // one at a time — a device working through its backlog. None is charged,
  // which is what the exemption exists for.
  const n = CFG.rateBurst + 10;
  for (let i = 0; i < n; i++) {
    a.send({ t: 'send', id: `m${i}`, to: bob.rid, payload: 'aGk=' });
    await a.next((f) => f.t === 'sent' && f.id === `m${i}`);
    await sleep(3); // Alice stays inside her own budget: she is not the subject
  }
  assert.deepStrictEqual(
    a.frames.filter((f) => f.t === 'error'),
    [],
    'the sender filled the mailbox without being limited'
  );
  for (let i = 0; i < n; i++) {
    b.send({ t: 'recv', id: `m${i}`, from: alice.rid });
    await sleep(2);
  }
  await sleep(400);
  assert.deepStrictEqual(
    b.frames.filter((f) => f.t === 'error' && f.code === 'rate_limited'),
    [],
    `${n} acknowledgements that each freed an envelope were never rate-limited`
  );

  // 4. Now a flood of acknowledgements that free nothing, all in one read.
  // Past ACK_IN_FLIGHT (8 here) they are charged like any other frame, so
  // the bucket empties and the gate refuses the rest UNREAD — rather than
  // every one of them reaching the store first and the bucket going into
  // debt afterwards.
  const c = await new Client(port, makeIdentity()).auth();
  const missBefore = metric(await get(port, '/metrics'), 'z_ack_miss_total');
  const flood = CFG.rateBurst * 3;
  for (let i = 0; i < flood; i++) c.send({ t: 'recv', id: `nosuch${i}` });
  const limited = await c.next((f) => f.t === 'error' && f.code === 'rate_limited', 5000);
  assert.ok(limited, 'the socket is refused');
  await sleep(300);
  const reached = metric(await get(port, '/metrics'), 'z_ack_miss_total') - missBefore;
  assert.ok(
    reached < flood,
    `${reached} of ${flood} unmatched acknowledgements reached the store; the rest were refused unread`
  );
  a.close();
  b.close();
  c.close();
});
