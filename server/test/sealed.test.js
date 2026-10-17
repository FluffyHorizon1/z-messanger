'use strict';
// /metrics requires a bearer token (P1-14); set one before server.js is
// required so CFG picks it up, and send it on the gets below.
process.env.METRICS_TOKEN = process.env.METRICS_TOKEN || 'z-test-metrics-token';


// Sealed-sender delivery at the relay (the zero-knowledge upgrade) and the
// /metrics endpoint (Phase 4 delivery SLIs).
//
// A payload with the 'zs1.' prefix is a sealed envelope: the relay must store
// and deliver it with NO sender attribution, accept an ack by id alone, and
// generate no relay-level receipt (receipts travel E2E instead). Legacy
// payloads keep the old attributed behaviour, so old and new clients coexist.
//
// Since 44.2 a 'zs2.' payload is a sealed envelope too: ADR 0033 §5's outer
// layer, an ML-KEM-768 ciphertext beside the X25519 ephemeral,
//   "zs2." || b64url( ephPub(32) || ct(1088) || nonce(12) || box || mac(16) )
// with box §8's padding, unchanged. No client sends one yet (44.7 does), so
// the relay takes it first. It is sealed wherever a 'zs1.' envelope is, and
// nothing else is. Criteria (the tests numbered 44.2/N below):
//   1. each bucket's envelope has the length on the wire pinned here, 'zs1.'
//      and 'zs2.' alike, and 'zs2.' is 1 450 characters longer at every one;
//   2. a 'zs2.' envelope of every bucket under the frame cap is taken from a
//      connection that never authenticated, delivered live and from the
//      flush with no sender, held with none and charged as 'zs1.' is (its
//      length plus 256), acknowledged by id alone, and counted sealed and
//      unattributable — and the relay checks no length: four characters of
//      body are taken as well;
//   3. on an authenticated connection a 'zs2.' envelope is sealed as a
//      'zs1.' one is: no sender stored or delivered, and no `delivered`;
//   4. only the four characters 'zs2.' make it so: 'zs3.', 'zs2' with no
//      dot, 'ZS2.', 'Zs2.' and a body holding 'zs2.' further in are refused
//      `not_authed` on a connection that never authenticated, and on one
//      that did are stamped with the sender and receipted;
//   5. the frame cap is the same for both: the largest bucket is `too_large`
//      on either kind of connection, whichever prefix it carries;
//   6. the shared store (Redis) holds a 'zs2.' envelope as it holds a 'zs1.'
//      one — no sender in its key or in its entry — and an id-only
//      acknowledgement removes it.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, routingIdFromPub, _internal, CFG, RedisCoordinator } = require('../server.js');

// The bound form (PROTOCOL §12.1): the relay's authority — what was dialled,
// as the Host header says it — under the signature with the nonce.
const AUTH_CONTEXT = Buffer.from('z-relay-auth-v2:', 'utf8');
const authority = (ws) => Buffer.from(new URL(ws.url).host.toLowerCase().replace(/:(80|443)$/, ''), 'utf8');

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
      Buffer.concat([AUTH_CONTEXT, authority(this.ws), nonce]),
      this.identity.privateKey
    );
    this.send({
      t: 'auth',
      v: 2,
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
      .get(`http://127.0.0.1:${port}${path}`, { headers: { authorization: `Bearer ${process.env.METRICS_TOKEN}` } }, (res) => {
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

test('a sealed envelope is accepted from a connection that never authenticated — and counted as unattributable', async () => {
  const before = metric((await get(port, '/metrics')).body, 'z_sealed_unattributable_total') || 0;
  const b = await mk();
  // A sender that only ever opens the socket: it sees the challenge and does
  // not answer it. The relay has no identity to attach to what it sends.
  const anon = await new Client(port, makeIdentity()).open();
  clients.push(anon);
  await anon.next((f) => f.t === 'challenge');
  anon.send({ t: 'send', id: 'u1', to: b.identity.rid, payload: 'zs1.EEEE' });
  const ack = await anon.next((f) => f.t === 'sent' && f.id === 'u1');
  // Delivered live — and the anonymous sender is not told so. Until
  // 2026-09-14 this read `queued: false`, which is the relay answering
  // "that person is online, now" to anyone who has ever seen a contact
  // code: one 60-byte sealed envelope a minute to a routing id is a 24/7
  // activity timeline for someone with no relationship to its owner.
  // THREAT_MODEL grants presence to the relay operator (R1), not to the
  // internet. The delivery itself is unaffected, below.
  assert.strictEqual(ack.queued, true, 'an anonymous sender is told nothing about the recipient');
  const msg = await b.next((f) => f.t === 'msg' && f.id === 'u1');
  assert.strictEqual(msg.from, undefined);
  assert.strictEqual(msg.payload, 'zs1.EEEE');
  // Queued for an offline recipient looks EXACTLY the same from here, which
  // is the point: the two cases are what the oracle told apart.
  const offline = makeIdentity();
  anon.send({ t: 'send', id: 'u2', to: offline.rid, payload: 'zs1.FFFF' });
  const ack2 = await anon.next((f) => f.t === 'sent' && f.id === 'u2');
  assert.strictEqual(ack2.queued, true);
  const shape = (f) => ({ ...f, id: undefined });
  assert.deepStrictEqual(shape(ack2), shape(ack), 'online and offline are indistinguishable to an anonymous sender');
  assert.strictEqual(_internal.queues.get(offline.rid).entries[0].from, null);
  // An authenticated sender is told the same. Until 2026-09-17 it got the
  // real answer, on the premise that an authenticated sender was asking
  // about its own conversation — but an identity here is one generated
  // keypair, so the oracle was closed to the anonymous socket and open to
  // anyone who bothered to answer the challenge with a key of their own
  // (the 2026-09-14 review's finding 12). `auth` is exactly that: a fresh
  // key with no relationship to b, and b is online.
  const auth = await mk();
  auth.send({ t: 'send', id: 'u5', to: b.identity.rid, payload: 'zs1.GGGG' });
  const ack5 = await auth.next((f) => f.t === 'sent' && f.id === 'u5');
  assert.strictEqual(ack5.queued, true, 'authenticating with a minted key buys no presence');
  await b.next((f) => f.t === 'msg' && f.id === 'u5'); // and it was delivered live all the same
  // Nor does an attributed (legacy, unsealed) envelope from that key, which
  // the relay accepts on an authenticated socket: the same frame, the same
  // nothing, for a recipient who is online and one who is not.
  auth.send({ t: 'send', id: 'u6', to: b.identity.rid, payload: 'bGVnYWN5' });
  const ack6 = await auth.next((f) => f.t === 'sent' && f.id === 'u6');
  auth.send({ t: 'send', id: 'u7', to: offline.rid, payload: 'bGVnYWN5' });
  const ack7 = await auth.next((f) => f.t === 'sent' && f.id === 'u7');
  assert.strictEqual(ack6.queued, true);
  assert.deepStrictEqual(shape(ack7), shape(ack6), 'online and offline are indistinguishable to an authenticated stranger too');
  const after = metric((await get(port, '/metrics')).body, 'z_sealed_unattributable_total');
  // Two, not three: the third went on an AUTHENTICATED socket, and a sealed
  // envelope sent there is attributable to that connection's identity by the
  // relay process — which is R21, and why clients send them anonymously.
  assert.strictEqual(after, before + 2, 'only the anonymous sends counted as unattributable');
});

test('an unauthenticated connection cannot send an attributed envelope, receive, or ack', async () => {
  const b = await mk();
  const anon = await new Client(port, makeIdentity()).open();
  clients.push(anon);
  await anon.next((f) => f.t === 'challenge');
  anon.send({ t: 'send', id: 'u3', to: b.identity.rid, payload: 'legacy-blob' });
  const err = await anon.next((f) => f.t === 'error');
  assert.strictEqual(err.code, 'not_authed', 'an envelope that would be stamped with a sender needs one');
  await sleep(100);
  assert.ok(!b.frames.some((f) => f.t === 'msg' && f.id === 'u3'), 'nothing delivered');
  // A `recv` from an unauthenticated connection is ignored: it cannot own a mailbox.
  const a = await mk();
  a.send({ t: 'send', id: 'u4', to: b.identity.rid, payload: 'zs1.GGGG' });
  await b.next((f) => f.t === 'msg' && f.id === 'u4');
  anon.send({ t: 'recv', id: 'u4' });
  await sleep(100);
  // b still holds the envelope until B acks it: the relay's queue for b was
  // delivered live, so check that the anonymous ack did not raise the acked
  // counter.
  const acked = metric((await get(port, '/metrics')).body, 'z_acked_total');
  b.send({ t: 'recv', id: 'u4' });
  await sleep(100);
  assert.strictEqual(metric((await get(port, '/metrics')).body, 'z_acked_total'), acked + 1, 'only the mailbox owner\'s ack counts');
});

// ---- 44.2: 'zs2.' is sealed too (ADR 0033 §5) --------------------------------

/** An awaited poll on an observable, failing with what it waited for. */
async function waitUntil(pred, { what, timeoutMs = 8000 }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

// What each bucket's envelope is on the wire, in characters: PROTOCOL §8's
// buckets, the box being the padded plaintext and nothing else. 'zs1.'
// carries 60 bytes beside it (ephemeral, nonce, tag) and 'zs2.' 1 148
// (the ML-KEM-768 ciphertext too), b64url without padding. Computed from the
// two formats by hand and pinned; the test below rebuilds them from the
// format. The last bucket is past the default frame cap for both.
const KEM_CT_BYTES = 1088;
const SEALED_LENGTHS = [
  // bucket, 'zs1.', 'zs2.'
  [1024, 1450, 2900],
  [4096, 5546, 6996],
  [16384, 21930, 23380],
  [65536, 87466, 88916],
  [262144, 349610, 351060],
  [1146880, 1529258, 1530708],
];

/** An envelope of the format's shape and [bucket]'s length, random inside —
 * the relay cannot tell it from a real one, which is the point. */
function sealedShaped(prefix, bucket) {
  const raw = 32 + (prefix === 'zs2.' ? KEM_CT_BYTES : 0) + 12 + bucket + 16;
  return prefix + crypto.randomBytes(raw).toString('base64url');
}

async function anonymous() {
  const c = await new Client(port, makeIdentity()).open();
  clients.push(c);
  await c.next((f) => f.t === 'challenge');
  return c;
}

const sentFrame = (id) => ({ t: 'sent', id, queued: true });

/** The relay's answer to the send of [id] on [c]: the frame naming it, or a
 * refusal that names nothing — a connection answers its frames in order, so
 * that one is about what was just sent (§12.2). */
const answerTo = (c, id) => c.next((f) => f.id === id || (f.t === 'error' && f.id === undefined));

test('44.2/1 the length on the wire of each bucket\'s envelope, zs1. and zs2., is the one pinned', () => {
  assert.deepStrictEqual(
    SEALED_LENGTHS.map(([b]) => b),
    [1024, 4096, 16384, 65536, 262144, 1120 * 1024],
    'the buckets of PROTOCOL §8'
  );
  for (const [bucket, zs1, zs2] of SEALED_LENGTHS) {
    assert.strictEqual(sealedShaped('zs1.', bucket).length, zs1, `zs1. at ${bucket}`);
    assert.strictEqual(sealedShaped('zs2.', bucket).length, zs2, `zs2. at ${bucket}`);
    // Every bucket is 1 mod 3, so a zs1. body ends two characters into a
    // group and a zs2. one (1 088 more bytes) on a group's boundary.
    assert.strictEqual(zs2 - zs1, 1450, `zs2. is 1 450 characters longer at ${bucket}`);
  }
  const [, topZs1, topZs2] = SEALED_LENGTHS[SEALED_LENGTHS.length - 1];
  assert.ok(topZs1 > CFG.maxEnvelopeBytes && topZs2 > CFG.maxEnvelopeBytes, 'the top bucket is over the frame cap for both');
  assert.ok(SEALED_LENGTHS.slice(0, -1).every(([, a, b]) => a <= CFG.maxEnvelopeBytes && b <= CFG.maxEnvelopeBytes), 'and every other bucket under it');
});

test('44.2/2 a zs2. envelope of every bucket under the cap is taken from a connection that never authenticated — no sender, charged as zs1., acknowledged by id alone, counted', async () => {
  const before = (await get(port, '/metrics')).body;
  const anon = await anonymous();
  const b = await mk();
  const usable = SEALED_LENGTHS.filter(([, , zs2]) => zs2 <= CFG.maxEnvelopeBytes).map(([bucket]) => bucket);
  assert.strictEqual(usable.length, 5);
  let sends = 0;
  for (const bucket of usable) {
    // Live, to a recipient that is connected.
    const live = sealedShaped('zs2.', bucket);
    anon.send({ t: 'send', id: `l${bucket}`, to: b.identity.rid, payload: live });
    assert.deepStrictEqual(await answerTo(anon, `l${bucket}`), sentFrame(`l${bucket}`), `taken at ${bucket}`);
    const m = await b.next((f) => f.t === 'msg' && f.id === `l${bucket}`);
    assert.strictEqual(m.from, undefined, `delivered live with no sender at ${bucket}`);
    assert.strictEqual(m.payload, live);
    b.send({ t: 'recv', id: m.id }); // by id alone
    // Held, for a recipient that is not.
    const offline = makeIdentity();
    const held = sealedShaped('zs2.', bucket);
    anon.send({ t: 'send', id: `q${bucket}`, to: offline.rid, payload: held });
    assert.deepStrictEqual(await answerTo(anon, `q${bucket}`), sentFrame(`q${bucket}`));
    const q = _internal.queues.get(offline.rid);
    assert.ok(q && q.entries.length === 1);
    assert.strictEqual(q.entries[0].from, null, `held with no sender at ${bucket}`);
    assert.strictEqual(q.entries[0].size, held.length + 256, 'charged as a zs1. envelope is: its length plus 256');
    const r = await new Client(port, offline).open();
    clients.push(r);
    await r.auth();
    const flushed = await r.next((f) => f.t === 'msg' && f.id === `q${bucket}`);
    assert.strictEqual(flushed.from, undefined, 'and flushed with none');
    r.send({ t: 'recv', id: flushed.id });
    await waitUntil(() => !_internal.queues.get(offline.rid), { what: `the id-only acknowledgement at ${bucket} emptying the mailbox` });
    sends += 2;
  }
  // The relay checks no bucket: any body under the cap is a sealed envelope.
  anon.send({ t: 'send', id: 'short', to: b.identity.rid, payload: 'zs2.AAAA' });
  assert.deepStrictEqual(await answerTo(anon, 'short'), sentFrame('short'));
  assert.strictEqual((await b.next((f) => f.t === 'msg' && f.id === 'short')).from, undefined);
  sends += 1;
  const after = (await get(port, '/metrics')).body;
  for (const name of ['z_sealed_total', 'z_sealed_unattributable_total']) {
    assert.strictEqual(metric(after, name) - (metric(before, name) || 0), sends, name);
  }
});

test('44.2/3 on an authenticated connection a zs2. envelope is sealed as a zs1. one is: no sender held or delivered, and no delivered receipt', async () => {
  const a = await mk();
  const b = await mk();
  const p = sealedShaped('zs2.', 1024);
  a.send({ t: 'send', id: 'z2a', to: b.identity.rid, payload: p });
  assert.deepStrictEqual(await answerTo(a, 'z2a'), sentFrame('z2a'));
  const m = await b.next((f) => f.t === 'msg' && f.id === 'z2a');
  assert.strictEqual(m.from, undefined, 'no sender, though the connection has one');
  const q = _internal.queues.get(b.identity.rid);
  const entry = q && q.entries.find((e) => e.id === 'z2a');
  assert.ok(entry, 'held until acknowledged');
  assert.strictEqual(entry.from, null, 'and held with no sender');
  assert.strictEqual(entry.key, 'm:z2a', 'under a key that names nobody');
  b.send({ t: 'recv', id: 'z2a' });
  // A barrier: an attributed envelope after it, acknowledged with its sender.
  // The relay handles one connection's acknowledgements in order, so a
  // receipt for z2a would have reached `a` before this one does.
  a.send({ t: 'send', id: 'after', to: b.identity.rid, payload: 'YXR0cmlidXRlZA' });
  assert.strictEqual((await b.next((f) => f.t === 'msg' && f.id === 'after')).from, a.identity.rid);
  b.send({ t: 'recv', id: 'after', from: a.identity.rid });
  await a.next((f) => f.t === 'delivered' && f.id === 'after');
  assert.ok(!a.frames.some((f) => f.t === 'delivered' && f.id === 'z2a'), 'no receipt for the sealed one');
  assert.ok(!(_internal.queues.get(b.identity.rid) || { entries: [] }).entries.some((e) => e.id === 'z2a'), 'and the id-only acknowledgement removed it');
});

test('44.2/4 only the four characters zs2. make it sealed: near misses are refused not_authed anonymously and stamped with the sender when authenticated', async () => {
  const nearMisses = {
    zs3: 'zs3.' + 'A'.repeat(64),
    nodot: 'zs2' + 'A'.repeat(64),
    upper: 'ZS2.' + 'A'.repeat(64),
    mixed: 'Zs2.' + 'A'.repeat(64),
    inside: 'A' + 'zs2.' + 'A'.repeat(64),
  };
  const anon = await anonymous();
  const a = await mk();
  const b = await mk();
  for (const [id, payload] of Object.entries(nearMisses)) {
    anon.send({ t: 'send', id: `anon-${id}`, to: b.identity.rid, payload });
    assert.deepStrictEqual(await anon.next((f) => f.t === 'error' || f.t === 'sent'), { t: 'error', code: 'not_authed' }, `${id}: not sealed, so it needs a sender`);
  }
  for (const [id, payload] of Object.entries(nearMisses)) {
    a.send({ t: 'send', id, to: b.identity.rid, payload });
    assert.deepStrictEqual(await answerTo(a, id), sentFrame(id));
    const m = await b.next((f) => f.t === 'msg' && f.id === id);
    assert.strictEqual(m.from, a.identity.rid, `${id}: stamped with the authenticated sender`);
    b.send({ t: 'recv', id, from: a.identity.rid });
    assert.strictEqual((await a.next((f) => f.t === 'delivered' && f.id === id)).to, b.identity.rid, `${id}: receipted`);
  }
  // None of the anonymous ones reached b: everything b was sent went before
  // the authenticated ones did, and b holds only those.
  assert.ok(!b.frames.some((f) => typeof f.id === 'string' && f.id.startsWith('anon-')), 'nothing the anonymous socket sent was delivered');
});

test('44.2/5 the frame cap is the same for both prefixes: one character over it is too_large from either kind of connection, and the top bucket is past the socket\'s own limit', async () => {
  const anon = await anonymous();
  const a = await mk();
  const b = await mk();
  for (const prefix of ['zs1.', 'zs2.']) {
    const over = prefix + 'A'.repeat(CFG.maxEnvelopeBytes + 1 - prefix.length);
    for (const [who, c] of [['anonymous', anon], ['authenticated', a]]) {
      const id = `${who}-${prefix}`;
      c.send({ t: 'send', id, to: b.identity.rid, payload: over });
      assert.deepStrictEqual(await answerTo(c, id), { t: 'error', code: 'too_large', id }, `${prefix} one over the cap, from a connection ${who}`);
    }
  }
  // At the cap exactly, a zs2. envelope is taken: the cap is the only bound.
  const at = 'zs2.' + 'A'.repeat(CFG.maxEnvelopeBytes - 4);
  anon.send({ t: 'send', id: 'at-cap', to: b.identity.rid, payload: at });
  assert.deepStrictEqual(await answerTo(anon, 'at-cap'), sentFrame('at-cap'));
  assert.strictEqual((await b.next((f) => f.t === 'msg' && f.id === 'at-cap')).payload.length, CFG.maxEnvelopeBytes);
  b.send({ t: 'recv', id: 'at-cap' });
  // The top bucket does not fit a frame at all (MAX_ENVELOPE_BYTES + 4 096):
  // the socket is closed before the relay reads it, for either prefix.
  for (const prefix of ['zs1.', 'zs2.']) {
    const c = await anonymous();
    const closed = new Promise((res) => c.ws.once('close', (code) => res(code)));
    c.send({ t: 'send', id: 'top', to: b.identity.rid, payload: sealedShaped(prefix, 1146880) });
    assert.strictEqual(await closed, 1009, `${prefix}: message too big`);
  }
  assert.ok(!b.frames.some((f) => f.id === 'top'), 'and nothing of it was delivered');
});

function hasRedis() {
  if (spawnSync('redis-server', ['--version']).status !== 0) return false;
  try {
    require.resolve('ioredis');
    return true;
  } catch {
    return false;
  }
}
const SKIP_REDIS = !hasRedis() && 'redis-server/ioredis unavailable';

function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
    s.on('error', rej);
  });
}

test('44.2/6 Redis: the shared store holds a zs2. envelope as a zs1. one — no sender in its key or its entry — and an id-only acknowledgement removes it', { skip: SKIP_REDIS }, async (t) => {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  const IORedis = require('ioredis');
  const raw = new IORedis(`redis://127.0.0.1:${redisPort}`, { lazyConnect: true, maxRetriesPerRequest: 0, retryStrategy: () => 20 });
  raw.on('error', () => {});
  let srv = null;
  let coord = null;
  // One hook, in this order: the relay, its coordinator, then the store.
  t.after(async () => {
    if (srv) {
      for (const ws of srv.wss.clients) ws.terminate();
      await new Promise((r) => srv.httpServer.close(r));
    }
    if (coord) await coord.close();
    try {
      await raw.quit();
    } catch {}
    redis.kill('SIGKILL');
  });
  await waitUntil(async () => (await raw.ping().catch(() => null)) === 'PONG', { what: 'redis-server answering PING' });
  coord = new RedisCoordinator(`redis://127.0.0.1:${redisPort}`, 'sealed44');
  srv = createServer({ coordinator: coord, pushSender: null });
  await new Promise((r) => srv.httpServer.listen(0, '127.0.0.1', r));
  const p = srv.httpServer.address().port;
  const anon = await new Client(p, makeIdentity()).open();
  await anon.next((f) => f.t === 'challenge');
  const a = await new Client(p, makeIdentity()).open().then((c) => c.auth());
  const bob = makeIdentity();
  const zs2 = sealedShaped('zs2.', 4096);
  anon.send({ t: 'send', id: 'r1', to: bob.rid, payload: zs2 });
  assert.deepStrictEqual(await answerTo(anon, 'r1'), sentFrame('r1'));
  a.send({ t: 'send', id: 'r2', to: bob.rid, payload: sealedShaped('zs2.', 1024) });
  assert.deepStrictEqual(await answerTo(a, 'r2'), sentFrame('r2'));
  a.send({ t: 'send', id: 'r3', to: bob.rid, payload: 'zs3.' + 'A'.repeat(64) });
  assert.deepStrictEqual(await answerTo(a, 'r3'), sentFrame('r3'));
  const fields = await raw.hgetall(`qe:${bob.rid}`);
  assert.deepStrictEqual(Object.keys(fields).sort(), ['m:r1', 'm:r2', `m:r3:${a.identity.rid}`], 'the zs2. envelopes are keyed by id alone, from either connection; the near miss names its sender');
  assert.strictEqual(JSON.parse(fields['m:r1']).from, null);
  assert.strictEqual(JSON.parse(fields['m:r2']).from, null);
  assert.strictEqual(JSON.parse(fields[`m:r3:${a.identity.rid}`]).from, a.identity.rid);
  assert.strictEqual(JSON.parse(fields['m:r1']).size, zs2.length + 256, 'charged as zs1. is');
  const b = await new Client(p, bob).open().then((c) => c.auth());
  for (const id of ['r1', 'r2']) {
    const m = await b.next((f) => f.t === 'msg' && f.id === id);
    assert.strictEqual(m.from, undefined, `${id}: flushed with no sender`);
    b.send({ t: 'recv', id });
  }
  assert.strictEqual((await b.next((f) => f.t === 'msg' && f.id === 'r3')).from, a.identity.rid);
  b.send({ t: 'recv', id: 'r3', from: a.identity.rid });
  await waitUntil(async () => (await raw.exists(`q:${bob.rid}`, `qe:${bob.rid}`)) === 0, { what: 'the acknowledgements emptying the mailbox in the store' });
  for (const c of [anon, a, b]) c.close();
});
