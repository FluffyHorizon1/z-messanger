'use strict';

// The two coordinators must behave the same. `MemoryCoordinator` is what a
// single instance runs and what most of this suite exercises;
// `RedisCoordinator` is what production runs (render.ha.yaml, two instances
// sharing one Valkey). Every finding in roadmap revision 45 was a place they
// had drifted apart — a group's receipts arrived three-of-three in RAM and
// one-of-three in Redis, and no test compared them, because each mode was
// tested against what it happened to do.
//
// So this file runs ONE script against both and compares the frames the
// clients actually received. It is deliberately about client-visible
// behaviour and nothing else: not keys, not counters, not call counts. If a
// future change makes the two modes disagree about what a client sees, this
// fails, whichever mode is the wrong one.
//
// The caps are lowered so the refusal path is in the script too.
//
// Criteria, each asserted below:
//  1. every client's frames are identical between the two coordinators —
//     same frames, same order, same fields;
//  2. the script did exercise the paths it claims to, so criterion 1 cannot
//     pass by comparing two empty transcripts;
//  5. and the mailbox-admission gate is charged on first contact in BOTH
//     modes. It was charged whenever the recipient's queue was empty, and a
//     recipient who is online and acknowledges has no queue — so the steady
//     state paid a token per message and the relay stopped at
//     NEW_MAILBOX_PER_MIN messages a minute. Redis matters most here: it is
//     what the public deployment runs, and its decision is made inside the
//     Lua script rather than in JavaScript, so the two could be fixed apart.
//
// Skips itself where `redis-server` or `ioredis` is missing: parity needs
// both modes, so there is nothing to compare without it.

process.env.MAX_QUEUE_MSGS_PER_USER = process.env.MAX_QUEUE_MSGS_PER_USER || '8';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, CFG, routingIdFromPub } = require('../server.js');

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

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

// The identities are made once and used by both runs, so the routing ids in
// the two transcripts are the same strings and can be compared directly.
const ALICE = makeIdentity();
const BOB = makeIdentity();
const CAROL = makeIdentity();
const DAVE = makeIdentity();
// Never connects: the mailbox the cap step fills, so filling it does not
// take a member of the group step's group out of action.
const EVE = makeIdentity();
const NAME = new Map([
  [ALICE.rid, 'alice'],
  [BOB.rid, 'bob'],
  [CAROL.rid, 'carol'],
  [DAVE.rid, 'dave'],
  [EVE.rid, 'eve'],
]);

/**
 * A frame as the comparison sees it: the fields the protocol defines, with
 * the timestamp dropped (it is wall-clock) and routing ids replaced by
 * names (they are the same in both runs, but names make a failure readable).
 */
function norm(f) {
  const who = (r) => (r == null ? undefined : NAME.get(r) || r);
  const out = { t: f.t };
  if (f.id !== undefined) out.id = f.id;
  if (f.code !== undefined) out.code = f.code;
  if (f.from !== undefined) out.from = who(f.from);
  if (f.to !== undefined) out.to = who(f.to);
  if (f.payload !== undefined) out.payload = f.payload;
  // `queued` is compared now. It was left out, so the two implementations
  // were free to disagree about whether an envelope had been handed to a
  // live socket — which is exactly where they did disagree: the Redis path
  // reported a cross-instance publish as a live delivery.
  if (f.queued !== undefined) out.queued = f.queued;
  // A sealed envelope's frame has no `from` at all, which is the whole
  // point of it: mark that, so the comparison would notice attribution
  // appearing in one mode and not the other.
  if (f.t === 'msg' && f.from == null) out.sealed = true;
  return out;
}

class Client {
  constructor(port, identity) {
    this.identity = identity;
    this.frames = [];
    this.log = [];
    this.waiters = [];
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('error', () => {});
    this.ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
      // `challenge` carries a fresh nonce and `ready` the client's own id:
      // neither says anything about coordinator behaviour.
      if (f.t !== 'challenge' && f.t !== 'ready') this.log.push(norm(f));
      const i = this.waiters.findIndex((w) => w.pred(f));
      if (i !== -1) this.waiters.splice(i, 1)[0].resolve(f);
      else this.frames.push(f);
    });
  }
  next(pred, timeoutMs = 5000) {
    const i = this.frames.findIndex(pred);
    if (i !== -1) return Promise.resolve(this.frames.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout waiting for a frame')), timeoutMs);
      this.waiters.push({ pred, resolve: (f) => (clearTimeout(t), resolve(f)) });
    });
  }
  send(o) {
    this.ws.send(JSON.stringify(o));
  }
  async auth() {
    const ch = await this.next((f) => f.t === 'challenge');
    const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, Buffer.from(ch.nonce, 'base64')]), this.identity.privateKey);
    this.send({ t: 'auth', pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    await this.next((f) => f.t === 'ready');
    // The relay sends `ready` and *then* flushes the mailbox, because a
    // client should not wait on a 64 MB backlog to be told it is
    // authenticated. So an envelope that arrives in that window is
    // delivered live AND picked up by the flush still starting: the
    // recipient gets it twice, which is at-least-once delivery working as
    // §12.5 describes and not a difference between coordinators — but it
    // lands in whichever run loses the race, so the script waits for the
    // flush of its own (empty) mailbox rather than comparing two coin
    // flips. Found by this test failing one run in three.
    await sleep(150);
    return this;
  }
  /** Sends and waits for this relay's answer to it, so the script is ordered. */
  async deliver(id, to, payload) {
    this.send({ t: 'send', id, to, payload });
    return this.next((f) => (f.t === 'sent' || f.t === 'error') && f.id === id);
  }
  async ack(id, from) {
    this.send(from ? { t: 'recv', id, from } : { t: 'recv', id });
    await sleep(120); // an acknowledgement is answered by its effects, not a frame
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

/**
 * The script. Every step waits for the frame it expects before the next, so
 * the transcript is ordered by the script and not by either coordinator's
 * internal timing. What it covers is listed in COVERS, which criterion 2
 * checks against the transcript.
 */
async function script(port, log) {
  // `port` may be one port, or a function naming one per identity — the
  // two-instance run splits the clients across instances, and a reconnection
  // must land on the same one so the transcript is the same script rather
  // than a different one with kicks in it.
  const P = (who) => (typeof port === 'function' ? port(who) : port);
  const alice = await new Client(P('alice'), ALICE).auth();
  const bob = await new Client(P('bob'), BOB).auth();

  // --- live delivery, an acknowledgement, and the receipt it produces ---
  assert.strictEqual((await alice.deliver('m1', BOB.rid, 'aGVsbG8=')).t, 'sent');
  await bob.next((f) => f.t === 'msg' && f.id === 'm1');
  await bob.ack('m1', ALICE.rid);
  await alice.next((f) => f.t === 'delivered' && f.id === 'm1');

  // --- a retry of the same id: acknowledged, and not delivered twice ---
  assert.strictEqual((await alice.deliver('m2', BOB.rid, 'cmV0cnk=')).t, 'sent');
  await bob.next((f) => f.t === 'msg' && f.id === 'm2');
  assert.strictEqual((await alice.deliver('m2', BOB.rid, 'cmV0cnk=')).t, 'sent');
  await sleep(200);
  await bob.ack('m2', ALICE.rid);
  await alice.next((f) => f.t === 'delivered' && f.id === 'm2');
  // The second copy, if there was one, is still in the mailbox: ack again.
  await bob.ack('m2', ALICE.rid);
  await sleep(150);

  // --- two senders, one id, one recipient: neither displaces the other ---
  const carol = await new Client(P('carol'), CAROL).auth();
  assert.strictEqual((await alice.deliver('same', BOB.rid, 'YQ==')).t, 'sent');
  assert.strictEqual((await carol.deliver('same', BOB.rid, 'Yg==')).t, 'sent');
  await bob.next((f) => f.t === 'msg' && f.id === 'same' && f.from === ALICE.rid);
  await bob.next((f) => f.t === 'msg' && f.id === 'same' && f.from === CAROL.rid);
  await bob.ack('same', ALICE.rid);
  await bob.ack('same', CAROL.rid);
  await alice.next((f) => f.t === 'delivered' && f.id === 'same');
  await carol.next((f) => f.t === 'delivered' && f.id === 'same');

  // --- a sealed envelope: no attribution, acknowledged by id alone ---
  assert.strictEqual((await alice.deliver('s1', BOB.rid, 'zs1.c2VhbGVk')).t, 'sent');
  await bob.next((f) => f.t === 'msg' && f.id === 's1');
  await bob.ack('s1'); // no `from` to give
  await sleep(150); // and no receipt is possible: nothing arrives for alice

  // --- an acknowledgement that names nothing ---
  await bob.ack('nosuch', ALICE.rid);

  // --- refusals: an id the protocol will not take, and a bad recipient ---
  const big = await alice.deliver('big', BOB.rid, 'A'.repeat(CFG.maxEnvelopeBytes + 1));
  assert.strictEqual(big.code, 'too_large');
  const bad = await alice.deliver('bad', 'not-a-routing-id', 'aGk=');
  assert.strictEqual(bad.code, 'bad_send');

  // --- an offline recipient: queued, then flushed in order on connect ---
  const queued = ['q1', 'q2', 'q3'];
  for (const id of queued) {
    assert.strictEqual((await alice.deliver(id, DAVE.rid, 'ZA==')).t, 'sent');
  }
  const dave = await new Client(P('dave'), DAVE).auth();
  for (const id of queued) await dave.next((f) => f.t === 'msg' && f.id === id);
  for (const id of queued) await dave.ack(id, ALICE.rid);
  for (const id of queued) await alice.next((f) => f.t === 'delivered' && f.id === id);

  // --- the queue cap: MAX_QUEUE_MSGS_PER_USER, then refusals ---
  dave.close();
  await sleep(250);
  const answers = [];
  for (let i = 0; i < CFG.maxQueueMsgsPerUser + 3; i++) {
    answers.push((await alice.deliver(`f${i}`, EVE.rid, 'Zg==')).t);
  }
  assert.strictEqual(answers.filter((x) => x === 'sent').length, CFG.maxQueueMsgsPerUser);
  assert.strictEqual(answers.filter((x) => x === 'error').length, 3);

  // --- a group: three members acknowledge one id, the sender is offline ---
  const members = [BOB, CAROL, DAVE];
  const conns = [bob, carol, await new Client(P('dave'), DAVE).auth()];
  for (const m of members) {
    assert.strictEqual((await alice.deliver('g1', m.rid, 'Zw==')).t, 'sent');
  }
  for (const c of conns) await c.next((f) => f.t === 'msg' && f.id === 'g1');
  alice.close();
  await sleep(250);
  for (const c of conns) await c.ack('g1', ALICE.rid);
  const back = await new Client(P('alice'), ALICE).auth();
  await sleep(500);

  log.set('alice', alice.log.concat(back.log));
  log.set('bob', bob.log);
  log.set('carol', carol.log);
  log.set('dave', dave.log.concat(conns[2].log));
  conns.forEach((c) => c.close());
  bob.close();
  carol.close();
  back.close();
}

async function runMemory() {
  const srv = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  const log = new Map();
  try {
    await script(port, log);
  } finally {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
  }
  return log;
}

async function runRedis() {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  await sleep(700);
  const coord = new RedisCoordinator(`redis://127.0.0.1:${redisPort}`, 'instA');
  const srv = createServer({ coordinator: coord, pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  const log = new Map();
  try {
    await script(port, log);
  } finally {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
    await coord.close();
    redis.kill('SIGKILL');
  }
  return log;
}

/** The paths criterion 2 requires the transcript to show. */
const COVERS = [
  ['live delivery', (all) => all.some((f) => f.t === 'msg' && f.from === 'alice')],
  ['sealed delivery', (all) => all.some((f) => f.t === 'msg' && f.sealed)],
  ['a delivery receipt', (all) => all.some((f) => f.t === 'delivered')],
  ['three receipts for one group id', (all) => all.filter((f) => f.t === 'delivered' && f.id === 'g1').length === 3],
  ['two senders on one id', (all) => all.filter((f) => f.t === 'msg' && f.id === 'same').length === 2],
  ['a refused oversize envelope', (all) => all.some((f) => f.code === 'too_large')],
  ['a refused recipient', (all) => all.some((f) => f.code === 'bad_send')],
  ['a full queue', (all) => all.filter((f) => f.code === 'queue_full').length === 3],
];

/**
 * The same script again, with the clients split across TWO instances sharing
 * one store — which is what the public deployment runs, and what nothing
 * compared until now: `runRedis` above uses a single instance, so every
 * cross-instance path (presence between instances, the kick, `deliver` over
 * pub/sub) was outside the comparison entirely.
 */
async function runRedisPair() {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  await sleep(700);
  const url = `redis://127.0.0.1:${redisPort}`;
  const coords = [new RedisCoordinator(url, 'instA'), new RedisCoordinator(url, 'instB')];
  const srvs = coords.map((coordinator) => createServer({ coordinator, pushSender: null }));
  const ports = [];
  for (const srv of srvs) {
    const port = await freePort();
    await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
    ports.push(port);
  }
  // Alice and Carol on one, Bob and Dave on the other, so every message
  // between the pairs the script uses crosses instances.
  const on = { alice: 0, carol: 0, bob: 1, dave: 1 };
  const log = new Map();
  try {
    await script((who) => ports[on[who] ?? 0], log);
  } finally {
    for (const srv of srvs) {
      for (const ws of srv.wss.clients) ws.terminate();
      try {
        srv.httpServer.close();
      } catch {}
    }
    for (const c of coords) await c.close();
    redis.kill('SIGKILL');
  }
  return log;
}

let runs = null;
function both() {
  if (!runs) {
    runs = (async () => ({
      memory: await runMemory(),
      redis: await runRedis(),
      pair: await runRedisPair(),
    }))();
  }
  return runs;
}

test('1. the same script produces the same frames in both coordinators', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { memory, redis } = await both();
  assert.deepStrictEqual([...redis.keys()].sort(), [...memory.keys()].sort(), 'the same clients');
  for (const who of memory.keys()) {
    assert.deepStrictEqual(
      redis.get(who),
      memory.get(who),
      `${who} saw different frames in Redis mode than in RAM mode`
    );
  }
  t.diagnostic(`${[...memory.values()].reduce((n, l) => n + l.length, 0)} frames compared, frame for frame`);
});

test('2. and the script exercised the paths it claims', { skip: SKIP && 'redis-server/ioredis unavailable' }, async () => {
  const { memory, redis } = await both();
  for (const [name, log] of [['RAM', memory], ['Redis', redis]]) {
    const all = [...log.values()].flat();
    for (const [what, ok] of COVERS) {
      assert.ok(ok(all), `${name}: the transcript shows no ${what}`);
    }
  }
});

test(
  '3. and the same script across two instances, which is what the deployment runs',
  { skip: SKIP && 'redis-server/ioredis unavailable' },
  async (t) => {
    const { memory, pair } = await both();
    assert.deepStrictEqual([...pair.keys()].sort(), [...memory.keys()].sort(), 'the same clients');

    // Everything a client can observe must be the same as in one process —
    // every message, every receipt, every refusal, in the same order — with
    // ONE exception, which is the point of the test.
    let crossed = 0;
    for (const who of memory.keys()) {
      const a = memory.get(who);
      const b = pair.get(who);
      assert.strictEqual(b.length, a.length, `${who} saw a different number of frames`);
      for (let i = 0; i < a.length; i++) {
        if (a[i].t === 'sent' && a[i].queued === false && b[i].queued === true) {
          // The exception: a send that crossed instances. One process hands
          // the envelope to the recipient's socket and knows it; the other
          // instance publishes it and cannot see whether a socket received
          // it, so it says the envelope is held — which it is, until it is
          // acknowledged. Reporting `false` there was a guess presented as
          // a fact, and it suppressed the wake push with it.
          crossed += 1;
          assert.deepStrictEqual({ ...b[i], queued: false }, a[i], `${who}: frame ${i} differs by more than queued`);
          continue;
        }
        assert.deepStrictEqual(b[i], a[i], `${who} saw a different frame ${i} across two instances`);
      }
    }
    assert.ok(crossed > 0, 'the split put no send across an instance boundary: the comparison proves nothing');
    t.diagnostic(`${crossed} sends crossed instances and were reported held rather than delivered`);
  }
);

test(
  '4. and the two-instance run exercised the same paths',
  { skip: SKIP && 'redis-server/ioredis unavailable' },
  async () => {
    const { pair } = await both();
    const all = [...pair.values()].flat();
    for (const [what, ok] of COVERS) {
      assert.ok(ok(all), `two instances: the transcript shows no ${what}`);
    }
  }
);

test(
  '5. a recipient who drains is not charged per message, in Redis too',
  { skip: SKIP && 'redis-server/ioredis unavailable' },
  async (t) => {
    const Redis = require('ioredis');
    const redisPort = await freePort();
    const redis = spawn(
      'redis-server',
      ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'],
      { stdio: 'ignore' }
    );
    await sleep(700);
    const url = `redis://127.0.0.1:${redisPort}`;
    const coord = new RedisCoordinator(url, 'instA');
    const probe = new Redis(url);
    try {
      // Count what the gate actually spends. Frames cannot show this: a send
      // that is admitted looks the same whether or not it cost a token, and
      // that is exactly how the bug survived — the relay stopped at
      // NEW_MAILBOX_PER_MIN messages a minute with nothing in the transcript
      // to say why.
      let spent = 0;
      const gate = coord.newMailbox;
      const take = gate.take.bind(gate);
      const refund = gate.refund.bind(gate);
      gate.take = () => {
        const got = take();
        if (got) spent += 1;
        return got;
      };
      gate.refund = () => {
        spent -= 1;
        refund();
      };

      const rid = routingIdFromPub(crypto.randomBytes(32));
      const sends = CFG.newMailboxPerMin + 10;
      let refused = 0;
      let emptied = 0;
      for (let i = 0; i < sends; i++) {
        try {
          await coord.deliverEnqueue(null, rid, `drain-${i}`, 'aGk=');
          await coord.ack(rid, '', `drain-${i}`);
          // The mailbox really is gone again — otherwise this test would be
          // the one the review found: a Bob who never drains, so the case
          // that matters never runs.
          if ((await probe.llen(`q:${rid}`)) === 0) emptied += 1;
        } catch (e) {
          refused += 1;
        }
      }
      assert.strictEqual(emptied, sends, 'every message was acknowledged and the mailbox deleted');
      assert.strictEqual(refused, 0, `${sends} messages to a recipient who keeps up`);
      assert.strictEqual(spent, 1,
        'first contact costs one token and nothing after it does');

      // And the allowance is still there for a recipient nobody has written
      // to, which is what the gate is actually for.
      const stranger = routingIdFromPub(crypto.randomBytes(32));
      await coord.deliverEnqueue(null, stranger, 'first', 'aGk=');
      assert.strictEqual(spent, 2, 'a genuinely new mailbox is charged');

      // A refused send leaves no trace here either. Drain the allowance, then
      // offer a routing id that cannot be admitted: if the attempt were
      // remembered, the next flood would have it for nothing.
      coord.newMailbox.tokens = 0;
      const refusedRid = routingIdFromPub(crypto.randomBytes(32));
      const r = await coord.deliverEnqueue(null, refusedRid, 'refused', 'aGk=');
      assert.ok(r && r.storeFull, 'no allowance left, so this must be refused');
      assert.strictEqual(coord.seen.has(refusedRid), false,
        'a refused send must not warm the set for the flood after it');
      t.diagnostic(`${sends} drained sends cost 1 admission token`);
    } finally {
      probe.disconnect();
      await coord.close();
      redis.kill();
    }
  }
);
