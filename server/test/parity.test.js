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
//     pass by comparing two empty transcripts.
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
  const alice = await new Client(port, ALICE).auth();
  const bob = await new Client(port, BOB).auth();

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
  const carol = await new Client(port, CAROL).auth();
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
  const dave = await new Client(port, DAVE).auth();
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
  const conns = [bob, carol, await new Client(port, DAVE).auth()];
  for (const m of members) {
    assert.strictEqual((await alice.deliver('g1', m.rid, 'Zw==')).t, 'sent');
  }
  for (const c of conns) await c.next((f) => f.t === 'msg' && f.id === 'g1');
  alice.close();
  await sleep(250);
  for (const c of conns) await c.ack('g1', ALICE.rid);
  const back = await new Client(port, ALICE).auth();
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

let runs = null;
function both() {
  if (!runs) runs = (async () => ({ memory: await runMemory(), redis: await runRedis() }))();
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
