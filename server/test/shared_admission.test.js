'use strict';

// The mailbox-creation gate across instances (25.3).
//
// `NewMailboxGate` is a per-instance token bucket, so N instances admit
// N × NEW_MAILBOX_PER_MIN new mailboxes a minute between them. The byte caps
// bound the store regardless of N — the store has one `maxmemory` and each
// mailbox one `MAX_QUEUE_BYTES_PER_USER` whatever N is — so the N× loosens the
// creation RATE, not the store's worst case. NEW_MAILBOX_SHARED=on holds that
// rate relay-wide through one counter in the store; it is OFF by default,
// because sharing has costs an operator should choose: a flood that spends the
// shared window spends it for every instance at once, and an instance that has
// just started pays first contact again against that window (R22, LOAD.md).
//
// What is asserted, on real two-instance deployments (one redis, two
// RedisCoordinators):
//   1. the default is OFF: with NEW_MAILBOX_SHARED unset the per-instance gate
//      is what runs, and only `on` turns sharing on;
//   2. ON: two instances admit the relay-wide allowance between them — not
//      twice it — and the surplus is refused `store_full`, counted once, as
//      z_new_mailbox_refused_total and not as z_store_full_total;
//   3. OFF: the same flood admits twice the allowance, the per-instance N×;
//   4. the window is the STORE's clock: an instance whose own clock is three
//      windows out still counts into the same window as the others;
//   5. a send into a mailbox whose list already exists is granted without a
//      charge — nothing is created — so the counter counts creations only;
//   6. a cold instance with the window spent still delivers into an existing
//      mailbox; and the cost that remains is pinned rather than hidden: a
//      recipient who is online and has drained has no list, so a first contact
//      to them through a cold instance is charged and, with the window spent,
//      refused — the reason sharing is not the default;
//   7. a slot taken for a push that created nothing is given back: a charged
//      first contact refused by the per-mailbox byte cap leaves the count where
//      it was, and two instances racing to create one mailbox count one;
//   8. a refund is bound to the window it was taken in: after the window has
//      passed, or the counter expired, it changes nothing and creates nothing,
//      and a stray second refund cannot take the count below zero or strip its
//      TTL;
//   9. when the counter cannot be consulted, admission falls back to the
//      per-instance bucket — exactly its allowance, never more — and each
//      fallback is counted (z_new_mailbox_shared_fallback_total), except a
//      store that is merely full, whose push is refused and counted anyway;
//  10. the counter is one hash of two integers for the whole relay: ordinary
//      traffic into a known mailbox never reaches it, and no routing id does.
//
// Skips itself where `redis-server` or `ioredis` is missing, as ha.test.js does.

process.env.NEW_MAILBOX_PER_MIN = '10';
// Small enough that one envelope can be refused by the byte cap on its own
// (criterion 7); every other send here is a few hundred bytes.
process.env.MAX_QUEUE_BYTES_PER_USER = '50000';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const path = require('path');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, RedisCoordinator, CFG } = require('../server.js');

const SEALED = `zs1.${'x'.repeat(200)}`; // a sealed envelope: no auth needed
const ALLOWANCE = 10; // NEW_MAILBOX_PER_MIN in this file

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

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Resolves once something accepts connections on the port: redis booting. */
async function listening(port, ms = 5000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const ok = await new Promise((resolve) => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => (s.destroy(), resolve(true)));
      s.once('error', () => resolve(false));
    });
    if (ok) return;
    if (Date.now() > deadline) throw new Error(`redis did not start on ${port}`);
    await sleep(10);
  }
}

function get(port, p) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port, path: p }, (res) => {
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
  constructor(port) {
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

/**
 * One redis and two instances, both with sharing set as asked and a full own
 * bucket that does not refill mid-test, so only the shape under test decides
 * what is admitted. `raw` is a side connection for reading the counter.
 */
async function twoInstances(t, { shared }) {
  const IORedis = require('ioredis');
  const redisPort = await freePort();
  const redis = spawn(
    'redis-server',
    ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'],
    { stdio: 'ignore' }
  );
  await listening(redisPort);
  const url = `redis://127.0.0.1:${redisPort}`;
  const raw = new IORedis(url);
  const coords = [];
  const make = (id) => {
    const c = new RedisCoordinator(url, id);
    c.newMailboxShared = shared;
    const T = Date.now();
    c.newMailbox.now = () => T; // the own bucket does not refill mid-test
    c.newMailbox.at = T;
    c.newMailbox.tokens = ALLOWANCE;
    coords.push(c);
    return c;
  };
  const coordA = make('instA');
  const coordB = make('instB');
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
    for (const c of coords) await c.close();
    try {
      await raw.quit();
    } catch {}
    redis.kill('SIGKILL');
  });
  return { url, raw, make, coordA, coordB, portA, portB };
}

/** The store's own clock, in seconds. */
async function storeSeconds(raw) {
  const [s] = await raw.time();
  return Number(s);
}

/**
 * Wait, if need be, until at least `needSec` of the current one-minute window
 * remain, so a test that counts within one window is not split across two.
 */
async function clearOfBoundary(raw, needSec = 8) {
  const s = await storeSeconds(raw);
  const left = 60 - (s % 60);
  if (left < needSec) await sleep(left * 1000 + 100);
}

/** What the relay-wide counter says: the current window's creations. */
async function created(raw) {
  const s = await storeSeconds(raw);
  const [w, n] = await raw.hmget('z:nm', 'w', 'n');
  return Number(w) === Math.floor(s / 60) ? Number(n || 0) : 0;
}

/** Mark the current window spent, as a flood would leave it. */
async function spendWindow(raw) {
  const s = await storeSeconds(raw);
  await raw.hset('z:nm', 'w', String(Math.floor(s / 60)), 'n', String(ALLOWANCE));
  await raw.expire('z:nm', 120);
}

/** Flood `each` fresh mailboxes from an anonymous socket on each instance. */
async function flood(portA, portB, each) {
  const a = await new Client(portA).open();
  const b = await new Client(portB).open();
  const fire = (client, tag) =>
    Promise.all(Array.from({ length: each }, (_, i) => client.deliver(`${tag}-${i}`, randomRid(), SEALED)));
  const answers = (await Promise.all([fire(a, 'a'), fire(b, 'b')])).flat();
  a.close();
  b.close();
  return {
    accepted: answers.filter((f) => f.t === 'sent').length,
    refused: answers.filter((f) => f.t === 'error' && f.code === 'store_full').length,
    other: answers.filter((f) => f.t === 'error' && f.code !== 'store_full'),
  };
}

test('1. the default is off: NEW_MAILBOX_SHARED must say `on`', () => {
  const server = path.join(__dirname, '..', 'server.js');
  const probe = (value) => {
    const env = { ...process.env };
    delete env.NEW_MAILBOX_SHARED;
    if (value !== undefined) env.NEW_MAILBOX_SHARED = value;
    const r = spawnSync(process.execPath, ['-e', `process.stdout.write(String(require(${JSON.stringify(server)}).CFG.newMailboxShared))`], { env, encoding: 'utf8' });
    assert.strictEqual(r.status, 0, r.stderr);
    return r.stdout;
  };
  assert.strictEqual(probe(undefined), 'false', 'unset: the per-instance gate, exactly as before');
  assert.strictEqual(probe('on'), 'true');
  assert.strictEqual(probe(' ON '), 'true', 'read the way RELAY_AUTH_V1 is');
  assert.strictEqual(probe('off'), 'false');
  assert.strictEqual(probe('yes'), 'false', 'nothing but `on` turns it on');
});

test('2. ON: two instances admit the relay-wide allowance between them, counted once', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, portA, portB } = await twoInstances(t, { shared: true });
  await clearOfBoundary(raw);
  const m0 = await get(portA, '/metrics');
  // Ten fresh mailboxes from each instance — each within one instance's own
  // allowance, so only the shared window can hold the total to ten.
  const { accepted, refused, other } = await flood(portA, portB, ALLOWANCE);
  assert.deepStrictEqual(other, [], 'nothing refused for a reason other than the gate');
  assert.strictEqual(accepted, ALLOWANCE, `${accepted} admitted across two instances`);
  assert.strictEqual(refused, ALLOWANCE, `${refused} refused store_full`);
  assert.strictEqual(await created(raw), ALLOWANCE, 'the counter holds exactly the creations');
  const m1 = await get(portA, '/metrics');
  assert.strictEqual(metric(m1, 'z_new_mailbox_refused_total') - metric(m0, 'z_new_mailbox_refused_total'), refused);
  assert.strictEqual(
    metric(m1, 'z_store_full_total') - metric(m0, 'z_store_full_total'),
    0,
    'a creation refusal is not a full store — counted once, under its own name'
  );
});

test('3. OFF: the per-instance gate admits twice the allowance across two instances', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, portA, portB } = await twoInstances(t, { shared: false });
  const { accepted, refused, other } = await flood(portA, portB, ALLOWANCE);
  assert.deepStrictEqual(other, []);
  assert.strictEqual(accepted, 2 * ALLOWANCE, `${accepted} admitted with the gate per instance`);
  assert.strictEqual(refused, 0);
  assert.strictEqual(await raw.exists('z:nm'), 0, 'and the shared counter is never touched');
});

test('4. the window is the store\'s clock, not an instance\'s', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, coordA, coordB } = await twoInstances(t, { shared: true });
  await clearOfBoundary(raw);
  const want = Math.floor((await storeSeconds(raw)) / 60);
  const realNow = Date.now;
  let a;
  let b;
  try {
    // Instance B's clock three windows ahead: with the window taken from the
    // instance, the two counted into different keys and the allowance was
    // N × again (20 a window against 10, measured at this skew).
    a = await coordA._takeShared(randomRid());
    Date.now = () => realNow() + 3 * 60_000;
    b = await coordB._takeShared(randomRid());
  } finally {
    Date.now = realNow;
  }
  assert.strictEqual(a.window, want, 'the window is the store\'s minute');
  assert.strictEqual(b.window, want, 'whatever the instance\'s clock says');
  assert.strictEqual(await created(raw), 2, 'both charged to one window');
});

test('5. a send into a mailbox that exists is granted without a charge', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, coordA, coordB } = await twoInstances(t, { shared: true });
  await clearOfBoundary(raw);
  const carol = randomRid(); // offline: her mailbox keeps what is sent
  assert.ok(!(await coordA.deliverEnqueue(null, carol, 'c1', SEALED)).storeFull);
  assert.strictEqual(await created(raw), 1, 'A created it: one creation');
  // B has never queued for Carol, so it consults the window — and the window
  // sees her list and charges nothing: the entry goes into a mailbox that
  // is already there.
  const take = await coordB._takeShared(carol);
  assert.deepStrictEqual(take, { granted: true, window: null, fellBack: false });
  for (let i = 2; i <= 6; i++) {
    assert.ok(!(await coordB.deliverEnqueue(null, carol, `c${i}`, SEALED)).storeFull);
  }
  assert.strictEqual(await created(raw), 1, 'six envelopes from two instances, one creation');
  assert.strictEqual(await raw.llen(`q:${carol}`), 6);
});

test('6. a cold instance with the window spent: existing mailboxes deliver, and the remaining cost is pinned', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, make, coordA } = await twoInstances(t, { shared: true });
  await clearOfBoundary(raw);
  const carol = randomRid(); // offline, with mail waiting
  const bob = randomRid(); // online and keeping up: his mailbox is empty
  assert.ok(!(await coordA.deliverEnqueue(null, carol, 'c1', SEALED)).storeFull);
  assert.ok(!(await coordA.deliverEnqueue(null, bob, 'b1', SEALED)).storeFull);
  await coordA.ack(bob, '', 'b1'); // Bob acknowledges: his list is gone again
  assert.strictEqual(await raw.exists(`q:${bob}`), 0);

  await spendWindow(raw); // a flood, say, holds the window
  const cold = make('instC'); // just started: it has queued for nobody
  const toCarol = await cold.deliverEnqueue(null, carol, 'c2', SEALED);
  assert.ok(!toCarol.storeFull && !toCarol.refused, 'into an existing mailbox: delivered');
  assert.strictEqual(await raw.llen(`q:${carol}`), 2);

  // The cost that remains. Bob has no list, so to an instance that has not
  // queued for him this is a first contact; with the window spent it is
  // refused — and the client then pauses its outbox for a minute. Nothing
  // the relay may know can tell Bob from a flood's target here: a shared
  // record of who was written to would put routing ids in the store, and a
  // presence check would let anyone who authenticates a throwaway key
  // create mailboxes uncharged. So this is the price of sharing, and the
  // reason it is not the default (LOAD.md, R22).
  const toBob = await cold.deliverEnqueue(null, bob, 'b2', SEALED);
  assert.strictEqual(toBob.storeFull, true, 'a cold instance pays first contact again, against the shared window');
});

test('7. a slot taken for a push that created nothing is given back', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, coordA, coordB } = await twoInstances(t, { shared: true });
  await clearOfBoundary(raw);
  // Charged — there is no list yet — and then refused by the byte cap on
  // its own (MAX_QUEUE_BYTES_PER_USER is 50 000 here): nothing was created,
  // so the slot goes back. Without the refund the count stays one higher for
  // the rest of the window, and every such refusal shrinks the allowance.
  const before = await created(raw);
  const big = await coordA.deliverEnqueue(null, randomRid(), 'big', `zs1.${'y'.repeat(60_000)}`);
  assert.strictEqual(big.refused, true, 'refused queue_full by the byte cap');
  assert.strictEqual(await created(raw), before, 'and the slot it was charged is back');

  // Two instances creating one mailbox at once: however the takes and the
  // pushes interleave, one creation is counted.
  const dave = randomRid();
  const [x, y] = await Promise.all([
    coordA.deliverEnqueue(null, dave, 'd-a', SEALED),
    coordB.deliverEnqueue(null, dave, 'd-b', SEALED),
  ]);
  assert.ok(!x.storeFull && !y.storeFull);
  assert.strictEqual(await raw.llen(`q:${dave}`), 2, 'both envelopes held');
  assert.strictEqual(await created(raw), before + 1, 'one mailbox, one creation');
});

test('8. a refund is bound to its window and creates nothing', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, coordA } = await twoInstances(t, { shared: true });
  await clearOfBoundary(raw);
  const take = await coordA._takeShared(randomRid());
  assert.strictEqual(take.granted, true);
  assert.strictEqual(await created(raw), 1);
  assert.ok((await raw.ttl('z:nm')) > 0);

  // A stray second refund cannot go below zero, nor strip the TTL.
  await coordA._refundShared(take.window);
  await coordA._refundShared(take.window);
  assert.strictEqual(await created(raw), 0);
  assert.ok((await raw.ttl('z:nm')) > 0, 'the counter still expires');

  // A refund for a window that has passed changes nothing in this one.
  await coordA._takeShared(randomRid());
  await coordA._refundShared(take.window - 1);
  assert.strictEqual(await created(raw), 1, 'an old window\'s refund leaves the current count alone');

  // And after the counter has expired, a refund creates nothing at all —
  // it used to DECR a missing key into a counter with no TTL.
  await raw.del('z:nm');
  await coordA._refundShared(take.window);
  assert.strictEqual(await raw.exists('z:nm'), 0, 'no key without a TTL is left behind');
});

test('9. a counter that cannot be consulted falls back to the own bucket, counted', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { portA, coordA } = await twoInstances(t, { shared: true });
  const m0 = await get(portA, '/metrics');
  coordA.cmd.zNewMailboxTake = () => Promise.reject(new Error('Connection is closed.'));
  let accepted = 0;
  let refused = 0;
  for (let i = 0; i < 2 * ALLOWANCE; i++) {
    const r = await coordA.deliverEnqueue(null, randomRid(), `f-${i}`, SEALED);
    if (r.storeFull) refused += 1;
    else accepted += 1;
  }
  assert.strictEqual(accepted, ALLOWANCE, 'exactly the own allowance — not everything');
  assert.strictEqual(refused, ALLOWANCE, 'and the rest refused, not let through');
  const m1 = await get(portA, '/metrics');
  assert.strictEqual(
    metric(m1, 'z_new_mailbox_shared_fallback_total') - metric(m0, 'z_new_mailbox_shared_fallback_total'),
    2 * ALLOWANCE,
    'every decision the window could not make is counted'
  );

  // A store that is merely full is not a fallback worth an alarm: its push
  // is refused for the same reason, and counted as a full store.
  coordA.cmd.zNewMailboxTake = () => Promise.reject(new Error("OOM command not allowed when used memory > 'maxmemory'."));
  await coordA._takeShared(randomRid());
  const m2 = await get(portA, '/metrics');
  assert.strictEqual(metric(m2, 'z_new_mailbox_shared_fallback_total'), metric(m1, 'z_new_mailbox_shared_fallback_total'));
});

test('10. the counter is two integers for the whole relay; ordinary traffic never reaches it', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, coordA } = await twoInstances(t, { shared: true });
  await clearOfBoundary(raw);
  const bob = randomRid();
  for (let i = 0; i < 21; i++) {
    assert.ok(!(await coordA.deliverEnqueue(null, bob, `m${i}`, SEALED)).storeFull);
    await coordA.ack(bob, '', `m${i}`); // Bob keeps up: his list empties each time
  }
  assert.strictEqual(await created(raw), 1, 'twenty-one sends to one recipient: one creation');
  assert.deepStrictEqual(await raw.keys('z:nm*'), ['z:nm'], 'one key for the relay, not one per anything');
  const fields = await raw.hgetall('z:nm');
  assert.deepStrictEqual(Object.keys(fields).sort(), ['n', 'w']);
  for (const v of Object.values(fields)) assert.match(v, /^\d+$/, 'integers, never a routing id');
});
