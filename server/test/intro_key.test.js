'use strict';

// /metrics requires a bearer token (P1-14); set one before server.js is
// required so CFG picks it up, and send it on the reads below.
process.env.METRICS_TOKEN = process.env.METRICS_TOKEN || 'z-test-metrics-token';

// The relay keeps introduction keys (44.10; ADR 0033 addendum A, PROTOCOL
// §12.7): a device's sealing key — public — and `iks`, its signature by the
// key the mailbox is the hash of, published on the device's own bound
// connection and served on a connection that never authenticated, so that a
// sender who has never heard from the device can seal to it post-quantum. No
// client publishes or fetches one before 44.11–44.12; this drives the frames
// from the specification, in RAM and in the Redis path (skipped, as the HA
// tests are, without redis-server or ioredis). The relay checks a key's
// length and nothing else of it (the modulus check is the sender's, §8.3), so
// the keys here are random bytes of the right length.
//
// Criteria, each asserted below (N in RAM, Nb in the Redis path):
//   1. the challenge says `ik:1` on every connection; a publish is taken
//      only on a connection authenticated with v2 — refused `not_authed`
//      before authentication and after a v1 one — and only with an `iks` by
//      the key that connection authenticated as, over that key and the
//      sealing key's hash: another key's signature, a signature over another
//      sealing key, a key or a signature of another length, and a
//      non-canonical spelling are each refused `bad_ikey` and leave nothing
//      held; a taken one is `ikey_ok`, held byte for byte, counted, and named
//      by the next login's `ready.ik` — which names nothing before;
//   2. an entry lives OWNED_TTL from its routing id's last login: a login
//      renews it, a re-publish replaces the key and renews nothing, and an
//      entry nobody logs in for is gone after OWNED_TTL;
//   3. a restart loses every entry — a RAM relay's own, and in the Redis
//      path the store's (an instance's restart keeps them) — and the device's
//      next login names none, so it publishes again;
//   4. after a store loss the heartbeat puts back the entry of every socket
//      the instance holds, with the life it had left, and no other — not a
//      device that has gone offline — and only when `ik:epoch` has gone or
//      changed; an instance that holds no entry's copy writes nothing;
//   5. IKEY_CAP takes a new entry and forgets the one whose routing id
//      authenticated least recently (in the Redis path, at the sweep), a
//      login moving an entry to the back, and counts it;
//   6. `ikey` frames are paced per routing id, every frame counting, and with
//      CLIENT_IP_HEADER new entries per client address, a replacement not
//      counting; without the header there is no per-address pace;
//   7. `ikey_get` is answered on a connection that never authenticated with
//      the entry byte for byte, or with nothing — the same answer for a
//      mailbox nobody has seen as for an owned one that keeps no key — and
//      on an authenticated connection is refused `anon_only` and counted; a
//      `to` that is no routing id is `bad_ikey`; and the relay keeps no
//      record of who asked for what;
//   8. `/metrics`, read with the METRICS_TOKEN bearer, counts publishes,
//      answers with and without a key, evictions and `anon_only`, and
//      reports how many entries are held (`z_ikeys`).

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, CFG, RedisCoordinator, routingIdFromPub } = require('../server.js');

const V1 = Buffer.from('z-relay-auth-v1:', 'utf8');
const V2 = Buffer.from('z-relay-auth-v2:', 'utf8');
const IK_CONTEXT = Buffer.from('z-intro-key-v1:', 'utf8');

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
const SKIP_REDIS = (!hasRedisServer() || !hasIoredis()) && 'redis-server/ioredis unavailable';

// ---- the entry, from the specification (PROTOCOL §8.3, §12.7) ----------------

const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}
/** A sealing key the relay cannot tell from a real one: it checks the length. */
const sealingKey = () => crypto.randomBytes(1184);
/** iks: Ed25519 by [id]'s key over the context, that key and SHA-256(ek). */
const iksBy = (id, ek, pub = id.rawPub) => crypto.sign(null, Buffer.concat([IK_CONTEXT, pub, sha256(ek)]), id.privateKey);
/** What `ready` names an entry by. */
const hintOf = (ek, iks) => sha256(Buffer.concat([ek, iks])).subarray(0, 16).toString('base64url');

// ---- harness -----------------------------------------------------------------

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
/** An awaited poll on an observable, failing with what it was waiting for —
 * never a bare sleep as synchronisation. */
async function waitUntil(pred, { what, timeoutMs = 10000 }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred()) return;
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}
/** The store's TTLs are milliseconds: let the clock move on between two
 * things the test means to tell apart by them. */
async function millisecondsPass(n) {
  const t = Date.now();
  await waitUntil(() => Date.now() >= t + n, { what: `${n} ms on the clock` });
}
async function startRedis() {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  const IORedis = require('ioredis');
  const raw = new IORedis(`redis://127.0.0.1:${redisPort}`, { lazyConnect: true, maxRetriesPerRequest: 0, retryStrategy: () => 20 });
  raw.on('error', () => {});
  const stop = async () => {
    try {
      await raw.quit();
    } catch {}
    redis.kill('SIGKILL');
  };
  try {
    await waitUntil(async () => (await raw.ping().catch(() => null)) === 'PONG', { what: 'redis-server answering PING' });
  } catch (e) {
    await stop();
    throw e;
  }
  return { redisPort, raw, stop };
}

class Client {
  constructor(port, identity, headers = {}) {
    this.port = port;
    this.identity = identity;
    this.frames = [];
    this.waiters = [];
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`, { headers });
    this.ws.on('error', () => {});
    this.ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
      const i = this.waiters.findIndex((w) => w.pred(f));
      if (i !== -1) this.waiters.splice(i, 1)[0].resolve(f);
      else this.frames.push(f);
    });
  }
  next(pred, timeoutMs = 8000) {
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
  challenge() {
    return this.next((f) => f.t === 'challenge');
  }
  /** Authenticates — the bound form unless [v1] — and resolves to `ready`. */
  async auth({ v1 = false } = {}) {
    const ch = await this.challenge();
    this.lastChallenge = ch;
    const nonce = Buffer.from(ch.nonce, 'base64');
    const msg = v1 ? Buffer.concat([V1, nonce]) : Buffer.concat([V2, Buffer.from(`127.0.0.1:${this.port}`, 'utf8'), nonce]);
    const sig = crypto.sign(null, msg, this.identity.privateKey);
    this.send({ t: 'auth', ...(v1 ? {} : { v: 2 }), pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    return this.next((f) => f.t === 'ready' || f.t === 'error');
  }
  /** Sends an `ikey` frame as given, and resolves to the answer. */
  ikeyRaw(ek, iks) {
    this.send({ t: 'ikey', ek, iks });
    return this.next((f) => f.t === 'ikey_ok' || f.t === 'error');
  }
  publish(ek, iks) {
    return this.ikeyRaw(ek.toString('base64'), iks.toString('base64'));
  }
  fetch(to) {
    this.send({ t: 'ikey_get', to });
    return this.next((f) => f.t === 'ikey_for' || f.t === 'error');
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

function withCfg(cfg) {
  const saved = {};
  for (const k of Object.keys(cfg)) {
    saved[k] = CFG[k];
    CFG[k] = cfg[k];
  }
  return () => {
    for (const k of Object.keys(saved)) CFG[k] = saved[k];
  };
}
async function listen(srv) {
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  return port;
}
function shut(srv) {
  for (const ws of srv.wss.clients) ws.terminate();
  try {
    srv.httpServer.close();
  } catch {}
}
/** A relay in RAM, CFG set before it is built and restored after the test. */
async function ram(t, cfg = {}) {
  const restore = withCfg(cfg);
  const srv = createServer({ pushSender: null });
  const port = await listen(srv);
  t.after(() => {
    shut(srv);
    restore();
  });
  return { kind: 'ram', srv, coord: srv.coordinator, port };
}
/** A relay in the Redis path on a store of its own; the sweep and the
 * heartbeat only when a test calls them, so what the store holds is the
 * test's doing. [shared] — `{ store, cleanups }` — puts a second instance on
 * one store: its cleanup joins the list, which the test closes in order, the
 * store last. */
async function redis(t, cfg = {}, shared = null) {
  const s = shared ? shared.store : await startRedis();
  const restore = withCfg({ sweepIntervalMs: 3600000, heartbeatMs: 3600000, ...cfg });
  const coord = new RedisCoordinator(`redis://127.0.0.1:${s.redisPort}`, `inst${crypto.randomBytes(3).toString('hex')}`);
  const srv = createServer({ coordinator: coord, pushSender: null });
  const port = await listen(srv);
  const cleanup = async () => {
    shut(srv);
    await coord.close();
    restore();
  };
  if (shared) {
    shared.cleanups.push(cleanup);
  } else {
    t.after(async () => {
      await cleanup();
      await s.stop();
    });
  }
  return { kind: 'redis', srv, coord, port, raw: s.raw, store: s };
}
/** One store for several instances, closed after them. */
async function sharedStore(t) {
  const shared = { store: await startRedis(), cleanups: [] };
  t.after(async () => {
    for (const f of shared.cleanups.reverse()) await f();
    await shared.store.stop();
  });
  return shared;
}
/** The entry the relay holds for [rid], as bytes, or null. */
async function heldEntry(h, rid) {
  if (h.kind === 'ram') {
    const e = h.coord.ikeys.get(rid);
    return e ? e.entry : null;
  }
  return h.raw.getBuffer(`ik:${rid}`);
}
async function gone(h, rid) {
  if (h.kind === 'ram') return !h.coord.online.has(rid);
  return !h.coord.local.has(rid) && (await h.raw.exists(`presence:${rid}`)) === 0;
}
function leave(h, client) {
  client.close();
  return waitUntil(() => gone(h, client.identity.rid), { what: `${client.identity.rid.slice(0, 8)}… gone from the relay` });
}
async function anon(h, headers = {}) {
  const c = new Client(h.port, makeIdentity(), headers);
  const ch = await c.challenge();
  return { c, ch };
}
/** A device that logs in, publishes a fresh entry and — unless [stay] —
 * leaves. Resolves to its identity, key, signature and client. */
async function publisher(h, { stay = false, headers = {} } = {}) {
  const id = makeIdentity();
  const c = new Client(h.port, id, headers);
  assert.strictEqual((await c.auth()).t, 'ready');
  const ek = sealingKey();
  const iks = iksBy(id, ek);
  assert.deepStrictEqual(await c.publish(ek, iks), { t: 'ikey_ok' });
  if (!stay) await leave(h, c);
  return { id, ek, iks, c };
}
function getMetrics(port) {
  return new Promise((resolve, reject) => {
    http
      .get(`http://127.0.0.1:${port}/metrics`, { headers: { authorization: `Bearer ${process.env.METRICS_TOKEN}` } }, (res) => {
        let body = '';
        res.on('data', (d) => (body += d));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      })
      .on('error', reject);
  });
}
const metric = (body, name) => {
  const m = body.match(new RegExp(`^${name} (\\d+)$`, 'm'));
  return m ? parseInt(m[1], 10) : null;
};
const servedFrame = (rid, ek, iks) => ({ t: 'ikey_for', to: rid, ek: ek.toString('base64'), iks: iks.toString('base64') });

// ---- 1. publishing --------------------------------------------------------------

async function publishing(h) {
  const before = (await getMetrics(h.port)).body;
  const { c: a, ch } = await anon(h);
  assert.strictEqual(ch.ik, 1, 'the challenge on a connection that will not authenticate says ik:1');
  const id = makeIdentity();
  const ek = sealingKey();
  const iks = iksBy(id, ek);
  // Before authenticating, and after the unbound (v1) form.
  assert.deepStrictEqual(await a.publish(ek, iks), { t: 'error', code: 'not_authed' }, 'not before authentication');
  const v1 = new Client(h.port, id);
  assert.strictEqual((await v1.auth({ v1: true })).t, 'ready', 'v1 still authenticates here');
  assert.deepStrictEqual(await v1.publish(ek, iks), { t: 'error', code: 'not_authed' }, 'not on a v1-authenticated connection');
  await leave(h, v1);
  assert.strictEqual(await heldEntry(h, id.rid), null);
  // Bound: the first login's challenge says ik:1 too, and `ready` names no entry.
  const c = new Client(h.port, id);
  const ready = await c.auth();
  assert.strictEqual(c.lastChallenge.ik, 1, 'and on one that will');
  assert.deepStrictEqual(Object.keys(ready).sort(), ['id', 't'], 'ready names no entry before one is held');
  const other = makeIdentity();
  const longer = Buffer.concat([ek, Buffer.alloc(1)]);
  const refusals = {
    "another key's signature": [ek.toString('base64'), iksBy(other, ek, id.rawPub).toString('base64')],
    'a signature over another sealing key': [ek.toString('base64'), iksBy(id, sealingKey()).toString('base64')],
    'a signature naming another key in its input': [ek.toString('base64'), iksBy(id, ek, other.rawPub).toString('base64')],
    'a key a byte short': [ek.subarray(0, 1183).toString('base64'), iksBy(id, ek.subarray(0, 1183)).toString('base64')],
    'a key a byte long': [longer.toString('base64'), iksBy(id, longer).toString('base64')],
    'a signature a byte short': [ek.toString('base64'), iks.subarray(0, 63).toString('base64')],
    'the key in base64url': [ek.toString('base64url'), iks.toString('base64')],
    'the signature without its padding': [ek.toString('base64'), iks.toString('base64').replace(/=+$/, '')],
    'a key that is not a string': [7, iks.toString('base64')],
    'no signature': [ek.toString('base64'), undefined],
  };
  for (const [why, [k, sig]] of Object.entries(refusals)) {
    assert.deepStrictEqual(await c.ikeyRaw(k, sig), { t: 'error', code: 'bad_ikey' }, why);
    assert.strictEqual(await heldEntry(h, id.rid), null, `${why}: nothing held`);
  }
  // Taken: held byte for byte, and named by the next login.
  assert.deepStrictEqual(await c.publish(ek, iks), { t: 'ikey_ok' });
  assert.deepStrictEqual(await heldEntry(h, id.rid), Buffer.concat([ek, iks]), 'held as ek || iks');
  await leave(h, c);
  const again = new Client(h.port, id);
  const r2 = await again.auth();
  assert.strictEqual(r2.ik, hintOf(ek, iks), 'the next login names it by its hint');
  assert.strictEqual(r2.ik.length, 22);
  const after = (await getMetrics(h.port)).body;
  assert.strictEqual(metric(after, 'z_ikey_published_total') - metric(before, 'z_ikey_published_total'), 1, 'one publish taken, counted');
  for (const x of [a, again]) x.close();
}

// Criterion 1 sends a dozen frames from one routing id; its pace is
// criterion 6's, so it is lifted here.
const unpaced = { ikeyPerRidPerMin: 100 };

test('1 RAM: ik:1 in every challenge; a publish needs a v2 login and an iks by its own key over its own key, and ready names what is held', async (t) => {
  await publishing(await ram(t, unpaced));
});

test('1b Redis: ik:1 in every challenge; a publish needs a v2 login and an iks by its own key over its own key, and ready names what is held', { skip: SKIP_REDIS }, async (t) => {
  await publishing(await redis(t, unpaced));
});

// ---- 2. a login renews an entry; a publish does not ----------------------------

test('2 RAM: an entry lives OWNED_TTL from its last login — a login renews it, a re-publish does not, and one nobody logs in for goes', async (t) => {
  const h = await ram(t);
  // The coordinator's own clock, so the month is a number and not a wait.
  const T0 = 1_000_000_000_000;
  const ttl = CFG.ownedTtlMs;
  const id = makeIdentity();
  const e1 = Buffer.concat([sealingKey(), crypto.randomBytes(64)]);
  const e2 = Buffer.concat([sealingKey(), crypto.randomBytes(64)]);
  assert.strictEqual(await h.coord.setIkey(id.rid, e1, null, T0), 'set');
  assert.strictEqual(h.coord.ikeys.get(id.rid).at, T0);
  // A re-publish a day later replaces the key and leaves its life alone.
  assert.strictEqual(await h.coord.setIkey(id.rid, e2, null, T0 + 86400000), 'replaced');
  assert.strictEqual(h.coord.ikeys.get(id.rid).at, T0, 'a re-publish renews nothing');
  assert.deepStrictEqual(await h.coord.getIkey(id.rid, T0 + 86400000), e2, 'but it is the new key that is served');
  assert.strictEqual(await h.coord.getIkey(id.rid, T0 + ttl + 1), null, 'past OWNED_TTL from the publish, no key');
  // A login before then renews it from that moment.
  const kept = makeIdentity();
  await h.coord.setIkey(kept.rid, e1, null, T0);
  const loginAt = T0 + ttl - 1000;
  assert.deepStrictEqual(await h.coord.ikeyLogin(kept.rid, null, loginAt), e1, 'a login finds its entry');
  assert.strictEqual(h.coord.ikeys.get(kept.rid).at, loginAt);
  assert.deepStrictEqual(await h.coord.getIkey(kept.rid, T0 + ttl + 1), e1, 'and renews it');
  assert.deepStrictEqual(await h.coord.getIkey(kept.rid, loginAt + ttl), e1);
  assert.strictEqual(await h.coord.getIkey(kept.rid, loginAt + ttl + 1), null, 'for OWNED_TTL from the login');
  // The sweep forgets what has lapsed, and only that.
  h.coord._trimIkeys(T0 + ttl + 1);
  assert.ok(!h.coord.ikeys.has(id.rid), 'lapsed: forgotten');
  assert.ok(h.coord.ikeys.has(kept.rid), 'renewed: kept');
  // Through the frames: a real login moves the entry's clock.
  const { id: p, c } = await publisher(h, { stay: true });
  const first = h.coord.ikeys.get(p.rid).at;
  await millisecondsPass(3);
  assert.deepStrictEqual(await c.publish(sealingKey(), iksBy(p, sealingKey())), { t: 'error', code: 'bad_ikey' }, '(a bad one changes nothing either)');
  const ek3 = sealingKey();
  assert.deepStrictEqual(await c.publish(ek3, iksBy(p, ek3)), { t: 'ikey_ok' });
  assert.strictEqual(h.coord.ikeys.get(p.rid).at, first, 'a re-publish over the frames renews nothing');
  await leave(h, c);
  await millisecondsPass(3);
  const c2 = new Client(h.port, p);
  assert.strictEqual((await c2.auth()).ik, hintOf(ek3, iksBy(p, ek3)));
  assert.ok(h.coord.ikeys.get(p.rid).at > first, 'a login does');
  c2.close();
});

test('2b Redis: ik:{rid} is renewed with owned:{rid} at each login, and a re-publish keeps its TTL', { skip: SKIP_REDIS }, async (t) => {
  const h = await redis(t);
  const { id, c } = await publisher(h, { stay: true });
  const key = `ik:${id.rid}`;
  const p0 = await h.raw.pttl(key);
  assert.ok(p0 > CFG.ownedTtlMs - 60000 && p0 <= CFG.ownedTtlMs, 'a new entry lives OWNED_TTL');
  await millisecondsPass(30);
  const ek2 = sealingKey();
  assert.deepStrictEqual(await c.publish(ek2, iksBy(id, ek2)), { t: 'ikey_ok' });
  const p1 = await h.raw.pttl(key);
  assert.ok(p1 < p0, `a re-publish keeps the TTL it had (${p1} < ${p0})`);
  assert.deepStrictEqual(await h.raw.getBuffer(key), Buffer.concat([ek2, iksBy(id, ek2)]), 'and replaces the key');
  await leave(h, c);
  await millisecondsPass(30);
  const before = await h.raw.pttl(key);
  const c2 = new Client(h.port, id);
  assert.strictEqual((await c2.auth()).ik, hintOf(ek2, iksBy(id, ek2)));
  const p2 = await h.raw.pttl(key);
  assert.ok(p2 > before, `a login renews it (${p2} > ${before})`);
  const owned = await h.raw.pttl(`owned:${id.rid}`);
  assert.ok(Math.abs(owned - p2) < 5000, 'with its ownership');
  c2.close();
});

// ---- 3. a restart loses every entry ------------------------------------------

async function nothingFor(h, who) {
  const { c } = await anon(h);
  assert.deepStrictEqual(await c.fetch(who.rid), { t: 'ikey_for', to: who.rid }, 'nothing served');
  c.close();
  const l = new Client(h.port, who);
  const r = await l.auth();
  assert.strictEqual(r.ik, undefined, "the device's next login names none, so it publishes again");
  const ek = sealingKey();
  assert.deepStrictEqual(await l.publish(ek, iksBy(who, ek)), { t: 'ikey_ok' });
  l.close();
}

test('3 RAM: a restart loses every entry', async (t) => {
  const first = await ram(t);
  const { id } = await publisher(first);
  assert.ok(await heldEntry(first, id.rid));
  shut(first.srv); // a deploy
  const second = await ram(t);
  assert.strictEqual(second.coord.ikeys.size, 0, 'the new process holds none');
  await nothingFor(second, id);
});

test('3b Redis: an instance restart keeps the entries; a store that comes back empty loses them', { skip: SKIP_REDIS }, async (t) => {
  const shared = await sharedStore(t);
  const store = shared.store;
  const a = await redis(t, {}, shared);
  const { id, ek, iks } = await publisher(a);
  shut(a.srv); // a rolling deploy: this instance goes, the store stays
  await a.coord.close();
  const b = await redis(t, {}, shared);
  const { c } = await anon(b);
  assert.deepStrictEqual(await c.fetch(id.rid), servedFrame(id.rid, ek, iks), 'kept across an instance restart');
  c.close();
  // The store with persistence off, as both shipped configurations run it,
  // comes back from its own restart empty; FLUSHALL leaves it so.
  await store.raw.flushall();
  await nothingFor(b, id);
});

// ---- 4. the heartbeat puts entries back after a store loss -----------------------

test('4b Redis: after a store loss the heartbeat puts back the entries of the sockets the instance holds, and only when ik:epoch changed', { skip: SKIP_REDIS }, async (t) => {
  const shared = await sharedStore(t);
  const store = shared.store;
  const one = await redis(t, {}, shared);
  const two = await redis(t, {}, shared);
  // Before any device publishes, a heartbeat writes nothing for this.
  await one.coord.heartbeat();
  assert.strictEqual(await store.raw.get('ik:epoch'), null, 'an instance that holds no copy writes no epoch');
  const here = await publisher(one, { stay: true }); // connected to instance one
  const there = await publisher(two, { stay: true }); // connected to instance two
  const away = await publisher(one); // gone offline
  await one.coord.heartbeat();
  await two.coord.heartbeat();
  const epoch = await store.raw.get('ik:epoch');
  assert.ok(epoch, 'an instance that finds no epoch sets one');
  const lifeBefore = await store.raw.pttl(`ik:${here.id.rid}`);
  await store.raw.flushall(); // the store came back empty
  for (const x of [here, there, away]) assert.strictEqual(await heldEntry(one, x.id.rid), null);
  await one.coord.heartbeat();
  assert.deepStrictEqual(await heldEntry(one, here.id.rid), Buffer.concat([here.ek, here.iks]), 'put back by the instance holding its socket');
  const lifeAfter = await store.raw.pttl(`ik:${here.id.rid}`);
  assert.ok(lifeAfter <= lifeBefore && lifeAfter > lifeBefore - 60000, `with the life it had left (${lifeAfter} ≤ ${lifeBefore})`);
  assert.strictEqual(await heldEntry(one, there.id.rid), null, "not another instance's socket's");
  assert.strictEqual(await heldEntry(one, away.id.rid), null, 'nor a device that has gone offline');
  const newEpoch = await store.raw.get('ik:epoch');
  assert.ok(newEpoch && newEpoch !== epoch, 'a new epoch');
  await two.coord.heartbeat();
  assert.deepStrictEqual(await heldEntry(two, there.id.rid), Buffer.concat([there.ek, there.iks]), 'and the other instance puts back its own');
  // Only on a change: with the epoch as it was, a missing entry stays missing
  // until its device logs in — the heartbeat does not write on every beat.
  await store.raw.del(`ik:${here.id.rid}`);
  await one.coord.heartbeat();
  assert.strictEqual(await heldEntry(one, here.id.rid), null, 'no change of epoch, nothing put back');
  // And `ready` at the device's next login says so, and it publishes again.
  here.c.close();
  await waitUntil(() => gone(one, here.id.rid), { what: 'here gone' });
  const back = new Client(one.port, here.id);
  assert.strictEqual((await back.auth()).ik, undefined);
  assert.deepStrictEqual(await back.publish(here.ek, here.iks), { t: 'ikey_ok' });
  for (const x of [back, there.c]) x.close();
});

// ---- 5. IKEY_CAP forgets the least recently authenticated ---------------------

async function capForgetsTheOldest(h, settle) {
  const before = (await getMetrics(h.port)).body;
  const a = await publisher(h);
  await millisecondsPass(3);
  const b = await publisher(h);
  await millisecondsPass(3);
  // A logs in again: B is now the one least recently authenticated.
  const a2 = new Client(h.port, a.id);
  assert.strictEqual((await a2.auth()).ik, hintOf(a.ek, a.iks));
  await leave(h, a2);
  await millisecondsPass(3);
  // IKEY_CAP is 2: a third, new entry is taken, and B goes for it.
  const c = await publisher(h);
  await settle();
  assert.ok(await heldEntry(h, c.id.rid), 'a new entry past the cap is taken');
  assert.strictEqual(await heldEntry(h, b.id.rid), null, 'B, least recently authenticated, went for it');
  assert.ok(await heldEntry(h, a.id.rid), 'A, which logged in since, stays');
  const after = (await getMetrics(h.port)).body;
  assert.strictEqual(metric(after, 'z_ikey_evicted_total') - metric(before, 'z_ikey_evicted_total'), 1, 'counted');
  // B's next login names none, and it publishes again — now A is the oldest.
  await millisecondsPass(3);
  const b2 = new Client(h.port, b.id);
  assert.strictEqual((await b2.auth()).ik, undefined);
  assert.deepStrictEqual(await b2.publish(b.ek, b.iks), { t: 'ikey_ok' });
  await leave(h, b2);
  await settle();
  assert.strictEqual(await heldEntry(h, a.id.rid), null, 'A, least recently authenticated now, went');
  assert.ok(await heldEntry(h, b.id.rid));
  assert.ok(await heldEntry(h, c.id.rid));
}

test('5 RAM: IKEY_CAP takes a new entry and forgets the one least recently authenticated', async (t) => {
  await capForgetsTheOldest(await ram(t, { ikeyCap: 2 }), async () => {});
});

test('5b Redis: IKEY_CAP takes a new entry and the sweep forgets the one least recently authenticated', { skip: SKIP_REDIS }, async (t) => {
  const h = await redis(t, { ikeyCap: 2 });
  await capForgetsTheOldest(h, () => h.coord.sweep());
});

// ---- 6. pacing -------------------------------------------------------------------

async function paced(h) {
  // Per routing id, every frame: three a minute here.
  const { id, ek, iks, c } = await publisher(h, { stay: true });
  assert.deepStrictEqual(await c.ikeyRaw('not a key', iks.toString('base64')), { t: 'error', code: 'bad_ikey' }, 'a bad frame counts too');
  assert.deepStrictEqual(await c.publish(ek, iks), { t: 'ikey_ok' });
  const ek2 = sealingKey();
  assert.deepStrictEqual(await c.publish(ek2, iksBy(id, ek2)), { t: 'error', code: 'rate_limited' }, 'the fourth frame in a minute is refused');
  assert.deepStrictEqual(await heldEntry(h, id.rid), Buffer.concat([ek, iks]), 'and the entry stays as it was');
  c.close();
  // Per client address, CLIENT_IP_HEADER being set: two NEW entries a minute
  // here; replacing one does not count.
  const x = await publisher(h, { stay: true, headers: { 'x-test-ip': '10.0.0.1' } });
  const ekx = sealingKey();
  assert.deepStrictEqual(await x.c.publish(ekx, iksBy(x.id, ekx)), { t: 'ikey_ok' }, 'a replacement');
  const y = await publisher(h, { stay: true, headers: { 'x-test-ip': '10.0.0.1' } });
  const z = new Client(h.port, makeIdentity(), { 'x-test-ip': '10.0.0.1' });
  assert.strictEqual((await z.auth()).t, 'ready');
  const ekz = sealingKey();
  assert.deepStrictEqual(await z.publish(ekz, iksBy(z.identity, ekz)), { t: 'error', code: 'rate_limited' }, 'a third new entry from one address in a minute is refused');
  assert.strictEqual(await heldEntry(h, z.identity.rid), null, 'and not kept');
  const eky = sealingKey();
  assert.deepStrictEqual(await y.c.publish(eky, iksBy(y.id, eky)), { t: 'ikey_ok' }, 'while one it holds is still replaced');
  const w = await publisher(h, { stay: true, headers: { 'x-test-ip': '10.0.0.2' } });
  for (const v of [x.c, y.c, z, w.c]) v.close();
}

const pacedCfg = { ikeyPerRidPerMin: 3, ikeyNewPerIpPerMin: 2, clientIpHeader: 'x-test-ip' };

test('6 RAM: ikey frames are paced per routing id, and new entries per client address when CLIENT_IP_HEADER names one', async (t) => {
  await paced(await ram(t, pacedCfg));
});

test('6b Redis: ikey frames are paced per routing id, and new entries per client address when CLIENT_IP_HEADER names one', { skip: SKIP_REDIS }, async (t) => {
  await paced(await redis(t, pacedCfg));
});

test('6 RAM: without CLIENT_IP_HEADER there is no per-address pace', async (t) => {
  const h = await ram(t, { ikeyNewPerIpPerMin: 2 });
  for (let i = 0; i < 4; i++) await publisher(h);
  assert.strictEqual(h.coord.ikeys.size, 4, 'four new entries from one socket address');
});

// ---- 7. fetching -----------------------------------------------------------------

/** Everything the relay holds that a fetch could have written to. */
async function footprint(h) {
  if (h.kind === 'ram') {
    const c = h.coord;
    return JSON.stringify({
      ikeys: [...c.ikeys.keys()],
      owned: [...c.owned.keys()],
      queues: [...c.queues.keys()],
      seen: c.seen.size,
      intro: c.intro.size,
      unownedIp: [...c.unownedIp.ips.keys()],
      pushTokens: c.pushTokens.size,
    });
  }
  const keys = (await h.raw.keys('*')).filter((k) => !k.startsWith('presence:')).sort();
  return JSON.stringify(keys);
}

async function fetching(h) {
  const before = (await getMetrics(h.port)).body;
  const keeper = await publisher(h);
  // An owned mailbox that keeps no key: it authenticated, and published none.
  const keyless = makeIdentity();
  const kc = new Client(h.port, keyless);
  assert.strictEqual((await kc.auth()).t, 'ready');
  await leave(h, kc);
  const unknown = makeIdentity(); // a mailbox this relay has never seen
  const { c } = await anon(h);
  const start = await footprint(h);
  assert.deepStrictEqual(await c.fetch(keeper.id.rid), servedFrame(keeper.id.rid, keeper.ek, keeper.iks), 'the entry, byte for byte');
  const a = await c.fetch(keyless.rid);
  const b = await c.fetch(unknown.rid);
  assert.deepStrictEqual(a, { t: 'ikey_for', to: keyless.rid }, 'an owned mailbox with no key: nothing');
  assert.deepStrictEqual(b, { t: 'ikey_for', to: unknown.rid });
  assert.deepStrictEqual(Object.keys(a).sort(), Object.keys(b).sort(), 'the same answer, member for member, as for a mailbox nobody has seen');
  // Asked many times, from several sockets: nothing about who asked is kept.
  for (let i = 0; i < 20; i++) {
    const { c: s } = await anon(h);
    await s.fetch([keeper.id.rid, keyless.rid, unknown.rid][i % 3]);
    s.close();
  }
  assert.strictEqual(await footprint(h), start, 'the relay holds exactly what it held before the fetches');
  // Not on an authenticated connection, whatever it asks; and not for
  // something that is no routing id.
  const authed = new Client(h.port, makeIdentity());
  assert.strictEqual((await authed.auth()).t, 'ready');
  assert.deepStrictEqual(await authed.fetch(keeper.id.rid), { t: 'error', code: 'anon_only' }, 'refused on an authenticated connection');
  assert.deepStrictEqual(await authed.fetch(unknown.rid), { t: 'error', code: 'anon_only' });
  for (const to of ['', 'x'.repeat(42), 'x'.repeat(44), 7, null]) {
    assert.deepStrictEqual(await c.fetch(to), { t: 'error', code: 'bad_ikey' }, `to = ${JSON.stringify(to)}`);
  }
  const after = (await getMetrics(h.port)).body;
  const delta = (n) => metric(after, n) - metric(before, n);
  assert.strictEqual(delta('z_ikey_served_total'), 1 + 7, 'answers with a key, counted');
  assert.strictEqual(delta('z_ikey_missing_total'), 2 + 13, 'answers with none, counted');
  assert.strictEqual(delta('z_ikey_anon_only_total'), 2, 'refusals on an authenticated connection, counted');
  for (const x of [c, authed]) x.close();
}

test('7 RAM: ikey_get on an anonymous connection only — the entry or nothing, alike for unknown and keyless mailboxes, and nothing kept about the asker', async (t) => {
  await fetching(await ram(t));
});

test('7b Redis: ikey_get on an anonymous connection only — the entry or nothing, alike for unknown and keyless mailboxes, and nothing kept about the asker', { skip: SKIP_REDIS }, async (t) => {
  await fetching(await redis(t));
});

// ---- 8. /metrics -----------------------------------------------------------------

async function metrics(h, settle) {
  const res = await getMetrics(h.port);
  assert.strictEqual(res.status, 200, 'read with the bearer token');
  for (const name of ['z_ikey_published_total', 'z_ikey_served_total', 'z_ikey_missing_total', 'z_ikey_evicted_total', 'z_ikey_anon_only_total']) {
    assert.ok(metric(res.body, name) !== null, `${name} reported`);
  }
  await publisher(h);
  await publisher(h);
  await settle();
  const after = (await getMetrics(h.port)).body;
  assert.strictEqual(metric(after, 'z_ikeys'), 2, 'z_ikeys: the entries held');
  const noToken = await new Promise((resolve, reject) => {
    http.get(`http://127.0.0.1:${h.port}/metrics`, (r) => resolve(r.statusCode)).on('error', reject);
  });
  assert.strictEqual(noToken, 401, 'and nothing without the token');
}

test('8 RAM: /metrics counts introduction keys, with the METRICS_TOKEN bearer', async (t) => {
  await metrics(await ram(t), async () => {});
});

test('8b Redis: /metrics counts introduction keys, z_ikeys as the last sweep counted', { skip: SKIP_REDIS }, async (t) => {
  const h = await redis(t);
  await metrics(h, () => h.coord.sweep());
});
