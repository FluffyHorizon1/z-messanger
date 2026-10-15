'use strict';

// Found by an independent review of handles (2026-10-09): an introduction
// mailbox's flag lived in the RAM owner list and left with it, so
// authenticating OWNED_CAP throwaway identities stripped it and the mailbox
// took sends with no stamp; and a restart of a RAM relay strips every flag
// (PROTOCOL §21.6). Now the flags are a bounded store of their own that no
// login moves, `intro` frames are paced, and a
// stamp travels with its envelope to the owner — into a flagged mailbox
// always, into any other when it is worth 16 bits — so the owner's app checks
// the work itself, and a flag the relay loses costs an honest request
// nothing. Through the real relay, in RAM and in the Redis path (skipped, as
// the HA tests are, without redis-server or ioredis). The stamps are made
// here from the specification.
//
// Criteria, each asserted below (N in RAM, Nb in the Redis path):
//   1. the review's probe: after an owner flags its mailbox, authenticating
//      throwaway identities — OWNED_CAP of them, which pushes the owner out
//      of the RAM owner list — leaves the flag: an unstamped send is still
//      refused `pow_required`, the owner's next drain holds only stamped
//      envelopes, and the mailbox keeps the owned caps (more than
//      UNOWNED_MAILBOX_BYTES of stamped requests taken, none of it charged to
//      the unowned budget);
//   2. a full flag store (INTRO_CAP) takes a NEW flag and forgets the entry
//      least recently renewed for it (in the Redis path, at its sweep) —
//      never refuses one, since whoever filled the store would otherwise
//      deny every owner a flag after a restart — and a renewal, the owner's
//      own `intro`, moves a flag to the back of that queue;
//   3. `intro` frames are paced: past INTRO_PER_RID_PER_MIN in a minute a
//      routing id is refused `rate_limited` and its flag stays as it was;
//      with CLIENT_IP_HEADER naming the client address, past
//      INTRO_NEW_PER_IP_PER_MIN new flags in a minute that address is
//      refused `rate_limited` while another address still flags, and
//      renewing a flag it holds does not count (without the header there is
//      no per-address pace: intro_flag_shadow.test.js);
//   4. an envelope taken into a flagged mailbox reaches the owner with the
//      stamp it was taken on, `pow`, and the day that stamp was good under,
//      `powDay` — live and from the flush, a today's and a yesterday's
//      stamp, `powDay` the day of the envelope's `ts` or the one before — so
//      the owner can check the work itself; into a mailbox nobody flagged a
//      stamp worth 16 bits for the relay's today or yesterday travels the
//      same way, flushed and live, and that mailbox still refuses nothing:
//      no stamp, a malformed one, one short of 16 bits, one two days old and
//      one on an envelope over 64 KiB are all taken, and carry neither;
//   5. a flag the relay loses — a RAM relay's restart, or a store with
//      persistence off coming back empty — leaves the mailbox taking
//      unstamped sends until the owner's next `intro`, each arriving with no
//      `pow`, which is how the owner's app tells it from a request that was
//      stamped; a stamped request taken meanwhile arrives with its stamp,
//      which checks out, so it is not lost; once the owner flags again a
//      stamp is needed again.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, CFG, RedisCoordinator, routingIdFromPub } = require('../server.js');

const V2 = Buffer.from('z-relay-auth-v2:', 'utf8');

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

// ---- the stamp, from the specification (PROTOCOL §21.6) --------------------

const POW_CONTEXT = Buffer.from('z-intro-pow-v1:', 'utf8');
const DAY_MS = 86400000;
const today = () => Math.floor(Date.now() / DAY_MS);
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const u32be = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
function zeroBits(h) {
  let n = 0;
  for (const byte of h) {
    if (byte === 0) {
      n += 8;
      continue;
    }
    for (let mask = 0x80; mask && !(byte & mask); mask >>= 1) n += 1;
    break;
  }
  return n;
}
const prefixFor = (rid, payload, day) =>
  Buffer.concat([POW_CONTEXT, Buffer.from(rid, 'base64url'), u32be(day), sha256(Buffer.from(payload, 'utf8'))]);
/** What an owner's app checks: the leading zero bits a stamp earns for its
 * own mailbox, this payload and the day it was handed. */
const bitsOf = (rid, payload, day, pow) => zeroBits(sha256(Buffer.concat([prefixFor(rid, payload, day), Buffer.from(pow, 'base64url')])));
/** A nonce good for (rid, payload, day) at `min` bits, and for neither day in
 * `avoid` — so a yesterday's stamp is one the relay can only take as such. */
function mine({ rid, payload, day, min, avoid = [] }) {
  const base = crypto.createHash('sha256').update(prefixFor(rid, payload, day));
  const nonce = crypto.randomBytes(16);
  for (let i = 0; ; i++) {
    nonce.writeUInt32BE(i >>> 0, 12);
    if (zeroBits(base.copy().update(nonce).digest()) < min) continue;
    const pow = nonce.toString('base64url');
    if (avoid.every((d) => bitsOf(rid, payload, d, pow) < min)) return pow;
  }
}
/** A stamp made against the day it was made on, re-made if UTC midnight passed
 * while it was mined, so the relay's clock agrees with the one it was made for. */
function stamp(make) {
  for (;;) {
    const d = today();
    const s = make(d);
    if (today() === d) return s;
  }
}
/** A well-formed stamp worth fewer than 16 bits for (rid, payload) on either
 * day the relay takes — what a mailbox nobody flagged ignores. */
function weak(rid, payload) {
  return stamp((d) => {
    for (;;) {
      const pow = crypto.randomBytes(16).toString('base64url');
      if (bitsOf(rid, payload, d, pow) < 16 && bitsOf(rid, payload, d - 1, pow) < 16) return pow;
    }
  });
}
/** The day of a delivered envelope's `ts` less its `powDay`: 0 or 1 when the
 * relay took the stamp under its today or yesterday at that moment. */
const powAge = (m) => Math.floor(m.ts / DAY_MS) - m.powDay;

// ---- harness -----------------------------------------------------------------

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey, rawPub, rid: routingIdFromPub(rawPub) };
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
    this.closed = null;
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`, { headers });
    this.ws.on('error', () => {});
    this.ws.on('close', (code) => (this.closed = code == null ? 1006 : code));
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
  async seenChallenge() {
    return this.next((f) => f.t === 'challenge');
  }
  async auth() {
    const ch = await this.seenChallenge();
    const msg = Buffer.concat([V2, Buffer.from(`127.0.0.1:${this.port}`, 'utf8'), Buffer.from(ch.nonce, 'base64')]);
    const sig = crypto.sign(null, msg, this.identity.privateKey);
    this.send({ t: 'auth', v: 2, pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    return this.next((f) => f.t === 'ready' || f.t === 'error');
  }
  intro(pow) {
    this.send({ t: 'intro', pow });
    return this.next((f) => f.t === 'intro_ok' || f.t === 'error');
  }
  ask(frame, answers) {
    this.send(frame);
    return this.next((f) => answers.includes(f.t));
  }
  deliver(id, to, payload, pow) {
    const frame = { t: 'send', id, to, payload };
    if (pow !== undefined) frame.pow = pow;
    this.send(frame);
    return this.next((f) => (f.t === 'sent' || f.t === 'error') && f.id === id, 15000);
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
/** A relay in the Redis path on a redis-server of its own; the sweep only when
 * a test calls it, so a counted store is the test's doing. */
async function redis(t, cfg = {}) {
  const { redisPort, raw, stop } = await startRedis();
  const restore = withCfg({ sweepIntervalMs: 3600000, ...cfg });
  const coord = new RedisCoordinator(`redis://127.0.0.1:${redisPort}`, 'instA');
  const srv = createServer({ coordinator: coord, pushSender: null });
  const port = await listen(srv);
  t.after(async () => {
    shut(srv);
    await coord.close();
    await stop();
    restore();
  });
  return { kind: 'redis', srv, coord, port, raw };
}
async function gone(h, rid) {
  if (h.kind === 'ram') return !h.coord.online.has(rid);
  return !h.coord.local.has(rid) && (await h.raw.exists(`presence:${rid}`)) === 0;
}
function leave(h, client) {
  client.close();
  return waitUntil(() => gone(h, client.identity.rid), { what: `${client.identity.rid.slice(0, 8)}… gone from the relay` });
}
async function flagOf(h, rid) {
  if (h.kind === 'ram') return h.coord.introBits(rid);
  return Number(await h.raw.get(`intro:${rid}`)) || 0;
}
/** An owner that authenticates with v2, flags its mailbox, and leaves. */
async function flaggedOwner(h, bits = 16, headers = {}) {
  const owner = makeIdentity();
  const c = new Client(h.port, owner, headers);
  assert.strictEqual((await c.auth()).t, 'ready');
  assert.deepStrictEqual(await c.intro(bits), { t: 'intro_ok' });
  await leave(h, c);
  return owner;
}
async function anonSender(h) {
  const s = new Client(h.port, makeIdentity());
  await s.seenChallenge();
  return s;
}
/** What the store holds for `rid`: its entries as stored, and the payload
 * hashes it has indexed to recognise a copy. */
async function heldFor(h, rid) {
  if (h.kind === 'ram') {
    const q = h.coord.queues.get(rid);
    return { entries: q ? q.entries.map((e) => ({ ...e })) : [], index: q && q.hashes ? [...q.hashes.keys()] : [] };
  }
  const all = await h.raw.hgetall(`qe:${rid}`);
  return {
    entries: Object.entries(all)
      .filter(([k]) => !k.startsWith('h:'))
      .map(([, v]) => JSON.parse(v)),
    index: Object.keys(all).filter((k) => k.startsWith('h:')),
  };
}
/** Everything the relay holds for `rid`, read off a fresh connection as `who`,
 * acknowledged so the relay forgets it. */
async function drain(h, who, count) {
  const c = new Client(h.port, who);
  assert.strictEqual((await c.auth()).t, 'ready');
  const got = [];
  for (let i = 0; i < count; i++) {
    const m = await c.next((f) => f.t === 'msg');
    got.push(m);
    c.send({ t: 'recv', id: m.id });
  }
  return { client: c, got };
}
const SEALED = (tag, n = 600) => 'zs1.' + sha256(tag).toString('base64url') + 'x'.repeat(n);
const sent = (id) => ({ t: 'sent', id, queued: true });
const isPowRequired = (r, id, bits) => r.t === 'error' && r.code === 'pow_required' && r.id === id && r.bits === bits;

// ---- 1. the review's probe: a flood of logins leaves the flag ----------------

async function floodLeavesTheFlag(h, throwaways) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  assert.ok(isPowRequired(await s.deliver('before', owner.rid, SEALED('before')), 'before', 16), 'control: the flag is in force');
  // The attack: authenticate fresh identities — free keys — fifty at a time.
  const t0 = Date.now();
  for (let i = 0; i < throwaways; i += 50) {
    await Promise.all(
      Array.from({ length: Math.min(50, throwaways - i) }, async () => {
        const c = new Client(h.port, makeIdentity());
        assert.strictEqual((await c.auth()).t, 'ready');
        c.close();
      })
    );
  }
  const ms = Date.now() - t0;
  if (h.kind === 'ram') assert.ok(!h.coord.owned.has(owner.rid), 'the flood pushed the owner out of the owner list');
  assert.strictEqual(await flagOf(h, owner.rid), 16, 'and left the flag');
  for (let i = 0; i < 5; i++) {
    assert.ok(isPowRequired(await s.deliver(`after-${i}`, owner.rid, SEALED(`after-${i}`)), `after-${i}`, 16), 'an unstamped send is still refused');
  }
  // Still owned for its caps: three stamped requests of 2 256 bytes each are
  // past UNOWNED_MAILBOX_BYTES (4 000 here), and none of it is unowned.
  const unownedBefore = h.kind === 'ram' ? h.coord.unownedBytes : null;
  const payloads = ['a', 'b', 'c'].map((c) => 'zs1.' + c.repeat(2000 - 4));
  for (let i = 0; i < 3; i++) {
    const pow = stamp((d) => mine({ rid: owner.rid, payload: payloads[i], day: d, min: 16 }));
    assert.deepStrictEqual(await s.deliver(`ok-${i}`, owner.rid, payloads[i], pow), sent(`ok-${i}`), 'a stamped request is taken under the owned caps');
  }
  if (h.kind === 'ram') assert.strictEqual(h.coord.unownedBytes, unownedBefore, 'nothing charged to the unowned budget');
  else assert.strictEqual(await h.raw.exists(`owned:${owner.rid}`), 1, 'the store still has the mailbox owned');
  // The owner's next drain holds the three stamped envelopes and nothing else.
  const { client, got } = await drain(h, owner, 3);
  assert.deepStrictEqual(got.map((m) => m.id).sort(), ['ok-0', 'ok-1', 'ok-2']);
  assert.ok(got.every((m) => typeof m.pow === 'string'), 'each with its stamp');
  client.close();
  s.close();
  return ms;
}

test('1 RAM: the review\'s probe — OWNED_CAP throwaway logins no longer strip a flag', async (t) => {
  const h = await ram(t, { ownedCap: 300, unownedMailboxBytes: 4000 });
  const ms = await floodLeavesTheFlag(h, CFG.ownedCap);
  t.diagnostic(`${CFG.ownedCap} throwaway authentications took ${ms} ms; the flag stood`);
});

test('1b Redis: a flood of throwaway logins leaves a flag', { skip: SKIP_REDIS }, async (t) => {
  const h = await redis(t, { unownedMailboxBytes: 4000 });
  await floodLeavesTheFlag(h, 100);
});

// ---- 2. a full flag store forgets the least recently renewed -------------------

/** The store, INTRO_CAP 2, as the owners of A, B and C would see it: a NEW
 * flag is never refused for the store being full; the entry least recently
 * renewed goes for it (the second review of the handles fixes, 2026-10-10 —
 * refusing let whoever filled the store deny every owner a flag after a
 * restart), and a renewal moves an entry to the back of that queue. `settle`
 * is what the Redis path needs between a flood and the count: its sweep. */
async function fullStoreForgetsTheOldest(h, settle) {
  // The Redis path tells "least recently renewed" by the life each key has
  // left, at the store's millisecond resolution; so the clock moves on
  // between one renewal and the next, as it does between two drains.
  const millisecondsPass = async (n) => {
    const t = Date.now();
    await waitUntil(() => Date.now() >= t + n, { what: `${n} ms on the clock` });
  };
  const a = makeIdentity();
  const b = makeIdentity();
  const c = makeIdentity();
  const ac = new Client(h.port, a);
  const bc = new Client(h.port, b);
  const cc = new Client(h.port, c);
  for (const x of [ac, bc, cc]) assert.strictEqual((await x.auth()).t, 'ready');
  assert.deepStrictEqual(await ac.intro(16), { t: 'intro_ok' });
  assert.deepStrictEqual(await bc.intro(16), { t: 'intro_ok' });
  await millisecondsPass(3);
  // A renewal: A is now the more recently renewed of the two.
  assert.deepStrictEqual(await ac.intro(20), { t: 'intro_ok' }, 'renewing a held flag');
  assert.strictEqual(await flagOf(h, a.rid), 20);
  await millisecondsPass(3);
  // INTRO_CAP is 2: a third, new flag is taken, and B, least recently
  // renewed, is forgotten for it — not A, renewed since.
  assert.deepStrictEqual(await cc.intro(16), { t: 'intro_ok' }, 'a new flag past INTRO_CAP is taken');
  await settle();
  assert.strictEqual(await flagOf(h, c.rid), 16, 'and set');
  assert.strictEqual(await flagOf(h, b.rid), 0, "B's flag, least recently renewed, went for it");
  assert.strictEqual(await flagOf(h, a.rid), 20, "A's, renewed since, stands");
  const s = await anonSender(h);
  assert.ok(isPowRequired(await s.deliver('a1', a.rid, SEALED('a1')), 'a1', 20), "A's mailbox is guarded");
  assert.deepStrictEqual(await s.deliver('b1', b.rid, SEALED('b1')), sent('b1'), "B's is not, until B's next drain");
  // B's next drain flags it again — a new flag, so now A, the least recently
  // renewed, goes.
  await millisecondsPass(3);
  assert.deepStrictEqual(await bc.intro(16), { t: 'intro_ok' }, "B's owner flags again");
  await settle();
  assert.strictEqual(await flagOf(h, b.rid), 16);
  assert.strictEqual(await flagOf(h, a.rid), 0, 'A, least recently renewed, went for it');
  assert.strictEqual(await flagOf(h, c.rid), 16);
  for (const x of [ac, bc, cc, s]) x.close();
}

test('2 RAM: a full flag store takes a new flag and forgets the one least recently renewed', async (t) => {
  await fullStoreForgetsTheOldest(await ram(t, { introCap: 2 }), async () => {});
});

test('2b Redis: a full flag store takes a new flag and the sweep forgets the one least recently renewed', { skip: SKIP_REDIS }, async (t) => {
  const h = await redis(t, { introCap: 2 });
  await fullStoreForgetsTheOldest(h, () => h.coord.sweep());
});

// ---- 3. intro frames are paced -------------------------------------------------

async function paced(h) {
  // Per routing id: three frames a minute here.
  const owner = makeIdentity();
  const oc = new Client(h.port, owner);
  assert.strictEqual((await oc.auth()).t, 'ready');
  for (let i = 0; i < 3; i++) assert.deepStrictEqual(await oc.intro(16), { t: 'intro_ok' });
  assert.deepStrictEqual(await oc.intro(24), { t: 'error', code: 'rate_limited' }, 'the fourth in a minute is refused');
  assert.strictEqual(await flagOf(h, owner.rid), 16, 'and the flag stays as it was');
  oc.close();
  // Per client address, CLIENT_IP_HEADER being set: two NEW flags a minute
  // here; renewing a flag already held does not count.
  const joined = async (ip) => {
    const id = makeIdentity();
    const c = new Client(h.port, id, { 'x-test-ip': ip });
    assert.strictEqual((await c.auth()).t, 'ready');
    return { id, c };
  };
  const x = await joined('10.0.0.1');
  for (let i = 0; i < 3; i++) assert.deepStrictEqual(await x.c.intro(16), { t: 'intro_ok' }, 'one new flag, renewed twice');
  const y = await joined('10.0.0.1');
  assert.deepStrictEqual(await y.c.intro(16), { t: 'intro_ok' }, 'the renewals did not count: a second new flag is taken');
  const z = await joined('10.0.0.1');
  assert.deepStrictEqual(await z.c.intro(16), { t: 'error', code: 'rate_limited' }, 'a third new flag from one address in a minute is refused');
  assert.strictEqual(await flagOf(h, z.id.rid), 0, 'and not set');
  assert.deepStrictEqual(await y.c.intro(17), { t: 'intro_ok' }, 'while a flag it holds is still renewed');
  assert.strictEqual(await flagOf(h, y.id.rid), 17);
  const elsewhere = await joined('10.0.0.2');
  assert.deepStrictEqual(await elsewhere.c.intro(16), { t: 'intro_ok' }, 'another address still flags');
  for (const w of [x, y, z, elsewhere]) w.c.close();
}

const pacedCfg = { introPerRidPerMin: 3, introNewPerIpPerMin: 2, clientIpHeader: 'x-test-ip' };

test('3 RAM: intro frames are paced per routing id, and new flags per client address when CLIENT_IP_HEADER names one', async (t) => {
  await paced(await ram(t, pacedCfg));
});

test('3b Redis: intro frames are paced per routing id, and new flags per client address when CLIENT_IP_HEADER names one', { skip: SKIP_REDIS }, async (t) => {
  await paced(await redis(t, pacedCfg));
});

// ---- 4. the stamp travels with its envelope --------------------------------------

async function stampHandedOn(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  const p1 = SEALED('today');
  const p2 = SEALED('yesterday');
  // Each good for its own day only, so the day the relay takes it under is known.
  let d1;
  let d2;
  const s1 = stamp((d) => {
    d1 = d;
    return mine({ rid: owner.rid, payload: p1, day: d, min: 16, avoid: [d - 1] });
  });
  const s2 = stamp((d) => {
    d2 = d - 1;
    return mine({ rid: owner.rid, payload: p2, day: d - 1, min: 16, avoid: [d] });
  });
  assert.deepStrictEqual(await s.deliver('f1', owner.rid, p1, s1), sent('f1'));
  assert.deepStrictEqual(await s.deliver('f2', owner.rid, p2, s2), sent('f2'));
  // From the flush: each envelope with its stamp and the day it was good under.
  const { client: oc, got } = await drain(h, owner, 2);
  const byId = Object.fromEntries(got.map((m) => [m.id, m]));
  assert.deepStrictEqual(Object.keys(byId.f1).sort(), ['id', 'payload', 'pow', 'powDay', 't', 'ts'], 'no sender; the stamp and its day');
  assert.strictEqual(byId.f1.pow, s1);
  assert.strictEqual(byId.f2.pow, s2);
  assert.strictEqual(byId.f1.powDay, d1, "a today's stamp is handed on with today");
  assert.strictEqual(byId.f2.powDay, d2, "a yesterday's stamp with yesterday");
  for (const m of got) {
    assert.ok(bitsOf(owner.rid, m.payload, m.powDay, m.pow) >= 16, `${m.id}: the owner can check the work itself`);
    assert.ok([0, 1].includes(powAge(m)), `${m.id}: powDay is the day of ts or the one before`);
  }
  // Live: the same.
  const p3 = SEALED('live');
  const s3 = stamp((d) => mine({ rid: owner.rid, payload: p3, day: d, min: 16 }));
  assert.deepStrictEqual(await s.deliver('f3', owner.rid, p3, s3), sent('f3'));
  const live = await oc.next((f) => f.t === 'msg' && f.id === 'f3');
  assert.strictEqual(live.pow, s3, 'a live delivery carries it too');
  assert.ok(bitsOf(owner.rid, p3, live.powDay, live.pow) >= 16);
  assert.ok([0, 1].includes(powAge(live)));
  oc.close();
  // A mailbox nobody flagged refuses nothing. A stamp worth 16 bits for the
  // relay's today or yesterday travels with its envelope all the same, so a
  // flag the relay has lost costs an honest request nothing; any other stamp
  // is ignored as it always was.
  const bob = makeIdentity();
  const bob0 = new Client(h.port, bob);
  assert.strictEqual((await bob0.auth()).t, 'ready');
  await leave(h, bob0);
  let e1;
  let e2;
  const P = { g1: SEALED('g1'), g2: SEALED('g2'), g5: SEALED('g5'), g6: SEALED('g6'), g7: SEALED('g7', 66000) };
  const forwarded = {
    g1: stamp((d) => ((e1 = d), mine({ rid: bob.rid, payload: P.g1, day: d, min: 16, avoid: [d - 1] }))),
    g2: stamp((d) => ((e2 = d - 1), mine({ rid: bob.rid, payload: P.g2, day: d - 1, min: 16, avoid: [d] }))),
  };
  const ignored = {
    g3: [SEALED('g3'), undefined], // none
    g4: [SEALED('g4'), 'not a stamp'], // malformed
    g5: [P.g5, weak(bob.rid, P.g5)], // short of 16 bits on either day
    g6: [P.g6, stamp((d) => mine({ rid: bob.rid, payload: P.g6, day: d - 2, min: 16, avoid: [d, d - 1] }))], // two days old
    g7: [P.g7, stamp((d) => mine({ rid: bob.rid, payload: P.g7, day: d, min: 16 }))], // over 64 KiB: not hashed
  };
  assert.deepStrictEqual(await s.deliver('g1', bob.rid, P.g1, forwarded.g1), sent('g1'));
  assert.deepStrictEqual(await s.deliver('g2', bob.rid, P.g2, forwarded.g2), sent('g2'));
  for (const [id, [payload, pow]] of Object.entries(ignored)) {
    assert.deepStrictEqual(await s.deliver(id, bob.rid, payload, pow), sent(id), `${id}: taken, never refused`);
  }
  // Kept beside the two envelopes whose stamps are worth it — and no copy
  // index, which is a flagged mailbox's alone.
  const held = await heldFor(h, bob.rid);
  assert.deepStrictEqual(held.entries.filter((e) => 'pow' in e).map((e) => e.id).sort(), ['g1', 'g2'], 'two stamps kept');
  assert.ok(held.entries.every((e) => !('ph' in e)) && held.index.length === 0, 'and no payload hash for a mailbox nobody flagged');
  const { client: bc, got: flushed } = await drain(h, bob, 7);
  const fromFlush = Object.fromEntries(flushed.map((m) => [m.id, m]));
  assert.deepStrictEqual([fromFlush.g1.pow, fromFlush.g1.powDay], [forwarded.g1, e1], "a today's stamp, flushed, with today");
  assert.deepStrictEqual([fromFlush.g2.pow, fromFlush.g2.powDay], [forwarded.g2, e2], "a yesterday's, with yesterday");
  for (const id of ['g1', 'g2']) {
    const m = fromFlush[id];
    assert.ok(bitsOf(bob.rid, m.payload, m.powDay, m.pow) >= 16 && [0, 1].includes(powAge(m)), `${id}: checks out`);
  }
  for (const id of Object.keys(ignored)) {
    assert.deepStrictEqual(Object.keys(fromFlush[id]).sort(), ['id', 'payload', 't', 'ts'], `${id}: carries neither`);
  }
  // Live: the same, both ways.
  const p8 = SEALED('g8');
  const s8 = stamp((d) => mine({ rid: bob.rid, payload: p8, day: d, min: 16 }));
  assert.deepStrictEqual(await s.deliver('g8', bob.rid, p8, s8), sent('g8'));
  const g8 = await bc.next((f) => f.t === 'msg' && f.id === 'g8');
  assert.strictEqual(g8.pow, s8, 'live, with its stamp');
  assert.ok(bitsOf(bob.rid, p8, g8.powDay, g8.pow) >= 16 && [0, 1].includes(powAge(g8)));
  const p9 = SEALED('g9');
  assert.deepStrictEqual(await s.deliver('g9', bob.rid, p9, weak(bob.rid, p9)), sent('g9'));
  const g9 = await bc.next((f) => f.t === 'msg' && f.id === 'g9');
  assert.deepStrictEqual(Object.keys(g9).sort(), ['id', 'payload', 't', 'ts'], 'live, a stamp short of 16 bits ignored');
  bc.close();
  s.close();
}

test('4 RAM: a stamp travels with its envelope to the owner, as pow and powDay — always into a flagged mailbox, into any other when worth 16 bits', async (t) => {
  await stampHandedOn(await ram(t));
});

test('4b Redis: a stamp travels with its envelope to the owner, as pow and powDay — always into a flagged mailbox, into any other when worth 16 bits', { skip: SKIP_REDIS }, async (t) => {
  await stampHandedOn(await redis(t));
});

// ---- 5. a flag the relay loses ---------------------------------------------------

async function lostFlag(h, owner) {
  // The mailbox is not guarded at the relay until the owner's next `intro`:
  // an unstamped send is taken, and so is an honest request, stamped at the
  // difficulty the handle asks.
  const s = await anonSender(h);
  assert.deepStrictEqual(await s.deliver('u1', owner.rid, SEALED('u1')), sent('u1'), 'an unstamped send is taken');
  const p2 = SEALED('u2');
  const s2 = stamp((d) => mine({ rid: owner.rid, payload: p2, day: d, min: 16 }));
  assert.deepStrictEqual(await s.deliver('u2', owner.rid, p2, s2), sent('u2'), 'and a stamped one');
  // The unstamped one arrives with no `pow`, which the owner's app drops; the
  // stamped one with its stamp, which checks out — it is not lost.
  const oc = new Client(h.port, owner);
  assert.strictEqual((await oc.auth()).t, 'ready');
  const m1 = await oc.next((f) => f.t === 'msg' && f.id === 'u1');
  assert.ok(!('pow' in m1) && !('powDay' in m1), 'the unstamped one: no pow');
  const m2 = await oc.next((f) => f.t === 'msg' && f.id === 'u2');
  assert.strictEqual(m2.pow, s2, 'the stamped one: its stamp');
  assert.ok(bitsOf(owner.rid, p2, m2.powDay, m2.pow) >= 16 && [0, 1].includes(powAge(m2)), 'which the owner can check');
  for (const id of ['u1', 'u2']) oc.send({ t: 'recv', id });
  // The owner's drain flags it again, and a stamp is needed again.
  assert.deepStrictEqual(await oc.intro(16), { t: 'intro_ok' });
  assert.ok(isPowRequired(await s.deliver('u3', owner.rid, SEALED('u3')), 'u3', 16), 'guarded again');
  oc.close();
  s.close();
}

test('5 RAM: a restart forgets the flags; until the owner flags again, unstamped envelopes arrive without pow and stamped ones with it', async (t) => {
  const first = await ram(t);
  const owner = await flaggedOwner(first, 16);
  shut(first.srv); // a deploy
  const second = await ram(t);
  assert.strictEqual(await flagOf(second, owner.rid), 0, 'the new process knows no flag');
  await lostFlag(second, owner);
});

test('5b Redis: a store that comes back empty forgets the flags the same way', { skip: SKIP_REDIS }, async (t) => {
  const h = await redis(t);
  const owner = await flaggedOwner(h, 16);
  // A store run with persistence off, as both shipped configurations run it,
  // comes back from a restart empty; FLUSHALL leaves it as such a restart would.
  await h.raw.flushall();
  assert.strictEqual(await flagOf(h, owner.rid), 0);
  await lostFlag(h, owner);
});
