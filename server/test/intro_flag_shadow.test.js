'use strict';

// The second review of the handles fixes (2026-10-10) broke the flag store
// two ways. A handle's mailbox whose flag was absent — lapsed, or refused
// after a restart — but whose owner had authenticated to drain it was an
// ordinary owned mailbox: no stamp asked, held to the 64 MiB owned cap, free
// for anyone who had resolved the handle to fill until an honest stamped
// request was refused `queue_full`. And new flags were paced per address
// with the address being everyone's behind a front without CLIENT_IP_HEADER
// (the shipped configuration), so one sender flagging fresh keys ten times
// a minute denied every honest owner the NEW flag a restart made them need;
// a full store (INTRO_CAP) refused new flags outright, so a one-time fill
// did the same for a month. Now a flag has a SHADOW: for OWNED_TTL after it
// lapses the mailbox still asks a stamp at the last difficulty and is still
// held to INTRO_MAILBOX_BYTES, while the owned caps follow the owner list
// alone; the per-address pace engages only when CLIENT_IP_HEADER names a
// client address; and a full store forgets the flag least recently renewed
// rather than refuse. Through the real relay, in RAM and in the Redis path
// (skipped, as the HA tests are, without redis-server or ioredis). The
// stamps are made here from the specification (PROTOCOL §21.6).
//
// Criteria, each asserted below (N in RAM, Nb in the Redis path):
//   1. the review's probe 72b, as it arises: an owner's flag lapses
//      (OWNED_TTL since its last `intro`) while the owner is still on the
//      owner list — the shadow keeps the difficulty: a flood of unstamped
//      junk is refused `pow_required` down to the last envelope, the mailbox
//      is held to INTRO_MAILBOX_BYTES and not the owned cap (three stamped
//      requests of 2 256 bytes fit in 8 000, a fourth is `queue_full`), an
//      honest stamped request gets in after the junk, push registration is
//      still refused, and the owner's next drain renews the shadow into a
//      flag — a renewal, not a new flag;
//   2. the shadow does not keep the mailbox owned: with the owner gone from
//      the owner list the mailbox is held to the first-contact caps like
//      any other — its bytes in the unowned total, UNOWNED_MAILBOX_BYTES
//      binding, refused `store_full` past it — while a stamp is still
//      asked; the owner's login claims it back and settles the total; and
//      the shadow's end, another OWNED_TTL on, leaves an ordinary mailbox
//      (an unstamped send taken and delivered without `pow`) with nothing
//      settled twice;
//   3. the review's probe 72a, the other way round: behind a front without
//      CLIENT_IP_HEADER new flags are not paced per address at all, so after
//      a restart strangers flagging fresh keys from the owner's address
//      leave the owner's first flag `intro_ok` and in force; with the header
//      set the pace is per client address — a stranger elsewhere spending
//      its minute does not touch the owner, and one sharing the owner's
//      address does, which SELF_HOSTING says;
//   4. a full store cannot be used to deny a flag: with N fresh keys flagged
//      for N ten times INTRO_CAP, an honest owner's first flag after a
//      restart is `intro_ok` and in force, the store holds INTRO_CAP entries
//      (in the Redis path once the sweep has walked it) and the rest are
//      counted `z_intro_evicted_total` — the shadow of a lapsed flag going
//      before any flag in force.

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
function mine({ rid, payload, day, min }) {
  const base = crypto.createHash('sha256').update(prefixFor(rid, payload, day));
  const nonce = crypto.randomBytes(16);
  for (let i = 0; ; i++) {
    nonce.writeUInt32BE(i >>> 0, 12);
    if (zeroBits(base.copy().update(nonce).digest()) >= min) return nonce.toString('base64url');
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
const stampFor = (rid, payload, bits = 16) => stamp((d) => mine({ rid, payload, day: d, min: bits }));

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
function get(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    http
      .get({ host: '127.0.0.1', port, path, headers }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      })
      .on('error', reject);
  });
}
function metric(body, name) {
  const m = body.match(new RegExp(`^${name} (\\d+)$`, 'm'));
  return m ? Number(m[1]) : null;
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
 * a test calls it, so what the sweep does is the test's doing. */
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
/** The difficulty the relay asks of a send to `rid`: flag or shadow. */
async function flagOf(h, rid) {
  if (h.kind === 'ram') return h.coord.introBits(rid);
  return Number(await h.raw.get(`intro:${rid}`)) || 0;
}
/** Whether `rid`'s mailbox has the owned caps. */
async function ownedFor(h, rid) {
  if (h.kind === 'ram') return h.coord._owns(rid);
  return (await h.raw.exists(`owned:${rid}`)) === 1;
}
/** Whether `rid`'s flag is in force, as opposed to lapsed into its shadow. */
async function inForce(h, rid) {
  if (h.kind === 'ram') return h.coord._flagged(rid);
  // The shadow is intro: outliving owned:, so in force is both there with the
  // flag's life still past the ownership's.
  return (await h.raw.exists(`owned:${rid}`)) === 1 && (await h.raw.pttl(`intro:${rid}`)) > CFG.ownedTtlMs;
}
/** How many entries, flags and shadows, the store holds. */
async function storeSize(h) {
  if (h.kind === 'ram') return h.coord.intro.size;
  let n = 0;
  let cursor = '0';
  do {
    const [next, keys] = await h.raw.scan(cursor, 'MATCH', 'intro:*', 'COUNT', '1000');
    cursor = next;
    n += keys.length;
  } while (cursor !== '0');
  return n;
}
/** OWNED_TTL passes since `rid`'s last `intro` — the flag lapses into its
 * shadow — while its owner is still on the owner list. In RAM the entry's
 * time is moved back and the sweep settles it; in the Redis path the flag's
 * life is cut to the shadow's half (what the clock would leave it) and the
 * owner's login, which this test makes, renews only `owned:`. */
async function lapse(h, owner) {
  if (h.kind === 'ram') {
    h.coord.intro.get(owner.rid).at -= CFG.ownedTtlMs + 1;
    h.coord.sweep();
    assert.ok(h.coord.intro.get(owner.rid).shadow, 'the sweep marked the shadow');
  } else {
    assert.strictEqual(await h.raw.pexpire(`intro:${owner.rid}`, CFG.ownedTtlMs), 1);
  }
  const c = new Client(h.port, owner);
  assert.strictEqual((await c.auth()).t, 'ready'); // the owner is seen, and sends no intro
  await leave(h, c);
}
/** The owner's login lapses too: it is gone from the owner list. In RAM the
 * owner is the only one who ever authenticated, so it heads the list and the
 * list's own trim lets it go; in the Redis path `owned:` expires. */
async function ownerForgotten(h, rid) {
  if (h.kind === 'ram') {
    assert.strictEqual(h.coord.owned.keys().next().value, rid, 'the owner heads the owner list');
    h.coord.owned.set(rid, 0);
    h.coord._trimOwned();
    assert.ok(!h.coord.owned.has(rid));
  } else {
    assert.strictEqual(await h.raw.del(`owned:${rid}`), 1);
  }
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
/** `n` strangers, fresh keys, each flagging its own mailbox at 16 bits from
 * a connection with `headers`, fifty at a time; their answers. */
async function strangersFlag(h, n, headers = {}) {
  const answers = [];
  for (let i = 0; i < n; i += 50) {
    const batch = await Promise.all(
      Array.from({ length: Math.min(50, n - i) }, async () => {
        const c = new Client(h.port, makeIdentity(), headers);
        assert.strictEqual((await c.auth()).t, 'ready');
        const r = await c.intro(16);
        c.close();
        return r.t === 'intro_ok' ? 'ok' : r.code;
      })
    );
    answers.push(...batch);
  }
  return answers;
}
/** What the relay counts as unowned bytes: RAM's total, or the Redis path's
 * live counter (reconciled by the sweep). */
async function unownedBytes(h) {
  if (h.kind === 'ram') return h.coord.unownedBytes;
  return Number(await h.raw.get('z:ub')) || 0;
}
const SEALED = (tag, n = 600) => 'zs1.' + sha256(tag).toString('base64url') + 'x'.repeat(n);
const fill = (c) => 'zs1.' + c.repeat(2000 - 4); // charged 2 256 bytes
const sent = (id) => ({ t: 'sent', id, queued: true });
const isPowRequired = (r, id, bits) => r.t === 'error' && r.code === 'pow_required' && r.id === id && r.bits === bits;

// ---- 1. the shadow holds the line (the review's probe 72b) ---------------------

async function shadowHoldsTheLine(h) {
  const owner = await flaggedOwner(h, 16);
  await lapse(h, owner);
  assert.ok(await ownedFor(h, owner.rid), 'the owner was seen lately: the mailbox is owned');
  assert.ok(!(await inForce(h, owner.rid)), 'and the flag has lapsed');
  assert.strictEqual(await flagOf(h, owner.rid), 16, 'but its shadow keeps the difficulty');
  // The flood: forty unstamped envelopes, each refused before it is stored.
  const s = await anonSender(h);
  for (let i = 0; i < 40; i++) {
    assert.ok(isPowRequired(await s.deliver(`junk-${i}`, owner.rid, SEALED(`junk-${i}`)), `junk-${i}`, 16), `junk ${i} refused`);
  }
  // The honest request gets in; the cap is INTRO_MAILBOX_BYTES (8 000 here),
  // not the owned 64 KiB: three stamped envelopes fit, a fourth does not.
  const P = ['a', 'b', 'c', 'd'].map(fill);
  const answers = [];
  for (let i = 0; i < 4; i++) answers.push(await s.deliver(`req-${i}`, owner.rid, P[i], stampFor(owner.rid, P[i])));
  assert.deepStrictEqual(answers.slice(0, 3), [sent('req-0'), sent('req-1'), sent('req-2')], 'honest stamped requests are taken after the junk');
  assert.deepStrictEqual(answers[3], { t: 'error', code: 'queue_full', id: 'req-3' }, 'and the mailbox is held to INTRO_MAILBOX_BYTES');
  // Never woken, shadow or flag.
  const oc = new Client(h.port, owner);
  assert.strictEqual((await oc.auth()).t, 'ready');
  assert.deepStrictEqual(await oc.ask({ t: 'push-register', token: 'OWNER_FCM', platform: 'android' }, ['push-ok', 'error']), { t: 'error', code: 'push_refused' });
  // The owner's drain renews the shadow into a flag.
  assert.deepStrictEqual(await oc.intro(16), { t: 'intro_ok' });
  assert.ok(await inForce(h, owner.rid), 'in force again');
  oc.close();
  s.close();
}

test('1 RAM: a lapsed flag leaves its shadow — unstamped junk refused, the intro cap kept, the honest request taken, the next drain renewing it', async (t) => {
  await shadowHoldsTheLine(await ram(t, { maxQueueBytesPerUser: 64 * 1024, introMailboxBytes: 8000 }));
});

test('1b Redis: a lapsed flag leaves its shadow — unstamped junk refused, the intro cap kept, the honest request taken, the next drain renewing it', { skip: SKIP_REDIS }, async (t) => {
  await shadowHoldsTheLine(await redis(t, { maxQueueBytesPerUser: 64 * 1024, introMailboxBytes: 8000 }));
});

// ---- 2. the shadow and the owner list ---------------------------------------------

async function shadowIsNotOwnership(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  // Flagged and on the owner list, then off it: the flag alone keeps the
  // owned caps, so what the mailbox holds is no part of the unowned total.
  const p0 = fill('a');
  assert.deepStrictEqual(await s.deliver('r0', owner.rid, p0, stampFor(owner.rid, p0)), sent('r0'));
  await ownerForgotten(h, owner.rid);
  assert.ok(await ownedFor(h, owner.rid) === (h.kind === 'ram'), 'in RAM the flag in force keeps the mailbox owned; in the Redis path the flag and the ownership are two keys and the lapse is one');
  if (h.kind === 'ram') assert.strictEqual(h.coord.unownedBytes, 0, 'nothing unowned while the flag is in force');
  // The flag lapses into its shadow: the mailbox is unowned, its bytes in the
  // unowned total, and a stamp is still asked.
  if (h.kind === 'ram') {
    h.coord.intro.get(owner.rid).at -= CFG.ownedTtlMs + 1;
    h.coord.sweep();
    assert.ok(h.coord.intro.get(owner.rid).shadow);
    assert.strictEqual(h.coord.unownedBytes, 2256, "the shadow's mailbox is in the unowned total");
  }
  assert.ok(!(await ownedFor(h, owner.rid)), 'a shadow is not ownership');
  assert.strictEqual(await flagOf(h, owner.rid), 16);
  assert.ok(isPowRequired(await s.deliver('u1', owner.rid, SEALED('u1')), 'u1', 16), 'a stamp is still asked');
  // The first-contact caps: UNOWNED_MAILBOX_BYTES is 4 000 here, so a second
  // stamped envelope of 2 256 is past it — refused as any unowned mailbox's
  // overflow is, `store_full`, with the stamp having been checked first.
  const p1 = fill('b');
  assert.deepStrictEqual(await s.deliver('r1', owner.rid, p1, stampFor(owner.rid, p1)), { t: 'error', code: 'store_full', id: 'r1' }, 'held to the unowned cap');
  assert.ok(isPowRequired(await s.deliver('u2', owner.rid, SEALED('u2')), 'u2', 16), 'and no stamp, no entry, cap or no cap');
  if (h.kind === 'redis') {
    await h.coord.sweep(); // the live counter is a sum the sweep recounts
    assert.strictEqual(await unownedBytes(h), 2256, "the shadow's mailbox is in the unowned total");
  }
  // The owner's login claims the mailbox: the total is settled.
  const oc = new Client(h.port, owner);
  assert.strictEqual((await oc.auth()).t, 'ready');
  await oc.next((f) => f.t === 'msg' && f.id === 'r0');
  assert.ok(await ownedFor(h, owner.rid));
  if (h.kind === 'redis') await h.coord.sweep();
  assert.strictEqual(await unownedBytes(h), 0, 'settled on the owner\'s login');
  assert.deepStrictEqual(await oc.intro(16), { t: 'intro_ok' }, 'and its drain renews the shadow');
  assert.ok(await inForce(h, owner.rid));
  await leave(h, oc);
  // The shadow's end: the owner forgotten again, then another OWNED_TTL on
  // the entry goes — an ordinary mailbox, nothing settled twice.
  await ownerForgotten(h, owner.rid);
  if (h.kind === 'ram') {
    assert.strictEqual(h.coord.unownedBytes, 0, 'the flag in force still owns it');
    h.coord.intro.get(owner.rid).at -= 2 * CFG.ownedTtlMs + 1;
    h.coord.sweep();
    assert.ok(!h.coord.intro.has(owner.rid), 'the entry is gone');
    assert.strictEqual(h.coord.unownedBytes, 2256, 'settled once, at the flag\'s end');
  } else {
    assert.strictEqual(await h.raw.del(`intro:${owner.rid}`), 1); // what its TTL does
  }
  assert.strictEqual(await flagOf(h, owner.rid), 0);
  assert.deepStrictEqual(await s.deliver('u3', owner.rid, SEALED('u3')), sent('u3'), 'an ordinary mailbox again');
  const back = new Client(h.port, owner);
  assert.strictEqual((await back.auth()).t, 'ready');
  const m = await back.next((f) => f.t === 'msg' && f.id === 'u3');
  assert.ok(!('pow' in m) && !('powDay' in m), 'delivered without pow');
  if (h.kind === 'ram') assert.strictEqual(h.coord.unownedBytes, 0, "settled by the owner's login, once");
  back.close();
  s.close();
}

test('2 RAM: a shadow is not ownership — the first-contact caps apply, the stamp is still asked, and the unowned total is settled once each way', async (t) => {
  await shadowIsNotOwnership(await ram(t, { unownedMailboxBytes: 4000 }));
});

test('2b Redis: a shadow is not ownership — the first-contact caps apply, the stamp is still asked, and the unowned total is settled once each way', { skip: SKIP_REDIS }, async (t) => {
  await shadowIsNotOwnership(await redis(t, { unownedMailboxBytes: 4000 }));
});

// ---- 3. new flags are paced per client address, or not at all (72a) ------------

async function notPacedWithoutTheHeader(h) {
  // Behind a front without CLIENT_IP_HEADER every client is one address: the
  // five strangers and the owner alike. INTRO_NEW_PER_IP_PER_MIN is 3, and
  // inert.
  assert.deepStrictEqual(await strangersFlag(h, 5), ['ok', 'ok', 'ok', 'ok', 'ok'], 'strangers are not paced per address');
  const owner = makeIdentity();
  const c = new Client(h.port, owner);
  assert.strictEqual((await c.auth()).t, 'ready');
  assert.deepStrictEqual(await c.intro(20), { t: 'intro_ok' }, "the owner's first flag after a restart is taken");
  assert.ok(await inForce(h, owner.rid));
  const s = await anonSender(h);
  assert.ok(isPowRequired(await s.deliver('j1', owner.rid, SEALED('j1')), 'j1', 20), 'and in force');
  s.close();
  c.close();
}
test('3 RAM: without CLIENT_IP_HEADER new flags are not paced per address, so strangers cannot deny an owner its first flag', async (t) => {
  await notPacedWithoutTheHeader(await ram(t, { introNewPerIpPerMin: 3 }));
});

test('3b Redis: without CLIENT_IP_HEADER new flags are not paced per address, so strangers cannot deny an owner its first flag', { skip: SKIP_REDIS }, async (t) => {
  await notPacedWithoutTheHeader(await redis(t, { introNewPerIpPerMin: 3 }));
});

test('3c RAM: with CLIENT_IP_HEADER the pace is per client address — a stranger elsewhere does not touch the owner, one sharing the address does', async (t) => {
  const h = await ram(t, { introNewPerIpPerMin: 3, clientIpHeader: 'x-test-ip' });
  const at = (ip) => ({ 'x-test-ip': ip });
  assert.deepStrictEqual((await strangersFlag(h, 5, at('10.0.0.9'))).sort(), ['ok', 'ok', 'ok', 'rate_limited', 'rate_limited'], 'an address gets its minute of new flags');
  const owner = new Client(h.port, makeIdentity(), at('10.0.0.1'));
  assert.strictEqual((await owner.auth()).t, 'ready');
  assert.deepStrictEqual(await owner.intro(20), { t: 'intro_ok' }, 'another address is untouched');
  assert.deepStrictEqual(await owner.intro(20), { t: 'intro_ok' }, 'and renews freely');
  // The residual SELF_HOSTING names: an owner behind the same client address
  // as a stranger who spent its minute waits for the next one.
  const neighbour = new Client(h.port, makeIdentity(), at('10.0.0.9'));
  assert.strictEqual((await neighbour.auth()).t, 'ready');
  assert.deepStrictEqual(await neighbour.intro(20), { t: 'error', code: 'rate_limited' }, "a NEW flag from the stranger's address this minute is paced");
  owner.close();
  neighbour.close();
});

// ---- 4. a full store forgets the least recently renewed, never refuses ------------

async function fullStoreCannotDeny(h) {
  const bearer = { authorization: 'Bearer m' };
  const scrape = async () => (await get(h.port, '/metrics', bearer)).body;
  const evictedBefore = metric(await scrape(), 'z_intro_evicted_total');
  // An old owner whose flag has lapsed into its shadow: the first to go.
  const old = await flaggedOwner(h, 16);
  await lapse(h, old);
  // The flood: ten times INTRO_CAP (20 here) fresh keys, every one flagged.
  const n = 10 * CFG.introCap;
  const answers = await strangersFlag(h, n);
  assert.strictEqual(answers.filter((a) => a === 'ok').length, n, 'no flag is refused for the store being full');
  if (h.kind === 'redis') await h.coord.sweep(); // which does the forgetting here
  assert.strictEqual(await storeSize(h), CFG.introCap, 'the store holds INTRO_CAP entries');
  assert.strictEqual(await flagOf(h, old.rid), 0, 'the shadow went first');
  assert.strictEqual(metric(await scrape(), 'z_intro_evicted_total') - evictedBefore, n + 1 - CFG.introCap, 'the rest counted as forgotten');
  // An honest owner's first flag after a restart, the store full of the
  // flood: taken, in force, the store no larger.
  const owner = makeIdentity();
  const c = new Client(h.port, owner);
  assert.strictEqual((await c.auth()).t, 'ready');
  assert.deepStrictEqual(await c.intro(20), { t: 'intro_ok' }, 'the honest flag is never refused');
  assert.ok(await inForce(h, owner.rid));
  const s = await anonSender(h);
  assert.ok(isPowRequired(await s.deliver('j1', owner.rid, SEALED('j1')), 'j1', 20), 'and in force');
  if (h.kind === 'redis') await h.coord.sweep();
  assert.strictEqual(await storeSize(h), CFG.introCap);
  assert.ok(await inForce(h, owner.rid), 'the newest entry is the last to go');
  s.close();
  c.close();
}

test('4 RAM: a store at INTRO_CAP takes a new flag and forgets the least recently renewed — ten times the cap in fresh keys cannot deny an owner', async (t) => {
  await fullStoreCannotDeny(await ram(t, { introCap: 20, metricsToken: 'm' }));
});

test('4b Redis: a store at INTRO_CAP takes a new flag and the sweep forgets the least recently renewed — ten times the cap in fresh keys cannot deny an owner', { skip: SKIP_REDIS }, async (t) => {
  await fullStoreCannotDeny(await redis(t, { introCap: 20, metricsToken: 'm' }));
});
