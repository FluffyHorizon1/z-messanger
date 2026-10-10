'use strict';

// Phase 37 — introduction mailboxes at the relay (PROTOCOL §21.6).
//
// A handle resolves to an introduction mailbox: a routing id that anybody who
// resolves the handle can address. Its owner flags it with `intro`; from then
// on a send to it needs a proof of work at the owner's difficulty, it is never
// woken by push, and it is held to INTRO_MAILBOX_BYTES on top of the owned
// caps. Everything runs through the real relay, in RAM and in the real Redis
// path, where the decisions live in the push Lua and in store keys (skipped,
// as the HA tests are, when redis-server or ioredis is missing). The stamps
// are computed here from the specification, not with the relay's own helper.
//
// Criteria, each asserted below (N in RAM, Nb in the Redis path):
//   1. only the owner can flag: `intro` on a connection that never
//      authenticated, or that authenticated with v1, is refused `not_authed`;
//      on a v2 connection it flags that connection's own routing id and
//      nobody else's, whatever else the frame names;
//   2. the difficulty must be an integer from 16 to 28 (`bad_intro`, nothing
//      flagged); `intro` is idempotent, and the newest difficulty wins;
//   3. a mailbox nobody flagged needs no stamp — today's behaviour unchanged:
//      the same frames, a `pow` member that is malformed or worth fewer
//      than 16 bits ignored (one worth 16 travels with its envelope:
//      intro_flag_hardening.test.js), the creation gate charged once for a
//      first contact as before, push registered and woken;
//   4. a send to a flagged mailbox with no stamp, or a malformed one (a valid
//      stamp written non-canonically included), is refused `pow_required`
//      with the envelope id, the difficulty and the relay's day, before
//      anything is stored and without the creation gate being consulted;
//   5. so is a well-formed stamp made for another recipient, another
//      envelope, two days back, tomorrow, or with fewer bits than asked;
//   6. a stamp that meets the difficulty — today's or yesterday's — is
//      delivered from a connection that never authenticated, with no sender,
//      and counted; the stamp is kept with the envelope and handed to the
//      owner as `pow`, with `powDay` the day it was good under;
//   7. Redis: the flag survives a relay restart — a store key with the
//      ownership TTL — and once an instance has queued for the mailbox, the
//      push script itself refuses a stamp-less send without writing anything;
//   8. push: a flagged identity's `push-register` is refused, a token it held
//      is deleted when it flags, and a send to it never wakes it;
//   9. a flagged mailbox is capped at INTRO_MAILBOX_BYTES below the owned cap
//      an unflagged one has (`queue_full`), and a receipt the relay queues
//      for its owner is asked for no stamp;
//  10. RAM: flags are a store of their own — OWNED_CAP forgetting the least
//      recently authenticated owner leaves its flag, and the mailbox keeps
//      the owned caps; INTRO_CAP refuses a new flag and forgets none — and
//      lapse OWNED_TTL after the owner's last `intro`, though the owner has
//      logged in since;
//  11. nothing new is logged: flagging, refusing and accepting stamped sends
//      and refusing push write no log line;
//  12. /metrics carries z_intro_pow_refused_total, z_intro_accepted_total,
//      z_intro_duplicate_total and the z_intro_mailboxes gauge;
//  13. (amendment 1) an envelope byte-identical to one a flagged mailbox holds
//      is answered `sent` and stored once — a retry under the same id or a
//      replay under a new one, stamp and all — neither stored, delivered nor
//      woken for again, and not refused at the mailbox's cap; once the held
//      one is acknowledged or expires, the same payload is new again; a
//      mailbox nobody flagged keeps both copies, as before;
//  14. (amendment 1) a flagged mailbox refuses an envelope over 64 KiB as
//      the relay charges it — 65 536 accepted, 65 537 not, nor a shorter one
//      the store would hold escaped past it — `too_large`, before the stamp
//      is looked at and before anything is stored or the gate consulted (in
//      the Redis path both before a first contact and in the script); an
//      unflagged mailbox still takes it;
//  15. (amendment 1) `pow_required` names the relay's current day, and a
//      client whose clock is a day ahead re-makes its stamp once for that day
//      and is accepted.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const { createServer, CFG, MemoryCoordinator, RedisCoordinator, routingIdFromPub } = require('../server.js');

const V1 = Buffer.from('z-relay-auth-v1:', 'utf8');
const V2 = Buffer.from('z-relay-auth-v2:', 'utf8');
const authorityOf = (port) => `127.0.0.1:${port}`;

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

// ---- the stamp, from the specification -------------------------------------
//
// pow = b64url(nonce), nonce 16 bytes, such that
//   SHA-256("z-intro-pow-v1:" ‖ ridBytes(32) ‖ u32be(day) ‖ SHA-256(payload) ‖ nonce)
// has at least N leading zero bits; day = UTC days since the epoch.

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
function prefixFor(rid, payload, day) {
  return Buffer.concat([POW_CONTEXT, Buffer.from(rid, 'base64url'), u32be(day), sha256(Buffer.from(payload, 'utf8'))]);
}
/** The leading zero bits a nonce earns for (rid, payload, day). */
function bitsOf(rid, payload, day, nonce) {
  return zeroBits(sha256(Buffer.concat([prefixFor(rid, payload, day), nonce])));
}
/**
 * Mines a nonce whose hash for (rid, payload, day) has at least `min` and
 * fewer than `max` leading zero bits, and that earns fewer than `a.bits` for
 * every target in `avoid` — so a stamp meant to fail for the real recipient
 * cannot pass for it by the 2^-N chance a random hash has, and the test is
 * deterministic.
 */
function mine({ rid, payload, day, min, max = Infinity, avoid = [] }) {
  const base = crypto.createHash('sha256').update(prefixFor(rid, payload, day));
  const nonce = crypto.randomBytes(16);
  for (let i = 0; ; i++) {
    nonce.writeUInt32BE(i >>> 0, 12);
    const bits = zeroBits(base.copy().update(nonce).digest());
    if (bits >= min && bits < max && avoid.every((a) => bitsOf(a.rid, a.payload, a.day, nonce) < a.bits)) {
      return nonce.toString('base64url');
    }
  }
}
/**
 * A stamp made against the day it was made on, re-made if UTC midnight passed
 * while it was mined, so the relay's clock (read a moment later) agrees with
 * the one the stamp was made for.
 */
function stamp(make) {
  for (;;) {
    const d = today();
    const s = make(d);
    if (today() === d) return s;
  }
}
/** Neither of the days the relay accepts: what a stamp for the real target must fail. */
const notFor = (rid, payload, bits, d) => [
  { rid, payload, day: d, bits },
  { rid, payload, day: d - 1, bits },
];

// ---- harness ---------------------------------------------------------------

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
  constructor(port, identity) {
    this.port = port;
    this.identity = identity;
    this.frames = [];
    this.waiters = [];
    this.closed = null;
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('error', () => {});
    this.ws.on('close', (code) => (this.closed = code == null ? 1006 : code));
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
  async seenChallenge() {
    return this.next((f) => f.t === 'challenge');
  }
  /** The bound (v2) authentication every current client makes. */
  async auth() {
    const ch = await this.seenChallenge();
    const msg = Buffer.concat([V2, Buffer.from(authorityOf(this.port), 'utf8'), Buffer.from(ch.nonce, 'base64')]);
    const sig = crypto.sign(null, msg, this.identity.privateKey);
    this.send({ t: 'auth', v: 2, pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    return this.next((f) => f.t === 'ready' || f.t === 'error');
  }
  /** The unbound v1 form, which a relay may still accept from old clients. */
  async authV1() {
    const ch = await this.seenChallenge();
    const sig = crypto.sign(null, Buffer.concat([V1, Buffer.from(ch.nonce, 'base64')]), this.identity.privateKey);
    this.send({ t: 'auth', pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    return this.next((f) => f.t === 'ready' || f.t === 'error');
  }
  /** Sends a frame and waits for the one answer it gets (intro, push-register). */
  ask(frame, answers) {
    this.send(frame);
    return this.next((f) => answers.includes(f.t));
  }
  intro(pow, extra = {}) {
    return this.ask({ t: 'intro', pow, ...extra }, ['intro_ok', 'error']);
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

/** Sets CFG for one test and restores it afterwards. */
function withCfg(t, cfg) {
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

/** A relay in RAM. `pushSender` records wakes where a test needs it. */
async function ram(t, cfg = {}, pushSender = null) {
  const restore = withCfg(t, cfg);
  const srv = createServer({ pushSender });
  const port = await listen(srv);
  t.after(() => {
    shut(srv);
    restore();
  });
  return { kind: 'ram', srv, coord: srv.coordinator, port };
}

/** A relay in the Redis path, on a redis-server of its own. The sweep is
 * moved out of the way so a store snapshot sees only what the test did. */
async function redis(t, cfg = {}, pushSender = null) {
  const { redisPort, raw, stop } = await startRedis();
  const restore = withCfg(t, { sweepIntervalMs: 3600000, ...cfg });
  const coord = new RedisCoordinator(`redis://127.0.0.1:${redisPort}`, 'instA');
  const srv = createServer({ coordinator: coord, pushSender });
  const port = await listen(srv);
  t.after(async () => {
    shut(srv);
    await coord.close();
    await stop();
    restore();
  });
  return { kind: 'redis', srv, coord, port, raw, redisPort };
}

/**
 * Whether the relay has let go of `rid`'s socket: in the Redis path that
 * includes the presence record, which is deleted a moment after the socket —
 * a receipt or a wake decided before then would see the recipient online.
 */
async function gone(h, rid) {
  if (h.kind === 'ram') return !h.coord.online.has(rid);
  return !h.coord.local.has(rid) && (await h.raw.exists(`presence:${rid}`)) === 0;
}
function leave(h, client) {
  client.close();
  return waitUntil(() => gone(h, client.identity.rid), { what: `${client.identity.rid.slice(0, 8)}… gone from the relay` });
}

/** Whether `rid` is flagged, read where the coordinator keeps it. */
async function flagOf(h, rid) {
  if (h.kind === 'ram') return h.coord.introBits(rid);
  return Number(await h.raw.get(`intro:${rid}`)) || 0;
}
async function flaggedRids(h) {
  if (h.kind === 'ram') return [...h.coord.intro.keys()].sort();
  return (await h.raw.keys('intro:*')).map((k) => k.slice('intro:'.length)).sort();
}

/**
 * Everything a send could have changed: in RAM the store's byte and envelope
 * totals, the unowned total, which mailboxes exist, who is owned and seen, and
 * the per-address budgets; in Redis every key and its value (TTLs aside).
 */
async function snapshot(h) {
  const seen = h.coord.seen.size;
  if (h.kind === 'ram') {
    const c = h.coord;
    return JSON.stringify({
      bytes: c.storeBytes(),
      count: c.count,
      unowned: c.unownedBytes,
      queues: [...c.queues.keys()].sort(),
      owned: [...c.owned.keys()].sort(),
      ips: [...c.unownedIp.ips.keys()].sort(),
      seen,
    });
  }
  const out = [];
  for (const k of (await h.raw.keys('*')).sort()) {
    const type = await h.raw.type(k);
    let v = type;
    if (type === 'string') v = await h.raw.get(k);
    else if (type === 'list') v = await h.raw.lrange(k, 0, -1);
    else if (type === 'hash') v = await h.raw.hgetall(k);
    out.push([k, v]);
  }
  return JSON.stringify({ store: out, seen, ips: [...h.coord.unownedIp.ips.keys()].sort() });
}

/** Counts every consultation of the mailbox-creation gate: the instance's own
 * bucket and, in the Redis path, the store's shared window. */
function spyGate(coord) {
  const calls = { take: 0, shared: 0 };
  const take = coord.newMailbox.take.bind(coord.newMailbox);
  coord.newMailbox.take = () => {
    calls.take += 1;
    return take();
  };
  if (typeof coord._takeShared === 'function') {
    const shared = coord._takeShared.bind(coord);
    coord._takeShared = (rid) => {
      calls.shared += 1;
      return shared(rid);
    };
  }
  return calls;
}

/** An owner that authenticates with v2, flags its mailbox, and leaves. */
async function flaggedOwner(h, bits) {
  const owner = makeIdentity();
  const c = new Client(h.port, owner);
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

const SEALED = (tag, n = 600) => 'zs1.' + crypto.createHash('sha256').update(tag).digest('base64url') + 'x'.repeat(n);
/**
 * Asserts `r` is the refusal of envelope `id` for want of `bits` of work,
 * naming the relay's day (amendment 1): today's by this clock, or yesterday's
 * if UTC midnight passed between the relay's reading and this one.
 */
function assertPowRequired(r, id, bits, msg) {
  const { day, ...rest } = r;
  assert.deepStrictEqual(rest, { t: 'error', code: 'pow_required', id, bits }, msg);
  const d = today();
  assert.ok(day === d || day === d - 1, `${msg || id}: the refusal names the relay's day (${day}; here ${d})`);
}
const sent = (id) => ({ t: 'sent', id, queued: true });

// ---- 1. only the owner can flag ---------------------------------------------

async function onlyTheOwnerFlags(h) {
  // A connection that never authenticated.
  const anon = await anonSender(h);
  assert.deepStrictEqual(await anon.intro(16), { t: 'error', code: 'not_authed' }, 'no authentication: refused');
  // One that authenticated with the unbound v1 form, which another relay can
  // have drawn out of the device (§12.1).
  const alice = makeIdentity();
  const aliceC = new Client(h.port, alice);
  assert.strictEqual((await aliceC.authV1()).t, 'ready', 'v1 is still accepted for receiving');
  assert.deepStrictEqual(await aliceC.intro(16), { t: 'error', code: 'not_authed' }, 'v1: refused');
  assert.strictEqual(await flagOf(h, alice.rid), 0, 'and nothing was flagged');
  // A v2 connection flags its own routing id — and only that, whatever other
  // routing id the frame carries.
  const bob = makeIdentity();
  const bobC = new Client(h.port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  const owner = makeIdentity();
  const ownerC = new Client(h.port, owner);
  assert.strictEqual((await ownerC.auth()).t, 'ready');
  assert.deepStrictEqual(await ownerC.intro(16, { to: bob.rid, rid: bob.rid, id: bob.rid }), { t: 'intro_ok' });
  assert.deepStrictEqual(await flaggedRids(h), [owner.rid], "the owner's routing id, and nobody else's, is flagged");
  // Seen from a sender: the owner's mailbox now wants a stamp; Bob's and
  // Alice's do not.
  const s = await anonSender(h);
  assertPowRequired(await s.deliver('o1', owner.rid, SEALED('o1')), 'o1', 16);
  assert.deepStrictEqual(await s.deliver('b1', bob.rid, SEALED('b1')), sent('b1'));
  assert.deepStrictEqual(await s.deliver('a1', alice.rid, SEALED('a1')), sent('a1'));
  for (const c of [anon, aliceC, bobC, ownerC, s]) c.close();
}

test('1 RAM: only the owner can flag, on a v2 connection, and only its own routing id', async (t) => {
  await onlyTheOwnerFlags(await ram(t));
});

test('1b Redis: only the owner can flag, on a v2 connection, and only its own routing id', { skip: SKIP_REDIS }, async (t) => {
  await onlyTheOwnerFlags(await redis(t));
});

// ---- 2. the difficulty's range; idempotence ---------------------------------

async function difficultyInRange(h) {
  const owner = makeIdentity();
  const c = new Client(h.port, owner);
  assert.strictEqual((await c.auth()).t, 'ready');
  for (const bad of [15, 29, 0, -16, 16.5, '20', null, true, [20], { n: 20 }, 1e3]) {
    assert.deepStrictEqual(await c.intro(bad), { t: 'error', code: 'bad_intro' }, `pow ${JSON.stringify(bad)} refused`);
  }
  assert.deepStrictEqual(await c.ask({ t: 'intro' }, ['intro_ok', 'error']), { t: 'error', code: 'bad_intro' }, 'no pow: refused');
  assert.deepStrictEqual(await flaggedRids(h), [], 'nothing was flagged by any of them');
  // The edges are in range.
  assert.deepStrictEqual(await c.intro(16), { t: 'intro_ok' });
  assert.strictEqual(await flagOf(h, owner.rid), 16);
  // The same frame again changes nothing and is answered the same.
  assert.deepStrictEqual(await c.intro(16), { t: 'intro_ok' });
  assert.strictEqual(await flagOf(h, owner.rid), 16, 'idempotent');
  assert.deepStrictEqual(await flaggedRids(h), [owner.rid], 'one flag, not two');
  // A new difficulty replaces the old.
  assert.deepStrictEqual(await c.intro(28), { t: 'intro_ok' });
  assert.strictEqual(await flagOf(h, owner.rid), 28, 'the newest difficulty wins');
  const s = await anonSender(h);
  assertPowRequired(await s.deliver('x', owner.rid, SEALED('x')), 'x', 28, 'and is the one a sender is told');
  c.close();
  s.close();
}

test('2 RAM: the difficulty must be an integer from 16 to 28; intro is idempotent, the newest wins', async (t) => {
  await difficultyInRange(await ram(t));
});

test('2b Redis: the difficulty must be an integer from 16 to 28; intro is idempotent, the newest wins', { skip: SKIP_REDIS }, async (t) => {
  await difficultyInRange(await redis(t));
});

// ---- 3. an unflagged mailbox: today's behaviour ------------------------------

async function unflaggedUnchanged(h, wakes) {
  // Bob has used this relay (owned), registers push, and goes offline.
  const bob = makeIdentity();
  const bobC = new Client(h.port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  assert.deepStrictEqual(await bobC.ask({ t: 'push-register', token: 'BOB_FCM', platform: 'android' }, ['push-ok', 'error']), { t: 'push-ok' });
  await leave(h, bobC);
  const gate = spyGate(h.coord);
  const s = await anonSender(h);
  const payloads = { n1: SEALED('n1'), n2: SEALED('n2'), n3: SEALED('n3') };
  // No stamp; a malformed one; a well-formed one worth fewer than 16 bits on
  // either day the relay takes: all the same to a mailbox nobody flagged.
  assert.deepStrictEqual(await s.deliver('n1', bob.rid, payloads.n1), sent('n1'));
  assert.deepStrictEqual(await s.deliver('n2', bob.rid, payloads.n2, 'not a stamp'), sent('n2'));
  const short = stamp((d) => mine({ rid: bob.rid, payload: payloads.n3, day: d, min: 0, max: 16, avoid: [{ rid: bob.rid, payload: payloads.n3, day: d - 1, bits: 16 }] }));
  assert.deepStrictEqual(await s.deliver('n3', bob.rid, payloads.n3, short), sent('n3'));
  assert.strictEqual(gate.take + gate.shared, 1, 'the first contact consulted the creation gate once, as before; the rest not at all');
  // Offline, so each one woke him, as push always has.
  await waitUntil(() => wakes.length === 3, { what: 'three wakes for three envelopes to an offline recipient' });
  assert.deepStrictEqual(wakes, ['BOB_FCM', 'BOB_FCM', 'BOB_FCM']);
  // And he receives exactly what he always did: no member added.
  const back = new Client(h.port, bob);
  assert.strictEqual((await back.auth()).t, 'ready');
  for (const id of ['n1', 'n2', 'n3']) {
    const m = await back.next((f) => f.t === 'msg' && f.id === id);
    assert.deepStrictEqual(Object.keys(m).sort(), ['id', 'payload', 't', 'ts'], `msg ${id} is the frame it always was`);
    assert.strictEqual(m.payload, payloads[id]);
  }
  back.close();
  s.close();
}

function wakeRecorder() {
  const wakes = [];
  return { wakes, sender: { sendWake: async (tok) => (wakes.push(tok), { ok: true, status: 200 }) } };
}

test('3 RAM: a mailbox nobody flagged needs no stamp — today\'s behaviour unchanged', async (t) => {
  const { wakes, sender } = wakeRecorder();
  await unflaggedUnchanged(await ram(t, {}, sender), wakes);
});

test('3b Redis: a mailbox nobody flagged needs no stamp — today\'s behaviour unchanged', { skip: SKIP_REDIS }, async (t) => {
  const { wakes, sender } = wakeRecorder();
  await unflaggedUnchanged(await redis(t, {}, sender), wakes);
});

// ---- 4. missing and malformed stamps ----------------------------------------

async function malformedRefused(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  const payload = SEALED('m');
  // A stamp that WOULD pass, to be spoilt in ways that keep its decoded bytes.
  const good = stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 }));
  const goodBytes = Buffer.from(good, 'base64url');
  // 16 bytes are 128 bits: the last of 22 characters carries 2 of them, and
  // its 4 low bits must be zero. Set one and the bytes decode the same.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const last = alphabet.indexOf(good[21]);
  const nonCanonical = good.slice(0, 21) + alphabet[last | 1];
  assert.notStrictEqual(nonCanonical, good);
  assert.deepStrictEqual(Buffer.from(nonCanonical, 'base64url'), goodBytes, 'the same 16 bytes, written another way');
  const cases = {
    missing: undefined,
    null: null,
    number: 1234567,
    object: { nonce: good },
    empty: '',
    short: good.slice(0, 21),
    long: good + 'A',
    padded: good + '==',
    standardAlphabet: good.slice(0, 20) + '+/', // base64's two characters, not base64url's
    notBase64: '!'.repeat(22),
    nonCanonical,
  };
  const before = await snapshot(h);
  const gate = spyGate(h.coord);
  const refusedBefore = metric((await get(h.port, '/metrics', { authorization: 'Bearer i' })).body, 'z_intro_pow_refused_total');
  let n = 0;
  for (const [name, pow] of Object.entries(cases)) {
    const id = `bad-${name}`;
    assertPowRequired(await s.deliver(id, owner.rid, payload, pow), id, 16, `${name}: refused`);
    n += 1;
  }
  assert.strictEqual(await snapshot(h), before, 'nothing was stored, owned, seen or charged by any of them');
  assert.deepStrictEqual(gate, { take: 0, shared: 0 }, 'the creation gate was never consulted');
  const refusedAfter = metric((await get(h.port, '/metrics', { authorization: 'Bearer i' })).body, 'z_intro_pow_refused_total');
  assert.strictEqual(refusedAfter - refusedBefore, n, 'each one counted');
  // The unspoilt stamp goes through, so it was the spoiling that was refused.
  assert.deepStrictEqual(await s.deliver('good', owner.rid, payload, good), sent('good'));
  s.close();
}

test('4 RAM: no stamp, or a malformed one, is refused before anything is stored or charged', async (t) => {
  const h = await ram(t, { metricsToken: 'i' });
  await malformedRefused(h);
});

test('4b Redis: no stamp, or a malformed one, is refused before anything is stored or charged', { skip: SKIP_REDIS }, async (t) => {
  // The shared creation window on, so the gate a refusal must not reach is a
  // write to the store.
  const h = await redis(t, { metricsToken: 'i', newMailboxShared: true });
  await malformedRefused(h);
});

// ---- 5. stamps that do not meet the target -----------------------------------

async function wrongStampsRefused(h) {
  const owner = await flaggedOwner(h, 16);
  const hard = await flaggedOwner(h, 18);
  const s = await anonSender(h);
  const payload = SEALED('w');
  const other = makeIdentity().rid;
  const cases = {
    'another recipient': stamp((d) => mine({ rid: other, payload, day: d, min: 16, avoid: notFor(owner.rid, payload, 16, d) })),
    'another envelope': stamp((d) => mine({ rid: owner.rid, payload: SEALED('other'), day: d, min: 16, avoid: notFor(owner.rid, payload, 16, d) })),
    'two days back': stamp((d) => mine({ rid: owner.rid, payload, day: d - 2, min: 16, avoid: notFor(owner.rid, payload, 16, d) })),
    tomorrow: stamp((d) => mine({ rid: owner.rid, payload, day: d + 1, min: 16, avoid: notFor(owner.rid, payload, 16, d) })),
  };
  // Too easy: 16 or 17 bits today (and fewer than 18 yesterday) against 18.
  const tooEasy = stamp((d) => mine({ rid: hard.rid, payload, day: d, min: 16, max: 18, avoid: [{ rid: hard.rid, payload, day: d - 1, bits: 18 }] }));
  const before = await snapshot(h);
  const gate = spyGate(h.coord);
  for (const [name, pow] of Object.entries(cases)) {
    const id = `w-${name.replace(/ /g, '-')}`;
    assertPowRequired(await s.deliver(id, owner.rid, payload, pow), id, 16, `${name}: refused`);
  }
  assertPowRequired(await s.deliver('w-easy', hard.rid, payload, tooEasy), 'w-easy', 18, 'too easy: refused, naming the 18 bits asked');
  assert.strictEqual(await snapshot(h), before, 'nothing was stored, owned, seen or charged by any of them');
  assert.deepStrictEqual(gate, { take: 0, shared: 0 }, 'the creation gate was never consulted');
  s.close();
}

test('5 RAM: a stamp for another recipient, envelope or day, or too easy, is refused the same way', async (t) => {
  await wrongStampsRefused(await ram(t));
});

test('5b Redis: a stamp for another recipient, envelope or day, or too easy, is refused the same way', { skip: SKIP_REDIS }, async (t) => {
  await wrongStampsRefused(await redis(t, { newMailboxShared: true }));
});

// ---- 6. a good stamp ----------------------------------------------------------

/** The entries the store holds for `rid`, as stored (in the Redis path, the
 * `h:` fields beside them are the index of held payloads, not entries). */
async function storedEntries(h, rid) {
  if (h.kind === 'ram') {
    const q = h.coord.queues.get(rid);
    return q ? q.entries.map((e) => ({ ...e })) : [];
  }
  const all = await h.raw.hgetall(`qe:${rid}`);
  return Object.entries(all)
    .filter(([k]) => !k.startsWith('h:'))
    .map(([, v]) => JSON.parse(v));
}

async function goodStampDelivered(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h); // never authenticates: no sender at all
  const p1 = SEALED('today');
  const p2 = SEALED('yesterday');
  // Each good for its own day only, so the day the relay takes it under is known.
  let day1;
  let day2;
  const todays = stamp((d) => ((day1 = d), mine({ rid: owner.rid, payload: p1, day: d, min: 16, avoid: [{ rid: owner.rid, payload: p1, day: d - 1, bits: 16 }] })));
  const yesterdays = stamp((d) => ((day2 = d - 1), mine({ rid: owner.rid, payload: p2, day: d - 1, min: 16, avoid: [{ rid: owner.rid, payload: p2, day: d, bits: 16 }] })));
  assert.deepStrictEqual(await s.deliver('g1', owner.rid, p1, todays), sent('g1'), "today's stamp: accepted, with the ordinary answer");
  assert.deepStrictEqual(await s.deliver('g2', owner.rid, p2, yesterdays), sent('g2'), "yesterday's stamp: accepted");
  // Stored with no sender; the stamp is kept with the envelope for its owner
  // (an independent review of handles, 2026-10-09), with the day it was
  // good under.
  const held = await storedEntries(h, owner.rid);
  assert.strictEqual(held.length, 2);
  for (const e of held) assert.strictEqual(e.from, null, 'no sender stored');
  assert.deepStrictEqual(
    held.map((e) => [e.id, e.pow, e.powDay]).sort(),
    [
      ['g1', todays, day1],
      ['g2', yesterdays, day2],
    ],
    'each with its stamp and that day'
  );
  // The owner drains its introduction mailbox like any other, and is handed
  // each stamp with its day, enough to check the work itself.
  const ownerC = new Client(h.port, owner);
  assert.strictEqual((await ownerC.auth()).t, 'ready');
  for (const [id, p, pow, day] of [
    ['g1', p1, todays, day1],
    ['g2', p2, yesterdays, day2],
  ]) {
    const m = await ownerC.next((f) => f.t === 'msg' && f.id === id);
    assert.deepStrictEqual(Object.keys(m).sort(), ['id', 'payload', 'pow', 'powDay', 't', 'ts'], 'delivered with no sender, and with the stamp');
    assert.strictEqual(m.payload, p);
    assert.strictEqual(m.pow, pow);
    assert.strictEqual(m.powDay, day);
    assert.ok(bitsOf(owner.rid, m.payload, m.powDay, Buffer.from(m.pow, 'base64url')) >= 16, `${id}: the stamp checks out against powDay`);
    ownerC.send({ t: 'recv', id });
  }
  await waitUntil(async () => (await storedEntries(h, owner.rid)).length === 0, { what: 'the owner acknowledged both' });
  ownerC.close();
  s.close();
}

test('6 RAM: a stamp that meets the difficulty, today\'s or yesterday\'s, is delivered with no sender, and with the stamp and its day', async (t) => {
  await goodStampDelivered(await ram(t));
});

test('6b Redis: a stamp that meets the difficulty, today\'s or yesterday\'s, is delivered with no sender, and with the stamp and its day', { skip: SKIP_REDIS }, async (t) => {
  await goodStampDelivered(await redis(t));
});

// ---- 7. Redis: the flag survives a restart; the script's own check ------------

test('7 Redis: the flag survives a relay restart, and the push script refuses a stamp-less send itself', { skip: SKIP_REDIS }, async (t) => {
  const { redisPort, raw, stop } = await startRedis();
  const restore = withCfg(t, { sweepIntervalMs: 3600000 });
  const url = `redis://127.0.0.1:${redisPort}`;
  const started = [];
  t.after(async () => {
    for (const { srv, coord } of started) {
      shut(srv);
      await coord.close();
    }
    await stop();
    restore();
  });
  const instance = async (id) => {
    const coord = new RedisCoordinator(url, id);
    const srv = createServer({ coordinator: coord, pushSender: null });
    const port = await listen(srv);
    started.push({ srv, coord });
    return { kind: 'redis', srv, coord, port, raw };
  };

  const a = await instance('instA');
  const owner = await flaggedOwner(a, 16);
  // A store key with the ownership TTL, written beside the ownership itself.
  const pttl = await raw.pttl(`intro:${owner.rid}`);
  assert.ok(pttl > CFG.ownedTtlMs - 60000 && pttl <= CFG.ownedTtlMs, `intro: carries OWNED_TTL (${pttl} ms)`);
  assert.strictEqual(await raw.get(`intro:${owner.rid}`), '16', 'a routing id and a number');
  const expiresAt = (k) => raw.call('PEXPIRETIME', k).then(Number);
  assert.ok((await expiresAt(`owned:${owner.rid}`)) >= (await expiresAt(`intro:${owner.rid}`)), 'the flag never outlives its ownership');
  // Instance A goes away entirely; B starts against the same store.
  shut(a.srv);
  await a.coord.close();
  started.splice(0, 1);
  const b = await instance('instB');
  const s = await anonSender(b);
  const payload = SEALED('after-restart');
  assertPowRequired(await s.deliver('r1', owner.rid, payload), 'r1', 16, 'the new instance knows the flag');
  const good = stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 }));
  assert.deepStrictEqual(await s.deliver('r2', owner.rid, payload, good), sent('r2'));
  // B has now queued for this mailbox, so a send to it skips the question it
  // asks before a first contact: the push script must refuse on its own,
  // atomically with the write it does not make.
  assert.ok(b.coord.seen.has(owner.rid), 'the instance has queued for it');
  const ask = b.coord.introBits.bind(b.coord);
  let asked = 0;
  b.coord.introBits = (rid) => ((asked += 1), ask(rid));
  const before = await snapshot(b);
  const gate = spyGate(b.coord);
  assertPowRequired(await s.deliver('r3', owner.rid, SEALED('r3')), 'r3', 16, 'refused by the script');
  assert.strictEqual(asked, 0, 'no question was asked before the push: the script decided');
  assert.deepStrictEqual(gate, { take: 0, shared: 0 }, 'the creation gate was not consulted');
  assert.strictEqual(await snapshot(b), before, 'and nothing was written');
  s.close();
});

// ---- 8. push -----------------------------------------------------------------

/** Puts a token in place behind the relay's back, as a registration that raced the flag would. */
async function plantToken(h, rid, token) {
  if (h.kind === 'ram') h.coord.pushTokens.set(rid, { token, platform: 'android', ts: Date.now() });
  else await h.raw.set(`push:${rid}`, JSON.stringify({ token, platform: 'android' }), 'PX', 60000);
}
async function hasToken(h, rid) {
  if (h.kind === 'ram') return h.coord.pushTokens.has(rid);
  return (await h.raw.exists(`push:${rid}`)) === 1;
}

async function neverWoken(h, wakes) {
  const owner = makeIdentity();
  const c = new Client(h.port, owner);
  assert.strictEqual((await c.auth()).t, 'ready');
  // A token registered before the flag goes when it is set.
  assert.deepStrictEqual(await c.ask({ t: 'push-register', token: 'OWNER_FCM', platform: 'android' }, ['push-ok', 'error']), { t: 'push-ok' });
  assert.ok(await hasToken(h, owner.rid));
  assert.deepStrictEqual(await c.intro(16), { t: 'intro_ok' });
  assert.ok(!(await hasToken(h, owner.rid)), 'flagging deleted the token it held');
  // And no new one is taken.
  assert.deepStrictEqual(await c.ask({ t: 'push-register', token: 'OWNER_FCM2', platform: 'android' }, ['push-ok', 'error']), { t: 'error', code: 'push_refused' });
  assert.ok(!(await hasToken(h, owner.rid)), 'nothing stored for it');
  await leave(h, c);
  // Even with a token there behind the relay's back, a stamped request to the
  // offline owner wakes nothing.
  await plantToken(h, owner.rid, 'PLANTED');
  // Control: an unflagged offline recipient with a token IS woken, so this
  // harness can see a wake when there is one.
  const bob = makeIdentity();
  const bobC = new Client(h.port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  assert.deepStrictEqual(await bobC.ask({ t: 'push-register', token: 'BOB_FCM', platform: 'android' }, ['push-ok', 'error']), { t: 'push-ok' });
  await leave(h, bobC);
  const s = await anonSender(h);
  const payload = SEALED('req');
  const good = stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 }));
  assert.deepStrictEqual(await s.deliver('req', owner.rid, payload, good), sent('req'));
  // The wake decision for the request was made before its `sent`; Bob's,
  // after, is the barrier that shows the recorder working.
  assert.deepStrictEqual(await s.deliver('ctl', bob.rid, SEALED('ctl')), sent('ctl'));
  await waitUntil(() => wakes.length >= 1, { what: "Bob's wake" });
  assert.deepStrictEqual(wakes, ['BOB_FCM'], 'Bob was woken; the introduction mailbox was not');
  s.close();
}

test('8 RAM: an introduction mailbox is never woken — registration refused, an old token deleted, no wake', async (t) => {
  const { wakes, sender } = wakeRecorder();
  await neverWoken(await ram(t, {}, sender), wakes);
});

test('8b Redis: an introduction mailbox is never woken — registration refused, an old token deleted, no wake', { skip: SKIP_REDIS }, async (t) => {
  const { wakes, sender } = wakeRecorder();
  await neverWoken(await redis(t, {}, sender), wakes);
});

// ---- 9. the cap; receipts ----------------------------------------------------

async function capped(h) {
  // Each envelope is charged 2 000 + 256 bytes: three fit in 8 000, a fourth
  // does not. Four different envelopes, each with its own stamp — the same
  // one four times would be held once (criterion 13).
  const owner = await flaggedOwner(h, 16);
  const bob = makeIdentity(); // owned, unflagged: the owned cap only
  const bobC = new Client(h.port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  await leave(h, bobC);
  const s = await anonSender(h);
  const payloads = [0, 1, 2, 3].map((i) => 'zs1.' + String(i).repeat(2000 - 4));
  const stamps = payloads.map((payload) => stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 })));
  const toOwner = [];
  const toBob = [];
  for (let i = 0; i < 4; i++) {
    toOwner.push(await s.deliver(`c${i}`, owner.rid, payloads[i], stamps[i]));
    toBob.push(await s.deliver(`b${i}`, bob.rid, payloads[i]));
  }
  assert.deepStrictEqual(toOwner.slice(0, 3), [sent('c0'), sent('c1'), sent('c2')]);
  assert.deepStrictEqual(toOwner[3], { t: 'error', code: 'queue_full', id: 'c3' }, 'the fourth is past INTRO_MAILBOX_BYTES: refused as at any per-mailbox cap');
  assert.deepStrictEqual(toBob, [sent('b0'), sent('b1'), sent('b2'), sent('b3')], 'an unflagged owned mailbox still takes all four');
  s.close();

  // A receipt the relay queues for a flagged mailbox's owner needs no stamp:
  // the owner sends an attributed envelope, leaves, and the acknowledgement's
  // receipt is queued for it.
  const carol = makeIdentity();
  const carolC = new Client(h.port, carol);
  assert.strictEqual((await carolC.auth()).t, 'ready');
  const sender = await flaggedOwner(h, 16);
  const senderC = new Client(h.port, sender);
  assert.strictEqual((await senderC.auth()).t, 'ready');
  assert.deepStrictEqual(await senderC.deliver('hello', carol.rid, 'aGVsbG8='), sent('hello'));
  await leave(h, senderC);
  const m = await carolC.next((f) => f.t === 'msg' && f.id === 'hello');
  assert.strictEqual(m.from, sender.rid);
  carolC.send({ t: 'recv', id: 'hello', from: sender.rid });
  await waitUntil(async () => (await storedEntries(h, sender.rid)).some((e) => e.kind === 'receipt'), { what: 'the receipt queued in the flagged mailbox' });
  const back = new Client(h.port, sender);
  assert.strictEqual((await back.auth()).t, 'ready');
  const d = await back.next((f) => f.t === 'delivered' && f.id === 'hello');
  assert.strictEqual(d.to, carol.rid, 'and the owner gets it');
  back.close();
  carolC.close();
}

test('9 RAM: a flagged mailbox is capped at INTRO_MAILBOX_BYTES; a receipt for it needs no stamp', async (t) => {
  await capped(await ram(t, { introMailboxBytes: 8000 }));
});

test('9b Redis: a flagged mailbox is capped at INTRO_MAILBOX_BYTES; a receipt for it needs no stamp', { skip: SKIP_REDIS }, async (t) => {
  await capped(await redis(t, { introMailboxBytes: 8000 }));
});

// ---- 10. RAM: the flags are bounded ------------------------------------------

test('10 RAM: flags are a store of their own — logins never move them, INTRO_CAP refuses a new one — and lapse OWNED_TTL after the last intro', async (t) => {
  const restore = withCfg(t, { ownedCap: 2, ownedTtlMs: 1000, introCap: 2 });
  t.after(restore);
  const c = new MemoryCoordinator();
  assert.strictEqual(c.setIntro('A', 16, 0), 'set');
  assert.strictEqual(c.setIntro('B', 17, 10), 'set');
  assert.deepStrictEqual([...c.intro.keys()], ['A', 'B']);
  // A third owner past OWNED_CAP of 2: A, the least recently authenticated,
  // leaves the owner list — and its flag stays (an independent review of
  // handles, 2026-10-09).
  c.claimOwner('C', 20);
  assert.deepStrictEqual([...c.owned.keys()], ['B', 'C']);
  assert.deepStrictEqual([...c.intro.keys()], ['A', 'B'], "A's flag stays when the owner list lets A go");
  assert.strictEqual(c.introBits('A', 20), 16);
  // Past INTRO_CAP of 2 a NEW flag is refused and none is forgotten for it; a
  // held one is renewed, newest last; an address over its minute of new flags
  // is refused a new one and still renews.
  for (let i = 0; i < 10; i++) assert.strictEqual(c.setIntro(`F${i}`, 16, 30 + i), 'full');
  assert.deepStrictEqual([...c.intro.keys()], ['A', 'B'], 'none forgotten');
  assert.strictEqual(c.setIntro('A', 20, 50), 'refreshed');
  assert.strictEqual(c.setIntro('G', 16, 60, { ipOver: true }), 'limited');
  assert.strictEqual(c.setIntro('A', 21, 60, { ipOver: true }), 'refreshed');
  assert.deepStrictEqual([...c.intro.keys()], ['B', 'A']);
  assert.strictEqual(c.introBits('A', 60), 21);
  // Once the oldest lapses there is room for a new one.
  assert.strictEqual(c.setIntro('G', 16, 1011), 'set');
  assert.deepStrictEqual([...c.intro.keys()], ['A', 'G'], "B's lapsed and made room");
  // While flagged a mailbox has the owned caps, out of the owner list or not:
  // what it holds is no part of the unowned budget — leaving the list or
  // coming back to it moves nothing — until its flag lapses with the owner
  // list no longer holding it. U is a mailbox nobody owns, there to show it.
  const e = new MemoryCoordinator();
  const env = (seq, size) => ({ seq, kind: 'msg', id: `x${seq}`, from: null, payload: 'zs1.x', ts: 0, size });
  e.setIntro('A', 16, 0);
  assert.ok(e._enqueue('A', env(1, 1000)));
  assert.ok(e._enqueue('U', env(2, 500)));
  assert.strictEqual(e.unownedBytes, 500);
  e.claimOwner('B', 1);
  e.claimOwner('C', 2);
  assert.deepStrictEqual([...e.owned.keys()], ['B', 'C'], 'A is out of the owner list');
  assert.strictEqual(e.unownedBytes, 500, 'and still owned for its caps while flagged');
  e.claimOwner('A', 3);
  assert.strictEqual(e.unownedBytes, 500, 'back in the list: nothing moves');
  e.claimOwner('D', 4);
  e.claimOwner('E', 5);
  assert.deepStrictEqual([...e.owned.keys()], ['D', 'E'], 'out again');
  assert.strictEqual(e.unownedBytes, 500);
  e._trimIntro(1001);
  assert.strictEqual(e.unownedBytes, 1500, 'its flag lapsed: unowned again');
  e._removeKey('A', e.queues.get('A').entries[0].key);
  assert.strictEqual(e.unownedBytes, 500, 'and settled when what it held goes');
  // A flag lapses OWNED_TTL after its last `intro`, though its owner logged
  // in since (a login refreshes ownership, not the flag).
  const d = new MemoryCoordinator();
  d.setIntro('D', 16, 0);
  d.claimOwner('D', 900);
  assert.strictEqual(d.introBits('D', 1000), 16, 'still flagged at the TTL');
  assert.strictEqual(d.introBits('D', 1001), 0, 'lapsed past it, even before a sweep');
  d._trimIntro(1001);
  assert.deepStrictEqual([...d.intro.keys()], [], 'and the sweep forgets it');
  assert.deepStrictEqual([...d.owned.keys()], ['D'], 'while D is still owned');
});

// ---- 11. nothing new is logged ------------------------------------------------

test('11 RAM: flagging, refusing and accepting stamped sends, and refusing push, log nothing', async (t) => {
  const h = await ram(t, { logLevel: 'info' });
  const owner = makeIdentity();
  const c = new Client(h.port, owner);
  assert.strictEqual((await c.auth()).t, 'ready');
  // The one line the relay writes per login predates this phase (and may
  // land after `ready`, so it is filtered below); anything else written from
  // here on is new.
  const lines = [];
  const original = console.log;
  console.log = (...args) => lines.push(args.map(String).join(' '));
  t.after(() => (console.log = original));
  try {
    assert.deepStrictEqual(await c.intro(16), { t: 'intro_ok' });
    assert.deepStrictEqual(await c.intro(99), { t: 'error', code: 'bad_intro' });
    assert.deepStrictEqual((await c.ask({ t: 'push-register', token: 'T', platform: 'android' }, ['push-ok', 'error'])).code, 'push_refused');
    const s = await anonSender(h);
    const payload = SEALED('log');
    const good = stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 }));
    assertPowRequired(await s.deliver('l1', owner.rid, payload), 'l1', 16);
    assert.deepStrictEqual(await s.deliver('l2', owner.rid, payload, good), sent('l2'));
    await c.next((f) => f.t === 'msg' && f.id === 'l2');
    s.close();
  } finally {
    console.log = original;
  }
  const other = lines.filter((l) => !/client authenticated; local connections =/.test(l));
  assert.deepStrictEqual(other, [], `no new log line (got ${JSON.stringify(other)})`);
  assert.ok(!lines.some((l) => l.includes(owner.rid)), 'no routing id in anything logged');
  c.close();
});

// ---- 12. metrics ---------------------------------------------------------------

async function metricsCarried(h) {
  const bearer = { authorization: 'Bearer m' };
  const scrape = async () => (await get(h.port, '/metrics', bearer)).body;
  const before = await scrape();
  const ownerA = await flaggedOwner(h, 16);
  await flaggedOwner(h, 16);
  const s = await anonSender(h);
  const payload = SEALED('metrics');
  const good = stamp((d) => mine({ rid: ownerA.rid, payload, day: d, min: 16 }));
  assertPowRequired(await s.deliver('m1', ownerA.rid, payload), 'm1', 16);
  assertPowRequired(await s.deliver('m2', ownerA.rid, payload, 'x'), 'm2', 16);
  assert.deepStrictEqual(await s.deliver('m3', ownerA.rid, payload, good), sent('m3'));
  assert.deepStrictEqual(await s.deliver('m5', ownerA.rid, payload, good), sent('m5'), 'a copy of a held envelope');
  assert.deepStrictEqual(await s.deliver('m4', makeIdentity().rid, payload), sent('m4'), 'an unflagged send counts in none of them');
  if (h.kind === 'redis') await h.coord.sweep(); // the gauge is what a sweep counted
  const after = await scrape();
  const delta = (name) => metric(after, name) - metric(before, name);
  assert.strictEqual(delta('z_intro_pow_refused_total'), 2, 'two refusals counted');
  assert.strictEqual(delta('z_intro_accepted_total'), 1, 'one accepted');
  assert.strictEqual(delta('z_intro_duplicate_total'), 1, 'one copy answered and not stored, counted apart');
  assert.strictEqual(metric(after, 'z_intro_mailboxes'), 2, 'two mailboxes flagged');
  for (const [name, type] of [['z_intro_pow_refused_total', 'counter'], ['z_intro_accepted_total', 'counter'], ['z_intro_duplicate_total', 'counter'], ['z_intro_mailboxes', 'gauge']]) {
    assert.ok(new RegExp(`^# TYPE ${name} ${type}$`, 'm').test(after), `${name} is a ${type}`);
  }
  s.close();
}

test('12 RAM: /metrics carries the refusals, the acceptances and the flagged-mailbox gauge', async (t) => {
  await metricsCarried(await ram(t, { metricsToken: 'm' }));
});

test('12b Redis: /metrics carries the refusals, the acceptances and the flagged-mailbox gauge', { skip: SKIP_REDIS }, async (t) => {
  await metricsCarried(await redis(t, { metricsToken: 'm' }));
});

// ---- 13. (amendment 1) a copy of a held envelope is held once ---------------

const hashOf = (payload) => sha256(Buffer.from(payload, 'utf8')).toString('base64url');
const idsHeld = async (h, rid) => (await storedEntries(h, rid)).map((e) => e.id).sort();
/** The payload hashes a mailbox has indexed to recognise a copy. */
async function indexed(h, rid) {
  if (h.kind === 'ram') {
    const q = h.coord.queues.get(rid);
    return q && q.hashes ? [...q.hashes.keys()].sort() : [];
  }
  return Object.keys(await h.raw.hgetall(`qe:${rid}`))
    .filter((k) => k.startsWith('h:'))
    .map((k) => k.slice(2))
    .sort();
}
/** Makes the held envelope `id` older than QUEUE_TTL_HOURS, as time would. */
async function backdate(h, rid, id) {
  if (h.kind === 'ram') {
    h.coord.queues.get(rid).entries.find((e) => e.id === id).ts = 0;
    return;
  }
  const e = JSON.parse(await h.raw.hget(`qe:${rid}`, `m:${id}`));
  e.ts = 0;
  await h.raw.hset(`qe:${rid}`, `m:${id}`, JSON.stringify(e));
}
const fill = (c) => 'zs1.' + c.repeat(2000 - 4); // charged 2 256 bytes

async function copiesHeldOnce(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  const P = ['a', 'b', 'c', 'd', 'e', 'f'].map(fill);
  const S = P.map((payload) => stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 })));
  // Stored once: the send, its retry under the same id, and a replay of the
  // same envelope and stamp under a new id — all answered as if stored.
  assert.deepStrictEqual(await s.deliver('d1', owner.rid, P[0], S[0]), sent('d1'));
  const once = await snapshot(h);
  assert.deepStrictEqual(await s.deliver('d1', owner.rid, P[0], S[0]), sent('d1'), 'a retry: answered as if stored');
  assert.deepStrictEqual(await s.deliver('d2', owner.rid, P[0], S[0]), sent('d2'), 'a replay under a new id: answered the same');
  assert.strictEqual(await snapshot(h), once, 'and neither stored anything');
  // At the cap (8 000 bytes: three envelopes) a fourth is refused, but a copy
  // of one held is no new bytes and is answered as if stored.
  assert.deepStrictEqual(await s.deliver('d3', owner.rid, P[1], S[1]), sent('d3'));
  assert.deepStrictEqual(await s.deliver('d4', owner.rid, P[2], S[2]), sent('d4'));
  assert.deepStrictEqual(await s.deliver('d5', owner.rid, P[3], S[3]), { t: 'error', code: 'queue_full', id: 'd5' }, 'the mailbox is at its cap');
  assert.deepStrictEqual(await s.deliver('d6', owner.rid, P[1], S[1]), sent('d6'), 'a copy is not refused at the cap: it is held already');
  assert.deepStrictEqual(await idsHeld(h, owner.rid), ['d1', 'd3', 'd4'], 'three envelopes held, no copy among them');
  // The owner drains exactly those.
  const ownerC = new Client(h.port, owner);
  assert.strictEqual((await ownerC.auth()).t, 'ready');
  for (const id of ['d1', 'd3', 'd4']) {
    await ownerC.next((f) => f.t === 'msg' && f.id === id);
    ownerC.send({ t: 'recv', id });
  }
  await waitUntil(async () => (await storedEntries(h, owner.rid)).length === 0, { what: 'the owner acknowledged all three' });
  // Online, a copy is not delivered either: e1 arrives, its copy e2 does not,
  // and e3 after it is the barrier — a copy would have come first.
  assert.deepStrictEqual(await s.deliver('e1', owner.rid, P[4], S[4]), sent('e1'));
  await ownerC.next((f) => f.t === 'msg' && f.id === 'e1');
  assert.deepStrictEqual(await s.deliver('e2', owner.rid, P[4], S[4]), sent('e2'));
  assert.deepStrictEqual(await s.deliver('e3', owner.rid, P[5], S[5]), sent('e3'));
  await ownerC.next((f) => f.t === 'msg' && f.id === 'e3');
  assert.ok(!ownerC.frames.some((f) => f.t === 'msg' && ['d2', 'd6', 'e2'].includes(f.id)), 'no copy was ever delivered');
  // Once the held envelope is acknowledged, the same payload is new again.
  ownerC.send({ t: 'recv', id: 'e1' });
  ownerC.send({ t: 'recv', id: 'e3' });
  await waitUntil(async () => (await storedEntries(h, owner.rid)).length === 0, { what: 'e1 and e3 acknowledged' });
  assert.deepStrictEqual(await s.deliver('e4', owner.rid, P[4], S[4]), sent('e4'));
  await ownerC.next((f) => f.t === 'msg' && f.id === 'e4');
  ownerC.close();
  // A mailbox nobody flagged keeps both copies, as it always has.
  const bob = makeIdentity();
  const bobC = new Client(h.port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  await leave(h, bobC);
  assert.deepStrictEqual(await s.deliver('u1', bob.rid, P[0]), sent('u1'));
  assert.deepStrictEqual(await s.deliver('u2', bob.rid, P[0]), sent('u2'));
  assert.deepStrictEqual(await idsHeld(h, bob.rid), ['u1', 'u2'], 'an unflagged mailbox holds both');
  s.close();
}

test('13 RAM: a copy of an envelope a flagged mailbox holds is answered as if stored, and held once', async (t) => {
  await copiesHeldOnce(await ram(t, { introMailboxBytes: 8000 }));
});

test('13b Redis: a copy of an envelope a flagged mailbox holds is answered as if stored, and held once', { skip: SKIP_REDIS }, async (t) => {
  await copiesHeldOnce(await redis(t, { introMailboxBytes: 8000 }));
});

async function copyIndexGoesWithTheEnvelope(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  const [A, B, C] = ['x', 'y', 'z'].map(fill);
  const [SA, SB, SC] = [A, B, C].map((payload) => stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 })));
  assert.deepStrictEqual(await s.deliver('k1', owner.rid, A, SA), sent('k1'));
  assert.deepStrictEqual(await s.deliver('k2', owner.rid, B, SB), sent('k2'));
  assert.deepStrictEqual(await s.deliver('k3', owner.rid, C, SC), sent('k3'));
  assert.deepStrictEqual(await indexed(h, owner.rid), [hashOf(A), hashOf(B), hashOf(C)].sort(), 'each held envelope indexed by its payload hash');
  // Expiry: A, at the head, has outlived the TTL; B and C have not.
  await backdate(h, owner.rid, 'k1');
  await h.coord.sweep();
  assert.deepStrictEqual(await idsHeld(h, owner.rid), ['k2', 'k3']);
  assert.deepStrictEqual(await indexed(h, owner.rid), [hashOf(B), hashOf(C)].sort(), 'the expired envelope left the index with it');
  // An acknowledgement: B goes, and its index entry with it.
  const ownerC = new Client(h.port, owner);
  assert.strictEqual((await ownerC.auth()).t, 'ready');
  await ownerC.next((f) => f.t === 'msg' && f.id === 'k2');
  ownerC.send({ t: 'recv', id: 'k2' });
  await waitUntil(async () => (await idsHeld(h, owner.rid)).join() === 'k3', { what: 'k2 acknowledged' });
  assert.deepStrictEqual(await indexed(h, owner.rid), [hashOf(C)], 'the acknowledged envelope left the index with it');
  // So A and B are new again, and C is still a copy.
  assert.deepStrictEqual(await s.deliver('k4', owner.rid, A, SA), sent('k4'));
  assert.deepStrictEqual(await s.deliver('k5', owner.rid, B, SB), sent('k5'));
  assert.deepStrictEqual(await s.deliver('k6', owner.rid, C, SC), sent('k6'));
  assert.deepStrictEqual(await idsHeld(h, owner.rid), ['k3', 'k4', 'k5'], 'A and B stored anew; C held once');
  assert.deepStrictEqual(await indexed(h, owner.rid), [hashOf(A), hashOf(B), hashOf(C)].sort());
  ownerC.close();
  s.close();
}

test('13 RAM: the index that recognises a copy goes with the envelope, on acknowledgement and on expiry', async (t) => {
  await copyIndexGoesWithTheEnvelope(await ram(t));
});

test('13b Redis: the index that recognises a copy goes with the envelope, on acknowledgement and on expiry', { skip: SKIP_REDIS }, async (t) => {
  await copyIndexGoesWithTheEnvelope(await redis(t));
});

// ---- 14. (amendment 1) over 64 KiB is too large for an introduction mailbox --

async function tooLargeRefused(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  const atLimit = 'zs1.' + 'q'.repeat(65536 - 4);
  const over = 'zs1.' + 'q'.repeat(65537 - 4);
  // 12 004 characters, which the store holds JSON-escaped at six bytes each.
  const escaped = 'zs1.' + '\u0001'.repeat(12000);
  const [sAt, sOver, sEscaped] = [atLimit, over, escaped].map((payload) => stamp((d) => mine({ rid: owner.rid, payload, day: d, min: 16 })));
  const tooLarge = (id) => ({ t: 'error', code: 'too_large', id });
  const refusedClean = async (sends) => {
    const before = await snapshot(h);
    const gate = spyGate(h.coord);
    for (const [id, payload, pow, why] of sends) assert.deepStrictEqual(await s.deliver(id, owner.rid, payload, pow), tooLarge(id), why);
    assert.strictEqual(await snapshot(h), before, 'nothing stored, owned, seen or charged');
    assert.deepStrictEqual(gate, { take: 0, shared: 0 }, 'the creation gate was not consulted');
  };
  // A first contact (in the Redis path, refused on the question asked before
  // the gate) — with a good stamp, without one, and escaped past the limit.
  await refusedClean([
    ['t1', over, sOver, 'one byte over, with a good stamp: refused'],
    ['t2', over, undefined, 'decided before the stamp: no stamp, still too_large'],
    ['t3', escaped, sEscaped, 'shorter, but held escaped past 64 KiB: refused'],
  ]);
  assert.deepStrictEqual(await s.deliver('t4', owner.rid, atLimit, sAt), sent('t4'), 'exactly 64 KiB is taken');
  // Now the instance has queued for it: the push script decides (Redis), the
  // same check (RAM).
  await refusedClean([['t5', over, sOver, 'over, to a mailbox already queued for: refused']]);
  // A mailbox nobody flagged still takes it, as it always has.
  const bob = makeIdentity();
  const bobC = new Client(h.port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  await leave(h, bobC);
  assert.deepStrictEqual(await s.deliver('u1', bob.rid, over), sent('u1'));
  s.close();
}

test('14 RAM: a flagged mailbox refuses an envelope over 64 KiB, too_large, before anything is stored or charged', async (t) => {
  await tooLargeRefused(await ram(t));
});

test('14b Redis: a flagged mailbox refuses an envelope over 64 KiB, too_large, before anything is stored or charged', { skip: SKIP_REDIS }, async (t) => {
  await tooLargeRefused(await redis(t, { newMailboxShared: true }));
});

// ---- 15. (amendment 1) the refusal names the relay's day ---------------------

async function dayNamed(h) {
  const owner = await flaggedOwner(h, 16);
  const s = await anonSender(h);
  const payload = SEALED('clock');
  // A sender whose clock is a day ahead: its today is the relay's tomorrow.
  const ahead = stamp((d) => mine({ rid: owner.rid, payload, day: d + 1, min: 16, avoid: notFor(owner.rid, payload, 16, d) }));
  const r = await s.deliver('c1', owner.rid, payload, ahead);
  assertPowRequired(r, 'c1', 16, "the ahead clock's stamp is refused, naming the relay's day");
  // One stamp re-made for the day the relay named is taken.
  const again = mine({ rid: owner.rid, payload, day: r.day, min: 16 });
  assert.deepStrictEqual(await s.deliver('c2', owner.rid, payload, again), sent('c2'));
  s.close();
}

test('15 RAM: pow_required names the relay\'s day, and a stamp re-made for it is taken', async (t) => {
  await dayNamed(await ram(t));
});

test('15b Redis: pow_required names the relay\'s day, and a stamp re-made for it is taken', { skip: SKIP_REDIS }, async (t) => {
  await dayNamed(await redis(t));
});
