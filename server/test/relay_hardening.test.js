'use strict';

// Phase 29 — the relay cannot be taken down or read from outside.
//
// These exercise the abuse limits P0-4/P1-13/P1-14 added, through the real
// relay (and the real Redis path where the behaviour lives in Lua), by
// mutating CFG before each server is built. Every CFG change is restored in a
// t.after so one test cannot leak a limit into the next.
//
// Criteria, each asserted below:
//   1. the store-fill attack is refused WITHIN its budget — a flood of sealed
//      envelopes to mailboxes nobody owns fills the unowned budget and is then
//      refused `store_full` (counted z_unowned_refused_total, not
//      z_store_full_total), while an OWNED mailbox still receives throughout;
//   2. the per-unowned-mailbox byte cap holds, and an owned mailbox has the
//      full per-user cap;
//   3. the relay-wide unowned budget bounds the SUM across unowned mailboxes;
//   4. per-IP unowned budget: one IP spends its minute and is refused while a
//      second IP still gets through; keyed on CLIENT_IP_HEADER when set;
//   5. the global connection cap refuses past its limit; the per-IP connection
//      cap engages only when CLIENT_IP_HEADER is set;
//   6. an unauthenticated socket that sends nothing is closed on the idle
//      timeout, while one that pings (an anonymous sender) is left alone;
//   7. /metrics is 404 without a token, 401 with the wrong one, 200 with the
//      right one; /health is liveness only — no counters, no instance id;
//   8. ownership survives in the Redis path and its unowned budget is enforced
//      in Lua, while an owned mailbox still receives; and the sweep reconciles
//      z:ub so a per-key TTL expiry cannot leak it upward for ever, and
//      reports it as the z_unowned_bytes store-fill gauge;
//   9. a wake push is NOT sent to a recipient online on ANOTHER instance;
//  10. envelope-id "squatting" (#42) cannot dedupe an honest envelope away: two
//      sealed envelopes sharing an id are both delivered, and an attributed
//      envelope is keyed by the relay-stamped sender so a different sender's
//      same-id envelope cannot displace it;
//  11. a reader stuck above the high-water mark is terminated after the drain
//      timeout, with the relay's buffered bytes bounded throughout, and loses
//      nothing: its whole backlog is flushed when it reconnects;
//  12. an envelope is charged what it really occupies, not its UTF-16 unit
//      count: base64 traffic exactly as before, a payload V8 must hold two
//      bytes a unit at twice its length, and one the store's JSON escapes at
//      its escaped size (relay P2);
//  13. a socket that stops reading while it keeps sending (the P1-13 shape:
//      envelopes to its own mailbox, acknowledged unread) is dropped once
//      what the relay holds for it passes SEND_BUFFER_CAP, the relay's buffer
//      for it never exceeding the cap plus one frame, and counted;
//  14. several such sockets are bounded TOGETHER by SEND_BUFFER_TOTAL: past
//      it the socket holding the most is dropped though it is under its own
//      cap, and one holding less is kept;
//  15. sends the unowned budget refuses spend none of the NEW_MAILBOX_PER_MIN
//      creation allowance, so a flood it stops cannot also take the creation
//      an honest first message needs — to a recipient who has authenticated
//      but whose mailbox is empty (RAM, and 15b in the Redis path);
//  16. the RAM coordinator's memory of owners is bounded — OWNED_CAP forgets
//      the least recently authenticated, OWNED_TTL the stale — and a
//      forgotten owner's mailbox is simply unowned again, its bytes back in
//      the unowned total (the Redis path's owned: keys expire on the TTL).
//
// Redis-only criteria skip when redis-server/ioredis are unavailable, as the
// HA tests do.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const WebSocket = require('ws');

const {
  createServer,
  CFG,
  RedisCoordinator,
  routingIdFromPub,
} = require('../server.js');

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
/** Starts a throwaway redis-server and resolves once it answers PING. The
 * caller stops it (`stop`) after closing every coordinator that uses it, in
 * the one cleanup hook, as the HA tests do. */
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

/** A client that can authenticate (becoming owned) or stay anonymous. */
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
  async auth() {
    const ch = await this.next((f) => f.t === 'challenge');
    const msg = Buffer.concat([V2, Buffer.from(authorityOf(this.port), 'utf8'), Buffer.from(ch.nonce, 'base64')]);
    const sig = crypto.sign(null, msg, this.identity.privateKey);
    this.send({ t: 'auth', v: 2, pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    return this.next((f) => f.t === 'ready' || f.t === 'error');
  }
  async seenChallenge() {
    return this.next((f) => f.t === 'challenge');
  }
  deliver(id, to, payload) {
    this.send({ t: 'send', id, to, payload });
    return this.next((f) => (f.t === 'sent' || f.t === 'error') && f.id === id, 15000);
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

async function ramRelay(t, cfg = {}) {
  const saved = {};
  for (const k of Object.keys(cfg)) {
    saved[k] = CFG[k];
    CFG[k] = cfg[k];
  }
  const srv = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(() => {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
    for (const k of Object.keys(saved)) CFG[k] = saved[k];
  });
  return { srv, port };
}

const SEALED = (n) => 'zs1.' + 'x'.repeat(Math.max(0, n - 4));

test('1+2+3 RAM: unowned caps bound the flood; an owned mailbox receives throughout', async (t) => {
  // Small budgets so the test is quick; the shape is the production one.
  const { srv, port } = await ramRelay(t, {
    unownedMailboxBytes: 4000,
    unownedStoreBytes: 20000,
    newMailboxPerMin: 100000, // take the creation gate out of the way
  });
  const token = 'tok1';
  CFG.metricsToken = token;
  t.after(() => (CFG.metricsToken = null));
  const bearer = { authorization: `Bearer ${token}` };

  // Bob authenticates first: his mailbox is OWNED and must keep receiving.
  const bob = makeIdentity();
  const bobC = new Client(port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  bobC.close();
  await waitUntil(() => srv.wss.clients.size === 0, { what: "Bob's first socket gone from the relay" });

  const attacker = new Client(port, makeIdentity());
  await attacker.seenChallenge();

  // 2. One unowned mailbox fills its own small cap and is then refused.
  let acceptedOne = 0;
  for (let i = 0; i < 10; i++) {
    const r = await attacker.deliver(`a${i}`, 'A'.repeat(43), SEALED(1500));
    if (r.t === 'sent') acceptedOne++;
    else {
      assert.strictEqual(r.code, 'store_full', 'per-mailbox refusal is store_full');
      break;
    }
  }
  assert.ok(acceptedOne >= 1 && acceptedOne <= 3, `per-mailbox cap held (${acceptedOne} of ~1756-byte envelopes in a 4000-byte cap)`);

  // 3. The relay-wide unowned budget bounds the sum across many mailboxes.
  let acceptedTotal = acceptedOne;
  for (let i = 0; i < 100; i++) {
    const rid = crypto.randomBytes(32).toString('base64url');
    const r = await attacker.deliver(`m${i}`, rid, SEALED(1500));
    if (r.t === 'sent') acceptedTotal++;
  }
  const held = srv.coordinator.unownedBytes;
  assert.ok(held <= CFG.unownedStoreBytes, `unowned bytes held (${held}) within budget (${CFG.unownedStoreBytes})`);
  const refused = metric((await get(port, '/metrics', bearer)).body, 'z_unowned_refused_total');
  assert.ok(refused > 50, `the flood was refused (${refused}) and counted as unowned, not store_full`);
  assert.strictEqual(metric((await get(port, '/metrics', bearer)).body, 'z_store_full_total'), 0, 'not counted as a full store');

  // 1. Bob (owned) still receives, even though the unowned budget is spent.
  const alice = new Client(port, makeIdentity());
  await alice.seenChallenge();
  assert.strictEqual((await alice.deliver('forbob', bob.rid, SEALED(1500))).t, 'sent', 'an owned mailbox receives while the unowned budget is full');
  const bob2 = new Client(port, bob);
  assert.strictEqual((await bob2.auth()).t, 'ready');
  const got = await bob2.next((f) => f.t === 'msg' && f.id === 'forbob');
  assert.ok(got, 'Bob got the envelope');
  t.diagnostic(`flood: ${acceptedTotal} unowned envelopes accepted (~${Math.round(held / 1024)} KiB) then refused; Bob unaffected`);
  attacker.close();
  alice.close();
  bob2.close();
});

test('4 RAM: per-IP unowned budget — one IP is spent while another still gets through, keyed on CLIENT_IP_HEADER', async (t) => {
  const { srv, port } = await ramRelay(t, {
    unownedMailboxBytes: 1 << 20,
    unownedStoreBytes: 1 << 30, // out of the way; this test is about per-IP
    unownedBytesPerIpPerMin: 6000,
    newMailboxPerMin: 100000,
    clientIpHeader: 'x-test-ip',
  });
  // Two clients presenting different client IPs via the trusted header.
  const a = new Client(port, makeIdentity(), { 'x-test-ip': '10.0.0.1' });
  const b = new Client(port, makeIdentity(), { 'x-test-ip': '10.0.0.2' });
  await a.seenChallenge();
  await b.seenChallenge();
  // IP .1 spends its ~6000-byte minute on unowned mail.
  let aAccepted = 0;
  for (let i = 0; i < 20; i++) {
    const rid = crypto.randomBytes(32).toString('base64url');
    const r = await a.deliver(`a${i}`, rid, SEALED(1500));
    if (r.t === 'sent') aAccepted++;
    else break;
  }
  assert.ok(aAccepted >= 2 && aAccepted <= 4, `IP .1 bounded to its per-IP minute (${aAccepted})`);
  assert.strictEqual((await a.deliver('aOver', crypto.randomBytes(32).toString('base64url'), SEALED(1500))).code, 'store_full', 'IP .1 refused after its minute');
  // IP .2 is untouched by IP .1's spending.
  assert.strictEqual((await b.deliver('b0', crypto.randomBytes(32).toString('base64url'), SEALED(1500))).t, 'sent', 'IP .2 still gets through');
  a.close();
  b.close();
});

test('5 RAM: a global connection cap refuses past its limit; per-IP only with the header', async (t) => {
  const { port } = await ramRelay(t, { maxConnections: 3, maxConnectionsPerIp: 0 });
  const live = [];
  for (let i = 0; i < 3; i++) {
    const c = new Client(port, makeIdentity());
    await c.seenChallenge();
    live.push(c);
  }
  const over = new Client(port, makeIdentity());
  await waitUntil(() => over.closed != null, { what: 'the 4th connection closed' });
  assert.strictEqual(over.closed, 1013, `the 4th connection was refused (close ${over.closed})`);
  live.forEach((c) => c.close());
});

test('5b RAM: the per-IP connection cap engages when CLIENT_IP_HEADER is set', async (t) => {
  const { port } = await ramRelay(t, { maxConnections: 100, maxConnectionsPerIp: 2, clientIpHeader: 'x-test-ip' });
  const live = [];
  for (let i = 0; i < 2; i++) {
    const c = new Client(port, makeIdentity(), { 'x-test-ip': '7.7.7.7' });
    await c.seenChallenge();
    live.push(c);
  }
  const over = new Client(port, makeIdentity(), { 'x-test-ip': '7.7.7.7' });
  await waitUntil(() => over.closed != null, { what: 'the third same-IP connection closed' });
  assert.strictEqual(over.closed, 1013, 'a third from the same IP is refused');
  // A different IP is unaffected.
  const other = new Client(port, makeIdentity(), { 'x-test-ip': '8.8.8.8' });
  assert.ok((await other.seenChallenge()).t === 'challenge', 'a different IP connects');
  live.forEach((c) => c.close());
  other.close();
});

test('6 RAM: an idle unauthenticated socket is closed; one that pings is left alone', async (t) => {
  const { port } = await ramRelay(t, { heartbeatMs: 80, unauthIdleMs: 150 });
  const idle = new Client(port, makeIdentity());
  await idle.seenChallenge(); // seen, never answered, never pings
  const pinger = new Client(port, makeIdentity());
  await pinger.seenChallenge();
  const beat = setInterval(() => pinger.send({ t: 'ping' }), 40);
  t.after(() => clearInterval(beat));
  await waitUntil(() => idle.closed != null, { what: 'the silent socket closed' });
  assert.strictEqual(idle.closed, 4003, 'the silent unauthenticated socket was closed on the idle timeout');
  // The pinger must outlive several more idle windows: count its pongs past
  // the moment the silent one went (8 × 40 ms > 2 × the 150 ms timeout).
  const pongs = () => pinger.frames.filter((f) => f.t === 'pong').length;
  const base = pongs();
  await waitUntil(() => pongs() >= base + 8 || pinger.closed != null, { what: 'the pinger answered across two more idle windows' });
  assert.strictEqual(pinger.closed, null, 'the pinging (anonymous-sender) socket was left alone — not an auth deadline');
  pinger.close();
});

test('7 /metrics needs a bearer token (404 unset, 401 wrong, 200 right); /health is liveness only', async (t) => {
  // Unset: 404, not even admitting the endpoint exists.
  const open = await ramRelay(t, {});
  CFG.metricsToken = null;
  assert.strictEqual((await get(open.port, '/metrics')).status, 404, 'no token configured → 404');
  const h = JSON.parse((await get(open.port, '/health')).body);
  assert.strictEqual(h.ok, true);
  assert.strictEqual(h.storage, 'ram-only');
  assert.ok(!('queuedEnvelopes' in h), '/health carries no counters');
  assert.ok(!('connections' in h), '/health carries no connection count');
  assert.ok(!('instanceId' in h), '/health carries no instance id');
  assert.ok(!('storeBytes' in h), '/health carries no store bytes');

  // Configured: wrong token 401, right token 200.
  const sec = await ramRelay(t, {});
  CFG.metricsToken = 'the-secret';
  t.after(() => (CFG.metricsToken = null));
  assert.strictEqual((await get(sec.port, '/metrics')).status, 401, 'token configured, none sent → 401');
  assert.strictEqual((await get(sec.port, '/metrics', { authorization: 'Bearer wrong' })).status, 401, 'wrong token → 401');
  const ok = await get(sec.port, '/metrics', { authorization: 'Bearer the-secret' });
  assert.strictEqual(ok.status, 200, 'right token → 200');
  assert.ok(/^# TYPE z_connections /m.test(ok.body), 'and the metrics are served');
});

test('10 #42: an envelope id cannot be squatted to dedupe an honest envelope away', async (t) => {
  const { port } = await ramRelay(t, { newMailboxPerMin: 100000 });
  const box = makeIdentity();
  // Two sealed envelopes sharing one id, from an anonymous connection: both
  // are kept (slots) and both delivered — a sealed id never dedupes away.
  const anon = new Client(port, makeIdentity());
  await anon.seenChallenge();
  assert.strictEqual((await anon.deliver('dup', box.rid, SEALED(400) + 'A')).t, 'sent');
  assert.strictEqual((await anon.deliver('dup', box.rid, SEALED(400) + 'B')).t, 'sent');
  // An attributed envelope is keyed by the relay-stamped sender, so a second
  // authenticated sender using the same id lands on its own key, not the
  // first sender's: it cannot displace the honest one.
  const alice = new Client(port, makeIdentity());
  const mallory = new Client(port, makeIdentity());
  assert.strictEqual((await alice.auth()).t, 'ready');
  assert.strictEqual((await mallory.auth()).t, 'ready');
  assert.strictEqual((await alice.deliver('shared', box.rid, 'alicePlain')).t, 'sent');
  assert.strictEqual((await mallory.deliver('shared', box.rid, 'malloryPlain')).t, 'sent');

  const boxC = new Client(port, box);
  assert.strictEqual((await boxC.auth()).t, 'ready');
  const got = [];
  const deadline = Date.now() + 4000;
  while (got.length < 4 && Date.now() < deadline) {
    const f = await boxC.next((x) => x.t === 'msg', 2000).catch(() => null);
    if (!f) break;
    got.push(f);
  }
  const payloads = got.map((f) => f.payload).sort();
  assert.ok(payloads.includes('alicePlain') && payloads.includes('malloryPlain'),
    'both attributed envelopes survived — the colliding id did not dedupe the honest one away');
  const sealed = got.filter((f) => f.payload.startsWith('zs1.'));
  assert.strictEqual(sealed.length, 2, 'both same-id sealed envelopes were delivered');
  anon.close();
  alice.close();
  mallory.close();
  boxC.close();
});

test('11 RAM: a reader stuck above the high-water mark is terminated, buffered bytes bounded', async (t) => {
  const { srv, port } = await ramRelay(t, {
    flushPage: 4,
    flushHighWaterBytes: 64 * 1024,
    drainTimeoutMs: 400,
    newMailboxPerMin: 100000,
  });
  const bob = makeIdentity();
  // Fill Bob's (owned, so no unowned cap) mailbox with a backlog bigger than a
  // loopback socket swallows.
  const bobOwn = new Client(port, bob);
  assert.strictEqual((await bobOwn.auth()).t, 'ready');
  bobOwn.close();
  await waitUntil(() => srv.wss.clients.size === 0, { what: "Bob's first socket gone from the relay" });
  const sender = new Client(port, makeIdentity());
  await sender.seenChallenge();
  const BIG = SEALED(200 * 1024);
  const N = 60; // ~12 MiB: more than the loopback socket buffers swallow
  for (let i = 0; i < N; i++) {
    const r = await sender.deliver(`b${i}`, bob.rid, BIG);
    assert.strictEqual(r.t, 'sent', JSON.stringify(r));
  }
  // Bob reconnects and immediately stops reading. A paused client never sees
  // its socket close, so the relay's side of it is what is watched.
  const stuck = new Client(port, bob);
  assert.strictEqual((await stuck.auth()).t, 'ready');
  stuck.ws._socket.pause();
  const relaySide = srv.coordinator.online.get(bob.rid);
  assert.ok(relaySide, "the relay holds Bob's socket");
  let peak = 0;
  await waitUntil(
    () => {
      for (const ws of srv.wss.clients) peak = Math.max(peak, ws.bufferedAmount);
      return relaySide.readyState === WebSocket.CLOSED;
    },
    { what: 'the stuck reader terminated after the drain timeout' },
  );
  const bound = CFG.flushHighWaterBytes + 200 * 1024 + 64 * 1024;
  assert.ok(peak < bound, `buffered ${(peak / 1024).toFixed(0)} KiB stayed under the bound ${(bound / 1024).toFixed(0)} KiB`);
  // Nothing was lost: the backlog is still queued for Bob's next connection.
  stuck.ws.terminate();
  const back = new Client(port, bob);
  assert.strictEqual((await back.auth()).t, 'ready');
  const ids = new Set();
  await waitUntil(
    () => {
      for (let f = back.frames.shift(); f; f = back.frames.shift()) {
        if (f.t === 'msg') {
          ids.add(f.id);
          back.send({ t: 'recv', id: f.id, from: f.from || '' });
        }
      }
      return ids.size === N;
    },
    { what: 'the whole backlog flushed to the reconnected reader', timeoutMs: 30000 },
  );
  t.diagnostic(`stuck reader terminated; relay buffered at most ${(peak / 1024).toFixed(0)} KiB of a ${((N * 200) / 1024).toFixed(1)} MiB backlog; all ${N} delivered on reconnect`);
  back.close();
  sender.close();
});

test('12 the store charges real bytes, not UTF-16 units (relay P2)', async () => {
  const { MemoryCoordinator } = require('../server.js');
  const c = new MemoryCoordinator();
  // Owned, so the first-contact caps stay out of this (a relay before phase
  // 29 has neither, and runs the same assertions).
  if (typeof c.claimOwner === 'function') c.claimOwner('R');
  const charged = async (id, payload) => {
    const before = c.storeBytes();
    const r = await c.deliverEnqueue(null, 'R', id, payload, '1.1.1.1');
    assert.ok(!r.storeFull && !r.refused, JSON.stringify(r));
    return c.storeBytes() - before;
  };
  // The honest traffic — base64 under zs1. — is one byte a unit everywhere.
  const b64 = 'zs1.' + 'QUJD'.repeat(250);
  assert.strictEqual(await charged('a', b64), b64.length + 256, 'base64 is charged exactly as before');
  // ASCII plus ONE character above U+00FF: V8 now holds the whole string two
  // bytes a unit, though its UTF-8 length is barely more than its length.
  const mixed = 'zs1.' + 'x'.repeat(1000) + 'ā';
  assert.strictEqual(await charged('b', mixed), 2 * mixed.length + 256, 'charged as V8 holds it');
  // Control characters: the store's JSON escapes each one to six bytes.
  const ctl = 'zs1.' + '\u0001'.repeat(100);
  assert.strictEqual(await charged('c', ctl), 4 + 6 * 100 + 256, 'charged as the store holds it');
});

test('13 RAM: a socket that stops reading is dropped once its unread frames pass SEND_BUFFER_CAP', async (t) => {
  const CAP = 512 * 1024;
  const { srv, port } = await ramRelay(t, { sendBufferCapBytes: CAP, metricsToken: 'm13' });
  // The P1-13 shape: an authenticated socket sends envelopes to its OWN
  // mailbox and acknowledges each by id without reading anything, so the
  // store stays empty while every live delivery piles up in what the relay
  // has buffered for a socket that never drains it. Before the cap that
  // buffer grew without bound (+880 MiB in 9 s).
  const me = makeIdentity();
  const c = new Client(port, me);
  assert.strictEqual((await c.auth()).t, 'ready');
  const relaySide = srv.coordinator.online.get(me.rid);
  assert.ok(relaySide, 'the relay holds the socket');
  c.ws._socket.pause();
  const FRAME = 256 * 1024;
  const BIG = SEALED(FRAME);
  // What the relay holds for the socket is largest just after a frame is
  // queued and before the cap is checked, so it is read exactly there: every
  // frame the relay sends this socket goes through `send`.
  let peak = 0;
  const queue = relaySide.send.bind(relaySide);
  relaySide.send = (...args) => {
    const r = queue(...args);
    peak = Math.max(peak, relaySide.bufferedAmount);
    return r;
  };
  let sent = 0;
  while (relaySide.readyState === WebSocket.OPEN && sent < 200) {
    c.send({ t: 'send', id: `s${sent}`, to: me.rid, payload: BIG });
    c.send({ t: 'recv', id: `s${sent}` }); // sealed: acknowledged by id alone (§12.5)
    sent += 1;
    // Paced on what the relay has read off the wire, not on a clock.
    await waitUntil(() => c.ws.bufferedAmount < 2 * FRAME || relaySide.readyState !== WebSocket.OPEN, {
      what: 'the relay read the frames just sent',
    });
  }
  await waitUntil(() => relaySide.readyState === WebSocket.CLOSED, { what: 'the relay dropped the socket that stopped reading' });
  const bound = CAP + FRAME + 1024;
  assert.ok(peak > CAP, `the cap is what dropped it: the buffer reached ${(peak / 1024).toFixed(0)} KiB, past the ${CAP / 1024} KiB cap`);
  assert.ok(peak <= bound, `and the relay never held more than the cap plus one frame for it (${(peak / 1024).toFixed(0)} of ${(bound / 1024).toFixed(0)} KiB)`);
  const body = (await get(port, '/metrics', { authorization: 'Bearer m13' })).body;
  assert.ok(metric(body, 'z_slow_reader_closed_total') >= 1, 'and counted it in z_slow_reader_closed_total');
  assert.ok(metric(body, 'z_queued_envelopes') <= 3, `the acknowledgements landed, so the store held next to nothing (${metric(body, 'z_queued_envelopes')} queued): the relay's buffer was all there was`);
  t.diagnostic(
    `dropped after ${sent} self-addressed ${FRAME / 1024} KiB envelopes (${((sent * FRAME) / 1048576).toFixed(1)} MiB sent, ` +
      `the rest absorbed by the loopback socket buffers); the relay held at most ${(peak / 1024).toFixed(0)} KiB for it`,
  );
  c.ws.terminate();
});

test('14 RAM: sockets that stop reading are bounded TOGETHER by SEND_BUFFER_TOTAL — the heaviest goes first', async (t) => {
  const MiB = 1024 * 1024;
  const { srv, port } = await ramRelay(t, { sendBufferCapBytes: 2 * MiB, sendBufferTotalBytes: 1.5 * MiB, metricsToken: 'm14' });
  const FRAME = 256 * 1024;
  const BIG = SEALED(FRAME);
  const stored = async () => metric((await get(port, '/metrics', { authorization: 'Bearer m14' })).body, 'z_enqueued_total');
  // Criterion 13's shape on two sockets: self-addressed envelopes,
  // acknowledged unread, so only the relay's buffer for each one grows. Each
  // push waits until the relay has stored (and so delivered) that envelope,
  // so a socket's buffer grows one frame at a time.
  const nonReader = async () => {
    const id = makeIdentity();
    const c = new Client(port, id);
    assert.strictEqual((await c.auth()).t, 'ready');
    const relaySide = srv.coordinator.online.get(id.rid);
    assert.ok(relaySide, 'the relay holds the socket');
    c.ws._socket.pause();
    t.after(() => c.ws.terminate());
    let n = 0;
    const push = async () => {
      assert.ok(n < 200, 'bounded loop');
      const before = await stored();
      c.send({ t: 'send', id: `e${n}`, to: id.rid, payload: BIG });
      c.send({ t: 'recv', id: `e${n}` }); // sealed: acknowledged by id alone (§12.5)
      n += 1;
      await waitUntil(async () => relaySide.readyState !== WebSocket.OPEN || (await stored()) > before, {
        what: 'the relay stored the envelope just sent',
      });
    };
    return { relaySide, push };
  };
  const a = await nonReader();
  const b = await nonReader();
  // A alone, to just over 1 MiB: under its own cap and under the total.
  while (a.relaySide.bufferedAmount < MiB) {
    assert.strictEqual(a.relaySide.readyState, WebSocket.OPEN, 'A alone is under both limits');
    await a.push();
  }
  const aHeld = a.relaySide.bufferedAmount;
  assert.ok(aHeld < 1.5 * MiB && aHeld < CFG.sendBufferCapBytes, `A holds ${(aHeld / 1024).toFixed(0)} KiB, under its cap and the total`);
  // Now B: together they pass the total, and the one holding the most — A,
  // though under its own cap — is dropped; B, holding less, is kept.
  let total = 0;
  while (a.relaySide.readyState === WebSocket.OPEN && b.relaySide.readyState === WebSocket.OPEN) {
    await b.push();
    if (a.relaySide.readyState === WebSocket.OPEN) total = Math.max(total, a.relaySide.bufferedAmount + b.relaySide.bufferedAmount);
  }
  await waitUntil(() => a.relaySide.readyState === WebSocket.CLOSED, { what: 'the heaviest non-reader dropped' });
  assert.strictEqual(b.relaySide.readyState, WebSocket.OPEN, 'B, holding less, is kept');
  assert.ok(total <= 1.5 * MiB + FRAME + 1024, `together they never held more than the total plus one frame (${(total / 1024).toFixed(0)} KiB)`);
  t.diagnostic(`A dropped at ${(aHeld / 1024).toFixed(0)}+ KiB (its own cap ${(2 * MiB) / 1024} KiB) once A+B passed ${(1.5 * MiB) / 1024} KiB; B kept`);
});

test('16 RAM: remembered owners are bounded (OWNED_CAP, OWNED_TTL); a forgotten one is simply unowned again', async (t) => {
  const { MemoryCoordinator } = require('../server.js');
  const saved = { cap: CFG.ownedCap, ttl: CFG.ownedTtlMs };
  CFG.ownedCap = 2;
  CFG.ownedTtlMs = 1000;
  t.after(() => {
    CFG.ownedCap = saved.cap;
    CFG.ownedTtlMs = saved.ttl;
  });
  const c = new MemoryCoordinator();
  c.claimOwner('A', 0);
  assert.ok(!(await c.deliverEnqueue(null, 'A', 'a1', SEALED(1000), '192.0.2.1')).storeFull);
  assert.strictEqual(c.unownedBytes, 0, "an owned mailbox's bytes are not unowned");
  c.claimOwner('B', 10);
  c.claimOwner('C', 20); // past the cap of 2: A, the least recently authenticated, is forgotten
  assert.deepStrictEqual([...c.owned.keys()], ['B', 'C']);
  assert.strictEqual(c.unownedBytes, 1000 + 256, "and A's queued bytes count as unowned again");
  c.claimOwner('B', 30); // B authenticates again: C is now the oldest
  c._trimOwned(1021); // C last authenticated at 20, past the 1000 ms TTL; B at 30 is not
  assert.deepStrictEqual([...c.owned.keys()], ['B']);
});

/** Criterion 15, either coordinator. The creation allowance is 3 a minute and
 * the unowned budget two envelopes: a flood at ten fresh mailboxes has two
 * accepted (two creations spent) and eight refused BY THE BUDGET, which must
 * spend nothing — so the third creation is still there for an honest first
 * message to Bob, who has authenticated before but whose mailbox is empty
 * (sending to him creates it). Before phase 29 the flood spent all three and
 * Bob's message was refused. */
async function budgetRefusalsSpendNothing(port) {
  const bob = makeIdentity();
  const bobC = new Client(port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  bobC.close();
  const attacker = new Client(port, makeIdentity());
  await attacker.seenChallenge();
  let accepted = 0;
  for (let i = 0; i < 10; i++) {
    const r = await attacker.deliver(`f${i}`, crypto.randomBytes(32).toString('base64url'), SEALED(1000));
    if (r.t === 'sent') accepted += 1;
    else assert.strictEqual(r.code, 'store_full');
  }
  assert.strictEqual(accepted, 2, 'the unowned budget took two and refused the rest');
  const alice = new Client(port, makeIdentity());
  await alice.seenChallenge();
  assert.strictEqual((await alice.deliver('hi', bob.rid, SEALED(1000))).t, 'sent', "the refused flood left the creation Bob's first message needs");
  attacker.close();
  alice.close();
}

test('15 RAM: a flood the unowned budget refuses does not spend NEW_MAILBOX_PER_MIN', async (t) => {
  const { port } = await ramRelay(t, { newMailboxPerMin: 3, unownedStoreBytes: 2 * (1000 + 256) });
  await budgetRefusalsSpendNothing(port);
});

// ---- Redis-path criteria ----------------------------------------------------

async function redisRelay(t, instanceId, redisPort, cfg = {}, stopRedis = async () => {}) {
  const saved = {};
  for (const k of Object.keys(cfg)) {
    saved[k] = CFG[k];
    CFG[k] = cfg[k];
  }
  const url = `redis://127.0.0.1:${redisPort}`;
  const coord = new RedisCoordinator(url, instanceId);
  const srv = createServer({ coordinator: coord, pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(async () => {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
    await coord.close();
    await stopRedis();
    for (const k of Object.keys(saved)) CFG[k] = saved[k];
  });
  return { srv, coord, port };
}

test('8 Redis: ownership persists and the unowned budget is enforced in Lua; the sweep keeps z:ub honest', { skip: SKIP_REDIS }, async (t) => {
  const { redisPort, raw, stop } = await startRedis();

  const { srv, coord, port } = await redisRelay(
    t,
    'instA',
    redisPort,
    {
      unownedMailboxBytes: 4000,
      unownedStoreBytes: 16000,
      newMailboxPerMin: 100000,
      metricsToken: 'r',
    },
    stop,
  );

  // Bob authenticates: owned:{rid} is written and survives (a store key).
  const bob = makeIdentity();
  const bobC = new Client(port, bob);
  assert.strictEqual((await bobC.auth()).t, 'ready');
  assert.strictEqual(await raw.exists(`owned:${bob.rid}`), 1, 'ownership recorded in the store (survives a relay restart)');
  bobC.close();
  await waitUntil(() => srv.wss.clients.size === 0, { what: "Bob's socket gone from the relay" });

  // The flood of unowned mailboxes is bounded by z:ub, enforced in the push
  // Lua, counted as unowned.
  const attacker = new Client(port, makeIdentity());
  await attacker.seenChallenge();
  let accepted = 0;
  for (let i = 0; i < 60; i++) {
    const rid = crypto.randomBytes(32).toString('base64url');
    const r = await attacker.deliver(`m${i}`, rid, SEALED(1500));
    if (r.t === 'sent') accepted++;
  }
  const ub = Number(await raw.get('z:ub'));
  assert.ok(ub <= CFG.unownedStoreBytes, `z:ub (${ub}) within budget (${CFG.unownedStoreBytes})`);
  assert.ok(accepted <= 12, `the flood was bounded by the budget (${accepted} accepted)`);
  const refused = metric((await get(port, '/metrics', { authorization: 'Bearer r' })).body, 'z_unowned_refused_total');
  assert.ok(refused > 20, `and refused loudly (${refused})`);

  // Bob (owned) receives despite the budget being spent.
  const alice = new Client(port, makeIdentity());
  await alice.seenChallenge();
  assert.strictEqual((await alice.deliver('forbob', bob.rid, SEALED(1500))).t, 'sent', 'owned mailbox receives while unowned budget is full');

  // The Redis-mode store-fill gauge for the unowned budget is what the sweep
  // reconciled: present after a sweep, equal to the store's own count.
  await coord.sweep();
  const scrape = (await get(port, '/metrics', { authorization: 'Bearer r' })).body;
  assert.strictEqual(metric(scrape, 'z_unowned_bytes'), Number(await raw.get('z:ub')), 'z_unowned_bytes reports the reconciled total');
  assert.strictEqual(metric(scrape, 'z_unowned_max_bytes'), CFG.unownedStoreBytes, 'beside its budget');

  // The sweep reconciles z:ub to a true recount: delete the unowned mailboxes
  // out from under the counter (what a per-key TTL expiry does) and the next
  // sweep must bring z:ub back down rather than leave it pinned.
  const keys = await raw.keys('q:*');
  for (const k of keys) {
    const rid = k.slice(2);
    if ((await raw.exists(`owned:${rid}`)) === 0) await raw.del(k, `qe:${rid}`, `qb:${rid}`);
  }
  await coord.sweep();
  const after = Number(await raw.get('z:ub'));
  assert.strictEqual(after, 0, `the sweep reconciled z:ub to the true unowned total after a wholesale expiry (was ${ub}, now ${after})`);
  // And first contact works again now the budget is free.
  assert.strictEqual((await alice.deliver('fresh', crypto.randomBytes(32).toString('base64url'), SEALED(1500))).t, 'sent', 'first contact works again once the budget is reconciled free');
  attacker.close();
  alice.close();
});

test('15b Redis: a flood the unowned budget refuses does not spend NEW_MAILBOX_PER_MIN', { skip: SKIP_REDIS }, async (t) => {
  const { redisPort, stop } = await startRedis();
  const { port } = await redisRelay(t, 'instA', redisPort, { newMailboxPerMin: 3, unownedStoreBytes: 2 * (1000 + 256) }, stop);
  await budgetRefusalsSpendNothing(port);
});

test('9 Redis: no wake push to a recipient online on another instance', { skip: SKIP_REDIS }, async (t) => {
  const { redisPort, raw, stop } = await startRedis();
  const url = `redis://127.0.0.1:${redisPort}`;

  // Two instances sharing the store; a push sender that records every wake.
  const wakes = [];
  const fakePush = { sendWake: async (tok) => (wakes.push(tok), { ok: true, status: 200 }) };
  const coordA = new RedisCoordinator(url, 'instA');
  const coordB = new RedisCoordinator(url, 'instB');
  const srvA = createServer({ coordinator: coordA, pushSender: fakePush });
  const srvB = createServer({ coordinator: coordB, pushSender: fakePush });
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
    await coordA.close();
    await coordB.close();
    await stop();
  });

  // Bob registers a push token, then stays online on instance B.
  const bob = makeIdentity();
  const bobOnB = new Client(portB, bob);
  assert.strictEqual((await bobOnB.auth()).t, 'ready');
  bobOnB.send({ t: 'push-register', token: 'BOB_FCM', platform: 'android' });
  await bobOnB.next((f) => f.t === 'push-ok');
  await coordB.heartbeat(); // make Bob's presence authoritative in the store
  assert.strictEqual(await raw.get(`presence:${bob.rid}`), 'instB');

  // Alice, on instance A, sends to Bob: it crosses instances and must NOT wake.
  const alice = new Client(portA, makeIdentity());
  await alice.seenChallenge();
  assert.strictEqual((await alice.deliver('x', bob.rid, SEALED(400))).t, 'sent');
  const live = await bobOnB.next((f) => f.t === 'msg' && f.id === 'x', 4000);
  assert.ok(live, 'Bob got it live across instances');
  // A barrier, not a sleep: instance A issues any wake's token lookup on its
  // store connection before it answers `sent`, so two lookups queued behind
  // it on the same connection resolve after that one has been acted on.
  const barrier = async () => {
    await coordA.getPush(bob.rid);
    await coordA.getPush(bob.rid);
  };
  await barrier();
  assert.strictEqual(wakes.length, 0, 'an online user on another instance is not woken by FCM');

  // With Bob offline everywhere, the same send DOES wake.
  bobOnB.close();
  await waitUntil(() => srvB.wss.clients.size === 0, { what: "Bob's socket gone from instance B" });
  await raw.del(`presence:${bob.rid}`);
  assert.strictEqual((await alice.deliver('y', bob.rid, SEALED(400))).t, 'sent');
  await waitUntil(() => wakes.length >= 1, { what: 'the offline recipient woken' });
  await barrier();
  assert.deepStrictEqual(wakes, ['BOB_FCM'], 'an offline recipient is woken exactly once');
  alice.close();
});
