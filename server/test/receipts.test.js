'use strict';

// Delivery receipts, and what an acknowledgement costs the relay.
//
// A group message is N sends of one id, one per member, and each member's
// acknowledgement produces a receipt for the sender carrying that same id.
// Between 2.7.9 and 2.8.2 the Redis store keyed a receipt by the id alone,
// so the first member to acknowledge took the key and every other member's
// receipt was discarded — the push answered as if it had stored it. A group
// of three showed the sender one tick instead of three, and only in Redis
// mode: the RAM queue appended and kept all three. An entry's key now
// carries the party it belongs to, in both coordinators (roadmap revision
// 45).
//
// The other half is cost. An acknowledgement that names nothing the mailbox
// holds used to fall back to reading the whole mailbox into the relay and
// parsing it — and `recv` had just been exempted from the rate limit, so ten
// such frames against a 6 MB mailbox pulled 59 MB out of the store, free.
//
// Criteria, each asserted below:
//  1. RAM: three members acknowledging one group message give the offline
//     sender three receipts, one per member, and no receipt displaces
//     another;
//  2. Redis: the same, and the three are three separate entries in the
//     store, delivered and then removed by the flush;
//  3. Redis: ten acknowledgements that match nothing read a few kilobytes
//     from the store, not the mailbox — with a mailbox large enough that
//     the difference is three orders of magnitude;
//  4. an acknowledgement that names nothing is charged to the rate limit,
//     where one that frees an envelope is not (drain.test.js criterion 1).
//     The charge lands after the lookup, so a burst that arrives in one read
//     is charged in arrears: the bucket goes into debt and the socket is
//     refused until it refills. What that bounds is the rate, not the burst.
//
// Skips the Redis criteria where `redis-server` or `ioredis` is missing.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
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

/** One counter out of /metrics. */
function metric(port, name) {
  return new Promise((res, rej) => {
    http
      .get({ host: '127.0.0.1', port, path: '/metrics' }, (r) => {
        let body = '';
        r.on('data', (d) => (body += d));
        r.on('end', () => {
          const m = new RegExp(`^${name} (\\d+)$`, 'm').exec(body);
          res(m ? Number(m[1]) : null);
        });
      })
      .on('error', rej);
  });
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
    const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, Buffer.from(ch.nonce, 'base64')]), this.identity.privateKey);
    this.send({ t: 'auth', pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    await this.next((f) => f.t === 'ready');
    return this;
  }
  async deliver(id, to, payload) {
    this.send({ t: 'send', id, to, payload });
    return this.next((f) => (f.t === 'sent' || f.t === 'error') && f.id === id);
  }
  /** Every frame received so far matching `pred`, plus any already queued. */
  collected(pred) {
    return this.frames.filter(pred);
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

async function ramHarness(t) {
  const srv = createServer({ pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(() => {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
  });
  return { port, srv };
}

async function redisHarness(t) {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  await sleep(700);
  const url = `redis://127.0.0.1:${redisPort}`;
  const IORedis = require('ioredis');
  const raw = new IORedis(url);
  const coord = new RedisCoordinator(url, 'instA');
  const srv = createServer({ coordinator: coord, pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  t.after(async () => {
    for (const ws of srv.wss.clients) ws.terminate();
    try {
      srv.httpServer.close();
    } catch {}
    await coord.close();
    try {
      await raw.quit();
    } catch {}
    redis.kill('SIGKILL');
  });
  return { raw, port };
}

/**
 * One group message: `alice` sends id `gid` to each member, each member
 * receives it, then `alice` goes offline and each member acknowledges. The
 * receipts have nowhere to go but the sender's mailbox — which is the case
 * the collision used to eat.
 */
async function groupRound(port, alice, members, gid) {
  const conns = [];
  for (const m of members) conns.push(await new Client(port, m).auth());
  for (const m of members) {
    assert.strictEqual((await alice.deliver(gid, m.rid, 'Z3JvdXA=')).t, 'sent');
  }
  for (const c of conns) await c.next((f) => f.t === 'msg' && f.id === gid);
  alice.close();
  await sleep(250);
  for (const c of conns) c.send({ t: 'recv', id: gid, from: alice.identity.rid });
  await sleep(400);
  return conns;
}

test('1. RAM: every member of a group gets its own receipt to the sender', async (t) => {
  const { port } = await ramHarness(t);
  const alice = await new Client(port, makeIdentity()).auth();
  const members = [makeIdentity(), makeIdentity(), makeIdentity()];
  const conns = await groupRound(port, alice, members, 'g1');

  // Alice comes back: three receipts for one id, one per member.
  const back = new Client(port, alice.identity);
  await back.auth();
  await sleep(400);
  const got = back.collected((f) => f.t === 'delivered' && f.id === 'g1');
  assert.strictEqual(got.length, 3, 'one receipt per member');
  assert.deepStrictEqual(
    got.map((f) => f.to).sort(),
    members.map((m) => m.rid).sort(),
    'and each names the member that acknowledged'
  );
  conns.forEach((c) => c.close());
  back.close();
});

test('2. Redis: the same, as three entries in the store', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, port } = await redisHarness(t);
  const alice = await new Client(port, makeIdentity()).auth();
  const members = [makeIdentity(), makeIdentity(), makeIdentity()];
  const conns = await groupRound(port, alice, members, 'g1');

  // Three separate entries, each keyed by the member that acknowledged.
  assert.deepStrictEqual(
    (await raw.lrange(`q:${alice.identity.rid}`, 0, -1)).sort(),
    members.map((m) => `r:g1:${m.rid}`).sort()
  );

  const back = new Client(port, alice.identity);
  await back.auth();
  await sleep(500);
  const got = back.collected((f) => f.t === 'delivered' && f.id === 'g1');
  assert.strictEqual(got.length, 3, 'one receipt per member');
  assert.deepStrictEqual(got.map((f) => f.to).sort(), members.map((m) => m.rid).sort());
  // Receipts are removed by the flush that delivered them, so the mailbox is gone.
  assert.strictEqual(await raw.exists(`q:${alice.identity.rid}`, `qe:${alice.identity.rid}`, `qb:${alice.identity.rid}`), 0);
  conns.forEach((c) => c.close());
  back.close();
});

test('3. Redis: an acknowledgement that matches nothing does not read the mailbox', { skip: SKIP && 'redis-server/ioredis unavailable' }, async (t) => {
  const { raw, port } = await redisHarness(t);
  const bob = makeIdentity();
  const N = 200;
  const KB64 = 'zs1.' + 'x'.repeat(64 * 1024 - 4); // sealed: no receipts in the way
  const senders = [];
  for (let i = 0; i < Math.ceil(N / 200) + 1; i++) senders.push(await new Client(port, makeIdentity()).auth());
  for (let i = 0; i < N; i++) {
    assert.strictEqual((await senders[i % senders.length].deliver(`m${i}`, bob.rid, KB64)).t, 'sent');
  }
  const mailbox = Number(await raw.get(`qb:${bob.rid}`));
  assert.ok(mailbox > 12_000_000, `the mailbox is ${(mailbox / 1048576).toFixed(1)} MB`);

  // Bob connects and reads his backlog without acknowledging any of it, so
  // the mailbox is still there and the flush's own reads are behind us.
  const b = new Client(port, bob);
  await b.auth();
  const deadline = Date.now() + 30_000;
  while (b.frames.filter((f) => f.t === 'msg').length < N && Date.now() < deadline) await sleep(50);
  assert.strictEqual(b.frames.filter((f) => f.t === 'msg').length, N, 'the whole backlog arrived');
  await sleep(300);

  const before = +/total_net_output_bytes:(\d+)/.exec(await raw.info('stats'))[1];
  for (let i = 0; i < 10; i++) b.send({ t: 'recv', id: `nosuch${i}` });
  await sleep(1200);
  const read = +/total_net_output_bytes:(\d+)/.exec(await raw.info('stats'))[1] - before;
  assert.ok(
    read < 256 * 1024,
    `ten unmatched acknowledgements read ${(read / 1048576).toFixed(1)} MB from the store; ten mailboxes would be ${((10 * mailbox) / 1048576).toFixed(0)} MB`
  );
  t.diagnostic(`ten unmatched acks read ${read} bytes against a ${(mailbox / 1048576).toFixed(1)} MB mailbox`);
  // And nothing was removed by them.
  assert.strictEqual(await raw.llen(`q:${bob.rid}`), N);
  senders.forEach((s) => s.close());
  b.close();
});

test('4. an acknowledgement that names nothing is charged to the rate limit', async (t) => {
  const { port } = await ramHarness(t);
  const b = await new Client(port, makeIdentity()).auth();
  // Twice the burst against an empty mailbox. Whether the relay was going to
  // charge for these at all is the question: the exemption is for
  // acknowledgements that free memory, and these free nothing. The charge is
  // applied after the lookup, and a burst this size arrives in one read, so
  // it lands as debt — the next frame on this socket is refused, and stays
  // refused until the bucket refills. A device draining a real backlog sends
  // far more than this and is never limited at all (drain.test.js 1).
  const missBefore = await metric(port, 'z_ack_miss_total');
  for (let i = 0; i < CFG.rateBurst * 2; i++) b.send({ t: 'recv', id: `nosuch${i}` });
  await sleep(300);
  // Visible to whoever runs the relay, which is the point of counting it:
  // a socket spending lookups on nothing shows up as this climbing.
  const missAfter = await metric(port, 'z_ack_miss_total');
  assert.ok(
    missAfter - missBefore >= CFG.rateBurst,
    `z_ack_miss_total went up by ${missAfter - missBefore}`
  );
  const limited = b.next((f) => f.t === 'error' && f.code === 'rate_limited', 5000);
  b.send({ t: 'recv', id: 'one-more' });
  await limited;

  // And the debt is finite: it refills at RATE_PER_SEC, so the socket works
  // again rather than being dead for good.
  await sleep(((CFG.rateBurst * 2) / CFG.ratePerSec) * 1000 + 500);
  const ok = b.next((f) => f.t === 'sent' || (f.t === 'error' && f.code !== 'rate_limited'), 5000);
  b.send({ t: 'send', id: 'after', to: makeIdentity().rid, payload: 'aGk=' });
  const r = await ok;
  assert.strictEqual(r.t, 'sent', 'the socket recovers');
  b.close();
});
