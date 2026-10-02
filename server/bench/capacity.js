#!/usr/bin/env node
// What a queued envelope and a connected device actually cost the relay, so
// an operator can turn "U users, B envelopes of S bytes of backlog" into a
// number against MAX_STORE_BYTES (192 MB, single instance) or the shared
// store's maxmemory. Every figure in docs/CAPACITY.md comes from here.
//
// The relay charges an envelope `payload.length + 256` against its byte caps
// (server.js), which is the number the caps enforce — but the process (or the
// store) holds more than that per envelope: a JS object and a Map entry in RAM
// mode, a list element, a hash field and a counter in Redis. This measures the
// real footprint, at two payload sizes, so the fixed per-envelope overhead and
// the marginal per-byte cost come apart (intercept and slope of a line through
// two points), the way kt/test/log_memory.test.js measures the log.
//
//     node bench/capacity.js            # envelope RAM + connection RAM; Redis if present
//     node bench/capacity.js --n 20000  # more envelopes per point (steadier)
//
// RAM-mode and connection figures are in-process with gc() forced
// (heapUsed + external, so a Buffer's off-heap bytes count); the Redis figure
// is the store's own used_memory. Everything loopback on one machine.
'use strict';

const crypto = require('crypto');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const v8 = require('node:v8');
const vm = require('node:vm');

v8.setFlagsFromString('--expose_gc');
const gc = vm.runInNewContext('gc');
v8.setFlagsFromString('--no-expose_gc');

const { MemoryCoordinator, RedisCoordinator, routingIdFromPub, CFG } = require('../server.js');

const N = +(process.env.N || (argFlag('--n')) || 20000);

// Whatever this process starts — the store, the forked relay — is stopped
// however it ends: success, an error, SIGINT or SIGTERM.
const REAP = new Set();
function reapAll() {
  for (const p of REAP) {
    try {
      p.kill('SIGKILL');
    } catch {}
  }
  REAP.clear();
}
process.on('exit', reapAll);
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    reapAll();
    process.exit(sig === 'SIGINT' ? 130 : 143);
  });
}

function argFlag(name) {
  const i = process.argv.indexOf(name);
  return i !== -1 ? process.argv[i + 1] : null;
}

function randomRid() {
  return crypto.randomBytes(32).toString('base64url');
}

function retained() {
  gc();
  gc();
  const m = process.memoryUsage();
  return m.heapUsed + m.external;
}

function freePort() {
  return new Promise((res) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function hasRedis() {
  if (spawnSync('redis-server', ['--version']).status !== 0) return false;
  try {
    require.resolve('ioredis');
    return true;
  } catch {
    return false;
  }
}

// --- (a) RAM mode: what the MemoryCoordinator retains per queued envelope ---
//
// Queue N envelopes of payload P to offline mailboxes (so nothing is
// delivered or acked away), at two payload sizes, and read heap + external
// each time. The marginal cost per payload byte is the slope; the fixed cost
// per envelope — the entry object, its fields, the Map node that indexes it —
// is the intercept. Several mailboxes, so the per-mailbox Map/queue overhead
// is amortised the way a real backlog spreads it.
// A distinct payload of exactly `bytes` characters each time — a real backlog
// is distinct ciphertext, and one shared string would be counted once by V8
// and make the payload look free.
function distinctPayload(bytes, i) {
  const head = crypto.randomBytes(Math.ceil((bytes * 3) / 4)).toString('base64').replace(/[^A-Za-z0-9]/g, 'z');
  return (head + String(i)).slice(0, bytes).padEnd(bytes, 'z');
}

async function ramPerEnvelope(payloadBytes) {
  const c = new MemoryCoordinator();
  c.newMailbox.perMinute = Infinity;
  c.newMailbox.tokens = Infinity;
  const mailboxes = Math.max(1, Math.round(N / 50)); // ~50 envelopes each
  const rids = Array.from({ length: mailboxes }, () => randomRid());
  const at = retained();
  for (let i = 0; i < N; i++) {
    // Sealed (from=null): the shape a mailbox-filling backlog is, and the one
    // the per-mailbox byte cap is reasoned about. An attributed envelope also
    // retains its sender's routing id (~43 B here; in Redis it is in the key).
    await c.deliverEnqueue(null, rids[i % mailboxes], `m${i}`, distinctPayload(payloadBytes, i));
  }
  const cost = retained() - at;
  const held = c.heldEnvelopes();
  return { held, bytesPerEnvelope: cost / held, charged: payloadBytes + 256 };
}

// --- (a) Redis mode: what the store holds per queued envelope ---
async function redisPerEnvelope(url, payloadBytes) {
  const IORedis = require('ioredis');
  const raw = new IORedis(url);
  await raw.flushall();
  const coord = new RedisCoordinator(url, 'cap');
  // This measures what a queued envelope COSTS, not admission: let every
  // distinct mailbox be created (the shared gate would otherwise refuse a
  // flood of fresh routing ids as store_full).
  coord.newMailboxShared = false;
  coord.newMailbox.perMinute = Infinity;
  coord.newMailbox.tokens = Infinity;
  const mailboxes = Math.max(1, Math.round(N / 50));
  const rids = Array.from({ length: mailboxes }, () => randomRid());
  const used = async () => Number(/used_memory:(\d+)/.exec(await raw.info('memory'))[1]);
  const before = await used();
  let queued = 0;
  for (let i = 0; i < N; i++) {
    // Sealed, as in the RAM measurement: key is m:<id>, no sender in it.
    const r = await coord.deliverEnqueue(null, rids[i % mailboxes], `m${i}`, distinctPayload(payloadBytes, i));
    if (!(r && (r.refused || r.storeFull))) queued += 1;
  }
  const after = await used();
  await coord.close();
  await raw.quit();
  return { queued, bytesPerEnvelope: (after - before) / queued, charged: payloadBytes + 256 };
}

// --- (b) RAM per connection: the server side alone, via a forked relay ------
//
// The client sockets cost RAM too, and in one process they would be counted
// with the server's. So the relay runs in a child that reports its own RSS,
// and the harness opens the sockets. The delta is the relay's cost for an
// authenticated device holding one socket.
function forkRelay() {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [__filename, '--relay-child'], {
      env: { ...process.env, LOG_LEVEL: 'silent' },
      stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
    });
    REAP.add(child);
    child.once('message', (m) => (m && m.port ? resolve({ child, port: m.port }) : reject(new Error('no port'))));
    child.once('exit', (code) => reject(new Error(`relay child exited ${code}`)));
  });
}
function childRss(child) {
  return new Promise((resolve) => {
    const onMsg = (m) => {
      if (m && m.op === 'rss') {
        child.off('message', onMsg);
        resolve(m.rss);
      }
    };
    child.on('message', onMsg);
    child.send({ op: 'rss' });
  });
}

const WebSocket = require('ws');
const AUTH_CONTEXT = Buffer.from('z-relay-auth-v2:', 'utf8');
function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}
function authedSocket(port) {
  return new Promise((resolve, reject) => {
    const id = makeIdentity();
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    ws.on('error', reject);
    ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
      if (f.t === 'challenge') {
        const host = new URL(ws.url).host.toLowerCase().replace(/:(80|443)$/, '');
        const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, Buffer.from(host, 'utf8'), Buffer.from(f.nonce, 'base64')]), id.privateKey);
        ws.send(JSON.stringify({ t: 'auth', v: 2, pub: id.rawPub.toString('base64'), sig: sig.toString('base64') }));
      } else if (f.t === 'ready') resolve(ws);
    });
  });
}

async function ramPerConnection(conns) {
  const { child, port } = await forkRelay();
  await sleep(300);
  const rss0 = await childRss(child);
  const sockets = [];
  for (let i = 0; i < conns; i++) sockets.push(await authedSocket(port));
  await sleep(500); // let the server settle every registration
  const rss1 = await childRss(child);
  for (const ws of sockets) ws.terminate();
  child.send({ op: 'quit' });
  return { conns, bytesPerConnection: (rss1 - rss0) / conns, rss0, rss1 };
}

// The forked relay: a memory-coordinator relay that answers rss requests.
async function relayChild() {
  const { createServer } = require('../server.js');
  process.on('disconnect', () => process.exit(0)); // the parent is gone, however it went
  const srv = createServer({ pushSender: null });
  await new Promise((r) => srv.httpServer.listen(0, '127.0.0.1', r));
  process.on('message', (m) => {
    if (!m) return;
    if (m.op === 'rss') process.send({ op: 'rss', rss: process.memoryUsage().rss });
    else if (m.op === 'quit') {
      for (const ws of srv.wss.clients) ws.terminate();
      srv.httpServer.close();
      process.exit(0);
    }
  });
  process.send({ port: srv.httpServer.address().port });
}

function line(a, b) {
  // Through (sizeA, costA) and (sizeB, costB): marginal per byte, fixed per entry.
  const slope = (b.cost - a.cost) / (b.size - a.size);
  const fixed = a.cost - slope * a.size;
  return { slope, fixed };
}

async function main() {
  const smallP = 64;
  const bigP = 4096;
  console.log(`capacity: ${N} envelopes per point, loopback, one machine`);
  console.log(`(the relay charges an envelope payload+256 against its byte caps; these are the REAL footprint)\n`);

  // (a) RAM
  const ramS = await ramPerEnvelope(smallP);
  const ramB = await ramPerEnvelope(bigP);
  const ramLine = line({ size: smallP, cost: ramS.bytesPerEnvelope }, { size: bigP, cost: ramB.bytesPerEnvelope });
  console.log('RAM mode (MemoryCoordinator, heapUsed+external, gc forced):');
  console.log(`  ${smallP} B payload: ${ramS.bytesPerEnvelope.toFixed(0)} B/envelope held (charged ${ramS.charged})`);
  console.log(`  ${bigP} B payload: ${ramB.bytesPerEnvelope.toFixed(0)} B/envelope held (charged ${ramB.charged})`);
  console.log(`  => fixed ${ramLine.fixed.toFixed(0)} B/envelope + ${ramLine.slope.toFixed(2)} B per payload byte\n`);

  // (a) Redis
  if (hasRedis()) {
    const redisPort = await freePort();
    const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
    REAP.add(redis);
    const url = `redis://127.0.0.1:${redisPort}`;
    await sleep(700);
    let rS;
    let rB;
    try {
      rS = await redisPerEnvelope(url, smallP);
      rB = await redisPerEnvelope(url, bigP);
    } finally {
      redis.kill('SIGKILL');
      REAP.delete(redis);
    }
    const rLine = line({ size: smallP, cost: rS.bytesPerEnvelope }, { size: bigP, cost: rB.bytesPerEnvelope });
    console.log('Redis mode (store used_memory):');
    console.log(`  ${smallP} B payload: ${rS.bytesPerEnvelope.toFixed(0)} B/envelope in the store (charged ${rS.charged})`);
    console.log(`  ${bigP} B payload: ${rB.bytesPerEnvelope.toFixed(0)} B/envelope in the store (charged ${rB.charged})`);
    console.log(`  => fixed ${rLine.fixed.toFixed(0)} B/envelope + ${rLine.slope.toFixed(2)} B per payload byte\n`);
  } else {
    console.log('Redis mode: skipped (redis-server/ioredis unavailable)\n');
  }

  // (b) connections
  const conn = await ramPerConnection(2000);
  console.log('Per connection (server-side RSS, forked relay, 2000 authenticated sockets):');
  console.log(`  ${(conn.bytesPerConnection / 1024).toFixed(1)} KB per connected device (one socket)\n`);
}

if (process.argv.includes('--relay-child')) {
  relayChild().catch((e) => {
    console.error(e);
    process.exit(1);
  });
} else if (require.main === module) {
  main().then(() => process.exit(0)).catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = { ramPerEnvelope, redisPerEnvelope };
