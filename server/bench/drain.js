#!/usr/bin/env node
// What it costs to drain a mailbox in Redis mode — the production path. A
// device that reconnects with N envelopes waiting receives them in one flush
// and acknowledges each; the question is what the relay asks of the store
// per acknowledgement, because that is paid N times. Run:
//
//     npm run bench:drain                  # 2 000 envelopes of a short text
//     N=500 KB=64 npm run bench:drain      # 500 attachment-sized envelopes
//
// Needs redis-server on PATH (it starts a private one at a free port, RAM
// only) and ioredis. One instance, loopback, the load generator sharing the
// event loop, so the numbers are pessimistic; the shape is the point.
'use strict';

const crypto = require('crypto');
const net = require('net');
const { spawn } = require('child_process');
const WebSocket = require('ws');
const IORedis = require('ioredis');
const { createServer, RedisCoordinator, routingIdFromPub } = require('../server.js');

const N = +(process.env.N || 2000);
const KB = +(process.env.KB || 1);
const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

function freePort() {
  return new Promise((res) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}
function identity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}
function connect(port, id) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    const c = { ws, id, msgs: [], onMsg: null, onAck: new Map() };
    ws.on('error', reject);
    ws.on('message', (d) => {
      const f = JSON.parse(d.toString());
      if (f.t === 'challenge') {
        const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, Buffer.from(f.nonce, 'base64')]), id.privateKey);
        ws.send(JSON.stringify({ t: 'auth', pub: id.rawPub.toString('base64'), sig: sig.toString('base64') }));
      } else if (f.t === 'ready') resolve(c);
      else if (f.t === 'msg') {
        c.msgs.push(f);
        if (c.onMsg) c.onMsg(f);
      } else if (f.t === 'sent' || f.t === 'error') {
        const r = c.onAck.get(f.id);
        if (r) {
          c.onAck.delete(f.id);
          r(f);
        }
      }
    });
  });
}

async function main() {
  const redisPort = await freePort();
  const redis = spawn('redis-server', ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'], { stdio: 'ignore' });
  await new Promise((r) => setTimeout(r, 600));
  const url = `redis://127.0.0.1:${redisPort}`;
  const raw = new IORedis(url);
  const coord = new RedisCoordinator(url, 'bench');
  const { httpServer, wss } = createServer({ coordinator: coord, pushSender: null });
  const port = await freePort();
  await new Promise((r) => httpServer.listen(port, '127.0.0.1', r));

  const bob = identity();
  const payload = 'zs1.' + 'x'.repeat(KB * 1024 - 4); // sealed-looking, so acked by id alone
  // Queue N envelopes for offline Bob, from enough senders that none of them
  // crosses the per-connection rate limit (RATE_BURST, 240): the relay is
  // meant to shed a flood from one socket, and this is not a flood test.
  const senders = [];
  for (let i = 0; i < Math.ceil(N / 200); i++) senders.push(await connect(port, identity()));
  const tq = Date.now();
  for (let i = 0; i < N; i++) {
    const a = senders[i % senders.length];
    await new Promise((resolve) => {
      a.onAck.set(`m${i}`, resolve);
      a.ws.send(JSON.stringify({ t: 'send', id: `m${i}`, to: bob.rid, payload }));
    });
  }
  const queueMs = Date.now() - tq;
  const outBefore = +/total_net_output_bytes:(\d+)/.exec(await raw.info('stats'))[1];

  // Bob connects: the flush delivers everything; he acks each as it lands.
  const b = await connect(port, bob);
  const t0 = Date.now();
  let acked = 0;
  const done = new Promise((resolve) => {
    const ack = (f) => {
      b.ws.send(JSON.stringify({ t: 'recv', id: f.id }));
      if (++acked === N) resolve();
    };
    b.msgs.forEach(ack);
    b.onMsg = ack;
  });
  await done;
  const flushMs = Date.now() - t0;
  // Wait for the queue to be empty: every ack applied.
  while ((await raw.llen(`q:${bob.rid}`)) > 0) await new Promise((r) => setTimeout(r, 20));
  const drainMs = Date.now() - t0;
  const outAfter = +/total_net_output_bytes:(\d+)/.exec(await raw.info('stats'))[1];
  const mb = (outAfter - outBefore) / 1048576;
  const held = (N * (KB * 1024 + 300)) / 1048576;

  console.log(`| ${N} × ${KB} KB | ${queueMs} ms to queue | ${flushMs} ms until the last ack was sent | ${drainMs} ms until the queue was empty | ${mb.toFixed(1)} MB read from the store for ${held.toFixed(1)} MB held (${(mb / held).toFixed(0)}×) |`);

  for (const ws of wss.clients) ws.terminate();
  httpServer.close();
  await coord.close();
  await raw.quit();
  redis.kill('SIGKILL');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
