#!/usr/bin/env node
// The relay's latency profile under sustained load — the last item on
// docs/PERFORMANCE.md's "not measured" list.
//
// load.test.js exercises the relay's abuse and capacity behaviour (floods are
// rate-limited, oversize frames close only the offender, queues are capped).
// It does not say how long a message takes to cross the relay when many
// clients are talking at once, which is the number a user feels. This does:
// N sender/recipient pairs, each sender at a steady rate well under the
// per-connection limit (RATE_PER_SEC, 80), sealed-sender envelopes of the
// 1 024 bucket (1 450 chars, what a short text is on the wire), for T
// seconds; the latency of each message is the time from `send` to the
// recipient's `msg` frame, in-process, so no clock skew.
//
// A measurement, not a test. Run it deliberately:
//
//     node bench/latency.js                  # defaults: 50 pairs, 20/s each, 10 s
//     PAIRS=200 RATE=10 SECONDS=20 node bench/latency.js
//
// It prints offered and delivered rates and p50/p90/p99/max latency, and
// the relay's /health after. Everything is loopback on one machine, so the
// numbers are the relay's own cost, not the network's.
'use strict';

const crypto = require('crypto');
const http = require('http');
const WebSocket = require('ws');

const { createServer, routingIdFromPub } = require('../server.js');

const PAIRS = +(process.env.PAIRS || 50);
const RATE = +(process.env.RATE || 20); // messages per second per sender
const SECONDS = +(process.env.SECONDS || 10);
const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { publicKey, privateKey, rawPub, rid: routingIdFromPub(rawPub) };
}

class Client {
  constructor(port, identity, onMsg) {
    this.identity = identity;
    this.onMsg = onMsg;
    this.waiters = [];
    this.frames = []; // frames nobody was waiting for yet (the challenge)
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('error', () => {});
    this.ws.on('message', (d) => {
      let f;
      try {
        f = JSON.parse(d.toString());
      } catch {
        return;
      }
      if (f.t === 'msg') {
        this.onMsg(f);
        this.send({ t: 'recv', id: f.id });
        return;
      }
      const w = this.waiters.findIndex((x) => x.pred(f));
      if (w !== -1) this.waiters.splice(w, 1)[0].resolve(f);
      else if (f.t !== 'sent') this.frames.push(f);
    });
  }
  next(pred) {
    const i = this.frames.findIndex(pred);
    if (i !== -1) return Promise.resolve(this.frames.splice(i, 1)[0]);
    return new Promise((resolve) => this.waiters.push({ pred, resolve }));
  }
  send(obj) {
    this.ws.send(JSON.stringify(obj));
  }
  async open() {
    await new Promise((res, rej) => {
      this.ws.once('open', res);
      this.ws.once('error', rej);
    });
    const challenge = await this.next((f) => f.t === 'challenge');
    const nonce = Buffer.from(challenge.nonce, 'base64');
    const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, nonce]), this.identity.privateKey);
    this.send({ t: 'auth', pub: this.identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    await this.next((f) => f.t === 'ready');
    return this;
  }
  close() {
    try {
      this.ws.close();
    } catch {}
  }
}

function percentile(sorted, p) {
  if (sorted.length === 0) return NaN;
  const i = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[i];
}

function health(port) {
  return new Promise((resolve, reject) => {
    http
      .get(`http://127.0.0.1:${port}/health`, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve(JSON.parse(body)));
      })
      .on('error', reject);
  });
}

async function main() {
  const { httpServer } = createServer({ pushSender: null });
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  const port = httpServer.address().port;

  // A 1 024-bucket sealed envelope is 1 450 characters on the wire; the
  // relay only sees the prefix and the length, so random content will do.
  const payload = 'zs1.' + crypto.randomBytes(1084).toString('base64url').slice(0, 1446);

  const latencies = [];
  const sentAt = new Map();
  let delivered = 0;
  const pairs = [];
  for (let i = 0; i < PAIRS; i++) {
    const a = makeIdentity();
    const b = makeIdentity();
    const recv = await new Client(port, b, (f) => {
      const t0 = sentAt.get(f.id);
      if (t0 !== undefined) {
        latencies.push(Number(process.hrtime.bigint() - t0) / 1e6);
        sentAt.delete(f.id);
        delivered++;
      }
    }).open();
    const send = await new Client(port, a, () => {}).open();
    pairs.push({ send, recv, to: b.rid, seq: 0 });
  }

  let offered = 0;
  const intervalMs = 1000 / RATE;
  const start = Date.now();
  const timers = pairs.map((p, i) =>
    setInterval(() => {
      const id = `${i}-${p.seq++}`;
      sentAt.set(id, process.hrtime.bigint());
      offered++;
      p.send.send({ t: 'send', to: p.to, id, payload });
    }, intervalMs)
  );
  await new Promise((res) => setTimeout(res, SECONDS * 1000));
  timers.forEach(clearInterval);
  // Let the tail drain.
  await new Promise((res) => setTimeout(res, 1000));
  const elapsed = (Date.now() - start - 1000) / 1000;

  latencies.sort((x, y) => x - y);
  const h = await health(port);
  console.log(
    `pairs=${PAIRS} rate=${RATE}/s/sender seconds=${SECONDS}  ` +
      `offered ${offered} (${(offered / elapsed).toFixed(0)}/s)  delivered ${delivered} (${(delivered / elapsed).toFixed(0)}/s)  ` +
      `undelivered ${sentAt.size}`
  );
  console.log(
    `latency ms: p50 ${percentile(latencies, 50).toFixed(2)}  p90 ${percentile(latencies, 90).toFixed(2)}  ` +
      `p99 ${percentile(latencies, 99).toFixed(2)}  max ${(latencies[latencies.length - 1] || 0).toFixed(2)}`
  );
  console.log(`/health after: connections ${h.connections} queuedEnvelopes ${h.queuedEnvelopes} storage ${h.storage}`);

  for (const p of pairs) {
    p.send.close();
    p.recv.close();
  }
  if (httpServer.closeAllConnections) httpServer.closeAllConnections();
  await new Promise((res) => httpServer.close(res));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
